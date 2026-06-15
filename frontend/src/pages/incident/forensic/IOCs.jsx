import { useCallback, useEffect, useRef, useState } from 'react'
import { Link, useOutletContext } from 'react-router-dom'
import { api } from '../../../api/client.js'
import { formatLocal } from '../../../lib/datetime.js'
import BulkImportModal from './BulkImportModal.jsx'
import TagChip from '../../../components/TagChip.jsx'
import TagInput, { normalizeTags } from '../../../components/TagInput.jsx'

const IOC_TYPES = [
  { value: 'ip',           label: 'IP address' },
  { value: 'domain',       label: 'Domain' },
  { value: 'url',          label: 'URL' },
  { value: 'hash_md5',     label: 'Hash (MD5)' },
  { value: 'hash_sha1',    label: 'Hash (SHA1)' },
  { value: 'hash_sha256',  label: 'Hash (SHA256)' },
  { value: 'email',        label: 'Email' },
  { value: 'registry_key', label: 'Registry key' },
  { value: 'file_path',    label: 'File path' },
  { value: 'other',        label: 'Other' },
]

const labelOf = (v) => IOC_TYPES.find(t => t.value === v)?.label || v

// (Removed `parseTagsInput`: callers now use the shared <TagInput> + its
// `normalizeTags` export — single source of truth for the lowercase-dashed
// rules + 20-tag cap.)

// Types each platform can receive — used for per-platform IOC count
const PLATFORM_TYPES = {
  'mde-csv':     new Set(['ip', 'domain', 'url', 'hash_md5', 'hash_sha1', 'hash_sha256']),
  'mde-json':    new Set(['ip', 'domain', 'url', 'hash_md5', 'hash_sha1', 'hash_sha256']),
  'crowdstrike': new Set(['ip', 'domain', 'url', 'hash_md5', 'hash_sha256']),
  'sentinelone': new Set(['ip', 'domain', 'url', 'hash_md5', 'hash_sha1', 'hash_sha256']),
  'cortex-xdr':  new Set(['ip', 'domain', 'hash_md5', 'hash_sha1', 'hash_sha256']),
  'fortigate':   new Set(['ip', 'domain']),
  'panos':       new Set(['ip', 'domain', 'url']),
}

const PLATFORMS = [
  { id: 'mde-csv',     label: 'Microsoft Defender',   sub: 'CSV — bulk import',       types: 'IP · Domain · URL · MD5/SHA1/SHA256' },
  { id: 'mde-json',    label: 'Microsoft Defender',   sub: 'JSON — Graph API',         types: 'IP · Domain · URL · MD5/SHA1/SHA256' },
  { id: 'crowdstrike', label: 'CrowdStrike',           sub: 'JSON — Custom IOC API',    types: 'IP · Domain · URL · MD5/SHA256' },
  { id: 'sentinelone', label: 'SentinelOne',           sub: 'JSON — IOC API',           types: 'IP · Domain · URL · MD5/SHA1/SHA256' },
  { id: 'cortex-xdr',  label: 'Cortex XDR',            sub: 'JSON — Indicators API',    types: 'IP · Domain · Hashes' },
  { id: 'fortigate',   label: 'FortiGate',             sub: 'CLI script (.conf)',       types: 'IP · Domain only' },
  { id: 'panos',       label: 'Palo Alto PAN-OS',      sub: 'XML + EDL ZIP',           types: 'IP · Domain · URL' },
]

export default function IOCs() {
  const { inc } = useOutletContext()
  const isClosed = inc?.status === 'closed'

  const [allIocs, setAllIocs]               = useState([])
  const [iocs, setIocs]                     = useState([])
  const [loading, setLoading]               = useState(true)
  const [error, setError]                   = useState(null)
  const [typeFilter, setTypeFilter]         = useState('')
  const [modalOpen, setModalOpen]           = useState(false)
  const [exportOpen, setExportOpen]         = useState(false)
  const [bulkOpen, setBulkOpen]             = useState(false)
  const [editTarget, setEditTarget]         = useState(null) // IOC being edited
  const [busy, setBusy]                     = useState(false)
  const [editingNotesId, setEditingNotesId] = useState(null)
  const [notesDraft, setNotesDraft]         = useState('')
  const [corrMap, setCorrMap]               = useState({})   // ioc_id → IncidentRef[]
  const [corrTarget, setCorrTarget]         = useState(null) // { ioc, incidents } for modal
  const [entityMap, setEntityMap]           = useState({})   // entity_id → { name, type } for column rendering

  // Enrichment state
  const [enrichResults, setEnrichResults]   = useState({})  // ioc_id → [EnrichResultItem]
  const [enriching, setEnriching]           = useState(false)
  const [enrichingId, setEnrichingId]       = useState(null) // ioc_id being enriched individually
  const [enrichError, setEnrichError]       = useState(null)
  const [expandedId, setExpandedId]         = useState(null)

  // Source picker — collapsible menu attached to the Scan IOCs button.
  // sources comes from GET /api/osint/sources; selected defaults to all available.
  const [sources, setSources]               = useState([])    // [{id,label,available,...}]
  const [selectedSources, setSelectedSrc]   = useState(null)  // Set<string> | null (null = uninitialised)
  const [pickerOpen, setPickerOpen]         = useState(false)
  const pickerRef = useRef(null)

  const load = useCallback(async () => {
    setError(null)
    try {
      const res = await api.listIocs(inc.id, { limit: 200 })
      setAllIocs(res.items)
      setIocs(typeFilter ? res.items.filter(i => i.type === typeFilter) : res.items)
      // Load cross-incident correlations for badge display (best-effort — don't block render)
      try {
        const corr = await api.listIocCorrelations(inc.id)
        const map = {}
        for (const hit of corr.items) map[hit.ioc_id] = hit.matched_incidents
        setCorrMap(map)
      } catch {}
      try {
        const er = await api.listEntities(inc.id, { limit: 200 })
        const emap = {}
        for (const e of er.items || []) emap[e.id] = { name: e.name || e.value, type: e.type }
        setEntityMap(emap)
      } catch {}
    } catch (e) {
      setError(e.message || 'Could not load IOCs')
    } finally {
      setLoading(false)
    }
  }, [inc.id, typeFilter])

  useEffect(() => { load() }, [load])

  // Fetch enrichment sources once; preselect all currently-available sources.
  useEffect(() => {
    let cancelled = false
    api.osintSources()
      .then(res => {
        if (cancelled) return
        const list = res.sources || []
        setSources(list)
        setSelectedSrc(new Set(list.filter(s => s.available).map(s => s.id)))
      })
      .catch(() => {
        if (!cancelled) setSources([])
      })
    return () => { cancelled = true }
  }, [])

  // Close picker on outside click / Escape
  useEffect(() => {
    if (!pickerOpen) return
    const onClick = (e) => {
      if (pickerRef.current && !pickerRef.current.contains(e.target)) setPickerOpen(false)
    }
    const onKey = (e) => { if (e.key === 'Escape') setPickerOpen(false) }
    document.addEventListener('mousedown', onClick)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('mousedown', onClick)
      document.removeEventListener('keydown', onKey)
    }
  }, [pickerOpen])

  const onDelete = async (i) => {
    if (!window.confirm(`Delete this IOC?\n\n${labelOf(i.type)}: ${i.value}`)) return
    setBusy(true)
    try {
      await api.deleteIoc(inc.id, i.id)
      await load()
    } catch (e) {
      setError(e.message || 'Could not delete IOC')
    } finally {
      setBusy(false)
    }
  }

  const startNotesEdit  = (i) => { setEditingNotesId(i.id); setNotesDraft(i.notes || '') }
  const cancelNotesEdit = ()    => { setEditingNotesId(null); setNotesDraft('') }
  const saveNotesEdit   = async (i) => {
    const next = notesDraft.trim()
    if (next === (i.notes || '')) { cancelNotesEdit(); return }
    setBusy(true)
    try {
      await api.updateIoc(inc.id, i.id, { notes: next || null })
      await load()
    } catch (e) {
      setError(e.message || 'Could not update notes')
    } finally {
      setBusy(false)
      cancelNotesEdit()
    }
  }

  // Mark the IOC's tri-state status (true = malicious, false = clean, null =
  // unknown). No-op if the target state already matches.
  const markIoc = async (i, status) => {
    if (i.malicious === status) return
    setBusy(true)
    try {
      await api.updateIoc(inc.id, i.id, { malicious: status })
      await load()
    } catch (e) {
      setError(e.message || 'Could not update status')
    } finally {
      setBusy(false)
    }
  }

  const scanAll = async () => {
    setEnriching(true)
    setEnrichError(null)
    setPickerOpen(false)
    try {
      // Only send `sources` if the operator narrowed the set; otherwise let the
      // server use its full available list (preserves legacy behaviour).
      const allIds = sources.map(s => s.id)
      const picked = selectedSources ? [...selectedSources] : allIds
      const narrowed = picked.length !== allIds.length
      const payload = narrowed ? { sources: picked } : {}
      const res = await api.enrichAllIocs(inc.id, payload)
      setEnrichResults(res.results || {})
      if (res.enriched_count === 0) {
        setEnrichError('No IOCs could be enriched — configure API keys in Settings → API Keys.')
      }
    } catch (e) {
      setEnrichError(e.message || 'Enrichment failed')
    } finally {
      setEnriching(false)
    }
  }

  const toggleSource = (id) => {
    setSelectedSrc(prev => {
      const next = new Set(prev || [])
      if (next.has(id)) next.delete(id); else next.add(id)
      return next
    })
  }
  const selectAllSources = () =>
    setSelectedSrc(new Set(sources.filter(s => s.available).map(s => s.id)))
  const clearSources = () => setSelectedSrc(new Set())

  const selectedCount   = selectedSources ? selectedSources.size : 0
  const availableCount  = sources.filter(s => s.available).length
  const noneSelected    = selectedCount === 0
  const scanDisabled    = allIocs.length === 0 || enriching || noneSelected || availableCount === 0

  const enrichOne = async (i) => {
    setEnrichingId(i.id)
    try {
      const results = await api.enrichIoc(inc.id, i.id)
      setEnrichResults(prev => ({ ...prev, [i.id]: results }))
      setExpandedId(i.id)
    } catch (e) {
      setEnrichError(e.message || 'Enrichment failed')
    } finally {
      setEnrichingId(null)
    }
  }

  const hasAnyResults = Object.keys(enrichResults).length > 0

  return (
    <section className="panel">
      <div className="panel-toolbar">
        <h2 className="panel-h">Indicators of Compromise</h2>
        <div style={{ display: 'flex', gap: 'var(--space-2)' }}>
          <select
            className="select"
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
            aria-label="Filter by IOC type"
          >
            <option value="">All types</option>
            {IOC_TYPES.map(t => <option key={t.value} value={t.value}>{t.label}</option>)}
          </select>
          <div ref={pickerRef} style={{ position: 'relative', display: 'inline-flex' }}>
            <button
              type="button"
              className="btn ghost"
              onClick={scanAll}
              disabled={scanDisabled}
              title={
                allIocs.length === 0      ? 'No IOCs to scan'
                : availableCount === 0    ? 'No enrichment sources available — configure API keys in Settings → API Keys'
                : noneSelected            ? 'Pick at least one source from the menu'
                : `Scan with ${selectedCount} source${selectedCount === 1 ? '' : 's'}: ${
                    sources.filter(s => selectedSources?.has(s.id)).map(s => s.label).join(', ')
                  }`
              }
              style={{ borderTopRightRadius: 0, borderBottomRightRadius: 0, borderRight: 'none' }}
            >
              {enriching
                ? 'Scanning…'
                : `${hasAnyResults ? '↻ Re-scan' : 'Scan'} IOCs${availableCount > 0 ? ` (${selectedCount}/${availableCount})` : ''}`
              }
            </button>
            <button
              type="button"
              className="btn ghost"
              onClick={() => setPickerOpen(o => !o)}
              disabled={enriching || sources.length === 0}
              aria-haspopup="true"
              aria-expanded={pickerOpen}
              title="Choose enrichment sources"
              style={{ borderTopLeftRadius: 0, borderBottomLeftRadius: 0, padding: '0 8px' }}
            >
              ▾
            </button>

            {pickerOpen && (
              <div
                role="menu"
                style={{
                  position: 'absolute',
                  top: 'calc(100% + 4px)',
                  right: 0,
                  zIndex: 20,
                  minWidth: 280,
                  background: 'var(--surface)',
                  border: '1px solid var(--border)',
                  borderRadius: 'var(--radius)',
                  boxShadow: 'var(--shadow)',
                  padding: 'var(--space-2)',
                }}
              >
                <div style={{
                  display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                  padding: '0 var(--space-1) var(--space-2)',
                  borderBottom: '1px solid var(--border)', marginBottom: 'var(--space-2)',
                }}>
                  <span style={{ fontSize: 11, fontWeight: 700, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
                    Enrichment sources
                  </span>
                  <span style={{ display: 'flex', gap: 8 }}>
                    <button type="button" onClick={selectAllSources}
                      style={{ background: 'none', border: 'none', padding: 0, cursor: 'pointer', fontSize: 11, color: 'var(--accent)' }}>
                      All
                    </button>
                    <button type="button" onClick={clearSources}
                      style={{ background: 'none', border: 'none', padding: 0, cursor: 'pointer', fontSize: 11, color: 'var(--muted)' }}>
                      None
                    </button>
                  </span>
                </div>

                {sources.length === 0 ? (
                  <div style={{ fontSize: 12, color: 'var(--dim)', padding: 'var(--space-2)' }}>
                    Loading sources…
                  </div>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                    {sources.map(s => {
                      const checked = !!selectedSources?.has(s.id)
                      const disabled = !s.available
                      return (
                        <label
                          key={s.id}
                          title={disabled
                            ? `${s.description} — not available (configure API key in Settings → API Keys)`
                            : s.description}
                          style={{
                            display: 'flex', alignItems: 'center', gap: 8,
                            padding: '4px 6px', borderRadius: 'var(--radius-sm)',
                            cursor: disabled ? 'not-allowed' : 'pointer',
                            opacity: disabled ? 0.5 : 1,
                            fontSize: 12,
                          }}
                        >
                          <input
                            type="checkbox"
                            checked={checked}
                            disabled={disabled}
                            onChange={() => !disabled && toggleSource(s.id)}
                          />
                          <span style={{ flex: 1, color: 'var(--text)' }}>{s.label}</span>
                          {!s.available && (
                            <span style={{ fontSize: 10, color: 'var(--muted)' }}>no key</span>
                          )}
                          {s.public && (
                            <span style={{ fontSize: 10, color: 'var(--dim)' }}>public</span>
                          )}
                        </label>
                      )
                    })}
                  </div>
                )}

                {availableCount === 0 && (
                  <div style={{
                    marginTop: 'var(--space-2)', padding: 'var(--space-2)',
                    fontSize: 11, color: 'var(--muted)',
                    background: 'var(--surface-2)', borderRadius: 'var(--radius-sm)',
                  }}>
                    No sources available. Add API keys in Settings → API Keys.
                  </div>
                )}
              </div>
            )}
          </div>
          <button
            type="button"
            className="btn ghost"
            onClick={() => setExportOpen(true)}
            disabled={allIocs.length === 0}
            title={allIocs.length === 0 ? 'No IOCs to export' : 'Export IOCs to a security platform'}
          >
            Export
          </button>
          <button
            type="button"
            className="btn ghost"
            onClick={() => setBulkOpen(true)}
            disabled={isClosed}
            title={isClosed ? 'Closed incidents are read-only' : 'Bulk import IOCs from text or CSV'}
          >
            Bulk Import
          </button>
          <button
            type="button"
            className="btn primary"
            onClick={() => setModalOpen(true)}
            disabled={isClosed}
            title={isClosed ? 'Closed incidents are read-only' : 'Add IOC'}
          >
            + Add IOC
          </button>
        </div>
      </div>

      {error && (
        <div className="alert error" role="alert">
          <span className="alert-icon">!</span><span>{error}</span>
        </div>
      )}

      {enrichError && (
        <div className="alert warn" role="alert" style={{ marginBottom: 'var(--space-2)' }}>
          <span className="alert-icon">⚠</span><span>{enrichError}</span>
        </div>
      )}

      {loading ? (
        <div className="panel-empty"><div>Loading…</div></div>
      ) : iocs.length === 0 ? (
        <div className="panel-empty">
          <div className="panel-empty-mark" aria-hidden="true">◌</div>
          <div>No IOCs yet.</div>
          {!isClosed && <div style={{ color: 'var(--dim)', fontSize: 12 }}>Click "Add IOC" to record an indicator.</div>}
        </div>
      ) : (
        <table className="settings-table">
          <thead>
            <tr>
              <th style={{ width: 110 }}>Type</th>
              <th>Value</th>
              <th style={{ width: 150 }}>Entity</th>
              <th style={{ width: 90 }}>Source</th>
              <th style={{ width: 90 }}>Confidence</th>
              <th style={{ width: 160 }}>Tags</th>
              <th style={{ width: 130 }}>Added</th>
              <th style={{ width: 80 }}>Seen in</th>
              <th className="actions">Actions</th>
            </tr>
          </thead>
          <tbody>
            {iocs.flatMap(i => {
              const results = enrichResults[i.id]
              const isExpanded = expandedId === i.id
              return [
              <tr
                key={i.id}
                onClick={(e) => {
                  // Click-anywhere-to-toggle, except on actual interactive elements.
                  if (e.target.closest('button, a, input, textarea, select')) return
                  setExpandedId(isExpanded ? null : i.id)
                }}
                style={{ cursor: 'pointer' }}
                aria-expanded={isExpanded}
              >
                <td>
                  <span className="pill">{labelOf(i.type)}</span>
                  {i.malicious === true  && <span className="pill pill-crit" style={{ fontSize: 10, marginLeft: 4 }}>MALICIOUS</span>}
                  {i.malicious === false && <span className="pill pill-ok"   style={{ fontSize: 10, marginLeft: 4 }}>CLEAN</span>}
                  {i.malicious == null   && <span className="pill pill-gray" style={{ fontSize: 10, marginLeft: 4 }}>UNKNOWN</span>}
                </td>
                <td style={{ fontSize: 12, maxWidth: 280 }}>
                  <span
                    title={i.value}
                    style={{
                      display: 'inline-block', maxWidth: 240,
                      overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                      verticalAlign: 'middle',
                      fontFamily: 'var(--font-mono)',
                    }}
                  >{i.value}</span>
                  {i.ti_matched && (
                    <span
                      title={`Threat intel match — ${i.ti_match_source}`}
                      style={{
                        marginLeft: 6, fontSize: 10, padding: '1px 5px',
                        borderRadius: 'var(--radius-sm)',
                        background: 'color-mix(in srgb, var(--crit) 15%, transparent)',
                        color: 'var(--crit)',
                        border: '1px solid color-mix(in srgb, var(--crit) 40%, transparent)',
                        fontFamily: 'var(--font-body)', fontWeight: 600,
                        verticalAlign: 'middle', whiteSpace: 'nowrap', cursor: 'default',
                      }}
                    >⚠ TI</span>
                  )}
                  {i.lolbin_hit && (
                    <span
                      title={`LOLBin/GTFOBin — ${i.lolbin_name}`}
                      style={{
                        marginLeft: 6, fontSize: 10, padding: '1px 5px',
                        borderRadius: 'var(--radius-sm)',
                        background: 'color-mix(in srgb, var(--high) 15%, transparent)',
                        color: 'var(--high)',
                        border: '1px solid color-mix(in srgb, var(--high) 40%, transparent)',
                        fontFamily: 'var(--font-body)', fontWeight: 600,
                        verticalAlign: 'middle', whiteSpace: 'nowrap', cursor: 'default',
                      }}
                    >LOL</span>
                  )}
                </td>
                <td style={{ fontSize: 12 }}>
                  {i.entity_id && entityMap[i.entity_id] ? (
                    <Link
                      to={`/incidents/${inc.id}/entities`}
                      className="pill"
                      title={`Linked to ${entityMap[i.entity_id].type}: ${entityMap[i.entity_id].name} — click to open Entities`}
                      style={{ textDecoration: 'none' }}
                    >
                      {entityMap[i.entity_id].type}: {entityMap[i.entity_id].name}
                    </Link>
                  ) : (
                    <span style={{ color: 'var(--dim)' }}>—</span>
                  )}
                </td>
                <td style={{ color: 'var(--muted)', fontSize: 12 }}>{i.source || '—'}</td>
                <td><ConfidencePill value={i.confidence ?? 50} /></td>
                <td><TagChips tags={i.tags} /></td>
                <td
                  title={formatLocal(i.added_at)}
                  style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--muted)' }}
                >
                  {formatLocal(i.added_at).slice(0, 16)}
                </td>
                <td style={{ textAlign: 'center' }}>
                  {corrMap[i.id]?.length > 0 && (
                    <button
                      type="button"
                      className="btn ghost"
                      onClick={() => setCorrTarget({ ioc: i, incidents: corrMap[i.id] })}
                      title={`Also seen in ${corrMap[i.id].length} other incident${corrMap[i.id].length !== 1 ? 's' : ''}`}
                      style={{
                        fontSize: 11,
                        padding: '2px 6px',
                        color: 'var(--accent)',
                        fontFamily: 'var(--font-mono)',
                      }}
                    >
                      ⋈ {corrMap[i.id].length}
                    </button>
                  )}
                </td>
                <td className="actions">
                  <button
                    type="button"
                    className="btn ghost"
                    onClick={() => enrichOne(i)}
                    disabled={enrichingId === i.id}
                    title="Enrich this indicator (VT, AbuseIPDB, Shodan, GreyNoise, URLScan)"
                    style={{ fontSize: 11 }}
                  >
                    {enrichingId === i.id ? '…' : enrichResults[i.id] ? '↻' : 'Enrich'}
                  </button>
                  <button
                    type="button"
                    className="btn ghost"
                    onClick={() => setEditTarget(i)}
                    disabled={isClosed}
                    style={{ fontSize: 11 }}
                  >
                    Edit
                  </button>
                  <button
                    type="button"
                    className="btn ghost"
                    onClick={() => onDelete(i)}
                    disabled={isClosed || busy}
                  >
                    Delete
                  </button>
                </td>
              </tr>,
              isExpanded && (
                <tr key={`${i.id}-detail`}>
                  <td colSpan={9} style={{ paddingTop: 0, paddingBottom: 'var(--space-3)' }}>
                    <div style={{
                      display: 'flex', flexDirection: 'column', gap: 'var(--space-3)',
                      padding: 'var(--space-3)',
                      background: 'var(--surface)',
                      border: '1px solid var(--border)',
                      borderRadius: 'var(--radius-sm)',
                    }}>
                      {/* Full value (not truncated, selectable) */}
                      <div>
                        <div style={{ fontSize: 11, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 4 }}>
                          Value
                        </div>
                        <div style={{
                          fontFamily: 'var(--font-mono)', fontSize: 12,
                          wordBreak: 'break-all', userSelect: 'text', color: 'var(--text)',
                          padding: 'var(--space-2)',
                          background: 'var(--surface-2)',
                          border: '1px solid var(--border)',
                          borderRadius: 'var(--radius-sm)',
                        }}>
                          {i.value}
                        </div>
                      </div>

                      {/* Mark buttons */}
                      <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', flexWrap: 'wrap' }}>
                        <span style={{ fontSize: 11, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '0.06em', marginRight: 4 }}>
                          Status
                        </span>
                        <button
                          type="button"
                          className="btn"
                          onClick={() => markIoc(i, true)}
                          disabled={isClosed || busy}
                          aria-pressed={i.malicious === true}
                          style={{
                            fontSize: 11,
                            color: i.malicious === true ? 'var(--crit)' : 'var(--muted)',
                            borderColor: i.malicious === true ? 'color-mix(in srgb, var(--crit) 50%, transparent)' : undefined,
                            background:  i.malicious === true ? 'color-mix(in srgb, var(--crit) 14%, transparent)' : undefined,
                          }}
                        >⚠ Mark Malicious</button>
                        <button
                          type="button"
                          className="btn"
                          onClick={() => markIoc(i, false)}
                          disabled={isClosed || busy}
                          aria-pressed={i.malicious === false}
                          style={{
                            fontSize: 11,
                            color: i.malicious === false ? 'var(--ok)' : 'var(--muted)',
                            borderColor: i.malicious === false ? 'color-mix(in srgb, var(--ok) 50%, transparent)' : undefined,
                            background:  i.malicious === false ? 'color-mix(in srgb, var(--ok) 14%, transparent)' : undefined,
                          }}
                        >✓ Mark Clean</button>
                        <button
                          type="button"
                          className="btn"
                          onClick={() => markIoc(i, null)}
                          disabled={isClosed || busy}
                          aria-pressed={i.malicious == null}
                          style={{
                            fontSize: 11,
                            color: i.malicious == null ? 'var(--text)' : 'var(--muted)',
                            borderColor: i.malicious == null ? 'var(--border-strong)' : undefined,
                            background:  i.malicious == null ? 'var(--surface-2)' : undefined,
                          }}
                        >? Mark Unknown</button>
                      </div>

                      {/* Notes editor */}
                      <div>
                        <div style={{ fontSize: 11, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 4 }}>
                          Notes
                        </div>
                        {editingNotesId === i.id ? (
                          <textarea
                            className="input"
                            autoFocus
                            value={notesDraft}
                            onChange={(e) => setNotesDraft(e.target.value)}
                            onBlur={() => saveNotesEdit(i)}
                            onKeyDown={(e) => {
                              if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) {
                                e.preventDefault(); saveNotesEdit(i)
                              }
                              if (e.key === 'Escape') { e.preventDefault(); cancelNotesEdit() }
                            }}
                            rows={4}
                            maxLength={4096}
                            style={{ width: '100%', resize: 'vertical' }}
                          />
                        ) : (
                          <button
                            type="button"
                            className="btn ghost"
                            onClick={() => !isClosed && startNotesEdit(i)}
                            disabled={isClosed}
                            title={isClosed ? 'Closed incidents are read-only' : 'Click to edit notes (⌘/Ctrl+Enter to save · Esc to cancel)'}
                            style={{
                              padding: 'var(--space-2)',
                              textAlign: 'left',
                              fontFamily: 'var(--font-body)',
                              fontWeight: 400,
                              whiteSpace: 'pre-wrap',
                              wordBreak: 'break-word',
                              minHeight: 40,
                              width: '100%',
                              justifyContent: 'flex-start',
                              alignItems: 'flex-start',
                            }}
                          >
                            {i.notes || <span style={{ color: 'var(--dim)' }}>— click to add notes —</span>}
                          </button>
                        )}
                      </div>

                      {/* Enrichment results (only when loaded) */}
                      {results && <EnrichmentResults results={results} />}
                    </div>
                  </td>
                </tr>
              ),
              ]
            })}
          </tbody>
        </table>
      )}

      {modalOpen && (
        <IocModal
          incidentId={inc.id}
          onClose={() => setModalOpen(false)}
          onCreated={() => { setModalOpen(false); load() }}
        />
      )}

      {exportOpen && (
        <ExportModal
          incidentId={inc.id}
          allIocs={allIocs}
          onClose={() => setExportOpen(false)}
        />
      )}

      {bulkOpen && (
        <BulkImportModal
          incidentId={inc.id}
          onClose={() => setBulkOpen(false)}
          onImported={() => { setBulkOpen(false); load() }}
        />
      )}

      {corrTarget && (
        <CorrelationModal
          ioc={corrTarget.ioc}
          incidents={corrTarget.incidents}
          onClose={() => setCorrTarget(null)}
        />
      )}

      {editTarget && (
        <EditIocModal
          incidentId={inc.id}
          ioc={editTarget}
          onClose={() => setEditTarget(null)}
          onSaved={() => { setEditTarget(null); load() }}
        />
      )}
    </section>
  )
}

// ─── Confidence + tags cell renderers ────────────────────────────────────────

function ConfidencePill({ value }) {
  const v = Math.max(0, Math.min(100, Number(value) || 0))
  const band = v >= 70 ? 'high' : v >= 30 ? 'med' : 'low'
  const colour = band === 'high' ? 'var(--ok)' : band === 'med' ? 'var(--med)' : 'var(--dim)'
  return (
    <span
      title={`Confidence ${v}/100`}
      style={{
        display: 'inline-flex', alignItems: 'center', gap: 6,
        fontSize: 11, fontFamily: 'var(--font-mono)', color: colour,
      }}
    >
      <span style={{
        display: 'inline-block', width: 36, height: 6,
        borderRadius: 3, background: 'var(--surface-2)', overflow: 'hidden',
      }}>
        <span style={{
          display: 'block', width: `${v}%`, height: '100%', background: colour,
        }} />
      </span>
      {v}
    </span>
  )
}

function TagChips({ tags }) {
  // Delegates to the shared <TagChip> for hash-coloured rendering consistent
  // with the Incident list / detail / dashboard. v2 design 2026-05-17.
  const list = Array.isArray(tags) ? tags : []
  if (list.length === 0) return <span style={{ color: 'var(--dim)' }}>—</span>
  return (
    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
      {list.map(t => <TagChip key={t} tag={t} dense />)}
    </div>
  )
}


// ─── Enrichment result display ────────────────────────────────────────────────

function EnrichmentResults({ results }) {
  const meaningful = results.filter(r => r.available && !r.error)
  const errors     = results.filter(r => r.error)
  const unavail    = results.filter(r => !r.available)
  return (
    <div style={{
      display: 'flex', gap: 'var(--space-3)', flexWrap: 'wrap',
      padding: 'var(--space-2) var(--space-3)', background: 'var(--surface-2)',
      borderRadius: 'var(--radius)', margin: '0 var(--space-1)',
    }}>
      {meaningful.map(r => <EnrichCard key={r.source} r={r} />)}
      {errors.map(r => (
        <div key={r.source} style={{
          fontSize: 12, color: 'var(--crit)', padding: 'var(--space-2)', minWidth: 140,
          background: 'var(--surface)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)',
        }}>
          <div style={{ fontWeight: 600, marginBottom: 2 }}>{r.source}</div>
          <div>{r.error}</div>
        </div>
      ))}
      {unavail.map(r => (
        <div key={r.source} style={{ fontSize: 12, color: 'var(--dim)', padding: 'var(--space-2)', minWidth: 120 }}>
          {r.source}: no key
        </div>
      ))}
    </div>
  )
}

function EnrichCard({ r }) {
  const d = r.data
  if (!d) return null
  return (
    <div style={{
      minWidth: 180, maxWidth: 260, padding: 'var(--space-2) var(--space-3)',
      background: 'var(--surface)', borderRadius: 'var(--radius-sm)',
      border: '1px solid var(--border)', fontSize: 12,
    }}>
      <div style={{ fontWeight: 600, color: 'var(--text)', marginBottom: 'var(--space-1)', display: 'flex', gap: 'var(--space-1)', alignItems: 'center' }}>
        {r.source}
        {r.from_cache && <span style={{ color: 'var(--dim)', fontSize: 10, fontWeight: 400 }}>cached</span>}
      </div>
      {r.source === 'geoip'      && <GeoRow d={d} />}
      {r.source === 'greynoise'  && <GreyNoiseRow d={d} />}
      {r.source === 'abuseipdb'  && <AbuseRow d={d} />}
      {r.source === 'virustotal' && <VTRow d={d} />}
      {r.source === 'shodan'     && <ShodanRow d={d} />}
      {r.source === 'urlscan'    && <URLScanRow d={d} />}
    </div>
  )
}

function KV({ label, value, mono, danger }) {
  if (value === undefined || value === null || value === '') return null
  return (
    <div style={{ display: 'flex', gap: 4, marginBottom: 2 }}>
      <span style={{ color: 'var(--muted)', minWidth: 60, flexShrink: 0 }}>{label}</span>
      <span style={{ fontFamily: mono ? 'var(--font-mono)' : undefined, color: danger ? 'var(--crit)' : 'var(--text)', wordBreak: 'break-all' }}>
        {String(value)}
      </span>
    </div>
  )
}

function GeoRow({ d }) {
  if (d.private) return <div style={{ color: 'var(--dim)' }}>Private address</div>
  if (d.status === 'fail') return <div style={{ color: 'var(--crit)' }}>{d.message}</div>
  return (
    <>
      <KV label="Location" value={[d.city, d.regionName, d.countryCode].filter(Boolean).join(', ')} />
      <KV label="ISP"      value={d.isp} />
      <KV label="ASN"      value={d.as} />
      {d.proxy   && <div style={{ color: 'var(--high)', marginTop: 2 }}>Proxy/VPN</div>}
      {d.hosting && <div style={{ color: 'var(--med)', marginTop: 2 }}>Hosting/DC</div>}
    </>
  )
}

function GreyNoiseRow({ d }) {
  if (d.message && !d.noise && !d.riot) return <div style={{ color: 'var(--dim)' }}>{d.message}</div>
  const cls = d.classification
  const clsColor = cls === 'malicious' ? 'var(--crit)' : cls === 'benign' ? 'var(--ok)' : 'var(--muted)'
  return (
    <>
      {cls && <div style={{ color: clsColor, fontWeight: 600, marginBottom: 2, textTransform: 'capitalize' }}>{cls}</div>}
      <KV label="Noise" value={d.noise ? 'Yes' : 'No'} danger={d.noise} />
      <KV label="RIOT"  value={d.riot ? 'Known good' : null} />
      {d.name && <KV label="Name" value={d.name} />}
    </>
  )
}

function AbuseRow({ d }) {
  if (d.message && !d.data) return <div style={{ color: 'var(--dim)' }}>{d.message}</div>
  const x = d.data || d
  const score = x.abuseConfidenceScore ?? x.abuse_confidence_score
  const scoreColor = score >= 80 ? 'var(--crit)' : score >= 40 ? 'var(--high)' : score > 0 ? 'var(--med)' : 'var(--ok)'
  return (
    <>
      {score !== undefined && (
        <div style={{ display: 'flex', alignItems: 'baseline', gap: 4, marginBottom: 4 }}>
          <span style={{ fontSize: 20, fontWeight: 700, color: scoreColor, fontFamily: 'var(--font-mono)' }}>{score}%</span>
          <span style={{ color: 'var(--muted)', fontSize: 10 }}>confidence</span>
        </div>
      )}
      <KV label="Reports" value={x.totalReports ?? x.total_reports} />
      {x.isTor && <div style={{ color: 'var(--crit)', marginTop: 2 }}>Tor exit node</div>}
    </>
  )
}

function VTRow({ d }) {
  if (d.found === false) return <div style={{ color: 'var(--dim)' }}>Not in VirusTotal</div>
  const attrs = d.data?.attributes || {}
  const stats = attrs.last_analysis_stats || {}
  const mal   = (stats.malicious || 0) + (stats.suspicious || 0)
  const total = Object.values(stats).reduce((a, b) => a + b, 0)
  return (
    <>
      {total > 0 && (
        <div style={{ display: 'flex', alignItems: 'baseline', gap: 4, marginBottom: 4 }}>
          <span style={{ fontSize: 20, fontWeight: 700, color: mal > 0 ? 'var(--crit)' : 'var(--ok)', fontFamily: 'var(--font-mono)' }}>
            {mal}/{total}
          </span>
          <span style={{ color: 'var(--muted)', fontSize: 10 }}>engines</span>
        </div>
      )}
      {attrs.meaningful_name && <KV label="Name" value={attrs.meaningful_name} />}
    </>
  )
}

function ShodanRow({ d }) {
  if (d.found === false) return <div style={{ color: 'var(--dim)' }}>No Shodan data</div>
  if (d.message) return <div style={{ color: 'var(--dim)' }}>{d.message}</div>
  const ports = (d.ports || []).slice(0, 12)
  return (
    <>
      <KV label="Org"     value={d.org} />
      <KV label="ASN"     value={d.asn} />
      <KV label="Country" value={[d.city, d.country_code].filter(Boolean).join(', ')} />
      {ports.length > 0 && (
        <div style={{ marginTop: 2 }}>
          <span style={{ color: 'var(--muted)' }}>Ports: </span>
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>
            {ports.join(', ')}{(d.ports?.length || 0) > 12 ? '…' : ''}
          </span>
        </div>
      )}
    </>
  )
}

function URLScanRow({ d }) {
  if (d.found === false) return <div style={{ color: 'var(--dim)' }}>No results in URLScan</div>
  const hits = d.hits || []
  const first = hits[0]
  if (!first) return null
  const hasMal = hits.some(h => h.malicious > 0)
  return (
    <>
      <div style={{ display: 'flex', alignItems: 'center', gap: 4, marginBottom: 4 }}>
        <span style={{ fontWeight: 600, color: hasMal ? 'var(--crit)' : 'var(--ok)', fontSize: 13, fontFamily: 'var(--font-mono)' }}>
          {hasMal ? '⚠ Malicious' : '✓ Clean'}
        </span>
        <span style={{ color: 'var(--dim)', fontSize: 10 }}>{d.total} scan{d.total !== 1 ? 's' : ''}</span>
      </div>
      {first.country && <KV label="Country" value={first.country} />}
      {first.server  && <KV label="Server"  value={first.server} />}
      {first.ip      && <KV label="IP"      value={first.ip} mono />}
      <a
        href={first.report_url}
        target="_blank"
        rel="noopener noreferrer"
        style={{ fontSize: 11, color: 'var(--accent)', textDecoration: 'none', display: 'block', marginTop: 4 }}
      >
        View report →
      </a>
    </>
  )
}

// ─── IOC create modal ─────────────────────────────────────────────────────────

function IocModal({ incidentId, onClose, onCreated }) {
  const [type, setType]         = useState('ip')
  const [value, setValue]       = useState('')
  const [source, setSource]     = useState('')
  const [notes, setNotes]       = useState('')
  const [malicious, setMalicious] = useState(false)
  const [confidence, setConfidence] = useState(50)
  const [tags, setTags]         = useState([])
  const [entityId, setEntityId] = useState('')
  const [entities, setEntities] = useState([])
  const [busy, setBusy]         = useState(false)
  const [error, setError]       = useState(null)

  useEffect(() => {
    api.listEntities(incidentId, { limit: 200 }).then(r => setEntities(r.items || [])).catch(() => {})
  }, [incidentId])

  useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape' && !busy) onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [busy, onClose])

  const onSubmit = async (e) => {
    e.preventDefault()
    setError(null)
    const v = value.trim()
    if (!v) { setError('Value is required.'); return }
    setBusy(true)
    try {
      await api.createIoc(incidentId, {
        type,
        value: v,
        notes:      notes.trim()  || null,
        source:     source.trim() || null,
        // Tri-state: unchecked checkbox maps to null (Unknown) so new IOCs
        // default to "not yet reviewed" rather than implicitly Clean.
        malicious:  malicious ? true : null,
        confidence,
        tags:       normalizeTags(tags),
        entity_id:  entityId || null,
      })
      onCreated()
    } catch (err) {
      setError(err.message || 'Could not add IOC.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="modal-backdrop">
      <div className="modal" role="dialog" aria-labelledby="ioc-modal-title">
        <div className="modal-head">
          <h2 id="ioc-modal-title">Add indicator of compromise</h2>
          <button type="button" className="modal-close" onClick={onClose} disabled={busy} aria-label="Close">×</button>
        </div>
        <form onSubmit={onSubmit}>
          <div className="modal-body">
            <div className="form">
              <div className="form-row">
                <div className="field">
                  <label className="field-label" htmlFor="ioc-type">Type</label>
                  <select id="ioc-type" className="select" value={type} onChange={(e) => setType(e.target.value)}>
                    {IOC_TYPES.map(t => <option key={t.value} value={t.value}>{t.label}</option>)}
                  </select>
                </div>
                <div className="field">
                  <label className="field-label" htmlFor="ioc-source">Source (optional)</label>
                  <input id="ioc-source" className="input" value={source}
                    onChange={(e) => setSource(e.target.value)} maxLength={256} placeholder="manual" />
                </div>
              </div>
              <div className="field">
                <label className="field-label" htmlFor="ioc-value">Value</label>
                <input id="ioc-value" className="input" value={value}
                  onChange={(e) => setValue(e.target.value)}
                  autoFocus required maxLength={2048}
                  placeholder="e.g. 192.0.2.10 · evil.example.com · sha256 hash …"
                  style={{ fontFamily: 'var(--font-mono)' }}
                />
              </div>
              <div className="form-row">
                <div className="field">
                  <label className="field-label" htmlFor="ioc-entity">Linked entity (optional)</label>
                  <select id="ioc-entity" className="select" value={entityId}
                    onChange={(e) => setEntityId(e.target.value)}>
                    <option value="">— none —</option>
                    {entities.map(en => (
                      <option key={en.id} value={en.id}>{en.type}: {en.value}</option>
                    ))}
                  </select>
                </div>
                <div className="field" style={{ justifyContent: 'flex-end' }}>
                  <label className="field-label" style={{ visibility: 'hidden' }}>x</label>
                  <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer', fontSize: 13 }}>
                    <input type="checkbox" checked={malicious}
                      onChange={(e) => setMalicious(e.target.checked)} />
                    Mark as malicious
                  </label>
                </div>
              </div>
              <div className="form-row">
                <div className="field">
                  <label className="field-label" htmlFor="ioc-confidence">
                    Confidence — <span style={{ fontFamily: 'var(--font-mono)' }}>{confidence}</span>
                    <span style={{ color: 'var(--dim)', marginLeft: 6 }}>
                      ({confidence >= 70 ? 'High' : confidence >= 30 ? 'Medium' : 'Low'})
                    </span>
                  </label>
                  <input id="ioc-confidence" type="range" min={0} max={100} value={confidence}
                    onChange={(e) => setConfidence(Number(e.target.value))}
                    style={{ width: '100%' }} />
                </div>
                <div className="field">
                  <label className="field-label">Tags</label>
                  <TagInput value={tags} onChange={setTags} scope="ioc" placeholder="c2, apt29, lateral-movement…" />
                </div>
              </div>
              <div className="field">
                <label className="field-label" htmlFor="ioc-notes">Notes (optional)</label>
                <textarea id="ioc-notes" className="input" value={notes}
                  onChange={(e) => setNotes(e.target.value)} rows={3} maxLength={4096} />
              </div>
              {error && (
                <div className="alert error" role="alert">
                  <span className="alert-icon">!</span><span>{error}</span>
                </div>
              )}
            </div>
          </div>
          <div className="modal-foot">
            <button type="button" className="btn ghost" onClick={onClose} disabled={busy}>Cancel</button>
            <button type="submit" className="btn primary" disabled={busy}>
              {busy ? 'Adding…' : 'Add IOC'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

function EditIocModal({ incidentId, ioc, onClose, onSaved }) {
  const [notes, setNotes]             = useState(ioc.notes || '')
  const [malicious, setMalicious]     = useState(ioc.malicious ?? false)
  const [confidence, setConfidence]   = useState(ioc.confidence ?? 50)
  const [tags, setTags]               = useState(Array.isArray(ioc.tags) ? [...ioc.tags] : [])
  const [entityId, setEntityId]       = useState(ioc.entity_id || '')
  const [entities, setEntities]       = useState([])
  const [busy, setBusy]               = useState(false)
  const [error, setError]             = useState(null)

  useEffect(() => {
    api.listEntities(incidentId, { limit: 200 }).then(r => setEntities(r.items || [])).catch(() => {})
  }, [incidentId])

  useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape' && !busy) onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [busy, onClose])

  const onSubmit = async (e) => {
    e.preventDefault()
    setBusy(true); setError(null)
    try {
      await api.updateIoc(incidentId, ioc.id, {
        notes:      notes.trim() || null,
        malicious,
        confidence,
        tags:       normalizeTags(tags),
        entity_id:  entityId || null,
      })
      onSaved()
    } catch (err) {
      setError(err.message || 'Save failed.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="modal-backdrop">
      <div className="modal" role="dialog" aria-labelledby="edit-ioc-title" style={{ maxWidth: 480 }}>
        <div className="modal-head">
          <h2 id="edit-ioc-title">Edit IOC</h2>
          <button type="button" className="modal-close" onClick={onClose} disabled={busy} aria-label="Close">×</button>
        </div>
        <form onSubmit={onSubmit}>
          <div className="modal-body" style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--muted)', wordBreak: 'break-all' }}>
              <span className="pill" style={{ marginRight: 6 }}>{labelOf(ioc.type)}</span>
              {ioc.value}
            </div>
            <div className="field">
              <label className="field-label" htmlFor="eioc-entity">Linked entity</label>
              <select id="eioc-entity" className="select" value={entityId}
                onChange={(e) => setEntityId(e.target.value)}>
                <option value="">— none —</option>
                {entities.map(en => (
                  <option key={en.id} value={en.id}>{en.type}: {en.value}</option>
                ))}
              </select>
            </div>
            <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer', fontSize: 13 }}>
              <input type="checkbox" checked={malicious} onChange={(e) => setMalicious(e.target.checked)} />
              Mark as malicious
            </label>
            <div className="field">
              <label className="field-label" htmlFor="eioc-confidence">
                Confidence — <span style={{ fontFamily: 'var(--font-mono)' }}>{confidence}</span>
                <span style={{ color: 'var(--dim)', marginLeft: 6 }}>
                  ({confidence >= 70 ? 'High' : confidence >= 30 ? 'Medium' : 'Low'})
                </span>
              </label>
              <input id="eioc-confidence" type="range" min={0} max={100} value={confidence}
                onChange={(e) => setConfidence(Number(e.target.value))} style={{ width: '100%' }} />
            </div>
            <div className="field">
              <label className="field-label">Tags</label>
              <TagInput value={tags} onChange={setTags} scope="ioc" placeholder="c2, apt29, lateral-movement…" />
            </div>
            <div className="field">
              <label className="field-label" htmlFor="eioc-notes">Notes</label>
              <textarea id="eioc-notes" className="input" value={notes}
                onChange={(e) => setNotes(e.target.value)} rows={4} maxLength={4096} autoFocus />
            </div>
            {error && (
              <div className="alert error" role="alert">
                <span className="alert-icon">!</span><span>{error}</span>
              </div>
            )}
          </div>
          <div className="modal-foot">
            <button type="button" className="btn ghost" onClick={onClose} disabled={busy}>Cancel</button>
            <button type="submit" className="btn primary" disabled={busy}>
              {busy ? 'Saving…' : 'Save changes'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

function ExportModal({ incidentId, allIocs, onClose }) {
  const [downloading, setDownloading] = useState({})
  const [errors, setErrors]           = useState({})

  useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  const countFor = (platformId) =>
    allIocs.filter(i => PLATFORM_TYPES[platformId]?.has(i.type)).length

  const download = async (platformId) => {
    setDownloading(d => ({ ...d, [platformId]: true }))
    setErrors(e => ({ ...e, [platformId]: null }))
    try {
      await api.exportIocs(incidentId, platformId)
    } catch (err) {
      setErrors(e => ({ ...e, [platformId]: err.message || 'Download failed' }))
    } finally {
      setDownloading(d => ({ ...d, [platformId]: false }))
    }
  }

  return (
    <div
      className="modal-backdrop"
     
    >
      <div className="modal" role="dialog" aria-labelledby="export-modal-title" style={{ maxWidth: 640 }}>
        <div className="modal-head">
          <h2 id="export-modal-title">Export IOCs</h2>
          <button type="button" className="modal-close" onClick={onClose} aria-label="Close">×</button>
        </div>
        <div className="modal-body">
          <p style={{ color: 'var(--muted)', fontSize: 13, marginBottom: 'var(--space-3)' }}>
            Each platform receives only the IOC types it supports. The "Compatible" count
            reflects how many of the {allIocs.length} IOC{allIocs.length !== 1 ? 's' : ''} will
            be included in each file.
          </p>
          <table className="settings-table">
            <thead>
              <tr>
                <th>Platform</th>
                <th>Format</th>
                <th style={{ width: 80 }}>Compatible</th>
                <th className="actions">Download</th>
              </tr>
            </thead>
            <tbody>
              {PLATFORMS.map(p => {
                const count = countFor(p.id)
                const busy  = downloading[p.id]
                const err   = errors[p.id]
                return (
                  <tr key={p.id}>
                    <td>
                      <div style={{ fontWeight: 500 }}>{p.label}</div>
                      <div style={{ fontSize: 11, color: 'var(--dim)' }}>{p.types}</div>
                    </td>
                    <td style={{ fontSize: 12, color: 'var(--muted)' }}>{p.sub}</td>
                    <td style={{ textAlign: 'center' }}>
                      <span
                        style={{
                          fontFamily: 'var(--font-mono)',
                          fontSize: 13,
                          color: count > 0 ? 'var(--ok)' : 'var(--dim)',
                          fontWeight: count > 0 ? 600 : 400,
                        }}
                      >
                        {count}
                      </span>
                    </td>
                    <td className="actions" style={{ flexDirection: 'column', alignItems: 'flex-end', gap: 2 }}>
                      <button
                        type="button"
                        className="btn ghost"
                        onClick={() => download(p.id)}
                        disabled={busy || count === 0}
                        title={count === 0 ? 'No compatible IOCs for this platform' : `Download ${p.sub}`}
                        style={{ fontSize: 12 }}
                      >
                        {busy ? 'Downloading…' : 'Download'}
                      </button>
                      {err && (
                        <div style={{ fontSize: 11, color: 'var(--crit)', textAlign: 'right' }}>{err}</div>
                      )}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
        <div className="modal-foot">
          <button type="button" className="btn ghost" onClick={onClose}>Close</button>
        </div>
      </div>
    </div>
  )
}

// ─── Correlation detail modal ─────────────────────────────────────────────────

const PHASE_SHORT = {
  preparation:                      'Prep',
  detection_and_analysis:           'Detect',
  containment_eradication_recovery: 'C/E/R',
  post_incident:                    'Post',
}

const SEV_PILL = {
  low:      'pill-low',
  medium:   'pill-med',
  high:     'pill-high',
  critical: 'pill-crit',
}

function CorrelationModal({ ioc, incidents, onClose }) {
  useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  return (
    <div
      className="modal-backdrop"
     
    >
      <div className="modal" role="dialog" aria-labelledby="corr-modal-title" style={{ maxWidth: 560 }}>
        <div className="modal-head">
          <h2 id="corr-modal-title">Also seen in {incidents.length} incident{incidents.length !== 1 ? 's' : ''}</h2>
          <button type="button" className="modal-close" onClick={onClose} aria-label="Close">×</button>
        </div>
        <div className="modal-body">
          <p style={{ color: 'var(--muted)', fontSize: 13, marginBottom: 'var(--space-3)', fontFamily: 'var(--font-mono)' }}>
            {labelOf(ioc.type)}: {ioc.value}
          </p>
          <table className="settings-table">
            <thead>
              <tr>
                <th>Incident</th>
                <th style={{ width: 80 }}>Severity</th>
                <th style={{ width: 70 }}>Phase</th>
                <th style={{ width: 80, textAlign: 'right' }}>Open</th>
              </tr>
            </thead>
            <tbody>
              {incidents.map(inc => (
                <tr key={inc.id}>
                  <td style={{ maxWidth: 260, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {inc.ref && <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--accent)', marginRight: 6 }}>{inc.ref}</span>}
                    {inc.title}
                  </td>
                  <td>
                    {inc.severity
                      ? <span className={`pill ${SEV_PILL[inc.severity] || ''}`} style={{ fontSize: 10 }}>{inc.severity}</span>
                      : <span style={{ color: 'var(--dim)' }}>—</span>}
                  </td>
                  <td>
                    <span className="pill" style={{ fontSize: 10, background: 'var(--surface-2)', color: 'var(--muted)' }}>
                      {PHASE_SHORT[inc.phase] || inc.phase || '—'}
                    </span>
                  </td>
                  <td className="actions">
                    <Link
                      to={`/incidents/${inc.id}/forensic/iocs`}
                      className="btn ghost"
                      style={{ fontSize: 11, padding: '2px 8px' }}
                      onClick={onClose}
                    >
                      View ›
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="modal-foot">
          <button type="button" className="btn ghost" onClick={onClose}>Close</button>
        </div>
      </div>
    </div>
  )
}
