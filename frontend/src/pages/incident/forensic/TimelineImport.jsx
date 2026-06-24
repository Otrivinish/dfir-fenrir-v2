import { useRef, useState, useMemo, useEffect, useCallback } from 'react'
import { useOutletContext, useSearchParams } from 'react-router-dom'
import { api } from '../../../api/client.js'
import { formatLocalShort, formatLocal } from '../../../lib/datetime.js'
import { tacticColor } from '../../../lib/mitre.js'
import { detectNode, detectForest, severityColor } from '../../../lib/processTreeDetect.js'

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

const ACCEPTED = '.evtx,.xml,.db,.sqlite,.csv,.tsv,.json,.jsonl,.log'
const MAX_MB = 100

// ─── Main ────────────────────────────────────────────────────────────────────

export default function TimelineImport() {
  const { inc } = useOutletContext()
  const isClosed = inc?.status === 'closed'
  const fileRef = useRef(null)

  const [file, setFile]                 = useState(null)
  const [dragging, setDragging]         = useState(false)
  const [parsing, setParsing]           = useState(false)
  const [parseError, setParseError]     = useState(null)
  const [result, setResult]             = useState(null)   // ForensicParseResponse (with .import_id when persisted)
  const [selected, setSelected]         = useState(new Set())
  const [filterText, setFilterText]     = useState('')
  const [filterSuspicious, setFilterSuspicious] = useState(false)
  const [filterSource, setFilterSource] = useState('')
  const [promoting, setPromoting]       = useState(false)
  const [promoteMsg, setPromoteMsg]     = useState(null)
  const [iocTarget, setIocTarget]       = useState(null)   // ParsedEventOut | null
  const [iocBulkOpen, setIocBulkOpen]   = useState(false)  // bulk add-to-IOCs modal
  const [viewMode, setViewMode]         = useState('table') // 'table' | 'tree'

  // Persisted imports — listed on mount; refreshes after each upload/dispose.
  const [imports, setImports]           = useState([])
  const [importsLoading, setImportsLoading] = useState(true)
  const [activeImportId, setActiveImportId] = useState(null)

  const loadImports = useCallback(async () => {
    try {
      const r = await api.listForensicImports(inc.id)
      setImports(r?.items || [])
    } catch (e) {
      // Non-fatal — list just stays empty.
      // eslint-disable-next-line no-console
      console.warn('Failed to list forensic imports:', e?.message)
    } finally {
      setImportsLoading(false)
    }
  }, [inc.id])

  useEffect(() => { loadImports() }, [loadImports])

  // Deep-link target: /forensic/timeline-import?artifact=<id> (from Collections).
  // Consume the param once so a refresh doesn't re-import.
  const [searchParams, setSearchParams] = useSearchParams()
  useEffect(() => {
    const aid = searchParams.get('artifact')
    if (!aid) return
    searchParams.delete('artifact')
    setSearchParams(searchParams, { replace: true })
    importFromArtifact(aid)
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const events  = result?.events || []
  const sources = useMemo(() => [...new Set(events.map(e => e.source).filter(Boolean))], [events])

  const visible = useMemo(() => events.filter(e => {
    if (filterSuspicious && !e.suspicious) return false
    if (filterSource && e.source !== filterSource) return false
    if (filterText) {
      const q = filterText.toLowerCase()
      return (
        e.description?.toLowerCase().includes(q) ||
        e.hostname?.toLowerCase().includes(q) ||
        e.source?.toLowerCase().includes(q) ||
        e.event_type?.toLowerCase().includes(q) ||
        (e.mitre_technique_name || '').toLowerCase().includes(q)
      )
    }
    return true
  }), [events, filterSuspicious, filterSource, filterText])

  const selectedVisible = visible.filter(e => selected.has(e.idx))
  const allVisibleSelected = visible.length > 0 && visible.every(e => selected.has(e.idx))

  // ── File pick ──────────────────────────────────────────────────────────────

  function pickFile(f) {
    if (!f) return
    if (f.size > MAX_MB * 1024 * 1024) {
      setParseError(`File is ${Math.round(f.size / (1024 * 1024))} MB — exceeds ${MAX_MB} MB limit.`)
      return
    }
    setFile(f)
    setParseError(null)
    setResult(null)
    setSelected(new Set())
    setPromoteMsg(null)
  }

  function onDrop(e) {
    e.preventDefault()
    setDragging(false)
    const f = e.dataTransfer.files[0]
    if (f) pickFile(f)
  }

  // ── Parse & save ──────────────────────────────────────────────────────────
  // Upload + parse + persist in one call. Refresh dies → reload past imports.

  async function onParse() {
    if (!file) return
    setParsing(true)
    setParseError(null)
    setResult(null)
    setSelected(new Set())
    setPromoteMsg(null)
    setActiveImportId(null)
    try {
      const detail = await api.createForensicImport(inc.id, file)
      // detail shape: ForensicImportDetail — same as ParseResponse + id + metadata.
      setResult({
        source_file:      detail.filename,
        detected_format:  detail.detected_format,
        count:            detail.event_count,
        suspicious_count: detail.suspicious_count,
        events:           detail.events,
        import_id:        detail.id,
      })
      setActiveImportId(detail.id)
      await loadImports()
      // Clear the staged file so the dropzone resets — the upload is now saved.
      setFile(null)
    } catch (e) {
      setParseError(e.message || 'Upload failed.')
    } finally {
      setParsing(false)
    }
  }

  // ── Load a past import (persisted) ────────────────────────────────────────

  async function loadImport(importId) {
    setParsing(true)
    setParseError(null)
    setSelected(new Set())
    setPromoteMsg(null)
    try {
      const detail = await api.getForensicImport(inc.id, importId)
      setResult({
        source_file:      detail.filename,
        detected_format:  detail.detected_format,
        count:            detail.event_count,
        suspicious_count: detail.suspicious_count,
        events:           detail.events,
        import_id:        detail.id,
      })
      setActiveImportId(detail.id)
      setFile(null)
    } catch (e) {
      setParseError(e.message || 'Load failed.')
    } finally {
      setParsing(false)
    }
  }

  // ── Deep-link from Collections: parse an ingested collection artifact ──────
  async function importFromArtifact(artifactId) {
    setParsing(true)
    setParseError(null)
    setSelected(new Set())
    setPromoteMsg(null)
    try {
      const detail = await api.importForensicFromArtifact(inc.id, artifactId)
      setResult({
        source_file:      detail.filename,
        detected_format:  detail.detected_format,
        count:            detail.event_count,
        suspicious_count: detail.suspicious_count,
        events:           detail.events,
        import_id:        detail.id,
      })
      setActiveImportId(detail.id)
      setFile(null)
      await loadImports()
    } catch (e) {
      setParseError(e.message || 'Could not parse the collection.')
    } finally {
      setParsing(false)
    }
  }

  async function disposeImport(imp) {
    if (!confirm(
      `Dispose "${imp.filename}"?\n\n` +
      `${imp.event_count} parsed event(s) will be removed from this incident.\n` +
      `Events already promoted to the timeline are not affected. Audit-logged.`
    )) return
    try {
      await api.deleteForensicImport(inc.id, imp.id)
      if (activeImportId === imp.id) {
        setResult(null)
        setActiveImportId(null)
        setSelected(new Set())
      }
      await loadImports()
    } catch (e) {
      setParseError(e.message || 'Dispose failed.')
    }
  }

  // ── Selection ──────────────────────────────────────────────────────────────

  function toggleRow(idx) {
    setSelected(prev => {
      const next = new Set(prev)
      next.has(idx) ? next.delete(idx) : next.add(idx)
      return next
    })
  }

  function toggleAllVisible() {
    if (allVisibleSelected) {
      setSelected(prev => {
        const next = new Set(prev)
        visible.forEach(e => next.delete(e.idx))
        return next
      })
    } else {
      setSelected(prev => {
        const next = new Set(prev)
        visible.forEach(e => next.add(e.idx))
        return next
      })
    }
  }

  // ── Promote to timeline ────────────────────────────────────────────────────

  async function onPromote() {
    if (!selectedVisible.length || promoting || isClosed) return
    const NOW = new Date().toISOString()
    const noTs = selectedVisible.filter(e => !e.event_time)

    const confirmed = window.confirm(
      `Add ${selectedVisible.length} event${selectedVisible.length !== 1 ? 's' : ''} to the incident timeline?` +
      (noTs.length ? `\n\n${noTs.length} event${noTs.length !== 1 ? 's' : ''} have no timestamp and will use the current time.` : '')
    )
    if (!confirmed) return

    setPromoting(true)
    setPromoteMsg(null)
    try {
      const res = await api.batchCreateTimelineEvents(inc.id, {
        events: selectedVisible.map(e => ({
          event_time:          e.event_time || NOW,
          hostname:            e.hostname   || null,
          source:              e.source     || null,
          event_type:          e.event_type || null,
          description:         e.description,
          raw_log:             e.raw_log    || null,
          ir_phase:            null,
          mitre_tactic_id:     e.mitre_tactic_id     || null,
          mitre_tactic_name:   e.mitre_tactic_name   || null,
          mitre_technique_id:  e.mitre_technique_id  || null,
          mitre_technique_name:e.mitre_technique_name || null,
        })),
      })
      const msg = `Added ${res.created} event${res.created !== 1 ? 's' : ''} to the timeline.` +
        (res.errors.length ? ` ${res.errors.length} failed.` : '')
      setPromoteMsg({ kind: 'ok', text: msg })
      setSelected(prev => {
        const next = new Set(prev)
        selectedVisible.forEach(e => next.delete(e.idx))
        return next
      })
    } catch (e) {
      setPromoteMsg({ kind: 'err', text: e.message || 'Promote failed.' })
    } finally {
      setPromoting(false)
    }
  }

  // ─────────────────────────────────────────────────────────────────────────

  return (
    <section className="panel">
      {/* Header */}
      <div className="panel-toolbar">
        <h2 className="panel-h">Timeline Import</h2>
        <span style={{ color: 'var(--muted)', fontSize: 13 }}>
          Parse artifact → triage → promote to timeline
        </span>
      </div>

      {/* Saved imports — persisted server-side; survives refresh, can be disposed. */}
      {!importsLoading && imports.length > 0 && (
        <div style={{
          border: '1px solid var(--border)',
          borderRadius: 'var(--radius)',
          background: 'var(--surface)',
          marginBottom: 'var(--space-3)',
        }}>
          <div style={{
            padding: 'var(--space-2) var(--space-3)',
            borderBottom: '1px solid var(--border)',
            fontSize: 11, fontWeight: 700, color: 'var(--muted)',
            textTransform: 'uppercase', letterSpacing: '0.08em',
            display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          }}>
            <span>Saved imports ({imports.length})</span>
            <span style={{ fontWeight: 400, textTransform: 'none', letterSpacing: 0, color: 'var(--dim)' }}>
              Click a row to re-load · × to dispose (audit-logged)
            </span>
          </div>
          <div>
            {imports.map(imp => {
              const isActive = activeImportId === imp.id
              return (
                <div
                  key={imp.id}
                  onClick={() => !isActive && loadImport(imp.id)}
                  style={{
                    display: 'flex', alignItems: 'center', gap: 'var(--space-2)',
                    padding: 'var(--space-2) var(--space-3)',
                    borderBottom: '1px solid var(--border)',
                    background: isActive ? 'var(--accent-soft)' : 'transparent',
                    cursor: isActive ? 'default' : 'pointer',
                    fontSize: 12,
                  }}
                >
                  <span style={{
                    fontFamily: 'var(--font-mono)',
                    color: isActive ? 'var(--accent)' : 'var(--text)',
                    flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                  }} title={imp.filename}>{imp.filename}</span>
                  <span style={{ color: 'var(--dim)', fontFamily: 'var(--font-mono)' }}>
                    {imp.detected_format || '—'}
                  </span>
                  <span style={{ color: 'var(--muted)' }}>
                    {imp.event_count} ev
                  </span>
                  {imp.suspicious_count > 0 && (
                    <span style={{ color: 'var(--crit)', fontWeight: 700 }} title={`${imp.suspicious_count} suspicious`}>
                      ⚠ {imp.suspicious_count}
                    </span>
                  )}
                  <span style={{
                    color: 'var(--dim)', fontSize: 11, fontFamily: 'var(--font-mono)',
                    whiteSpace: 'nowrap',
                  }} title={formatLocal(imp.uploaded_at)}>
                    {formatLocalShort(imp.uploaded_at)}
                  </span>
                  {imp.uploaded_by && (
                    <span style={{ color: 'var(--dim)', fontSize: 11 }}>{imp.uploaded_by}</span>
                  )}
                  <button
                    type="button"
                    onClick={(e) => { e.stopPropagation(); disposeImport(imp) }}
                    disabled={isClosed}
                    title={isClosed ? 'Closed incidents are read-only' : 'Dispose this import (audit-logged)'}
                    style={{
                      background: 'transparent', border: '1px solid var(--border)',
                      color: 'var(--crit)', borderRadius: 'var(--radius-sm)',
                      padding: '2px 8px', fontSize: 11, cursor: isClosed ? 'not-allowed' : 'pointer',
                    }}
                  >× dispose</button>
                </div>
              )
            })}
          </div>
        </div>
      )}

      {/* Drop zone */}
      <div
        role="button"
        tabIndex={0}
        aria-label="Drop artifact file here or click to choose"
        className={`dropzone${dragging ? ' dragover' : ''}`}
        onClick={() => fileRef.current?.click()}
        onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') fileRef.current?.click() }}
        onDragOver={(e) => { e.preventDefault(); setDragging(true) }}
        onDragLeave={() => setDragging(false)}
        onDrop={onDrop}
        style={{
          border: `2px dashed var(--border${dragging ? '-strong' : ''})`,
          borderRadius: 'var(--radius)',
          padding: 'var(--space-5) var(--space-4)',
          textAlign: 'center',
          cursor: 'pointer',
          color: 'var(--muted)',
          fontSize: 14,
          marginBottom: 'var(--space-3)',
          background: dragging ? 'var(--surface-2)' : 'transparent',
          transition: 'background 0.12s, border-color 0.12s',
        }}
      >
        <input
          ref={fileRef}
          type="file"
          accept={ACCEPTED}
          style={{ display: 'none' }}
          onChange={(e) => pickFile(e.target.files[0])}
        />
        {file ? (
          <span>
            <span style={{ color: 'var(--text)', fontFamily: 'var(--font-mono)', fontSize: 13 }}>
              {file.name}
            </span>
            {' '}
            <span style={{ color: 'var(--dim)', fontSize: 12 }}>
              ({(file.size / 1024).toFixed(0)} KB)
            </span>
          </span>
        ) : (
          <>
            <div style={{ fontSize: 28, marginBottom: 'var(--space-2)' }} aria-hidden="true">⊕</div>
            <div>Drop an artifact here or click to choose</div>
            <div style={{ fontSize: 12, color: 'var(--dim)', marginTop: 'var(--space-1)' }}>
              EVTX · Windows XML · SQLite · CSV/TSV · JSON/JSONL · syslog/auth.log · journald JSON · macOS Unified Log — up to {MAX_MB} MB
            </div>
          </>
        )}
      </div>

      {/* Parse button */}
      {file && !parsing && (
        <div style={{ display: 'flex', gap: 'var(--space-2)', marginBottom: 'var(--space-3)' }}>
          <button
            type="button"
            className="btn primary"
            onClick={onParse}
            disabled={isClosed}
            title={isClosed ? 'Closed incidents are read-only — re-open the incident to import' : 'Parse the file and save events to this incident'}
          >
            Parse &amp; save
          </button>
          <button
            type="button"
            className="btn ghost"
            onClick={() => { setFile(null); setResult(null); setParseError(null); setPromoteMsg(null) }}
          >
            Clear
          </button>
        </div>
      )}

      {parsing && (
        <div className="panel-empty"><div style={{ color: 'var(--muted)' }}>Parsing…</div></div>
      )}

      {parseError && (
        <div className="alert error" role="alert" style={{ marginBottom: 'var(--space-3)' }}>
          <span className="alert-icon">!</span><span>{parseError}</span>
        </div>
      )}

      {/* Summary bar */}
      {result && (
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 'var(--space-3)',
            padding: 'var(--space-2) var(--space-3)',
            background: 'var(--surface-2)',
            borderRadius: 'var(--radius)',
            marginBottom: 'var(--space-3)',
            fontSize: 13,
            flexWrap: 'wrap',
          }}
        >
          <span>
            <span style={{ color: 'var(--muted)' }}>Format: </span>
            <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--accent)' }}>{result.detected_format}</span>
          </span>
          <span>
            <span style={{ color: 'var(--muted)' }}>Events: </span>
            <strong>{result.count}</strong>
          </span>
          {result.suspicious_count > 0 && (
            <span>
              <span style={{ color: 'var(--muted)' }}>Suspicious: </span>
              <strong style={{ color: 'var(--crit)' }}>{result.suspicious_count}</strong>
            </span>
          )}
          <span style={{ color: 'var(--dim)', fontSize: 12 }}>{result.source_file}</span>
        </div>
      )}

      {/* Promote message */}
      {promoteMsg && (
        <div
          className={`alert ${promoteMsg.kind === 'ok' ? 'info' : 'error'}`}
          role="alert"
          style={{ marginBottom: 'var(--space-3)' }}
        >
          <span className="alert-icon">{promoteMsg.kind === 'ok' ? '✓' : '!'}</span>
          <span>{promoteMsg.text}</span>
        </div>
      )}

      {/* Triage table */}
      {result && events.length > 0 && (
        <>
          {/* Filter row */}
          <div
            style={{
              display: 'flex',
              gap: 'var(--space-2)',
              marginBottom: 'var(--space-2)',
              flexWrap: 'wrap',
              alignItems: 'center',
            }}
          >
            <input
              type="search"
              className="input"
              placeholder="Filter events…"
              value={filterText}
              onChange={(e) => setFilterText(e.target.value)}
              style={{ flex: '1 1 200px', maxWidth: 340 }}
            />
            {sources.length > 0 && (
              <select
                className="select"
                value={filterSource}
                onChange={(e) => setFilterSource(e.target.value)}
                aria-label="Filter by source"
              >
                <option value="">All sources</option>
                {sources.map(s => <option key={s} value={s}>{s}</option>)}
              </select>
            )}
            <label
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 'var(--space-1)',
                cursor: 'pointer',
                fontSize: 13,
                color: 'var(--text)',
                userSelect: 'none',
              }}
            >
              <input
                type="checkbox"
                checked={filterSuspicious}
                onChange={(e) => setFilterSuspicious(e.target.checked)}
              />
              Suspicious only
              {result.suspicious_count > 0 && (
                <span style={{ color: 'var(--crit)', fontSize: 12 }}>({result.suspicious_count})</span>
              )}
            </label>
            <div style={{ display: 'flex', gap: 4, marginLeft: 'auto', alignItems: 'center' }}>
              <span style={{ color: 'var(--dim)', fontSize: 12 }}>
                {visible.length} of {events.length} shown
              </span>
              <div style={{ display: 'flex', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', marginLeft: 'var(--space-2)' }}>
                <button
                  type="button"
                  onClick={() => setViewMode('table')}
                  style={{
                    fontSize: 11, padding: '3px 8px',
                    background: viewMode === 'table' ? 'var(--accent-soft)' : 'transparent',
                    color: viewMode === 'table' ? 'var(--accent)' : 'var(--muted)',
                    border: 'none', cursor: 'pointer',
                  }}
                >Table</button>
                <button
                  type="button"
                  onClick={() => setViewMode('tree')}
                  title="Process tree (rebuilt from PID / parent PID in Sysmon/process-creation events)"
                  style={{
                    fontSize: 11, padding: '3px 8px',
                    background: viewMode === 'tree' ? 'var(--accent-soft)' : 'transparent',
                    color: viewMode === 'tree' ? 'var(--accent)' : 'var(--muted)',
                    border: 'none', borderLeft: '1px solid var(--border)', cursor: 'pointer',
                  }}
                >Process tree</button>
              </div>
            </div>
          </div>

          {/* Selection action bar */}
          {selectedVisible.length > 0 && (
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 'var(--space-3)',
                padding: 'var(--space-2) var(--space-3)',
                background: 'var(--accent-soft)',
                borderRadius: 'var(--radius)',
                marginBottom: 'var(--space-2)',
                fontSize: 13,
              }}
            >
              <span style={{ color: 'var(--text)' }}>
                {selectedVisible.length} event{selectedVisible.length !== 1 ? 's' : ''} selected
              </span>
              <button
                type="button"
                className="btn primary"
                onClick={onPromote}
                disabled={promoting || isClosed}
              >
                {promoting ? 'Adding…' : `Add ${selectedVisible.length} to Timeline`}
              </button>
              <button
                type="button"
                className="btn"
                onClick={() => setIocBulkOpen(true)}
                disabled={promoting || isClosed}
                title={isClosed ? 'Closed incidents are read-only' : 'Add the selected events as IOCs'}
              >
                {`Add ${selectedVisible.length} to IOCs`}
              </button>
              <button
                type="button"
                className="btn ghost"
                onClick={() => setSelected(new Set())}
                disabled={promoting}
              >
                Clear selection
              </button>
            </div>
          )}

          {viewMode === 'table' && (
            <div style={{ overflowX: 'auto' }}>
              <table className="settings-table">
                <thead>
                  <tr>
                    <th style={{ width: 32 }}>
                      <input
                        type="checkbox"
                        checked={allVisibleSelected}
                        onChange={toggleAllVisible}
                        aria-label="Select all visible"
                        title="Select all visible"
                      />
                    </th>
                    <th style={{ width: 24 }} aria-label="Suspicious" title="Suspicious">⚠</th>
                    <th style={{ width: 140 }}>Timestamp</th>
                    <th style={{ width: 100 }}>Source</th>
                    <th style={{ width: 130 }}>Hostname</th>
                    <th style={{ width: 110 }}>Event type</th>
                    <th>Description</th>
                    <th style={{ width: 130 }}>MITRE</th>
                    <th className="actions" style={{ width: 60 }}>IOC</th>
                  </tr>
                </thead>
                <tbody>
                  {visible.map(e => (
                    <TriageRow
                      key={e.idx}
                      event={e}
                      checked={selected.has(e.idx)}
                      onToggle={() => toggleRow(e.idx)}
                      onIoc={() => setIocTarget(e)}
                      isClosed={isClosed}
                    />
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {viewMode === 'tree' && (
            <ProcessTreeView
              events={visible}
              selected={selected}
              onSelectSubtree={(idxs) => {
                setSelected(prev => {
                  const next = new Set(prev)
                  for (const i of idxs) next.add(i)
                  return next
                })
              }}
            />
          )}

          {visible.length === 0 && (
            <div className="panel-empty">
              <div>No events match the current filters.</div>
            </div>
          )}
        </>
      )}

      {result && events.length === 0 && (
        <div className="panel-empty">
          <div className="panel-empty-mark" aria-hidden="true">◌</div>
          <div>No events extracted from this artifact.</div>
        </div>
      )}

      {iocTarget && (
        <IocQuickModal
          incidentId={inc.id}
          event={iocTarget}
          onClose={() => setIocTarget(null)}
          onCreated={() => setIocTarget(null)}
        />
      )}

      {iocBulkOpen && (
        <BulkIocModal
          incidentId={inc.id}
          events={selectedVisible}
          onClose={() => setIocBulkOpen(false)}
          onDone={(msg) => {
            setIocBulkOpen(false)
            setPromoteMsg(msg)
            setSelected(new Set())
          }}
        />
      )}
    </section>
  )
}

// ─── Triage row ───────────────────────────────────────────────────────────────

function TriageRow({ event: e, checked, onToggle, onIoc, isClosed }) {
  const [expanded, setExpanded] = useState(false)
  const tacticId = e.mitre_tactic_id
  const color = tacticId ? tacticColor(tacticId) : 'var(--muted)'

  return (
    <>
      <tr
        style={{ background: e.suspicious ? 'color-mix(in srgb, var(--crit) 6%, transparent)' : undefined }}
        onClick={() => setExpanded(x => !x)}
      >
        <td onClick={(ev) => ev.stopPropagation()}>
          <input type="checkbox" checked={checked} onChange={onToggle} />
        </td>
        <td>
          {e.suspicious && (
            <span
              title={e.suspicious_reasons?.join('\n') || 'Suspicious'}
              style={{ color: 'var(--crit)', cursor: 'help', fontSize: 14 }}
              aria-label="Suspicious"
            >
              ⚠
            </span>
          )}
        </td>
        <td
          title={e.event_time ? formatLocal(e.event_time) : 'No timestamp'}
          style={{ fontFamily: 'var(--font-mono)', fontSize: 11, whiteSpace: 'nowrap' }}
        >
          {e.event_time ? formatLocalShort(e.event_time) : <span style={{ color: 'var(--dim)' }}>—</span>}
        </td>
        <td style={{ fontSize: 12, color: 'var(--muted)' }}>{e.source || '—'}</td>
        <td
          style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--muted)' }}
          title={e.hostname || ''}
        >
          {e.hostname || '—'}
        </td>
        <td style={{ fontSize: 12 }}>{e.event_type || '—'}</td>
        <td
          style={{ fontSize: 13, maxWidth: 400, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', cursor: 'pointer' }}
          title={expanded ? undefined : e.description}
        >
          {e.description}
        </td>
        <td>
          {tacticId ? (
            <span
              className="pill"
              style={{
                background: `color-mix(in srgb, ${color} 18%, transparent)`,
                color,
                border: `1px solid color-mix(in srgb, ${color} 40%, transparent)`,
                fontSize: 11,
                fontFamily: 'var(--font-mono)',
              }}
              title={`${e.mitre_tactic_name || tacticId}${e.mitre_technique_id ? ` / ${e.mitre_technique_id} ${e.mitre_technique_name || ''}` : ''}`}
            >
              {tacticId}
            </span>
          ) : '—'}
        </td>
        <td className="actions" onClick={(ev) => ev.stopPropagation()}>
          <button
            type="button"
            className="btn ghost"
            style={{ fontSize: 12, padding: '2px 6px' }}
            onClick={onIoc}
            disabled={isClosed}
            title={isClosed ? 'Closed incidents are read-only' : 'Add as IOC'}
          >
            + IOC
          </button>
        </td>
      </tr>
      {expanded && (
        <tr>
          <td colSpan={9} style={{ paddingTop: 0, paddingBottom: 'var(--space-2)' }}>
            <div
              style={{
                padding: 'var(--space-2)',
                background: 'var(--surface-2)',
                borderRadius: 'var(--radius-sm)',
                fontSize: 12,
              }}
            >
              {e.mitre_technique_id && (
                <div style={{ marginBottom: 'var(--space-1)', color: 'var(--muted)' }}>
                  <strong>Technique:</strong>{' '}
                  {e.mitre_technique_id} — {e.mitre_technique_name || ''}
                </div>
              )}
              {e.suspicious_reasons?.length > 0 && (
                <div style={{ marginBottom: 'var(--space-1)', color: 'var(--crit)' }}>
                  <strong>Why suspicious:</strong> {e.suspicious_reasons.join(' · ')}
                </div>
              )}
              {e.raw_log && (
                <pre
                  style={{
                    margin: 0,
                    fontFamily: 'var(--font-mono)',
                    fontSize: 11,
                    color: 'var(--muted)',
                    whiteSpace: 'pre-wrap',
                    wordBreak: 'break-all',
                    maxHeight: 200,
                    overflow: 'auto',
                  }}
                >
                  {e.raw_log}
                </pre>
              )}
            </div>
          </td>
        </tr>
      )}
    </>
  )
}

// ─── IOC quick-add modal ──────────────────────────────────────────────────────

function IocQuickModal({ incidentId, event, onClose, onCreated }) {
  const [type,  setType]  = useState('other')
  const [value, setValue] = useState(event.description.slice(0, 512))
  const [notes, setNotes] = useState(
    event.raw_log ? event.raw_log.slice(0, 512) : ''
  )
  const [busy,  setBusy]  = useState(false)
  const [error, setError] = useState(null)

  const onSubmit = async (e) => {
    e.preventDefault()
    const v = value.trim()
    if (!v) { setError('Value is required.'); return }
    setError(null)
    setBusy(true)
    try {
      await api.createIoc(incidentId, {
        type,
        value:  v,
        notes:  notes.trim() || null,
        source: event.source || null,
      })
      onCreated()
    } catch (err) {
      setError(err.message || 'Could not add IOC.')
      setBusy(false)
    }
  }

  return (
    <div className="modal-backdrop">
      <div className="modal" role="dialog" aria-labelledby="iocq-title" style={{ maxWidth: 480 }}>
        <div className="modal-head">
          <h2 id="iocq-title">Add as IOC</h2>
          <button type="button" className="modal-close" onClick={onClose} disabled={busy} aria-label="Close">×</button>
        </div>
        <form onSubmit={onSubmit}>
          <div className="modal-body">
            {error && (
              <div className="alert error" style={{ marginBottom: 'var(--space-3)' }}>
                <span className="alert-icon">!</span><span>{error}</span>
              </div>
            )}
            <div className="form">
              <div className="form-row">
                <div className="field">
                  <label className="field-label" htmlFor="iocq-type">Type</label>
                  <select id="iocq-type" className="select" value={type} onChange={(e) => setType(e.target.value)}>
                    {IOC_TYPES.map(t => <option key={t.value} value={t.value}>{t.label}</option>)}
                  </select>
                </div>
              </div>
              <div className="field">
                <label className="field-label" htmlFor="iocq-value">Value</label>
                <input
                  id="iocq-value"
                  autoFocus
                  className="input"
                  value={value}
                  onChange={(e) => setValue(e.target.value)}
                  maxLength={2048}
                  required
                  style={{ fontFamily: 'var(--font-mono)' }}
                />
              </div>
              <div className="field">
                <label className="field-label" htmlFor="iocq-notes">Notes (optional)</label>
                <textarea
                  id="iocq-notes"
                  className="input"
                  value={notes}
                  onChange={(e) => setNotes(e.target.value)}
                  rows={3}
                  maxLength={4096}
                />
              </div>
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

// ─── Bulk add-to-IOCs modal ───────────────────────────────────────────────────
// Parsed events carry no extracted indicator, so the analyst picks one IOC type
// and which field becomes the value (description / hostname / source); one IOC is
// created per selected event that has a value for that field. Duplicates skipped.

const VALUE_FIELDS = [
  { key: 'description', label: 'Description' },
  { key: 'hostname',    label: 'Hostname' },
  { key: 'source',      label: 'Source' },
]

function BulkIocModal({ incidentId, events, onClose, onDone }) {
  const [type, setType]           = useState('other')
  const [valueField, setValueField] = useState('description')
  const [busy, setBusy]           = useState(false)
  const [error, setError]         = useState(null)

  useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape' && !busy) onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [busy, onClose])

  // Events that actually have a value for the chosen field.
  const items = events
    .map(e => (e[valueField] || '').trim())
    .filter(Boolean)
    .map(v => ({ type, value: v.slice(0, 2048) }))
  const eligible = items.length
  const skippedNoValue = events.length - eligible

  const onSubmit = async (e) => {
    e.preventDefault()
    if (!eligible) { setError(`No selected events have a ${valueField}.`); return }
    setBusy(true); setError(null)
    try {
      const res = await api.batchCreateIocs(incidentId, { items })
      const parts = [`Added ${res.created} IOC${res.created !== 1 ? 's' : ''}`]
      if (res.skipped)            parts.push(`${res.skipped} duplicate${res.skipped !== 1 ? 's' : ''} skipped`)
      if (skippedNoValue)         parts.push(`${skippedNoValue} had no ${valueField}`)
      if (res.errors?.length)     parts.push(`${res.errors.length} failed`)
      onDone({ kind: res.created ? 'ok' : 'err', text: parts.join(' · ') + '.' })
    } catch (err) {
      setError(err.message || 'Bulk add failed.')
      setBusy(false)
    }
  }

  return (
    <div className="modal-backdrop">
      <div className="modal" role="dialog" aria-labelledby="bulkioc-title" style={{ maxWidth: 480 }}>
        <div className="modal-head">
          <h2 id="bulkioc-title">Add {events.length} event{events.length !== 1 ? 's' : ''} as IOCs</h2>
          <button type="button" className="modal-close" onClick={onClose} disabled={busy} aria-label="Close">×</button>
        </div>
        <form onSubmit={onSubmit}>
          <div className="modal-body">
            {error && (
              <div className="alert error" style={{ marginBottom: 'var(--space-3)' }}>
                <span className="alert-icon">!</span><span>{error}</span>
              </div>
            )}
            <div className="form">
              <div className="form-row">
                <div className="field">
                  <label className="field-label" htmlFor="bulkioc-type">Type (applied to all)</label>
                  <select id="bulkioc-type" className="select" value={type} onChange={(e) => setType(e.target.value)}>
                    {IOC_TYPES.map(t => <option key={t.value} value={t.value}>{t.label}</option>)}
                  </select>
                </div>
                <div className="field">
                  <label className="field-label" htmlFor="bulkioc-field">Value from</label>
                  <select id="bulkioc-field" className="select" value={valueField} onChange={(e) => setValueField(e.target.value)}>
                    {VALUE_FIELDS.map(f => <option key={f.key} value={f.key}>{f.label}</option>)}
                  </select>
                </div>
              </div>
              <div className="field-hint">
                {eligible} of {events.length} selected event{events.length !== 1 ? 's' : ''} have a {valueField} and will be added
                {skippedNoValue ? ` (${skippedNoValue} skipped)` : ''}. Duplicates already on the incident are skipped.
              </div>
            </div>
          </div>
          <div className="modal-foot">
            <button type="button" className="btn ghost" onClick={onClose} disabled={busy}>Cancel</button>
            <button type="submit" className="btn primary" disabled={busy || !eligible}>
              {busy ? 'Adding…' : `Add ${eligible} IOC${eligible !== 1 ? 's' : ''}`}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ─── Process tree view ────────────────────────────────────────────────────────
// Rebuilds a parent/child process tree from imported process-creation events.
// Reads PID + parent PID + image names out of each event's raw_log JSON.
//
// Supported inputs:
//   - Sysmon EID 1 (Process Create)       fields: ProcessId, ParentProcessId, Image, ParentImage, CommandLine, User
//   - Sysmon EID 5 (Process Terminated)   fields: ProcessId, Image
//   - Windows Security EID 4688           fields: NewProcessId, ProcessId (parent), NewProcessName, ParentProcessName
//   - syslog / journald                   only single pid, no ppid — listed as orphans
//
// Events without a usable PID are filtered out so the tree only shows process events.

const _PROC_FIELDS = {
  pid:        ['ProcessId', 'NewProcessId', 'pid'],
  ppid:       ['ParentProcessId', 'ProcessId', 'PPID'],   // for EID 4688, parent-pid lives in ProcessId
  image:      ['Image', 'NewProcessName', 'ProcessName', 'proc', 'process'],
  parentImage:['ParentImage', 'ParentProcessName'],
  cmdLine:    ['CommandLine'],
  user:       ['User', 'SubjectUserName'],
}

function _firstField(obj, names) {
  if (!obj) return null
  for (const n of names) {
    const v = obj[n]
    if (v !== undefined && v !== null && v !== '') return String(v)
  }
  return null
}

function _parseRaw(rawLog) {
  if (!rawLog) return null
  try { return JSON.parse(rawLog) } catch { return null }
}

function _extractProcess(ev) {
  const raw = _parseRaw(ev.raw_log)
  if (!raw) return null

  // EID-aware mapping: Windows Security 4688 stores parent PID in ProcessId
  // and child PID in NewProcessId — flip the convention there.
  const eid = raw.EventID
  let pid, ppid
  if (eid === 4688) {
    pid  = raw.NewProcessId
    ppid = raw.ProcessId
  } else {
    pid  = _firstField(raw, _PROC_FIELDS.pid)
    ppid = _firstField(raw, _PROC_FIELDS.ppid)
  }
  if (!pid) return null

  // Normalise hex PIDs (Sysmon uses "0x1234")
  const norm = (x) => (typeof x === 'string' && /^0x/i.test(x)) ? String(parseInt(x, 16)) : (x != null ? String(x) : null)

  const base = {
    pid:         norm(pid),
    ppid:        norm(ppid),
    image:       _firstField(raw, _PROC_FIELDS.image),
    parentImage: _firstField(raw, _PROC_FIELDS.parentImage),
    cmdLine:     _firstField(raw, _PROC_FIELDS.cmdLine),
    user:        _firstField(raw, _PROC_FIELDS.user),
    hostname:    ev.hostname,
    eventTime:   ev.event_time,
    description: ev.description,
    eventIdx:    ev.idx,        // for "select subtree" → existing promote pipeline
    eid,
  }
  // Tree-time detection layer. Merge with whatever the backend parser already
  // flagged on the event (parser-side suspicious wins, plus our findings).
  const det = detectNode(base)
  const parserReasons = (ev.suspicious_reasons || []).map(r => ({
    name: 'parser_rule', severity: 'medium', mitre: ev.mitre_technique_id || null, reason: r,
  }))
  const reasons = [...parserReasons, ...det.suspicious_reasons]
  return {
    ...base,
    suspicious:         ev.suspicious || det.suspicious,
    suspicious_reasons: reasons,
    max_severity:       det.max_severity || (ev.suspicious ? 'medium' : null),
  }
}

// imageBasename — strip Windows path so the tree label is "powershell.exe"
// rather than "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe".
function _basename(p) {
  if (!p) return null
  const winSlash = p.lastIndexOf('\\')
  const nixSlash = p.lastIndexOf('/')
  return p.slice(Math.max(winSlash, nixSlash) + 1) || p
}

function buildProcessForest(events) {
  // Map pid → enriched node. If a PID appears multiple times (rare; can happen
  // after PID reuse), keep the earliest record — process creation always
  // precedes termination in a well-formed dump.
  const nodes = new Map()
  for (const ev of events) {
    const p = _extractProcess(ev)
    if (!p) continue
    if (!nodes.has(p.pid)) nodes.set(p.pid, { ...p, children: [] })
  }

  if (nodes.size === 0) return []

  // Wire children to their parents; collect roots (no known parent in the dump).
  const roots = []
  for (const node of nodes.values()) {
    const parent = node.ppid ? nodes.get(node.ppid) : null
    if (parent) parent.children.push(node)
    else        roots.push(node)
  }

  // Order siblings by event time so the tree reads as it unfolded.
  const sortKey = (a, b) => (a.eventTime || '').localeCompare(b.eventTime || '')
  const sortRec = (arr) => { arr.sort(sortKey); arr.forEach(n => sortRec(n.children)) }
  sortRec(roots)
  // Forest-level rules (parent-child anomalies). Mutates nodes in-place.
  detectForest(roots)
  return roots
}

// Count suspicious descendants per node (computed once per forest, used for
// the "⚠ N" badge on collapsed parents so the analyst sees there's hidden
// danger below). Severity is summarised as the max severity in the subtree.
function _annotateSubtreeFindings(forest) {
  const visit = (n) => {
    let count = n.suspicious ? 1 : 0
    let maxSev = n.max_severity || null
    for (const c of n.children) {
      const r = visit(c)
      count += r.count
      if (r.maxSev && (!maxSev || _sevWeight(r.maxSev) > _sevWeight(maxSev))) maxSev = r.maxSev
    }
    n.subtreeSuspiciousCount = count
    n.subtreeMaxSeverity     = maxSev
    return { count, maxSev }
  }
  for (const root of forest) visit(root)
  return forest
}

function _sevWeight(s) { return s === 'high' ? 3 : s === 'medium' ? 2 : s === 'low' ? 1 : 0 }

// ── Tree-wide helpers (memoised once per forest) ──────────────────────────
//
// descendantsOf(pid)  — Set of all descendant PIDs (used by hover highlight
//                       and "select subtree").
// occurrencesByImage  — Map<basename, node[]> sorted by eventTime, so each
//                       node can show "N/M" without re-scanning the forest.

function _walkForest(forest, visit) {
  const stack = [...forest]
  while (stack.length) {
    const n = stack.pop()
    visit(n)
    for (const c of n.children) stack.push(c)
  }
}

function _buildDescendantsMap(forest) {
  // Post-order: for each node, descendants = union(children's descendants ∪ child PIDs).
  const out = new Map()
  const recurse = (node) => {
    const set = new Set()
    for (const c of node.children) {
      set.add(c.pid)
      const sub = recurse(c)
      for (const p of sub) set.add(p)
    }
    out.set(node.pid, set)
    return set
  }
  for (const root of forest) recurse(root)
  return out
}

function _buildOccurrences(forest) {
  const by = new Map()
  _walkForest(forest, (n) => {
    const key = (_basename(n.image) || `pid ${n.pid}`).toLowerCase()
    if (!by.has(key)) by.set(key, [])
    by.get(key).push(n)
  })
  for (const list of by.values()) {
    list.sort((a, b) => (a.eventTime || '').localeCompare(b.eventTime || ''))
  }
  return by
}

function ProcessTreeView({ events, selected, onSelectSubtree }) {
  const forest = useMemo(() => _annotateSubtreeFindings(buildProcessForest(events)), [events])
  const totalSuspicious = useMemo(
    () => forest.reduce((s, n) => s + (n.subtreeSuspiciousCount || 0), 0),
    [forest],
  )
  const totalNodes = useMemo(() => {
    let n = 0
    _walkForest(forest, () => { n++ })
    return n
  }, [forest])

  const descendants  = useMemo(() => _buildDescendantsMap(forest), [forest])
  const occurrences  = useMemo(() => _buildOccurrences(forest), [forest])

  const [hoveredPid, setHoveredPid] = useState(null)
  const [query, setQuery] = useState('')

  // Match set: PIDs whose own row matches the search. Used for highlight +
  // for the "keep ancestors of matches visible" filter (a node renders if it
  // matches OR has a descendant that matches).
  const matchSet = useMemo(() => {
    const q = query.trim().toLowerCase()
    if (!q) return null
    const m = new Set()
    _walkForest(forest, (n) => {
      const hay = [
        _basename(n.image), n.image, n.pid, n.cmdLine, n.user, n.hostname,
      ].filter(Boolean).join(' ').toLowerCase()
      if (hay.includes(q)) m.add(n.pid)
    })
    return m
  }, [forest, query])

  // visibleSet — node renders if it's a match OR an ancestor of a match.
  const visibleSet = useMemo(() => {
    if (!matchSet) return null
    const v = new Set(matchSet)
    for (const [pid, descs] of descendants.entries()) {
      for (const d of descs) if (matchSet.has(d)) { v.add(pid); break }
    }
    return v
  }, [matchSet, descendants])

  if (forest.length === 0) {
    return (
      <div className="panel-empty">
        <div className="panel-empty-mark" aria-hidden="true">⊥</div>
        <div>No process events with PID / parent-PID found in the current filter.</div>
        <div style={{ color: 'var(--dim)', fontSize: 12 }}>
          The tree view rebuilds parent/child chains from Sysmon EID 1/5, Windows Security
          EID 4688, and syslog/journald PIDs. Import an EVTX with process-creation events
          to see the chain.
        </div>
      </div>
    )
  }

  const matchCount = matchSet?.size ?? 0

  return (
    <div style={{
      background: 'var(--surface)',
      border: '1px solid var(--border)',
      borderRadius: 'var(--radius)',
      padding: 'var(--space-3)',
    }}>
      {/* Header row: count + search */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 'var(--space-2)',
        marginBottom: 'var(--space-2)', flexWrap: 'wrap',
      }}>
        <span style={{ color: 'var(--dim)', fontSize: 11 }}>
          {totalNodes} process{totalNodes !== 1 ? 'es' : ''} across {forest.length} root{forest.length !== 1 ? 's' : ''}
          {totalSuspicious > 0 && (
            <> · <strong style={{ color: 'var(--crit)' }}>⚠ {totalSuspicious}</strong> suspicious</>
          )}
          {matchSet && (
            <> · <strong style={{ color: matchCount ? 'var(--accent)' : 'var(--crit)' }}>{matchCount}</strong> match{matchCount !== 1 ? 'es' : ''}</>
          )}
        </span>
        <input
          type="search"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search image / pid / cmdline / user / host…"
          aria-label="Search process tree"
          style={{
            flex: 1, minWidth: 200, marginLeft: 'auto',
            background: 'var(--surface-2)', color: 'var(--text)',
            border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)',
            padding: '4px 8px', fontSize: 12, fontFamily: 'var(--font-mono)',
          }}
        />
        {query && (
          <button type="button"
            onClick={() => setQuery('')}
            style={{
              background: 'transparent', border: 'none', color: 'var(--muted)',
              cursor: 'pointer', fontSize: 12, padding: '2px 4px',
            }}
            title="Clear search"
          >×</button>
        )}
      </div>

      <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>
        {forest.map(root => (
          <ProcessTreeNode
            key={`${root.pid}-${root.eventTime}`}
            node={root}
            depth={0}
            descendants={descendants}
            occurrences={occurrences}
            hoveredPid={hoveredPid}
            setHoveredPid={setHoveredPid}
            matchSet={matchSet}
            visibleSet={visibleSet}
            selected={selected}
            onSelectSubtree={onSelectSubtree}
          />
        ))}
      </div>
    </div>
  )
}

function _shortTime(iso) {
  if (!iso) return null
  // HH:MM:SS local. Defer to the project's formatLocalShort so the local-TZ
  // policy stays consistent.
  return formatLocalShort(iso)
}

function ProcessTreeNode({
  node, depth,
  descendants, occurrences,
  hoveredPid, setHoveredPid,
  matchSet, visibleSet,
  selected, onSelectSubtree,
}) {
  const [open, setOpen] = useState(depth < 3)  // first three levels expanded by default

  // Search visibility — hide nodes that don't match and have no matching descendant.
  if (visibleSet && !visibleSet.has(node.pid)) return null

  const hasChildren = node.children.length > 0
  const name = _basename(node.image) || `pid ${node.pid}`
  const sevColor = node.suspicious ? severityColor(node.max_severity || 'medium') : null
  const color = sevColor || 'var(--text)'
  // Reasons string for the ⚠ tooltip + the subtree-summary badge.
  const reasonText = (node.suspicious_reasons || [])
    .map(r => `[${(r.severity || '?').toUpperCase()}] ${r.reason}${r.mitre ? ` (${r.mitre})` : ''}`)
    .join('\n')
  // For collapsed parents that hide suspicious descendants.
  const hiddenSuspicious = !open && hasChildren
    ? (node.subtreeSuspiciousCount || 0) - (node.suspicious ? 1 : 0)
    : 0

  // Occurrence position — N/M for processes whose image appears more than once.
  const occList = occurrences.get(name.toLowerCase()) || []
  const occIdx  = occList.indexOf(node)
  const showOcc = occList.length > 1 && occIdx >= 0

  // Hover-subtree highlight: this node is in the hovered subtree if it IS
  // the hovered node OR a descendant of it.
  const inHoveredSubtree = !!hoveredPid && (
    node.pid === hoveredPid ||
    (descendants.get(hoveredPid)?.has(node.pid))
  )

  const isMatch = matchSet?.has(node.pid)

  // Subtree selection — collect own event.idx + all descendant event.idx.
  const selectSubtree = (e) => {
    e.stopPropagation()
    const idxs = []
    const visit = (n) => {
      if (n.eventIdx !== undefined && n.eventIdx !== null) idxs.push(n.eventIdx)
      for (const c of n.children) visit(c)
    }
    visit(node)
    onSelectSubtree?.(idxs)
  }

  // Visual feedback when this node's own event is currently selected.
  const isSelected = selected && node.eventIdx !== undefined && selected.has(node.eventIdx)

  // Background priority: match > hover-subtree > selected > none.
  let rowBg = 'transparent'
  if (isMatch)               rowBg = 'color-mix(in srgb, var(--accent) 18%, transparent)'
  else if (inHoveredSubtree) rowBg = 'color-mix(in srgb, var(--accent) 7%, transparent)'
  else if (isSelected)       rowBg = 'var(--accent-soft)'

  return (
    <div style={{ marginLeft: depth === 0 ? 0 : 16 }}>
      <div
        onClick={() => hasChildren && setOpen(o => !o)}
        onMouseEnter={() => setHoveredPid(node.pid)}
        onMouseLeave={() => setHoveredPid(prev => prev === node.pid ? null : prev)}
        style={{
          display: 'flex', alignItems: 'baseline', gap: 6,
          padding: '2px 4px',
          cursor: hasChildren ? 'pointer' : 'default',
          userSelect: 'none',
          background: rowBg,
          borderRadius: 3,
          transition: 'background 80ms ease',
        }}
      >
        <span style={{ width: 12, color: 'var(--dim)', fontSize: 10 }}>
          {hasChildren ? (open ? '▾' : '▸') : '·'}
        </span>
        {node.suspicious && (
          <span
            style={{ color: sevColor, fontSize: 11, cursor: 'help' }}
            title={reasonText}
            aria-label={`Suspicious — ${(node.suspicious_reasons || []).length} finding(s)`}
          >⚠</span>
        )}
        {hiddenSuspicious > 0 && (
          <span
            title={`${hiddenSuspicious} suspicious process${hiddenSuspicious !== 1 ? 'es' : ''} in collapsed subtree`}
            style={{
              fontSize: 9, padding: '0 4px', borderRadius: 'var(--radius-sm)',
              background: 'color-mix(in srgb, var(--crit) 22%, transparent)',
              color: 'var(--crit)', fontFamily: 'var(--font-mono)', fontWeight: 700,
              border: '1px solid color-mix(in srgb, var(--crit) 40%, transparent)',
            }}
          >⚠{hiddenSuspicious}</span>
        )}
        <span style={{ color, fontWeight: 600 }}>{name}</span>
        <span style={{ color: 'var(--dim)' }}>[{node.pid}]</span>
        {showOcc && (
          <span
            title={`This image basename appears ${occList.length} times in the forest`}
            style={{
              fontSize: 10, padding: '0 4px', borderRadius: 'var(--radius-sm)',
              background: 'color-mix(in srgb, var(--med) 18%, transparent)',
              color: 'var(--med)', fontFamily: 'var(--font-mono)',
            }}
          >{occIdx + 1}/{occList.length}</span>
        )}
        {hasChildren && (
          <span style={{ color: 'var(--dim)', fontSize: 10 }}>· {node.children.length}</span>
        )}
        {node.user && (
          <span style={{ color: 'var(--muted)', fontSize: 11 }}>· {node.user}</span>
        )}
        {/* Right-aligned: time, host, subtree button */}
        <span style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 6 }}>
          {node.eventTime && (
            <span
              title={formatLocal(node.eventTime)}
              style={{ color: 'var(--dim)', fontSize: 10, fontFamily: 'var(--font-mono)' }}
            >{_shortTime(node.eventTime)}</span>
          )}
          {node.hostname && (
            <span style={{ color: 'var(--dim)', fontSize: 11 }}>{node.hostname}</span>
          )}
          {onSelectSubtree && (hasChildren || node.eventIdx !== undefined) && (
            <button
              type="button"
              onClick={selectSubtree}
              title={hasChildren
                ? `Select this process and its ${descendants.get(node.pid)?.size ?? 0} descendant(s) for promotion`
                : 'Select this process for promotion'}
              style={{
                background: 'transparent', border: '1px solid var(--border)',
                color: 'var(--muted)', borderRadius: 'var(--radius-sm)',
                padding: '0 6px', fontSize: 10, fontFamily: 'var(--font-mono)',
                cursor: 'pointer',
              }}
            >+ select subtree</button>
          )}
        </span>
      </div>

      {node.cmdLine && open && (
        <div style={{
          marginLeft: 18, fontSize: 10, color: 'var(--muted)',
          wordBreak: 'break-all', whiteSpace: 'pre-wrap',
          borderLeft: '1px dashed var(--border)',
          paddingLeft: 6, marginTop: 1, marginBottom: 2,
        }}>
          {node.cmdLine}
        </div>
      )}

      {open && node.suspicious && (node.suspicious_reasons?.length > 0) && (
        <div style={{
          marginLeft: 18, marginTop: 2, marginBottom: 4,
          borderLeft: `2px solid ${sevColor}`, paddingLeft: 6,
          display: 'flex', flexDirection: 'column', gap: 2,
        }}>
          {node.suspicious_reasons.map((r, i) => (
            <div key={i} style={{ fontSize: 10, color: 'var(--muted)', display: 'flex', gap: 6, alignItems: 'baseline' }}>
              <span style={{
                fontSize: 8, padding: '0 4px', borderRadius: 'var(--radius-sm)',
                background: `color-mix(in srgb, ${severityColor(r.severity)} 22%, transparent)`,
                color: severityColor(r.severity), fontFamily: 'var(--font-mono)',
                fontWeight: 700, textTransform: 'uppercase', flexShrink: 0,
              }}>{r.severity || '?'}</span>
              <span style={{ color: 'var(--text)' }}>{r.reason}</span>
              {r.mitre && (
                <span style={{ color: 'var(--dim)', fontFamily: 'var(--font-mono)' }}>· {r.mitre}</span>
              )}
            </div>
          ))}
        </div>
      )}

      {open && hasChildren && node.children.map(c => (
        <ProcessTreeNode
          key={`${c.pid}-${c.eventTime}`}
          node={c}
          depth={depth + 1}
          descendants={descendants}
          occurrences={occurrences}
          hoveredPid={hoveredPid}
          setHoveredPid={setHoveredPid}
          matchSet={matchSet}
          visibleSet={visibleSet}
          selected={selected}
          onSelectSubtree={onSelectSubtree}
        />
      ))}
    </div>
  )
}
