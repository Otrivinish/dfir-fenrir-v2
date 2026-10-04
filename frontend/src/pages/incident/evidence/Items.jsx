import { Fragment, useCallback, useEffect, useRef, useState } from 'react'
import { useOutletContext } from 'react-router-dom'
import { useAuth } from '../../../hooks/useAuth.jsx'
import { api } from '../../../api/client.js'
import { formatLocal } from '../../../lib/datetime.js'
import { TLP, labelOf, pillOf } from '../../../lib/incidentVocab.js'
import AcquisitionWizard from './AcquisitionWizard.jsx'
import ExaminationWizard, { ExamTarget, examTargetMissing } from './ExaminationWizard.jsx'
import { scoreEvidence, severityColor, aggregateIntegrity, hashAlgorithm } from '../../../lib/evidenceProvenance.js'
import { SEV_PALETTE } from '../../../components/SevBadge.jsx'
import { fmtOffset, parseOffsetSeconds } from '../../../components/ClockOffset.jsx'
import { DraftBadge } from '../../../components/ExhibitPicker.jsx'
import UploadProgress, { useChunkedUpload, useRetainedUpload } from '../../../components/UploadProgress.jsx'
import LocalDateTimePicker from '../../../components/LocalDateTimePicker.jsx'
import { CUSTODY_ACTION_COLOR, CUSTODY_ACTION_LABEL } from '../../../lib/custodyLabels.js'

const KIND_LABEL = { digital_file: 'Digital file', physical_item: 'Physical item' }
const STATUS_LABEL = {
  active:        'Active',
  verify_failed: 'Verify failed',
  destroyed:     'Destroyed',
  returned:      'Returned',
  archived:      'Archived',
}
const STATUS_PILL = {
  active:        'pill-ok',
  verify_failed: 'pill-crit',
  destroyed:     'pill-gray',
  returned:      'pill-gray',
  archived:      'pill-gray',
}

// C3 — how the imaging tool's target hash compared with the uploaded bytes.
function hashCheckView(item) {
  const algo = hashAlgorithm(item.acquisition_hash_target)
  switch (item.upload_hash_check) {
    case 'match':
      return { color: 'var(--ok)', text: `✓ Target hash (${algo}) matches the uploaded file` }
    case 'mismatch':
      return { color: 'var(--crit)', text: `✗ Target hash (${algo || 'unrecognised'}) does not match the uploaded file — registered before uploads were checked` }
    case 'container_media':
      return { color: 'var(--med)', text: `Advisory — the target hash (${algo}) covers the container's media, not the uploaded file; not compared` }
    case 'not_checked':
      return { color: 'var(--muted)', text: 'Not checked — no target hash given' }
    default:
      return { color: 'var(--muted)', text: 'Not checked — no target hash recorded' }
  }
}

function fmtBytes(n) {
  if (!n && n !== 0) return '—'
  const units = ['B', 'KiB', 'MiB', 'GiB']
  let v = n, i = 0
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++ }
  return `${v.toFixed(i === 0 ? 0 : 1)} ${units[i]}`
}

// The API's one rule set for an item's acquisition facts (the acquisition record and the clock offset,
// G-fix M10): its collector, its current custodian, the incident lead or an admin; the item held
// internally with no transfer pending. Why not, or null. (The API decides; this only hides controls.)
function acquisitionFactsBlock(ev, me, isAdmin, isLead) {
  if (!ev.current_custodian_id) return 'In external custody: take it back first'
  if (ev.pending_custodian_id) return 'A custody transfer awaits acceptance'
  if (!isAdmin && !isLead && me?.id !== ev.collected_by_id && me?.id !== ev.current_custodian_id)
    return 'Only its collector, its custodian, the incident lead or an admin can record its acquisition facts'
  return null
}

// G3 — an unsealed, active item is a draft exhibit (registered by an analyser upload or a Quick add):
// "Complete & seal" fills in its acquisition record (acquisitionFactsBlock decides who).
function draftState(ev, me, isAdmin, isClosed, isLead) {
  const draft = !ev.coc_sealed && ev.status === 'active'
  if (!draft) return { draft: false }
  return { draft: true, blocked: isClosed ? 'Closed incidents are read-only' : acquisitionFactsBlock(ev, me, isAdmin, isLead) }
}

// G-fix FE-L11 — state badges that must stand out use SEV_PALETTE (CLAUDE.md), not the dim pill tints.
function paletteStyle(sev) {
  const p = SEV_PALETTE[sev]
  return p ? { background: p.bg, color: p.text, borderColor: p.border } : undefined
}

function shorten(s, n = 12) {
  if (!s) return '—'
  return s.length > n ? `${s.slice(0, n)}…` : s
}

// C4 — "awaiting acceptance by X" while an internal custody transfer is pending (SEV_PALETTE.medium).
function PendingTransferBadge({ item, usernameOf }) {
  if (!item.pending_custodian_id) return null
  const p = SEV_PALETTE.medium
  return (
    <span className="pill" data-pending-transfer={item.pending_custodian_id}
          title={`Requested by ${usernameOf(item.pending_transfer_by_id)} at ${formatLocal(item.pending_transfer_requested_at)}. Custody changes when the recipient accepts.`}
          style={{ fontSize: 10, whiteSpace: 'nowrap', background: p.bg, color: p.text, borderColor: p.border }}>
      Awaiting acceptance by {usernameOf(item.pending_custodian_id)}
    </span>
  )
}

export default function Items() {
  const { inc, bumpRail, access } = useOutletContext()
  const { user } = useAuth()
  const isClosed = inc?.status === 'closed'
  const isAdmin  = user?.role === 'admin'
  const canWrite = !!user && user.role !== 'viewer'   // FE-L12: viewers see the register read-only

  const [items, setItems]         = useState([])
  const [users, setUsers]         = useState([])
  const [entities, setEntities]   = useState([])
  const [loading, setLoading]     = useState(true)
  const [error, setError]         = useState(null)
  const [kindFilter, setKindFilter]     = useState('')
  const [statusFilter, setStatusFilter] = useState('')
  const [modal, setModal]         = useState(null)   // null | { mode, item? }
  const [busy, setBusy]           = useState(false)

  const replaceItem = useCallback(
    (updated) => setModal(m => m ? { ...m, item: updated } : m),
    []
  )

  // Each load gets a sequence number; only the newest one may set state, so an
  // older multi-page load that finishes late can't overwrite a newer view.
  const loadSeq = useRef(0)
  // The running load's controller: a newer load, an incident change or unmount aborts it.
  const loadAbort = useRef(null)

  const load = useCallback(async () => {
    const seq = ++loadSeq.current
    loadAbort.current?.abort()
    const { signal } = (loadAbort.current = new AbortController())
    setError(null)
    try {
      const params = {}
      if (kindFilter)   params.kind   = kindFilter
      if (statusFilter) params.status = statusFilter
      // Every page, so the register lists every exhibit of the incident.
      const all = await api.listAllPages(api.listEvidence, inc.id, params, 200, { signal })
      if (seq === loadSeq.current) setItems(all)
    } catch (e) {
      if (seq === loadSeq.current && !signal.aborted) setError(e.message || 'Could not load evidence')
    } finally {
      if (seq === loadSeq.current) setLoading(false)
    }
  }, [inc.id, kindFilter, statusFilter])

  useEffect(() => { load(); return () => loadAbort.current?.abort() }, [load])
  // After a write: re-read the list and the rail's counts.
  const reload = useCallback(() => { bumpRail?.(); return load() }, [bumpRail, load])

  // Use the non-admin-safe assignable endpoint so the Transfer picker works
  // for every analyst, not just admins. Returns {id, username, full_name}
  // — enough for display + the UUID we need to POST.
  useEffect(() => {
    let cancelled = false
    api.listAssignableUsers()
      .then(u => { if (!cancelled) setUsers(u || []) })
      .catch(() => {})
    return () => { cancelled = true }
  }, [])

  // Load entities for the entity picker in the add modal and table display.
  useEffect(() => {
    let cancelled = false
    api.listAllEntities(inc.id)   // every page (200 each)
      .then(all => { if (!cancelled) setEntities(all) })
      .catch(() => {})
    return () => { cancelled = true }
  }, [inc.id])

  const usernameOf = (uid) => {
    if (!uid) return '—'
    const u = users.find(x => x.id === uid)
    return u ? u.username : shorten(uid, 8)
  }

  // Render the current custodian — internal user OR external party.
  // Returns a React node so the list/detail views can colour external segments.
  const renderCustodian = (ev) => {
    if (ev.current_custodian_id) {
      return <span style={{ fontFamily: 'var(--font-mono)' }}>{usernameOf(ev.current_custodian_id)}</span>
    }
    if (ev.current_custodian_external_name) {
      return (
        <span title={[
          ev.current_custodian_external_name,
          ev.current_custodian_external_org && `(${ev.current_custodian_external_org})`,
          ev.current_custodian_external_contact && `· ${ev.current_custodian_external_contact}`,
        ].filter(Boolean).join(' ')}>
          <span style={{
            fontSize: 9, padding: '0 4px', borderRadius: 'var(--radius-sm)',
            background: 'color-mix(in srgb, var(--med) 22%, transparent)',
            color: 'var(--med)', fontFamily: 'var(--font-mono)', fontWeight: 700,
            marginRight: 6,
          }}>EXT</span>
          <span>{ev.current_custodian_external_name}</span>
          {ev.current_custodian_external_org && (
            <span style={{ color: 'var(--muted)', fontSize: 11 }}> — {ev.current_custodian_external_org}</span>
          )}
        </span>
      )
    }
    return <span style={{ color: 'var(--dim)' }}>—</span>
  }

  const entityLabelOf = (eid) => {
    if (!eid) return null
    const e = entities.find(x => x.id === eid)
    if (!e) return null
    return `${e.type}: ${e.name || e.value}`
  }

  return (
    <section className="panel">
      <div className="panel-toolbar">
        <h2 className="panel-h">Evidence items</h2>
        <div style={{ display: 'flex', gap: 'var(--space-2)' }}>
          <select className="select" value={kindFilter} onChange={(e) => setKindFilter(e.target.value)} aria-label="Filter by kind">
            <option value="">All kinds</option>
            <option value="digital_file">Digital file</option>
            <option value="physical_item">Physical item</option>
          </select>
          <select className="select" value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)} aria-label="Filter by status">
            <option value="">All statuses</option>
            {Object.entries(STATUS_LABEL).map(([v, l]) => <option key={v} value={v}>{l}</option>)}
          </select>
          {canWrite && (
            <>
              <button
                type="button"
                className="btn ghost"
                onClick={() => setModal({ mode: 'add' })}
                disabled={isClosed}
                title={isClosed ? 'Closed incidents are read-only' : 'Quick add (no wizard)'}
              >
                + Quick add
              </button>
              <button
                type="button"
                className="btn primary"
                onClick={() => setModal({ mode: 'wizard' })}
                disabled={isClosed}
                title={isClosed ? 'Closed incidents are read-only' : 'Court-grade acquisition wizard (ISO 27037 + GDPR)'}
              >
                🛡 Wizard add
              </button>
            </>
          )}
        </div>
      </div>

      {error && (
        <div className="alert error" role="alert">
          <span className="alert-icon">!</span><span>{error}</span>
        </div>
      )}

      {loading ? (
        <div className="panel-empty"><div>Loading…</div></div>
      ) : items.length === 0 ? (
        <div className="panel-empty">
          <div className="panel-empty-mark" aria-hidden="true">⊞</div>
          <div>No evidence yet.</div>
          {!isClosed && canWrite && <div style={{ color: 'var(--dim)', fontSize: 12 }}>Use “Quick add” or “Wizard add” to register a file or physical item.</div>}
        </div>
      ) : (
        <>
          <ChainIntegrityCard items={items} />
          <div className="table-scroll">
          <table className="settings-table">
            <thead>
              <tr>
                <th style={{ width: 120 }}>Kind</th>
                <th>Name / Identifier</th>
                <th style={{ width: 110 }}>Provenance</th>
                <th>SHA-256</th>
                <th>Custodian</th>
                <th style={{ width: 130 }}>TLP</th>
                <th style={{ width: 130 }}>Status</th>
                <th className="actions">Actions</th>
              </tr>
            </thead>
            <tbody>
              {items.map(ev => {
                const prov = scoreEvidence(ev)
                const provColor = severityColor(prov.score)
                const sealed = ev.coc_sealed
                const ds = draftState(ev, user, isAdmin, isClosed, !!access?.is_lead)
                return (
                  <tr key={ev.id}>
                    <td>
                      <span className="pill">{KIND_LABEL[ev.kind] || ev.kind}</span>
                    </td>
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                        {sealed && <span title="Sealed (wizard A)" style={{ color: 'var(--accent)' }}>🔒</span>}
                        <span style={{ fontWeight: 600 }}>{ev.name}</span>
                      </div>
                      <div style={{ color: 'var(--muted)', fontFamily: 'var(--font-mono)', fontSize: 11 }}>
                        {ev.identifier}
                      </div>
                      {ds.draft && <div style={{ marginTop: 2 }}><DraftBadge /></div>}
                      {ev.legal_hold && (
                        <div style={{ marginTop: 2 }}>
                          <span className="pill" data-legal-hold-badge title={ev.legal_hold_reason || 'On legal hold'}
                                style={paletteStyle('medium')}>Legal hold</span>
                        </div>
                      )}
                      {ev.entity_id && entityLabelOf(ev.entity_id) && (
                        <div style={{ fontSize: 10, color: 'var(--accent)', fontFamily: 'var(--font-mono)', marginTop: 2 }}>
                          ↳ {entityLabelOf(ev.entity_id)}
                        </div>
                      )}
                    </td>
                    <td>
                      <span
                        title={`${prov.summary} · ${prov.completeness}% complete\n\n` + prov.checks.map(c =>
                          `[${c.status.toUpperCase()}] ${c.label}${c.note ? ' — ' + c.note : ''}`
                        ).join('\n')}
                        style={{
                          display: 'inline-flex', alignItems: 'center', gap: 4,
                          padding: '2px 8px', borderRadius: 'var(--radius-sm)',
                          fontSize: 11, fontFamily: 'var(--font-mono)', fontWeight: 700,
                          color: provColor,
                          background: `color-mix(in srgb, ${provColor} 16%, transparent)`,
                          border: `1px solid color-mix(in srgb, ${provColor} 40%, transparent)`,
                          cursor: 'help',
                        }}
                      >● {prov.score.toUpperCase()} · {prov.completeness}%</span>
                    </td>
                    <td>
                      {ev.sha256 ? (
                        <button
                          type="button"
                          className="btn ghost"
                          onClick={() => { navigator.clipboard?.writeText(ev.sha256) }}
                          title={`Click to copy:\n${ev.sha256}`}
                          style={{ padding: '2px 6px', fontFamily: 'var(--font-mono)', fontSize: 10, fontWeight: 400 }}
                        >
                          {ev.sha256.slice(0, 12)}…
                        </button>
                      ) : <span style={{ color: 'var(--dim)' }}>—</span>}
                    </td>
                    <td style={{ fontSize: 12 }}>
                      {renderCustodian(ev)}
                      {ev.pending_custodian_id && (
                        <div style={{ marginTop: 2 }}><PendingTransferBadge item={ev} usernameOf={usernameOf} /></div>
                      )}
                    </td>
                    <td>
                      <span className={`pill ${pillOf('tlp', ev.tlp)}`}>{labelOf('tlp', ev.tlp)}</span>
                    </td>
                    <td>
                      <span className={`pill ${STATUS_PILL[ev.status] || 'pill-gray'}`}>
                        {STATUS_LABEL[ev.status] || ev.status}
                      </span>
                    </td>
                    <td className="actions">
                      {ds.draft && user?.role !== 'viewer' && (
                        <button type="button" className="btn ghost" data-testid="ev-complete-seal"
                                onClick={() => setModal({ mode: 'complete', item: ev })} disabled={!!ds.blocked}
                                title={ds.blocked || 'Complete the acquisition record, then seal (ISO/IEC 27037 §5.4.4)'}>
                          Complete &amp; seal
                        </button>
                      )}
                      <button
                        type="button"
                        className="btn ghost"
                        onClick={() => setModal({ mode: 'detail', item: ev })}
                      >Detail</button>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
          </div>
        </>
      )}

      {modal?.mode === 'add' && (
        <AddEvidenceModal
          incidentId={inc.id}
          entities={entities}
          onClose={() => setModal(null)}
          onSaved={() => { setModal(null); reload() }}
        />
      )}
      {modal?.mode === 'wizard' && (
        <AcquisitionWizard
          incidentId={inc.id}
          entities={entities}
          users={users}
          onClose={() => setModal(null)}
          onSaved={() => { setModal(null); reload() }}
        />
      )}
      {modal?.mode === 'complete' && (
        <AcquisitionWizard
          incidentId={inc.id}
          entities={entities}
          users={users}
          existing={modal.item}
          onClose={() => setModal(null)}
          onSaved={() => { setModal(null); reload() }}
        />
      )}
      {modal?.mode === 'detail' && (
        <DetailModal
          incidentId={inc.id}
          item={modal.item}
          users={users}
          entities={entities}
          me={user}
          isAdmin={isAdmin}
          isClosed={isClosed}
          onClose={() => setModal(null)}
          onChanged={async () => { await reload() }}
          onReplaceItem={replaceItem}
          onComplete={(it) => setModal({ mode: 'complete', item: it })}
          isLead={!!access?.is_lead}
        />
      )}
    </section>
  )
}

// ── Add modal ─────────────────────────────────────────────────────────────

function AddEvidenceModal({ incidentId, entities, onClose, onSaved }) {
  const [kind, setKind]               = useState('digital_file')
  const [name, setName]               = useState('')
  const [identifier, setIdentifier]   = useState('')
  const [description, setDescription] = useState('')
  const [tlp, setTlp]                 = useState('amber')
  const [collectedLocation, setCollectedLocation] = useState('')
  const [entityId, setEntityId]       = useState('')
  const [file, setFile]               = useState(null)

  // physical_item extras
  const [make, setMake]               = useState('')
  const [model, setModel]             = useState('')
  const [serial, setSerial]           = useState('')
  const [physicalLocation, setPhysicalLocation] = useState('')
  const [condition, setCondition]     = useState('')

  const [busy, setBusy]   = useState(false)
  const [error, setError] = useState(null)
  const up = useChunkedUpload()   // G1 stage 3b: progress + cancel of the chunked upload
  const kept = useRetainedUpload() // G-fix FE-M2: an upload the server kept after a refused complete

  useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape' && !busy) onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [busy, onClose])

  const onSubmit = async (e) => {
    e.preventDefault()
    setError(null)
    if (!name.trim() || !identifier.trim()) {
      setError('Name and identifier are required.'); return
    }
    if (kind === 'digital_file' && !file) {
      setError('Please choose a file to upload.'); return
    }
    setBusy(true)
    try {
      if (kind === 'digital_file') {
        const fields = {
          name: name.trim(),
          identifier: identifier.trim(),
          description: description.trim() || null,
          tlp,
          collected_location: collectedLocation.trim() || null,
          entity_id: entityId || null,
          file,
        }
        const opts = up.start(file.size)
        if (kept.held) await kept.held.retry(api.digitalCompleteBody(fields), opts)   // no re-upload
        else await api.collectDigital(incidentId, fields, { ...opts, retainOnError: true })
        kept.drop({ cancel: false })
      } else {
        await api.collectPhysical(incidentId, {
          name: name.trim(),
          identifier: identifier.trim(),
          description: description.trim() || null,
          tlp,
          entity_id: entityId || null,
          make: make.trim() || null,
          model: model.trim() || null,
          serial: serial.trim() || null,
          physical_location: physicalLocation.trim() || null,
          condition: condition.trim() || null,
          collected_location: collectedLocation.trim() || null,
          photos: [],
        })
      }
      onSaved()
    } catch (err) {
      if (err.retained) kept.keep(err, file)
      else if (kept.held) kept.drop({ cancel: false })
      setError((err.code === 'identifier_exists'
        ? `The identifier “${identifier.trim()}” is already used on this incident: change it.`
        : (err.message || 'Could not add evidence.'))
        + (err.retained ? ' The file stays uploaded on the server: Add evidence again to finish without re-sending it.' : ''))
    } finally {
      up.done()
      setBusy(false)
    }
  }

  return (
    <div
      className="modal-backdrop"
     
    >
      <div className="modal" role="dialog" aria-labelledby="ev-add-title">
        <div className="modal-head">
          <h2 id="ev-add-title">Add evidence</h2>
          <button type="button" className="modal-close" onClick={onClose} disabled={busy} aria-label="Close">×</button>
        </div>
        <form onSubmit={onSubmit}>
          <div className="modal-body">
            <div className="form">
              <div className="form-row">
                <div className="field">
                  <label className="field-label" htmlFor="ev-kind">Kind</label>
                  <select id="ev-kind" className="select" value={kind} onChange={(e) => setKind(e.target.value)}>
                    <option value="digital_file">Digital file (uploaded, AES-256 at rest)</option>
                    <option value="physical_item">Physical item (referenced, off-platform)</option>
                  </select>
                </div>
                <div className="field">
                  <label className="field-label" htmlFor="ev-tlp">TLP</label>
                  <select id="ev-tlp" className="select" value={tlp} onChange={(e) => setTlp(e.target.value)}>
                    {TLP.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
                  </select>
                </div>
              </div>

              <div className="field">
                <label className="field-label" htmlFor="ev-name">Name</label>
                <input id="ev-name" className="input" value={name} onChange={(e) => setName(e.target.value)}
                       autoFocus required maxLength={256} placeholder="e.g. WIN-FS01 memory dump" />
              </div>

              <div className="field">
                <label className="field-label" htmlFor="ev-id">Identifier (case tag / item number)</label>
                <input id="ev-id" className="input" value={identifier} onChange={(e) => setIdentifier(e.target.value)}
                       required maxLength={128} placeholder="e.g. EV-2026-042-01" style={{ fontFamily: 'var(--font-mono)' }} />
              </div>

              <div className="field">
                <label className="field-label" htmlFor="ev-desc">Description (optional)</label>
                <textarea id="ev-desc" className="input" value={description} onChange={(e) => setDescription(e.target.value)}
                          rows={2} maxLength={4096} />
              </div>

              <div className="field">
                <label className="field-label" htmlFor="ev-loc">Collected at (location, optional)</label>
                <input id="ev-loc" className="input" value={collectedLocation}
                       onChange={(e) => setCollectedLocation(e.target.value)} maxLength={256}
                       placeholder="e.g. Finance dept, 4F server room" />
              </div>

              {entities.length > 0 && (
                <div className="field">
                  <label className="field-label" htmlFor="ev-entity">Asset / entity (optional)</label>
                  <select id="ev-entity" className="select" value={entityId} onChange={(e) => setEntityId(e.target.value)}>
                    <option value="">— No entity linked —</option>
                    {entities.map(e => (
                      <option key={e.id} value={e.id}>
                        {e.type}: {e.name || e.value}{e.compromised ? ' ⚠ compromised' : ''}
                      </option>
                    ))}
                  </select>
                  <div className="field-hint">Link this evidence item to an asset in the incident's entity list.</div>
                </div>
              )}

              {kind === 'digital_file' && (
                <div className="field">
                  <label className="field-label" htmlFor="ev-file">File</label>
                  <input id="ev-file" className="input" type="file"
                         onChange={(e) => { if (kept.held) kept.drop(); setFile(e.target.files?.[0] || null) }} required />
                  <div className="field-hint">Sent in 8 MiB pieces, each hashed (SHA-256 + SHA-1 + MD5) and encrypted as it arrives; nothing is stored until the whole file is in and checked. Up to 10 GiB (the server default).</div>
                  <UploadProgress progress={up.progress} onCancel={up.cancel} testid="ev-add-upload-progress"
                                  limit={up.limit} incidentId={incidentId} />
                  {kept.held && !busy && (
                    <div className="field-hint" data-testid="ev-add-upload-held">
                      {kept.held.filename} is uploaded and held by the server (not stored yet): correct the field and add it again,
                      {' '}or <button type="button" className="btn ghost" onClick={() => kept.drop()}>Discard upload</button>.
                    </div>
                  )}
                </div>
              )}

              {kind === 'physical_item' && (
                <>
                  <div className="form-row">
                    <div className="field">
                      <label className="field-label" htmlFor="ev-make">Make</label>
                      <input id="ev-make" className="input" value={make} onChange={(e) => setMake(e.target.value)} maxLength={128} />
                    </div>
                    <div className="field">
                      <label className="field-label" htmlFor="ev-model">Model</label>
                      <input id="ev-model" className="input" value={model} onChange={(e) => setModel(e.target.value)} maxLength={128} />
                    </div>
                  </div>
                  <div className="field">
                    <label className="field-label" htmlFor="ev-serial">Serial</label>
                    <input id="ev-serial" className="input" value={serial} onChange={(e) => setSerial(e.target.value)} maxLength={128}
                           style={{ fontFamily: 'var(--font-mono)' }} />
                  </div>
                  <div className="field">
                    <label className="field-label" htmlFor="ev-physloc">Stored at (physical location)</label>
                    <input id="ev-physloc" className="input" value={physicalLocation}
                           onChange={(e) => setPhysicalLocation(e.target.value)} maxLength={256}
                           placeholder="e.g. Evidence locker B-12, tamper seal #4471" />
                  </div>
                  <div className="field">
                    <label className="field-label" htmlFor="ev-cond">Condition</label>
                    <textarea id="ev-cond" className="input" value={condition}
                              onChange={(e) => setCondition(e.target.value)} rows={2} maxLength={4096}
                              placeholder="e.g. powered off, seal intact, no visible damage" />
                  </div>
                </>
              )}

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
              {busy ? 'Uploading…' : 'Add evidence'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ── Detail modal (read-only summary + per-item custody log + actions) ─────

// Working copies (ISO/IEC 27037 §7.1.3.1.1). G5: the master is never downloadable — a download is issued
// as a registered working copy whose hash is of the bytes FENRIR sent; a copy made outside FENRIR is
// recorded with the hash its tool reported. The API decides status, match and usability; this only shows them.
const COPY_KIND = { download: 'Download', lab_copy: 'Lab copy', export: 'Export', legacy_record: 'Legacy record' }
// sev = the SEV_PALETTE entry of the state badge (FE-L11); none = a neutral grey pill.
const COPY_STATUS = {
  issued:            { label: 'Link issued' },
  downloading:       { label: 'Downloading',        sev: 'medium' },
  complete:          { label: 'Complete',           sev: 'low' },
  aborted:           { label: 'Aborted',            sev: 'high' },
  failed_integrity:  { label: 'Failed integrity',   sev: 'critical' },
  expired:           { label: 'Link expired' },
  verified:          { label: 'Verified',           sev: 'low' },
  mismatch:          { label: 'Hash mismatch',      sev: 'critical' },
  exported:          { label: 'Exported' },
  legacy_unverified: { label: 'Not verifiable' },
}
const END_REASON = {
  client_disconnected: 'the transfer stopped before the end',
  read_error:          'the stored file could not be read',
  integrity:           'the stored master failed its integrity check (frozen)',
  hash_mismatch:       'the bytes sent do not match the recorded hash (frozen)',
  interrupted:         'interrupted (server restart)',
}

function copyMatchText(c) {
  if (c.kind === 'legacy_record') return { color: 'var(--muted)', text: 'Holds the master\u2019s hash, not the copy\u2019s — not a verified copy' }
  if (c.verified_against_master) return { color: 'var(--ok)', text: '✓ Copy hash matches the master' }
  if (c.status === 'mismatch' || c.status === 'failed_integrity') return { color: 'var(--crit)', text: '✗ Copy hash does NOT match the master' }
  return { color: 'var(--muted)', text: 'No copy hash (not complete)' }
}

// Why no new working copy can be made now (the API enforces the same rules), else null.
function copyBlocked(item) {
  if (item.kind !== 'digital_file') return 'Physical items have no working copies'
  if (item.status === 'verify_failed') return 'Frozen pending admin review (verify failed)'
  if (item.status !== 'active') return `The item is ${STATUS_LABEL[item.status] || item.status}`
  if (!item.current_custodian_id) return 'In external custody: take it back first'
  if (item.pending_custodian_id) return 'A custody transfer awaits acceptance'
  return null
}

function WorkingCopiesPanel({ incidentId, item, usernameOf, canWrite, onChanged }) {
  const [copies,  setCopies]  = useState([])
  const [loading, setLoading] = useState(true)
  const [mode,    setMode]    = useState(null)   // null | 'download' | 'lab'
  const [purpose, setPurpose] = useState('')
  const [dest,    setDest]    = useState('')
  const [tool,    setTool]    = useState('')
  const [hashes,  setHashes]  = useState({ copy_sha256: '', copy_sha1: '', copy_md5: '' })
  const [busy,    setBusy]    = useState(false)
  const [err,     setErr]     = useState(null)
  const [notice,  setNotice]  = useState(null)
  const pollRef = useRef(null)
  const alive = useRef(true)      // FE-L18: no poll or state change after the panel closes

  const load = useCallback(async () => {
    try {
      const r = await api.listWorkingCopies(incidentId, item.id)
      if (alive.current) setCopies(r.items || [])
      return r.items || []
    }
    catch { return null }
    finally { if (alive.current) setLoading(false) }
  }, [incidentId, item.id])
  useEffect(() => { alive.current = true; load(); return () => { alive.current = false; clearTimeout(pollRef.current) } }, [load])

  // FE-L7 / FE-L18 — the browser downloads the link itself, so the page can't see a refusal (409 / 410 /
  // 503): it follows the copy the server records instead. Re-read every 2 s, backing off to 15 s, for as
  // long as the panel is open, until the copy's transfer ends (or its link expires unused).
  const follow = (issued, n = 0, t0 = Date.now(), warned = false) => {
    clearTimeout(pollRef.current)
    pollRef.current = setTimeout(async () => {
      if (!alive.current) return
      const list = await load()
      if (!alive.current) return
      const c = list?.find(x => x.id === issued.copy.id)
      const id = issued.copy.copy_identifier
      const st = list === null ? 'unknown' : c?.status
      if (st === 'unknown' || st === 'issued' || st === 'downloading') {
        if (st === 'downloading') {
          setErr(null)
          setNotice(`Download started as ${id}. FENRIR hashes what it sends and records it here when the transfer ends — compare it with your own hash of the file.`)
        } else if (st === 'issued' && !warned && Date.now() - t0 >= 15000) {   // the server has not started sending
          warned = true
          setNotice(null)
          setErr(`The download of ${id} has not started. FENRIR may have refused the link (the item is frozen, held externally or in a transfer) or your browser blocked it. Check the item, then issue a new working copy; this link expires at ${formatLocal(issued.token_expires_at)}.`)
        }
        follow(issued, n + 1, t0, warned)
        return
      }
      setNotice(null); setErr(null)
      if (st === 'complete') {
        setNotice(`${id} downloaded${c.bytes_sent != null ? ` (${fmtBytes(c.bytes_sent)})` : ''}. FENRIR recorded the SHA-256 of exactly what it sent (below) — compare it with your own hash of the file.`)
      } else if (st === 'aborted') {
        setErr(`The download of ${id} stopped: ${END_REASON[c.end_reason] || c.end_reason || 'unknown reason'}. The copy is not usable — issue a new one.`)
      } else if (st === 'failed_integrity') {
        setErr(`${id} FAILED: ${END_REASON[c.end_reason] || 'integrity check'}. Nothing usable was sent; the item has been frozen pending admin review.`)
      } else if (st === 'expired') {
        setErr(`The link for ${id} expired unused: nothing was downloaded. Issue a new working copy.`)
      }
      onChanged?.()
    }, Math.min(15000, Math.round(2000 * 1.5 ** Math.min(n, 5))))
  }

  const blocked = copyBlocked(item)
  const reset = () => { setMode(null); setPurpose(''); setDest(''); setTool(''); setHashes({ copy_sha256: '', copy_sha1: '', copy_md5: '' }) }

  const download = async (e) => {
    e.preventDefault()
    if (!purpose.trim()) { setErr('Purpose is required (custody log).'); return }
    setBusy(true); setErr(null); setNotice(null)
    try {
      const r = await api.issueWorkingCopy(incidentId, item.id, { purpose: purpose.trim(), destination_note: dest.trim() || null })
      // A same-origin link: the browser streams it to disk with your session. It works once, for you.
      const a = document.createElement('a')
      a.href = r.download_url
      a.rel = 'noopener'
      a.setAttribute('download', '')
      a.setAttribute('data-testid', 'wc-download-link')
      document.body.appendChild(a); a.click(); a.remove()
      setNotice(`Link issued as ${r.copy.copy_identifier}: your browser saves the file. Waiting for FENRIR to start sending…`)
      reset(); await load(); follow(r)
    } catch (e2) { setErr(e2.message || 'Could not issue a working copy') }
    finally { setBusy(false) }
  }

  const record = async (e) => {
    e.preventDefault()
    if (!purpose.trim()) { setErr('Purpose is required (custody log).'); return }
    const given = Object.fromEntries(Object.entries(hashes).map(([k, v]) => [k, v.trim()]).filter(([, v]) => v))
    if (!Object.keys(given).length) { setErr('Enter at least one hash your copying tool reported for the copy.'); return }
    setBusy(true); setErr(null); setNotice(null)
    try {
      const c = await api.mintWorkingCopy(incidentId, item.id, {
        purpose: purpose.trim(), copy_tool: tool.trim() || null, destination_note: dest.trim() || null, ...given })
      setNotice(c.status === 'verified'
        ? `${c.copy_identifier} recorded: its hash matches the master.`
        : `${c.copy_identifier} recorded as a MISMATCH: its hash does not match the master. It is flagged and can't be examined.`)
      reset(); await load(); await onChanged?.()
    } catch (e2) { setErr(e2.message || 'Could not record the lab copy') }
    finally { setBusy(false) }
  }

  const hashField = (key, label, len) => (
    <div className="field" key={key}>
      <label className="field-label" htmlFor={`wc-${key}`}>{label}</label>
      <input id={`wc-${key}`} className="input compact" value={hashes[key]} maxLength={len} spellCheck={false}
             onChange={e => setHashes(h => ({ ...h, [key]: e.target.value }))}
             style={{ fontFamily: 'var(--font-mono)' }} placeholder={`${len} hex characters`} />
    </div>
  )

  return (
    <section data-testid="ev-working-copies">
      <h3 className="panel-h" style={{ marginTop: 'var(--space-4)' }}>
        Working copies{' '}
        <span style={{ fontWeight: 400, color: 'var(--muted)', fontSize: 12 }}>· ISO 27037 §7.1.3.1.1 — the master is never downloadable</span>
      </h3>
      {loading ? (
        <div style={{ color: 'var(--muted)', fontSize: 13 }}>Loading…</div>
      ) : copies.length === 0 ? (
        <div style={{ color: 'var(--muted)', fontSize: 13 }}>No working copies yet. Download one, or record a copy you made in the lab with the hash your tool reported. An export records one for an item whose file is stored in FENRIR (not for physical items).</div>
      ) : (
        <ul style={{ listStyle: 'none', margin: 0, padding: 0, display: 'flex', flexDirection: 'column', gap: 6 }}>
          {copies.map(c => {
            const st = COPY_STATUS[c.status] || { label: c.status }
            const m = copyMatchText(c)
            return (
              <li key={c.id} data-copy-status={c.status} data-copy-kind={c.kind}
                  style={{ fontSize: 12, border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', padding: '6px 10px', background: 'var(--surface-2)' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
                  <span style={{ display: 'inline-flex', gap: 6, alignItems: 'center', flexWrap: 'wrap' }}>
                    <b style={{ fontFamily: 'var(--font-mono)' }}>{c.copy_identifier || COPY_KIND[c.kind]}</b>
                    <span className="pill pill-gray">{COPY_KIND[c.kind] || c.kind}</span>
                    <span className={`pill${st.sev ? '' : ' pill-gray'}`} data-copy-pill={c.status} style={paletteStyle(st.sev)}>{st.label}</span>
                    {c.usable_for_examination && <span className="pill" style={paletteStyle('low')} title="An examination may name this copy">Usable for examination</span>}
                    {c.altered_at && <span className="pill" style={paletteStyle('critical')} title={`Found altered at ${formatLocal(c.altered_at)}`}>Altered</span>}
                  </span>
                  <span style={{ color: 'var(--dim)', fontFamily: 'var(--font-mono)' }}>{formatLocal(c.created_at)}</span>
                </div>
                <div style={{ color: m.color, marginTop: 2 }}>{m.text}</div>
                <div style={{ color: 'var(--muted)' }}>{c.purpose || '—'}{c.destination_note ? ` · to ${c.destination_note}` : ''}{c.copy_tool ? ` · ${c.copy_tool}` : ''}</div>
                <div style={{ color: 'var(--dim)', fontFamily: 'var(--font-mono)', fontSize: 11, wordBreak: 'break-all' }}>
                  {c.kind === 'download' ? 'issued to ' : 'by '}{usernameOf(c.issued_to_id || c.created_by_id)}
                  {c.kind === 'download' && c.bytes_sent != null ? ` · ${fmtBytes(c.bytes_sent)} sent` : ''}
                  {c.completed_at ? ` · ended ${formatLocal(c.completed_at)}` : ''}
                  {c.end_reason && END_REASON[c.end_reason] ? ` · ${END_REASON[c.end_reason]}` : ''}
                </div>
                {(c.sha256 || c.sha1 || c.md5) && (
                  <div style={{ color: 'var(--dim)', fontFamily: 'var(--font-mono)', fontSize: 11, wordBreak: 'break-all' }}>
                    {c.sha256 && <div>SHA-256 {c.sha256}</div>}
                    {c.sha1 && <div>SHA-1 {c.sha1}</div>}
                    {c.md5 && <div>MD5 {c.md5}</div>}
                  </div>
                )}
              </li>
            )
          })}
        </ul>
      )}
      {canWrite && item.kind === 'digital_file' && !mode && (
        <div style={{ display: 'flex', gap: 'var(--space-2)', marginTop: 'var(--space-2)', flexWrap: 'wrap' }}>
          <button type="button" className="btn" data-testid="wc-open-download" disabled={!!blocked || busy}
                  title={blocked || 'Download a working copy: FENRIR registers it, hashes the bytes it sends and logs it'}
                  onClick={() => { setErr(null); setNotice(null); setMode('download') }}>Download a working copy</button>
          <button type="button" className="btn ghost" data-testid="wc-open-lab" disabled={!!blocked || busy}
                  title={blocked || 'Record a copy you made outside FENRIR, with the hash its tool reported'}
                  onClick={() => { setErr(null); setNotice(null); setMode('lab') }}>Record a lab copy</button>
        </div>
      )}
      {mode && (
        <form onSubmit={mode === 'download' ? download : record} className="form" data-testid={`wc-form-${mode}`}
              style={{ marginTop: 'var(--space-2)', padding: 'var(--space-3)', border: '1px solid var(--border)', borderRadius: 'var(--radius)', background: 'var(--surface-2)' }}>
          <div className="field">
            <label className="field-label" htmlFor="wc-purpose">Purpose (required, audited)</label>
            <input id="wc-purpose" className="input" value={purpose} maxLength={2048} onChange={e => setPurpose(e.target.value)}
                   placeholder={mode === 'download' ? 'e.g. Memory analysis with Volatility on VM AN-07' : 'e.g. Imaged to lab WS-04 for Autopsy review'} />
          </div>
          {mode === 'lab' && (
            <>
              <div className="field">
                <label className="field-label" htmlFor="wc-tool">Copying tool + version</label>
                <input id="wc-tool" className="input" value={tool} maxLength={256} onChange={e => setTool(e.target.value)} placeholder="e.g. FTK Imager 4.7.1" />
              </div>
              <div className="field-hint">The hash(es) your tool reported for the copy — at least one. Each is compared with the master's recorded hash of the same algorithm.</div>
              <div className="form-row">
                {hashField('copy_sha256', 'Copy SHA-256', 64)}
                {hashField('copy_sha1', 'Copy SHA-1', 40)}
                {hashField('copy_md5', 'Copy MD5', 32)}
              </div>
            </>
          )}
          <div className="field">
            <label className="field-label" htmlFor="wc-dest">{mode === 'download' ? 'Where the copy will go (optional)' : 'Where the copy is (optional)'}</label>
            <input id="wc-dest" className="input" value={dest} maxLength={1024} onChange={e => setDest(e.target.value)} placeholder="e.g. analysis VM AN-07 · lab WS-04 D:\\cases" />
          </div>
          {mode === 'download' && (
            <div className="field-hint">The link works once, for you, for 10 minutes. Your browser saves the file; FENRIR records the SHA-256 of exactly what it sent.</div>
          )}
          <div style={{ display: 'flex', gap: 'var(--space-2)', flexWrap: 'wrap' }}>
            <button type="submit" className="btn primary" disabled={busy}>
              {busy ? 'Working…' : mode === 'download' ? 'Issue and download' : 'Record lab copy'}
            </button>
            <button type="button" className="btn ghost" disabled={busy} onClick={() => { reset(); setErr(null) }}>Cancel</button>
          </div>
        </form>
      )}
      {notice && <div className="alert info" role="status" style={{ marginTop: 6 }}><span className="alert-icon">i</span><span>{notice}</span></div>}
      {err && <div className="alert error" role="alert" style={{ marginTop: 6 }}><span className="alert-icon">!</span><span>{err}</span></div>}
    </section>
  )
}

// G5 (R09) — legal hold: the current hold and its history (from the custody log). Setting one is open to
// any analyst who can see the incident; releasing is for the incident lead or an admin (the API decides).
function LegalHoldPanel({ incidentId, item, events, usernameOf, canWrite, isLead, onChanged }) {
  const [mode, setMode]     = useState(null)   // null | 'set' | 'release'
  const [reason, setReason] = useState('')
  const [busy, setBusy]     = useState(false)
  const [err, setErr]       = useState(null)
  const history = events.filter(e => e.event_type === 'evidence_legal_hold_set' || e.event_type === 'evidence_legal_hold_released')

  const submit = async (e) => {
    e.preventDefault()
    if (!reason.trim()) { setErr('A reason is required (custody log).'); return }
    setBusy(true); setErr(null)
    try {
      await api.setLegalHold(incidentId, item.id, { legal_hold: mode === 'set', reason: reason.trim() })
      setMode(null); setReason(''); await onChanged()
    } catch (e2) { setErr(e2.message || 'Could not change the legal hold') }
    finally { setBusy(false) }
  }

  return (
    <section data-testid="ev-legal-hold" data-legal-hold={item.legal_hold ? 'on' : 'off'}>
      <h3 className="panel-h" style={{ marginTop: 'var(--space-4)' }}>Legal hold</h3>
      {item.legal_hold ? (
        <div style={{ fontSize: 13 }}>
          <span className="pill" style={paletteStyle('medium')}>On legal hold</span>{' '}
          since <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>{formatLocal(item.legal_hold_since)}</span>
          {' '}by <b>{usernameOf(item.legal_hold_by_id)}</b>
          {item.legal_hold_reason && <div style={{ color: 'var(--muted)', whiteSpace: 'pre-wrap' }}>{item.legal_hold_reason}</div>}
          <div className="field-hint">While held it can't be destroyed; returning or archiving it needs a second approver.</div>
        </div>
      ) : (
        <div style={{ color: 'var(--muted)', fontSize: 13 }}>Not on legal hold.</div>
      )}
      {canWrite && !mode && (
        item.legal_hold ? (
          <button type="button" className="btn ghost" style={{ marginTop: 'var(--space-2)' }} disabled={!isLead}
                  data-testid="lh-open-release"
                  title={isLead ? 'Release the hold (reason required, audited)' : 'Only the incident lead (IC / Deputy) or an admin can release a hold'}
                  onClick={() => { setErr(null); setMode('release') }}>Release hold…</button>
        ) : item.status !== 'destroyed' && (
          <button type="button" className="btn" style={{ marginTop: 'var(--space-2)' }} data-testid="lh-open-set"
                  onClick={() => { setErr(null); setMode('set') }}>Place on legal hold…</button>
        )
      )}
      {mode && (
        <form onSubmit={submit} className="form" style={{ marginTop: 'var(--space-2)' }} data-testid={`lh-form-${mode}`}>
          <div className="field">
            <label className="field-label" htmlFor="lh-reason">{mode === 'set' ? 'Why is it held? (required, audited)' : 'Why release it? (required, audited)'}</label>
            <textarea id="lh-reason" className="input" rows={2} maxLength={2048} value={reason} onChange={e => setReason(e.target.value)}
                      placeholder={mode === 'set' ? 'e.g. Litigation hold — counsel letter of 2026-10-04' : 'e.g. Counsel confirmed the matter is closed'} />
          </div>
          <div style={{ display: 'flex', gap: 'var(--space-2)', flexWrap: 'wrap' }}>
            <button type="submit" className="btn primary" disabled={busy}>{busy ? 'Saving…' : mode === 'set' ? 'Place on hold' : 'Release hold'}</button>
            <button type="button" className="btn ghost" disabled={busy} onClick={() => { setMode(null); setReason(''); setErr(null) }}>Cancel</button>
          </div>
        </form>
      )}
      {history.length > 0 && (
        <ul style={{ listStyle: 'none', margin: 'var(--space-2) 0 0', padding: 0, fontSize: 12 }} data-testid="lh-history">
          {history.map(h => (
            <li key={h.id} style={{ color: 'var(--muted)' }}>
              <span style={{ fontFamily: 'var(--font-mono)' }}>{formatLocal(h.created_at)}</span>{' '}
              <b style={{ color: 'var(--text)' }}>{h.event_type === 'evidence_legal_hold_set' ? 'Set' : 'Released'}</b>
              {' by '}{h.username || '—'}{h.details?.reason ? ` — ${h.details.reason}` : ''}
            </li>
          ))}
        </ul>
      )}
      {err && <div className="alert error" role="alert" style={{ marginTop: 6 }}><span className="alert-icon">!</span><span>{err}</span></div>}
    </section>
  )
}

// G5 (R09) — the acquisition record as captured (and sealed). Identity, server hashes, the C3 upload check,
// acquisition time and the clock offset are in the summary above; this is the rest of the record.
const LAWFUL_BASIS_LABEL = { ir: 'Incident response', consent: 'Consent', warrant: 'Warrant', court_order: 'Court order',
  eio: 'European Investigation Order', mla: 'Mutual legal assistance', lia: 'Legitimate interest', other: 'Other' }
const yesNo = (v) => v === true ? 'Yes' : v === false ? 'No' : null
const SYSTEM_STATE_LABEL = { powered_off: 'Powered off', live: 'Live', live_critical: 'Live, mission-critical', unknown: 'Unknown' }
const HANDLING_LABEL = { collect: 'Collect (seize the device)', acquire: 'Acquire (forensic copy)' }
const SCOPE_LABEL = { full_image: 'Full image', logical: 'Logical / selected files' }

function AcquisitionRecord({ item, usernameOf }) {
  const rows = [
    ['Lawful basis', item.lawful_basis ? (LAWFUL_BASIS_LABEL[item.lawful_basis] || item.lawful_basis) : null],
    ['Basis note', item.lawful_basis_note],
    ['Tool', [item.acquisition_tool, item.acquisition_tool_version].filter(Boolean).join(' ') || null],
    ['Tool SHA-256', item.acquisition_tool_sha256, true],
    ['Parameters', item.acquisition_params, true],
    ['Tool validated', yesNo(item.acquisition_tool_validated) && [yesNo(item.acquisition_tool_validated),
      item.acquisition_tool_validation_ref, item.acquisition_tool_validation_date].filter(Boolean).join(' · ')],
    ['Source hash', item.acquisition_hash_source, true],
    ['Target hash', item.acquisition_hash_target, true],
    ['Write-blocker', yesNo(item.write_blocker_used) && [yesNo(item.write_blocker_used), item.write_blocker_serial].filter(Boolean).join(' · ')],
    ['System state', item.system_state && (SYSTEM_STATE_LABEL[item.system_state] || item.system_state)],
    ['Live justification', item.live_justification],
    ['Network isolated', yesNo(item.network_isolated)],
    ['Witness', [item.witness_user_id ? usernameOf(item.witness_user_id) : null, item.witness_name].filter(Boolean).join(' · ') || null],
    ['Device types', (item.device_types || []).join(', ') || null],
    ['Handling', item.handling_mode && (HANDLING_LABEL[item.handling_mode] || item.handling_mode)],
    ['Scope', item.acquisition_scope && (SCOPE_LABEL[item.acquisition_scope] || item.acquisition_scope)],
    ['Logical rationale', item.logical_acquisition_rationale],
    ['Screen state', item.screen_state],
    ['Changes made', item.changes_made],
    ['Collector qualifications', item.collected_by_qualifications],
  ].filter(([, v]) => v !== null && v !== undefined && v !== '')
  const objRows = (obj) => Object.entries(obj || {}).filter(([, v]) => v !== null && v !== '' && v !== undefined)
  const dd = objRows(item.device_details)
  const df = objRows(item.decision_factors)

  return (
    <section data-testid="ev-acquisition-record" data-sealed={item.coc_sealed ? 'yes' : 'no'}>
      <h3 className="panel-h" style={{ marginTop: 'var(--space-4)' }}>
        Acquisition record{' '}
        <span style={{ fontWeight: 400, color: 'var(--muted)', fontSize: 12 }}>· ISO 27037 §5.4.4, §6.1</span>
      </h3>
      <div style={{ fontSize: 13, marginBottom: 'var(--space-2)' }}>
        {item.coc_sealed ? (
          <span>🔒 <b>Sealed</b> at <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>{formatLocal(item.coc_sealed_at)}</span> by <b>{usernameOf(item.coc_sealed_by_id)}</b>
            {item.seal_tst_time
              ? <span style={{ color: 'var(--muted)' }}> · trusted timestamp {formatLocal(item.seal_tst_time)}{item.seal_tsa ? ` (${item.seal_tsa})` : ''}</span>
              : <span style={{ color: 'var(--muted)' }}> · server clock only (no TSA)</span>}
            <div className="field-hint">Changes after the seal are logged as <b>Amended after seal</b>. The photos already attached and the collector's role can't change; a new photo can still be added (logged as <b>Photo added</b>).</div>
          </span>
        ) : (
          <span><DraftBadge /> <span style={{ color: 'var(--muted)' }}>The record is incomplete or not yet sealed — use <b>Complete &amp; seal</b>.</span></span>
        )}
      </div>
      {rows.length === 0 && dd.length === 0 && df.length === 0 ? (
        <div style={{ color: 'var(--muted)', fontSize: 13 }}>No acquisition details recorded.</div>
      ) : (
        <dl className="kv">
          {rows.map(([k, v, mono]) => (
            <Fragment key={k}><dt>{k}</dt><dd style={mono ? { fontFamily: 'var(--font-mono)', fontSize: 11, wordBreak: 'break-all' } : { whiteSpace: 'pre-wrap' }}>{String(v)}</dd></Fragment>
          ))}
          {dd.length > 0 && <><dt>Device details</dt><dd style={{ fontSize: 12 }}>{dd.map(([k, v]) => <div key={k}><span style={{ color: 'var(--muted)' }}>{k}:</span> {typeof v === 'object' ? JSON.stringify(v) : String(v)}</div>)}</dd></>}
          {df.length > 0 && <><dt>Decision factors</dt><dd style={{ fontSize: 12 }}>{df.map(([k, v]) => <div key={k}><span style={{ color: 'var(--muted)' }}>{k}:</span> {typeof v === 'object' ? JSON.stringify(v) : String(v)}</div>)}</dd></>}
        </dl>
      )}
    </section>
  )
}

// G5 (R09) — what the custody log says about this item at a glance, and its examinations.
function CustodySummary({ item, events, usernameOf }) {
  const transfers = events.filter(e => e.event_type === 'evidence_transfer').length
  const exams = events.filter(e => e.event_type === 'evidence_examine')
  return (
    <section data-testid="ev-custody-summary">
      <h3 className="panel-h" style={{ marginTop: 'var(--space-4)' }}>Custody and examinations</h3>
      <div style={{ fontSize: 13 }}>
        Collected by <b>{usernameOf(item.collected_by_id)}</b> · {transfers} custody transfer{transfers === 1 ? '' : 's'} ·
        {' '}{item.current_custodian_id ? <>held by <b>{usernameOf(item.current_custodian_id)}</b></> : item.current_custodian_external_name ? <>held externally by <b>{item.current_custodian_external_name}</b></> : 'no custodian'}
        {item.pending_custodian_id ? ' · transfer pending' : ''} · {exams.length} examination{exams.length === 1 ? '' : 's'}
      </div>
      {exams.length > 0 && (
        <ul style={{ listStyle: 'none', margin: 'var(--space-2) 0 0', padding: 0, display: 'flex', flexDirection: 'column', gap: 4 }} data-testid="ev-exams">
          {exams.map(x => {
            const d = x.details || {}
            const on = d.copy_identifier ? `on ${d.copy_identifier}`
              : d.examined_in_place ? `in place — ${d.in_place_reason || ''}`
              : d.examined_on ? d.examined_on
              : d.working_copy_id ? 'on a working copy' : 'target not recorded'
            return (
              <li key={x.id} style={{ fontSize: 12, color: 'var(--muted)' }}>
                <span style={{ fontFamily: 'var(--font-mono)' }}>{formatLocal(x.created_at)}</span>{' '}
                <b style={{ color: 'var(--text)' }}>{[d.tool, d.version].filter(Boolean).join(' ') || 'Examination'}</b>
                {' by '}{x.username || '—'} · {on}
                {d.result && d.result !== 'timeline_import' ? ` · ${d.result}` : ''}
                {d.findings ? <div style={{ whiteSpace: 'pre-wrap' }}>Findings: {String(d.findings).slice(0, 300)}</div> : null}
              </li>
            )
          })}
        </ul>
      )}
    </section>
  )
}

function DetailModal({ incidentId, item, users, entities, me, isAdmin, isClosed, onClose, onChanged, onReplaceItem, onComplete, isLead }) {
  // G5: a viewer sees the whole record read-only; the API refuses their writes anyway.
  const canWrite = !!me && me.role !== 'viewer'
  const entityLabel = item.entity_id
    ? (() => { const e = entities.find(x => x.id === item.entity_id); return e ? `${e.type}: ${e.name || e.value}` : null })()
    : null
  const [events, setEvents] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError]   = useState(null)
  const [busy, setBusy]     = useState(false)
  const [action, setAction] = useState(null)   // null | 'transfer' | 'examine' | 'verify' | 'dispose'

  const reload = useCallback(async () => {
    setLoading(true); setError(null)
    try {
      const [refreshed, log] = await Promise.all([
        api.getEvidence(incidentId, item.id),
        api.custodyLog(incidentId, item.id),
      ])
      setEvents(log)
      onReplaceItem(refreshed)
    } catch (e) {
      setError(e.message || 'Could not load custody log')
    } finally {
      setLoading(false)
    }
  }, [incidentId, item.id, onReplaceItem])

  useEffect(() => { reload() }, [reload])

  useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape' && !busy && !action) onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [busy, action, onClose])

  const usernameOf = (uid) => {
    if (!uid) return '—'
    const u = users.find(x => x.id === uid)
    return u ? u.username : uid
  }

  const onVerify = async () => {
    setBusy(true); setError(null)
    try {
      const r = await api.verifyEvidence(incidentId, item.id)
      await reload()
      await onChanged()
      if (!r.ok) setError(`Integrity check FAILED. recorded=${r.sha256_recorded?.slice(0, 12)}… recomputed=${r.sha256_recomputed?.slice(0, 12)}…`)
    } catch (e) {
      setError(e.message || 'Verify failed')
    } finally {
      setBusy(false)
    }
  }

  const finalActive = item.status === 'active'

  return (
    <div
      className="modal-backdrop"
     
    >
      <div className="modal" role="dialog" aria-labelledby="ev-detail-title" style={{ width: 'min(720px, 96vw)' }}>
        <div className="modal-head">
          <h2 id="ev-detail-title">Evidence detail</h2>
          <button type="button" className="modal-close" onClick={onClose} disabled={busy} aria-label="Close">×</button>
        </div>
        <div className="modal-body">
          <dl className="kv">
            <dt>Kind</dt><dd>{KIND_LABEL[item.kind]}</dd>
            <dt>Name</dt><dd>{item.name}</dd>
            {entityLabel && <><dt>Asset</dt><dd style={{ color: 'var(--accent)', fontFamily: 'var(--font-mono)', fontSize: 12 }}>{entityLabel}</dd></>}
            <dt>Identifier</dt><dd style={{ fontFamily: 'var(--font-mono)' }}>{item.identifier}</dd>
            <dt>Status</dt><dd>
              <span className={`pill ${STATUS_PILL[item.status] || 'pill-gray'}`}>{STATUS_LABEL[item.status] || item.status}</span>
            </dd>
            <dt>TLP</dt><dd><span className={`pill ${pillOf('tlp', item.tlp)}`}>{labelOf('tlp', item.tlp)}</span></dd>
            <dt>Custodian</dt><dd style={{ fontSize: 13 }}>
              {item.current_custodian_id
                ? <span style={{ fontFamily: 'var(--font-mono)' }}>{usernameOf(item.current_custodian_id)}</span>
                : item.current_custodian_external_name
                  ? (
                    <span>
                      <span style={{
                        fontSize: 9, padding: '0 4px', borderRadius: 'var(--radius-sm)',
                        background: 'color-mix(in srgb, var(--med) 22%, transparent)',
                        color: 'var(--med)', fontFamily: 'var(--font-mono)', fontWeight: 700,
                        marginRight: 6,
                      }}>EXT</span>
                      {item.current_custodian_external_name}
                      {item.current_custodian_external_org && (
                        <span style={{ color: 'var(--muted)', fontSize: 12 }}> — {item.current_custodian_external_org}</span>
                      )}
                      {item.current_custodian_external_contact && (
                        <div style={{ fontSize: 11, color: 'var(--dim)', fontFamily: 'var(--font-mono)', marginTop: 2 }}>
                          {item.current_custodian_external_contact}
                        </div>
                      )}
                    </span>
                  )
                  : <span style={{ color: 'var(--dim)' }}>—</span>}
              {item.pending_custodian_id && (
                <div style={{ marginTop: 4 }}><PendingTransferBadge item={item} usernameOf={usernameOf} /></div>
              )}
            </dd>
            <dt>Collected by</dt><dd style={{ fontFamily: 'var(--font-mono)' }}>{usernameOf(item.collected_by_id)}</dd>
            {item.collected_as_role && (
              <><dt>Collected as</dt><dd>{item.collected_as_role === 'defr' ? 'DEFR — first responder' : 'DES — specialist'}</dd></>
            )}
            <dt>Acquired at</dt><dd style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>
              {item.acquired_at ? formatLocal(item.acquired_at) : <span style={{ color: 'var(--dim)' }}>Not recorded</span>}
            </dd>
            <dt>Collected at</dt><dd style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>{formatLocal(item.collected_at)}</dd>
            {item.collected_location && <><dt>Location</dt><dd>{item.collected_location}</dd></>}
            {item.description && <><dt>Description</dt><dd style={{ whiteSpace: 'pre-wrap' }}>{item.description}</dd></>}
            {item.kind === 'digital_file' && (
              <>
                <dt>Filename</dt><dd>{item.original_filename || '—'}</dd>
                <dt>Size</dt><dd>{fmtBytes(item.file_size_bytes)}</dd>
                <dt>SHA-256</dt><dd style={{ fontFamily: 'var(--font-mono)', fontSize: 11, wordBreak: 'break-all' }}>{item.sha256 || '—'}</dd>
                <dt>SHA-1</dt><dd style={{ fontFamily: 'var(--font-mono)', fontSize: 11, wordBreak: 'break-all' }}>{item.sha1 || '—'}</dd>
                <dt>MD5</dt><dd style={{ fontFamily: 'var(--font-mono)', fontSize: 11, wordBreak: 'break-all' }}>{item.md5 || '—'}</dd>
                <dt>Hash check</dt><dd data-hash-check={item.upload_hash_check || ''}>
                  <span style={{ color: hashCheckView(item).color }}>{hashCheckView(item).text}</span>
                  {item.acquisition_hash_target && (
                    <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--muted)', wordBreak: 'break-all' }}>
                      target {item.acquisition_hash_target}
                    </div>
                  )}
                </dd>
                <dt>Encryption</dt><dd>{item.status === 'destroyed' ? 'File deleted (hashes retained)' : 'AES-256-GCM at rest'}</dd>
                <dt>Device clock</dt><dd>
                  <DeviceClock incidentId={incidentId} item={item}
                    editable={canWrite && !isClosed && (item.status === 'active' || item.status === 'verify_failed')
                      && !acquisitionFactsBlock(item, me, isAdmin, isLead)}
                    onSaved={async (updated) => { onReplaceItem(updated); await reload(); await onChanged() }} />
                </dd>
              </>
            )}
            {item.kind === 'physical_item' && (
              <>
                {item.make && <><dt>Make</dt><dd>{item.make}</dd></>}
                {item.model && <><dt>Model</dt><dd>{item.model}</dd></>}
                {item.serial && <><dt>Serial</dt><dd style={{ fontFamily: 'var(--font-mono)' }}>{item.serial}</dd></>}
                {item.physical_location && <><dt>Stored at</dt><dd>{item.physical_location}</dd></>}
                {item.condition && <><dt>Condition</dt><dd style={{ whiteSpace: 'pre-wrap' }}>{item.condition}</dd></>}
              </>
            )}
            {item.disposed_at && (
              <>
                <dt>Disposed at</dt><dd style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>{formatLocal(item.disposed_at)}</dd>
                {item.dispose_witness_id && (
                  <><dt>Disposal witness</dt><dd style={{ fontFamily: 'var(--font-mono)' }}>{usernameOf(item.dispose_witness_id)}</dd></>
                )}
                {item.final_hash_at_disposition && (
                  <><dt>Final hash</dt><dd style={{ fontFamily: 'var(--font-mono)', fontSize: 11, wordBreak: 'break-all' }}>{item.final_hash_at_disposition}</dd></>
                )}
              </>
            )}
          </dl>

          {item.pending_custodian_id && (
            <PendingTransferPanel incidentId={incidentId} item={item} me={me} isAdmin={isAdmin}
              usernameOf={usernameOf} onDone={async () => { await reload(); await onChanged() }} />
          )}

          {error && (
            <div className="alert error" role="alert" style={{ marginTop: 'var(--space-3)' }}>
              <span className="alert-icon">!</span><span>{error}</span>
            </div>
          )}

          <AcquisitionRecord item={item} usernameOf={usernameOf} />

          <LegalHoldPanel incidentId={incidentId} item={item} events={events} usernameOf={usernameOf}
            canWrite={canWrite} isLead={isLead} onChanged={async () => { await reload(); await onChanged() }} />

          <PhotosPanel incidentId={incidentId} item={item} isClosed={isClosed || !canWrite}
            onReplaceItem={onReplaceItem} onChanged={reload} />

          <CustodySummary item={item} events={events} usernameOf={usernameOf} />

          <h3 className="panel-h" style={{ marginTop: 'var(--space-4)' }}>Custody log</h3>
          {loading ? (
            <div style={{ color: 'var(--muted)', fontSize: 13 }}>Loading…</div>
          ) : events.length === 0 ? (
            <div style={{ color: 'var(--muted)', fontSize: 13 }}>No custody events recorded.</div>
          ) : (
            <CustodyTimeline events={events} usernameOf={usernameOf} />
          )}

          <WorkingCopiesPanel incidentId={incidentId} item={item}
            usernameOf={usernameOf} canWrite={canWrite} onChanged={reload} />
        </div>

        <div className="modal-foot" style={{ flexWrap: 'wrap', gap: 'var(--space-2)' }}>
          <button type="button" className="btn ghost" onClick={onClose} disabled={busy}>Close</button>
          {(() => {
            // While in external custody, the actions that need an internal
            // actor (examine/verify/seal/exam-session) are gated. Transfer
            // remains available so the row can be taken back; admin Dispose
            // also remains available (destroy/return/archive of the local copy).
            const isExternal = !item.current_custodian_id && !!item.current_custodian_external_name
            const externalTip = isExternal
              ? `Blocked while in external custody (${item.current_custodian_external_name}). Transfer back to an internal user first.`
              : null
            // C4 — only the custodian or an admin hands an item over; anyone (not read-only) can
            // take an item back from external custody into their own. A pending transfer blocks
            // another transfer, Seal and Dispose until it is accepted or declined.
            const pending = !!item.pending_custodian_id
            const pendingTip = pending ? 'Blocked while a custody transfer awaits acceptance' : null
            const canTransfer = !pending && (isAdmin || (!!me && item.current_custodian_id === me.id)
              || (isExternal && !!me && me.role !== 'viewer'))
            return canWrite && !isClosed && finalActive && (
              <>
                {canTransfer && (
                  <button type="button" className="btn" onClick={() => setAction('transfer')} disabled={busy}>
                    {isExternal ? 'Take back' : 'Request transfer'}
                  </button>
                )}
                <button type="button" className="btn"
                        onClick={() => setAction('examine')}
                        disabled={busy || isExternal}
                        title={externalTip || 'Record an examination (free-text tool)'}>
                  Examine (quick)
                </button>
                {item.kind === 'digital_file' && (
                  <>
                    <button type="button" className="btn primary"
                            onClick={() => setAction('exam_session')}
                            disabled={busy || isExternal}
                            title={externalTip || 'On a verified working copy: copy hash before → record → copy hash after (ISO 27037 §5.4.5)'}>
                      🛡 Exam wizard
                    </button>
                    <button type="button" className="btn"
                            onClick={onVerify}
                            disabled={busy || isExternal}
                            title={externalTip || 'Recompute SHA-256 and compare to recorded'}>
                      {busy ? 'Verifying…' : 'Verify integrity'}
                    </button>
                  </>
                )}
                {!item.coc_sealed && onComplete && (() => {
                  const ds = draftState(item, me, isAdmin, isClosed, isLead)
                  return (
                    <button type="button" className="btn primary" data-testid="ev-detail-complete-seal"
                            onClick={() => onComplete(item)} disabled={busy || !!ds.blocked}
                            title={ds.blocked || 'Complete the acquisition record (lawful basis, device type, tool + version…), then seal'}>
                      Complete &amp; seal
                    </button>
                  )
                })()}
                {!item.coc_sealed && (
                  <button type="button" className="btn"
                          onClick={async () => {
                            try {
                              await api.sealEvidence(incidentId, item.id)
                              await reload(); await onChanged()
                            } catch (e) {
                              setError(e.message || 'Could not seal evidence')
                            }
                          }}
                          disabled={busy || isExternal || pending}
                          title={externalTip || pendingTip || 'Seal acquisition (locks ISO 27037 + GDPR fields)'}>
                    🔒 Seal
                  </button>
                )}
                {isAdmin && (
                  <button type="button" className="btn primary" onClick={() => setAction('dispose')}
                          disabled={busy || pending} title={pendingTip || undefined}>Dispose</button>
                )}
              </>
            )
          })()}
          {canWrite && !isClosed && item.status === 'verify_failed' && item.kind === 'digital_file' && (
            <button type="button" className="btn" onClick={onVerify} disabled={busy}>
              {busy ? 'Verifying…' : 'Re-verify'}
            </button>
          )}
        </div>

        {action === 'transfer' && (
          <TransferModal
            incidentId={incidentId}
            item={item}
            users={users}
            me={me}
            isAdmin={isAdmin}
            onClose={() => setAction(null)}
            onSaved={async () => { setAction(null); await reload(); await onChanged() }}
          />
        )}
        {action === 'exam_session' && (
          <ExaminationWizard
            incidentId={incidentId}
            item={item}
            onClose={() => setAction(null)}
            onSaved={async () => { setAction(null); await reload(); await onChanged() }}
          />
        )}
        {action === 'examine' && (
          <ExamineModal
            incidentId={incidentId}
            item={item}
            onClose={() => setAction(null)}
            onSaved={async () => { setAction(null); await reload(); await onChanged() }}
          />
        )}
        {action === 'dispose' && (
          <DisposeModal
            incidentId={incidentId}
            item={item}
            users={users}
            me={me}
            onClose={() => setAction(null)}
            onSaved={async () => { setAction(null); await reload(); await onChanged() }}
          />
        )}
      </div>
    </div>
  )
}

// ── Custody timeline (vertical list inside detail modal) ──────────────────

// G-fix FE-L8: the custody-log labels and colours are shared with Evidence › Custody log.
const ACTION_COLOR = CUSTODY_ACTION_COLOR
const ACTION_LABEL = CUSTODY_ACTION_LABEL

// ─── Device clock offset (G4, R35) ───────────────────────────────────────────
// The acquisition note (free text, never interpreted) and the structured offset in seconds that
// imports from this exhibit apply. Setting / correcting it is audited {from, to} (an amendment
// after seal on a sealed item); imports already made keep the offset they were parsed with.
function DeviceClock({ incidentId, item, editable, onSaved }) {
  const [editing, setEditing] = useState(false)
  const [value, setValue]     = useState('')
  const [busy, setBusy]       = useState(false)
  const [err, setErr]         = useState(null)
  const parsed = parseOffsetSeconds(value)
  const current = item.system_time_offset_seconds
  const has = current !== null && current !== undefined

  const save = async () => {
    if (parsed === undefined) return
    if (parsed === (has ? current : null)) { setEditing(false); return }
    if (!confirm((item.coc_sealed ? 'This item is sealed: the change is recorded as an amendment after seal.\n\n' : '')
      + 'Imports already made from this exhibit keep the offset they were parsed with — import it again to apply the new value. Continue?')) return
    setBusy(true); setErr(null)
    try {
      const updated = await api.updateEvidence(incidentId, item.id, { system_time_offset_seconds: parsed })
      setEditing(false)
      await onSaved(updated)
    } catch (e) {
      setErr(e.message || 'Could not save the clock offset')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div data-testid="ev-device-clock">
      <div>
        {has
          ? <><strong data-testid="ev-offset-seconds">{fmtOffset(current)}</strong> <span style={{ color: 'var(--muted)', fontSize: 12 }}>applied to imports</span></>
          : <span style={{ color: 'var(--dim)' }}>No offset in seconds</span>}
        {item.system_time_offset && (
          <div style={{ fontSize: 12, color: 'var(--muted)' }}>Note: {item.system_time_offset}{!has && ' (text only: not applied)'}</div>
        )}
      </div>
      {editable && !editing && (
        <button type="button" className="btn ghost" style={{ fontSize: 11, marginTop: 4 }}
                onClick={() => { setValue(has ? String(current) : ''); setErr(null); setEditing(true) }}>
          {has ? 'Change offset' : 'Set offset'}
        </button>
      )}
      {editing && (
        <div style={{ marginTop: 'var(--space-2)' }}>
          <div style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'center', flexWrap: 'wrap' }}>
            <label className="field-label" htmlFor="ev-offset-input" style={{ margin: 0 }}>Seconds</label>
            <input id="ev-offset-input" className="input compact" inputMode="numeric" value={value}
                   onChange={e => setValue(e.target.value)} maxLength={12} placeholder="e.g. +120 · empty = clear"
                   aria-invalid={parsed === undefined || undefined} aria-describedby="ev-offset-hint"
                   style={{ width: 160, ...(parsed === undefined ? { borderColor: 'var(--crit)' } : {}) }} />
            <button type="button" className="btn primary" onClick={save} disabled={busy || parsed === undefined}>
              {busy ? 'Saving…' : 'Save'}
            </button>
            <button type="button" className="btn ghost" onClick={() => setEditing(false)} disabled={busy}>Cancel</button>
          </div>
          <div id="ev-offset-hint" className="field-hint">
            {parsed === undefined
              ? <span style={{ color: 'var(--crit)' }}>A whole number of seconds, e.g. +120 or -30.</span>
              : 'Device clock minus true time, after its timezone: +120 = the device was 2 minutes ahead. Empty clears it.'}
          </div>
          {err && <div className="field-hint" role="alert" style={{ color: 'var(--crit)' }}>{err}</div>}
        </div>
      )}
    </div>
  )
}

function CustodyTimeline({ events, usernameOf }) {
  return (
    <ul style={{ listStyle: 'none', margin: 0, padding: 0, display: 'flex', flexDirection: 'column', gap: 'var(--space-2)' }}>
      {events.map(ev => (
        <li
          key={ev.id}
          style={{
            display: 'grid',
            gridTemplateColumns: '160px 1fr',
            gap: 'var(--space-3)',
            padding: 'var(--space-2) var(--space-3)',
            background: 'var(--surface-2)',
            border: '1px solid var(--border)',
            borderLeft: `3px solid ${ACTION_COLOR[ev.event_type] || 'var(--border)'}`,
            borderRadius: 'var(--radius)',
          }}
        >
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--muted)' }}>
            {formatLocal(ev.created_at)}
          </div>
          <div>
            <div>
              <b style={{ color: ACTION_COLOR[ev.event_type] || 'var(--text)' }}>
                {ACTION_LABEL[ev.event_type] || ev.event_type}
              </b>
              {' by '}
              <span style={{ fontFamily: 'var(--font-mono)' }}>{ev.username || '—'}</span>
            </div>
            {ev.details && Object.keys(ev.details).length > 0 && (
              <details style={{ marginTop: 4 }}>
                <summary style={{ cursor: 'pointer', color: 'var(--muted)', fontSize: 12 }}>details</summary>
                <pre style={{
                  margin: '4px 0 0', fontSize: 10, color: 'var(--muted)',
                  background: 'var(--bg)', padding: 'var(--space-2)',
                  borderRadius: 'var(--radius-sm)', overflow: 'auto',
                  whiteSpace: 'pre-wrap', wordBreak: 'break-all',
                }}>{JSON.stringify(ev.details, null, 2)}</pre>
              </details>
            )}
            {ev.hash && (
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--dim)', marginTop: 4 }}>
                hash: {ev.hash.slice(0, 16)}…
              </div>
            )}
          </div>
        </li>
      ))}
    </ul>
  )
}

// ── Sub-modals ────────────────────────────────────────────────────────────

// C4 — a pending internal transfer: who asked, for whom, and the recipient's Accept form
// (condition on receipt + seals) or Decline; the requester or an admin can cancel it. The API
// enforces who may do what; this only shows each person their own controls.
function PendingTransferPanel({ incidentId, item, me, isAdmin, usernameOf, onDone }) {
  const isRecipient = !!me && me.id === item.pending_custodian_id
  const canCancel   = !isRecipient && !!me && (me.id === item.pending_transfer_by_id || isAdmin)
  const [declining, setDeclining] = useState(false)
  const [condition, setCondition] = useState('')
  const [seals, setSeals]         = useState('')   // '' | 'intact' | 'broken'
  const [reason, setReason]       = useState('')
  const [busy, setBusy]           = useState(false)
  const [error, setError]         = useState(null)

  const run = async (call, failMsg) => {
    setBusy(true); setError(null)
    try { await call(); await onDone() }
    catch (e) { setError(e.message || failMsg) }
    finally { setBusy(false) }
  }
  const onAccept = (e) => {
    e.preventDefault()
    if (!condition.trim()) { setError('Record the condition of the item on receipt.'); return }
    if (!seals) { setError('State whether the seals are intact.'); return }
    run(() => api.acceptEvidenceTransfer(incidentId, item.id,
      { condition_on_receipt: condition.trim(), seals_intact: seals === 'intact' }), 'Could not accept the transfer')
  }
  const onDecline = (e) => {
    e.preventDefault()
    if (!reason.trim()) { setError('A reason is required (audit log).'); return }
    run(() => api.declineEvidenceTransfer(incidentId, item.id, { reason: reason.trim() }), 'Could not decline the transfer')
  }

  return (
    <div data-pending-panel={isRecipient ? 'recipient' : canCancel ? 'requester' : 'other'} style={{
      marginTop: 'var(--space-3)', padding: 'var(--space-3)',
      background: 'var(--surface-2)', border: '1px solid var(--border)', borderRadius: 'var(--radius)',
    }}>
      <h3 className="panel-h" style={{ margin: 0 }}>Pending custody transfer</h3>
      <div style={{ fontSize: 13, marginTop: 'var(--space-1)' }}>
        Requested by <b>{usernameOf(item.pending_transfer_by_id)}</b> at{' '}
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>{formatLocal(item.pending_transfer_requested_at)}</span>{' '}
        for <b>{usernameOf(item.pending_custodian_id)}</b>. Custody stays with the current custodian until the recipient accepts.
      </div>

      {isRecipient && !declining && (
        <form onSubmit={onAccept} className="form" style={{ marginTop: 'var(--space-2)' }}>
          <div className="field">
            <label className="field-label" htmlFor="ev-acc-cond">Condition on receipt (required, audited)</label>
            <textarea id="ev-acc-cond" className="input" rows={3} maxLength={4096} value={condition}
                      onChange={(e) => setCondition(e.target.value)}
                      placeholder="Inspect the item first. e.g. Bag #4471 sealed, laptop powered off, matches the description" />
          </div>
          <div className="field">
            <label className="field-label" htmlFor="ev-acc-seals">Seals / tamper-evident packaging</label>
            <select id="ev-acc-seals" className="select" value={seals} onChange={(e) => setSeals(e.target.value)}>
              <option value="">Choose…</option>
              <option value="intact">Intact</option>
              <option value="broken">Broken or missing (describe it above)</option>
            </select>
          </div>
          <div style={{ display: 'flex', gap: 'var(--space-2)', flexWrap: 'wrap' }}>
            <button type="submit" className="btn primary" disabled={busy}>{busy ? 'Accepting…' : 'Accept custody'}</button>
            <button type="button" className="btn ghost" disabled={busy} onClick={() => { setDeclining(true); setError(null) }}>Decline…</button>
          </div>
        </form>
      )}

      {canCancel && !declining && (
        <div style={{ marginTop: 'var(--space-2)' }}>
          <button type="button" className="btn ghost" disabled={busy} onClick={() => { setDeclining(true); setError(null) }}>Cancel request…</button>
        </div>
      )}

      {declining && (
        <form onSubmit={onDecline} className="form" style={{ marginTop: 'var(--space-2)' }}>
          <div className="field">
            <label className="field-label" htmlFor="ev-dec-reason">
              {isRecipient ? 'Why are you declining? (required, audited)' : 'Why cancel the request? (required, audited)'}
            </label>
            <textarea id="ev-dec-reason" className="input" rows={2} maxLength={2048} value={reason}
                      onChange={(e) => setReason(e.target.value)} autoFocus />
          </div>
          <div style={{ display: 'flex', gap: 'var(--space-2)', flexWrap: 'wrap' }}>
            <button type="submit" className="btn primary" disabled={busy}>
              {busy ? 'Saving…' : (isRecipient ? 'Decline transfer' : 'Cancel request')}
            </button>
            <button type="button" className="btn ghost" disabled={busy} onClick={() => { setDeclining(false); setError(null) }}>Back</button>
          </div>
        </form>
      )}

      {error && (
        <div className="alert error" role="alert" style={{ marginTop: 'var(--space-2)' }}>
          <span className="alert-icon">!</span><span>{error}</span>
        </div>
      )}
    </div>
  )
}

function TransferModal({ incidentId, item, users, me, isAdmin, onClose, onSaved }) {
  // Two-mode picker per ISO/IEC 27037 §6.1 chain coverage:
  //   internal — recipient has a Fenrir account (picker reuses /users/assignable). C4: a
  //              REQUEST — custody changes only when the recipient accepts. From external
  //              custody it is a take-back: you receive the item and record its condition.
  //   external — recipient is a real-world party (courier, external counsel, LE
  //              officer pre-formal-handoff, vendor IR team). Captured as
  //              free-text {name, organisation, contact}; one step.
  const isExternalNow = !item.current_custodian_id && !!item.current_custodian_external_name
  const canExternal   = !isExternalNow || isAdmin   // external → external: admin only
  const [mode, setMode]       = useState('internal')
  const [toUserId, setToUserId] = useState('')
  const [extName, setExtName] = useState('')
  const [extOrg, setExtOrg]   = useState('')
  const [extContact, setExtContact] = useState('')
  const [reason, setReason]   = useState('')
  // Structured tamper-evident transport (ISO/IEC 27037 §6.9.4) — optional.
  const [transportMethod, setTransportMethod] = useState('')
  const [sealId, setSealId]   = useState('')
  const [courierRef, setCourierRef] = useState('')
  // Take-back from external custody: what you found on receipt (required).
  const [condition, setCondition] = useState('')
  const [seals, setSeals]     = useState('')
  const [busy, setBusy]       = useState(false)
  const [error, setError]     = useState(null)
  const isReturn = mode === 'internal' && isExternalNow

  // Filter out the current holder so the picker doesn't offer it back to itself, and yourself:
  // the API refuses a transfer to the requester (recipient_is_requester, two-person control).
  const candidates = (users || []).filter(u => u.id !== item.current_custodian_id && u.id !== me?.id)

  const onSubmit = async (e) => {
    e.preventDefault()
    setError(null)
    if (!reason.trim()) { setError('Reason is required (audit log).'); return }

    const transport = {
      transport_method: transportMethod.trim() || null,
      seal_id:          sealId.trim() || null,
      courier_ref:      courierRef.trim() || null,
    }

    let payload
    if (isReturn) {
      if (!condition.trim()) { setError('Record the condition of the item on receipt.'); return }
      if (!seals) { setError('State whether the seals are intact.'); return }
      payload = { to_user_id: me?.id, reason: reason.trim(), ...transport,
                  condition_on_receipt: condition.trim(), seals_intact: seals === 'intact' }
    } else if (mode === 'internal') {
      if (!toUserId) { setError('Choose a recipient user.'); return }
      payload = { to_user_id: toUserId, reason: reason.trim(), ...transport }
    } else {
      if (!extName.trim()) { setError('External recipient name is required.'); return }
      payload = {
        to_external: {
          name:         extName.trim(),
          organisation: extOrg.trim() || null,
          contact:      extContact.trim() || null,
        },
        reason: reason.trim(),
        ...transport,
      }
    }

    setBusy(true)
    try {
      await api.transferEvidence(incidentId, item.id, payload)
      onSaved()
    } catch (e2) {
      setError(e2.message || 'Transfer failed')
    } finally {
      setBusy(false)
    }
  }

  const title = mode === 'external' ? 'Hand over to an external party'
    : isReturn ? 'Take back into your custody' : 'Request custody transfer'

  return (
    <div className="modal-backdrop" style={{ background: 'rgba(0,0,0,0.4)' }}>
      <div className="modal" role="dialog" aria-labelledby="ev-transfer-title">
        <div className="modal-head">
          <h2 id="ev-transfer-title">{title}</h2>
          <button type="button" className="modal-close" onClick={onClose} disabled={busy}>×</button>
        </div>
        <form onSubmit={onSubmit}>
          <div className="modal-body">
            <div className="form">

              {/* Mode picker */}
              <div className="field">
                <label className="field-label">Recipient type</label>
                <div style={{
                  display: 'inline-flex', border: '1px solid var(--border)',
                  borderRadius: 'var(--radius)', overflow: 'hidden',
                }}>
                  <button type="button"
                    className={`btn ${mode === 'internal' ? 'primary' : 'ghost'}`}
                    style={{ borderRadius: 0, fontSize: 12, padding: '4px 12px' }}
                    onClick={() => setMode('internal')}>
                    {isExternalNow ? 'You (take it back)' : 'Internal user (Fenrir account)'}
                  </button>
                  {canExternal && (
                    <button type="button"
                      className={`btn ${mode === 'external' ? 'primary' : 'ghost'}`}
                      style={{ borderRadius: 0, borderLeft: '1px solid var(--border)',
                               fontSize: 12, padding: '4px 12px' }}
                      onClick={() => setMode('external')}>
                      External party (courier / counsel / LE)
                    </button>
                  )}
                </div>
                <div className="field-hint">
                  {mode === 'external'
                    ? 'Records that the item is in the hands of a real-world party without a Fenrir account. ' +
                      'While external, examine / verify / seal are blocked — take it back first.'
                    : isReturn
                      ? `You record that you received the item back from ${item.current_custodian_external_name}. Inspect it first — the condition and seals are required and audited.`
                      : 'The recipient must accept it and record the condition and seals. Custody stays with the current custodian until then.'}
                </div>
              </div>

              {mode === 'internal' && !isReturn && (
                <div className="field">
                  <label className="field-label" htmlFor="ev-to">Recipient</label>
                  {candidates.length === 0 ? (
                    <div style={{ fontSize: 12, color: 'var(--muted)' }}>
                      No other users available to receive custody.
                    </div>
                  ) : (
                    <select id="ev-to" className="select" value={toUserId}
                            onChange={(e) => setToUserId(e.target.value)}>
                      <option value="">Choose recipient…</option>
                      {candidates.map(u => (
                        <option key={u.id} value={u.id}>
                          {u.username}{u.full_name ? ` — ${u.full_name}` : ''}
                        </option>
                      ))}
                    </select>
                  )}
                </div>
              )}

              {isReturn && (
                <>
                  <div className="field">
                    <label className="field-label" htmlFor="ev-ret-cond">Condition on receipt (required, audited)</label>
                    <textarea id="ev-ret-cond" className="input" rows={3} maxLength={4096} value={condition}
                              onChange={(e) => setCondition(e.target.value)}
                              placeholder="e.g. Bag #4471 seal intact, contents match the description" />
                  </div>
                  <div className="field">
                    <label className="field-label" htmlFor="ev-ret-seals">Seals / tamper-evident packaging</label>
                    <select id="ev-ret-seals" className="select" value={seals} onChange={(e) => setSeals(e.target.value)}>
                      <option value="">Choose…</option>
                      <option value="intact">Intact</option>
                      <option value="broken">Broken or missing (describe it above)</option>
                    </select>
                  </div>
                </>
              )}

              {mode === 'external' && (
                <>
                  <div className="field">
                    <label className="field-label" htmlFor="ev-ext-name">Recipient name *</label>
                    <input id="ev-ext-name" className="input" value={extName}
                           onChange={(e) => setExtName(e.target.value)} autoFocus
                           maxLength={256} placeholder="e.g. Insp. P. Hansen" />
                  </div>
                  <div className="field">
                    <label className="field-label" htmlFor="ev-ext-org">Organisation</label>
                    <input id="ev-ext-org" className="input" value={extOrg}
                           onChange={(e) => setExtOrg(e.target.value)} maxLength={256}
                           placeholder="e.g. Stockholm County Police — Cybercrime Unit" />
                  </div>
                  <div className="field">
                    <label className="field-label" htmlFor="ev-ext-contact">Contact (email / phone / badge #)</label>
                    <input id="ev-ext-contact" className="input" value={extContact}
                           onChange={(e) => setExtContact(e.target.value)} maxLength={256}
                           placeholder="e.g. p.hansen@polisen.se · +46 8 401 00 00 · badge B-44219"
                           style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }} />
                  </div>
                </>
              )}

              <div className="field">
                <label className="field-label" htmlFor="ev-reason">Reason (required, audited)</label>
                <textarea id="ev-reason" className="input" value={reason}
                          onChange={(e) => setReason(e.target.value)} rows={3} maxLength={2048}
                          placeholder={mode === 'external'
                            ? 'e.g. Sealed in evidence bag #4471 (tamper-evident), handed to courier for transport to Stockholm Police HQ'
                            : isReturn ? 'e.g. Returned by courier after the LE review'
                              : 'e.g. Handoff to malware analyst for static analysis'} />
              </div>

              {/* Structured tamper-evident transport (ISO/IEC 27037 §6.9.4) — optional. */}
              <div className="form-row">
                <div className="field">
                  <label className="field-label" htmlFor="ev-tm">Transport method</label>
                  <input id="ev-tm" className="input" value={transportMethod}
                         onChange={(e) => setTransportMethod(e.target.value)} maxLength={128}
                         placeholder="e.g. courier · hand-carry · encrypted channel" />
                </div>
                <div className="field">
                  <label className="field-label" htmlFor="ev-seal">Seal ID</label>
                  <input id="ev-seal" className="input" value={sealId}
                         onChange={(e) => setSealId(e.target.value)} maxLength={128}
                         placeholder="e.g. bag #4471" style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }} />
                </div>
                <div className="field">
                  <label className="field-label" htmlFor="ev-cref">Courier / tracking ref</label>
                  <input id="ev-cref" className="input" value={courierRef}
                         onChange={(e) => setCourierRef(e.target.value)} maxLength={128}
                         placeholder="e.g. DHL 7741-2293" style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }} />
                </div>
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
              {busy ? 'Sending…' : (mode === 'external' ? 'Transfer (external)' : isReturn ? 'Take back' : 'Request transfer')}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

function ExamineModal({ incidentId, item, onClose, onSaved }) {
  const [tool, setTool]   = useState('')
  const [notes, setNotes] = useState('')
  const [busy, setBusy]   = useState(false)
  const [error, setError] = useState(null)
  // G5 (R08): a digital exhibit names the verified working copy examined, or "in place" with a reason.
  const isDigital = item.kind === 'digital_file'
  const [copies, setCopies] = useState([])
  const [target, setTarget] = useState({ workingCopyId: '', inPlace: false, inPlaceReason: '' })
  useEffect(() => {
    if (!isDigital) return
    api.listWorkingCopies(incidentId, item.id).then(r => setCopies(r.items || [])).catch(() => {})
  }, [incidentId, item.id, isDigital])

  const onSubmit = async (e) => {
    e.preventDefault()
    setError(null)
    if (!tool.trim()) { setError('Tool is required (audit log).'); return }
    const missing = isDigital ? examTargetMissing(target) : null
    if (missing) { setError(missing); return }
    setBusy(true)
    try {
      await api.examineEvidence(incidentId, item.id, {
        tool: tool.trim(),
        notes: notes.trim() || null,
        ...(isDigital ? {
          working_copy_id: target.inPlace ? null : target.workingCopyId,
          examined_in_place: target.inPlace,
          in_place_reason: target.inPlace ? target.inPlaceReason.trim() : null,
        } : {}),
      })
      onSaved()
    } catch (e2) {
      setError(e2.message || 'Could not record examination')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="modal-backdrop" style={{ background: 'rgba(0,0,0,0.4)' }}
        >
      <div className="modal" role="dialog" aria-labelledby="ev-examine-title">
        <div className="modal-head">
          <h2 id="ev-examine-title">Record examination</h2>
          <button type="button" className="modal-close" onClick={onClose} disabled={busy}>×</button>
        </div>
        <form onSubmit={onSubmit}>
          <div className="modal-body">
            <div className="form">
              <div className="field">
                <label className="field-label" htmlFor="ev-tool">Tool used</label>
                <input id="ev-tool" className="input" value={tool} onChange={(e) => setTool(e.target.value)}
                       autoFocus required maxLength={256}
                       placeholder="e.g. Volatility 3, Autopsy 4.21, manual review" />
              </div>
              <div className="field">
                <label className="field-label" htmlFor="ev-notes">Notes (optional)</label>
                <textarea id="ev-notes" className="input" value={notes} onChange={(e) => setNotes(e.target.value)}
                          rows={4} maxLength={4096}
                          placeholder="What was examined, findings, hashes verified, …" />
              </div>
              {isDigital && <ExamTarget copies={copies} value={target} onChange={setTarget} idPrefix="exq" />}
              <div className="alert info" role="status">
                <span className="alert-icon">i</span>
                <span>This records an examination event in the chain of custody. The platform doesn't run the tool — you run it externally and record what you did.</span>
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
              {busy ? 'Recording…' : 'Record examination'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

// GS-11 — photographs (ISO/IEC 27037 §6.2.1). Uploaded images are encrypted at
// rest; thumbnails fetch via the auth-gated photo route. Legacy caption-only
// photos (no url) render as a caption chip.
// G-fix (R101): a PATCH of the photo list is merged by photo id — every photo is sent with its id and
// only its caption / taken_at change; none can be removed (422 photo_remove_not_supported) and after the
// seal the list can't change at all (409). Adding a photo (POST …/photos) works before and after the seal.
function PhotosPanel({ incidentId, item, isClosed, onReplaceItem, onChanged }) {
  const [caption, setCaption] = useState('')
  const [takenAt, setTakenAt] = useState(item.acquired_at || '')   // FE-L9: the acquisition time, unless you change it
  const [busy, setBusy]       = useState(false)
  const [error, setError]     = useState(null)
  const [editIdx, setEditIdx] = useState(null)
  const [editText, setEditText] = useState('')
  const photos = Array.isArray(item.photos) ? item.photos : []
  const filesGone = item.status === 'destroyed'
  const canEdit = !isClosed && (item.status === 'active' || item.status === 'verify_failed')
  const canEditCaptions = canEdit && !item.coc_sealed

  async function onPick(e) {
    const file = e.target.files?.[0]
    e.target.value = ''   // allow re-selecting the same file
    if (!file) return
    if (!file.type.startsWith('image/')) { setError('File must be an image.'); return }
    setBusy(true); setError(null)
    try {
      const updated = await api.addEvidencePhoto(incidentId, item.id, {
        file, caption: caption.trim() || null, taken_at: takenAt || null,
      })
      setCaption('')
      onReplaceItem?.(updated)
      await onChanged?.()
    } catch (e2) {
      setError(e2.status === 507
        ? `${e2.message || 'The server has no room for the upload right now.'} Try again later or ask an admin.`
        : (e2.message || 'Photo upload failed'))
    } finally {
      setBusy(false)
    }
  }

  // Every photo is sent back with its id (stored photos keep their file and hashes server-side).
  async function saveCaption(i) {
    setBusy(true); setError(null)
    try {
      const list = photos.map((p, j) => ({
        ...(p.id ? { id: p.id } : {}), url: p.url || '',
        caption: j === i ? (editText.trim() || null) : (p.caption ?? null), taken_at: p.taken_at ?? null,
      }))
      const updated = await api.updateEvidence(incidentId, item.id, { photos: list })
      setEditIdx(null)
      onReplaceItem?.(updated)
      await onChanged?.()
    } catch (e2) {
      const code = e2.code || e2.data?.code
      setError(code === 'unknown_photo_id'
        ? 'A photo on this item changed meanwhile (unknown photo id): nothing was changed. Close and reopen the item, then try again.'
        : code === 'photo_remove_not_supported'
          ? 'An uploaded photo can’t be removed: nothing was changed. Close and reopen the item, then try again.'
          : code === 'sealed_field_immutable'
            ? 'The item is sealed: its photos can’t change. Add a new photo instead.'
            : (e2.message || 'Could not save the caption'))
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <h3 className="panel-h" style={{ marginTop: 'var(--space-4)' }}>
        Photographs <span style={{ fontWeight: 400, color: 'var(--muted)', fontSize: 12 }}>· ISO 27037 §6.2.1</span>
      </h3>
      {photos.length === 0 ? (
        <div style={{ color: 'var(--muted)', fontSize: 13 }}>No photographs attached.</div>
      ) : (
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 'var(--space-2)' }} data-testid="ev-photos">
          {photos.map((p, i) => (
            <figure key={p.id || i} style={{ margin: 0, width: 132 }} data-photo-id={p.id || ''}>
              {p.url && !filesGone ? (
                <a href={p.url} target="_blank" rel="noreferrer">
                  <img src={p.url} alt={p.caption || `photo ${i + 1}`}
                       style={{ width: 132, height: 99, objectFit: 'cover',
                                border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)' }} />
                </a>
              ) : (
                <div style={{ width: 132, height: 99, display: 'flex', alignItems: 'center',
                              justifyContent: 'center', fontSize: 11, color: 'var(--muted)',
                              border: '1px dashed var(--border)', borderRadius: 'var(--radius-sm)' }}>
                  {filesGone ? 'file deleted' : 'no image'}
                </div>
              )}
              {editIdx === i ? (
                <div style={{ marginTop: 2 }}>
                  <input className="input compact" value={editText} maxLength={512} aria-label="Photo caption"
                         onChange={e => setEditText(e.target.value)} disabled={busy} data-testid="ev-photo-caption-edit" />
                  <div style={{ display: 'flex', gap: 4, marginTop: 2 }}>
                    <button type="button" className="btn primary" onClick={() => saveCaption(i)} disabled={busy}>Save</button>
                    <button type="button" className="btn ghost" onClick={() => setEditIdx(null)} disabled={busy}>Cancel</button>
                  </div>
                </div>
              ) : (
                <>
                  {p.caption && <figcaption style={{ fontSize: 11, color: 'var(--muted)', marginTop: 2 }}>{p.caption}</figcaption>}
                  {p.taken_at && <div style={{ fontSize: 10, color: 'var(--dim)', fontFamily: 'var(--font-mono)' }}>{formatLocal(p.taken_at)}</div>}
                  {canEditCaptions && (
                    <button type="button" className="btn ghost" style={{ fontSize: 11, marginTop: 2 }} disabled={busy}
                            data-testid="ev-photo-edit" onClick={() => { setEditIdx(i); setEditText(p.caption || ''); setError(null) }}>
                      Edit caption
                    </button>
                  )}
                </>
              )}
            </figure>
          ))}
        </div>
      )}
      {photos.length > 0 && (
        <div className="field-hint" data-testid="ev-photos-rule">
          {item.coc_sealed
            ? 'Sealed: these photos and their captions can’t change, and none can be removed. A new photo can still be added (logged as Photo added).'
            : 'Captions can be edited until the seal. An attached photo can’t be removed.'}
        </div>
      )}
      {canEdit && (
        <div className="form" style={{ marginTop: 'var(--space-2)' }}>
          <div className="form-row">
            <div className="field">
              <label className="field-label" htmlFor="ev-photo-cap">Caption (optional)</label>
              <input id="ev-photo-cap" className="input" value={caption} maxLength={512}
                     onChange={e => setCaption(e.target.value)}
                     placeholder="e.g. Drive in situ, serial visible" disabled={busy} />
            </div>
            <div className="field">
              <label className="field-label" htmlFor="ev-photo-at">Taken at</label>
              <LocalDateTimePicker id="ev-photo-at" value={takenAt} onChange={setTakenAt} clearable disabled={busy} />
              <div className="field-hint">When the photo was taken: starts at the acquisition time. Blank = unknown.</div>
            </div>
          </div>
          <label className="btn" style={{ alignSelf: 'flex-start', cursor: busy ? 'wait' : 'pointer' }}>
            {busy ? 'Uploading…' : 'Add photo'}
            <input type="file" accept="image/*" hidden onChange={onPick} disabled={busy} />
          </label>
        </div>
      )}
      {error && (
        <div className="alert error" role="alert" style={{ marginTop: 'var(--space-2)' }}>
          <span className="alert-icon">!</span><span>{error}</span>
        </div>
      )}
    </>
  )
}


function DisposeModal({ incidentId, item, users, me, onClose, onSaved }) {
  const [kind, setKind]     = useState('archive')
  const [reason, setReason] = useState('')
  const [witnessId, setWitnessId] = useState('')
  const [busy, setBusy]     = useState(false)
  const [error, setError]   = useState(null)
  const isDestroy = kind === 'destroy'
  // GS-10 — legal-hold disposal needs a second approver, distinct from the admin disposing it (the
  // backend refuses witness_id = you); the list leaves you out.
  // G5: a held item can't be destroyed at all (409 legal_hold_active) — release the hold first.
  const needsWitness = !!item.legal_hold
  const holdBlocksDestroy = !!item.legal_hold && isDestroy
  const witnessCandidates = (users || []).filter(u => u.id !== me?.id)

  const onSubmit = async (e) => {
    e.preventDefault()
    setError(null)
    if (!reason.trim()) { setError('Reason is required (audit log).'); return }
    if (needsWitness && !witnessId) {
      setError('This item is under legal hold — a second approver (witness) is required.'); return
    }
    if (isDestroy && !window.confirm(
      `DESTROY this evidence?\n\n${item.name} (${item.identifier})\n\n` +
      `The encrypted file will be PERMANENTLY DELETED. The custody chain and SHA-256 hash are retained, but the file cannot be recovered.\n\nProceed?`
    )) return
    setBusy(true)
    try {
      await api.disposeEvidence(incidentId, item.id, {
        kind, reason: reason.trim(),
        witness_id: needsWitness ? witnessId : null,
      })
      onSaved()
    } catch (e2) {
      setError(e2.message || 'Dispose failed')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="modal-backdrop" style={{ background: 'rgba(0,0,0,0.4)' }}
        >
      <div className="modal" role="dialog" aria-labelledby="ev-dispose-title">
        <div className="modal-head">
          <h2 id="ev-dispose-title">Dispose of evidence (admin)</h2>
          <button type="button" className="modal-close" onClick={onClose} disabled={busy}>×</button>
        </div>
        <form onSubmit={onSubmit}>
          <div className="modal-body">
            <div className="form">
              <div className="field">
                <label className="field-label" htmlFor="ev-dispkind">Disposition</label>
                <select id="ev-dispkind" className="select" value={kind} onChange={(e) => setKind(e.target.value)}>
                  <option value="archive">Archive (status only — file retained)</option>
                  <option value="return">Return to owner (status only — file retained)</option>
                  <option value="destroy" disabled={!!item.legal_hold}>Destroy (delete the encrypted file){item.legal_hold ? ' — not while on legal hold' : ''}</option>
                </select>
              </div>
              <div className="field">
                <label className="field-label" htmlFor="ev-dispreason">Reason / authorisation (required, audited)</label>
                <textarea id="ev-dispreason" className="input" value={reason}
                          onChange={(e) => setReason(e.target.value)} rows={3} maxLength={2048}
                          placeholder="e.g. Retention period expired per IR-RET-04 policy, approved by Legal" />
              </div>
              {needsWitness && (
                <div className="field">
                  <label className="field-label" htmlFor="ev-dispwitness">Second approver / witness (required — legal hold)</label>
                  <select id="ev-dispwitness" className="select" value={witnessId}
                          onChange={(e) => setWitnessId(e.target.value)}>
                    <option value="">— select a different user —</option>
                    {witnessCandidates.map(u => (
                      <option key={u.id} value={u.id}>{u.username}{u.full_name ? ` (${u.full_name})` : ''}</option>
                    ))}
                  </select>
                  <div className="field-hint">Two-person integrity (SWGDE/ACPO): disposing legal-hold evidence requires a second accountable approver — another user, not you (the admin disposing it).</div>
                </div>
              )}
              {item.legal_hold && (
                <div className="alert warn" role="status" data-testid="dispose-hold-note">
                  <span className="alert-icon">!</span>
                  <span>On legal hold: it can't be destroyed until the incident lead or an admin releases the hold. Archive or return needs a second approver.</span>
                </div>
              )}
              {isDestroy && !holdBlocksDestroy && (
                <div className="alert warn" role="status">
                  <span className="alert-icon">!</span>
                  <span>Destruction permanently deletes the encrypted file. SHA-256 + custody chain are retained for legal record. This cannot be undone.</span>
                </div>
              )}
              {error && (
                <div className="alert error" role="alert">
                  <span className="alert-icon">!</span><span>{error}</span>
                </div>
              )}
            </div>
          </div>
          <div className="modal-foot">
            <button type="button" className="btn ghost" onClick={onClose} disabled={busy}>Cancel</button>
            <button type="submit" className="btn primary" disabled={busy || holdBlocksDestroy}>
              {busy ? 'Saving…' : (isDestroy ? 'Destroy evidence' : `Confirm ${kind}`)}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ── Chain-integrity summary card ─────────────────────────────────────────
//
// Per-incident overview shown above the evidence table. Aggregates the
// client-side provenance score so an analyst sees, at a glance, how many
// items are court-ready vs. need work before handoff.

function ChainIntegrityCard({ items }) {
  const agg = aggregateIntegrity(items)
  const Stat = ({ label, value, color }) => (
    <div style={{
      flex: 1, padding: 'var(--space-2) var(--space-3)',
      background: 'var(--surface)',
      borderRight: '1px solid var(--border)',
    }}>
      <div style={{ fontSize: 10, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>{label}</div>
      <div style={{ fontSize: 18, fontWeight: 700, fontFamily: 'var(--font-mono)', color: color || 'var(--text)' }}>{value}</div>
    </div>
  )
  return (
    <div style={{
      display: 'flex',
      border: '1px solid var(--border)', borderRadius: 'var(--radius)',
      overflow: 'hidden',
      marginBottom: 'var(--space-3)',
    }}>
      <Stat label="Items"          value={agg.total} />
      <Stat label="Sealed"         value={agg.sealed}       color="var(--accent)" />
      <Stat label="Legal hold"     value={agg.onHold}       color="var(--med)" />
      <Stat label="Verify failed"  value={agg.verifyFailed} color={agg.verifyFailed ? 'var(--crit)' : 'var(--text)'} />
      <Stat label="Green"          value={agg.dist.green || 0} color="var(--ok)" />
      <Stat label="Amber"          value={agg.dist.amber || 0} color="var(--med)" />
      <div style={{ flex: 1, padding: 'var(--space-2) var(--space-3)', background: 'var(--surface)' }}>
        <div style={{ fontSize: 10, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>Red</div>
        <div style={{ fontSize: 18, fontWeight: 700, fontFamily: 'var(--font-mono)',
                      color: (agg.dist.red || 0) > 0 ? 'var(--crit)' : 'var(--text)' }}>{agg.dist.red || 0}</div>
      </div>
    </div>
  )
}
