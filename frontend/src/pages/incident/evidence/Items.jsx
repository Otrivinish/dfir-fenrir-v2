import { useCallback, useEffect, useState } from 'react'
import { useOutletContext } from 'react-router-dom'
import { useAuth } from '../../../hooks/useAuth.jsx'
import { api } from '../../../api/client.js'
import { formatLocal } from '../../../lib/datetime.js'
import { TLP, labelOf, pillOf } from '../../../lib/incidentVocab.js'
import AcquisitionWizard from './AcquisitionWizard.jsx'
import ExaminationWizard from './ExaminationWizard.jsx'
import { scoreEvidence, severityColor, aggregateIntegrity } from '../../../lib/evidenceProvenance.js'

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

function fmtBytes(n) {
  if (!n && n !== 0) return '—'
  const units = ['B', 'KiB', 'MiB', 'GiB']
  let v = n, i = 0
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++ }
  return `${v.toFixed(i === 0 ? 0 : 1)} ${units[i]}`
}

function shorten(s, n = 12) {
  if (!s) return '—'
  return s.length > n ? `${s.slice(0, n)}…` : s
}

export default function Items() {
  const { inc } = useOutletContext()
  const { user } = useAuth()
  const isClosed = inc?.status === 'closed'
  const isAdmin  = user?.role === 'admin'

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

  const load = useCallback(async () => {
    setError(null)
    try {
      const params = { limit: 200 }
      if (kindFilter)   params.kind   = kindFilter
      if (statusFilter) params.status = statusFilter
      const res = await api.listEvidence(inc.id, params)
      setItems(res.items)
    } catch (e) {
      setError(e.message || 'Could not load evidence')
    } finally {
      setLoading(false)
    }
  }, [inc.id, kindFilter, statusFilter])

  useEffect(() => { load() }, [load])

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
    api.listEntities(inc.id, { limit: 200 })   // backend caps limit at 200
      .then(r => { if (!cancelled) setEntities(r.items || []) })
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
          {!isClosed && <div style={{ color: 'var(--dim)', fontSize: 12 }}>Click "Add evidence" to register a file or physical item.</div>}
        </div>
      ) : (
        <>
          <ChainIntegrityCard items={items} />
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
        </>
      )}

      {modal?.mode === 'add' && (
        <AddEvidenceModal
          incidentId={inc.id}
          entities={entities}
          onClose={() => setModal(null)}
          onSaved={() => { setModal(null); load() }}
        />
      )}
      {modal?.mode === 'wizard' && (
        <AcquisitionWizard
          incidentId={inc.id}
          entities={entities}
          users={users}
          onClose={() => setModal(null)}
          onSaved={() => { setModal(null); load() }}
        />
      )}
      {modal?.mode === 'detail' && (
        <DetailModal
          incidentId={inc.id}
          item={modal.item}
          users={users}
          entities={entities}
          isAdmin={isAdmin}
          isClosed={isClosed}
          onClose={() => setModal(null)}
          onChanged={async () => { await load() }}
          onReplaceItem={replaceItem}
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
        await api.collectDigital(incidentId, {
          name: name.trim(),
          identifier: identifier.trim(),
          description: description.trim() || null,
          tlp,
          collected_location: collectedLocation.trim() || null,
          entity_id: entityId || null,
          file,
        })
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
      setError(err.message || 'Could not add evidence.')
    } finally {
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
                         onChange={(e) => setFile(e.target.files?.[0] || null)} required />
                  <div className="field-hint">Hashed (SHA-256 + SHA-1 + MD5) and encrypted at rest on upload. 1 GiB max.</div>
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

// Working-copy ledger (ISO/IEC 27037 §7.1.3.1.1, Slice C). The master is the stored
// blob (never handed out directly); each row is a tracked, master-verified derivation.
function WorkingCopiesPanel({ incidentId, item, usernameOf, isClosed, onChanged }) {
  const [copies,  setCopies]  = useState([])
  const [loading, setLoading] = useState(true)
  const [purpose, setPurpose] = useState('')
  const [busy,    setBusy]    = useState(false)
  const [err,     setErr]     = useState(null)

  const load = useCallback(async () => {
    setLoading(true)
    try { const r = await api.listWorkingCopies(incidentId, item.id); setCopies(r.items || []) }
    catch { /* non-fatal */ }
    finally { setLoading(false) }
  }, [incidentId, item.id])
  useEffect(() => { load() }, [load])

  const mint = async (e) => {
    e.preventDefault()
    if (!purpose.trim()) { setErr('Purpose is required.'); return }
    setBusy(true); setErr(null)
    try {
      await api.mintWorkingCopy(incidentId, item.id, { purpose: purpose.trim() })
      setPurpose(''); await load(); await onChanged?.()
    } catch (e2) { setErr(e2.message || 'Could not record working copy') }
    finally { setBusy(false) }
  }

  return (
    <>
      <h3 className="panel-h" style={{ marginTop: 'var(--space-4)' }}>
        Working copies{' '}
        <span style={{ fontWeight: 400, color: 'var(--muted)', fontSize: 12 }}>· ISO 27037 §7.1.3.1.1 — master is never handed out directly</span>
      </h3>
      {loading ? (
        <div style={{ color: 'var(--muted)', fontSize: 13 }}>Loading…</div>
      ) : copies.length === 0 ? (
        <div style={{ color: 'var(--muted)', fontSize: 13 }}>No working copies yet. Exports auto-record one per item; or record an out-of-band copy below.</div>
      ) : (
        <ul style={{ listStyle: 'none', margin: 0, padding: 0, display: 'flex', flexDirection: 'column', gap: 6 }}>
          {copies.map(c => (
            <li key={c.id} style={{ fontSize: 12, border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', padding: '6px 10px', background: 'var(--surface-2)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8 }}>
                <span style={{ color: c.verified_against_master ? 'var(--ok)' : 'var(--crit)', fontWeight: 600 }}>
                  {c.verified_against_master ? '✓ verified vs master' : '✗ NOT verified'}
                </span>
                <span style={{ color: 'var(--dim)', fontFamily: 'var(--font-mono)' }}>{(c.created_at || '').slice(0, 19).replace('T', ' ')}</span>
              </div>
              <div style={{ color: 'var(--muted)' }}>{c.purpose || '—'}</div>
              <div style={{ color: 'var(--dim)', fontFamily: 'var(--font-mono)', fontSize: 11 }}>
                by {usernameOf(c.created_by_id)}{c.export_id ? ' · via export' : ''}{c.sha256 ? ' · ' + c.sha256.slice(0, 12) + '…' : ''}
              </div>
            </li>
          ))}
        </ul>
      )}
      {!isClosed && item.kind === 'digital_file' && (
        <form onSubmit={mint} style={{ display: 'flex', gap: 6, marginTop: 'var(--space-2)' }}>
          <input className="input" value={purpose} onChange={e => setPurpose(e.target.value)} maxLength={2048}
                 placeholder="Record an out-of-band working copy (e.g. imaged to lab WS-04 for analysis)" />
          <button type="submit" className="btn" disabled={busy}>{busy ? 'Recording…' : 'Record copy'}</button>
        </form>
      )}
      {err && <div className="alert error" role="alert" style={{ marginTop: 6 }}><span className="alert-icon">!</span><span>{err}</span></div>}
    </>
  )
}

function DetailModal({ incidentId, item, users, entities, isAdmin, isClosed, onClose, onChanged, onReplaceItem }) {
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
            </dd>
            <dt>Collected by</dt><dd style={{ fontFamily: 'var(--font-mono)' }}>{usernameOf(item.collected_by_id)}</dd>
            {item.collected_as_role && (
              <><dt>Collected as</dt><dd>{item.collected_as_role === 'defr' ? 'DEFR — first responder' : 'DES — specialist'}</dd></>
            )}
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
                <dt>Encryption</dt><dd>{item.status === 'destroyed' ? 'File deleted (hashes retained)' : 'AES-256-GCM at rest'}</dd>
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

          {error && (
            <div className="alert error" role="alert" style={{ marginTop: 'var(--space-3)' }}>
              <span className="alert-icon">!</span><span>{error}</span>
            </div>
          )}

          <PhotosPanel incidentId={incidentId} item={item} isClosed={isClosed}
            onReplaceItem={onReplaceItem} />

          <h3 className="panel-h" style={{ marginTop: 'var(--space-4)' }}>Custody log</h3>
          {loading ? (
            <div style={{ color: 'var(--muted)', fontSize: 13 }}>Loading…</div>
          ) : events.length === 0 ? (
            <div style={{ color: 'var(--muted)', fontSize: 13 }}>No custody events recorded.</div>
          ) : (
            <CustodyTimeline events={events} usernameOf={usernameOf} />
          )}

          <WorkingCopiesPanel incidentId={incidentId} item={item}
            usernameOf={usernameOf} isClosed={isClosed} onChanged={reload} />
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
            return !isClosed && finalActive && (
              <>
                <button type="button" className="btn" onClick={() => setAction('transfer')} disabled={busy}>
                  {isExternal ? 'Transfer (take back)' : 'Transfer'}
                </button>
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
                            title={externalTip || 'Pre-verify → record → post-verify (ISO 27037 §9.4.2)'}>
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
                          disabled={busy || isExternal}
                          title={externalTip || 'Seal acquisition (locks ISO 27037 + GDPR fields)'}>
                    🔒 Seal
                  </button>
                )}
                {isAdmin && (
                  <button type="button" className="btn primary" onClick={() => setAction('dispose')} disabled={busy}>Dispose</button>
                )}
              </>
            )
          })()}
          {!isClosed && item.status === 'verify_failed' && item.kind === 'digital_file' && (
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
            onClose={() => setAction(null)}
            onSaved={async () => { setAction(null); await reload(); await onChanged() }}
          />
        )}
      </div>
    </div>
  )
}

// ── Custody timeline (vertical list inside detail modal) ──────────────────

const ACTION_COLOR = {
  evidence_collect:        'var(--ok)',
  evidence_transfer:       'var(--accent)',
  evidence_examine:        'var(--med)',
  evidence_verify:         'var(--ok)',
  evidence_verify_failed:  'var(--crit)',
  evidence_update:         'var(--muted)',
  evidence_destroy:        'var(--crit)',
  evidence_return:         'var(--high)',
  evidence_archive:        'var(--muted)',
  evidence_export:         'var(--accent)',
}

const ACTION_LABEL = {
  evidence_collect:       'Collected',
  evidence_transfer:      'Transferred',
  evidence_examine:       'Examined',
  evidence_verify:        'Verified',
  evidence_verify_failed: 'Verify FAILED',
  evidence_update:        'Updated',
  evidence_destroy:       'Destroyed',
  evidence_return:        'Returned',
  evidence_archive:       'Archived',
  evidence_export:        'Exported',
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

function TransferModal({ incidentId, item, users, onClose, onSaved }) {
  // Two-mode picker per ISO/IEC 27037 §9.3 chain coverage:
  //   internal — recipient has a Fenrir account (picker reuses /users/assignable)
  //   external — recipient is a real-world party (courier, external counsel, LE
  //              officer pre-formal-handoff, vendor IR team). Captured as
  //              free-text {name, organisation, contact}.
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
  const [busy, setBusy]       = useState(false)
  const [error, setError]     = useState(null)

  // Filter out the current holder so the picker doesn't offer it back to itself.
  const candidates = (users || []).filter(u => u.id !== item.current_custodian_id)

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
    if (mode === 'internal') {
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

  return (
    <div className="modal-backdrop" style={{ background: 'rgba(0,0,0,0.4)' }}>
      <div className="modal" role="dialog" aria-labelledby="ev-transfer-title">
        <div className="modal-head">
          <h2 id="ev-transfer-title">Transfer custody</h2>
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
                    Internal user (Fenrir account)
                  </button>
                  <button type="button"
                    className={`btn ${mode === 'external' ? 'primary' : 'ghost'}`}
                    style={{ borderRadius: 0, borderLeft: '1px solid var(--border)',
                             fontSize: 12, padding: '4px 12px' }}
                    onClick={() => setMode('external')}>
                    External party (courier / counsel / LE)
                  </button>
                </div>
                <div className="field-hint">
                  {mode === 'internal'
                    ? 'Hands off to another Fenrir analyst. They become the recorded custodian.'
                    : 'Records that the item is in the hands of a real-world party without a Fenrir account. ' +
                      'While external, examine / verify / seal are blocked — transfer back to an internal user first.'}
                </div>
              </div>

              {mode === 'internal' && (
                <div className="field">
                  <label className="field-label" htmlFor="ev-to">Transfer to</label>
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
                          placeholder={mode === 'internal'
                            ? 'e.g. Handoff to malware analyst for static analysis'
                            : 'e.g. Sealed in evidence bag #4471 (tamper-evident), handed to courier for transport to Stockholm Police HQ'} />
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
              {busy ? 'Transferring…' : (mode === 'internal' ? 'Transfer (internal)' : 'Transfer (external)')}
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

  const onSubmit = async (e) => {
    e.preventDefault()
    setError(null)
    if (!tool.trim()) { setError('Tool is required (audit log).'); return }
    setBusy(true)
    try {
      await api.examineEvidence(incidentId, item.id, {
        tool: tool.trim(),
        notes: notes.trim() || null,
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

// GS-11 — photographs (ISO/IEC 27037 §9.1.4). Uploaded images are encrypted at
// rest; thumbnails fetch via the auth-gated photo route. Legacy caption-only
// photos (no url) render as a caption chip.
function PhotosPanel({ incidentId, item, isClosed, onReplaceItem }) {
  const [caption, setCaption] = useState('')
  const [busy, setBusy]       = useState(false)
  const [error, setError]     = useState(null)
  const photos = Array.isArray(item.photos) ? item.photos : []
  const filesGone = item.status === 'destroyed'
  const canEdit = !isClosed && (item.status === 'active' || item.status === 'verify_failed')

  async function onPick(e) {
    const file = e.target.files?.[0]
    e.target.value = ''   // allow re-selecting the same file
    if (!file) return
    if (!file.type.startsWith('image/')) { setError('File must be an image.'); return }
    setBusy(true); setError(null)
    try {
      const updated = await api.addEvidencePhoto(incidentId, item.id, {
        file, caption: caption.trim() || null, taken_at: new Date().toISOString(),
      })
      setCaption('')
      onReplaceItem?.(updated)
    } catch (e2) {
      setError(e2.message || 'Photo upload failed')
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <h3 className="panel-h" style={{ marginTop: 'var(--space-4)' }}>
        Photographs <span style={{ fontWeight: 400, color: 'var(--muted)', fontSize: 12 }}>· ISO 27037 §9.1.4</span>
      </h3>
      {photos.length === 0 ? (
        <div style={{ color: 'var(--muted)', fontSize: 13 }}>No photographs attached.</div>
      ) : (
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 'var(--space-2)' }}>
          {photos.map((p, i) => (
            <figure key={p.id || i} style={{ margin: 0, width: 132 }}>
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
              {p.caption && <figcaption style={{ fontSize: 11, color: 'var(--muted)', marginTop: 2 }}>{p.caption}</figcaption>}
            </figure>
          ))}
        </div>
      )}
      {canEdit && (
        <div className="form" style={{ marginTop: 'var(--space-2)' }}>
          <div className="field">
            <label className="field-label" htmlFor="ev-photo-cap">Caption (optional)</label>
            <input id="ev-photo-cap" className="input" value={caption} maxLength={512}
                   onChange={e => setCaption(e.target.value)}
                   placeholder="e.g. Drive in situ, serial visible" disabled={busy} />
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


function DisposeModal({ incidentId, item, users, onClose, onSaved }) {
  const [kind, setKind]     = useState('archive')
  const [reason, setReason] = useState('')
  const [witnessId, setWitnessId] = useState('')
  const [busy, setBusy]     = useState(false)
  const [error, setError]   = useState(null)
  const isDestroy = kind === 'destroy'
  // GS-10 — legal-hold disposal needs a second approver. The backend enforces
  // "distinct from the disposing admin"; we surface all users and let it gate.
  const needsWitness = !!item.legal_hold
  const witnessCandidates = users || []

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
                  <option value="destroy">Destroy (delete the encrypted file)</option>
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
                  <div className="field-hint">Two-person integrity (SWGDE/ACPO): disposing legal-hold evidence requires a second accountable approver, distinct from the collector.</div>
                </div>
              )}
              {isDestroy && (
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
            <button type="submit" className="btn primary" disabled={busy}>
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
