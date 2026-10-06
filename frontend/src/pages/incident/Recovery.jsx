import { useCallback, useEffect, useState } from 'react'
import { useOutletContext } from 'react-router-dom'
import { api } from '../../api/client.js'
import { useAuth } from '../../hooks/useAuth.jsx'
import { formatLocal } from '../../lib/datetime.js'
import LocalDateTimePicker from '../../components/LocalDateTimePicker.jsx'
import DeclareMilestoneModal, { MILESTONES } from '../../components/DeclareMilestoneModal.jsx'

// I1 — Recovery tracker: one row per in-scope system (a compromised host / service / network
// range). The API owns every rule: allowed steps (`allowed_transitions`), required fields, time
// checks, the same-person flag and the roll-up (`summary`). This page renders them and sends
// PATCH …/recovery/{entity_id}; nothing here sets the incident's recovered_at by itself.

const STATE_LABEL = {
  not_started: 'Not started', restoring: 'Restoring', restored: 'Restored',
  validated: 'Validated', not_required: 'Not required',
}
const STATE_PILL = {
  not_started: 'pill-gray', restoring: 'pill-med', restored: 'pill-low', validated: 'pill-ok', not_required: 'pill-gray',
}
const BACKWARD = { restoring: ['restored', 'validated'], not_started: ['restoring', 'not_required'] }
const isBack = (from, to) => (BACKWARD[to] || []).includes(from)

function stepLabel(from, to) {
  if (isBack(from, to)) return to === 'restoring' ? 'Restore again' : 'Reset'
  return { restoring: 'Start restore', restored: 'Mark restored', validated: 'Validate', not_required: 'Not required' }[to]
}

// "x/y validated" for the Situation board and the rail: not_required systems are left out of y.
function recoveryCount(s) {
  return { done: s.validated, of: s.total - s.not_required, notRequired: s.not_required }
}

const nowIso = () => new Date().toISOString()
const orNull = v => (v === '' || v === undefined ? null : v)

function Time({ iso }) {
  return iso ? <span className="rec-time" title={formatLocal(iso)}>{formatLocal(iso)}</span> : <span className="rec-dim">—</span>
}

function Checklist({ items, onChange, disabled }) {
  const set = (i, patch) => onChange(items.map((x, j) => (j === i ? { ...x, ...patch } : x)))
  return (
    <div className="rec-checklist">
      {items.map((x, i) => (
        <div className="rec-check-row" key={i}>
          <input type="checkbox" checked={x.done} disabled={disabled} aria-label={`Done: ${x.item || 'item'}`}
                 onChange={e => set(i, { done: e.target.checked })} />
          <input className="input compact" value={x.item} maxLength={200} disabled={disabled} placeholder="Check performed"
                 aria-label="Checklist item" onChange={e => set(i, { item: e.target.value })} />
          <button type="button" className="btn ghost" disabled={disabled} aria-label="Remove item"
                  onClick={() => onChange(items.filter((_, j) => j !== i))}>×</button>
        </div>
      ))}
      {items.length < 30 && (
        <button type="button" className="btn ghost" disabled={disabled}
                onClick={() => onChange([...items, { item: '', done: false }])}>+ Add check</button>
      )}
    </div>
  )
}

// One modal for a state step (`to`) or for editing the record's details (`to` = null).
function RecoveryModal({ sys, to, userId, onSave, onClose }) {
  const back = to && isBack(sys.state, to)
  const editing = !to
  const [f, setF] = useState(() => ({
    reason: '', not_required_reason: '',
    restore_point_ref: sys.restore_point_ref || '', restore_point_at: sys.restore_point_at || '',
    restored_at: to === 'restored' ? nowIso() : (sys.restored_at || ''),
    validation_method: sys.validation_method || '',
    validation_checklist: sys.validation_checklist || [],
    validated_at: to === 'validated' ? nowIso() : (sys.validated_at || ''),
    monitoring_start: sys.monitoring_start || '', monitoring_end: sys.monitoring_end || '',
    notes: sys.notes || '',
  }))
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)
  const set = k => e => setF(p => ({ ...p, [k]: e?.target ? e.target.value : e }))

  useEffect(() => {
    const onKey = e => { if (e.key === 'Escape' && !busy) onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [busy, onClose])

  const showRestorePoint = editing || (!back && ['restoring', 'restored'].includes(to))
  const showValidation = (editing && sys.state === 'validated') || to === 'validated'
  const showWindow = editing || to === 'validated'
  const selfValidate = to === 'validated' && sys.restored_by_id && sys.restored_by_id === userId

  const submit = async e => {
    e.preventDefault()
    const body = {}
    if (to) body.state = to
    if (back) body.reason = f.reason
    if (to === 'not_required') body.not_required_reason = f.not_required_reason
    if (showRestorePoint) Object.assign(body, { restore_point_ref: orNull(f.restore_point_ref), restore_point_at: orNull(f.restore_point_at) })
    if (to === 'restored') body.restored_at = f.restored_at
    if (showValidation) Object.assign(body, {
      validation_method: orNull(f.validation_method),
      validation_checklist: f.validation_checklist.filter(x => x.item.trim()),
    })
    if (to === 'validated') body.validated_at = f.validated_at
    if (showWindow) Object.assign(body, { monitoring_start: orNull(f.monitoring_start), monitoring_end: orNull(f.monitoring_end) })
    if (editing) body.notes = orNull(f.notes)
    setError(null); setBusy(true)
    try {
      await onSave(sys.entity_id, body)
    } catch (err) {
      setError(err.message || 'Could not save.')
      setBusy(false)
    }
  }

  const title = editing ? 'Recovery details' : stepLabel(sys.state, to)
  return (
    <div className="modal-backdrop">
      <div className="modal" role="dialog" aria-labelledby="rec-modal-title">
        <div className="modal-head">
          <h2 id="rec-modal-title">{title}: <span className="rec-mono">{sys.entity_value}</span></h2>
          <button type="button" className="modal-close" onClick={onClose} disabled={busy} aria-label="Close">×</button>
        </div>
        <form onSubmit={submit}>
          <div className="modal-body">
            <div className="form">
              {back && (
                <div className="field">
                  <label className="field-label" htmlFor="rec-reason">Reason for going back</label>
                  <textarea id="rec-reason" className="input" required maxLength={2000} value={f.reason} onChange={set('reason')} />
                  <span className="field-hint">Clears the later sign-offs; the reason goes to the audit log.</span>
                </div>
              )}
              {to === 'not_required' && (
                <div className="field">
                  <label className="field-label" htmlFor="rec-nr">Why no restore is needed</label>
                  <textarea id="rec-nr" className="input" required maxLength={2000} value={f.not_required_reason} onChange={set('not_required_reason')} />
                </div>
              )}
              {showRestorePoint && (
                <>
                  <div className="field">
                    <label className="field-label" htmlFor="rec-rp">Restore point (backup id, snapshot or image)</label>
                    <input id="rec-rp" className="input" maxLength={512} required={to === 'restored'}
                           value={f.restore_point_ref} onChange={set('restore_point_ref')} />
                  </div>
                  <div className="field">
                    <label className="field-label" htmlFor="rec-rp-at">Restore point time</label>
                    <LocalDateTimePicker id="rec-rp-at" value={f.restore_point_at} onChange={set('restore_point_at')} clearable />
                  </div>
                </>
              )}
              {to === 'restored' && (
                <div className="field">
                  <label className="field-label" htmlFor="rec-restored-at">Restored at</label>
                  <LocalDateTimePicker id="rec-restored-at" value={f.restored_at} onChange={set('restored_at')} required />
                  <span className="field-hint">You are recorded as the person who restored it.</span>
                </div>
              )}
              {showValidation && (
                <>
                  {selfValidate && (
                    <div className="alert warn" role="status">
                      <span className="alert-icon">!</span>
                      <span>You restored this system. A second responder should validate it; if you go ahead, it is flagged as same-person validation.</span>
                    </div>
                  )}
                  <div className="field">
                    <label className="field-label" htmlFor="rec-vm">Validation method</label>
                    <textarea id="rec-vm" className="input" maxLength={4000} required={to === 'validated'}
                              placeholder="e.g. EDR full scan clean, hashes match the gold image, no beaconing in 24 h of proxy logs"
                              value={f.validation_method} onChange={set('validation_method')} />
                  </div>
                  <div className="field">
                    <span className="field-label">Checklist (optional)</span>
                    <Checklist items={f.validation_checklist} disabled={busy}
                               onChange={v => setF(p => ({ ...p, validation_checklist: v }))} />
                  </div>
                  {to === 'validated' && (
                    <div className="field">
                      <label className="field-label" htmlFor="rec-val-at">Validated at</label>
                      <LocalDateTimePicker id="rec-val-at" value={f.validated_at} onChange={set('validated_at')} required />
                      <span className="field-hint">You are recorded as the validator.</span>
                    </div>
                  )}
                </>
              )}
              {showWindow && (
                <div className="rec-window">
                  <div className="field">
                    <label className="field-label" htmlFor="rec-mon-start">Monitoring from</label>
                    <LocalDateTimePicker id="rec-mon-start" value={f.monitoring_start} onChange={set('monitoring_start')} clearable />
                  </div>
                  <div className="field">
                    <label className="field-label" htmlFor="rec-mon-end">Monitoring until</label>
                    <LocalDateTimePicker id="rec-mon-end" value={f.monitoring_end} onChange={set('monitoring_end')} clearable />
                  </div>
                </div>
              )}
              {editing && (
                <div className="field">
                  <label className="field-label" htmlFor="rec-notes">Notes</label>
                  <textarea id="rec-notes" className="input" maxLength={8000} value={f.notes} onChange={set('notes')} />
                </div>
              )}
              {error && (
                <div className="alert error" role="alert"><span className="alert-icon">!</span><span>{error}</span></div>
              )}
            </div>
          </div>
          <div className="modal-foot">
            <button type="button" className="btn ghost" onClick={onClose} disabled={busy}>Cancel</button>
            <button type="submit" className="btn primary" disabled={busy}>{busy ? 'Saving…' : editing ? 'Save' : title}</button>
          </div>
        </form>
      </div>
    </div>
  )
}

export default function Recovery() {
  const { inc, canEdit, applyUpdate, bumpRail } = useOutletContext()
  const { user } = useAuth()
  const [data, setData] = useState(null)
  const [error, setError] = useState(null)
  const [filter, setFilter] = useState('')
  const [modal, setModal] = useState(null)         // { sys, to } — to = null edits details
  const [declaring, setDeclaring] = useState(false)

  const load = useCallback(() => {
    let cancelled = false
    api.listRecovery(inc.id, { limit: 500 })
      .then(d => { if (!cancelled) { setData(d); setError(null) } })
      .catch(e => { if (!cancelled) setError(e.message || 'Could not load the recovery tracker.') })
    return () => { cancelled = true }
  }, [inc.id])
  useEffect(() => load(), [load, inc.updated_at])

  const save = async (entityId, body) => {
    await api.updateRecovery(inc.id, entityId, body)
    setModal(null)
    load()
    bumpRail()
  }
  const declare = async (field, value) => {
    applyUpdate(await api.updateIncident(inc.id, { [field]: value }))
    setDeclaring(false)
  }

  if (error && !data) return <div className="panel"><div className="alert error" role="alert"><span className="alert-icon">!</span><span>{error}</span></div></div>
  if (!data) return <div className="panel"><div className="panel-empty">Loading…</div></div>

  const s = data.summary
  const c = recoveryCount(s)
  const rows = filter ? data.items.filter(x => x.state === filter) : data.items
  return (
    <div className="panel rec-page" data-recovery-complete={s.complete ? 'true' : 'false'}>
      <div className="panel-toolbar">
        <h2 className="panel-h">Recovery</h2>
        <span className="rec-summary" data-summary>
          <b>{c.done}/{c.of}</b> validated
          {c.notRequired > 0 && <> · {c.notRequired} not required</>}
          {s.restoring > 0 && <> · {s.restoring} restoring</>}
          {s.restored > 0 && <> · {s.restored} awaiting validation</>}
          {s.not_started > 0 && <> · {s.not_started} not started</>}
        </span>
        <select className="select" value={filter} onChange={e => setFilter(e.target.value)} aria-label="Filter by state">
          <option value="">All states</option>
          {Object.entries(STATE_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
        </select>
      </div>

      {s.can_declare_recovered && canEdit && (
        <div className="alert info rec-declare" role="status">
          <span className="alert-icon">✓</span>
          <span>Every system in scope is validated or not required. Declare the incident recovered when normal operation is confirmed.</span>
          <button type="button" className="btn primary" onClick={() => setDeclaring(true)}>Declare recovered</button>
        </div>
      )}
      {s.same_person_validations > 0 && (
        <div className="alert warn" role="status">
          <span className="alert-icon">!</span>
          <span>{s.same_person_validations} system{s.same_person_validations === 1 ? ' was' : 's were'} validated by the person who restored {s.same_person_validations === 1 ? 'it' : 'them'}. A second responder should confirm.</span>
        </div>
      )}
      {error && <div className="alert error" role="alert"><span className="alert-icon">!</span><span>{error}</span></div>}

      {data.items.length === 0 ? (
        <div className="panel-empty">
          <div className="panel-empty-mark" aria-hidden="true">⊘</div>
          <div>No systems in scope.</div>
          <div className="rec-dim">Mark hosts, services or network ranges as compromised on Entities; they appear here.</div>
        </div>
      ) : (
        <div className="table-scroll">
          <table className="settings-table compact rec-table">
            <thead>
              <tr>
                <th>System</th>
                <th>State</th>
                <th>Restore point</th>
                <th>Restored</th>
                <th>Validated</th>
                <th>Monitoring window</th>
                {canEdit && <th className="actions">Actions</th>}
              </tr>
            </thead>
            <tbody>
              {rows.map(x => (
                <tr key={x.entity_id} data-entity={x.entity_id} data-state={x.state}>
                  <td>
                    <div className="rec-mono">{x.entity_value}</div>
                    <div className="rec-dim">{x.entity_type.replace('_', ' ')} · {x.criticality}</div>
                  </td>
                  <td>
                    <span className={`pill ${STATE_PILL[x.state]}`}>{STATE_LABEL[x.state]}</span>
                    {x.not_required_reason && <div className="rec-dim rec-wrap">{x.not_required_reason}</div>}
                  </td>
                  <td>
                    {x.restore_point_ref ? <div className="rec-wrap">{x.restore_point_ref}</div> : <span className="rec-dim">—</span>}
                    {x.restore_point_at && <div><Time iso={x.restore_point_at} /></div>}
                  </td>
                  <td>
                    <Time iso={x.restored_at} />
                    {x.restored_by_username && <div className="rec-dim">{x.restored_by_username}</div>}
                  </td>
                  <td>
                    <Time iso={x.validated_at} />
                    {x.validated_by_username && <div className="rec-dim">{x.validated_by_username}</div>}
                    {x.same_person_validation && <div className="rec-flag" title="Validated by the person who restored it">! same person</div>}
                    {x.validation_method && <div className="rec-dim rec-wrap" title={x.validation_method}>{x.validation_method}</div>}
                    {x.validation_checklist.length > 0 && (
                      <div className="rec-dim">{x.validation_checklist.filter(i => i.done).length}/{x.validation_checklist.length} checks</div>
                    )}
                  </td>
                  <td>
                    {x.monitoring_start || x.monitoring_end
                      ? <><Time iso={x.monitoring_start} /><div className="rec-dim">until</div><Time iso={x.monitoring_end} /></>
                      : <span className="rec-dim">—</span>}
                  </td>
                  {canEdit && (
                    <td className="actions">
                      <div className="rec-actions">
                        {x.allowed_transitions.map(to => (
                          <button key={to} type="button" className={`btn${!isBack(x.state, to) && to !== 'not_required' ? ' primary' : ''}`}
                                  onClick={() => setModal({ sys: x, to })}>{stepLabel(x.state, to)}</button>
                        ))}
                        <button type="button" className="btn ghost" onClick={() => setModal({ sys: x, to: null })}>Edit</button>
                      </div>
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {modal && (
        <RecoveryModal sys={modal.sys} to={modal.to} userId={user?.id} onSave={save} onClose={() => setModal(null)} />
      )}
      {declaring && (
        <DeclareMilestoneModal milestone={MILESTONES[2]} onConfirm={declare} onClose={() => setDeclaring(false)} />
      )}
    </div>
  )
}
