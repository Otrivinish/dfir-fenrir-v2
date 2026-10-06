import { useCallback, useEffect, useState } from 'react'
import { useOutletContext } from 'react-router-dom'
import { api } from '../../../api/client.js'
import { useAuth } from '../../../hooks/useAuth.jsx'
import { formatLocal } from '../../../lib/datetime.js'
import { span } from '../../../components/ClockChips.jsx'
import LocalDateTimePicker from '../../../components/LocalDateTimePicker.jsx'

// I2 — Stakeholder notification tracker: one row per stakeholder-matrix rule that matches (or
// matched) the incident's severity and type. The API owns every rule: which obligations exist,
// their countdown (from when the incident first reached the severity), allowed steps, required
// fields, time checks and the roll-up. Recording here sends nothing to anyone.

export const CHANNEL_LABEL = { phone: 'Phone', email: 'Email', in_person: 'In person', oob: 'Out-of-band', other: 'Other' }
const STATUS_LABEL = { pending: 'Pending', notified: 'Notified', not_required: 'Not required' }
const STATUS_PILL = { pending: 'pill-med', notified: 'pill-ok', not_required: 'pill-gray' }
const SUPERSEDED_LABEL = {
  severity_changed: 'severity changed', incident_type: 'incident type no longer matches',
  rule_changed: 'matrix rule changed', rule_removed: 'matrix rule deleted',
}
const SEV_LABEL = { low: 'Low', medium: 'Medium', high: 'High', critical: 'Critical' }
const MIN = 60_000
const HOUR = 60 * MIN

const nowIso = () => new Date().toISOString()
const orNull = v => (v === '' || v === undefined ? null : v)
const itemsOf = r => (Array.isArray(r) ? r : r?.items || [])

// Countdown for a pending, active obligation: --crit when overdue or under 2 h, --high under 12 h.
export function dueChip(x, now) {
  if (x.status !== 'pending' || x.superseded) return null
  const ms = new Date(x.due_at).getTime() - now
  const cls = ms <= 2 * HOUR ? 'crit' : ms <= 12 * HOUR ? 'high' : 'ok'
  return { cls, text: ms <= 0 ? `overdue ${span(ms)}` : `${span(ms)} left` }
}

function Time({ iso }) {
  return iso ? <span className="sn-time" title={formatLocal(iso)}>{formatLocal(iso)}</span> : <span className="sn-dim">—</span>
}

// One modal: mode = notify (record) | correct (edit a recorded one) | not_required | undo.
function NotifyModal({ x, mode, stakeholders, oob, onSave, onClose }) {
  const [f, setF] = useState(() => ({
    notified_at: mode === 'correct' ? x.notified_at : nowIso(),
    channel: x.channel || '', stakeholder_id: x.stakeholder_id || '', oob_log_id: x.oob_log_id || '',
    note: x.note || '', not_required_reason: '', reason: '',
  }))
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)
  const set = k => e => setF(p => ({ ...p, [k]: e?.target ? e.target.value : e }))

  useEffect(() => {
    const onKey = e => { if (e.key === 'Escape' && !busy) onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [busy, onClose])

  const recording = mode === 'notify' || mode === 'correct'
  const submit = async e => {
    e.preventDefault()
    let body
    if (mode === 'notify') body = { status: 'notified' }
    else if (mode === 'not_required') body = { status: 'not_required', not_required_reason: f.not_required_reason }
    else if (mode === 'undo') body = { status: 'pending', reason: f.reason }
    else body = { reason: f.reason }
    if (recording) Object.assign(body, {
      notified_at: f.notified_at, channel: f.channel,
      stakeholder_id: orNull(f.stakeholder_id), oob_log_id: orNull(f.oob_log_id), note: orNull(f.note),
    })
    setError(null); setBusy(true)
    try {
      await onSave(x.id, body)
    } catch (err) {
      setError(err.message || 'Could not save.')
      setBusy(false)
    }
  }

  const title = { notify: 'Record notification', correct: 'Correct notification', not_required: 'Not required', undo: 'Undo' }[mode]
  return (
    <div className="modal-backdrop">
      <div className="modal" role="dialog" aria-labelledby="sn-modal-title">
        <div className="modal-head">
          <h2 id="sn-modal-title">{title}: {x.role}</h2>
          <button type="button" className="modal-close" onClick={onClose} disabled={busy} aria-label="Close">×</button>
        </div>
        <form onSubmit={submit}>
          <div className="modal-body">
            <div className="form">
              {recording && (
                <>
                  <div className="field">
                    <label className="field-label" htmlFor="sn-at">Notified at</label>
                    <LocalDateTimePicker id="sn-at" value={f.notified_at} onChange={set('notified_at')} required />
                    <span className="field-hint">When the stakeholder was told; not in the future. You are recorded as the person who notified them.</span>
                  </div>
                  <div className="field">
                    <label className="field-label" htmlFor="sn-channel">Channel</label>
                    <select id="sn-channel" className="select" required value={f.channel} onChange={set('channel')}>
                      <option value="" disabled>Choose…</option>
                      {Object.entries(CHANNEL_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
                    </select>
                  </div>
                  <div className="field">
                    <label className="field-label" htmlFor="sn-sh">Stakeholder record (optional)</label>
                    <select id="sn-sh" className="select" value={f.stakeholder_id} onChange={set('stakeholder_id')}>
                      <option value="">None</option>
                      {stakeholders.map(s => <option key={s.id} value={s.id}>{s.name}{s.title ? ` · ${s.title}` : ''}</option>)}
                    </select>
                  </div>
                  {oob.length > 0 && (
                    <div className="field">
                      <label className="field-label" htmlFor="sn-oob">Out-of-band log entry (optional)</label>
                      <select id="sn-oob" className="select" value={f.oob_log_id} onChange={set('oob_log_id')}>
                        <option value="">None</option>
                        {oob.map(o => <option key={o.id} value={o.id}>{formatLocal(o.created_at)} · {o.stakeholder_name}</option>)}
                      </select>
                    </div>
                  )}
                  <div className="field">
                    <label className="field-label" htmlFor="sn-note">Note</label>
                    <textarea id="sn-note" className="input" maxLength={4000} value={f.note} onChange={set('note')} />
                  </div>
                </>
              )}
              {mode === 'not_required' && (
                <div className="field">
                  <label className="field-label" htmlFor="sn-nr">Why this notification is not needed</label>
                  <textarea id="sn-nr" className="input" required maxLength={2000} value={f.not_required_reason} onChange={set('not_required_reason')} />
                </div>
              )}
              {(mode === 'undo' || mode === 'correct') && (
                <div className="field">
                  <label className="field-label" htmlFor="sn-reason">Reason</label>
                  <textarea id="sn-reason" className="input" required maxLength={2000} value={f.reason} onChange={set('reason')} />
                  <span className="field-hint">{mode === 'undo' ? 'Clears what was recorded. ' : ''}The reason goes to the audit log.</span>
                </div>
              )}
              {error && <div className="alert error" role="alert"><span className="alert-icon">!</span><span>{error}</span></div>}
            </div>
          </div>
          <div className="modal-foot">
            <button type="button" className="btn ghost" onClick={onClose} disabled={busy}>Cancel</button>
            <button type="submit" className="btn primary" disabled={busy}>{busy ? 'Saving…' : title}</button>
          </div>
        </form>
      </div>
    </div>
  )
}

export default function Notifications() {
  const { inc, isClosed, bumpRail, bumpNotify } = useOutletContext()
  const { user } = useAuth()
  const canWrite = user?.role !== 'viewer'
  const [data, setData] = useState(null)
  const [error, setError] = useState(null)
  const [filter, setFilter] = useState('')
  const [modal, setModal] = useState(null)          // { x, mode }
  const [links, setLinks] = useState({ stakeholders: [], oob: [] })
  const [now, setNow] = useState(() => Date.now())

  const load = useCallback(() => {
    let cancelled = false
    api.listStakeholderNotifications(inc.id, { limit: 500 })
      .then(d => { if (!cancelled) { setData(d); setError(null) } })
      .catch(e => { if (!cancelled) setError(e.message || 'Could not load the notification tracker.') })
    return () => { cancelled = true }
  }, [inc.id])
  useEffect(() => load(), [load, inc.updated_at])
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 30_000)
    return () => clearInterval(t)
  }, [])

  const open = async (x, mode) => {
    setModal({ x, mode })
    if (mode === 'notify' || mode === 'correct') {
      const [s, o] = await Promise.allSettled([api.listStakeholders(inc.id), api.listOOBLog(inc.id)])
      setLinks({ stakeholders: s.status === 'fulfilled' ? itemsOf(s.value) : [],
                 oob: o.status === 'fulfilled' ? itemsOf(o.value) : [] })
    }
  }
  const save = async (id, body) => {
    await api.updateStakeholderNotification(inc.id, id, body)
    setModal(null)
    load()
    bumpRail?.()
    bumpNotify?.()
  }

  if (error && !data) return <div className="panel"><div className="alert error" role="alert"><span className="alert-icon">!</span><span>{error}</span></div></div>
  if (!data) return <div className="panel"><div className="panel-empty">Loading…</div></div>

  const s = data.summary
  const rows = data.items.filter(x => !filter || (filter === 'superseded' ? x.superseded
    : filter === 'overdue' ? x.overdue : !x.superseded && x.status === filter))
  return (
    <div className="panel sn-page">
      <div className="panel-toolbar">
        <h2 className="panel-h">Notifications</h2>
        <span className="sn-summary" data-summary>
          <b>{s.notified} of {s.required_total}</b> required notified
          {s.overdue > 0 && <> · <span className="sn-overdue">{s.overdue} overdue</span></>}
          {s.not_required > 0 && <> · {s.not_required} not required</>}
        </span>
        <select className="select" value={filter} onChange={e => setFilter(e.target.value)} aria-label="Filter notifications">
          <option value="">All</option>
          <option value="overdue">Overdue</option>
          {Object.entries(STATUS_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
          <option value="superseded">Superseded</option>
        </select>
      </div>
      <p className="sn-dim sn-intro">
        From the stakeholder matrix (Settings › Stakeholder matrix). Each countdown starts when the incident first reached
        the rule’s severity. Recording here sends nothing: notify the stakeholder yourself, then record when and how.
      </p>
      {data.severity_levels.length > 0 && (
        <div className="sn-levels" data-levels>
          Severity reached:{' '}
          {data.severity_levels.map((lv, i) => (
            <span key={lv.severity}>{i > 0 && ' → '}<b>{SEV_LABEL[lv.severity]}</b> <Time iso={lv.reached_at} /></span>
          ))}
        </div>
      )}
      {error && <div className="alert error" role="alert"><span className="alert-icon">!</span><span>{error}</span></div>}

      {data.items.length === 0 ? (
        <div className="panel-empty">
          <div className="panel-empty-mark" aria-hidden="true">✉</div>
          <div>No stakeholder matrix rule matches this incident’s severity and type.</div>
        </div>
      ) : (
        <div className="table-scroll">
          <table className="settings-table compact sn-table">
            <thead>
              <tr>
                <th>Stakeholder</th>
                <th>Due</th>
                <th>Status</th>
                <th>Notified</th>
                {canWrite && <th className="actions">Actions</th>}
              </tr>
            </thead>
            <tbody>
              {rows.map(x => {
                const chip = dueChip(x, now)
                const writable = canWrite && (!isClosed || (x.status === 'pending'))
                return (
                  <tr key={x.id} data-notification={x.id} data-status={x.status} data-overdue={x.overdue ? 'true' : 'false'}
                      className={x.superseded ? 'sn-superseded' : undefined}>
                    <td>
                      <div className="sn-role">{x.role}</div>
                      <div className="sn-dim">
                        {SEV_LABEL[x.severity]} · {x.category} · within {span(x.notify_within_minutes * MIN)}
                        {!x.required && <> · advisory</>}
                      </div>
                      {x.superseded && <div className="sn-dim">Superseded: {SUPERSEDED_LABEL[x.superseded_reason] || x.superseded_reason}</div>}
                    </td>
                    <td>
                      <Time iso={x.due_at} />
                      {chip && <div><span className={`clock-chip ${chip.cls}`} data-due-chip><span className="clock-chip-left">{chip.text}</span></span></div>}
                      <div className="sn-dim" title={formatLocal(x.clock_start_at)}>from {formatLocal(x.clock_start_at)}</div>
                    </td>
                    <td>
                      <span className={`pill ${STATUS_PILL[x.status]}`}>{STATUS_LABEL[x.status]}</span>
                      {x.not_required_reason && <div className="sn-dim sn-wrap">{x.not_required_reason}</div>}
                    </td>
                    <td>
                      {x.status === 'notified' ? (
                        <>
                          <Time iso={x.notified_at} />
                          <div className="sn-dim">
                            {CHANNEL_LABEL[x.channel] || x.channel}{x.notified_by_username && <> · by {x.notified_by_username}</>}
                            {new Date(x.notified_at) > new Date(x.due_at) && <> · <span className="sn-overdue">late</span></>}
                          </div>
                          {x.stakeholder_name && <div className="sn-dim">To {x.stakeholder_name}</div>}
                          {x.oob_log_id && <div className="sn-dim">Linked to an out-of-band log entry</div>}
                        </>
                      ) : <span className="sn-dim">—</span>}
                      {x.note && <div className="sn-dim sn-wrap" title={x.note}>{x.note}</div>}
                    </td>
                    {canWrite && (
                      <td className="actions">
                        {writable && (
                          <div className="sn-actions">
                            {x.status === 'pending' && (
                              <button type="button" className="btn primary" onClick={() => open(x, 'notify')}>Record notified</button>
                            )}
                            {!isClosed && x.status === 'pending' && (
                              <button type="button" className="btn" onClick={() => open(x, 'not_required')}>Not required</button>
                            )}
                            {!isClosed && x.status === 'notified' && (
                              <button type="button" className="btn ghost" onClick={() => open(x, 'correct')}>Correct</button>
                            )}
                            {!isClosed && x.status !== 'pending' && (
                              <button type="button" className="btn ghost" onClick={() => open(x, 'undo')}>Undo</button>
                            )}
                          </div>
                        )}
                      </td>
                    )}
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}

      {modal && (
        <NotifyModal x={modal.x} mode={modal.mode} stakeholders={links.stakeholders} oob={links.oob}
                     onSave={save} onClose={() => setModal(null)} />
      )}
    </div>
  )
}
