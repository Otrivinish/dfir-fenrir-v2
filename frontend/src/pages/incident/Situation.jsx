import { Component, useEffect, useMemo, useState } from 'react'
import { Link, useOutletContext } from 'react-router-dom'
import ReactMarkdown from 'react-markdown'
import { api } from '../../api/client.js'
import { formatLocal } from '../../lib/datetime.js'
import { PHASE } from '../../lib/incidentVocab.js'
import { MILESTONES } from '../../components/DeclareMilestoneModal.jsx'
import { legalClocks, span } from '../../components/ClockChips.jsx'
import ClassificationStrip from '../../components/ClassificationStrip.jsx'
import ContainmentBadge from '../../components/ContainmentBadge.jsx'
import StakeholderMatrixBanner from '../../components/StakeholderMatrixBanner.jsx'
import { notificationsChip } from '../../components/NotificationsChip.jsx'
import { usePhaseTimes } from '../../components/PhaseStepper.jsx'

// Situation board: the incident landing tab. A read-only, one-screen summary built from
// existing endpoints; every rule (gates, containment state, counts) comes from the API.

const PHASE_BY_VALUE = Object.fromEntries(PHASE.map(p => [p.value, p]))
const OPEN = ['open', 'in_progress']
const CATEGORY = { containment: 'Containment', eradication: 'Eradication', recovery: 'Recovery' }
const CATEGORY_ORDER = Object.keys(CATEGORY)
// Phases in which a missing Contained time is shown as NOT CONTAINED.
const CONTAINED_BY = ['containment_eradication_recovery', 'post_incident']
const DESC_LINES = 6

// The board's reads, in parallel. A panel lists the keys it needs and shows its own error.
const LOADS = {
  snapshot: id => api.getIncidentSnapshot(id),
  gates:    id => api.getIncidentGates(id),
  actions:  id => api.listRespondActions(id, { limit: 200 }),
  scope:    id => api.listEntities(id, { compromised: true, limit: 200 }),
  iocs:     id => api.listIocs(id, { limit: 200 }),
  handoffs: id => api.listHandoffs(id),
  tasks:    id => api.listPlaybookTasks(id),
  legal:    id => api.listDeadlines(id),
  events:   id => api.listTimelineEvents(id, { sort: '-event_time', limit: 5, key: true }),   // K3: key events
  coverage: id => api.getRosterCoverage(id),
  users:    () => api.listAssignableUsers(),
}

// Re-read when the incident changes (any save bumps updated_at); a stale response is dropped.
// The reads are tagged with the incident they belong to: after a switch to another incident,
// the previous one's data renders as loading, never under the new header.
function useBoard(inc) {
  const [board, setBoard] = useState(null)   // { id, data }
  useEffect(() => {
    let cancelled = false
    const keys = Object.keys(LOADS)
    Promise.allSettled(keys.map(k => LOADS[k](inc.id))).then(results => {
      if (cancelled) return
      setBoard({ id: inc.id, data: Object.fromEntries(results.map((r, i) => [keys[i],
        r.status === 'fulfilled' ? { value: r.value } : { error: r.reason?.message || 'Request failed' }])) })
    })
    return () => { cancelled = true }
  }, [inc.id, inc.updated_at])
  return board?.id === inc.id ? board.data : null
}

// A render error in one panel replaces only that panel. It retries when `resetKey` changes
// (another incident, or a re-read of the board), so a panel recovers once its data renders.
class PanelBoundary extends Component {
  state = { failed: false }
  static getDerivedStateFromError() { return { failed: true } }
  componentDidUpdate(prev, prevState) {
    // prevState.failed: not the commit that recorded the failure (its prev props are older).
    if (this.state.failed && prevState.failed && prev.resetKey !== this.props.resetKey) this.setState({ failed: false })
  }
  render() {
    if (!this.state.failed) return this.props.children
    return (
      <section className="panel sit-panel" aria-label={this.props.title} data-panel={this.props.title}>
        <h2 className="panel-h">{this.props.title}</h2>
        <div className="sit-error" role="alert">Couldn’t show this panel.</div>
      </section>
    )
  }
}

// One panel: heading (+ optional meta and a link to its page), then its body once the reads it
// `need`s are in, or a loading / couldn't-load line. `children(data)` renders the body.
function Panel({ title, meta, to, toLabel, data, need = [], children }) {
  const failed = data ? need.filter(k => data[k].error) : []
  return (
    <section className="panel sit-panel" aria-label={title} data-panel={title}>
      <div className="sit-head">
        <h2 className="panel-h">{title}{meta != null && <span className="sit-meta"> · {meta}</span>}</h2>
        {to && <Link to={`../${to}`} className="sit-more">{toLabel || 'Open'} →</Link>}
      </div>
      {!data && need.length > 0 ? <div className="sit-muted">Loading…</div>
        : failed.length > 0 ? <div className="sit-error" role="alert">Couldn’t load this panel ({failed.map(k => data[k].error).join('; ')}).</div>
        : children(data)}
    </section>
  )
}

const ready = (data, ...keys) => data && keys.every(k => data[k].value !== undefined)
// Username of an assignee; 'assigned' when the user list couldn't be read.
const nameOf = (data, id) => {
  if (!id) return null
  if (!ready(data, 'users')) return 'assigned'
  return data.users.value.find(x => x.id === id)?.username || 'unknown user'
}

// ── Clocks row ──────────────────────────────────────────────────────────────

function Clocks({ inc, data }) {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 60_000)
    return () => clearInterval(t)
  }, [])

  const notContained = !inc.contained_at && CONTAINED_BY.includes(inc.phase)
  // K2 (R38): time in the current phase (snapshot phase_history); earlier phases' durations on hover.
  const hist  = ready(data, 'snapshot') ? data.snapshot.value.phase_history : null
  const times = usePhaseTimes(hist && hist.phase === inc.phase ? hist : null)
  const phase = PHASE_BY_VALUE[inc.phase]
  const tookTitle = times ? [`In ${phase?.label || inc.phase} since ${times.since}`,
    ...(hist.completed || []).map(c => `${PHASE_BY_VALUE[c.phase]?.label || c.phase}: ${span(c.seconds * 1000)}` +
                                      (c.periods > 1 ? ` (${c.periods} periods)` : ''))].join('\n') : undefined
  const cells = [
    { key: 'occurred', label: 'Occurred', at: inc.occurred_at },
    { key: 'detected', label: 'Detected', at: inc.detected_at },
    { key: 'declared', label: 'Declared', at: inc.created_at, title: 'Incident opened in FENRIR' },
    ...MILESTONES.map(m => ({ key: m.field, label: m.title, at: inc[m.field] })),
  ]
  const start = inc.detected_at || inc.created_at
  const end   = inc.closed_at ? new Date(inc.closed_at).getTime() : now
  const elapsed = `${span(end - new Date(start).getTime())} ${inc.detected_at ? 'since detection' : 'since declared'}${inc.closed_at ? ', to close' : ''}`

  let legal
  if (!data) legal = <span className="sit-muted">Loading…</span>
  else if (data.legal.error) legal = <span className="sit-error" role="alert">Couldn’t load legal deadlines.</span>
  else {
    const rows = Array.isArray(data.legal.value) ? data.legal.value : []
    const open = legalClocks(rows, now).filter(c => Number.isFinite(c.ms))
    if (!rows.length) legal = <span className="sit-muted">None recorded</span>
    else if (!open.length) legal = <span className="sit-muted">All completed or waived</span>
    else {
      const c = open[0]
      legal = (
        <Link to="../legal" className={`sit-legal ${c.cls}`} title={c.title} data-reg={c.reg}>
          {c.label}: {c.text}{open.length > 1 && ` (+${open.length - 1} more)`}
        </Link>
      )
    }
  }

  // I2: stakeholder notifications "x of y" from the snapshot roll-up (required matrix rules only).
  let notify
  if (!data) notify = <span className="sit-muted">Loading…</span>
  else if (data.snapshot.error) notify = <span className="sit-error" role="alert">Couldn’t load notifications.</span>
  else {
    const c = notificationsChip(data.snapshot.value.notifications, now)
    notify = c
      ? <Link to="../comms/notifications" className={`sit-legal ${c.cls === 'done' ? '' : c.cls}`} title={c.title} data-notify-line>{c.text}</Link>
      : <span className="sit-muted">None required</span>
  }

  return (
    <section className="panel sit-panel" aria-label="Clocks" data-panel="Clocks">
      <dl className="sit-clocks">
        {cells.map(c => {
          const missing = c.key === 'contained_at' && notContained
          return (
            <div key={c.key} className={`sit-clock${missing ? ' missing' : ''}`} data-clock={c.key}>
              <dt title={c.title}>{c.label}</dt>
              <dd>{c.at ? formatLocal(c.at) : missing ? 'NOT CONTAINED' : <span className="sit-muted">—</span>}</dd>
            </div>
          )
        })}
        <div className="sit-clock" data-clock="elapsed"><dt>Elapsed</dt><dd>{elapsed}</dd></div>
        <div className="sit-clock" data-clock="in-phase" title={tookTitle}>
          <dt>Time in phase</dt>
          <dd>{times ? <>{phase?.short || phase?.label || inc.phase} · {times.inPhase}{times.closed ? ' (closed)' : ''}</>
                     : <span className="sit-muted">{data ? '—' : 'Loading…'}</span>}</dd>
        </div>
        <div className="sit-clock" data-clock="legal"><dt>Nearest legal deadline</dt><dd>{legal}</dd></div>
        <div className="sit-clock" data-clock="notifications"><dt>Stakeholder notifications</dt><dd>{notify}</dd></div>
      </dl>
    </section>
  )
}

// ── Panels ──────────────────────────────────────────────────────────────────

const ROLE_SHORT = { ic: 'IC', dpo: 'DPO' }

function GatePanel({ inc, data }) {
  const name = inc.status === 'closed' ? null : inc.phase === 'post_incident' ? 'close' : 'post_incident'
  return (
    <Panel title="Next gate" data={data} need={name ? ['gates'] : []}>
      {d => {
        if (!name) return <div className="sit-muted">Closed {formatLocal(inc.closed_at)}: no gate pending.</div>
        const g = (d.gates.value.items || []).find(x => x.gate === name)
        if (!g) return <div className="sit-muted">No gate reported.</div>
        if (g.exempt) return <div className="sit-muted" data-gate-state="exempt">{g.label} does not apply to a false or benign positive.</div>
        const warns = g.warnings || []
        const signs = (g.sign_offs_required || []).map(role => {
          const s = (g.sign_offs || []).find(x => x.role === role)
          return <span key={role} data-signoff-role={role} data-signoff-state={s ? 'signed' : 'missing'}>
            {ROLE_SHORT[role]} {s ? '✓' : 'missing'}
          </span>
        })
        const warnLine = warns.length > 0 && (
          <div className="sit-sub" data-gate-group="warn">
            {warns.length} {warns.length === 1 ? 'warning' : 'warnings'} (not blocking):{' '}
            {warns.slice(0, 2).map((it, i) => (
              <span key={it.key} data-gate-key={it.key} data-gate-level="warn">
                {i > 0 && '; '}{it.route ? <Link to={`../${it.route}`}>{it.label}</Link> : it.label}
              </span>
            ))}
            {warns.length > 2 && '; …'}
          </div>
        )
        const signLine = signs.length > 0 && (
          <div className="sit-sub" data-gate-signoffs>Sign-offs: {signs.reduce((a, el, i) => i ? [...a, ', ', el] : [el], [])}</div>
        )
        if (g.met) return (
          <div data-gate-state="met">
            <span className="sit-ok"><span className="sit-ok-mark" aria-hidden="true">✓</span> {g.label}: met</span>
            {warnLine}
            {signLine}
            {g.carried_forward?.length > 0 && <div className="sit-sub">{g.carried_forward.length} open obligation(s) carried forward</div>}
          </div>
        )
        const top = g.unmet.slice(0, 3)
        return (
          <div data-gate-state="unmet">
            <div className="sit-warn">{g.label}: {g.unmet.length} blocking {g.unmet.length === 1 ? 'item' : 'items'}</div>
            <ul className="sit-list" data-gate-group="block">
              {top.map(it => (
                <li key={it.key} data-gate-key={it.key} data-gate-level="block">
                  {it.route ? <Link to={`../${it.route}`}>{it.label}</Link> : it.label}
                </li>
              ))}
            </ul>
            {g.unmet.length > top.length && <div className="sit-sub">+{g.unmet.length - top.length} more, listed when you change phase or close</div>}
            {warnLine}
            {signLine}
          </div>
        )
      }}
    </Panel>
  )
}

// I4: incident-start checks from the snapshot (the API computes each status). Open ones first, each
// with a link to the page that fixes it; met ones are only counted. Hidden on a closed incident.
const SC_MARK = { ok: '✓', warning: '!', overdue: '✕' }

function StartChecksPanel({ data }) {
  const sc = ready(data, 'snapshot') ? data.snapshot.value.start_checks : null
  return (
    <Panel title="Start checks" meta={sc ? `${sc.ok} of ${sc.total} met` : null} data={data} need={['snapshot']}>
      {() => {
        if (!sc) return <div className="sit-muted">Not reported.</div>
        const open = sc.items.filter(i => i.status !== 'ok').sort((a, b) => (a.status === 'overdue' ? 0 : 1) - (b.status === 'overdue' ? 0 : 1))
        if (!open.length) return <div className="sit-ok"><span className="sit-ok-mark" aria-hidden="true">✓</span> All {sc.total} start checks met</div>
        return (
          <>
            <ul className="sc-list">
              {open.map(i => (
                <li key={i.key} className={`sc-item ${i.status}`} data-start-check={i.key} data-status={i.status}>
                  <span className="sc-mark" aria-hidden="true">{SC_MARK[i.status]}</span>
                  <span className="sc-label">{i.label}</span>
                  <span className="sc-state">{i.status === 'overdue' ? 'overdue' : 'missing'}</span>
                  <Link to={`../${i.route}`} className="sit-more">Fix →</Link>
                  {i.detail && <span className="sc-detail">{i.detail}</span>}
                </li>
              ))}
            </ul>
            {sc.warning > 0 && <div className="sit-sub">Missing checks turn overdue {sc.overdue_after_minutes} min after the incident was opened ({formatLocal(sc.overdue_at)}).</div>}
          </>
        )
      }}
    </Panel>
  )
}

function ContainmentPanel({ data }) {
  const actions = ready(data, 'actions') ? data.actions.value.items : []
  const open = actions.filter(a => OPEN.includes(a.status))
    .sort((a, b) => CATEGORY_ORDER.indexOf(a.category) - CATEGORY_ORDER.indexOf(b.category) || new Date(a.created_at) - new Date(b.created_at))
  const more = ready(data, 'actions') && data.actions.value.next_cursor ? '+' : ''
  const entities = new Map(ready(data, 'scope') ? data.scope.value.items.map(e => [e.id, e]) : [])
  const iocs     = new Map(ready(data, 'iocs') ? data.iocs.value.items.map(i => [i.id, i]) : [])
  const now = Date.now()
  return (
    <Panel title="Open response actions" meta={ready(data, 'actions') ? `${open.length} open / ${actions.length}${more}` : null}
           to="containment" toLabel="Containment" data={data} need={['actions']}>
      {() => {
        if (!actions.length) return <div className="sit-muted">No response actions yet.</div>
        if (!open.length) return <div className="sit-muted">No open actions.</div>
        return (
          <>
            <ul className="sit-list">
              {open.slice(0, 5).map(a => {
                const target = a.details?.target
                const ent = a.entity_id && entities.get(a.entity_id)
                const ioc = a.ioc_id && iocs.get(a.ioc_id)
                return (
                  <li key={a.id} data-action={a.id}>
                    <span className="pill pill-gray">{CATEGORY[a.category] || a.category}</span>
                    <span className="sit-title">{a.title}</span>
                    {a.entity_id || a.ioc_id ? (
                      <span className="sit-target">
                        <Link to={`../${a.entity_id ? 'scope' : 'iocs'}`}>{target || (ent || ioc)?.value || 'linked target'}</Link>
                        <ContainmentBadge containment={(ent || ioc)?.containment} />
                      </span>
                    ) : target ? <span className="sit-sub">{target}</span> : null}
                    <span className="sit-sub">
                      {nameOf(data, a.assignee_id) || 'unassigned'}
                      {a.status === 'in_progress' && ' · in progress'}
                      {' · '}<span title={formatLocal(a.created_at)}>{span(now - new Date(a.created_at).getTime())} old</span>
                    </span>
                  </li>
                )
              })}
            </ul>
            {open.length > 5 && <div className="sit-sub">+{open.length - 5} more on Containment and Eradication &amp; Recovery</div>}
          </>
        )
      }}
    </Panel>
  )
}

function ScopePanel({ data }) {
  return (
    <Panel title="Scope" to="scope" toLabel="Scope" data={data} need={['snapshot', 'scope']}>
      {d => {
        const s = d.snapshot.value
        const hosts = d.scope.value.items
        return (
          <>
            <div className="sit-counts">
              <span><b>{s.affected_systems}</b> compromised</span>
              <span><b>{s.entities}</b> entities</span>
              <Link to="../iocs"><b>{s.iocs}</b> IOCs</Link>
              {s.recovery?.total > 0 && (
                <Link to="../recovery" data-recovery-count>
                  Recovery <b>{s.recovery.validated}/{s.recovery.total - s.recovery.not_required}</b> validated
                  {s.recovery.not_required > 0 && <> · {s.recovery.not_required} not required</>}
                </Link>
              )}
            </div>
            {hosts.length === 0 ? <div className="sit-muted">No entity is marked compromised yet.</div> : (
              <ul className="sit-list">
                {hosts.slice(0, 5).map(e => (
                  <li key={e.id} data-entity={e.id}>
                    <span className="sit-mono">{e.value}</span>
                    <ContainmentBadge containment={e.containment} />
                  </li>
                ))}
              </ul>
            )}
            {s.affected_systems > 5 && <div className="sit-sub">+{s.affected_systems - Math.min(5, hosts.length)} more</div>}
          </>
        )
      }}
    </Panel>
  )
}

function TeamPanel({ data }) {
  const slots = ready(data, 'coverage') ? data.coverage.value.slots || [] : []
  const filled = slots.filter(s => s.assignments.length > 0).length
  return (
    <Panel title="Team" meta={ready(data, 'coverage') && slots.length ? `${filled} of ${slots.length} roles filled` : null}
           to="assignments" toLabel="Team" data={data} need={['coverage']}>
      {() => slots.length === 0 ? <div className="sit-muted">No operational roles configured.</div> : (
        <ul className="sit-slots">
          {slots.map(s => {
            const vacant = s.assignments.length === 0
            return (
              <li key={s.role_id} className={`sit-slot${vacant ? ' vacant' : ''}`} data-role={s.role_key}>
                <span className="sit-slot-role">{s.role_label}</span>
                <span className="sit-slot-who">{vacant ? 'vacant' : s.assignments.map(a => a.username).join(', ')}</span>
              </li>
            )
          })}
        </ul>
      )}
    </Panel>
  )
}

function HandoffPanel({ data }) {
  return (
    <Panel title="Latest shift handoff" to="handoffs" toLabel="Shift handoffs" data={data} need={['handoffs']}>
      {d => {
        const h = (d.handoffs.value.items || [])[0]
        if (!h) return <div className="sit-muted">No shift handoffs yet.</div>
        return (
          <div className="sit-handoff">
            <div>
              <b>{h.outgoing_username}</b> → <b>{h.incoming_username}</b>
              <span className="sit-sub"> · {formatLocal(h.created_at)} · </span>
              {h.status === 'acknowledged'
                ? <span className="sit-sub">acknowledged</span>
                : <span className="sit-warn">awaiting acknowledgement</span>}
            </div>
            {h.current_hypothesis
              ? <blockquote className="sit-hypothesis">“{h.current_hypothesis}” <span className="sit-sub">({h.hypothesis_confidence}% confidence)</span></blockquote>
              : <div className="sit-muted">No hypothesis recorded.</div>}
          </div>
        )
      }}
    </Panel>
  )
}

function TasksPanel({ inc, data }) {
  const phase = PHASE_BY_VALUE[inc.phase]
  const tasks = ready(data, 'tasks') && Array.isArray(data.tasks.value) ? data.tasks.value : []
  const open = tasks.filter(t => t.phase === inc.phase && OPEN.includes(t.status)).sort((a, b) => a.order_index - b.order_index)
  const now = Date.now()
  return (
    <Panel title="Next tasks" meta={phase ? phase.label : null} to="playbook" toLabel="Playbook" data={data} need={['tasks']}>
      {() => {
        if (!tasks.length) return <div className="sit-muted">No playbook applied.</div>
        if (!open.length) return <div className="sit-muted">No open tasks for this phase.</div>
        return (
          <>
            <ul className="sit-list">
              {open.slice(0, 3).map(t => {
                const due = t.due_at && new Date(t.due_at).getTime()
                return (
                  <li key={t.id} data-task={t.id}>
                    <span aria-hidden="true">☐</span>
                    <span className="sit-title">{t.title}</span>
                    <span className="sit-sub">
                      {nameOf(data, t.assignee_id) || 'unassigned'}
                      {t.status === 'in_progress' && ' · in progress'}
                      {due && (due <= now
                        ? <> · <span className="sit-crit" title={formatLocal(t.due_at)}>overdue {span(now - due)}</span></>
                        : <> · <span title={formatLocal(t.due_at)}>due in {span(due - now)}</span></>)}
                    </span>
                  </li>
                )
              })}
            </ul>
            {open.length > 3 && <div className="sit-sub">{open.length} open in this phase</div>}
          </>
        )
      }}
    </Panel>
  )
}

// K3 (R39): the newest 5 key events (key_event: flagged, ATT&CK-tagged or recorded by FENRIR).
function EventsPanel({ inc, data }) {
  return (
    <Panel title="Key timeline" meta="newest 5" to="timeline?key=true" toLabel="Timeline" data={data} need={['events']}>
      {d => {
        const events = d.events.value.items || []
        return (
          <>
          {!events.length ? <div className="sit-muted">No key events yet. Flag one on the Timeline (★ Key event), or tag it with ATT&amp;CK.</div> : (
          <ul className="sit-list sit-events">
            {events.map(e => (
              <li key={e.id} data-event={e.id}>
                <span className="sit-mono sit-time">{formatLocal(e.event_time)}</span>
                <span className="sit-event-text" title={e.description}>{e.description}</span>
                {e.hostname && <span className="sit-sub sit-mono">{e.hostname}</span>}
              </li>
            ))}
          </ul>
          )}
          {inc.status !== 'closed' && <Link to="../timeline?add=1" className="sit-more" data-add-event>+ event</Link>}
          </>
        )
      }}
    </Panel>
  )
}

function DescriptionPanel({ inc }) {
  const lines = (inc.description || '').split('\n')
  const cut = lines.length > DESC_LINES
  return (
    <Panel title="Description" to="details" toLabel={cut ? 'Show all' : 'Details'}>
      {() => inc.description?.trim()
        ? <div className="md-body sit-desc"><ReactMarkdown>{cut ? lines.slice(0, DESC_LINES).join('\n') + '\n\n…' : inc.description}</ReactMarkdown></div>
        : <div className="sit-muted">No description.</div>}
    </Panel>
  )
}

export default function Situation() {
  const { inc, canEdit, startEdit } = useOutletContext()
  const data = useBoard(inc)
  // New whenever the incident or the board's data changes: a failed panel then renders again.
  const rk = useMemo(() => ({}), [inc, data])
  return (
    <div className="sit-board">
      <StakeholderMatrixBanner incidentId={inc.id} rev={inc.updated_at} to="../comms/notifications" />
      <PanelBoundary title="Classification" resetKey={rk}>
        <section className="panel sit-panel" aria-label="Classification" data-panel="Classification">
          <div className="panel-toolbar">
            <h2 className="panel-h">Classification</h2>
            {canEdit && <button type="button" className="btn" onClick={startEdit}>Edit details</button>}
          </div>
          <ClassificationStrip inc={inc} />
        </section>
      </PanelBoundary>
      <PanelBoundary title="Clocks" resetKey={rk}><Clocks inc={inc} data={data} /></PanelBoundary>
      <div className="sit-grid">
        <div className="sit-col">
          {inc.status !== 'closed' && <PanelBoundary title="Start checks" resetKey={rk}><StartChecksPanel data={data} /></PanelBoundary>}
          <PanelBoundary title="Next gate" resetKey={rk}><GatePanel inc={inc} data={data} /></PanelBoundary>
          <PanelBoundary title="Open response actions" resetKey={rk}><ContainmentPanel data={data} /></PanelBoundary>
          <PanelBoundary title="Scope" resetKey={rk}><ScopePanel data={data} /></PanelBoundary>
        </div>
        <div className="sit-col">
          <PanelBoundary title="Team" resetKey={rk}><TeamPanel data={data} /></PanelBoundary>
          <PanelBoundary title="Latest shift handoff" resetKey={rk}><HandoffPanel data={data} /></PanelBoundary>
          <PanelBoundary title="Next tasks" resetKey={rk}><TasksPanel inc={inc} data={data} /></PanelBoundary>
        </div>
      </div>
      <PanelBoundary title="Key timeline" resetKey={rk}><EventsPanel inc={inc} data={data} /></PanelBoundary>
      <PanelBoundary title="Description" resetKey={rk}><DescriptionPanel inc={inc} /></PanelBoundary>
    </div>
  )
}
