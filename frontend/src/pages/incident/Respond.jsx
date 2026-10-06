import { useCallback, useEffect, useRef, useState } from 'react'
import { useOutletContext, useSearchParams } from 'react-router-dom'
import { api } from '../../api/client.js'
import { formatLocalShort } from '../../lib/datetime.js'
import LocalDateTimePicker from '../../components/LocalDateTimePicker.jsx'
import { ACTION_TEMPLATES, TEMPLATE_BY_ID } from './respond/actionTemplates.js'

// ── Vocabulary ────────────────────────────────────────────────────────────

const ACTION_STATUS = [
  { value: 'open',        label: 'Open',        pill: 'pill-gray' },
  { value: 'in_progress', label: 'In progress', pill: 'pill-med'  },
  { value: 'done',        label: 'Done',        pill: 'pill-ok'   },
  { value: 'deferred',    label: 'Deferred',    pill: 'pill-gray' },
  { value: 'reverted',    label: 'Reverted',    pill: 'pill-gray' },
]

// Statuses the user can pick from the dropdown — `reverted` is set only via
// the Revert workflow (which captures a reason and auto-logs to timeline).
const ACTION_STATUS_SELECTABLE = ACTION_STATUS.filter(s => s.value !== 'reverted')

const DECISION_OUTCOMES = [
  { value: 'pending',  label: 'Pending',  pill: 'pill-gray' },
  { value: 'approved', label: 'Approved', pill: 'pill-ok'   },
  { value: 'rejected', label: 'Rejected', pill: 'pill-crit' },
  { value: 'deferred', label: 'Deferred', pill: 'pill-med'  },
]

const statusMeta  = (v) => ACTION_STATUS.find(s => s.value === v)    ?? { label: v, pill: 'pill-gray' }
const outcomeMeta = (v) => DECISION_OUTCOMES.find(o => o.value === v) ?? { label: v, pill: 'pill-gray' }

const COLUMN_COLOR = {
  containment: 'var(--crit)',
  eradication: 'var(--high)',
  recovery:    'var(--ok)',
  decisions:   'var(--accent)',
}

// Every page of a per-incident list (entities / IOCs) for the Target picker,
// so an incident with more than one page of them still offers all of them.
// A failed page doesn't throw: { items: the pages that loaded, error }.
async function listAll(listFn, incidentId) {
  const byId = new Map()
  let cursor = null
  try {
    do {
      const res = await listFn(incidentId, { limit: 200, ...(cursor ? { cursor } : {}) })
      for (const it of res.items) byId.set(it.id, it)
      cursor = res.next_cursor
    } while (cursor)
  } catch (e) {
    return { items: [...byId.values()], error: e.message || 'request failed' }
  }
  return { items: [...byId.values()], error: null }
}


// ── Main component ────────────────────────────────────────────────────────

export default function Respond() {
  const { inc, bumpRail } = useOutletContext()
  const isClosed = inc?.status === 'closed'

  const [actions,   setActions]   = useState([])
  const [decisions, setDecisions] = useState([])
  const [tasks,     setTasks]     = useState([])   // J5: playbook tasks, for the action ↔ task links
  const [users,     setUsers]     = useState([])
  const [loading,   setLoading]   = useState(true)
  const [error,     setError]     = useState(null)
  const [busy,      setBusy]      = useState(false)

  // modal state: null | { type:'action', category, prefill? } | { type:'action-edit', action }
  //              | { type:'decision' } | { type:'decision-edit', decision }
  const [modal, setModal] = useState(null)

  // J5: an Entities / IOCs row button links here with ?new_action=<template>&entity_id= | ioc_id=:
  // open the action form on that template, linked to that entity / IOC.
  const [searchParams, setSearchParams] = useSearchParams()
  useEffect(() => {
    const tpl = TEMPLATE_BY_ID[searchParams.get('new_action') || '']
    if (!searchParams.get('new_action')) return
    if (tpl && !isClosed) {
      setModal({ type: 'action', category: tpl.category, prefill: {
        template: tpl, entityId: searchParams.get('entity_id') || '', iocId: searchParams.get('ioc_id') || '' } })
    }
    setSearchParams(p => { ['new_action', 'entity_id', 'ioc_id'].forEach(k => p.delete(k)); return p }, { replace: true })
  }, [searchParams, setSearchParams, isClosed])

  // The board needs only actions + decisions; the Target picker loads entities / IOCs itself
  // when the action modal opens (ActionModal), so neither slows nor fails the board.
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
      // Every page (the default page is 100), so the board shows every action and decision.
      const [aResult, dResult, tResult] = await Promise.all([
        api.listAllPages(api.listRespondActions, inc.id, {}, 200, { signal }),
        api.listAllPages(api.listDecisions, inc.id, {}, 200, { signal }),
        api.listPlaybookTasks(inc.id).catch(() => []),
      ])
      if (seq !== loadSeq.current) return
      setActions(aResult)
      setDecisions(dResult)
      setTasks(tResult)
    } catch (e) {
      if (seq === loadSeq.current && !signal.aborted) setError(e.message || 'Could not load respond data')
    } finally {
      if (seq === loadSeq.current) setLoading(false)
    }
  }, [inc.id])

  useEffect(() => { load(); return () => loadAbort.current?.abort() }, [load])

  // /users/assignable is open to every authenticated user (active users only).
  useEffect(() => {
    let cancelled = false
    api.listAssignableUsers().then(u => { if (!cancelled) setUsers(u || []) }).catch(() => {})
    return () => { cancelled = true }
  }, [])

  // J5 link chips: titles by id (display only; the links themselves live on the action).
  const decisionOf = (id) => decisions.find(d => d.id === id)
  const taskOf     = (id) => tasks.find(t => t.id === id)

  const usernameOf = (uid) => {
    if (!uid) return null
    const u = users.find(x => x.id === uid)
    return u ? u.username : uid.slice(0, 8) + '…'
  }

  const onActionStatusChange = async (action, next) => {
    setBusy(true); setError(null)
    try {
      const updated = await api.updateRespondAction(inc.id, action.id, { status: next })
      setActions(prev => prev.map(a => a.id === updated.id ? updated : a))
      bumpRail?.()
    } catch (e) {
      setError(e.message || 'Could not update status')
    } finally {
      setBusy(false)
    }
  }

  const onActionDelete = async (action) => {
    if (!window.confirm(`Delete "${action.title}"?`)) return
    setBusy(true); setError(null)
    try {
      await api.deleteRespondAction(inc.id, action.id)
      setActions(prev => prev.filter(a => a.id !== action.id))
      bumpRail?.()
    } catch (e) {
      setError(e.message || 'Could not delete action')
    } finally {
      setBusy(false)
    }
  }

  const onActionRevert = async (action, revert_reason) => {
    setBusy(true); setError(null)
    try {
      const updated = await api.revertRespondAction(inc.id, action.id, { revert_reason })
      setActions(prev => prev.map(a => a.id === updated.id ? updated : a))
      bumpRail?.()
    } catch (e) {
      setError(e.message || 'Could not revert action')
      throw e
    } finally {
      setBusy(false)
    }
  }

  const onDecisionDelete = async (dec) => {
    if (!window.confirm(`Delete this decision?\n\n"${dec.summary.slice(0, 120)}"`)) return
    setBusy(true); setError(null)
    try {
      await api.deleteDecision(inc.id, dec.id)
      setDecisions(prev => prev.filter(d => d.id !== dec.id))
      bumpRail?.()
    } catch (e) {
      setError(e.message || 'Could not delete decision')
    } finally {
      setBusy(false)
    }
  }

  const totalActions = actions.length
  const doneActions  = actions.filter(a => a.status === 'done').length

  return (
    <section className="panel">
      <div className="panel-toolbar">
        <div>
          <h2 className="panel-h" style={{ marginBottom: 4 }}>Respond</h2>
          {totalActions > 0 && (
            <div style={{ color: 'var(--muted)', fontFamily: 'var(--font-mono)', fontSize: 11, display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
              {doneActions}/{totalActions} actions done
              <span style={{ display: 'inline-block', width: 100, height: 6, background: 'var(--surface-2)', borderRadius: 3 }}>
                <span style={{
                  display: 'block',
                  width: totalActions > 0 ? `${Math.round((doneActions / totalActions) * 100)}%` : '0%',
                  height: '100%', background: 'var(--accent)', borderRadius: 3,
                }} />
              </span>
              · {decisions.length} decision{decisions.length !== 1 ? 's' : ''} logged
            </div>
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
      ) : (
        <div className="respond-board-wrap">
        <div className="respond-board">
          {(['containment', 'eradication', 'recovery']).map(cat => (
            <BoardColumn
              key={cat}
              title={cat.charAt(0).toUpperCase() + cat.slice(1)}
              color={COLUMN_COLOR[cat]}
              items={
                actions
                  .filter(a => a.category === cat)
                  .sort((a, b) => a.order_index - b.order_index || a.created_at.localeCompare(b.created_at))
              }
              renderItem={(action) => (
                <ActionCard
                  key={action.id}
                  action={action}
                  decision={action.decision_id ? decisionOf(action.decision_id) : null}
                  task={action.task_id ? taskOf(action.task_id) : null}
                  usernameOf={usernameOf}
                  onStatusChange={(next) => onActionStatusChange(action, next)}
                  onEdit={() => setModal({ type: 'action-edit', action })}
                  onDelete={() => onActionDelete(action)}
                  onRevert={(reason) => onActionRevert(action, reason)}
                  isClosed={isClosed}
                  busy={busy}
                />
              )}
              emptyHint={`No ${cat} actions yet. Use templates or add a custom action.`}
              onAdd={!isClosed ? () => setModal({ type: 'action', category: cat }) : null}
              addLabel="+ Add action"
            />
          ))}

          <BoardColumn
            title="Decisions"
            color={COLUMN_COLOR.decisions}
            items={decisions}
            renderItem={(dec) => (
              <DecisionCard
                key={dec.id}
                decision={dec}
                linkedActions={actions.filter(a => a.decision_id === dec.id)}
                usernameOf={usernameOf}
                onEdit={() => setModal({ type: 'decision-edit', decision: dec })}
                onDelete={() => onDecisionDelete(dec)}
                isClosed={isClosed}
                busy={busy}
              />
            )}
            emptyHint="No decisions recorded yet."
            onAdd={!isClosed ? () => setModal({ type: 'decision' }) : null}
            addLabel="+ Record decision"
          />
        </div>
        </div>
      )}

      {(modal?.type === 'action' || modal?.type === 'action-edit') && (
        <ActionModal
          incidentId={inc.id}
          category={modal.category ?? modal.action?.category}
          editing={modal.action}
          prefill={modal.prefill}
          decisions={decisions}
          tasks={tasks}
          users={users}
          onClose={() => setModal(null)}
          onSaved={(saved) => {
            if (modal.action) {
              setActions(prev => prev.map(a => a.id === saved.id ? saved : a))
            } else {
              setActions(prev => [...prev, saved])
            }
            setModal(null)
            bumpRail?.()
          }}
        />
      )}
      {(modal?.type === 'decision' || modal?.type === 'decision-edit') && (
        <DecisionModal
          incidentId={inc.id}
          editing={modal.decision}
          actions={actions}
          users={users}
          onClose={() => setModal(null)}
          onSaved={(saved) => {
            if (modal.decision) {
              setDecisions(prev => prev.map(d => d.id === saved.id ? saved : d))
            } else {
              setDecisions(prev => [saved, ...prev])
            }
            // The approved-action links live on the actions: mirror the saved decision's list.
            const linked = new Set((saved.linked_actions ?? []).map(a => a.id))
            setActions(prev => prev.map(a =>
              linked.has(a.id) ? { ...a, decision_id: saved.id }
                : a.decision_id === saved.id ? { ...a, decision_id: null } : a))
            setModal(null)
            bumpRail?.()
          }}
        />
      )}
    </section>
  )
}

// ── Board column shell ────────────────────────────────────────────────────

function BoardColumn({ title, color, items, renderItem, emptyHint, onAdd, addLabel }) {
  const done  = items.filter(i => i.status === 'done').length
  const total = items.length

  return (
    <div style={{
      display: 'flex',
      flexDirection: 'column',
      background: 'var(--surface)',
      border: '1px solid var(--border)',
      borderRadius: 'var(--radius-lg)',
      overflow: 'hidden',
    }}>
      {/* Column header */}
      <div style={{
        padding: 'var(--space-2) var(--space-3)',
        borderBottom: '1px solid var(--border)',
        display: 'flex',
        flexWrap: 'wrap',
        gap: 'var(--space-2)',
        alignItems: 'center',
        justifyContent: 'space-between',
        background: 'var(--surface-2)',
        flexShrink: 0,
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
          <span style={{
            color,
            fontFamily: 'var(--font-heading)',
            fontSize: 12,
            fontWeight: 600,
            letterSpacing: 'var(--heading-letter-spacing)',
            textTransform: 'var(--heading-transform)',
          }}>{title}</span>
          {total > 0 && (
            <span style={{
              fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--muted)',
              background: 'var(--surface)', border: '1px solid var(--border)',
              borderRadius: 'var(--radius-sm)', padding: '0 5px', lineHeight: '18px',
            }}>
              {title !== 'Decisions' ? `${done}/${total}` : total}
            </span>
          )}
        </div>
        {onAdd && (
          <button
            type="button"
            className="btn primary"
            onClick={onAdd}
            style={{ fontSize: 11, padding: '2px 8px', whiteSpace: 'nowrap' }}
          >
            {addLabel}
          </button>
        )}
      </div>

      {/* Column body */}
      <div style={{
        overflowY: 'auto',
        maxHeight: '62vh',
        padding: 'var(--space-2)',
        display: 'flex',
        flexDirection: 'column',
        gap: 'var(--space-2)',
      }}>
        {items.length === 0 ? (
          <div style={{
            padding: 'var(--space-3)',
            border: '1px dashed var(--border)',
            borderRadius: 'var(--radius)',
            color: 'var(--dim)',
            fontSize: 12,
            textAlign: 'center',
            lineHeight: 1.5,
          }}>
            {emptyHint}
          </div>
        ) : (
          items.map(item => renderItem(item))
        )}
      </div>
    </div>
  )
}

// ── Action card ───────────────────────────────────────────────────────────

function ActionCard({ action, decision, task, usernameOf, onStatusChange, onEdit, onDelete, onRevert, isClosed, busy }) {
  const target = action.details?.target
  const isReverted = action.status === 'reverted'
  const [revertOpen, setRevertOpen] = useState(false)
  const [revertReason, setRevertReason] = useState('')
  const [reverting, setReverting] = useState(false)

  const submitRevert = async () => {
    const reason = revertReason.trim()
    if (!reason) return
    setReverting(true)
    try {
      await onRevert(reason)
      setRevertOpen(false)
      setRevertReason('')
    } catch {
      // parent surfaces the error; keep the form open so the analyst can retry.
    } finally {
      setReverting(false)
    }
  }

  return (
    <div style={{
      background: 'var(--surface-2)',
      border: '1px solid var(--border)',
      borderRadius: 'var(--radius)',
      padding: 'var(--space-2) var(--space-3)',
      display: 'flex',
      flexDirection: 'column',
      gap: 4,
      opacity: isReverted ? 0.65 : 1,
    }}>
      {/* Status select — full width, no competition. Disabled when reverted. */}
      <select
        className="select compact"
        value={action.status}
        onChange={(e) => onStatusChange(e.target.value)}
        disabled={isClosed || busy || isReverted}
        aria-label="Status"
      >
        {(isReverted ? ACTION_STATUS : ACTION_STATUS_SELECTABLE).map(s =>
          <option key={s.value} value={s.value}>{s.label}</option>
        )}
      </select>

      <div style={{
        fontSize: 13, fontWeight: 500,
        textDecoration: action.status === 'done' || isReverted ? 'line-through' : 'none',
        color: action.status === 'done' || isReverted ? 'var(--muted)' : 'var(--text)',
      }}>
        {action.title}
      </div>

      {target && (
        <div style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--accent)' }}>
          → {target}
          {!action.entity_id && !action.ioc_id && (
            <span data-unlinked-target
                  title="Free-text target: not linked to an entity or IOC, so it sets no containment state"
                  style={{ marginLeft: 6, color: 'var(--dim)', fontFamily: 'var(--font-body)' }}>
              (unlinked target)
            </span>
          )}
        </div>
      )}

      {action.description && (
        <div style={{ fontSize: 12, color: 'var(--muted)' }}>{action.description}</div>
      )}

      {(action.decision_id || action.task_id) && (
        <div className="link-chips" data-action-links>
          {action.decision_id && (
            <span className="link-chip" data-chip="decision" title={decision?.summary ?? 'Approving decision'}>
              ✓ Decision: {decision ? decision.summary.slice(0, 40) : '…'}
            </span>
          )}
          {action.task_id && (
            <span className="link-chip" data-chip="task" title={task?.title ?? 'Playbook task'}>
              ☐ Task: {task ? task.title.slice(0, 40) : '…'}
            </span>
          )}
        </div>
      )}

      {action.notes && (
        <div style={{ fontSize: 11, color: 'var(--dim)', fontStyle: 'italic' }}>{action.notes}</div>
      )}

      {action.status === 'deferred' && (
        <div style={{ fontSize: 11, color: 'var(--muted)' }} data-defer-reason>
          {action.defer_reason ? <>Deferred: {action.defer_reason}</> : <>Deferred without a reason: Edit to add one (Gate 1 warns).</>}
        </div>
      )}

      {isReverted && (action.revert_reason || action.reverted_at) && (
        <div style={{
          fontSize: 11, color: 'var(--dim)',
          borderTop: '1px solid var(--border)',
          paddingTop: 4, marginTop: 2,
        }}>
          <span style={{ fontFamily: 'var(--font-mono)' }}>↩ Reverted</span>
          {action.reverted_by_id && <> by {usernameOf(action.reverted_by_id)}</>}
          {action.reverted_at && <> · {formatLocalShort(action.reverted_at)}</>}
          {action.revert_reason && (
            <div style={{ marginTop: 2, fontStyle: 'italic' }}>{action.revert_reason}</div>
          )}
        </div>
      )}

      {/* Footer: meta left, actions right */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 2 }}>
        <div style={{ fontSize: 10, fontFamily: 'var(--font-mono)', color: 'var(--dim)', display: 'flex', gap: 6, flexWrap: 'wrap' }}>
          {action.assignee_id && <span>→ {usernameOf(action.assignee_id)}</span>}
          {action.occurred_at ? (
            <span style={{ color: 'var(--ok)' }}>⏱ {formatLocalShort(action.occurred_at)}</span>
          ) : action.status === 'done' && action.completed_at ? (
            <span style={{ color: 'var(--ok)' }}>✓ {formatLocalShort(action.completed_at)}</span>
          ) : (
            <span>{formatLocalShort(action.created_at)}</span>
          )}
        </div>
        {!isClosed && !isReverted && (
          <div style={{ display: 'flex', gap: 4, flexShrink: 0 }}>
            <button type="button" className="btn ghost" onClick={() => setRevertOpen(o => !o)} disabled={busy}
                    style={{ padding: '1px 6px', fontSize: 10, color: 'var(--high)' }}
                    title="Revert this action — records reason and auto-logs to timeline">↩</button>
            <button type="button" className="btn ghost" onClick={onEdit} disabled={busy}
                    style={{ padding: '1px 6px', fontSize: 10 }}>Edit</button>
            <button type="button" className="btn ghost" onClick={onDelete} disabled={busy}
                    style={{ padding: '1px 6px', fontSize: 10 }}>✕</button>
          </div>
        )}
      </div>

      {revertOpen && !isClosed && !isReverted && (
        <div style={{
          borderTop: '1px solid var(--border)',
          paddingTop: 6, marginTop: 2,
          display: 'flex', flexDirection: 'column', gap: 4,
        }}>
          <textarea
            className="input"
            value={revertReason}
            onChange={e => setRevertReason(e.target.value)}
            rows={2}
            maxLength={4096}
            placeholder="Why is this being reverted? (e.g. false positive, system restored)"
            style={{ fontSize: 11, resize: 'vertical' }}
            autoFocus
          />
          <div style={{ display: 'flex', gap: 4, justifyContent: 'flex-end' }}>
            <button type="button" className="btn ghost"
                    onClick={() => { setRevertOpen(false); setRevertReason('') }}
                    disabled={reverting}
                    style={{ padding: '1px 6px', fontSize: 10 }}>Cancel</button>
            <button type="button" className="btn ghost"
                    onClick={submitRevert}
                    disabled={reverting || !revertReason.trim()}
                    style={{ padding: '1px 6px', fontSize: 10, color: 'var(--high)' }}>
              {reverting ? 'Reverting…' : '↩ Confirm revert'}
            </button>
          </div>
        </div>
      )}
    </div>
  )
}

// ── Decision card ─────────────────────────────────────────────────────────

function DecisionCard({ decision, linkedActions, usernameOf, onEdit, onDelete, isClosed, busy }) {
  const [expanded, setExpanded] = useState(false)
  const om = outcomeMeta(decision.outcome)
  const longRationale = decision.rationale && decision.rationale.length > 180

  return (
    <div style={{
      background: 'var(--surface-2)',
      border: '1px solid var(--border)',
      borderRadius: 'var(--radius)',
      padding: 'var(--space-2) var(--space-3)',
    }}>
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 'var(--space-2)', marginBottom: 4 }}>
        <span className={`pill ${om.pill}`} style={{ fontSize: 10 }}>{om.label}</span>
        {!isClosed && (
          <div style={{ display: 'flex', gap: 4, flexShrink: 0 }}>
            <button type="button" className="btn ghost" onClick={onEdit} disabled={busy}
                    style={{ padding: '1px 6px', fontSize: 10 }}>Edit</button>
            <button type="button" className="btn ghost" onClick={onDelete} disabled={busy}
                    style={{ padding: '1px 6px', fontSize: 10 }}>✕</button>
          </div>
        )}
      </div>

      <div style={{ fontSize: 13, fontWeight: 500, marginBottom: 4, lineHeight: 1.4 }}>
        {decision.summary}
      </div>

      {decision.rationale && (
        <div style={{ fontSize: 12, color: 'var(--muted)', lineHeight: 1.5, marginBottom: 4 }}>
          {longRationale && !expanded ? (
            <>{decision.rationale.slice(0, 180)}…{' '}
              <button type="button" onClick={() => setExpanded(true)}
                      style={{ background: 'none', border: 'none', color: 'var(--accent)', cursor: 'pointer', fontSize: 11, padding: 0 }}>
                more
              </button>
            </>
          ) : (
            <>{decision.rationale}{longRationale && <>{' '}<button type="button" onClick={() => setExpanded(false)}
                      style={{ background: 'none', border: 'none', color: 'var(--accent)', cursor: 'pointer', fontSize: 11, padding: 0 }}>less</button></>}</>
          )}
        </div>
      )}

      {decision.tags?.length > 0 && (
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 3, marginBottom: 4 }}>
          {decision.tags.map(tag => (
            <span key={tag} style={{
              fontSize: 10, padding: '1px 5px',
              background: 'var(--surface)', border: '1px solid var(--border)',
              borderRadius: 'var(--radius-sm)', color: 'var(--muted)',
              fontFamily: 'var(--font-mono)',
            }}>{tag}</span>
          ))}
        </div>
      )}

      {linkedActions.length > 0 && (
        <div className="link-chips" data-decision-links style={{ marginBottom: 4 }}>
          {linkedActions.map(a => (
            <span key={a.id} className="link-chip" data-chip="action" title={`${a.category}: ${a.title} (${a.status})`}>
              → {a.title.slice(0, 40)} · {statusMeta(a.status).label}
            </span>
          ))}
        </div>
      )}

      <div style={{ fontSize: 10, fontFamily: 'var(--font-mono)', color: 'var(--dim)' }}>
        {decision.decided_by_id ? `by ${usernameOf(decision.decided_by_id)} · ` : ''}
        {formatLocalShort(decision.decided_at ?? decision.created_at)}
      </div>
    </div>
  )
}

// ── Action modal (2-step: template picker → form) ─────────────────────────

function ActionModal({ incidentId, category, editing, prefill, decisions, tasks, users, onClose, onSaved }) {
  const isEdit = !!editing

  // step: 'pick' (template selection) | 'form' (fill details). A row button (J5) prefills the
  // template and the linked entity / IOC, so the form opens directly.
  const [step,        setStep]        = useState(isEdit || prefill ? 'form' : 'pick')
  // selTemplate = TEMPLATE_BY_ID entry { id, title, targetHint, entityFilter, iocFilter };
  // when editing, the action's own template (for the Target picker filters).
  const [selTemplate, setSelTemplate] = useState(isEdit ? (TEMPLATE_BY_ID[editing.template_id] ?? null) : (prefill?.template ?? null))

  // form fields
  const [title,       setTitle]       = useState(editing?.title ?? prefill?.template?.title ?? '')
  const [target,      setTarget]      = useState(editing?.details?.target ?? '')
  // The entity / IOC the action is linked to ('' = free-text target, no link).
  const [entityId,    setEntityId]    = useState(editing?.entity_id ?? prefill?.entityId ?? '')
  const [iocId,       setIocId]       = useState(editing?.ioc_id    ?? prefill?.iocId    ?? '')
  // J5: the approving decision and the playbook task this action carries out ('' = none).
  const [decisionId,  setDecisionId]  = useState(editing?.decision_id ?? '')
  const [taskId,      setTaskId]      = useState(editing?.task_id     ?? '')
  const [description, setDescription] = useState(editing?.description      ?? '')
  const [status,      setStatus]      = useState(editing?.status           ?? 'open')
  const [assigneeId,  setAssigneeId]  = useState(editing?.assignee_id     ?? '')
  const [notes,       setNotes]       = useState(editing?.notes            ?? '')
  const [deferReason, setDeferReason] = useState(editing?.defer_reason     ?? '')
  const [occurredAt,  setOccurredAt]  = useState(editing?.occurred_at || '')
  const [busy,        setBusy]        = useState(false)
  const [error,       setError]       = useState(null)
  // Target picker data, loaded when the modal opens. A failed list keeps the pages that loaded
  // and shows its error in the picker; free text still works.
  const [entities,      setEntities]      = useState([])
  const [iocs,          setIocs]          = useState([])
  const [pickerLoading, setPickerLoading] = useState(true)
  const [pickerErrors,  setPickerErrors]  = useState([])

  useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape' && !busy) onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [busy, onClose])

  useEffect(() => {
    let live = true
    Promise.all([listAll(api.listEntities, incidentId), listAll(api.listIocs, incidentId)]).then(([e, i]) => {
      if (!live) return
      setEntities(e.items)
      setIocs(i.items)
      // A prefilled link (row button) copies the item's value into Target, as picking it does.
      if (prefill && !isEdit) {
        const item = prefill.entityId ? e.items.find(x => x.id === prefill.entityId)
                   : prefill.iocId    ? i.items.find(x => x.id === prefill.iocId) : null
        if (item) setTarget(t => t || item.value)
      }
      setPickerErrors([e.error && `entities (${e.error})`, i.error && `IOCs (${i.error})`].filter(Boolean))
      setPickerLoading(false)
    })
    return () => { live = false }
  }, [incidentId, prefill, isEdit])

  // pickTemplate receives a TEMPLATE_BY_ID entry, or null for a custom action
  const pickTemplate = (tpl) => {
    setSelTemplate(tpl)
    setTitle(tpl ? tpl.title : '')
    setTarget('')
    setEntityId('')
    setIocId('')
    setStep('form')
  }

  // Target picker options, filtered by the template group's entity / IOC types
  // (null = all types). The currently linked item is always offered.
  const offered = (items, filter, linkedId) =>
    items.filter(x => x.id === linkedId || !filter || filter.includes(x.type))
  const filteredEntities = offered(entities, selTemplate?.entityFilter, entityId)
  const filteredIocs     = offered(iocs,     selTemplate?.iocFilter,    iocId)
  const pickValue = entityId ? `entity:${entityId}` : iocId ? `ioc:${iocId}` : ''
  // The current link while the lists load (or when its list failed), so the select still shows it.
  const linkPending = pickValue && !(entityId ? entities : iocs).some(x => x.id === (entityId || iocId))
  const showPicker  = pickerLoading || pickerErrors.length > 0 || linkPending
    || filteredEntities.length > 0 || filteredIocs.length > 0

  // Picking an entity / IOC links it and copies its value into Target;
  // "free text" removes the link and keeps the typed text.
  const onTargetPick = (e) => {
    const [kind, id] = e.target.value.split(':')
    const item = kind === 'entity' ? entities.find(x => x.id === id)
               : kind === 'ioc'    ? iocs.find(x => x.id === id) : null
    setEntityId(kind === 'entity' ? id : '')
    setIocId(kind === 'ioc' ? id : '')
    if (item) setTarget(item.value)
  }

  const onSubmit = async (e) => {
    e.preventDefault()
    setError(null)
    if (!title.trim()) { setError('Title is required.'); return }
    setBusy(true)
    try {
      const payload = {
        category,
        title:       title.trim(),
        description: description.trim() || null,
        status,
        assignee_id: assigneeId || null,
        notes:       notes.trim() || null,
        details:     { ...(editing?.details ?? {}), target: target.trim() || undefined },
        defer_reason: status === 'deferred' ? deferReason.trim() : (editing?.defer_reason ?? undefined),
        occurred_at: occurredAt || null,
        entity_id:   entityId || null,
        ioc_id:      iocId || null,
        decision_id: decisionId || null,
        task_id:     taskId || null,
      }
      // The template is fixed once the action exists; editing leaves it unchanged.
      if (!isEdit && selTemplate) payload.template_id = selTemplate.id
      const saved = isEdit
        ? await api.updateRespondAction(incidentId, editing.id, payload)
        : await api.createRespondAction(incidentId, payload)
      onSaved(saved)
    } catch (e2) {
      setError(e2.message || 'Could not save action')
    } finally {
      setBusy(false)
    }
  }

  const categoryColor = COLUMN_COLOR[category] ?? 'var(--accent)'
  const categoryLabel = category.charAt(0).toUpperCase() + category.slice(1)
  const templates     = ACTION_TEMPLATES[category] ?? []

  return (
    <div className="modal-backdrop">
      <div className="modal" role="dialog" aria-labelledby="am-title"
           style={{ maxWidth: step === 'pick' ? 600 : 480 }}>
        <div className="modal-head">
          <h2 id="am-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ color: categoryColor }}>{categoryLabel}</span>
            <span style={{ color: 'var(--muted)', fontWeight: 400 }}>
              {isEdit ? '— edit action' : step === 'pick' ? '— choose template' : '— add action'}
            </span>
          </h2>
          <button type="button" className="modal-close" onClick={onClose} disabled={busy}>×</button>
        </div>

        {/* ── Step 1: template picker ── */}
        {step === 'pick' && (
          <div className="modal-body">
            {templates.map(group => (
              <div key={group.group} style={{ marginBottom: 'var(--space-3)' }}>
                <div style={{
                  fontSize: 10, fontFamily: 'var(--font-heading)',
                  color: 'var(--muted)', letterSpacing: 1,
                  textTransform: 'uppercase', marginBottom: 'var(--space-1)',
                }}>
                  {group.group}
                </div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 'var(--space-1)' }}>
                  {group.items.map(tpl => (
                    <button
                      key={tpl.id}
                      type="button"
                      className="btn"
                      onClick={() => pickTemplate(TEMPLATE_BY_ID[tpl.id])}
                      style={{ fontSize: 12, padding: '4px 10px' }}
                    >
                      {tpl.title}
                    </button>
                  ))}
                </div>
              </div>
            ))}
            <div style={{ borderTop: '1px solid var(--border)', paddingTop: 'var(--space-2)', marginTop: 'var(--space-1)' }}>
              <button
                type="button"
                className="btn ghost"
                onClick={() => pickTemplate(null)}
                style={{ fontSize: 12 }}
              >
                Custom action…
              </button>
            </div>
          </div>
        )}

        {/* ── Step 2: form ── */}
        {step === 'form' && (
          <form onSubmit={onSubmit}>
            <div className="modal-body">
              <div className="form">
                {!isEdit && selTemplate && (
                  <div style={{
                    padding: 'var(--space-2) var(--space-3)',
                    background: 'var(--surface-2)',
                    border: `1px solid ${categoryColor}40`,
                    borderLeft: `3px solid ${categoryColor}`,
                    borderRadius: 'var(--radius)',
                    fontSize: 12, color: 'var(--muted)',
                    marginBottom: 4,
                  }}>
                    Template: <strong style={{ color: 'var(--text)' }}>{selTemplate.title}</strong>
                    {' · '}
                    <button type="button" onClick={() => setStep('pick')}
                            style={{ background: 'none', border: 'none', color: 'var(--accent)', cursor: 'pointer', fontSize: 12, padding: 0 }}>
                      Change
                    </button>
                  </div>
                )}

                <div className="field">
                  <label className="field-label" htmlFor="am-title-input">Title</label>
                  <input id="am-title-input" className="input" value={title}
                         onChange={(e) => setTitle(e.target.value)}
                         autoFocus required maxLength={512} />
                </div>

                {/* Target picker: links the action to an entity or IOC of this incident */}
                {showPicker && (
                  <div className="field">
                    <label className="field-label" htmlFor="am-target-pick">
                      Link target
                      <span style={{ color: 'var(--dim)', fontWeight: 400, marginLeft: 4 }}>
                        (entity or IOC)
                      </span>
                    </label>
                    <select id="am-target-pick" className="select" value={pickValue}
                            onChange={onTargetPick}>
                      <option value="">— none: free-text target —</option>
                      {linkPending && (
                        <option value={pickValue}>linked: {target || (entityId ? 'entity' : 'IOC')}</option>
                      )}
                      {filteredEntities.length > 0 && (
                        <optgroup label="Entities">
                          {filteredEntities.map(ent => (
                            <option key={ent.id} value={`entity:${ent.id}`}>
                              [{ent.type}] {ent.value}{ent.name ? ` (${ent.name})` : ''}
                              {ent.compromised ? ' ⚠' : ''}
                            </option>
                          ))}
                        </optgroup>
                      )}
                      {filteredIocs.length > 0 && (
                        <optgroup label="IOCs">
                          {filteredIocs.map(ioc => (
                            <option key={ioc.id} value={`ioc:${ioc.id}`}>
                              [{ioc.type}] {ioc.value}
                            </option>
                          ))}
                        </optgroup>
                      )}
                    </select>
                    {pickerLoading && (
                      <div className="field-hint" role="status" data-testid="am-picker-loading">Loading entities and IOCs…</div>
                    )}
                    {pickerErrors.length > 0 && (
                      <div className="field-hint" role="alert" data-testid="am-picker-error" style={{ color: 'var(--crit)' }}>
                        Could not load {pickerErrors.join(' and ')}; only what loaded is listed. You can still type a free-text target.
                      </div>
                    )}
                  </div>
                )}

                <div className="field">
                  <label className="field-label" htmlFor="am-target">
                    Target
                    {selTemplate?.targetHint && (
                      <span style={{ color: 'var(--dim)', fontWeight: 400, marginLeft: 4 }}>
                        ({selTemplate.targetHint})
                      </span>
                    )}
                  </label>
                  <input id="am-target" className="input" value={target}
                         onChange={(e) => setTarget(e.target.value)}
                         placeholder={selTemplate?.targetHint ?? 'e.g. hostname, account, IP…'}
                         maxLength={512} />
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--space-3)' }}>
                  <div className="field">
                    <label className="field-label" htmlFor="am-status">Status</label>
                    <select id="am-status" className="select" value={status}
                            onChange={(e) => setStatus(e.target.value)}>
                      {ACTION_STATUS_SELECTABLE.map(s => <option key={s.value} value={s.value}>{s.label}</option>)}
                    </select>
                  </div>
                  <div className="field">
                    <label className="field-label" htmlFor="am-assignee">Assignee</label>
                    <select id="am-assignee" className="select" value={assigneeId}
                            onChange={(e) => setAssigneeId(e.target.value)}>
                      <option value="">Unassigned</option>
                      {users.map(u => <option key={u.id} value={u.id}>{u.username}</option>)}
                      {assigneeId && !users.some(u => u.id === assigneeId) && (
                        <option value={assigneeId}>{assigneeId.slice(0, 8)}…</option>
                      )}
                    </select>
                  </div>
                </div>

                {status === 'deferred' && (
                  <div className="field">
                    <label className="field-label" htmlFor="am-defer">Why is it deferred?</label>
                    <textarea id="am-defer" className="input" value={deferReason}
                              onChange={(e) => setDeferReason(e.target.value)} rows={2} maxLength={4096}
                              aria-describedby="am-defer-hint"
                              placeholder="e.g. business owner accepted the risk until the maintenance window" />
                    <span id="am-defer-hint" className="field-hint">
                      Recommended: Gate 1 (into Post-Incident) warns about a deferred action without a reason.
                    </span>
                  </div>
                )}

                <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1fr) minmax(0, 1fr)', gap: 'var(--space-3)' }}>
                  <div className="field">
                    <label className="field-label" htmlFor="am-decision">Approved by decision</label>
                    <select id="am-decision" className="select" value={decisionId}
                            onChange={(e) => setDecisionId(e.target.value)}>
                      <option value="">— none —</option>
                      {decisions.map(d => <option key={d.id} value={d.id}>{d.summary.slice(0, 60)}</option>)}
                    </select>
                  </div>
                  <div className="field">
                    <label className="field-label" htmlFor="am-task">Playbook task</label>
                    <select id="am-task" className="select" value={taskId}
                            onChange={(e) => setTaskId(e.target.value)}>
                      <option value="">— none —</option>
                      {tasks.map(t => <option key={t.id} value={t.id}>{t.title.slice(0, 60)}</option>)}
                    </select>
                  </div>
                </div>

                <div className="field">
                  <label className="field-label" htmlFor="am-occurred">Occurred at (optional)</label>
                  <LocalDateTimePicker id="am-occurred" value={occurredAt} onChange={setOccurredAt} />
                </div>

                <div className="field">
                  <label className="field-label" htmlFor="am-desc">Description (optional)</label>
                  <textarea id="am-desc" className="input" value={description}
                            onChange={(e) => setDescription(e.target.value)}
                            rows={2} maxLength={4096} />
                </div>

                <div className="field">
                  <label className="field-label" htmlFor="am-notes">Notes (optional)</label>
                  <textarea id="am-notes" className="input" value={notes}
                            onChange={(e) => setNotes(e.target.value)}
                            rows={2} maxLength={4096} />
                </div>

                {error && (
                  <div className="alert error" role="alert">
                    <span className="alert-icon">!</span><span>{error}</span>
                  </div>
                )}
              </div>
            </div>
            <div className="modal-foot">
              {!isEdit && (
                <button type="button" className="btn ghost" onClick={() => setStep('pick')} disabled={busy}>
                  ← Templates
                </button>
              )}
              <button type="button" className="btn ghost" onClick={onClose} disabled={busy}>Cancel</button>
              <button type="submit" className="btn primary" disabled={busy}>
                {busy ? 'Saving…' : (isEdit ? 'Save changes' : 'Add action')}
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  )
}

// ── Decision modal ────────────────────────────────────────────────────────

function DecisionModal({ incidentId, editing, actions, users, onClose, onSaved }) {
  const isEdit = !!editing

  const [summary,     setSummary]     = useState(editing?.summary       ?? '')
  const [rationale,   setRationale]   = useState(editing?.rationale     ?? '')
  const [outcome,     setOutcome]     = useState(editing?.outcome       ?? 'pending')
  const [decidedById, setDecidedById] = useState(editing?.decided_by_id ?? '')
  const [decidedAt,   setDecidedAt]   = useState(editing?.decided_at || '')
  const [tagsText,    setTagsText]    = useState((editing?.tags ?? []).join(', '))
  // J5: the actions this decision approves (stored on each action as decision_id).
  const [actionIds,   setActionIds]   = useState(() =>
    new Set(editing ? actions.filter(a => a.decision_id === editing.id).map(a => a.id) : []))
  const [busy, setBusy]               = useState(false)
  const [error, setError]             = useState(null)

  useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape' && !busy) onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [busy, onClose])

  const parseTags = (s) => s.split(',').map(t => t.trim()).filter(Boolean)

  const onSubmit = async (e) => {
    e.preventDefault()
    setError(null)
    if (!summary.trim()) { setError('Summary is required.'); return }
    setBusy(true)
    try {
      const payload = {
        summary:       summary.trim(),
        rationale:     rationale.trim() || null,
        outcome,
        decided_by_id: decidedById || null,
        decided_at:    decidedAt || null,
        tags:          parseTags(tagsText),
        action_ids:    [...actionIds],
      }
      const saved = isEdit
        ? await api.updateDecision(incidentId, editing.id, payload)
        : await api.createDecision(incidentId, payload)
      onSaved(saved)
    } catch (e2) {
      setError(e2.message || 'Could not save decision')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="modal-backdrop">
      <div className="modal" role="dialog" aria-labelledby="dm-title">
        <div className="modal-head">
          <h2 id="dm-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ color: COLUMN_COLOR.decisions }}>Decisions</span>
            <span style={{ color: 'var(--muted)', fontWeight: 400 }}>
              {isEdit ? '— edit' : '— record'}
            </span>
          </h2>
          <button type="button" className="modal-close" onClick={onClose} disabled={busy}>×</button>
        </div>
        <form onSubmit={onSubmit}>
          <div className="modal-body">
            <div className="form">
              <div className="field">
                <label className="field-label" htmlFor="dm-summary">Decision summary</label>
                <textarea id="dm-summary" className="input" value={summary}
                          onChange={(e) => setSummary(e.target.value)}
                          rows={3} maxLength={4096} autoFocus required />
              </div>

              <div className="field">
                <label className="field-label" htmlFor="dm-rationale">Rationale (optional)</label>
                <textarea id="dm-rationale" className="input" value={rationale}
                          onChange={(e) => setRationale(e.target.value)}
                          rows={3} maxLength={4096} />
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--space-3)' }}>
                <div className="field">
                  <label className="field-label" htmlFor="dm-outcome">Outcome</label>
                  <select id="dm-outcome" className="select" value={outcome}
                          onChange={(e) => setOutcome(e.target.value)}>
                    {DECISION_OUTCOMES.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
                  </select>
                </div>

                <div className="field">
                  <label className="field-label" htmlFor="dm-at">Decided at (optional)</label>
                  <LocalDateTimePicker id="dm-at" value={decidedAt} onChange={setDecidedAt} clearable />
                </div>
              </div>

              <div className="field">
                <label className="field-label" htmlFor="dm-by">Decided by</label>
                <select id="dm-by" className="select" value={decidedById}
                        onChange={(e) => setDecidedById(e.target.value)}>
                  <option value="">— not recorded —</option>
                  {users.map(u => <option key={u.id} value={u.id}>{u.username}</option>)}
                  {decidedById && !users.some(u => u.id === decidedById) && (
                    <option value={decidedById}>{decidedById.slice(0, 8)}…</option>
                  )}
                </select>
              </div>

              {actions.length > 0 && (
                <fieldset className="field" data-dm-actions style={{ border: 'none', padding: 0, margin: 0 }}>
                  <legend className="field-label">Approves these actions</legend>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 2, maxHeight: 140, overflowY: 'auto' }}>
                    {actions.map(a => (
                      <label key={a.id} style={{ display: 'flex', gap: 6, alignItems: 'center', fontSize: 12 }}>
                        <input type="checkbox" checked={actionIds.has(a.id)}
                               onChange={(e) => setActionIds(prev => {
                                 const next = new Set(prev)
                                 if (e.target.checked) next.add(a.id); else next.delete(a.id)
                                 return next
                               })} />
                        <span style={{ color: 'var(--dim)', fontFamily: 'var(--font-mono)', fontSize: 10 }}>{a.category}</span>
                        {a.title}
                      </label>
                    ))}
                  </div>
                </fieldset>
              )}

              <div className="field">
                <label className="field-label" htmlFor="dm-tags">Tags (comma-separated)</label>
                <input id="dm-tags" className="input" value={tagsText}
                       onChange={(e) => setTagsText(e.target.value)}
                       placeholder="e.g. isolation, legal, escalation"
                       maxLength={512} />
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
              {busy ? 'Saving…' : (isEdit ? 'Save changes' : 'Record decision')}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
