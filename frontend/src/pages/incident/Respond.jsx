import { useCallback, useEffect, useState } from 'react'
import { useOutletContext } from 'react-router-dom'
import { useAuth } from '../../hooks/useAuth.jsx'
import { api } from '../../api/client.js'
import { formatLocalShort } from '../../lib/datetime.js'
import UtcDateTimeInput from '../../components/UtcDateTimeInput.jsx'
import { ACTION_TEMPLATES } from './respond/actionTemplates.js'

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


// ── Main component ────────────────────────────────────────────────────────

export default function Respond() {
  const { inc }  = useOutletContext()
  const { user } = useAuth()
  const isClosed = inc?.status === 'closed'
  const isAdmin  = user?.role === 'admin'

  const [actions,   setActions]   = useState([])
  const [decisions, setDecisions] = useState([])
  const [users,     setUsers]     = useState([])
  const [entities,  setEntities]  = useState([])
  const [loading,   setLoading]   = useState(true)
  const [error,     setError]     = useState(null)
  const [busy,      setBusy]      = useState(false)

  // modal state: null | { type:'action', category } | { type:'action-edit', action }
  //              | { type:'decision' } | { type:'decision-edit', decision }
  const [modal, setModal] = useState(null)

  const load = useCallback(async () => {
    setError(null)
    try {
      const [aResult, dResult, eResult] = await Promise.all([
        api.listRespondActions(inc.id),
        api.listDecisions(inc.id),
        api.listEntities(inc.id),
      ])
      setActions(aResult.items   ?? aResult)
      setDecisions(dResult.items ?? dResult)
      setEntities(eResult.items  ?? eResult)
    } catch (e) {
      setError(e.message || 'Could not load respond data')
    } finally {
      setLoading(false)
    }
  }, [inc.id])

  useEffect(() => { load() }, [load])

  useEffect(() => {
    if (!isAdmin) return
    let cancelled = false
    api.listUsers().then(u => { if (!cancelled) setUsers(u) }).catch(() => {})
    return () => { cancelled = true }
  }, [isAdmin])

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
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(4, minmax(230px, 1fr))',
          gap: 'var(--space-3)',
          overflowX: 'auto',
          alignItems: 'start',
        }}>
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
      )}

      {(modal?.type === 'action' || modal?.type === 'action-edit') && (
        <ActionModal
          incidentId={inc.id}
          category={modal.category ?? modal.action?.category}
          editing={modal.action}
          users={users}
          entities={entities}
          isAdmin={isAdmin}
          onClose={() => setModal(null)}
          onSaved={(saved) => {
            if (modal.action) {
              setActions(prev => prev.map(a => a.id === saved.id ? saved : a))
            } else {
              setActions(prev => [...prev, saved])
            }
            setModal(null)
          }}
        />
      )}
      {(modal?.type === 'decision' || modal?.type === 'decision-edit') && (
        <DecisionModal
          incidentId={inc.id}
          editing={modal.decision}
          users={users}
          isAdmin={isAdmin}
          onClose={() => setModal(null)}
          onSaved={(saved) => {
            if (modal.decision) {
              setDecisions(prev => prev.map(d => d.id === saved.id ? saved : d))
            } else {
              setDecisions(prev => [saved, ...prev])
            }
            setModal(null)
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
            style={{ fontSize: 11, padding: '2px 8px' }}
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

function ActionCard({ action, usernameOf, onStatusChange, onEdit, onDelete, onRevert, isClosed, busy }) {
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
        className="select"
        value={action.status}
        onChange={(e) => onStatusChange(e.target.value)}
        disabled={isClosed || busy || isReverted}
        style={{ padding: '1px 5px', fontSize: 10, width: '100%' }}
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
        </div>
      )}

      {action.description && (
        <div style={{ fontSize: 12, color: 'var(--muted)' }}>{action.description}</div>
      )}

      {action.notes && (
        <div style={{ fontSize: 11, color: 'var(--dim)', fontStyle: 'italic' }}>{action.notes}</div>
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

function DecisionCard({ decision, usernameOf, onEdit, onDelete, isClosed, busy }) {
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

      <div style={{ fontSize: 10, fontFamily: 'var(--font-mono)', color: 'var(--dim)' }}>
        {decision.decided_by_id ? `by ${usernameOf(decision.decided_by_id)} · ` : ''}
        {formatLocalShort(decision.decided_at ?? decision.created_at)}
      </div>
    </div>
  )
}

// ── Action modal (2-step: template picker → form) ─────────────────────────

function ActionModal({ incidentId, category, editing, users, entities, isAdmin, onClose, onSaved }) {
  const isEdit = !!editing

  // step: 'pick' (template selection) | 'form' (fill details)
  const [step,        setStep]        = useState(isEdit ? 'form' : 'pick')
  // selTemplate carries { title, targetHint, entityFilter } from the chosen template's group
  const [selTemplate, setSelTemplate] = useState(null)

  // form fields
  const [title,       setTitle]       = useState(editing?.title           ?? '')
  const [target,      setTarget]      = useState(editing?.details?.target ?? '')
  const [description, setDescription] = useState(editing?.description      ?? '')
  const [status,      setStatus]      = useState(editing?.status           ?? 'open')
  const [assigneeId,  setAssigneeId]  = useState(editing?.assignee_id     ?? '')
  const [notes,       setNotes]       = useState(editing?.notes            ?? '')
  const [occurredAt,  setOccurredAt]  = useState(editing?.occurred_at || '')
  const [busy,        setBusy]        = useState(false)
  const [error,       setError]       = useState(null)

  useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape' && !busy) onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [busy, onClose])

  // pickTemplate receives { id, title, targetHint } + entityFilter from the group
  const pickTemplate = (tpl) => {
    setSelTemplate(tpl)
    if (tpl) {
      setTitle(tpl.title)
      setTarget('')
    } else {
      setTitle('')
      setTarget('')
    }
    setStep('form')
  }

  // Entities filtered by the template's group hint (or all if no filter / custom)
  const filteredEntities = (() => {
    if (!entities.length) return []
    const filter = selTemplate?.entityFilter
    if (!filter) return entities
    return entities.filter(e => filter.includes(e.type))
  })()

  const onEntityPick = (e) => {
    const val = e.target.value
    if (!val) return
    const ent = entities.find(x => x.id === val)
    if (ent) setTarget(ent.name || ent.value)
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
        occurred_at: occurredAt || null,
      }
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
                      onClick={() => pickTemplate({ ...tpl, entityFilter: group.entityFilter ?? null })}
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

                {/* Entity picker — only when incident has entities */}
                {filteredEntities.length > 0 && (
                  <div className="field">
                    <label className="field-label" htmlFor="am-entity">
                      Entity
                      <span style={{ color: 'var(--dim)', fontWeight: 400, marginLeft: 4 }}>
                        (picks target)
                      </span>
                    </label>
                    <select id="am-entity" className="select" defaultValue=""
                            onChange={onEntityPick}>
                      <option value="">— select from entities —</option>
                      {filteredEntities.map(ent => (
                        <option key={ent.id} value={ent.id}>
                          [{ent.type}] {ent.name || ent.value}
                          {ent.compromised ? ' ⚠' : ''}
                        </option>
                      ))}
                    </select>
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
                  {(isAdmin || users.length > 0) && (
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
                  )}
                </div>

                <div className="field">
                  <label className="field-label" htmlFor="am-occurred">Occurred at (UTC, optional)</label>
                  <UtcDateTimeInput id="am-occurred" value={occurredAt} onChange={setOccurredAt} />
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

function DecisionModal({ incidentId, editing, users, isAdmin, onClose, onSaved }) {
  const isEdit = !!editing

  const [summary,     setSummary]     = useState(editing?.summary       ?? '')
  const [rationale,   setRationale]   = useState(editing?.rationale     ?? '')
  const [outcome,     setOutcome]     = useState(editing?.outcome       ?? 'pending')
  const [decidedById, setDecidedById] = useState(editing?.decided_by_id ?? '')
  const [decidedAt,   setDecidedAt]   = useState(editing?.decided_at || '')
  const [tagsText,    setTagsText]    = useState((editing?.tags ?? []).join(', '))
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
                  <label className="field-label" htmlFor="dm-at">Decided at (UTC, optional)</label>
                  <UtcDateTimeInput id="dm-at" value={decidedAt} onChange={setDecidedAt} />
                </div>
              </div>

              {(isAdmin || users.length > 0) && (
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
