import { useCallback, useEffect, useMemo, useState } from 'react'
import { useOutletContext, Link } from 'react-router-dom'
import { useAuth } from '../../hooks/useAuth.jsx'
import { api } from '../../api/client.js'
import { PHASE, labelOf } from '../../lib/incidentVocab.js'
import { formatLocal } from '../../lib/datetime.js'

const STATUS_LABEL = {
  open:         'Open',
  in_progress:  'In progress',
  done:         'Done',
  skipped:      'Skipped',
}
const STATUS_PILL = {
  open:         'pill-gray',
  in_progress:  'pill-med',
  done:         'pill-ok',
  skipped:      'pill-gray',
}

export default function Playbook() {
  const { inc } = useOutletContext()
  const { user } = useAuth()
  const isClosed = inc?.status === 'closed'
  const isAdmin  = user?.role === 'admin'

  const [tasks, setTasks]         = useState([])
  const [templates, setTemplates] = useState([])
  const [users, setUsers]         = useState([])
  const [loading, setLoading]     = useState(true)
  const [error, setError]         = useState(null)
  const [busy, setBusy]           = useState(false)
  const [modal, setModal]         = useState(null)   // null | 'add' | 'apply'

  const load = useCallback(async () => {
    setError(null)
    try {
      const [t, tpl] = await Promise.all([
        api.listPlaybookTasks(inc.id),
        api.listPlaybookTemplates().catch(() => []),
      ])
      setTasks(t)
      setTemplates(tpl)
    } catch (e) {
      setError(e.message || 'Could not load playbook')
    } finally {
      setLoading(false)
    }
  }, [inc.id])

  useEffect(() => { load() }, [load])

  // Lazy-load users for the assignee picker. Endpoint is admin-only;
  // non-admins simply won't have it populated.
  useEffect(() => {
    if (!isAdmin) return
    let cancelled = false
    api.listUsers()
      .then(u => { if (!cancelled) setUsers(u) })
      .catch(() => {})
    return () => { cancelled = true }
  }, [isAdmin])

  const usernameOf = (uid) => {
    if (!uid) return null
    const u = users.find(x => x.id === uid)
    return u ? u.username : uid.slice(0, 8) + '…'
  }

  // Group tasks by phase, preserving PHASE ordering.
  const groups = useMemo(() => {
    const byPhase = new Map(PHASE.map(p => [p.value, []]))
    for (const t of tasks) {
      if (!byPhase.has(t.phase)) byPhase.set(t.phase, [])
      byPhase.get(t.phase).push(t)
    }
    return Array.from(byPhase.entries())
      .filter(([, list]) => list.length > 0)
      .map(([phase, list]) => ({
        phase,
        label: labelOf('phase', phase),
        tasks: [...list].sort((a, b) => a.order_index - b.order_index),
        done:  list.filter(t => t.status === 'done').length,
        total: list.length,
      }))
  }, [tasks])

  const totalDone  = tasks.filter(t => t.status === 'done').length
  const totalTasks = tasks.length
  const progress   = totalTasks > 0 ? Math.round((totalDone / totalTasks) * 100) : 0

  const onStatusChange = async (task, next) => {
    setBusy(true); setError(null)
    try {
      const updated = await api.updatePlaybookTask(inc.id, task.id, { status: next })
      setTasks(prev => prev.map(t => t.id === updated.id ? updated : t))
    } catch (e) {
      setError(e.message || 'Could not update status')
    } finally {
      setBusy(false)
    }
  }

  const onAssigneeChange = async (task, next) => {
    setBusy(true); setError(null)
    try {
      const updated = await api.updatePlaybookTask(inc.id, task.id, { assignee_id: next || null })
      setTasks(prev => prev.map(t => t.id === updated.id ? updated : t))
    } catch (e) {
      setError(e.message || 'Could not change assignee')
    } finally {
      setBusy(false)
    }
  }

  const onDelete = async (task) => {
    if (!window.confirm(`Delete task "${task.title}"?`)) return
    setBusy(true); setError(null)
    try {
      await api.deletePlaybookTask(inc.id, task.id)
      setTasks(prev => prev.filter(t => t.id !== task.id))
    } catch (e) {
      setError(e.message || 'Could not delete task')
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="panel">
      <div className="panel-toolbar">
        <div>
          <h2 className="panel-h" style={{ marginBottom: 4 }}>Playbook</h2>
          <div style={{ color: 'var(--muted)', fontFamily: 'var(--font-mono)', fontSize: 11 }}>
            {totalDone}/{totalTasks} done ({progress}%)
            {totalTasks > 0 && (
              <span style={{ display: 'inline-block', width: 120, height: 6, background: 'var(--surface-2)', marginLeft: 'var(--space-2)', borderRadius: 3, verticalAlign: 'middle' }}>
                <span style={{ display: 'block', width: `${progress}%`, height: '100%', background: 'var(--accent)', borderRadius: 3 }} />
              </span>
            )}
          </div>
        </div>
        <div style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'center' }}>
          <Link
            to="/playbooks"
            className="btn"
            style={{ textDecoration: 'none' }}
            title="Browse the playbook template library"
          >Browse library</Link>
          <button
            type="button"
            className="btn"
            onClick={() => setModal('apply')}
            disabled={isClosed || templates.length === 0}
            title={isClosed ? 'Closed incidents are read-only' : 'Apply a template'}
          >Apply template</button>
          <button
            type="button"
            className="btn primary"
            onClick={() => setModal('add')}
            disabled={isClosed}
          >+ Add task</button>
        </div>
      </div>

      {error && (
        <div className="alert error" role="alert">
          <span className="alert-icon">!</span><span>{error}</span>
        </div>
      )}

      {loading ? (
        <div className="panel-empty"><div>Loading…</div></div>
      ) : tasks.length === 0 ? (
        <div className="panel-empty">
          <div className="panel-empty-mark" aria-hidden="true">▤</div>
          <div>No tasks yet.</div>
          {!isClosed && (
            <div style={{ color: 'var(--dim)', fontSize: 12 }}>
              Apply a seeded template (NIST 800-61 R3, CISA Federal IR, CISA Vulnerability Response)
              or add custom tasks.
            </div>
          )}
        </div>
      ) : (
        groups.map(g => (
          <PhaseGroup
            key={g.phase}
            group={g}
            users={users}
            usernameOf={usernameOf}
            onStatusChange={onStatusChange}
            onAssigneeChange={onAssigneeChange}
            onDelete={onDelete}
            isClosed={isClosed}
            isAdmin={isAdmin}
            busy={busy}
          />
        ))
      )}

      {modal === 'add' && (
        <AddTaskModal
          incidentId={inc.id}
          onClose={() => setModal(null)}
          onSaved={(t) => { setTasks(prev => [...prev, t]); setModal(null) }}
        />
      )}
      {modal === 'apply' && (
        <ApplyTemplateModal
          incidentId={inc.id}
          templates={templates}
          existingCount={totalTasks}
          onClose={() => setModal(null)}
          onApplied={(allTasks) => { setTasks(allTasks); setModal(null) }}
        />
      )}
    </section>
  )
}

// ── Phase group ───────────────────────────────────────────────────────────

function PhaseGroup({ group, users, usernameOf, onStatusChange, onAssigneeChange, onDelete, isClosed, isAdmin, busy }) {
  return (
    <div style={{ marginBottom: 'var(--space-4)' }}>
      <h3 style={{
        margin: '0 0 var(--space-2) 0',
        fontFamily: 'var(--font-heading)',
        fontSize: 12,
        letterSpacing: 'var(--heading-letter-spacing)',
        textTransform: 'var(--heading-transform)',
        color: 'var(--accent)',
      }}>
        {group.label}{' '}
        <span style={{ color: 'var(--muted)', fontFamily: 'var(--font-mono)', fontSize: 11, fontWeight: 400 }}>
          {group.done}/{group.total}
        </span>
      </h3>
      <ul style={{ listStyle: 'none', margin: 0, padding: 0, display: 'flex', flexDirection: 'column', gap: 4 }}>
        {group.tasks.map(t => (
          <li key={t.id} style={{
            display: 'grid',
            gridTemplateColumns: '120px 1fr 180px 180px 80px',
            gap: 'var(--space-2)',
            padding: 'var(--space-2) var(--space-3)',
            background: 'var(--surface-2)',
            border: '1px solid var(--border)',
            borderRadius: 'var(--radius)',
            alignItems: 'start',
          }}>
            <div>
              <select
                className="select"
                value={t.status}
                onChange={(e) => onStatusChange(t, e.target.value)}
                disabled={isClosed || busy}
                style={{ padding: '2px 6px', fontSize: 11 }}
                aria-label="Status"
              >
                {Object.entries(STATUS_LABEL).map(([v, l]) => (
                  <option key={v} value={v}>{l}</option>
                ))}
              </select>
            </div>
            <div>
              <div style={{
                fontWeight: 500,
                textDecoration: t.status === 'done' || t.status === 'skipped' ? 'line-through' : 'none',
                color: t.status === 'done' || t.status === 'skipped' ? 'var(--muted)' : 'var(--text)',
              }}>
                {t.title}
              </div>
              {t.description && (
                <div style={{ color: 'var(--muted)', fontSize: 12, marginTop: 2 }}>
                  {t.description}
                </div>
              )}
              {t.status === 'done' && t.completed_at && (
                <div style={{ color: 'var(--ok)', fontFamily: 'var(--font-mono)', fontSize: 10, marginTop: 2 }}>
                  done {formatLocal(t.completed_at)}
                </div>
              )}
            </div>
            <div>
              <select
                className="select"
                value={t.assignee_id || ''}
                onChange={(e) => onAssigneeChange(t, e.target.value)}
                disabled={isClosed || busy || (!isAdmin && users.length === 0)}
                style={{ padding: '2px 6px', fontSize: 11 }}
                aria-label="Assignee"
              >
                <option value="">Unassigned</option>
                {users.map(u => (
                  <option key={u.id} value={u.id}>{u.username}</option>
                ))}
                {/* If a task is assigned to someone not in our user list (e.g. non-admin
                    viewing) keep the value showing rather than dropping it silently. */}
                {t.assignee_id && !users.some(u => u.id === t.assignee_id) && (
                  <option value={t.assignee_id}>{usernameOf(t.assignee_id)}</option>
                )}
              </select>
            </div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--muted)' }}>
              <span className={`pill ${STATUS_PILL[t.status] || 'pill-gray'}`}>{STATUS_LABEL[t.status]}</span>
              {t.source_template_id && (
                <div style={{ color: 'var(--dim)', fontSize: 10, marginTop: 4 }}>from template</div>
              )}
            </div>
            <div style={{ textAlign: 'right' }}>
              <button
                type="button"
                className="btn ghost"
                onClick={() => onDelete(t)}
                disabled={isClosed || busy}
                style={{ padding: '2px 8px', fontSize: 11 }}
              >Delete</button>
            </div>
          </li>
        ))}
      </ul>
    </div>
  )
}

// ── Add custom task modal ─────────────────────────────────────────────────

function AddTaskModal({ incidentId, onClose, onSaved }) {
  const [title, setTitle]             = useState('')
  const [description, setDescription] = useState('')
  const [phase, setPhase]             = useState('detection_and_analysis')
  const [busy, setBusy]               = useState(false)
  const [error, setError]             = useState(null)

  useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape' && !busy) onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [busy, onClose])

  const onSubmit = async (e) => {
    e.preventDefault()
    setError(null)
    if (!title.trim()) { setError('Title is required.'); return }
    setBusy(true)
    try {
      const t = await api.createPlaybookTask(incidentId, {
        title:       title.trim(),
        description: description.trim() || null,
        phase,
        order_index: 9999,
      })
      onSaved(t)
    } catch (e2) {
      setError(e2.message || 'Could not add task')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="modal-backdrop"
        >
      <div className="modal" role="dialog" aria-labelledby="pb-add-title">
        <div className="modal-head">
          <h2 id="pb-add-title">Add task</h2>
          <button type="button" className="modal-close" onClick={onClose} disabled={busy}>×</button>
        </div>
        <form onSubmit={onSubmit}>
          <div className="modal-body">
            <div className="form">
              <div className="field">
                <label className="field-label" htmlFor="pb-title">Title</label>
                <input id="pb-title" className="input" value={title}
                       onChange={(e) => setTitle(e.target.value)}
                       autoFocus required maxLength={512} />
              </div>
              <div className="field">
                <label className="field-label" htmlFor="pb-desc">Description (optional)</label>
                <textarea id="pb-desc" className="input" value={description}
                          onChange={(e) => setDescription(e.target.value)}
                          rows={3} maxLength={4096} />
              </div>
              <div className="field">
                <label className="field-label" htmlFor="pb-phase">Phase (800-61 R3)</label>
                <select id="pb-phase" className="select" value={phase}
                        onChange={(e) => setPhase(e.target.value)}>
                  {PHASE.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
                </select>
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
              {busy ? 'Adding…' : 'Add task'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ── Apply template modal ──────────────────────────────────────────────────

function ApplyTemplateModal({ incidentId, templates, existingCount, onClose, onApplied }) {
  const [templateId, setTemplateId] = useState(templates[0]?.id || '')
  const [confirmed,  setConfirmed]  = useState(false)
  const [busy, setBusy]             = useState(false)
  const [error, setError]           = useState(null)

  const hasExisting = existingCount > 0

  // Reset confirmation when template changes
  useEffect(() => { setConfirmed(false) }, [templateId])

  useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape' && !busy) onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [busy, onClose])

  const onSubmit = async (e) => {
    e.preventDefault()
    setError(null)
    if (!templateId) { setError('Pick a template.'); return }
    if (hasExisting && !confirmed) { setError('Confirm that existing tasks will be removed.'); return }
    setBusy(true)
    try {
      const tasks = await api.instantiatePlaybook(incidentId, {
        template_id: templateId,
        replace: true,
      })
      onApplied(tasks)
    } catch (e2) {
      setError(e2.message || 'Could not apply template')
    } finally {
      setBusy(false)
    }
  }

  const selected = templates.find(t => t.id === templateId)

  return (
    <div className="modal-backdrop"
        >
      <div className="modal" role="dialog" aria-labelledby="pb-apply-title">
        <div className="modal-head">
          <h2 id="pb-apply-title">Apply playbook template</h2>
          <button type="button" className="modal-close" onClick={onClose} disabled={busy}>×</button>
        </div>
        <form onSubmit={onSubmit}>
          <div className="modal-body">
            <div className="form">
              <div className="field">
                <label className="field-label" htmlFor="pb-tpl">Template</label>
                <select id="pb-tpl" className="select" value={templateId}
                        onChange={(e) => setTemplateId(e.target.value)} autoFocus>
                  {templates.map(t => (
                    <option key={t.id} value={t.id}>
                      {t.name} ({t.task_count} tasks){t.is_system ? '' : ' — custom'}
                    </option>
                  ))}
                </select>
              </div>

              {selected?.description && (
                <div style={{ color: 'var(--muted)', fontSize: 13, lineHeight: 1.5 }}>
                  {selected.description}
                </div>
              )}

              {hasExisting && (
                <div style={{
                  padding: 'var(--space-3)',
                  background: 'color-mix(in srgb, var(--high) 12%, transparent)',
                  border: '1px solid var(--high)',
                  borderRadius: 'var(--radius)',
                }}>
                  <div style={{ fontWeight: 600, fontSize: 13, color: 'var(--high)', marginBottom: 'var(--space-1)' }}>
                    This will delete the existing playbook
                  </div>
                  <div style={{ fontSize: 12, color: 'var(--text)', marginBottom: 'var(--space-2)', lineHeight: 1.5 }}>
                    The {existingCount} existing task{existingCount !== 1 ? 's' : ''} — including any completed or in-progress work — will be permanently deleted and replaced with the selected template.
                  </div>
                  <label style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', cursor: 'pointer', fontSize: 13 }}>
                    <input
                      type="checkbox"
                      checked={confirmed}
                      onChange={(e) => setConfirmed(e.target.checked)}
                    />
                    I understand all saved progress will be lost
                  </label>
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
            <button
              type="submit"
              className="btn primary"
              disabled={busy || (hasExisting && !confirmed)}
            >
              {busy ? 'Applying…' : 'Apply playbook'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
