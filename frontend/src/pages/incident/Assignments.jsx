import { useCallback, useEffect, useState } from 'react'
import { useOutletContext } from 'react-router-dom'
import { api } from '../../api/client.js'
import { useAuth } from '../../hooks/useAuth.jsx'
import { formatLocal } from '../../lib/datetime.js'

// ─── Role Coverage section ────────────────────────────────────────────────────

function RoleCoverage({ incidentId, refreshKey }) {
  const [slots, setSlots]   = useState(null)
  const [error, setError]   = useState(null)

  useEffect(() => {
    api.getRosterCoverage(incidentId)
      .then(d => setSlots(d.slots ?? []))
      .catch(e => setError(e.message ?? 'Could not load coverage'))
  }, [incidentId, refreshKey])

  if (error) return null  // non-critical — hide silently on error

  const filled  = slots?.filter(s => s.assignments.length > 0) ?? []
  const vacant  = slots?.filter(s => s.assignments.length === 0) ?? []

  return (
    <div style={{ marginTop: 'var(--space-6)' }}>
      <div style={{ marginBottom: 'var(--space-3)' }}>
        <h3 style={{ margin: 0, fontSize: '0.9rem', fontWeight: 700 }}>Role Coverage</h3>
        <p style={{ margin: '4px 0 0', fontSize: '0.8rem', color: 'var(--muted)' }}>
          CISA operational roles — filled vs. vacant on this incident.
        </p>
      </div>

      {slots === null && (
        <div style={{ fontSize: '0.8rem', color: 'var(--dim)' }}>Loading…</div>
      )}

      {slots !== null && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: 'var(--space-2)' }}>
          {slots.map(slot => {
            const isFilled = slot.assignments.length > 0
            return (
              <div key={slot.role_id} style={{
                padding: 'var(--space-2) var(--space-3)',
                borderRadius: 'var(--radius)',
                border: '1px solid var(--border)',
                borderLeft: `3px solid ${isFilled ? 'var(--ok)' : 'var(--border)'}`,
                background: 'var(--surface)',
                opacity: isFilled ? 1 : 0.6,
              }}>
                <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text)', marginBottom: 2 }}>
                  {slot.role_label}
                </div>
                {isFilled ? (
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 3 }}>
                    {slot.assignments.map(a => (
                      <span key={a.assignment_id} style={{
                        fontSize: 11, padding: '1px 6px',
                        background: 'var(--accent-soft)', color: 'var(--accent)',
                        borderRadius: 'var(--radius-sm)', fontWeight: 600,
                      }}>{a.username}</span>
                    ))}
                  </div>
                ) : (
                  <div style={{ fontSize: 11, color: 'var(--dim)' }}>Vacant</div>
                )}
              </div>
            )
          })}
        </div>
      )}

      {slots !== null && slots.length > 0 && (
        <div style={{ marginTop: 'var(--space-2)', fontSize: 11, color: 'var(--dim)' }}>
          {filled.length} of {slots.length} roles filled
          {vacant.length > 0 && ` · ${vacant.length} vacant`}
        </div>
      )}
    </div>
  )
}

// ─── Assign modal ─────────────────────────────────────────────────────────────

function AssignModal({ incidentId, onClose, onCreated }) {
  const [users, setUsers]   = useState([])
  const [roles, setRoles]   = useState([])
  const [userId, setUserId] = useState('')
  const [roleId, setRoleId] = useState('')
  const [notes, setNotes]   = useState('')
  const [saving, setSaving] = useState(false)
  const [error, setError]   = useState(null)

  useEffect(() => {
    Promise.all([
      api.listAssignableUsers(),
      api.listOperationalRoles(),
    ]).then(([u, r]) => {
      setUsers(u)
      const active = (r.items ?? r).filter(x => x.is_active)
      setRoles(active)
      if (active.length) setRoleId(active[0].id)
    }).catch(() => {})
  }, [])

  const handleSubmit = useCallback(async e => {
    e.preventDefault()
    if (!userId || !roleId) return
    setSaving(true)
    setError(null)
    try {
      const created = await api.createAssignment(incidentId, {
        user_id: userId,
        role_id: roleId,
        notes: notes.trim() || null,
      })
      onCreated(created)
    } catch (err) {
      setError(err.message ?? 'Failed to assign')
    } finally {
      setSaving(false)
    }
  }, [incidentId, userId, roleId, notes, onCreated])

  return (
    <div className="modal-backdrop">
      <div className="modal" style={{ maxWidth: 480 }}>
        <div className="modal-head">
          <h2>Assign to incident</h2>
          <button type="button" className="modal-close" onClick={onClose} aria-label="Close">×</button>
        </div>
        <form onSubmit={handleSubmit}>
          <div className="modal-body" style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
            {error && <div className="alert error" role="alert"><span className="alert-icon">!</span><span>{error}</span></div>}

            <label className="field-label">
              User
              <select
                className="input"
                value={userId}
                onChange={e => setUserId(e.target.value)}
                required
              >
                <option value="">— select user —</option>
                {users.map(u => (
                  <option key={u.id} value={u.id}>{u.username}</option>
                ))}
              </select>
            </label>

            <label className="field-label">
              Operational role
              <select
                className="input"
                value={roleId}
                onChange={e => setRoleId(e.target.value)}
                required
              >
                {roles.map(r => (
                  <option key={r.id} value={r.id}>{r.label}</option>
                ))}
              </select>
            </label>

            <label className="field-label">
              Notes <span className="muted">(optional)</span>
              <textarea
                className="input"
                rows={2}
                value={notes}
                onChange={e => setNotes(e.target.value)}
                maxLength={1024}
              />
            </label>
          </div>

          <div className="modal-foot">
            <button type="button" className="btn ghost" onClick={onClose}>Cancel</button>
            <button type="submit" className="btn primary" disabled={saving || !userId || !roleId}>
              {saving ? 'Assigning…' : 'Assign'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ─── Avatar initials ──────────────────────────────────────────────────────────

function Avatar({ username }) {
  const initials = username
    .split(/[\s._-]+/)
    .slice(0, 2)
    .map(w => w[0]?.toUpperCase() ?? '')
    .join('')
  return (
    <div style={{
      width: 36, height: 36, borderRadius: '50%',
      background: 'var(--accent-soft)',
      color: 'var(--accent)',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      fontFamily: 'var(--font-mono)',
      fontSize: '0.75rem', fontWeight: 700,
      flexShrink: 0,
    }}>
      {initials || '?'}
    </div>
  )
}

// ─── Assignment card ──────────────────────────────────────────────────────────

function AssignmentCard({ assignment, currentUser, isClosed, onRemoved }) {
  const [removing, setRemoving] = useState(false)

  const canRemove = !isClosed && (
    currentUser?.role === 'admin' || assignment.user_id === currentUser?.id
  )

  const handleRemove = useCallback(async () => {
    if (!window.confirm(`Remove ${assignment.username} (${assignment.role_label})?`)) return
    setRemoving(true)
    try {
      await api.deleteAssignment(assignment.incident_id, assignment.id)
      onRemoved(assignment.id)
    } catch (err) {
      alert(err.message ?? 'Failed to remove')
      setRemoving(false)
    }
  }, [assignment, onRemoved])

  return (
    <div className="surface-2" style={{
      borderRadius: 'var(--radius)',
      padding: 'var(--space-3)',
      display: 'flex', gap: 'var(--space-3)', alignItems: 'flex-start',
    }}>
      <Avatar username={assignment.username} />
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontWeight: 600, color: 'var(--text)', marginBottom: 2 }}>
          {assignment.username}
        </div>
        <div style={{
          display: 'inline-block',
          background: 'var(--accent-soft)',
          color: 'var(--accent)',
          borderRadius: 'var(--radius-sm)',
          padding: '1px 8px',
          fontSize: '0.75rem',
          fontWeight: 600,
          marginBottom: 4,
        }}>
          {assignment.role_label}
        </div>
        {assignment.notes && (
          <div style={{ fontSize: '0.8rem', color: 'var(--muted)', marginTop: 2 }}>
            {assignment.notes}
          </div>
        )}
        <div style={{ fontSize: '0.75rem', color: 'var(--dim)', marginTop: 4 }}>
          Assigned {formatLocal(assignment.assigned_at)}
          {assignment.assigned_by_username && ` by ${assignment.assigned_by_username}`}
        </div>
      </div>
      {canRemove && (
        <button
          className="btn btn-ghost"
          style={{ fontSize: '0.75rem', padding: '2px 8px', flexShrink: 0 }}
          onClick={handleRemove}
          disabled={removing}
        >
          {removing ? '…' : 'Remove'}
        </button>
      )}
    </div>
  )
}

// ─── Main page ────────────────────────────────────────────────────────────────

export default function Assignments() {
  const { inc: incident } = useOutletContext()
  const { user } = useAuth()
  const [assignments, setAssignments]   = useState([])
  const [loading, setLoading]           = useState(true)
  const [showModal, setShowModal]       = useState(false)
  const [coverageKey, setCoverageKey]   = useState(0)
  const isClosed = incident?.status === 'closed'

  const load = useCallback(async () => {
    if (!incident?.id) return
    try {
      const data = await api.listAssignments(incident.id)
      setAssignments(data.items ?? [])
    } catch (_) {}
    setLoading(false)
  }, [incident?.id])

  useEffect(() => { load() }, [load])

  const handleCreated = useCallback(created => {
    setAssignments(prev => [...prev, created])
    setShowModal(false)
    setCoverageKey(k => k + 1)
  }, [])

  const handleRemoved = useCallback(id => {
    setAssignments(prev => prev.filter(a => a.id !== id))
    setCoverageKey(k => k + 1)
  }, [])

  return (
    <div style={{ padding: 'var(--space-4)' }}>
      <div style={{
        display: 'flex', alignItems: 'center',
        justifyContent: 'space-between',
        marginBottom: 'var(--space-4)',
      }}>
        <div>
          <h2 style={{ margin: 0, fontSize: '1rem', fontWeight: 700 }}>Assignments</h2>
          <p style={{ margin: '4px 0 0', fontSize: '0.8rem', color: 'var(--muted)' }}>
            IR team members and their operational roles on this incident.
          </p>
        </div>
        {!isClosed && user?.role !== 'viewer' && (
          <button className="btn btn-primary" style={{ fontSize: '0.8rem' }}
            onClick={() => setShowModal(true)}>
            + Assign
          </button>
        )}
      </div>

      {loading && <p className="muted">Loading…</p>}

      {!loading && assignments.length === 0 && (
        <div style={{
          textAlign: 'center', padding: 'var(--space-6)',
          color: 'var(--muted)', fontSize: '0.85rem',
        }}>
          No assignments yet.{!isClosed && ' Use "+ Assign" to add team members.'}
        </div>
      )}

      {!loading && assignments.length > 0 && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: 'var(--space-3)' }}>
          {assignments.map(a => (
            <AssignmentCard
              key={a.id}
              assignment={a}
              currentUser={user}
              isClosed={isClosed}
              onRemoved={handleRemoved}
            />
          ))}
        </div>
      )}

      <RoleCoverage incidentId={incident.id} refreshKey={coverageKey} />

      {showModal && (
        <AssignModal
          incidentId={incident.id}
          onClose={() => setShowModal(false)}
          onCreated={handleCreated}
        />
      )}
    </div>
  )
}
