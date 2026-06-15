import { useCallback, useEffect, useState } from 'react'
import { api } from '../../api/client.js'
import { formatLocal } from '../../lib/datetime.js'

export default function Teams() {
  const [teams, setTeams]     = useState([])
  const [users, setUsers]     = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError]     = useState(null)
  const [modal, setModal]     = useState(null)            // null | { mode, team? }
  const [openTeamId, setOpenTeamId] = useState(null)

  const load = useCallback(async () => {
    setError(null)
    try {
      const [t, u] = await Promise.all([api.listTeams(), api.listUsers()])
      setTeams(t)
      setUsers(u)
    } catch (e) {
      setError(e.message || 'Could not load teams')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  const onDelete = async (team) => {
    if (!window.confirm(`Delete team "${team.name}"? Members are not deleted; only their team association.`)) return
    try {
      await api.deleteTeam(team.id)
      if (openTeamId === team.id) setOpenTeamId(null)
      await load()
    } catch (e) {
      setError(e.message || 'Could not delete team')
    }
  }

  return (
    <section className="panel">
      <div className="panel-toolbar">
        <h2 className="panel-h">Teams</h2>
        <button type="button" className="btn primary" onClick={() => setModal({ mode: 'create' })}>
          + New team
        </button>
      </div>

      {error && (
        <div className="alert error" role="alert">
          <span className="alert-icon">!</span>
          <span>{error}</span>
        </div>
      )}

      {loading ? (
        <div className="panel-empty"><div>Loading…</div></div>
      ) : teams.length === 0 ? (
        <div className="panel-empty">
          <div className="panel-empty-mark" aria-hidden="true">◌</div>
          <div>No teams yet.</div>
        </div>
      ) : (
        <table className="settings-table">
          <thead>
            <tr>
              <th style={{ width: 24 }}></th>
              <th>Name</th>
              <th>Description</th>
              <th>Members</th>
              <th>Created</th>
              <th className="actions">Actions</th>
            </tr>
          </thead>
          <tbody>
            {teams.map(t => (
              <TeamRow
                key={t.id}
                team={t}
                users={users}
                open={openTeamId === t.id}
                onToggle={() => setOpenTeamId(openTeamId === t.id ? null : t.id)}
                onEdit={() => setModal({ mode: 'edit', team: t })}
                onDelete={() => onDelete(t)}
                onMembershipChanged={load}
                setError={setError}
              />
            ))}
          </tbody>
        </table>
      )}

      {modal && (
        <TeamModal
          mode={modal.mode}
          team={modal.team}
          onClose={() => setModal(null)}
          onSaved={() => { setModal(null); load() }}
        />
      )}
    </section>
  )
}

function TeamRow({ team, users, open, onToggle, onEdit, onDelete, onMembershipChanged, setError }) {
  return (
    <>
      <tr>
        <td>
          <span aria-hidden="true" style={{
            display: 'inline-block', width: 12, height: 12, borderRadius: '50%',
            background: team.color, border: '1px solid var(--border)',
          }} />
        </td>
        <td><b>{team.name}</b></td>
        <td title={team.description || ''} style={{ maxWidth: 260, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
          {team.description || <span style={{ color: 'var(--dim)' }}>—</span>}
        </td>
        <td>{team.member_count}</td>
        <td title={formatLocal(team.created_at)}>{formatLocal(team.created_at).slice(0, 10)}</td>
        <td className="actions">
          <span className="row-actions">
            <button type="button" className="btn ghost" onClick={onToggle}>
              {open ? 'Hide members' : 'Members'}
            </button>
            <button type="button" className="btn ghost" onClick={onEdit}>Edit</button>
            <button type="button" className="btn ghost" onClick={onDelete}>Delete</button>
          </span>
        </td>
      </tr>
      {open && (
        <tr>
          <td colSpan={6} style={{ background: 'var(--surface-2)' }}>
            <MemberPanel team={team} users={users} onChange={onMembershipChanged} setError={setError} />
          </td>
        </tr>
      )}
    </>
  )
}

function MemberPanel({ team, users, onChange, setError }) {
  const [members, setMembers] = useState([])
  const [loading, setLoading] = useState(true)
  const [pick, setPick]       = useState('')
  const [busy, setBusy]       = useState(false)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const m = await api.listTeamMembers(team.id)
      setMembers(m)
    } catch (e) {
      setError?.(e.message || 'Could not load members')
    } finally {
      setLoading(false)
    }
  }, [team.id, setError])

  useEffect(() => { load() }, [load])

  const memberIds = new Set(members.map(m => m.id))
  const available = users.filter(u => u.is_active && !memberIds.has(u.id))

  const addMember = async () => {
    if (!pick) return
    setBusy(true)
    try {
      await api.addTeamMember(team.id, pick)
      setPick('')
      await load()
      onChange?.()
    } catch (e) {
      setError?.(e.message || 'Could not add member')
    } finally {
      setBusy(false)
    }
  }

  const removeMember = async (user) => {
    if (!window.confirm(`Remove ${user.username} from "${team.name}"?`)) return
    setBusy(true)
    try {
      await api.removeTeamMember(team.id, user.id)
      await load()
      onChange?.()
    } catch (e) {
      setError?.(e.message || 'Could not remove member')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div style={{ padding: 'var(--space-3)' }}>
      <div style={{ display: 'flex', gap: 'var(--space-2)', marginBottom: 'var(--space-3)', alignItems: 'center' }}>
        <select
          className="select"
          value={pick}
          onChange={(e) => setPick(e.target.value)}
          disabled={available.length === 0 || busy}
          style={{ flex: 1, maxWidth: 320 }}
        >
          <option value="">
            {available.length === 0 ? 'All active users are members' : 'Add member…'}
          </option>
          {available.map(u => (
            <option key={u.id} value={u.id}>{u.username} ({u.role})</option>
          ))}
        </select>
        <button type="button" className="btn primary" onClick={addMember} disabled={!pick || busy}>
          Add
        </button>
      </div>

      {loading ? (
        <div style={{ color: 'var(--muted)', fontSize: 13 }}>Loading members…</div>
      ) : members.length === 0 ? (
        <div style={{ color: 'var(--muted)', fontSize: 13 }}>No members yet.</div>
      ) : (
        <ul style={{ listStyle: 'none', margin: 0, padding: 0, display: 'flex', flexWrap: 'wrap', gap: 'var(--space-2)' }}>
          {members.map(u => (
            <li key={u.id} style={{
              display: 'inline-flex', alignItems: 'center', gap: 8,
              padding: '4px 4px 4px 10px', background: 'var(--surface)',
              border: '1px solid var(--border)', borderRadius: 'var(--radius)',
              fontSize: 13,
            }}>
              <span>{u.username}</span>
              <span style={{ color: 'var(--dim)', fontFamily: 'var(--font-mono)', fontSize: 10, letterSpacing: '0.08em', textTransform: 'uppercase' }}>
                {u.role}
              </span>
              <button
                type="button"
                onClick={() => removeMember(u)}
                disabled={busy}
                aria-label={`Remove ${u.username}`}
                title={`Remove ${u.username}`}
                style={{
                  background: 'transparent', border: 'none', color: 'var(--muted)',
                  cursor: 'pointer', padding: '2px 8px', fontSize: 14,
                }}
              >×</button>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}

function TeamModal({ mode, team, onClose, onSaved }) {
  const isEdit = mode === 'edit'
  const [name, setName]   = useState(team?.name || '')
  const [desc, setDesc]   = useState(team?.description || '')
  const [color, setColor] = useState(team?.color || '#22d3ee')
  const [busy, setBusy]   = useState(false)
  const [error, setError] = useState(null)

  useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  const onSubmit = async (e) => {
    e.preventDefault()
    setError(null)
    const n = name.trim()
    if (n.length < 1) { setError('Name is required.'); return }
    setBusy(true)
    try {
      const payload = { name: n, description: desc.trim() || null, color }
      if (isEdit) await api.updateTeam(team.id, payload)
      else        await api.createTeam(payload)
      onSaved()
    } catch (err) {
      setError(err.message || 'Could not save team')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="modal-backdrop">
      <div className="modal" role="dialog" aria-labelledby="team-modal-title">
        <div className="modal-head">
          <h2 id="team-modal-title">{isEdit ? 'Edit team' : 'New team'}</h2>
          <button className="modal-close" type="button" onClick={onClose} aria-label="Close">×</button>
        </div>
        <form onSubmit={onSubmit}>
          <div className="modal-body">
            <div className="form">
              <div className="field">
                <label className="field-label" htmlFor="team-name">Name</label>
                <input id="team-name" className="input" value={name} onChange={(e) => setName(e.target.value)}
                       autoFocus required minLength={1} maxLength={128} />
              </div>
              <div className="field">
                <label className="field-label" htmlFor="team-desc">Description (optional)</label>
                <textarea id="team-desc" className="input" value={desc} onChange={(e) => setDesc(e.target.value)}
                          rows={3} />
              </div>
              <div className="field">
                <label className="field-label" htmlFor="team-color">Colour</label>
                <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
                  <input id="team-color" type="color" value={color} onChange={(e) => setColor(e.target.value)}
                         style={{ width: 48, height: 32, padding: 0, border: '1px solid var(--border)', borderRadius: 'var(--radius)', background: 'var(--surface-2)', cursor: 'pointer' }} />
                  <input className="input" value={color} onChange={(e) => setColor(e.target.value)}
                         pattern="^#[0-9a-fA-F]{6}$" maxLength={7} style={{ maxWidth: 140 }} />
                </div>
              </div>
              {error && (
                <div className="alert error" role="alert">
                  <span className="alert-icon">!</span>
                  <span>{error}</span>
                </div>
              )}
            </div>
          </div>
          <div className="modal-foot">
            <button type="button" className="btn ghost" onClick={onClose} disabled={busy}>Cancel</button>
            <button type="submit" className="btn primary" disabled={busy}>
              {busy ? 'Saving…' : (isEdit ? 'Save changes' : 'Create team')}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
