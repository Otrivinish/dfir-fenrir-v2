import { useCallback, useEffect, useState } from 'react'
import { api } from '../../api/client.js'
import PasswordField from '../../components/PasswordField.jsx'
import { useAuth } from '../../hooks/useAuth.jsx'
import { formatLocal, formatLocalShort, relative } from '../../lib/datetime.js'

const ROLE_PILL = {
  admin:   'pill pill-crit',
  analyst: 'pill pill-ok',
  viewer:  'pill pill-gray',
}

const AVATAR_COLORS = [
  'var(--accent)', 'var(--ok)', 'var(--med)', 'var(--high)',
  'var(--low)', 'var(--crit)',
]

function Avatar({ user }) {
  const letter = (user.full_name || user.username)[0].toUpperCase()
  const color  = AVATAR_COLORS[user.username.charCodeAt(0) % AVATAR_COLORS.length]
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
      width: 28, height: 28, borderRadius: '50%', flexShrink: 0,
      background: color, color: 'var(--bg)',
      fontFamily: 'var(--font-mono)', fontSize: 11, fontWeight: 700,
    }}>{letter}</span>
  )
}

export default function Users() {
  const [users,    setUsers]    = useState([])
  const [allTeams, setAllTeams] = useState([])
  const [loading,  setLoading]  = useState(true)
  const [error,    setError]    = useState(null)
  const [search,   setSearch]   = useState('')
  const [roleF,    setRoleF]    = useState('')
  const [statusF,  setStatusF]  = useState('')
  const [modal,    setModal]    = useState(null)   // null | {mode:'create'} | {mode:'detail', user}

  const load = useCallback(async () => {
    setError(null)
    try {
      const [u, t] = await Promise.all([api.listUsers(), api.listTeams()])
      setUsers(u)
      setAllTeams(t)
    } catch (e) {
      setError(e.message || 'Could not load users')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  const filtered = users.filter(u => {
    if (search) {
      const q = search.toLowerCase()
      if (!u.username.toLowerCase().includes(q) &&
          !u.email.toLowerCase().includes(q) &&
          !(u.full_name || '').toLowerCase().includes(q)) return false
    }
    if (roleF   && u.role !== roleF)                           return false
    if (statusF && (statusF === 'active') !== u.is_active)     return false
    return true
  })

  const onDisable = async (user) => {
    if (!window.confirm(`Disable account "${user.username}"? They will be signed out.`)) return
    try {
      await api.updateUser(user.id, { is_active: false })
      await load()
    } catch (e) { setError(e.message || 'Could not disable user') }
  }

  const onEnable = async (user) => {
    try {
      await api.updateUser(user.id, { is_active: true })
      await load()
    } catch (e) { setError(e.message || 'Could not enable user') }
  }

  const onDelete = async (user) => {
    if (!window.confirm(`Permanently delete "${user.username}"? This cannot be undone.`)) return
    try {
      await api.deleteUser(user.id)
      await load()
    } catch (e) { setError(e.message || e.message || 'Could not delete user') }
  }

  const openDetail = (user) => setModal({ mode: 'detail', user })

  return (
    <section className="panel">
      <div className="panel-toolbar">
        <h2 className="panel-h">Users</h2>
        <button type="button" className="btn primary"
          onClick={() => setModal({ mode: 'create' })}>
          + New user
        </button>
      </div>

      <div style={{ display: 'flex', gap: 'var(--space-2)', marginBottom: 'var(--space-3)', flexWrap: 'wrap' }}>
        <input
          className="input"
          placeholder="Search username, email, name…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          style={{ flex: 1, minWidth: 200, maxWidth: 340 }}
        />
        <select className="select" value={roleF} onChange={(e) => setRoleF(e.target.value)}
          style={{ width: 140 }}>
          <option value="">All roles</option>
          <option value="admin">Admin</option>
          <option value="analyst">Analyst</option>
          <option value="viewer">Viewer</option>
        </select>
        <select className="select" value={statusF} onChange={(e) => setStatusF(e.target.value)}
          style={{ width: 130 }}>
          <option value="">All statuses</option>
          <option value="active">Active</option>
          <option value="inactive">Inactive</option>
        </select>
      </div>

      {error && (
        <div className="alert error" role="alert">
          <span className="alert-icon">!</span><span>{error}</span>
        </div>
      )}

      {loading ? (
        <div className="panel-empty"><div>Loading…</div></div>
      ) : filtered.length === 0 ? (
        <div className="panel-empty">
          <div className="panel-empty-mark" aria-hidden="true">◌</div>
          <div>{users.length === 0 ? 'No users yet.' : 'No users match the filter.'}</div>
        </div>
      ) : (
        <table className="settings-table">
          <thead>
            <tr>
              <th style={{ width: 36 }}></th>
              <th>Username</th>
              <th>Name</th>
              <th>Role</th>
              <th>Status</th>
              <th>TOTP</th>
              <th>Last login</th>
              <th className="actions">Actions</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map(u => (
              <UserRow
                key={u.id}
                user={u}
                onEdit={() => openDetail(u)}
                onDisable={() => onDisable(u)}
                onEnable={() => onEnable(u)}
                onDelete={() => onDelete(u)}
              />
            ))}
          </tbody>
        </table>
      )}

      {modal?.mode === 'create' && (
        <CreateModal
          onClose={() => setModal(null)}
          onSaved={() => { setModal(null); load() }}
        />
      )}

      {modal?.mode === 'detail' && (
        <DetailModal
          user={modal.user}
          allTeams={allTeams}
          onClose={() => setModal(null)}
          onChanged={async (updated) => {
            await load()
            if (updated) setModal({ mode: 'detail', user: updated })
          }}
        />
      )}
    </section>
  )
}

function UserRow({ user, onEdit, onDisable, onEnable, onDelete }) {
  return (
    <tr style={{ opacity: user.is_active ? 1 : 0.55 }}>
      <td><Avatar user={user} /></td>
      <td>
        <div style={{ fontWeight: 600 }}>{user.username}</div>
        <div style={{ fontSize: 11, color: 'var(--muted)', fontFamily: 'var(--font-mono)' }}>{user.email}</div>
      </td>
      <td style={{ color: user.full_name ? 'var(--text)' : 'var(--dim)' }}>
        {user.full_name || '—'}
      </td>
      <td><span className={ROLE_PILL[user.role] || 'pill pill-gray'}>{user.role}</span></td>
      <td>
        <span className={user.is_active ? 'pill pill-ok' : 'pill pill-gray'}>
          {user.is_active ? 'active' : 'inactive'}
        </span>
      </td>
      <td style={{ color: user.totp_enabled ? 'var(--ok)' : 'var(--dim)', fontFamily: 'var(--font-mono)', fontSize: 12 }}>
        {user.totp_enabled ? '✓' : '—'}
      </td>
      <td title={formatLocal(user.last_login_at)} style={{ fontSize: 12, color: 'var(--muted)' }}>
        {user.last_login_at ? relative(user.last_login_at) : 'Never'}
      </td>
      <td className="actions">
        <span className="row-actions">
          <button type="button" className="btn ghost" onClick={onEdit}>Edit</button>
          {user.is_active
            ? <button type="button" className="btn ghost" onClick={onDisable}>Disable</button>
            : <button type="button" className="btn ghost" onClick={onEnable}>Enable</button>
          }
          <button type="button" className="btn ghost" onClick={onDelete}
            style={{ color: 'var(--crit)' }}>Delete</button>
        </span>
      </td>
    </tr>
  )
}

// ─── Create user modal ───────────────────────────────────────────────────────

function CreateModal({ onClose, onSaved }) {
  const [username,  setUsername]  = useState('')
  const [email,     setEmail]     = useState('')
  const [fullName,  setFullName]  = useState('')
  const [role,      setRole]      = useState('analyst')
  const [qualifications, setQualifications] = useState('')
  const [password,  setPassword]  = useState('')
  const [confirm,   setConfirm]   = useState('')
  const [busy,      setBusy]      = useState(false)
  const [error,     setError]     = useState(null)

  useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  const onSubmit = async (e) => {
    e.preventDefault()
    setError(null)
    if (password !== confirm) { setError('Passwords do not match.'); return }
    if (password.length < 12) { setError('Password must be at least 12 characters.'); return }
    setBusy(true)
    try {
      await api.createUser({ username: username.trim(), email: email.trim(),
        full_name: fullName.trim() || null, role, password,
        qualifications: qualifications.trim() || null })
      onSaved()
    } catch (err) {
      setError(err.message || 'Could not create user')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="modal-backdrop">
      <div className="modal" role="dialog" aria-labelledby="create-user-title">
        <div className="modal-head">
          <h2 id="create-user-title">New user</h2>
          <button className="modal-close" type="button" onClick={onClose} aria-label="Close">×</button>
        </div>
        <form onSubmit={onSubmit}>
          <div className="modal-body">
            <div className="form">
              <div className="field">
                <label className="field-label" htmlFor="cu-username">Username</label>
                <input id="cu-username" className="input" value={username} required autoFocus
                  pattern="^[a-zA-Z0-9_.\-]+$" minLength={3} maxLength={64}
                  onChange={(e) => setUsername(e.target.value)} />
              </div>
              <div className="field">
                <label className="field-label" htmlFor="cu-email">Email</label>
                <input id="cu-email" className="input" type="email" value={email} required
                  onChange={(e) => setEmail(e.target.value)} />
              </div>
              <div className="field">
                <label className="field-label" htmlFor="cu-name">Full name (optional)</label>
                <input id="cu-name" className="input" value={fullName}
                  onChange={(e) => setFullName(e.target.value)} />
              </div>
              <div className="field">
                <label className="field-label" htmlFor="cu-role">Role</label>
                <select id="cu-role" className="select" value={role} onChange={(e) => setRole(e.target.value)}>
                  <option value="viewer">Viewer</option>
                  <option value="analyst">Analyst</option>
                  <option value="admin">Admin</option>
                </select>
              </div>
              <div className="field">
                <label className="field-label" htmlFor="cu-qual">Qualifications (ISO 27037 / 27041)</label>
                <textarea id="cu-qual" className="input" value={qualifications}
                  onChange={(e) => setQualifications(e.target.value)} rows={2} maxLength={2048}
                  placeholder="e.g. GCFE, EnCE; 6 yrs DFIR; trained on FTK Imager + Volatility" />
                <div className="field-hint">Recorded on evidence this user collects/examines + on LE transfer packages.</div>
              </div>
              <PasswordField id="cu-pw" label="Password" value={password} onChange={setPassword}
                autoComplete="new-password" minLength={12} />
              <PasswordField id="cu-pw2" label="Confirm password" value={confirm} onChange={setConfirm}
                autoComplete="new-password" />
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
              {busy ? 'Creating…' : 'Create user'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ─── Detail modal (tabbed) ───────────────────────────────────────────────────

const DETAIL_TABS = ['profile', 'teams', 'sessions', 'activity']

function DetailModal({ user: initialUser, allTeams, onClose, onChanged }) {
  const [user,     setUser]     = useState(initialUser)
  const [tab,      setTab]      = useState('profile')
  const [sessions, setSessions] = useState(null)
  const [teams,    setTeams]    = useState(null)
  const [activity, setActivity] = useState(null)
  const [loadErr,  setLoadErr]  = useState(null)

  useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  useEffect(() => {
    setLoadErr(null)
    Promise.all([
      api.getUserSessions(user.id),
      api.getUserTeams(user.id),
      api.getUserActivity(user.id),
    ]).then(([s, t, a]) => {
      setSessions(s); setTeams(t); setActivity(a)
    }).catch(e => setLoadErr(e.message || 'Could not load user details'))
  }, [user.id])

  const refreshUser = async () => {
    const updated = await api.getUser(user.id)
    setUser(updated)
    onChanged(updated)
  }

  const refreshSessions = async () => {
    const s = await api.getUserSessions(user.id)
    setSessions(s)
  }

  const refreshTeams = async () => {
    const t = await api.getUserTeams(user.id)
    setTeams(t)
  }

  return (
    <div className="modal-backdrop">
      <div className="modal modal-lg" role="dialog" aria-labelledby="detail-user-title">
        <div className="modal-head">
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
            <Avatar user={user} />
            <div>
              <h2 id="detail-user-title" style={{ margin: 0 }}>{user.username}</h2>
              <div style={{ fontSize: 12, color: 'var(--muted)' }}>{user.email}</div>
            </div>
          </div>
          <button className="modal-close" type="button" onClick={onClose} aria-label="Close">×</button>
        </div>

        {loadErr && (
          <div className="alert error" style={{ margin: 'var(--space-3) var(--space-4) 0' }} role="alert">
            <span className="alert-icon">!</span><span>{loadErr}</span>
          </div>
        )}

        <div className="u-tab-bar">
          {DETAIL_TABS.map(t => (
            <button key={t} type="button"
              className={`u-tab ${tab === t ? 'active' : ''}`}
              onClick={() => setTab(t)}>
              {t.charAt(0).toUpperCase() + t.slice(1)}
              {t === 'sessions' && sessions !== null && (
                <span style={{ marginLeft: 4, fontSize: 10, color: 'var(--muted)' }}>
                  ({sessions.length})
                </span>
              )}
            </button>
          ))}
        </div>

        <div className="modal-body" style={{ paddingTop: 0 }}>
          {tab === 'profile' && (
            <ProfileTab user={user} onChanged={refreshUser} />
          )}
          {tab === 'teams' && (
            <TeamsTab user={user} teams={teams} allTeams={allTeams} onChanged={refreshTeams} />
          )}
          {tab === 'sessions' && (
            <SessionsTab user={user} sessions={sessions} onChanged={refreshSessions} />
          )}
          {tab === 'activity' && (
            <ActivityTab activity={activity} />
          )}
        </div>
      </div>
    </div>
  )
}

// ─── Profile tab ─────────────────────────────────────────────────────────────

function ProfileTab({ user, onChanged }) {
  const { user: me } = useAuth()
  const isSelf = me?.id === user.id

  const [fullName,  setFullName]  = useState(user.full_name || '')
  const [role,      setRole]      = useState(user.role)
  const [qualifications, setQualifications] = useState(user.qualifications || '')
  const [isActive,  setIsActive]  = useState(user.is_active)
  const [forcePw,   setForcePw]   = useState(user.force_password_change)
  const [forceTotp, setForceTotp] = useState(user.force_totp_enrol)
  const [saving,    setSaving]    = useState(false)
  const [saveErr,   setSaveErr]   = useState(null)
  const [saveOk,    setSaveOk]    = useState(false)

  const [newPw,     setNewPw]     = useState('')
  const [forceChg,  setForceChg]  = useState(true)
  const [pwBusy,    setPwBusy]    = useState(false)
  const [pwErr,     setPwErr]     = useState(null)
  const [pwOk,      setPwOk]      = useState(false)

  const [actBusy,   setActBusy]   = useState(false)
  const [actErr,    setActErr]    = useState(null)

  const saveProfile = async (e) => {
    e.preventDefault()
    setSaveErr(null); setSaveOk(false); setSaving(true)
    try {
      await api.updateUser(user.id, {
        full_name: fullName.trim() || null, role,
        qualifications: qualifications.trim() || null,
        is_active: isActive,
        force_password_change: forcePw,
        force_totp_enrol: forceTotp,
      })
      setSaveOk(true)
      await onChanged()
    } catch (err) {
      setSaveErr(err.message || 'Could not save profile')
    } finally {
      setSaving(false)
    }
  }

  const disableTotp = async () => {
    if (!window.confirm(`Disable TOTP for "${user.username}"?`)) return
    setActErr(null); setActBusy(true)
    try {
      await api.updateUser(user.id, { disable_totp: true })
      await onChanged()
    } catch (err) {
      setActErr(err.message || 'Could not disable TOTP')
    } finally {
      setActBusy(false)
    }
  }

  const unlockAccount = async () => {
    setActErr(null); setActBusy(true)
    try {
      await api.unlockUser(user.id)
      setActErr(null)
    } catch (err) {
      setActErr(err.message || 'Could not unlock account')
    } finally {
      setActBusy(false)
    }
  }

  const resetPw = async (e) => {
    e.preventDefault()
    if (newPw.length < 12) { setPwErr('Password must be at least 12 characters.'); return }
    setPwErr(null); setPwOk(false); setPwBusy(true)
    try {
      await api.resetPassword(user.id, { new_password: newPw, force_change_on_login: forceChg })
      setNewPw(''); setPwOk(true)
      if (forceChg) {
        setForcePw(true)
        await onChanged()
      }
    } catch (err) {
      setPwErr(err.message || 'Could not reset password')
    } finally {
      setPwBusy(false)
    }
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>

      {/* Editable profile */}
      <form onSubmit={saveProfile}>
        <div className="form">
          <div className="field">
            <label className="field-label" htmlFor="dp-name">Full name</label>
            <input id="dp-name" className="input" value={fullName}
              onChange={(e) => setFullName(e.target.value)} />
          </div>
          <div className="field">
            <label className="field-label" htmlFor="dp-role">Role</label>
            <select id="dp-role" className="select" value={role}
              onChange={(e) => setRole(e.target.value)}
              disabled={isSelf}>
              <option value="viewer">Viewer</option>
              <option value="analyst">Analyst</option>
              <option value="admin">Admin</option>
            </select>
            {isSelf && <div style={{ fontSize: 11, color: 'var(--muted)', marginTop: 4 }}>You cannot change your own role.</div>}
          </div>
          <div className="field">
            <label className="field-label" htmlFor="dp-qual">Qualifications (ISO 27037 / 27041)</label>
            <textarea id="dp-qual" className="input" value={qualifications}
              onChange={(e) => setQualifications(e.target.value)} rows={2} maxLength={2048}
              placeholder="e.g. GCFE, EnCE; 6 yrs DFIR; trained on FTK Imager + Volatility" />
            <div style={{ fontSize: 11, color: 'var(--muted)', marginTop: 4 }}>Stamped onto evidence this user collects/examines + LE transfer packages.</div>
          </div>
          <div style={{ display: 'flex', gap: 'var(--space-4)', flexWrap: 'wrap' }}>
            <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: isSelf ? 'not-allowed' : 'pointer', fontSize: 13 }}>
              <input type="checkbox" checked={isActive} disabled={isSelf}
                onChange={(e) => setIsActive(e.target.checked)} />
              Account active
              {isSelf && <span style={{ fontSize: 11, color: 'var(--muted)' }}>(cannot deactivate self)</span>}
            </label>
            <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer', fontSize: 13 }}>
              <input type="checkbox" checked={forcePw}
                onChange={(e) => setForcePw(e.target.checked)} />
              Force password change on next login
            </label>
            <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer', fontSize: 13 }}>
              <input type="checkbox" checked={forceTotp}
                onChange={(e) => setForceTotp(e.target.checked)} />
              Force TOTP enrollment on next login
            </label>
          </div>
          {saveErr && (
            <div className="alert error" role="alert">
              <span className="alert-icon">!</span><span>{saveErr}</span>
            </div>
          )}
          {saveOk && (
            <div className="alert info" role="status">
              <span className="alert-icon">✓</span><span>Profile saved.</span>
            </div>
          )}
          <div>
            <button type="submit" className="btn primary" disabled={saving}>
              {saving ? 'Saving…' : 'Save changes'}
            </button>
          </div>
        </div>
      </form>

      {/* Read-only info */}
      <div style={{ borderTop: '1px solid var(--border)', paddingTop: 'var(--space-3)' }}>
        <div style={{ fontSize: 11, fontFamily: 'var(--font-mono)', textTransform: 'uppercase',
          letterSpacing: '0.08em', color: 'var(--muted)', marginBottom: 'var(--space-2)' }}>
          Account info
        </div>
        <div className="u-info-grid">
          <span className="u-info-label">Username</span>
          <span className="u-info-value">{user.username}</span>
          <span className="u-info-label">Email</span>
          <span className="u-info-value">{user.email}</span>
          <span className="u-info-label">Auth provider</span>
          <span className="u-info-value">{user.auth_provider}</span>
          <span className="u-info-label">TOTP</span>
          <span className="u-info-value">{user.totp_enabled ? 'Enabled' : 'Disabled'}</span>
          <span className="u-info-label">Created</span>
          <span className="u-info-value" title={formatLocal(user.created_at)}>
            {formatLocalShort(user.created_at)}
          </span>
          <span className="u-info-label">Last login</span>
          <span className="u-info-value" title={formatLocal(user.last_login_at)}>
            {user.last_login_at ? formatLocalShort(user.last_login_at) : 'Never'}
          </span>
        </div>
      </div>

      {/* Actions */}
      <div style={{ borderTop: '1px solid var(--border)', paddingTop: 'var(--space-3)', display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
        <div style={{ fontSize: 11, fontFamily: 'var(--font-mono)', textTransform: 'uppercase',
          letterSpacing: '0.08em', color: 'var(--muted)' }}>
          Actions
        </div>
        {actErr && (
          <div className="alert error" role="alert">
            <span className="alert-icon">!</span><span>{actErr}</span>
          </div>
        )}
        <div style={{ display: 'flex', gap: 'var(--space-2)', flexWrap: 'wrap' }}>
          {user.totp_enabled && (
            <button type="button" className="btn ghost" onClick={disableTotp} disabled={actBusy}>
              Disable TOTP
            </button>
          )}
          <button type="button" className="btn ghost" onClick={unlockAccount} disabled={actBusy}
            title="Clears login and TOTP lockout counters">
            Unlock account
          </button>
        </div>
      </div>

      {/* Reset password */}
      <div style={{ borderTop: '1px solid var(--border)', paddingTop: 'var(--space-3)' }}>
        <div style={{ fontSize: 11, fontFamily: 'var(--font-mono)', textTransform: 'uppercase',
          letterSpacing: '0.08em', color: 'var(--muted)', marginBottom: 'var(--space-2)' }}>
          Reset password
        </div>
        <form onSubmit={resetPw}>
          <div className="form">
            <PasswordField id="rp-pw" label="New password" value={newPw} onChange={setNewPw}
              autoComplete="new-password" minLength={12} />
            <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer', fontSize: 13 }}>
              <input type="checkbox" checked={forceChg}
                onChange={(e) => setForceChg(e.target.checked)} />
              Force password change on next login
            </label>
            {pwErr && (
              <div className="alert error" role="alert">
                <span className="alert-icon">!</span><span>{pwErr}</span>
              </div>
            )}
            {pwOk && (
              <div className="alert info" role="status">
                <span className="alert-icon">✓</span><span>Password reset.</span>
              </div>
            )}
            <div>
              <button type="submit" className="btn primary" disabled={pwBusy || !newPw}>
                {pwBusy ? 'Resetting…' : 'Reset password'}
              </button>
            </div>
          </div>
        </form>
      </div>

    </div>
  )
}

// ─── Teams tab ────────────────────────────────────────────────────────────────

function TeamsTab({ user, teams, allTeams, onChanged }) {
  const [pick,   setPick]   = useState('')
  const [busy,   setBusy]   = useState(false)
  const [error,  setError]  = useState(null)

  if (teams === null) return <div style={{ color: 'var(--muted)', fontSize: 13 }}>Loading…</div>

  const memberIds  = new Set((teams || []).map(t => t.id))
  const available  = allTeams.filter(t => !memberIds.has(t.id))

  const addTeam = async () => {
    if (!pick) return
    setBusy(true); setError(null)
    try {
      await api.addTeamMember(pick, user.id)
      setPick(''); await onChanged()
    } catch (e) { setError(e.message || 'Could not add to team') }
    finally { setBusy(false) }
  }

  const removeTeam = async (team) => {
    if (!window.confirm(`Remove "${user.username}" from "${team.name}"?`)) return
    setBusy(true); setError(null)
    try {
      await api.removeTeamMember(team.id, user.id)
      await onChanged()
    } catch (e) { setError(e.message || 'Could not remove from team') }
    finally { setBusy(false) }
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
      {error && (
        <div className="alert error" role="alert">
          <span className="alert-icon">!</span><span>{error}</span>
        </div>
      )}
      <div style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'center' }}>
        <select className="select" value={pick} onChange={(e) => setPick(e.target.value)}
          disabled={available.length === 0 || busy} style={{ flex: 1, maxWidth: 320 }}>
          <option value="">
            {available.length === 0 ? 'Member of all teams' : 'Add to team…'}
          </option>
          {available.map(t => (
            <option key={t.id} value={t.id}>{t.name}</option>
          ))}
        </select>
        <button type="button" className="btn primary" onClick={addTeam}
          disabled={!pick || busy}>Add</button>
      </div>

      {teams.length === 0 ? (
        <div style={{ color: 'var(--muted)', fontSize: 13 }}>Not a member of any team.</div>
      ) : (
        <ul style={{ listStyle: 'none', margin: 0, padding: 0, display: 'flex', flexWrap: 'wrap', gap: 'var(--space-2)' }}>
          {teams.map(t => (
            <li key={t.id} style={{
              display: 'inline-flex', alignItems: 'center', gap: 8,
              padding: '4px 4px 4px 10px', background: 'var(--surface)',
              border: '1px solid var(--border)', borderRadius: 'var(--radius)', fontSize: 13,
            }}>
              <span aria-hidden="true" style={{
                display: 'inline-block', width: 10, height: 10, borderRadius: '50%', background: t.color,
              }} />
              <span>{t.name}</span>
              <button type="button" onClick={() => removeTeam(t)} disabled={busy}
                aria-label={`Remove from ${t.name}`}
                style={{ background: 'transparent', border: 'none', color: 'var(--muted)',
                  cursor: 'pointer', padding: '2px 8px', fontSize: 14 }}>×</button>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}

// ─── Sessions tab ─────────────────────────────────────────────────────────────

function SessionsTab({ user, sessions, onChanged }) {
  const [busy,  setBusy]  = useState(false)
  const [error, setError] = useState(null)

  if (sessions === null) return <div style={{ color: 'var(--muted)', fontSize: 13 }}>Loading…</div>

  const revokeOne = async (s) => {
    setBusy(true); setError(null)
    try {
      await api.revokeUserSession(user.id, s.id)
      await onChanged()
    } catch (e) { setError(e.message || 'Could not revoke session') }
    finally { setBusy(false) }
  }

  const revokeAll = async () => {
    if (!window.confirm(`Revoke all sessions for "${user.username}"? They will be signed out immediately.`)) return
    setBusy(true); setError(null)
    try {
      await api.revokeUserAllSessions(user.id)
      await onChanged()
    } catch (e) { setError(e.message || 'Could not revoke sessions') }
    finally { setBusy(false) }
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
      {error && (
        <div className="alert error" role="alert">
          <span className="alert-icon">!</span><span>{error}</span>
        </div>
      )}
      {sessions.length > 0 && (
        <div>
          <button type="button" className="btn ghost" onClick={revokeAll} disabled={busy}
            style={{ color: 'var(--crit)' }}>
            Revoke all sessions ({sessions.length})
          </button>
        </div>
      )}
      {sessions.length === 0 ? (
        <div style={{ color: 'var(--muted)', fontSize: 13 }}>No active sessions.</div>
      ) : (
        <table className="settings-table">
          <thead>
            <tr>
              <th>IP</th>
              <th>Location</th>
              <th>Last seen</th>
              <th>Created</th>
              <th className="actions">Actions</th>
            </tr>
          </thead>
          <tbody>
            {sessions.map(s => (
              <tr key={s.id}>
                <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>
                  {s.ip_address || '—'}
                </td>
                <td style={{ fontSize: 12, color: 'var(--muted)' }}>
                  {[s.city, s.country].filter(Boolean).join(', ') || '—'}
                </td>
                <td title={formatLocal(s.last_seen_at)} style={{ fontSize: 12 }}>
                  {relative(s.last_seen_at)}
                </td>
                <td title={formatLocal(s.created_at)} style={{ fontSize: 12, color: 'var(--muted)' }}>
                  {formatLocalShort(s.created_at)}
                </td>
                <td className="actions">
                  <button type="button" className="btn ghost" onClick={() => revokeOne(s)}
                    disabled={busy} style={{ color: 'var(--crit)' }}>Revoke</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}

// ─── Activity tab ─────────────────────────────────────────────────────────────

const OUTCOME_COLOR = { success: 'var(--ok)', failure: 'var(--crit)', denied: 'var(--high)' }

function ActivityTab({ activity }) {
  if (activity === null) return <div style={{ color: 'var(--muted)', fontSize: 13 }}>Loading…</div>
  if (activity.length === 0) return <div style={{ color: 'var(--muted)', fontSize: 13 }}>No activity recorded.</div>

  return (
    <table className="settings-table">
      <thead>
        <tr>
          <th>Timestamp</th>
          <th>Action</th>
          <th>Resource</th>
          <th>Outcome</th>
          <th>IP</th>
        </tr>
      </thead>
      <tbody>
        {activity.map(e => (
          <tr key={e.id}>
            <td title={formatLocal(e.timestamp)}
              style={{ fontSize: 11, fontFamily: 'var(--font-mono)', whiteSpace: 'nowrap', color: 'var(--muted)' }}>
              {formatLocalShort(e.timestamp)}
            </td>
            <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>{e.action}</td>
            <td style={{ fontSize: 11, color: 'var(--muted)' }}>
              {e.resource_label || e.resource_id
                ? `${e.resource_type}: ${e.resource_label || e.resource_id}`
                : e.resource_type || '—'}
            </td>
            <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11,
              color: OUTCOME_COLOR[e.outcome] || 'var(--muted)' }}>
              {e.outcome || '—'}
            </td>
            <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--muted)' }}>
              {e.ip_address || '—'}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}
