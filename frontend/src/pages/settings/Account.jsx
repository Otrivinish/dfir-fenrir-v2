import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { useAuth } from '../../hooks/useAuth.jsx'
import { api } from '../../api/client.js'
import PasswordField from '../../components/PasswordField.jsx'
import StrengthMeter from '../../components/StrengthMeter.jsx'
import ApiTokenTable from '../../components/ApiTokenTable.jsx'
import { formatLocal } from '../../lib/datetime.js'
import { getStoredTz, setStoredTz, getBrowserTz, TIMEZONE_GROUPS } from '../../lib/timezone.js'

export default function Account() {
  const { user, refresh, policy } = useAuth()

  return (
    <div className="settings-stack">
      <ProfilePanel user={user} />
      <TimezonePanel />
      <ChangePasswordPanel />
      <TotpPanel user={user} policy={policy} onChanged={refresh} />
      <ApiTokensPanel user={user} />
    </div>
  )
}

function TimezonePanel() {
  const [tz, setTz]     = useState(getStoredTz)
  const [saved, setSaved] = useState(false)

  const allZoneIds = TIMEZONE_GROUPS.flatMap(g => g.zones.map(z => z.id))
  const tzInList   = allZoneIds.includes(tz)

  const handleSave = () => {
    setStoredTz(tz)
    setSaved(true)
    setTimeout(() => window.location.reload(), 800)
  }

  return (
    <section className="panel">
      <h2 className="panel-h">Display timezone</h2>
      <div className="settings-form">
        <div className="field">
          <label className="field-label" htmlFor="tz-select">Timezone</label>
          <select
            id="tz-select"
            className="input"
            value={tz}
            onChange={(e) => { setTz(e.target.value); setSaved(false) }}
          >
            {!tzInList && <option value={tz}>{tz}</option>}
            {TIMEZONE_GROUPS.map(({ group, zones }) => (
              <optgroup key={group} label={group}>
                {zones.map(z => (
                  <option key={z.id} value={z.id}>{z.label}</option>
                ))}
              </optgroup>
            ))}
          </select>
        </div>
        {saved && (
          <div className="alert info" role="status">
            <span className="alert-icon">✓</span>
            <span>Timezone saved — reloading…</span>
          </div>
        )}
        <div className="settings-form-actions">
          <button type="button" className="btn ghost" onClick={() => { setTz(getBrowserTz()); setSaved(false) }}>
            Detect from browser
          </button>
          <button type="button" className="btn primary" onClick={handleSave}>
            Save timezone
          </button>
        </div>
      </div>
    </section>
  )
}

function ProfilePanel({ user }) {
  return (
    <section className="panel">
      <h2 className="panel-h">Profile</h2>
      <dl className="kv">
        <dt>Username</dt>
        <dd>{user?.username || '—'}</dd>
        <dt>Email</dt>
        <dd>{user?.email || '—'}</dd>
        <dt>Full name</dt>
        <dd>{user?.full_name || '—'}</dd>
        <dt>Role</dt>
        <dd>{user?.role || '—'}</dd>
        <dt>Two-factor</dt>
        <dd>{user?.totp_enabled ? 'Enabled' : 'Disabled'}</dd>
        <dt>Provider</dt>
        <dd>{user?.auth_provider || '—'}</dd>
        <dt>Member since</dt>
        <dd>{user?.created_at ? formatLocal(user.created_at) : '—'}</dd>
        <dt>Last login</dt>
        <dd>{user?.last_login_at ? formatLocal(user.last_login_at) : '—'}</dd>
      </dl>
    </section>
  )
}

function ChangePasswordPanel() {
  const [current, setCurrent] = useState('')
  const [next, setNext]       = useState('')
  const [confirm, setConfirm] = useState('')
  const [busy, setBusy]       = useState(false)
  const [error, setError]     = useState(null)
  const [ok, setOk]           = useState(false)

  const mismatch = confirm.length > 0 && confirm !== next
  const tooShort = next.length > 0 && next.length < 12
  const canSubmit = current.length > 0 && next.length >= 12 && !mismatch && !busy

  const onSubmit = async (e) => {
    e.preventDefault()
    setError(null); setOk(false)
    if (!canSubmit) return
    setBusy(true)
    try {
      await api.changePassword({ current_password: current, new_password: next })
      setOk(true)
      setCurrent(''); setNext(''); setConfirm('')
    } catch (err) {
      setError(err.message || 'Could not change password')
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="panel">
      <h2 className="panel-h">Change password</h2>
      <form onSubmit={onSubmit} className="settings-form">
        <PasswordField
          id="cp-current"
          label="Current password"
          value={current}
          onChange={setCurrent}
          autoComplete="current-password"
        />
        <PasswordField
          id="cp-new"
          label="New password (min 12 characters)"
          value={next}
          onChange={setNext}
          autoComplete="new-password"
          minLength={12}
        />
        {next.length > 0 && <StrengthMeter password={next} />}
        <PasswordField
          id="cp-confirm"
          label="Confirm new password"
          value={confirm}
          onChange={setConfirm}
          autoComplete="new-password"
          minLength={12}
        />
        {mismatch && (
          <div className="alert error" role="alert">
            <span className="alert-icon">!</span>
            <span>Passwords do not match.</span>
          </div>
        )}
        {tooShort && !mismatch && (
          <div className="field-hint">Password must be at least 12 characters.</div>
        )}
        {error && (
          <div className="alert error" role="alert">
            <span className="alert-icon">!</span>
            <span>{error}</span>
          </div>
        )}
        {ok && (
          <div className="alert info" role="status">
            <span className="alert-icon">✓</span>
            <span>Password changed.</span>
          </div>
        )}
        <div className="settings-form-actions">
          <button type="submit" className="btn primary" disabled={!canSubmit}>
            {busy ? 'Saving…' : 'Change password'}
          </button>
        </div>
      </form>
    </section>
  )
}

function TotpPanel({ user, policy, onChanged }) {
  const enabled = !!user?.totp_enabled
  const required = !!policy?.totp_required

  const [showForm, setShowForm] = useState(false)
  const [password, setPassword] = useState('')
  const [code, setCode]         = useState('')
  const [busy, setBusy]         = useState(false)
  const [error, setError]       = useState(null)

  const disable = async (e) => {
    e.preventDefault()
    setError(null)
    if (!password) { setError('Password is required.'); return }
    setBusy(true)
    try {
      await api.totpDisable({ password, code: code || undefined })
      await onChanged?.()
      setShowForm(false); setPassword(''); setCode('')
    } catch (err) {
      setError(err.message || 'Could not disable two-factor')
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="panel">
      <h2 className="panel-h">Two-factor authentication</h2>

      <dl className="kv">
        <dt>Status</dt>
        <dd>{enabled ? 'Enabled' : 'Disabled'}</dd>
        <dt>Org policy</dt>
        <dd>{required ? 'Required for all accounts' : 'Optional'}</dd>
      </dl>

      <div className="settings-form-actions" style={{ marginTop: 'var(--space-3)' }}>
        {!enabled && (
          <Link to="/totp/enrol" className="btn primary">Enable two-factor</Link>
        )}
        {enabled && !required && !showForm && (
          <button type="button" className="btn ghost" onClick={() => setShowForm(true)}>
            Disable two-factor
          </button>
        )}
        {enabled && required && (
          <div className="field-hint">
            Two-factor is required by org policy and cannot be disabled here.
          </div>
        )}
      </div>

      {enabled && !required && showForm && (
        <form onSubmit={disable} className="settings-form" style={{ marginTop: 'var(--space-3)' }}>
          <PasswordField
            id="totp-disable-password"
            label="Current password"
            value={password}
            onChange={setPassword}
            autoComplete="current-password"
          />
          <div className="field">
            <label className="field-label" htmlFor="totp-disable-code">
              Current authenticator code (optional, recommended)
            </label>
            <input
              id="totp-disable-code"
              className="input code"
              value={code}
              onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 8))}
              placeholder="123456"
              inputMode="numeric"
              autoComplete="one-time-code"
            />
          </div>
          {error && (
            <div className="alert error" role="alert">
              <span className="alert-icon">!</span>
              <span>{error}</span>
            </div>
          )}
          <div className="settings-form-actions">
            <button type="button" className="btn ghost" onClick={() => { setShowForm(false); setError(null) }}>
              Cancel
            </button>
            <button type="submit" className="btn primary" disabled={busy}>
              {busy ? 'Disabling…' : 'Confirm disable'}
            </button>
          </div>
        </form>
      )}
    </section>
  )
}

// R144: the caller's own Bearer tokens. The server caps the role at yours and the expiry at 90 days.
const TOKEN_ROLES = ['viewer', 'analyst', 'admin']
const TOKEN_DAYS = [1, 7, 30, 90]

function ApiTokensPanel({ user }) {
  const [tokens, setTokens]   = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError]     = useState(null)
  const [busy, setBusy]       = useState(false)
  const [showForm, setShowForm] = useState(false)
  const [name, setName]       = useState('')
  const [role, setRole]       = useState('viewer')
  const [days, setDays]       = useState('30')
  const [issued, setIssued]   = useState(null)
  const [copied, setCopied]   = useState(false)

  const roles = TOKEN_ROLES.slice(0, TOKEN_ROLES.indexOf(user?.role) + 1)

  const load = useCallback(async () => {
    try {
      const r = await api.listApiTokens()
      setTokens(r.items || [])
    } catch (e) {
      setError(e.message || 'Could not load API tokens')
    } finally {
      setLoading(false)
    }
  }, [])
  useEffect(() => { load() }, [load])

  const onCreate = async (e) => {
    e.preventDefault()
    setError(null); setBusy(true)
    try {
      const r = await api.createApiToken({ name: name.trim(), role, expires_in_days: Number(days) })
      setIssued(r); setCopied(false)
      setShowForm(false); setName('')
      await load()
    } catch (err) {
      setError(err.message || 'Could not create the token')
    } finally {
      setBusy(false)
    }
  }

  const onRevoke = async (t) => {
    setError(null); setBusy(true)
    try {
      await api.revokeApiToken(t.id)
      await load()
    } catch (err) {
      setError(err.message || 'Could not revoke the token')
    } finally {
      setBusy(false)
    }
  }

  const copy = async () => {
    try { await navigator.clipboard.writeText(issued.token); setCopied(true) } catch { /* select it by hand */ }
  }

  return (
    <section className="panel">
      <div className="panel-toolbar">
        <div>
          <h2 className="panel-h">API tokens</h2>
          <div className="token-sub">Bearer tokens for scripts and the MCP server. They act as you, at the role you pick.</div>
        </div>
        <div className="token-controls">
          <button type="button" className="btn primary" disabled={busy || showForm} onClick={() => setShowForm(true)}>+ New token</button>
        </div>
      </div>

      {error && (
        <div className="alert error" role="alert">
          <span className="alert-icon">!</span>
          <span>{error}</span>
        </div>
      )}

      {issued && (
        <div className="token-issued">
          <div className="alert warn" role="status">
            <span className="alert-icon">!</span>
            <span>Copy this token now. FENRIR keeps only its hash and will never show it again.</span>
          </div>
          <code className="token-secret" aria-label={`Secret of token ${issued.name}`}>{issued.token}</code>
          <div className="settings-form-actions">
            <button type="button" className="btn primary" onClick={copy}>{copied ? 'Copied ✓' : 'Copy token'}</button>
            <button type="button" className="btn ghost" onClick={() => setIssued(null)}>Done</button>
          </div>
        </div>
      )}

      {showForm && (
        <form onSubmit={onCreate} className="settings-form token-form">
          <div className="field">
            <label className="field-label" htmlFor="tok-name">Name</label>
            <input id="tok-name" className="input" value={name} maxLength={128} required
                   placeholder="e.g. nightly-export script" onChange={(e) => setName(e.target.value)} />
          </div>
          <div className="field">
            <label className="field-label" htmlFor="tok-role">Role</label>
            <select id="tok-role" className="input" value={role} onChange={(e) => setRole(e.target.value)}>
              {roles.map(r => <option key={r} value={r}>{r}</option>)}
            </select>
            <div className="field-hint">Pick the lowest role the script needs. It can never exceed yours.</div>
          </div>
          <div className="field">
            <label className="field-label" htmlFor="tok-days">Expires after</label>
            <select id="tok-days" className="input" value={days} onChange={(e) => setDays(e.target.value)}>
              {TOKEN_DAYS.map(d => <option key={d} value={d}>{d} day{d > 1 ? 's' : ''}</option>)}
            </select>
          </div>
          <div className="settings-form-actions">
            <button type="button" className="btn ghost" disabled={busy} onClick={() => setShowForm(false)}>Cancel</button>
            <button type="submit" className="btn primary" disabled={busy || !name.trim()}>{busy ? 'Creating…' : 'Create token'}</button>
          </div>
        </form>
      )}

      {loading ? (
        <div className="panel-empty"><div>Loading…</div></div>
      ) : tokens.length === 0 ? (
        <div className="panel-empty"><div>No API tokens yet.</div></div>
      ) : (
        <ApiTokenTable tokens={tokens} onRevoke={onRevoke} busy={busy} />
      )}
    </section>
  )
}
