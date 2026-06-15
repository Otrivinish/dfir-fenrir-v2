import { useState } from 'react'
import { useNavigate, useLocation, Navigate } from 'react-router-dom'
import { api } from '../api/client.js'
import { useAuth } from '../hooks/useAuth.jsx'
import Brand from '../components/Brand.jsx'
import PasswordField from '../components/PasswordField.jsx'
import ThemePicker from '../components/ThemePicker.jsx'
import TimezonePicker from '../components/TimezonePicker.jsx'

export default function Login() {
  const { status, user, setSignedIn, refresh, needsSetup } = useAuth()
  const navigate = useNavigate()
  const loc = useLocation()
  // Only allow internal, same-origin redirects. Reject absolute ('https://evil')
  // and protocol-relative ('//evil') targets to prevent post-login open-redirect.
  const rawNext = new URLSearchParams(loc.search).get('next') || '/'
  const next = (rawNext.startsWith('/') && !rawNext.startsWith('//')) ? rawNext : '/'

  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [busy, setBusy]   = useState(false)
  const [error, setError] = useState('')
  const [locked, setLocked] = useState(false)

  if (needsSetup) return <Navigate to="/setup" replace />
  if (status === 'user' && user) {
    if (user.force_totp_enrol) return <Navigate to="/totp/enrol" replace />
    return <Navigate to={next} replace />
  }

  const onSubmit = async (e) => {
    e.preventDefault()
    if (!username.trim() || !password) return
    setBusy(true); setError(''); setLocked(false)
    try {
      const r = await api.login({ username: username.trim(), password })
      if (r.status === 'totp_required') {
        // Pending-totp cookie was set by the API. Move to step 2.
        navigate(`/login/totp${loc.search}`, { replace: true })
        return
      }
      // status === 'ok' — session cookie set. Refresh to pull authoritative user.
      const u = r.user || (await refresh())
      setSignedIn(u || r.user)
      if (u?.force_totp_enrol) {
        navigate('/totp/enrol', { replace: true })
      } else {
        navigate(next, { replace: true })
      }
    } catch (err) {
      if (err.status === 429) {
        setLocked(true)
        setError('Too many failed attempts. Wait 15 minutes and try again.')
      } else {
        setError(err.message || 'Login failed.')
      }
    } finally {
      setBusy(false)
    }
  }

  return (
    <main className="auth-page">
      <div className="corner-controls">
        <TimezonePicker variant="inline" />
        <ThemePicker variant="inline" />
      </div>
      <div className="auth-shell">
        <Brand />

        <div className="auth-card">
          <h1>Sign in</h1>
          <p className="lead">Authenticate with your operator credentials.</p>

          <form className="form" onSubmit={onSubmit} noValidate>
            <div className="field">
              <label className="field-label" htmlFor="lg-username">Username</label>
              <input
                id="lg-username"
                className="input"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                autoComplete="username"
                autoFocus
                required
                spellCheck={false}
                placeholder="analyst"
              />
            </div>

            <PasswordField
              id="lg-password"
              label="Password"
              value={password}
              onChange={setPassword}
              autoComplete="current-password"
              placeholder="••••••••"
            />

            {error && (
              <div className={`alert ${locked ? 'warn' : 'error'}`} role="alert">
                <span className="alert-icon">!</span>
                <span>{error}</span>
              </div>
            )}

            <button className="btn primary block" type="submit" disabled={busy || locked}>
              {busy ? 'Authenticating…' : 'Authenticate'}
            </button>
          </form>
        </div>

        <div className="auth-foot">TLP:RED · OPERATOR USE ONLY</div>
      </div>
    </main>
  )
}
