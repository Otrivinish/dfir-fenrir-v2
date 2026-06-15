import { useState } from 'react'
import { useNavigate, Navigate } from 'react-router-dom'
import { api } from '../api/client.js'
import { useAuth } from '../hooks/useAuth.jsx'
import Brand from '../components/Brand.jsx'
import PasswordField from '../components/PasswordField.jsx'
import StrengthMeter from '../components/StrengthMeter.jsx'
import ThemePicker from '../components/ThemePicker.jsx'
import TimezonePicker from '../components/TimezonePicker.jsx'

const USERNAME_RE = /^[a-zA-Z0-9_.-]+$/

export default function Setup() {
  const { needsSetup, status, policy, setSignedIn } = useAuth()
  const navigate = useNavigate()
  const [form, setForm] = useState({
    token: '', username: '', email: '', full_name: '', password: '', confirm: '',
  })
  const [showToken, setShowToken] = useState(false)
  const [busy, setBusy]   = useState(false)
  const [error, setError] = useState('')

  // Already initialised → can't run setup again.
  if (status !== 'loading' && !needsSetup) return <Navigate to="/login" replace />

  const update = (k) => (e) => setForm(f => ({ ...f, [k]: e.target.value }))
  const updateValue = (k) => (v) => setForm(f => ({ ...f, [k]: v }))

  const onSubmit = async (e) => {
    e.preventDefault()
    setError('')
    if (form.token.trim().length < 10)            return setError('Bootstrap token is too short.')
    if (!USERNAME_RE.test(form.username))         return setError('Username may contain letters, digits, dot, dash, underscore.')
    if (form.username.length < 3)                 return setError('Username must be at least 3 characters.')
    if (form.password.length < 12)                return setError('Password must be at least 12 characters.')
    if (form.password !== form.confirm)           return setError('Passwords do not match.')

    setBusy(true)
    try {
      const user = await api.setup({
        token: form.token.trim(),
        username: form.username.trim(),
        email: form.email.trim(),
        full_name: form.full_name.trim() || null,
        password: form.password,
      })
      // Setup endpoint sets the session cookie + returns the user.
      // Backend sets force_totp_enrol based on TOTP_REQUIRED org policy.
      setSignedIn(user)
      navigate(user.force_totp_enrol ? '/totp/enrol' : '/', { replace: true })
    } catch (err) {
      setError(err.message || 'Setup failed.')
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
      <div className="auth-shell wide">
        <Brand tag="FIRST-RUN SETUP" />

        <div className="auth-card">
          {policy.totp_required && (
            <div className="steps" aria-label="Setup progress">
              <span className="step active">1. Admin</span>
              <span className="step-sep">›</span>
              <span className="step">2. 2FA</span>
              <span className="step-sep">›</span>
              <span className="step">3. Done</span>
            </div>
          )}

          <h1>Create the initial administrator</h1>
          <p className="lead">
            This account has full admin rights. The bootstrap token is printed in the backend
            container logs and saved at <code>/app/data/bootstrap_token.txt</code> inside the
            container. It is single-use.
          </p>

          <form className="form" onSubmit={onSubmit} noValidate>
            <div className="field">
              <label className="field-label" htmlFor="su-token">Bootstrap token</label>
              <div className="input-wrap">
                <input
                  id="su-token"
                  className="input"
                  type={showToken ? 'text' : 'password'}
                  value={form.token}
                  onChange={update('token')}
                  placeholder="From backend container logs"
                  autoComplete="off"
                  spellCheck={false}
                  required
                  autoFocus
                />
                <button
                  type="button"
                  className="input-toggle"
                  aria-label={showToken ? 'Hide token' : 'Show token'}
                  aria-pressed={showToken}
                  onClick={() => setShowToken(s => !s)}
                >{showToken ? 'HIDE' : 'SHOW'}</button>
              </div>
            </div>

            <div className="form-row">
              <div className="field">
                <label className="field-label" htmlFor="su-username">Username</label>
                <input
                  id="su-username"
                  className="input"
                  value={form.username}
                  onChange={update('username')}
                  placeholder="admin"
                  autoComplete="username"
                  pattern="[A-Za-z0-9_.\-]{3,64}"
                  minLength={3}
                  maxLength={64}
                  required
                  spellCheck={false}
                />
              </div>
              <div className="field">
                <label className="field-label" htmlFor="su-fullname">Full name</label>
                <input
                  id="su-fullname"
                  className="input"
                  value={form.full_name}
                  onChange={update('full_name')}
                  placeholder="Optional"
                  autoComplete="name"
                  maxLength={255}
                />
              </div>
            </div>

            <div className="field">
              <label className="field-label" htmlFor="su-email">Email</label>
              <input
                id="su-email"
                className="input"
                type="email"
                value={form.email}
                onChange={update('email')}
                placeholder="admin@org.local"
                autoComplete="email"
                required
                spellCheck={false}
              />
            </div>

            <div className="form-row">
              <PasswordField
                id="su-pw"
                label="Password"
                value={form.password}
                onChange={updateValue('password')}
                autoComplete="new-password"
                minLength={12}
                placeholder="Min 12 characters"
              />
              <PasswordField
                id="su-pw-confirm"
                label="Confirm"
                value={form.confirm}
                onChange={updateValue('confirm')}
                autoComplete="new-password"
                minLength={12}
                placeholder="Re-enter"
              />
            </div>

            <StrengthMeter password={form.password} />

            {error && (
              <div className="alert error" role="alert">
                <span className="alert-icon">!</span>
                <span>{error}</span>
              </div>
            )}

            <div className="alert info" role="status">
              <span className="alert-icon">i</span>
              <span>
                {policy.totp_required
                  ? 'After creating the admin you will be required to enrol a TOTP authenticator before reaching the application.'
                  : 'TOTP enrolment is optional in this deployment. You can enable two-factor authentication from Settings after signing in (strongly recommended).'}
              </span>
            </div>

            <button className="btn primary block" type="submit" disabled={busy}>
              {busy ? 'Creating…' : 'Create administrator'}
            </button>
          </form>
        </div>

        <div className="auth-foot">TLP:RED · OPERATOR USE ONLY</div>
      </div>
    </main>
  )
}
