import { useState } from 'react'
import { useNavigate, useLocation } from 'react-router-dom'
import { api } from '../api/client.js'
import { useAuth } from '../hooks/useAuth.jsx'
import Brand from '../components/Brand.jsx'
import ThemePicker from '../components/ThemePicker.jsx'
import TimezonePicker from '../components/TimezonePicker.jsx'

export default function TotpVerify() {
  const { setSignedIn, refresh } = useAuth()
  const navigate = useNavigate()
  const loc = useLocation()
  const next = new URLSearchParams(loc.search).get('next') || '/'

  const [code, setCode] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  const onSubmit = async (e) => {
    e.preventDefault()
    setError('')
    const c = code.replace(/\s+/g, '')
    if (c.length < 6) { setError('Enter the 6-digit code from your authenticator.'); return }
    setBusy(true)
    try {
      const r = await api.totpVerify(c)
      const u = r.user || (await refresh())
      setSignedIn(u || r.user)
      navigate(u?.force_totp_enrol ? '/totp/enrol' : next, { replace: true })
    } catch (err) {
      if (err.status === 429) setError('TOTP locked. Contact an admin.')
      else if (err.status === 400) {
        setError('TOTP challenge expired. Please sign in again.')
        setTimeout(() => navigate('/login', { replace: true }), 1200)
      } else {
        setError(err.message || 'Invalid code.')
      }
      setCode('')
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
        <Brand tag="TWO-FACTOR" />

        <div className="auth-card">
          <h1>Enter authenticator code</h1>
          <p className="lead">Six-digit code from your TOTP app (Aegis, 1Password, Authy, …).</p>

          <form className="form" onSubmit={onSubmit} noValidate>
            <div className="field">
              <label className="field-label" htmlFor="tv-code">Code</label>
              <input
                id="tv-code"
                className="input code"
                value={code}
                onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 8))}
                inputMode="numeric"
                pattern="[0-9]*"
                autoComplete="one-time-code"
                autoFocus
                required
                placeholder="••••••"
                maxLength={8}
                aria-describedby="tv-code-hint"
              />
              <div id="tv-code-hint" className="field-hint">6 digits. The code rotates every 30 seconds.</div>
            </div>

            {error && (
              <div className="alert error" role="alert">
                <span className="alert-icon">!</span>
                <span>{error}</span>
              </div>
            )}

            <button className="btn primary block" type="submit" disabled={busy || code.length < 6}>
              {busy ? 'Verifying…' : 'Verify'}
            </button>
          </form>
        </div>

        <div className="auth-foot">TLP:RED · OPERATOR USE ONLY</div>
      </div>
    </main>
  )
}
