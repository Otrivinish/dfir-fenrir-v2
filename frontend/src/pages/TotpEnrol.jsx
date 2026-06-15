import { useEffect, useState } from 'react'
import { useNavigate, Navigate } from 'react-router-dom'
import { api } from '../api/client.js'
import { useAuth } from '../hooks/useAuth.jsx'
import Brand from '../components/Brand.jsx'
import ThemePicker from '../components/ThemePicker.jsx'
import TimezonePicker from '../components/TimezonePicker.jsx'

export default function TotpEnrol() {
  const { user, status, refresh, setSignedIn, signOut } = useAuth()
  const navigate = useNavigate()
  const [setup, setSetup] = useState(null) // {secret, provisioning_uri, qr_code_data_url}
  const [code, setCode]   = useState('')
  const [busy, setBusy]   = useState(false)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)

  // Must be signed in to enrol.
  // (After /setup the cookie is set; if user lands here without a session, bounce to login.)
  useEffect(() => {
    let cancelled = false
    ;(async () => {
      if (status !== 'user') return
      try {
        const s = await api.totpSetup()
        if (!cancelled) setSetup(s)
      } catch (err) {
        if (!cancelled) {
          // 400 with "TOTP already enabled" → enrol is somehow already done
          if (err.status === 400 && /already enabled/i.test(err.message || '')) {
            const u = await refresh()
            setSignedIn(u)
            navigate('/', { replace: true })
            return
          }
          setError(err.message || 'Could not begin TOTP setup.')
        }
      } finally {
        if (!cancelled) setLoading(false)
      }
    })()
    return () => { cancelled = true }
  }, [status, refresh, setSignedIn, navigate])

  if (status === 'loading') return null
  if (status === 'guest') return <Navigate to="/login" replace />
  // If TOTP is already enabled AND not force-enrol, no need to be here.
  if (user && user.totp_enabled && !user.force_totp_enrol) return <Navigate to="/" replace />

  const onEnable = async (e) => {
    e.preventDefault()
    const c = code.replace(/\s+/g, '')
    if (c.length < 6) { setError('Enter the 6-digit code from your authenticator.'); return }
    setBusy(true); setError('')
    try {
      await api.totpEnable(c)
      const u = await refresh()
      setSignedIn(u)
      navigate('/', { replace: true })
    } catch (err) {
      setError(err.message || 'Invalid code.')
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
      <div className="auth-shell wide">
        <Brand tag="TWO-FACTOR ENROLMENT" />

        <div className="auth-card">
          <div className="steps">
            <span className="step done">1. Admin</span>
            <span className="step-sep">›</span>
            <span className="step active">2. 2FA</span>
            <span className="step-sep">›</span>
            <span className="step">3. Done</span>
          </div>

          <h1>Enrol an authenticator</h1>
          <p className="lead">
            Two-factor authentication is mandatory. Scan the QR code with your authenticator
            app (Aegis, 1Password, Authy, Google Authenticator) or paste the secret manually,
            then enter a code to confirm.
          </p>

          {loading && <div className="alert info"><span className="alert-icon">…</span><span>Generating secret…</span></div>}

          {setup && (
            <div className="totp-grid">
              <div className="totp-qr">
                <img src={setup.qr_code_data_url} alt="TOTP provisioning QR code" />
              </div>
              <div>
                <div className="field" style={{ marginBottom: 'var(--space-3)' }}>
                  <div className="field-label">Manual entry secret</div>
                  <div className="totp-secret" aria-label="TOTP secret for manual entry">{setup.secret}</div>
                  <div className="field-hint">Issuer: DFIR-FENRIR · Algorithm: SHA-1 · Digits: 6 · Period: 30s</div>
                </div>

                <form className="form" onSubmit={onEnable} noValidate>
                  <div className="field">
                    <label className="field-label" htmlFor="te-code">Verification code</label>
                    <input
                      id="te-code"
                      className="input code"
                      value={code}
                      onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 8))}
                      inputMode="numeric"
                      pattern="[0-9]*"
                      autoComplete="one-time-code"
                      autoFocus
                      placeholder="••••••"
                      maxLength={8}
                    />
                  </div>

                  {error && (
                    <div className="alert error" role="alert">
                      <span className="alert-icon">!</span>
                      <span>{error}</span>
                    </div>
                  )}

                  <button className="btn primary block" type="submit" disabled={busy || code.length < 6}>
                    {busy ? 'Enabling…' : 'Enable two-factor'}
                  </button>
                </form>
              </div>
            </div>
          )}

          <div style={{ marginTop: 'var(--space-4)', display: 'flex', justifyContent: 'space-between', gap: 'var(--space-2)' }}>
            <button className="btn ghost" type="button" onClick={signOut}>Sign out</button>
            {user && !user.force_totp_enrol && (
              <button
                className="btn ghost"
                type="button"
                onClick={() => navigate('/', { replace: true })}
              >Skip for now</button>
            )}
          </div>
        </div>

        <div className="auth-foot">TLP:RED · OPERATOR USE ONLY</div>
      </div>
    </main>
  )
}
