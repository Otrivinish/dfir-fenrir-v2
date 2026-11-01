import { useEffect, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import { api } from '../api/client.js'
import PasswordField from './PasswordField.jsx'

// SE: shown by SessionGuard when the session has ended (or, from the 8-hour banner, is about to). An
// opaque cover hides the incident content (D3), but the page underneath stays mounted, so unsaved
// edits survive. Signing in again is the normal login (password, then TOTP), as the same user only.
const REASON = {
  idle:  (m) => `You were signed out after ${m} minutes without activity.`,
  hard:  () => 'Sessions end 8 hours after sign-in.',
  ended: () => 'Your session was ended, either from another device or by an administrator.',
  renew: () => 'Your session is about to reach its 8-hour limit. Sign in again to start a new one.',
}

export default function SessionExpiredDialog({ user, reason, timeoutMinutes, onSignedIn, onCancel }) {
  const [step, setStep]         = useState('password')   // 'password' | 'totp'
  const [password, setPassword] = useState('')
  const [code, setCode]         = useState('')
  const [busy, setBusy]         = useState(false)
  const [error, setError]       = useState('')
  const [switching, setSwitching] = useState(false)      // "Sign in as someone else" asks first
  const rootRef = useRef(null)

  // Nothing else on the page may be reachable while the cover is up (keyboard, screen readers).
  useEffect(() => {
    const own = rootRef.current
    const others = [...document.body.children].filter(el => el !== own && !el.hasAttribute('inert'))
    others.forEach(el => el.setAttribute('inert', ''))
    return () => others.forEach(el => el.removeAttribute('inert'))
  }, [])

  const finish = async (r) => onSignedIn(r.user || await api.me())

  const onPassword = async (e) => {
    e.preventDefault()
    if (!password) return
    setBusy(true); setError('')
    try {
      const r = await api.login({ username: user.username, password })
      setPassword('')
      if (r.status === 'totp_required') { setStep('totp'); return }
      await finish(r)
    } catch (err) {
      setError(err.status === 429 ? 'Too many failed attempts. Wait 15 minutes and try again.' : (err.message || 'Sign-in failed.'))
    } finally {
      setBusy(false)
    }
  }

  const onCode = async (e) => {
    e.preventDefault()
    const c = code.replace(/\s+/g, '')
    if (c.length < 6) { setError('Enter the 6-digit code from your authenticator.'); return }
    setBusy(true); setError('')
    try {
      await finish(await api.totpVerify(c))
    } catch (err) {
      if (err.status === 429) setError('TOTP locked. Contact an admin.')
      else if (err.status === 400) { setError('The code step timed out. Enter your password again.'); setStep('password') }
      else setError(err.message || 'Invalid code.')
      setCode('')
    } finally {
      setBusy(false)
    }
  }

  // A full page load drops every unsaved edit, so the next user can't save them.
  const signInAsSomeoneElse = () => window.location.assign(`/login?next=${encodeURIComponent(window.location.pathname)}`)

  return createPortal(
    <div ref={rootRef} className="session-cover" role="dialog" aria-modal="true"
         aria-labelledby="se-title" aria-describedby="se-desc">
      <div className="auth-card session-card">
        <h1 id="se-title">{reason === 'renew' ? 'Sign in again' : 'Session ended'}</h1>
        <p id="se-desc" className="lead">
          {REASON[reason](timeoutMinutes)} Your unsaved changes are still on this page.
          Sign in as <strong>{user.username}</strong> to continue.
        </p>

        {step === 'password' ? (
          <form className="form" onSubmit={onPassword} noValidate>
            <div className="field">
              <label className="field-label" htmlFor="se-username">Username</label>
              <input id="se-username" className="input" value={user.username} readOnly autoComplete="username" />
            </div>
            <PasswordField id="se-password" label="Password" value={password} onChange={setPassword}
                           autoComplete="current-password" autoFocus />
            {error && <div className="alert error" role="alert"><span className="alert-icon">!</span><span>{error}</span></div>}
            <button className="btn primary block" type="submit" disabled={busy || !password}>
              {busy ? 'Signing in…' : 'Sign in'}
            </button>
          </form>
        ) : (
          <form className="form" onSubmit={onCode} noValidate>
            <div className="field">
              <label className="field-label" htmlFor="se-code">Authenticator code</label>
              <input id="se-code" className="input" value={code} onChange={(e) => setCode(e.target.value)}
                     inputMode="numeric" autoComplete="one-time-code" maxLength={8} autoFocus spellCheck={false} />
            </div>
            {error && <div className="alert error" role="alert"><span className="alert-icon">!</span><span>{error}</span></div>}
            <button className="btn primary block" type="submit" disabled={busy}>
              {busy ? 'Verifying…' : 'Verify'}
            </button>
          </form>
        )}

        <div className="session-card-foot">
          {onCancel && <button type="button" className="btn ghost" onClick={onCancel}>Not now</button>}
          {!onCancel && !switching && (
            <button type="button" className="btn ghost" onClick={() => setSwitching(true)}>Sign in as someone else</button>
          )}
          {switching && (
            <div className="alert warn" role="alert">
              <span className="alert-icon">!</span>
              <span>
                Unsaved changes on this page will be lost.{' '}
                <button type="button" className="btn ghost" onClick={signInAsSomeoneElse}>Continue</button>{' '}
                <button type="button" className="btn ghost" onClick={() => setSwitching(false)}>Back</button>
              </span>
            </div>
          )}
        </div>
      </div>
    </div>,
    document.body,
  )
}
