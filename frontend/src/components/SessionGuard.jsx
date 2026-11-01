import { useCallback, useEffect, useRef, useState } from 'react'
import { api } from '../api/client.js'
import { useAuth } from '../hooks/useAuth.jsx'
import { formatLocal } from '../lib/datetime.js'
import SessionExpiredDialog from './SessionExpiredDialog.jsx'

// SE (docs/session-expiry-unsaved-work-slice.md). A session ends after the idle timeout (server
// setting, 30 min by default) or 8 h after sign-in, whichever comes first. Typing never reaches the
// server, so this reports real input with a heartbeat, warns 2 min before either end (D2), and on
// expiry covers the page with a sign-in dialog instead of leaving it: the page, and any unsaved edit
// in it, stays mounted.
const BEAT_EVERY_MS = 5 * 60_000   // at most one heartbeat per 5 min, and only after real input
const RETRY_MS      = 30_000       // after a failed (network) heartbeat, before the next try
const WARN_MS       = 2 * 60_000   // both warnings
const GRACE_MS      = 2_000        // past a deadline before checking it: the server ends it at "> timeout"
const INPUT_EVENTS  = ['keydown', 'pointerdown', 'wheel', 'touchstart']   // not mousemove, not timers

// Server answer → deadlines on this machine's clock (counted from server_time, so a wrong clock
// doesn't matter). `key` names the deadlines independently of network latency.
function toLocal(s) {
  const skew = Date.now() - Date.parse(s.server_time)
  return { idleAt: Date.parse(s.idle_expires_at) + skew, hardAt: Date.parse(s.expires_at) + skew,
           hardIso: s.expires_at, timeoutMs: s.idle_timeout_seconds * 1000, key: `${s.idle_expires_at}|${s.expires_at}` }
}

const mmss = (ms) => {
  const s = Math.max(0, Math.ceil(ms / 1000))
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`
}

export default function SessionGuard() {
  const { status, user, expire, resume, sessionEpoch } = useAuth()
  const [dl, setDl]   = useState(null)               // deadlines from the last server answer
  const [now, setNow] = useState(() => Date.now())
  const [renewing, setRenewing] = useState(false)    // "Sign in again" from the 8-hour banner
  const [reason, setReason]     = useState('ended')
  const beat    = useRef({ next: 0, busy: false })
  const checked = useRef({ warn: '', end: '' })      // deadlines already re-read before warning / ending

  const apply = useCallback((s) => setDl(toLocal(s)), [])

  const sendBeat = useCallback(async () => {
    const b = beat.current
    if (b.busy) return
    b.busy = true
    try {
      apply(await api.sessionHeartbeat())
      b.next = Date.now() + BEAT_EVERY_MS
    } catch (e) {
      if (e.status !== 401) b.next = Date.now() + RETRY_MS   // a 401 has already opened the dialog
    } finally {
      b.busy = false
    }
  }, [apply])

  // Loading the app, or signing in again, is activity: start from a fresh heartbeat.
  useEffect(() => { if (status === 'user') sendBeat() }, [status, sessionEpoch, sendBeat])

  // Real input (in this tab) → a heartbeat, at most every 5 min.
  useEffect(() => {
    if (status !== 'user') return
    const onInput = () => { if (Date.now() >= beat.current.next) sendBeat() }
    INPUT_EVENTS.forEach(t => window.addEventListener(t, onInput, { capture: true, passive: true }))
    return () => INPUT_EVENTS.forEach(t => window.removeEventListener(t, onInput, { capture: true }))
  }, [status, sendBeat])

  useEffect(() => {
    if (status !== 'user') return
    const t = setInterval(() => setNow(Date.now()), 1000)
    return () => clearInterval(t)
  }, [status])

  // Before a warning, and at a deadline, re-read the session (a pure read: it never extends it).
  // Another tab may have kept it alive; a 401 opens the dialog through the API client.
  useEffect(() => {
    if (status !== 'user' || !dl) return
    const left = Math.min(dl.idleAt, dl.hardAt) - now
    if (left <= -GRACE_MS && checked.current.end !== dl.key) {
      checked.current.end = dl.key
      api.getCurrentSession()
        .then(s => { if (toLocal(s).key !== dl.key) apply(s); else expire() })
        .catch(() => {})
    } else if (left <= WARN_MS && left > -GRACE_MS && checked.current.warn !== dl.key) {
      checked.current.warn = dl.key
      api.getCurrentSession().then(apply).catch(() => {})
    }
  }, [status, dl, now, apply, expire])

  // Why it ended, from the deadlines this tab last knew. Set while rendering the status change, so the
  // dialog's first frame already says the right thing.
  const [seenStatus, setSeenStatus] = useState(status)
  if (status !== seenStatus) {
    setSeenStatus(status)
    if (status === 'expired') {
      const t = Date.now()
      setReason(!dl ? 'ended' : t >= dl.hardAt - 5000 ? 'hard' : t >= dl.idleAt - 5000 ? 'idle' : 'ended')
    }
  }

  // Signed in again in another tab? Coming back to this one picks that up (resume checks the user).
  useEffect(() => {
    if (status !== 'expired') return
    const onBack = () => { if (document.visibilityState === 'visible') api.me().then(resume).catch(() => {}) }
    window.addEventListener('focus', onBack)
    document.addEventListener('visibilitychange', onBack)
    return () => {
      window.removeEventListener('focus', onBack)
      document.removeEventListener('visibilitychange', onBack)
    }
  }, [status, resume])

  const onSignedIn = useCallback((u) => { setRenewing(false); resume(u) }, [resume])
  const stay = useCallback(() => { if (Date.now() >= beat.current.next) sendBeat() }, [sendBeat])

  if (!user) return null
  const timeoutMinutes = Math.round((dl?.timeoutMs ?? 30 * 60_000) / 60_000)
  if (status === 'expired' || renewing) {
    return (
      <SessionExpiredDialog user={user} reason={status === 'expired' ? reason : 'renew'} timeoutMinutes={timeoutMinutes}
                            onSignedIn={onSignedIn} onCancel={status === 'expired' ? null : () => setRenewing(false)} />
    )
  }
  if (status !== 'user' || !dl) return null

  const idleLeft = dl.idleAt - now, hardLeft = dl.hardAt - now
  const showIdle = idleLeft <= WARN_MS && idleLeft > -GRACE_MS && idleLeft < hardLeft
  const showHard = hardLeft <= WARN_MS && hardLeft > -GRACE_MS
  return (
    <>
      {showHard && (
        <div className="session-banner" role="status">
          <span>
            Your session ends at {formatLocal(dl.hardIso)} (8-hour limit), in {mmss(hardLeft)}.
            Save your work, or sign in again now to keep going.
          </span>
          <button type="button" className="btn primary" onClick={() => setRenewing(true)}>Sign in again</button>
        </div>
      )}
      {showIdle && (
        <div className="modal-backdrop session-modal">
          <div className="modal" role="alertdialog" aria-modal="true" aria-labelledby="se-idle-title" aria-describedby="se-idle-desc">
            <div className="modal-head"><h2 id="se-idle-title">Still there?</h2></div>
            <div className="modal-body" id="se-idle-desc">
              You'll be signed out in <strong>{mmss(idleLeft)}</strong>: nothing has happened in FENRIR
              for {Math.floor((dl.timeoutMs - idleLeft) / 60_000)} minutes.
            </div>
            <div className="modal-foot">
              <button type="button" className="btn primary" onClick={stay} autoFocus>Stay signed in</button>
            </div>
          </div>
        </div>
      )}
    </>
  )
}
