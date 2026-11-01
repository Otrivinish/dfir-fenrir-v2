import { createContext, useCallback, useContext, useEffect, useState } from 'react'
import { api, setUnauthorizedHandler } from '../api/client.js'

const AuthCtx = createContext(null)

export function AuthProvider({ children }) {
  // status: 'loading' | 'guest' | 'user' | 'expired'
  // 'expired' (SE): the session ended mid-use. `user` is kept and the app stays mounted, so unsaved
  // work survives; SessionGuard covers the page with a sign-in dialog.
  const [status, setStatus] = useState('loading')
  const [user, setUser]     = useState(null)
  // Bumped after signing in again from that dialog, so WebSocket effects reconnect on the new session.
  const [sessionEpoch, setSessionEpoch] = useState(0)
  const [needsSetup, setNeedsSetup] = useState(false)
  // Org auth policy from /api/auth/policy. Default safe (TOTP required) until fetched.
  const [policy, setPolicy] = useState({ totp_required: true })

  const refresh = useCallback(async () => {
    try {
      const u = await api.me()
      setUser(u); setStatus('user'); return u
    } catch (e) {
      setUser(null); setStatus('guest'); return null
    }
  }, [])

  useEffect(() => {
    let cancelled = false
    ;(async () => {
      try {
        const [{ needs_setup }, p] = await Promise.all([
          api.setupCheck(),
          api.authPolicy().catch(() => ({ totp_required: true })),
        ])
        if (cancelled) return
        setPolicy(p)
        setNeedsSetup(!!needs_setup)
        if (needs_setup) { setStatus('guest'); return }
        await refresh()
      } catch {
        if (!cancelled) setStatus('guest')
      }
    })()
    return () => { cancelled = true }
  }, [refresh])

  // A 401 from any data endpoint means the session ended mid-use. Mark it expired (only if
  // currently signed in) instead of redirecting: a redirect unmounts the page and loses unsaved edits.
  const expire = useCallback(() => setStatus(s => (s === 'user' ? 'expired' : s)), [])
  useEffect(() => {
    setUnauthorizedHandler(expire)
    return () => setUnauthorizedHandler(null)
  }, [expire])

  const setSignedIn = useCallback((u) => {
    setUser(u); setStatus('user'); setNeedsSetup(false)
  }, [])

  // Signed in again from the dialog. The same user carries on with the page as it is. Anyone else
  // must never save the previous user's unsaved typing under their own name: a full reload drops it.
  const resume = useCallback((u) => {
    if (!u || u.id !== user?.id) { window.location.assign('/'); return }
    if (u.force_totp_enrol) { window.location.assign('/totp/enrol'); return }
    setUser(u); setStatus('user'); setSessionEpoch(n => n + 1)
  }, [user])

  const signOut = useCallback(async () => {
    try { await api.logout() } catch {}
    setUser(null); setStatus('guest')
  }, [])

  const value = { status, user, needsSetup, policy, refresh, setSignedIn, signOut, setNeedsSetup,
                  expire, resume, sessionEpoch }
  return <AuthCtx.Provider value={value}>{children}</AuthCtx.Provider>
}

export function useAuth() {
  const ctx = useContext(AuthCtx)
  if (!ctx) throw new Error('useAuth must be used inside <AuthProvider>')
  return ctx
}
