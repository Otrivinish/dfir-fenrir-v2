import { createContext, useCallback, useContext, useEffect, useState } from 'react'
import { api, setUnauthorizedHandler } from '../api/client.js'

const AuthCtx = createContext(null)

export function AuthProvider({ children }) {
  // status: 'loading' | 'guest' | 'user'
  const [status, setStatus] = useState('loading')
  const [user, setUser]     = useState(null)
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

  // A 401 from any data endpoint means the session ended mid-use. Drop to guest
  // (only if currently signed in) so RequireAuth redirects to /login?next=…,
  // instead of leaving the user stuck on an "unauthenticated" message.
  useEffect(() => {
    setUnauthorizedHandler(() => {
      setUser(null)
      setStatus(s => (s === 'user' ? 'guest' : s))
    })
    return () => setUnauthorizedHandler(null)
  }, [])

  const setSignedIn = useCallback((u) => {
    setUser(u); setStatus('user'); setNeedsSetup(false)
  }, [])

  const signOut = useCallback(async () => {
    try { await api.logout() } catch {}
    setUser(null); setStatus('guest')
  }, [])

  const value = { status, user, needsSetup, policy, refresh, setSignedIn, signOut, setNeedsSetup }
  return <AuthCtx.Provider value={value}>{children}</AuthCtx.Provider>
}

export function useAuth() {
  const ctx = useContext(AuthCtx)
  if (!ctx) throw new Error('useAuth must be used inside <AuthProvider>')
  return ctx
}
