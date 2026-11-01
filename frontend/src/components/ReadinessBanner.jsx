import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api/client.js'
import { useAuth } from '../hooks/useAuth.jsx'
import ReadinessDeferDialog from './ReadinessDeferDialog.jsx'

// Dashboard banner (E1): shown while GET /api/readiness reports a failing blocker. Silent on any
// error (a viewer's 403, a network failure): it is a hint, never a gate. RD: deferred checks are
// left out (the server's blockers_failing already excludes them); admins can defer from here.
export default function ReadinessBanner() {
  const { user } = useAuth()
  const [data, setData] = useState(null)
  const [deferring, setDeferring] = useState(false)

  useEffect(() => {
    let live = true
    api.getReadiness().then(d => { if (live) setData(d) }).catch(() => {})
    return () => { live = false }
  }, [])

  if (!data?.summary?.blockers_failing) return null
  const failing = data.checks.filter(c => c.level === 'blocker' && c.status === 'fail' && !c.deferral)
  const n = data.summary.blockers_failing
  return (
    <div className="rd-banner" role="status">
      <span className="rd-banner-mark" aria-hidden="true">!</span>
      <span className="rd-banner-text">
        <strong>{n} readiness blocker{n === 1 ? '' : 's'} failing:</strong> {failing.map(c => c.title).join(' · ')}
      </span>
      {user?.role === 'admin' && (
        <button type="button" className="btn-link rd-banner-defer" onClick={() => setDeferring(true)}>Defer…</button>
      )}
      <Link to="/readiness" className="rd-banner-link">Open Readiness →</Link>
      {deferring && (
        <ReadinessDeferDialog checks={failing} onClose={() => setDeferring(false)}
                              onDone={(d) => { setData(d); setDeferring(false) }} />
      )}
    </div>
  )
}
