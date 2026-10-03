import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api/client.js'

// Dashboard banner (E1): shown while GET /api/readiness reports a failing blocker. Silent on any
// error (a viewer's 403, a network failure): it is a hint, never a gate.
export default function ReadinessBanner() {
  const [data, setData] = useState(null)

  useEffect(() => {
    let live = true
    api.getReadiness().then(d => { if (live) setData(d) }).catch(() => {})
    return () => { live = false }
  }, [])

  if (!data?.summary?.blockers_failing) return null
  const titles = data.checks.filter(c => c.level === 'blocker' && c.status === 'fail').map(c => c.title)
  const n = data.summary.blockers_failing
  return (
    <div className="rd-banner" role="status">
      <span className="rd-banner-mark" aria-hidden="true">!</span>
      <span className="rd-banner-text">
        <strong>{n} readiness blocker{n === 1 ? '' : 's'} failing:</strong> {titles.join(' · ')}
      </span>
      <Link to="/readiness" className="rd-banner-link">Open Readiness →</Link>
    </div>
  )
}
