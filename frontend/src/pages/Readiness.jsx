import { useCallback, useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api/client.js'
import { useAuth } from '../hooks/useAuth.jsx'
import { formatLocal } from '../lib/datetime.js'

// Prepare → Readiness (E1). Shows GET /api/readiness as-is: the API decides every status and
// level. State is a glyph plus a word; the text stays in text tokens (readiness.css).
const STATUS = {
  pass:    { glyph: '✓', label: 'Pass' },
  fail:    { glyph: '✕', label: 'Fail' },
  unknown: { glyph: '?', label: 'Unknown' },
}
const LEVEL = { blocker: 'Blocker', warning: 'Warning' }

// Pages behind RequireAdmin in App.jsx: an analyst is sent away from them, so name who can fix it instead.
const adminOnlyRoute = (r) => r.startsWith('/admin') || (r.startsWith('/settings/') && r !== '/settings/account')
// Pages an analyst may open but not change (on-call entries and the Contacts directory are admin
// writes): "View →" while the check passes, "Needs an admin" while it doesn't.
const ADMIN_WRITE_ROUTES = new Set(['/on-call', '/contacts'])

const NOT_CHECKED = [
  'Restore tests and tabletop exercises.',
  'A jurisdiction profile (member state, NIS2 class, DORA).',
  'Whether a test email really arrives (only that email is configured).',
  'Validated tools per acquisition type (only that one exists).',
]

function plural(n, word) { return `${n} ${word}${n === 1 ? '' : 's'}` }

function CheckRow({ c, isAdmin }) {
  const st = STATUS[c.status] || STATUS.unknown
  const fixLabel = c.status === 'pass' ? 'View' : 'Fix'
  let fix = null
  if (c.fix_route) {
    fix = !isAdmin && (adminOnlyRoute(c.fix_route) || (ADMIN_WRITE_ROUTES.has(c.fix_route) && c.status !== 'pass'))
      ? <span className="rd-fix-admin">Needs an admin</span>
      : <Link to={c.fix_route} aria-label={`${fixLabel}: ${c.title}`}>{fixLabel} →</Link>
  }
  return (
    <li className={`rd-item rd-${c.status} rd-lvl-${c.level}`} data-check-id={c.id}>
      <span className="rd-status"><span className="rd-glyph" aria-hidden="true">{st.glyph}</span>{st.label}</span>
      <div className="rd-main">
        <div className="rd-title">{c.title}</div>
        <div className="rd-detail">{c.detail}</div>
      </div>
      <span className="rd-level">{LEVEL[c.level] || c.level}</span>
      <span className="rd-csf">{c.csf.length ? c.csf.join(' · ') : '—'}</span>
      <span className="rd-fix">{fix}</span>
    </li>
  )
}

export default function Readiness() {
  const { user } = useAuth()
  const isAdmin = user?.role === 'admin'
  const [data, setData] = useState(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)
  const seq = useRef(0)

  const load = useCallback(async () => {
    const mine = ++seq.current
    setLoading(true); setError('')
    try {
      const d = await api.getReadiness()
      if (mine === seq.current) setData(d)
    } catch (e) {
      if (mine === seq.current) setError(e.message || 'Could not load readiness.')
    } finally {
      if (mine === seq.current) setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  const s = data?.summary
  return (
    <div className="rd-page">
      <div className="page-head rd-head">
        <div>
          <h1 className="page-title">Readiness</h1>
          <div className="page-sub">
            Is the organisation prepared for the next incident?{data ? ` · checked ${formatLocal(data.generated_at)}` : ''}
          </div>
        </div>
        <button type="button" className="btn ghost" onClick={load} disabled={loading}>
          {loading ? 'Checking…' : 'Check again'}
        </button>
      </div>

      {error && (
        <div className="rd-error" role="alert"><span className="rd-error-mark" aria-hidden="true">!</span>{error}</div>
      )}
      {!data && loading && <div className="panel"><div className="panel-empty">Checking…</div></div>}

      {data && (
        <>
          <div className="panel rd-summary" role="status">
            <span className={`rd-count ${s.blockers_failing ? 'rd-count-blocker' : 'rd-count-ok'}`}>
              <span className="rd-glyph" aria-hidden="true">{s.blockers_failing ? '✕' : '✓'}</span>
              {plural(s.blockers_failing, 'blocker')} failing
            </span>
            <span className={`rd-count ${s.warnings_failing ? 'rd-count-warning' : 'rd-count-ok'}`}>
              <span className="rd-glyph" aria-hidden="true">{s.warnings_failing ? '✕' : '✓'}</span>
              {plural(s.warnings_failing, 'warning')} failing
            </span>
            {s.unknown > 0 && (
              <span className="rd-count rd-count-unknown">
                <span className="rd-glyph" aria-hidden="true">?</span>
                {s.unknown} not checked
              </span>
            )}
            <span className="rd-summary-note">Blockers never stop you opening an incident.</span>
          </div>

          <div className="panel rd-panel">
            <div className="rd-cols" aria-hidden="true">
              <span>Status</span><span>Check</span><span>Level</span><span>NIST CSF 2.0</span><span />
            </div>
            <ul className="rd-list" aria-label="Readiness checks">
              {data.checks.map(c => <CheckRow key={c.id} c={c} isAdmin={isAdmin} />)}
            </ul>
          </div>

          <div className="panel rd-limits">
            <h2 className="rd-limits-h">Not checked in v1</h2>
            <ul>{NOT_CHECKED.map(t => <li key={t}>{t}</li>)}</ul>
            <p>A pass means the record exists, not that it works. Most fixes need an admin.</p>
          </div>
        </>
      )}
    </div>
  )
}
