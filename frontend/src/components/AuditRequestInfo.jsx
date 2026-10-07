import { Fragment } from 'react'
import { shortClient } from '../lib/userAgent.js'

const LINE = { fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--dim)', marginTop: 2, overflowWrap: 'anywhere' }
const VALUE = { fontFamily: 'var(--font-mono)', fontSize: 11, overflowWrap: 'anywhere' }

// The line under an audit entry's timestamp: `METHOD IP · client`, the full user agent on
// hover. An entry without a client IP was written by the system (no request).
export function AuditClientLine({ ev }) {
  if (!ev.ip_address) return <div style={LINE} data-audit-client>system</div>
  const client = shortClient(ev.user_agent)
  return (
    <div style={LINE} title={ev.user_agent || undefined} data-audit-client>
      {[ev.request_method, ev.ip_address].filter(Boolean).join(' ')}{client && ` · ${client}`}
    </div>
  )
}

// The full request context of an expanded audit entry.
export function AuditRequestFields({ ev }) {
  const rows = [
    ['IP address', ev.ip_address || 'system'],
    ['User agent', ev.user_agent || '—'],
    ['Request path', ev.request_path || '—'],
    ['Request ID', ev.request_id || '—'],
  ]
  return (
    <dl className="kv" style={{ margin: 0, rowGap: 'var(--space-1)' }} data-audit-request>
      {rows.map(([k, v]) => (
        <Fragment key={k}><dt>{k}</dt><dd style={VALUE}>{v}</dd></Fragment>
      ))}
    </dl>
  )
}
