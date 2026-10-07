import { useState } from 'react'
import { formatLocal, formatLocalShort, relative } from '../lib/datetime.js'

const STATUS_PILL = { active: 'pill ok', expired: 'pill', revoked: 'pill' }

// R144: the API-token table shared by Settings → Account and Admin → API tokens.
// Revoke asks for an in-row confirm; `onRevoke(token)` returns a promise.
export default function ApiTokenTable({ tokens, showUser = false, onRevoke, busy = false }) {
  const [confirming, setConfirming] = useState(null)

  return (
    <div className="table-scroll">
      <table className="settings-table compact">
        <thead>
          <tr>
            {showUser && <th>User</th>}
            <th>Name</th>
            <th>Prefix</th>
            <th>Role</th>
            <th>Created</th>
            <th>Expires</th>
            <th>Last used</th>
            <th>Status</th>
            <th className="actions">Actions</th>
          </tr>
        </thead>
        <tbody>
          {tokens.map(t => (
            <tr key={t.id}>
              {showUser && <td className="token-mono">{t.username || '—'}</td>}
              <td className="token-name">{t.name}</td>
              <td className="token-mono">{t.token_prefix}…</td>
              <td>{t.role}</td>
              <td className="token-mono" title={formatLocal(t.created_at)}>{formatLocalShort(t.created_at)}</td>
              <td className="token-mono" title={t.expires_at ? formatLocal(t.expires_at) : 'Issued before expiry was required'}>
                {t.expires_at ? formatLocalShort(t.expires_at) : 'Never'}
              </td>
              <td title={t.last_used_at ? formatLocal(t.last_used_at) : ''}>
                {t.last_used_at ? relative(t.last_used_at) : <span className="token-dim">Never</span>}
              </td>
              <td><span className={STATUS_PILL[t.status] || 'pill'}>{t.status}</span></td>
              <td className="actions">
                {t.status !== 'active' ? (
                  <span className="token-dim">—</span>
                ) : confirming === t.id ? (
                  <span className="row-actions" role="group" aria-label={`Confirm revoking ${t.name}`}>
                    <span className="token-confirm-text">Revoke? Calls with it fail at once.</span>
                    <button type="button" className="btn primary" disabled={busy}
                            onClick={async () => { await onRevoke(t); setConfirming(null) }}>Confirm revoke</button>
                    <button type="button" className="btn ghost" disabled={busy} onClick={() => setConfirming(null)}>Cancel</button>
                  </span>
                ) : (
                  <button type="button" className="btn ghost" disabled={busy} onClick={() => setConfirming(t.id)}>Revoke</button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
