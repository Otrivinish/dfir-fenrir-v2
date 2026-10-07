import { useCallback, useEffect, useState } from 'react'
import { api } from '../../api/client.js'
import ApiTokenTable from '../../components/ApiTokenTable.jsx'

// R144: every user's API tokens; an admin revoke notifies the owner in-app.
export default function AdminApiTokens() {
  const [tokens, setTokens]   = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError]     = useState(null)
  const [busy, setBusy]       = useState(false)
  const [filter, setFilter]   = useState('')
  const [activeOnly, setActiveOnly] = useState(true)

  const load = useCallback(async () => {
    setError(null)
    try {
      const r = await api.listAllApiTokens()
      setTokens(r.items || [])
    } catch (e) {
      setError(e.message || 'Could not load API tokens')
    } finally {
      setLoading(false)
    }
  }, [])
  useEffect(() => { load() }, [load])

  const onRevoke = async (t) => {
    setError(null); setBusy(true)
    try {
      await api.adminRevokeApiToken(t.id)
      await load()
    } catch (e) {
      setError(e.message || 'Could not revoke the token')
    } finally {
      setBusy(false)
    }
  }

  const q = filter.trim().toLowerCase()
  const visible = tokens.filter(t =>
    (!activeOnly || t.status === 'active') &&
    (!q || (t.username || '').toLowerCase().includes(q) || t.name.toLowerCase().includes(q) || t.token_prefix.toLowerCase().includes(q)))
  const active = tokens.filter(t => t.status === 'active')
  const users = new Set(active.map(t => t.user_id)).size

  return (
    <section className="panel">
      <div className="panel-toolbar">
        <div>
          <h2 className="panel-h">API Tokens</h2>
          <div className="token-sub">
            {active.length} active token{active.length !== 1 ? 's' : ''} across {users} user{users !== 1 ? 's' : ''}. Revoking notifies the owner.
          </div>
        </div>
        <div className="token-controls">
          <input className="input" placeholder="Filter by user, name, prefix…" aria-label="Filter tokens"
                 value={filter} onChange={(e) => setFilter(e.target.value)} />
          <select className="select" aria-label="Which tokens" value={activeOnly ? 'active' : 'all'}
                  onChange={(e) => setActiveOnly(e.target.value === 'active')}>
            <option value="active">Active only</option>
            <option value="all">All (incl. expired, revoked)</option>
          </select>
          <button type="button" className="btn ghost" onClick={load} disabled={loading || busy}>↻ Refresh</button>
        </div>
      </div>

      {error && (
        <div className="alert error" role="alert">
          <span className="alert-icon">!</span>
          <span>{error}</span>
        </div>
      )}

      {loading ? (
        <div className="panel-empty"><div>Loading…</div></div>
      ) : visible.length === 0 ? (
        <div className="panel-empty"><div>{q || activeOnly ? 'No tokens match.' : 'No API tokens.'}</div></div>
      ) : (
        <ApiTokenTable tokens={visible} showUser onRevoke={onRevoke} busy={busy} />
      )}
    </section>
  )
}
