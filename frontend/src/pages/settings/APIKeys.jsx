import { useEffect, useState } from 'react'
import { api } from '../../api/client.js'

const SERVICE_DESCRIPTIONS = {
  virustotal: 'Multi-engine malware analysis (IP, domain, hashes). Queries are public to third parties.',
  abuseipdb:  'Crowdsourced IP abuse reports and confidence score.',
  shodan:     'Internet-connected device scan data — open ports, services, banners.',
  greynoise:  'Internet noise classification — mass scanner and known-good service detection.',
  urlscan:    'Historical URL and domain scan results. Optional — public endpoint works without a key.',
}

export default function APIKeys() {
  const [services, setServices] = useState([])
  const [loading,  setLoading]  = useState(true)
  const [error,    setError]    = useState(null)

  const load = async () => {
    setError(null)
    try {
      const res = await api.listApiKeyServices()
      setServices(res.services)
    } catch (e) {
      setError(e.message || 'Could not load API key settings')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  const onSaved = () => load()
  const onDeleted = () => load()

  return (
    <div>
      <div style={{ marginBottom: 'var(--space-4)' }}>
        <h2 style={{ margin: 0, fontSize: 18, fontFamily: 'var(--font-heading)' }}>IOC Enrichment API Keys</h2>
        <p style={{ color: 'var(--muted)', fontSize: 13, marginTop: 'var(--space-1)', marginBottom: 0 }}>
          Keys are stored encrypted (Fernet / AES-128) in the database. Raw values are never
          returned — only configured status. Env-var keys act as fallback if no DB key is set.
        </p>
      </div>

      {error && (
        <div className="alert error" role="alert" style={{ marginBottom: 'var(--space-3)' }}>
          <span className="alert-icon">!</span><span>{error}</span>
        </div>
      )}

      {loading ? (
        <div className="panel-empty"><div>Loading…</div></div>
      ) : (
        <table className="settings-table">
          <thead>
            <tr>
              <th style={{ width: 140 }}>Service</th>
              <th>Description</th>
              <th style={{ width: 120, textAlign: 'center' }}>Status</th>
              <th className="actions">Actions</th>
            </tr>
          </thead>
          <tbody>
            {services.map(svc => (
              <ServiceRow
                key={svc.service}
                svc={svc}
                onSaved={onSaved}
                onDeleted={onDeleted}
              />
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}

function ServiceRow({ svc, onSaved, onDeleted }) {
  const [editing,  setEditing]  = useState(false)
  const [keyValue, setKeyValue] = useState('')
  const [busy,     setBusy]     = useState(false)
  const [err,      setErr]      = useState(null)

  const save = async (e) => {
    e.preventDefault()
    const v = keyValue.trim()
    if (!v) { setErr('Key cannot be empty.'); return }
    setErr(null)
    setBusy(true)
    try {
      await api.setApiKey(svc.service, v)
      setEditing(false)
      setKeyValue('')
      onSaved()
    } catch (ex) {
      setErr(ex.message || 'Could not save key.')
    } finally {
      setBusy(false)
    }
  }

  const remove = async () => {
    if (!window.confirm(`Remove the ${svc.label} API key from the database?\n\nThe env-var fallback (if set) will still apply.`)) return
    setBusy(true)
    setErr(null)
    try {
      await api.deleteApiKey(svc.service)
      onDeleted()
    } catch (ex) {
      setErr(ex.message || 'Could not remove key.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <tr>
        <td style={{ fontWeight: 500 }}>{svc.label}</td>
        <td style={{ fontSize: 12, color: 'var(--muted)' }}>
          {SERVICE_DESCRIPTIONS[svc.service] || ''}
        </td>
        <td style={{ textAlign: 'center' }}>
          {svc.configured ? (
            <span
              style={{
                color:      'var(--ok)',
                fontSize:   12,
                fontWeight: 600,
              }}
              title={svc.source === 'env' ? 'Configured via environment variable' : 'Configured in database'}
            >
              {svc.source === 'env' ? '✓ env' : '✓ db'}
            </span>
          ) : (
            <span style={{ color: 'var(--dim)', fontSize: 12 }}>Not set</span>
          )}
        </td>
        <td className="actions">
          {editing ? (
            <button type="button" className="btn ghost" style={{ fontSize: 12 }}
              onClick={() => { setEditing(false); setKeyValue(''); setErr(null) }}
              disabled={busy}>
              Cancel
            </button>
          ) : (
            <>
              <button type="button" className="btn ghost" style={{ fontSize: 12 }}
                onClick={() => setEditing(true)} disabled={busy}>
                {svc.configured && svc.source === 'db' ? 'Rotate' : 'Set key'}
              </button>
              {svc.configured && svc.source === 'db' && (
                <button type="button" className="btn ghost" style={{ fontSize: 12, color: 'var(--crit)' }}
                  onClick={remove} disabled={busy}>
                  Remove
                </button>
              )}
            </>
          )}
        </td>
      </tr>
      {editing && (
        <tr>
          <td colSpan={4} style={{ paddingTop: 0, paddingBottom: 'var(--space-3)' }}>
            <form onSubmit={save}>
              <div style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'center', padding: '0 var(--space-2)' }}>
                <input
                  type="password"
                  autoFocus
                  className="input"
                  placeholder={`Paste ${svc.label} API key…`}
                  value={keyValue}
                  onChange={e => setKeyValue(e.target.value)}
                  maxLength={512}
                  style={{ flex: 1, fontFamily: 'var(--font-mono)', fontSize: 12 }}
                  autoComplete="off"
                />
                <button type="submit" className="btn primary" style={{ fontSize: 12 }} disabled={busy || !keyValue.trim()}>
                  {busy ? 'Saving…' : 'Save'}
                </button>
              </div>
              {err && (
                <div style={{ color: 'var(--crit)', fontSize: 12, marginTop: 'var(--space-1)', paddingLeft: 'var(--space-2)' }}>
                  {err}
                </div>
              )}
            </form>
          </td>
        </tr>
      )}
    </>
  )
}
