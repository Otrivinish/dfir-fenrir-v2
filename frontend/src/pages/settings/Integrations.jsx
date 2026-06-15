import { useEffect, useState } from 'react'
import { api } from '../../api/client.js'

export default function Integrations() {
  return (
    <div className="settings-stack">
      <SmtpPanel />
      <WebhookPanel />
      <SyslogPanel />
      <SiemInboundPanel />
    </div>
  )
}

// ── Shared helpers ────────────────────────────────────────────────────────────

function FieldRow({ label, children }) {
  return (
    <div className="field">
      <label className="field-label">{label}</label>
      {children}
    </div>
  )
}

function SaveRow({ busy, label = 'Save', onCancel, extra }) {
  return (
    <div className="settings-form-actions">
      {extra}
      {onCancel && <button type="button" className="btn ghost" onClick={onCancel} disabled={busy}>Cancel</button>}
      <button type="submit" className="btn primary" disabled={busy}>{busy ? 'Saving…' : label}</button>
    </div>
  )
}

// ── SMTP / Graph panel ────────────────────────────────────────────────────────

function SmtpPanel() {
  const [cfg, setCfg]       = useState(null)
  const [busy, setBusy]     = useState(false)
  const [testing, setTesting] = useState(false)
  const [error, setError]   = useState('')
  const [ok, setOk]         = useState('')

  useEffect(() => {
    api.getSmtpConfig().then(setCfg).catch(() => setCfg({}))
  }, [])

  if (!cfg) return <section className="panel"><div style={{ color: 'var(--muted)', fontSize: 13 }}>Loading…</div></section>

  const set = (k) => (e) => { setCfg(c => ({ ...c, [k]: e.target.value })); setOk('') }

  const handleSave = async (e) => {
    e.preventDefault()
    setBusy(true); setError(''); setOk('')
    try {
      await api.saveSmtpConfig(cfg)
      setOk('Settings saved.')
    } catch (err) {
      setError(err.message || 'Save failed.')
    } finally {
      setBusy(false)
    }
  }

  const handleTest = async () => {
    setTesting(true); setError(''); setOk('')
    try {
      await api.testEmail()
      setOk('Test email sent — check the admin inbox.')
    } catch (err) {
      setError(err.message || 'Test send failed.')
    } finally {
      setTesting(false)
    }
  }

  return (
    <section className="panel">
      <h2 className="panel-h">Email (SMTP / M365)</h2>
      <p className="field-hint" style={{ marginBottom: 'var(--space-3)' }}>
        Used for admin alerts (high/critical incidents). Disabled if mode is unset.
      </p>
      <form className="settings-form" onSubmit={handleSave}>
        <FieldRow label="Mode">
          <select className="select" value={cfg.mode ?? ''} onChange={set('mode')}>
            <option value="">— disabled —</option>
            <option value="smtp">SMTP / STARTTLS</option>
            <option value="graph">Microsoft Graph (M365 OAuth)</option>
          </select>
        </FieldRow>

        {cfg.mode === 'smtp' && (
          <>
            <FieldRow label="Admin alert recipient">
              <input className="input" type="email" value={cfg.admin_email ?? ''} onChange={set('admin_email')} placeholder="soc-admin@example.com" />
            </FieldRow>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 100px', gap: 'var(--space-2)' }}>
              <FieldRow label="SMTP host">
                <input className="input" value={cfg.host ?? ''} onChange={set('host')} placeholder="smtp.example.com" />
              </FieldRow>
              <FieldRow label="Port">
                <input className="input" type="number" value={cfg.port ?? 587} onChange={e => setCfg(c => ({ ...c, port: parseInt(e.target.value) || 587 }))} min={1} max={65535} />
              </FieldRow>
            </div>
            <FieldRow label="Username">
              <input className="input" value={cfg.username ?? ''} onChange={set('username')} placeholder="relay@example.com" autoComplete="off" />
            </FieldRow>
            <FieldRow label={`Password${cfg.password_set ? ' (set — leave blank to keep)' : ''}`}>
              <input className="input" type="password" value={cfg.password ?? ''} onChange={set('password')} placeholder={cfg.password_set ? '••••••••' : 'password'} autoComplete="new-password" />
            </FieldRow>
            <FieldRow label="From address (optional)">
              <input className="input" type="email" value={cfg.from_address ?? ''} onChange={set('from_address')} placeholder="fenrir@example.com" />
            </FieldRow>
          </>
        )}

        {cfg.mode === 'graph' && (
          <>
            <FieldRow label="Admin alert recipient">
              <input className="input" type="email" value={cfg.admin_email ?? ''} onChange={set('admin_email')} placeholder="soc-admin@example.com" />
            </FieldRow>
            <FieldRow label="Tenant ID">
              <input className="input" value={cfg.graph_tenant_id ?? ''} onChange={set('graph_tenant_id')} placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" />
            </FieldRow>
            <FieldRow label="Client ID (App Registration)">
              <input className="input" value={cfg.graph_client_id ?? ''} onChange={set('graph_client_id')} placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" />
            </FieldRow>
            <FieldRow label={`Client secret${cfg.graph_secret_set ? ' (set — leave blank to keep)' : ''}`}>
              <input className="input" type="password" value={cfg.graph_client_secret ?? ''} onChange={set('graph_client_secret')} placeholder={cfg.graph_secret_set ? '••••••••' : 'secret value'} autoComplete="new-password" />
            </FieldRow>
            <FieldRow label="Sender UPN (must have Mail.Send permission)">
              <input className="input" type="email" value={cfg.graph_sender ?? ''} onChange={set('graph_sender')} placeholder="fenrir@yourtenant.onmicrosoft.com" />
            </FieldRow>
          </>
        )}

        {error && <div className="alert error" role="alert"><span className="alert-icon">!</span><span>{error}</span></div>}
        {ok    && <div className="alert info"  role="status"><span className="alert-icon">✓</span><span>{ok}</span></div>}

        <SaveRow busy={busy} extra={
          cfg.mode ? (
            <button type="button" className="btn ghost" onClick={handleTest} disabled={busy || testing}>
              {testing ? 'Sending…' : 'Send test email'}
            </button>
          ) : null
        } />
      </form>
    </section>
  )
}

// ── Outbound webhooks panel ───────────────────────────────────────────────────

function WebhookPanel() {
  const [cfg, setCfg]   = useState(null)
  const [teams, setTeams] = useState('')
  const [slack, setSlack] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [ok, setOk]     = useState('')

  useEffect(() => {
    api.getWebhookConfig().then(data => {
      setCfg(data)
    }).catch(() => setCfg({ teams_url_set: false, slack_url_set: false }))
  }, [])

  if (!cfg) return <section className="panel"><div style={{ color: 'var(--muted)', fontSize: 13 }}>Loading…</div></section>

  const handleSave = async (e) => {
    e.preventDefault()
    setBusy(true); setError(''); setOk('')
    try {
      await api.saveWebhookConfig({
        teams_url: teams || (teams === '' && cfg.teams_url_set ? undefined : ''),
        slack_url: slack || (slack === '' && cfg.slack_url_set ? undefined : ''),
      })
      const updated = await api.getWebhookConfig()
      setCfg(updated)
      setTeams(''); setSlack('')
      setOk('Webhook URLs saved.')
    } catch (err) {
      setError(err.message || 'Save failed.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="panel">
      <h2 className="panel-h">Outbound webhooks</h2>
      <p className="field-hint" style={{ marginBottom: 'var(--space-3)' }}>
        Posts to Teams / Slack on: incident created, phase changed, severity changed, resolved.
      </p>
      <form className="settings-form" onSubmit={handleSave}>
        <FieldRow label={`Microsoft Teams webhook URL${cfg.teams_url_set ? ` (${cfg.teams_url_preview})` : ''}`}>
          <input className="input" type="url" value={teams} onChange={e => { setTeams(e.target.value); setOk('') }}
            placeholder={cfg.teams_url_set ? 'Paste new URL to replace, or leave blank' : 'https://xxx.webhook.office.com/…'} />
          {cfg.teams_url_set && !teams && (
            <button type="button" className="btn ghost" style={{ fontSize: 11, marginTop: 4 }}
              onClick={async () => { await api.saveWebhookConfig({ teams_url: '' }); setCfg(c => ({ ...c, teams_url_set: false, teams_url_preview: null })) }}>
              Remove Teams URL
            </button>
          )}
        </FieldRow>
        <FieldRow label={`Slack incoming webhook URL${cfg.slack_url_set ? ` (${cfg.slack_url_preview})` : ''}`}>
          <input className="input" type="url" value={slack} onChange={e => { setSlack(e.target.value); setOk('') }}
            placeholder={cfg.slack_url_set ? 'Paste new URL to replace, or leave blank' : 'https://hooks.slack.com/services/…'} />
          {cfg.slack_url_set && !slack && (
            <button type="button" className="btn ghost" style={{ fontSize: 11, marginTop: 4 }}
              onClick={async () => { await api.saveWebhookConfig({ slack_url: '' }); setCfg(c => ({ ...c, slack_url_set: false, slack_url_preview: null })) }}>
              Remove Slack URL
            </button>
          )}
        </FieldRow>
        {error && <div className="alert error" role="alert"><span className="alert-icon">!</span><span>{error}</span></div>}
        {ok    && <div className="alert info"  role="status"><span className="alert-icon">✓</span><span>{ok}</span></div>}
        <SaveRow busy={busy} />
      </form>
    </section>
  )
}

// ── SIEM inbound panel ────────────────────────────────────────────────────────

const BASE_URL = window.location.origin

function SiemInboundPanel() {
  const [keyState, setKeyState] = useState(null)
  const [newKey, setNewKey]     = useState('')
  const [busy, setBusy]         = useState(false)
  const [error, setError]       = useState('')

  useEffect(() => {
    api.getSiemKey().then(setKeyState).catch(() => setKeyState({ configured: false }))
  }, [])

  const handleGenerate = async () => {
    setBusy(true); setError(''); setNewKey('')
    try {
      const r = await api.generateSiemKey()
      setKeyState({ configured: true })
      setNewKey(r.key)
    } catch (err) {
      setError(err.message || 'Generate failed.')
    } finally {
      setBusy(false)
    }
  }

  const handleRevoke = async () => {
    if (!confirm('Revoke the SIEM inbound key? All SIEM integrations will stop working until a new key is generated.')) return
    setBusy(true); setError(''); setNewKey('')
    try {
      await api.deleteSiemKey()
      setKeyState({ configured: false })
    } catch (err) {
      setError(err.message || 'Revoke failed.')
    } finally {
      setBusy(false)
    }
  }

  const endpoints = [
    { label: 'Splunk',             path: '/api/webhooks/splunk' },
    { label: 'Microsoft Sentinel', path: '/api/webhooks/sentinel' },
    { label: 'Elastic SIEM',       path: '/api/webhooks/elastic' },
  ]

  return (
    <section className="panel">
      <h2 className="panel-h">SIEM inbound webhooks</h2>
      <p className="field-hint" style={{ marginBottom: 'var(--space-3)' }}>
        SIEMs POST alerts to these endpoints to automatically create incidents.
        Authenticate with <code style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>X-Fenrir-Key: &lt;key&gt;</code> header.
      </p>

      <table className="data-table" style={{ width: '100%', marginBottom: 'var(--space-4)' }}>
        <thead><tr><th>SIEM</th><th>Endpoint</th></tr></thead>
        <tbody>
          {endpoints.map(ep => (
            <tr key={ep.label}>
              <td>{ep.label}</td>
              <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>
                POST {BASE_URL}{ep.path}
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)', flexWrap: 'wrap' }}>
        <span style={{ fontSize: 13 }}>
          Status: {keyState === null ? '…' : keyState.configured
            ? <strong style={{ color: 'var(--ok)' }}>Key configured</strong>
            : <span style={{ color: 'var(--muted)' }}>No key — generate one to enable</span>
          }
        </span>
        <button type="button" className="btn primary" onClick={handleGenerate} disabled={busy}>
          {busy ? 'Generating…' : keyState?.configured ? 'Rotate key' : 'Generate key'}
        </button>
        {keyState?.configured && (
          <button type="button" className="btn ghost" onClick={handleRevoke} disabled={busy}
            style={{ color: 'var(--crit)' }}>
            Revoke key
          </button>
        )}
      </div>

      {newKey && (
        <div style={{
          marginTop: 'var(--space-3)', padding: 'var(--space-3)',
          background: 'color-mix(in srgb, var(--ok) 8%, transparent)',
          border: '1px solid var(--ok)', borderRadius: 'var(--radius)',
        }}>
          <div style={{ fontSize: 12, color: 'var(--ok)', fontWeight: 600, marginBottom: 4 }}>
            New key — copy it now. It will not be shown again.
          </div>
          <code style={{
            display: 'block', fontFamily: 'var(--font-mono)', fontSize: 12,
            wordBreak: 'break-all', userSelect: 'all', color: 'var(--text)',
          }}>
            {newKey}
          </code>
        </div>
      )}

      {error && <div className="alert error" role="alert" style={{ marginTop: 'var(--space-3)' }}><span className="alert-icon">!</span><span>{error}</span></div>}
    </section>
  )
}

// ── Syslog forwarding panel (RFC 5424) ────────────────────────────────────────

const SYSLOG_FACILITIES = [
  { value: 0,  label: '0  kern' },
  { value: 1,  label: '1  user' },
  { value: 3,  label: '3  daemon' },
  { value: 4,  label: '4  auth' },
  { value: 10, label: '10 authpriv' },
  { value: 13, label: '13 log audit (default)' },
  { value: 14, label: '14 log alert' },
  { value: 16, label: '16 local0' },
  { value: 17, label: '17 local1' },
  { value: 18, label: '18 local2' },
  { value: 19, label: '19 local3' },
  { value: 20, label: '20 local4' },
  { value: 21, label: '21 local5' },
  { value: 22, label: '22 local6' },
  { value: 23, label: '23 local7' },
]

function SyslogPanel() {
  const [cfg, setCfg]         = useState(null)
  const [draft, setDraft]     = useState({ ca_bundle: '', client_cert: '', client_key: '' })
  const [busy, setBusy]       = useState(false)
  const [testing, setTesting] = useState(false)
  const [error, setError]     = useState('')
  const [ok, setOk]           = useState('')

  const refresh = () => api.getSyslogConfig().then(setCfg).catch(err => {
    setCfg({ enabled: false, host: '', port: 514, protocol: 'udp', facility: 13,
             app_name: 'dfir-fenrir', scope: 'audit_only', verify_tls: true,
             ca_bundle_set: false, client_cert_set: false, client_key_set: false,
             connected: false, sent_count: 0, dropped_count: 0 })
    setError(err.message || '')
  })

  useEffect(() => { refresh() }, [])

  if (!cfg) return <section className="panel"><div style={{ color: 'var(--muted)', fontSize: 13 }}>Loading…</div></section>

  const set = (k) => (e) => {
    const v = e?.target?.type === 'checkbox' ? e.target.checked
            : e?.target?.type === 'number'   ? parseInt(e.target.value || '0', 10)
            : e?.target?.value
    setCfg(c => ({ ...c, [k]: v })); setOk('')
  }

  const setDraftK = (k) => (e) => { setDraft(d => ({ ...d, [k]: e.target.value })); setOk('') }

  const handleSave = async (e) => {
    e.preventDefault()
    setBusy(true); setError(''); setOk('')
    try {
      const payload = {
        enabled:    cfg.enabled,
        host:       cfg.host,
        port:       cfg.port,
        protocol:   cfg.protocol,
        facility:   cfg.facility,
        app_name:   cfg.app_name,
        scope:      cfg.scope,
        verify_tls: cfg.verify_tls,
      }
      // Only send PEMs when the user typed something or explicitly cleared.
      if (draft.ca_bundle   !== '') payload.ca_bundle   = draft.ca_bundle
      if (draft.client_cert !== '') payload.client_cert = draft.client_cert
      if (draft.client_key  !== '') payload.client_key  = draft.client_key
      await api.saveSyslogConfig(payload)
      setDraft({ ca_bundle: '', client_cert: '', client_key: '' })
      await refresh()
      setOk('Settings saved.')
    } catch (err) {
      setError(err.message || 'Save failed.')
    } finally {
      setBusy(false)
    }
  }

  const handleTest = async () => {
    setTesting(true); setError(''); setOk('')
    try {
      const r = await api.testSyslog()
      setOk(r?.message || 'Test message delivered.')
    } catch (err) {
      setError(err.message || 'Test send failed.')
    } finally {
      setTesting(false)
    }
  }

  const clearPem = async (field) => {
    if (!confirm(`Remove the saved ${field.replace('_', ' ')}?`)) return
    setBusy(true); setError(''); setOk('')
    try {
      await api.saveSyslogConfig({ [field]: '' })
      await refresh()
      setOk('Removed.')
    } catch (err) {
      setError(err.message || 'Failed.')
    } finally {
      setBusy(false)
    }
  }

  const isTls = cfg.protocol === 'tls'

  return (
    <section className="panel">
      <h2 className="panel-h">Syslog forwarding</h2>
      <p className="field-hint" style={{ marginBottom: 'var(--space-3)' }}>
        Forwards platform logs to an external syslog collector using RFC 5424.
        TCP transport uses RFC 6587 octet-counted framing. TLS uses TLS 1.3.
      </p>

      <form className="settings-form" onSubmit={handleSave}>
        <FieldRow label="Enabled">
          <label style={{ display: 'inline-flex', alignItems: 'center', gap: 8, fontSize: 13, cursor: 'pointer' }}>
            <input type="checkbox" checked={!!cfg.enabled} onChange={set('enabled')} />
            <span>Forward logs to the configured collector</span>
          </label>
        </FieldRow>

        <FieldRow label="What to forward">
          <select className="select" value={cfg.scope} onChange={set('scope')}>
            <option value="audit_only">Audit log only — every audit row</option>
            <option value="all">All — audit rows + application logs (warnings &amp; errors)</option>
          </select>
        </FieldRow>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 120px', gap: 'var(--space-2)' }}>
          <FieldRow label="Collector host">
            <input className="input" value={cfg.host || ''} onChange={set('host')}
                   placeholder="siem.example.com" autoComplete="off" />
          </FieldRow>
          <FieldRow label="Protocol">
            <select className="select" value={cfg.protocol} onChange={set('protocol')}>
              <option value="udp">UDP (RFC 5426)</option>
              <option value="tcp">TCP (RFC 6587)</option>
              <option value="tls">TCP + TLS 1.3 (RFC 5425)</option>
            </select>
          </FieldRow>
          <FieldRow label="Port">
            <input className="input" type="number" min={1} max={65535}
                   value={cfg.port || 514} onChange={set('port')} />
          </FieldRow>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--space-2)' }}>
          <FieldRow label="Facility (RFC 5424 §6.2.1)">
            <select className="select" value={cfg.facility} onChange={set('facility')}>
              {SYSLOG_FACILITIES.map(f => <option key={f.value} value={f.value}>{f.label}</option>)}
            </select>
          </FieldRow>
          <FieldRow label="APP-NAME (syslog header)">
            <input className="input" value={cfg.app_name || ''} onChange={set('app_name')}
                   placeholder="dfir-fenrir" maxLength={48} />
          </FieldRow>
        </div>

        {isTls && (
          <div style={{
            border: '1px solid var(--border)', borderRadius: 'var(--radius)',
            padding: 'var(--space-3)', background: 'var(--surface-2)',
            display: 'flex', flexDirection: 'column', gap: 'var(--space-2)',
          }}>
            <div style={{ fontSize: 12, fontWeight: 700, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
              TLS settings
            </div>

            <FieldRow label="Verify server certificate">
              <label style={{ display: 'inline-flex', alignItems: 'center', gap: 8, fontSize: 13, cursor: 'pointer' }}>
                <input type="checkbox" checked={!!cfg.verify_tls} onChange={set('verify_tls')} />
                <span>Require valid certificate (disable only for testing)</span>
              </label>
            </FieldRow>

            <FieldRow label={`CA bundle (PEM, optional)${cfg.ca_bundle_set ? ' — set' : ''}`}>
              <textarea className="input" rows={3} value={draft.ca_bundle} onChange={setDraftK('ca_bundle')}
                placeholder={cfg.ca_bundle_set ? 'Paste new PEM to replace, leave blank to keep' : '-----BEGIN CERTIFICATE-----\n…'}
                style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }} />
              {cfg.ca_bundle_set && (
                <button type="button" className="btn ghost" style={{ fontSize: 11, marginTop: 4 }}
                        onClick={() => clearPem('ca_bundle')}>Remove saved CA bundle</button>
              )}
            </FieldRow>

            <FieldRow label={`Client certificate (PEM, mTLS — optional)${cfg.client_cert_set ? ' — set' : ''}`}>
              <textarea className="input" rows={3} value={draft.client_cert} onChange={setDraftK('client_cert')}
                placeholder={cfg.client_cert_set ? 'Paste new PEM to replace, leave blank to keep' : '-----BEGIN CERTIFICATE-----\n…'}
                style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }} />
              {cfg.client_cert_set && (
                <button type="button" className="btn ghost" style={{ fontSize: 11, marginTop: 4 }}
                        onClick={() => clearPem('client_cert')}>Remove client certificate</button>
              )}
            </FieldRow>

            <FieldRow label={`Client key (PEM, mTLS — optional)${cfg.client_key_set ? ' — set' : ''}`}>
              <textarea className="input" rows={3} value={draft.client_key} onChange={setDraftK('client_key')}
                placeholder={cfg.client_key_set ? '••••••••' : '-----BEGIN PRIVATE KEY-----\n…'}
                style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }} autoComplete="new-password" />
              {cfg.client_key_set && (
                <button type="button" className="btn ghost" style={{ fontSize: 11, marginTop: 4 }}
                        onClick={() => clearPem('client_key')}>Remove client key</button>
              )}
            </FieldRow>
          </div>
        )}

        {/* Runtime status strip */}
        <div style={{
          display: 'flex', flexWrap: 'wrap', gap: 'var(--space-3)',
          padding: 'var(--space-2) var(--space-3)', background: 'var(--surface-2)',
          border: '1px solid var(--border)', borderRadius: 'var(--radius)',
          fontSize: 12, color: 'var(--muted)',
        }}>
          <span>
            Status:{' '}
            {cfg.enabled
              ? (cfg.connected
                  ? <strong style={{ color: 'var(--ok)' }}>connected</strong>
                  : <strong style={{ color: 'var(--med)' }}>disconnected</strong>)
              : <span style={{ color: 'var(--dim)' }}>disabled</span>}
          </span>
          <span>Sent: <strong style={{ color: 'var(--text)' }}>{cfg.sent_count}</strong></span>
          <span>Dropped: <strong style={{ color: cfg.dropped_count ? 'var(--crit)' : 'var(--text)' }}>{cfg.dropped_count}</strong></span>
          {cfg.last_success_at && <span>Last send: <span style={{ fontFamily: 'var(--font-mono)' }}>{cfg.last_success_at}</span></span>}
          {cfg.last_error && (
            <span style={{ color: 'var(--crit)' }}>Last error: {cfg.last_error}</span>
          )}
        </div>

        {error && <div className="alert error" role="alert"><span className="alert-icon">!</span><span>{error}</span></div>}
        {ok    && <div className="alert info"  role="status"><span className="alert-icon">✓</span><span>{ok}</span></div>}

        <SaveRow busy={busy} extra={
          cfg.host ? (
            <button type="button" className="btn ghost" onClick={handleTest} disabled={busy || testing}>
              {testing ? 'Sending…' : 'Send test message'}
            </button>
          ) : null
        } />
      </form>
    </section>
  )
}
