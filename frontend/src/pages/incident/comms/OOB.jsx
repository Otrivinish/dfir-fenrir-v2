import { useState, useEffect, useCallback } from 'react'
import { useOutletContext } from 'react-router-dom'
import { api } from '../../../api/client.js'
import { relative, formatLocal } from '../../../lib/datetime.js'

const CHANNEL_LABELS = {
  personal_mobile: 'Personal Mobile',
  signal:          'Signal',
  whatsapp:        'WhatsApp',
  personal_email:  'Personal Email',
  in_person:       'In Person',
  secure_fax:      'Secure Fax',
  courier:         'Courier',
  third_party_ir:  '3rd-Party IR',
}

const CHANNEL_OPTS = Object.entries(CHANNEL_LABELS).map(([value, label]) => ({ value, label }))

const EMPTY_FORM = {
  stakeholder_name:    '',
  channel:             'personal_mobile',
  direction:           'outbound',
  summary:             '',
  verified:            false,
  verification_method: '',
}

export default function OOB() {
  const { inc, isClosed, refresh } = useOutletContext()

  const [darkOp,      setDarkOp]      = useState(inc.dark_operation)
  const [passphrase,  setPassphrase]  = useState(null)
  const [logs,        setLogs]        = useState([])
  const [error,       setError]       = useState('')
  const [toggling,    setToggling]    = useState(false)
  const [regenning,   setRegenning]   = useState(false)
  const [copied,      setCopied]      = useState(false)
  const [formOpen,    setFormOpen]    = useState(false)
  const [submitting,  setSubmitting]  = useState(false)
  const [form,        setForm]        = useState(EMPTY_FORM)

  const loadPassphrase = useCallback(async () => {
    try {
      const p = await api.getPassphrase(inc.id)
      setPassphrase(p.passphrase)
    } catch { /* non-critical */ }
  }, [inc.id])

  const loadLogs = useCallback(async () => {
    try {
      const d = await api.listOOBLog(inc.id)
      setLogs(d.items)
    } catch (e) {
      setError(e.message || 'Failed to load OOB log.')
    }
  }, [inc.id])

  useEffect(() => {
    loadPassphrase()
    loadLogs()
  }, [loadPassphrase, loadLogs])

  // Keep local darkOp in sync if parent refreshes inc
  useEffect(() => { setDarkOp(inc.dark_operation) }, [inc.dark_operation])

  const toggleDarkOp = async () => {
    setToggling(true)
    try {
      const res = await api.toggleDarkOperation(inc.id, !darkOp)
      setDarkOp(res.dark_operation)
      refresh()
    } catch (e) {
      setError(e.message || 'Failed to update dark operation.')
    } finally {
      setToggling(false)
    }
  }

  const regenerate = async () => {
    if (!confirm('Generate a new passphrase? The old one will be invalidated.')) return
    setRegenning(true)
    try {
      const p = await api.regeneratePassphrase(inc.id)
      setPassphrase(p.passphrase)
    } catch (e) {
      setError(e.message || 'Failed to regenerate passphrase.')
    } finally {
      setRegenning(false)
    }
  }

  const copyPassphrase = async () => {
    if (!passphrase) return
    try {
      await navigator.clipboard.writeText(passphrase)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch { /* silently ignore */ }
  }

  const setFormField = (k) => (e) => {
    const v = e.target.type === 'checkbox' ? e.target.checked : e.target.value
    setForm(f => ({ ...f, [k]: v }))
  }

  const submitLog = async (e) => {
    e.preventDefault()
    if (!form.stakeholder_name.trim() || !form.summary.trim()) return
    setSubmitting(true)
    try {
      const entry = await api.createOOBLog(inc.id, {
        ...form,
        stakeholder_name:    form.stakeholder_name.trim(),
        summary:             form.summary.trim(),
        verification_method: form.verification_method.trim() || null,
      })
      setLogs(prev => [entry, ...prev])
      setForm(EMPTY_FORM)
      setFormOpen(false)
    } catch (e) {
      setError(e.message || 'Failed to log OOB communication.')
    } finally {
      setSubmitting(false)
    }
  }

  const delLog = async (logId) => {
    if (!confirm('Delete this log entry?')) return
    try {
      await api.deleteOOBLog(inc.id, logId)
      setLogs(prev => prev.filter(l => l.id !== logId))
    } catch (e) {
      setError(e.message || 'Failed to delete log entry.')
    }
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-5)' }}>
      {error && (
        <div className="alert error" role="alert">
          <span className="alert-icon">!</span><span>{error}</span>
        </div>
      )}

      {/* ── Dark Operation ─────────────────────────────────────────────── */}
      <section>
        <div className="panel-h">Dark Operation</div>
        <label style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', cursor: isClosed ? 'default' : 'pointer', width: 'fit-content' }}>
          <input
            type="checkbox"
            checked={darkOp}
            onChange={isClosed ? undefined : toggleDarkOp}
            disabled={isClosed || toggling}
            style={{ accentColor: 'var(--crit)', width: 16, height: 16 }}
          />
          <span style={{ fontWeight: 600, color: darkOp ? 'var(--crit)' : 'var(--text)', fontSize: 14 }}>
            {darkOp ? 'ACTIVE — communication blackout in effect' : 'Inactive'}
          </span>
        </label>
        <p style={{ fontSize: 13, color: 'var(--muted)', marginTop: 'var(--space-2)', maxWidth: 560 }}>
          Activating dark operation mode displays a prominent warning banner on the incident and
          restricts all external communications. Verify all callers using the passphrase below.
        </p>
      </section>

      {/* ── Passphrase ─────────────────────────────────────────────────── */}
      <section>
        <div className="panel-h">Out-of-Band Passphrase</div>
        <p style={{ fontSize: 13, color: 'var(--muted)', marginBottom: 'var(--space-3)', maxWidth: 560 }}>
          Shared verbally to verify caller identity. Format:{' '}
          <code style={{ fontFamily: 'var(--font-mono)' }}>ADJECTIVE-ANIMAL-NNNN</code>.
          Regenerate after each engagement.
        </p>
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)', flexWrap: 'wrap' }}>
          <code style={{
            fontFamily: 'var(--font-mono)',
            fontSize: 22,
            letterSpacing: '0.06em',
            color: 'var(--accent)',
            background: 'var(--surface-2)',
            padding: '8px 16px',
            borderRadius: 'var(--radius)',
            border: '1px solid var(--border)',
          }}>
            {passphrase ?? '—'}
          </code>
          <button className="btn" type="button" onClick={copyPassphrase} disabled={!passphrase}>
            {copied ? 'Copied!' : 'Copy'}
          </button>
          {!isClosed && (
            <button className="btn" type="button" onClick={regenerate} disabled={regenning}>
              {regenning ? 'Regenerating…' : 'Regenerate'}
            </button>
          )}
        </div>
      </section>

      {/* ── OOB Communications Log ─────────────────────────────────────── */}
      <section>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 'var(--space-3)' }}>
          <div className="panel-h" style={{ margin: 0 }}>OOB Communications Log</div>
          {!isClosed && (
            <button className="btn" type="button" onClick={() => setFormOpen(o => !o)}>
              {formOpen ? 'Cancel' : '+ Log communication'}
            </button>
          )}
        </div>

        {formOpen && (
          <form
            onSubmit={submitLog}
            style={{
              background: 'var(--surface)',
              border: '1px solid var(--border)',
              borderRadius: 'var(--radius)',
              padding: 'var(--space-4)',
              marginBottom: 'var(--space-4)',
            }}
          >
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 'var(--space-3)', marginBottom: 'var(--space-3)' }}>
              <div>
                <label className="field-label" style={{ display: 'block', marginBottom: 4 }}>Stakeholder</label>
                <input
                  className="input"
                  value={form.stakeholder_name}
                  onChange={setFormField('stakeholder_name')}
                  placeholder="Full name or org"
                  required
                  maxLength={255}
                />
              </div>
              <div>
                <label className="field-label" style={{ display: 'block', marginBottom: 4 }}>Channel</label>
                <select className="input" value={form.channel} onChange={setFormField('channel')}>
                  {CHANNEL_OPTS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
                </select>
              </div>
              <div>
                <label className="field-label" style={{ display: 'block', marginBottom: 4 }}>Direction</label>
                <select className="input" value={form.direction} onChange={setFormField('direction')}>
                  <option value="outbound">Outbound</option>
                  <option value="inbound">Inbound</option>
                </select>
              </div>
            </div>

            <div style={{ marginBottom: 'var(--space-3)' }}>
              <label className="field-label" style={{ display: 'block', marginBottom: 4 }}>Summary</label>
              <textarea
                className="input"
                value={form.summary}
                onChange={setFormField('summary')}
                rows={3}
                style={{ width: '100%', resize: 'vertical' }}
                required
                maxLength={4096}
              />
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-4)', marginBottom: 'var(--space-3)', flexWrap: 'wrap' }}>
              <label style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', fontSize: 13, cursor: 'pointer' }}>
                <input
                  type="checkbox"
                  checked={form.verified}
                  onChange={setFormField('verified')}
                  style={{ accentColor: 'var(--accent)' }}
                />
                Identity verified via passphrase
              </label>
              {form.verified && (
                <input
                  className="input"
                  style={{ flex: 1, minWidth: 200 }}
                  value={form.verification_method}
                  onChange={setFormField('verification_method')}
                  placeholder="Verification method detail (optional)"
                  maxLength={128}
                />
              )}
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
              <button
                className="btn primary"
                type="submit"
                disabled={submitting || !form.stakeholder_name.trim() || !form.summary.trim()}
              >{submitting ? 'Logging…' : 'Log entry'}</button>
            </div>
          </form>
        )}

        {logs.length === 0 ? (
          <div className="panel-empty" style={{ padding: 'var(--space-4) 0' }}>No OOB communications logged.</div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
            {logs.map(l => (
              <div key={l.id} className="oob-log-entry">
                <div className="oob-log-header">
                  <span className="oob-stakeholder">{l.stakeholder_name}</span>
                  <span className={`pill ${l.direction === 'outbound' ? 'pill-gray' : 'pill-ok'}`} style={{ fontSize: 10 }}>
                    {l.direction}
                  </span>
                  <span className="pill pill-gray" style={{ fontSize: 10 }}>
                    {CHANNEL_LABELS[l.channel] ?? l.channel}
                  </span>
                  {l.verified && (
                    <span className="pill pill-ok" style={{ fontSize: 10 }}>✓ verified</span>
                  )}
                  <span className="oob-log-meta" title={formatLocal(l.created_at)}>
                    {relative(l.created_at)}
                  </span>
                  {l.created_by_username && (
                    <span className="oob-log-meta">by {l.created_by_username}</span>
                  )}
                  {!isClosed && (
                    <button
                      className="btn-link danger"
                      type="button"
                      onClick={() => delLog(l.id)}
                      style={{ marginLeft: 'auto' }}
                    >Delete</button>
                  )}
                </div>
                <div className="oob-log-summary">{l.summary}</div>
                {l.verification_method && (
                  <div className="oob-log-verify">Verification: {l.verification_method}</div>
                )}
              </div>
            ))}
          </div>
        )}
      </section>
    </div>
  )
}
