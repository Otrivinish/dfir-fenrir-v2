import { useEffect, useState } from 'react'
import { api } from '../../api/client.js'

// Admin: prefix for new incident references (PREFIX-YYYY-NNNNN). Existing
// references are immutable, so a change only affects incidents created after it.
export default function IncidentReference() {
  const [data,    setData]    = useState(null)
  const [prefix,  setPrefix]  = useState('')
  const [saving,  setSaving]  = useState(false)
  const [error,   setError]   = useState(null)
  const [saved,   setSaved]   = useState(false)

  useEffect(() => {
    api.getIncidentRefSettings()
      .then(d => { setData(d); setPrefix(d.prefix) })
      .catch(e => setError(e.message || 'Could not load incident-reference settings'))
  }, [])

  const valid = /^[A-Z][A-Z0-9]{1,9}$/.test(prefix)
  const dirty = data && prefix !== data.prefix

  const save = async (e) => {
    e.preventDefault()
    if (!valid || !dirty) return
    setSaving(true); setError(null); setSaved(false)
    try {
      const d = await api.updateIncidentRefSettings(prefix)
      setData(d); setPrefix(d.prefix); setSaved(true)
    } catch (err) {
      setError(err.message || 'Save failed')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div>
      <div style={{ marginBottom: 'var(--space-4)' }}>
        <h2 style={{ margin: 0, fontSize: 18, fontFamily: 'var(--font-heading)' }}>Incident Reference</h2>
        <p style={{ color: 'var(--muted)', fontSize: 13, marginTop: 'var(--space-1)', marginBottom: 0 }}>
          Every incident gets a reference once, when it is created, and it never changes — so
          references in issued reports, LE packages and audit exports stay valid. Format:{' '}
          <code>PREFIX-YYYY-NNNNN</code> (UTC creation year; a global counter that never resets).
          Incidents created before this format keep their <code>INC-NNNN</code> reference.
        </p>
      </div>

      {error && (
        <div className="alert error" role="alert" style={{ marginBottom: 'var(--space-3)' }}>
          <span className="alert-icon">!</span><span>{error}</span>
        </div>
      )}

      {data && (
        <form className="panel" onSubmit={save} style={{ maxWidth: 560 }}>
          <div className="field">
            <label className="field-label" htmlFor="ref-prefix">Prefix for new incidents</label>
            <input
              id="ref-prefix"
              className="input"
              value={prefix}
              onChange={e => { setPrefix(e.target.value.toUpperCase()); setSaved(false) }}
              maxLength={10}
              autoComplete="off"
              spellCheck={false}
              style={{ fontFamily: 'var(--font-mono)', maxWidth: 200 }}
              aria-invalid={!valid}
            />
            <div className="field-hint">
              2–10 characters: a letter, then letters or digits (e.g. INC, ACME, SOC1). Identifies
              this FENRIR instance when references are shared with CERTs, insurers or law enforcement.
            </div>
          </div>

          <div style={{ marginTop: 'var(--space-3)', fontSize: 13 }}>
            <span style={{ color: 'var(--muted)' }}>Next incident (saved prefix): </span>
            <code style={{ fontSize: 13 }}>{data.next_ref_preview}</code>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', marginTop: 'var(--space-3)' }}>
            <button type="submit" className="btn primary" disabled={!valid || !dirty || saving}>
              {saving ? 'Saving…' : 'Save prefix'}
            </button>
            {saved && <span style={{ fontSize: 12, color: 'var(--ok)' }}>Saved — applies to new incidents only.</span>}
            {!valid && <span style={{ fontSize: 12, color: 'var(--crit)' }}>Invalid prefix.</span>}
          </div>
        </form>
      )}

      <ExhibitIdentifiers />
    </div>
  )
}

// EI — the naming convention for automatically assigned exhibit identifiers. The server checks the template
// (422 invalid_identifier_template, naming the rule) and gives the example; nothing is checked here.
function ExhibitIdentifiers() {
  const [data,     setData]     = useState(null)
  const [template, setTemplate] = useState('')
  const [saving,   setSaving]   = useState(false)
  const [error,    setError]    = useState(null)
  const [saved,    setSaved]    = useState(false)

  useEffect(() => {
    api.getEvidenceIdentifierSettings()
      .then(d => { setData(d); setTemplate(d.template) })
      .catch(e => setError(e.message || 'Could not load the exhibit identifier settings'))
  }, [])

  const dirty = data && template !== data.template

  const save = async (e) => {
    e.preventDefault()
    if (!dirty) return
    setSaving(true); setError(null); setSaved(false)
    try {
      const d = await api.updateEvidenceIdentifierSettings(template)
      setData(d); setTemplate(d.template); setSaved(true)
    } catch (err) {
      setError(err.message || 'Save failed')
    } finally {
      setSaving(false)
    }
  }

  return (
    <section style={{ marginTop: 'var(--space-5)' }} data-testid="exhibit-identifiers">
      <h3 style={{ margin: 0, fontSize: 16, fontFamily: 'var(--font-heading)' }}>Exhibit identifiers</h3>
      <p style={{ color: 'var(--muted)', fontSize: 13, marginTop: 'var(--space-1)' }}>
        When an exhibit is registered without an identifier, FENRIR assigns one from this convention. Drafts FENRIR
        registers itself (supporting documents, Email, Network capture and Browser history uploads) use it too.
        Identifiers already assigned never change.
      </p>

      {error && (
        <div className="alert error" role="alert" style={{ marginBottom: 'var(--space-3)' }}>
          <span className="alert-icon">!</span><span>{error}</span>
        </div>
      )}

      {data && (
        <form className="panel" onSubmit={save} style={{ maxWidth: 560 }}>
          <div className="field">
            <label className="field-label" htmlFor="ei-template">Convention</label>
            <input
              id="ei-template"
              className="input"
              value={template}
              onChange={e => { setTemplate(e.target.value); setSaved(false) }}
              autoComplete="off"
              spellCheck={false}
              style={{ fontFamily: 'var(--font-mono)' }}
            />
          </div>

          <table className="settings-table compact" style={{ marginTop: 'var(--space-2)' }}>
            <tbody>
              {data.tokens.map(t => (
                <tr key={t.token}>
                  <td style={{ whiteSpace: 'nowrap' }}><code>{t.token}</code></td>
                  <td style={{ color: 'var(--muted)', fontSize: 12 }}>{t.description}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <div className="field-hint">
            Other text: letters, digits, <code>.</code> <code>_</code> <code>-</code>. At most 64 characters.
          </div>

          <div style={{ marginTop: 'var(--space-3)', fontSize: 13 }}>
            <span style={{ color: 'var(--muted)' }}>Next exhibit of {data.example_incident_ref} (saved convention): </span>
            <code style={{ fontSize: 13 }} data-testid="ei-example">{data.example}</code>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', marginTop: 'var(--space-3)' }}>
            <button type="submit" className="btn primary" disabled={!dirty || saving}>
              {saving ? 'Saving…' : 'Save convention'}
            </button>
            {saved && <span style={{ fontSize: 12, color: 'var(--ok)' }}>Saved — applies to new exhibits only.</span>}
          </div>
        </form>
      )}
    </section>
  )
}
