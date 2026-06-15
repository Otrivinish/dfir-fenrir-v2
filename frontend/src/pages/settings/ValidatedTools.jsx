import { useCallback, useEffect, useState } from 'react'
import { api } from '../../api/client.js'

// Validated-tools registry (ISO/IEC 27041, GS-1). Admin-maintained catalog of
// validated forensic tools/methods; the acquisition + examination wizards pick from it.

export default function ValidatedTools() {
  const [tools, setTools]   = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError]   = useState(null)
  const [busy, setBusy]     = useState(false)

  const [form, setForm] = useState({
    name: '', version: '', validation_ref: '', scope: '', validated_by: '', validated_at: '', notes: '',
  })
  const set = (k) => (e) => setForm((f) => ({ ...f, [k]: e.target.value }))

  const load = useCallback(async () => {
    setLoading(true); setError(null)
    try {
      const r = await api.listValidatedTools({ include_inactive: true })
      setTools(r.items || [])
    } catch (e) {
      setError(e.message || 'Could not load validated tools')
    } finally {
      setLoading(false)
    }
  }, [])
  useEffect(() => { load() }, [load])

  const add = async (e) => {
    e.preventDefault()
    if (!form.name.trim() || !form.version.trim()) { setError('Name and version are required.'); return }
    setBusy(true); setError(null)
    try {
      await api.createValidatedTool({
        name: form.name.trim(), version: form.version.trim(),
        validation_ref: form.validation_ref.trim() || null,
        scope: form.scope.trim() || null,
        validated_by: form.validated_by.trim() || null,
        validated_at: form.validated_at || null,
        notes: form.notes.trim() || null,
      })
      setForm({ name: '', version: '', validation_ref: '', scope: '', validated_by: '', validated_at: '', notes: '' })
      await load()
    } catch (e2) {
      setError(e2.message || 'Could not add tool')
    } finally {
      setBusy(false)
    }
  }

  const toggleActive = async (t) => {
    setBusy(true); setError(null)
    try { await api.updateValidatedTool(t.id, { is_active: !t.is_active }); await load() }
    catch (e) { setError(e.message || 'Update failed') }
    finally { setBusy(false) }
  }

  const remove = async (t) => {
    if (!window.confirm(`Delete validated tool "${t.name} ${t.version}"? Acquisitions already referencing it keep their recorded validation_ref.`)) return
    setBusy(true); setError(null)
    try { await api.deleteValidatedTool(t.id); await load() }
    catch (e) { setError(e.message || 'Delete failed') }
    finally { setBusy(false) }
  }

  return (
    <section className="panel">
      <div className="panel-toolbar">
        <h2 className="panel-h">Validated tools <span style={{ fontWeight: 400, color: 'var(--muted)', fontSize: 12 }}>· ISO/IEC 27041 registry</span></h2>
      </div>
      <p style={{ color: 'var(--muted)', fontSize: 13, margin: '0 0 var(--space-3)' }}>
        A governed catalog of validated forensic tools/methods. The acquisition and
        examination wizards let analysts pick from this list — picking a registered
        tool records the acquisition as <strong>validated</strong> with its reference,
        instead of a free-text claim. Tools not listed are still usable but flagged
        unvalidated in the provenance score.
      </p>

      {error && (
        <div className="alert error" role="alert" style={{ marginBottom: 'var(--space-3)' }}>
          <span className="alert-icon">!</span><span>{error}</span>
        </div>
      )}

      {/* Add form */}
      <form onSubmit={add} className="form" style={{ marginBottom: 'var(--space-4)' }}>
        <div className="form-row">
          <div className="field">
            <label className="field-label" htmlFor="vt-name">Tool name *</label>
            <input id="vt-name" className="input" value={form.name} onChange={set('name')} maxLength={128}
                   placeholder="e.g. FTK Imager" />
          </div>
          <div className="field">
            <label className="field-label" htmlFor="vt-ver">Version *</label>
            <input id="vt-ver" className="input" value={form.version} onChange={set('version')} maxLength={64}
                   placeholder="e.g. 4.7.1" style={{ fontFamily: 'var(--font-mono)' }} />
          </div>
        </div>
        <div className="form-row">
          <div className="field">
            <label className="field-label" htmlFor="vt-ref">Validation reference</label>
            <input id="vt-ref" className="input" value={form.validation_ref} onChange={set('validation_ref')} maxLength={256}
                   placeholder="e.g. NIST CFTT report / lab VR-2026-014 / URL" />
          </div>
          <div className="field">
            <label className="field-label" htmlFor="vt-date">Validated on</label>
            <input id="vt-date" className="input" type="date" value={form.validated_at} onChange={set('validated_at')} />
          </div>
        </div>
        <div className="form-row">
          <div className="field">
            <label className="field-label" htmlFor="vt-by">Validated by</label>
            <input id="vt-by" className="input" value={form.validated_by} onChange={set('validated_by')} maxLength={128}
                   placeholder="e.g. Lab QA / analyst name" />
          </div>
          <div className="field">
            <label className="field-label" htmlFor="vt-scope">Scope</label>
            <input id="vt-scope" className="input" value={form.scope} onChange={set('scope')} maxLength={4096}
                   placeholder="e.g. disk imaging of SATA/NVMe; not validated for mobile" />
          </div>
        </div>
        <button type="submit" className="btn primary" disabled={busy}>{busy ? 'Saving…' : 'Add validated tool'}</button>
      </form>

      {/* List */}
      {loading ? (
        <div className="panel-empty"><div>Loading…</div></div>
      ) : tools.length === 0 ? (
        <div style={{ color: 'var(--muted)', fontSize: 13 }}>No validated tools yet. Add the tools your lab has validated.</div>
      ) : (
        <table className="table">
          <thead>
            <tr><th>Tool</th><th>Version</th><th>Reference</th><th>Validated by / on</th><th>Active</th><th></th></tr>
          </thead>
          <tbody>
            {tools.map((t) => (
              <tr key={t.id} style={{ opacity: t.is_active ? 1 : 0.55 }}>
                <td style={{ fontWeight: 600 }}>{t.name}</td>
                <td style={{ fontFamily: 'var(--font-mono)' }}>{t.version}</td>
                <td style={{ fontSize: 12, color: 'var(--muted)' }} title={t.scope || ''}>{t.validation_ref || '—'}</td>
                <td style={{ fontSize: 12, color: 'var(--muted)' }}>{[t.validated_by, t.validated_at].filter(Boolean).join(' · ') || '—'}</td>
                <td>
                  <button type="button" className="btn ghost" style={{ fontSize: 11, padding: '2px 8px' }}
                          onClick={() => toggleActive(t)} disabled={busy}>
                    {t.is_active ? '✓ active' : 'inactive'}
                  </button>
                </td>
                <td>
                  <button type="button" className="btn ghost" style={{ fontSize: 11, padding: '2px 8px', color: 'var(--crit)' }}
                          onClick={() => remove(t)} disabled={busy}>Delete</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  )
}
