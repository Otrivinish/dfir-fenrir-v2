import { useCallback, useEffect, useState } from 'react'
import { api } from '../../api/client.js'

export default function OperationalRoles() {
  const [roles, setRoles]   = useState([])
  const [loading, setLoading]         = useState(true)
  const [error, setError]             = useState(null)
  const [showInactive, setShowInactive] = useState(true)
  const [modal, setModal]   = useState(null)             // null | { mode, role? }

  const load = useCallback(async () => {
    setError(null)
    try {
      const list = await api.listOperationalRoles({ includeInactive: showInactive })
      setRoles(list)
    } catch (e) {
      setError(e.message || 'Could not load operational roles')
    } finally {
      setLoading(false)
    }
  }, [showInactive])

  useEffect(() => { load() }, [load])

  const toggleActive = async (r) => {
    try {
      await api.updateOperationalRole(r.id, { is_active: !r.is_active })
      await load()
    } catch (e) {
      setError(e.message || 'Could not toggle role')
    }
  }

  const onDelete = async (r) => {
    if (r.is_system) return
    if (!window.confirm(`Delete role "${r.label}"? This cannot be undone.`)) return
    try {
      await api.deleteOperationalRole(r.id)
      await load()
    } catch (e) {
      setError(e.message || 'Could not delete role')
    }
  }

  return (
    <section className="panel">
      <div className="panel-toolbar">
        <h2 className="panel-h">Operational roles</h2>
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
          <label style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 12, color: 'var(--muted)' }}>
            <input type="checkbox" checked={showInactive} onChange={(e) => setShowInactive(e.target.checked)} />
            Show inactive
          </label>
          <button type="button" className="btn primary" onClick={() => setModal({ mode: 'create' })}>
            + New role
          </button>
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
      ) : roles.length === 0 ? (
        <div className="panel-empty">
          <div className="panel-empty-mark" aria-hidden="true">★</div>
          <div>No operational roles defined.</div>
        </div>
      ) : (
        <table className="settings-table">
          <thead>
            <tr>
              <th style={{ width: 60 }}>Order</th>
              <th>Key</th>
              <th>Label</th>
              <th>Description</th>
              <th>Status</th>
              <th className="actions">Actions</th>
            </tr>
          </thead>
          <tbody>
            {roles.map(r => (
              <tr key={r.id} style={{ opacity: r.is_active ? 1 : 0.55 }}>
                <td style={{ fontFamily: 'var(--font-mono)', color: 'var(--muted)' }}>{r.sort_order}</td>
                <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>{r.key}</td>
                <td>
                  <b>{r.label}</b>
                  {r.is_system && <> <span className="pill">System</span></>}
                </td>
                <td title={r.description || ''} style={{ maxWidth: 320, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {r.description || <span style={{ color: 'var(--dim)' }}>—</span>}
                </td>
                <td>
                  {r.is_active
                    ? <span className="pill ok">Active</span>
                    : <span className="pill">Inactive</span>}
                </td>
                <td className="actions">
                  <span className="row-actions">
                    <button type="button" className="btn ghost" onClick={() => toggleActive(r)}>
                      {r.is_active ? 'Deactivate' : 'Activate'}
                    </button>
                    <button type="button" className="btn ghost" onClick={() => setModal({ mode: 'edit', role: r })}>
                      Edit
                    </button>
                    <button
                      type="button"
                      className="btn ghost"
                      onClick={() => onDelete(r)}
                      disabled={r.is_system}
                      title={r.is_system ? 'System roles cannot be deleted (deactivate instead)' : 'Delete role'}
                    >
                      Delete
                    </button>
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {modal && (
        <RoleModal
          mode={modal.mode}
          role={modal.role}
          onClose={() => setModal(null)}
          onSaved={() => { setModal(null); load() }}
        />
      )}
    </section>
  )
}

function RoleModal({ mode, role, onClose, onSaved }) {
  const isEdit = mode === 'edit'
  const isSystem = !!role?.is_system

  const [key, setKey]               = useState(role?.key || '')
  const [label, setLabel]           = useState(role?.label || '')
  const [description, setDesc]      = useState(role?.description || '')
  const [sortOrder, setSortOrder]   = useState(role?.sort_order ?? 100)
  const [busy, setBusy]             = useState(false)
  const [error, setError]           = useState(null)

  useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  const onSubmit = async (e) => {
    e.preventDefault()
    setError(null)
    setBusy(true)
    try {
      if (isEdit) {
        const payload = { sort_order: Number(sortOrder) }
        if (!isSystem) {
          payload.label       = label.trim()
          payload.description = description.trim() || null
        }
        await api.updateOperationalRole(role.id, payload)
      } else {
        if (!/^[a-z][a-z0-9_]*$/.test(key)) {
          setError('Key must be lowercase letters/numbers/underscores, starting with a letter.')
          setBusy(false); return
        }
        await api.createOperationalRole({
          key: key.trim(),
          label: label.trim(),
          description: description.trim() || null,
          sort_order: Number(sortOrder),
        })
      }
      onSaved()
    } catch (err) {
      setError(err.message || 'Could not save role')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="modal-backdrop">
      <div className="modal" role="dialog" aria-labelledby="role-modal-title">
        <div className="modal-head">
          <h2 id="role-modal-title">{isEdit ? 'Edit operational role' : 'New operational role'}</h2>
          <button className="modal-close" type="button" onClick={onClose} aria-label="Close">×</button>
        </div>
        <form onSubmit={onSubmit}>
          <div className="modal-body">
            <div className="form">
              {!isEdit && (
                <div className="field">
                  <label className="field-label" htmlFor="role-key">Key (lowercase, snake_case)</label>
                  <input id="role-key" className="input" value={key} onChange={(e) => setKey(e.target.value)}
                         autoFocus required pattern="^[a-z][a-z0-9_]*$" maxLength={64}
                         placeholder="e.g. handler_alpha" />
                </div>
              )}
              {isEdit && (
                <div className="field">
                  <label className="field-label">Key</label>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: 13, color: 'var(--muted)' }}>{role.key}</div>
                </div>
              )}

              <div className="field">
                <label className="field-label" htmlFor="role-label">Label</label>
                <input
                  id="role-label"
                  className="input"
                  value={label}
                  onChange={(e) => setLabel(e.target.value)}
                  required minLength={1} maxLength={128}
                  disabled={isEdit && isSystem}
                  title={isEdit && isSystem ? 'System role labels are fixed' : undefined}
                />
              </div>

              <div className="field">
                <label className="field-label" htmlFor="role-desc">Description (optional)</label>
                <textarea
                  id="role-desc"
                  className="input"
                  value={description}
                  onChange={(e) => setDesc(e.target.value)}
                  rows={3}
                  disabled={isEdit && isSystem}
                  title={isEdit && isSystem ? 'System role descriptions are fixed' : undefined}
                />
              </div>

              <div className="field">
                <label className="field-label" htmlFor="role-sort">Sort order</label>
                <input id="role-sort" className="input" type="number" min={0} max={9999}
                       value={sortOrder} onChange={(e) => setSortOrder(e.target.value)} style={{ maxWidth: 120 }} />
                <div className="field-hint">Lower numbers list first.</div>
              </div>

              {isEdit && isSystem && (
                <div className="alert info" role="status">
                  <span className="alert-icon">i</span>
                  <span>This is a system role. Only sort order can be edited; label and description are fixed.</span>
                </div>
              )}

              {error && (
                <div className="alert error" role="alert">
                  <span className="alert-icon">!</span>
                  <span>{error}</span>
                </div>
              )}
            </div>
          </div>
          <div className="modal-foot">
            <button type="button" className="btn ghost" onClick={onClose} disabled={busy}>Cancel</button>
            <button type="submit" className="btn primary" disabled={busy}>
              {busy ? 'Saving…' : (isEdit ? 'Save changes' : 'Create role')}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
