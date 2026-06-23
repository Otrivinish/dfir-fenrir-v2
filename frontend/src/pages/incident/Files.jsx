import { useCallback, useEffect, useRef, useState } from 'react'
import { useOutletContext } from 'react-router-dom'
import { api } from '../../api/client.js'
import { formatLocal } from '../../lib/datetime.js'

// Incident "Files" store — a working area for NON-malicious supporting material
// (screenshots, raw logs, notes). Shares one encrypted store with entity files;
// a file may be linked to an entity or stand alone at the incident level.

function fmtSize(bytes) {
  if (bytes == null) return '—'
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

function fileType(f) {
  const name = f.original_name || ''
  const dot = name.lastIndexOf('.')
  if (dot > 0 && dot < name.length - 1) return name.slice(dot + 1).toUpperCase()
  return f.content_type || '—'
}

export default function Files() {
  const { inc } = useOutletContext()
  const isClosed = inc?.status === 'closed'

  const [files, setFiles]       = useState([])
  const [entities, setEntities] = useState([])
  const [loading, setLoading]   = useState(true)
  const [error, setError]       = useState(null)
  const [busy, setBusy]         = useState(false)
  const [linkTarget, setLinkTarget] = useState(null) // file being (un)linked
  const fileInputRef = useRef(null)

  const load = useCallback(async () => {
    setError(null)
    try {
      const data = await api.listIncidentFiles(inc.id)
      setFiles(data.items || [])
    } catch (e) {
      setError(e.message || 'Could not load files')
    } finally {
      setLoading(false)
    }
  }, [inc.id])

  useEffect(() => { load() }, [load])
  useEffect(() => {
    api.listEntities(inc.id, { limit: 200 }).then(r => setEntities(r.items || [])).catch(() => {})
  }, [inc.id])

  const onPickFiles = async (e) => {
    const picked = Array.from(e.target.files || [])
    e.target.value = '' // allow re-selecting the same file
    if (picked.length === 0) return
    setBusy(true); setError(null)
    try {
      for (const f of picked) {
        await api.uploadIncidentFile(inc.id, f)
      }
      await load()
    } catch (err) {
      setError(err.message || 'Upload failed')
    } finally {
      setBusy(false)
    }
  }

  const onRename = async (f) => {
    const next = window.prompt('Rename file', f.original_name)
    if (next == null) return
    const name = next.trim()
    if (!name || name === f.original_name) return
    setBusy(true); setError(null)
    try {
      await api.updateIncidentFile(inc.id, f.id, { original_name: name })
      await load()
    } catch (err) {
      setError(err.message || 'Could not rename')
    } finally {
      setBusy(false)
    }
  }

  const onDelete = async (f) => {
    if (!window.confirm(`Delete this file?\n\n${f.original_name}`)) return
    setBusy(true); setError(null)
    try {
      await api.deleteIncidentFile(inc.id, f.id)
      await load()
    } catch (err) {
      setError(err.message || 'Could not delete file')
    } finally {
      setBusy(false)
    }
  }

  const onSaveLink = async (f, entityId) => {
    setBusy(true); setError(null)
    try {
      await api.updateIncidentFile(inc.id, f.id, { entity_id: entityId || null })
      setLinkTarget(null)
      await load()
    } catch (err) {
      setError(err.message || 'Could not update link')
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="panel">
      <div className="panel-toolbar">
        <h2 className="panel-h">Files</h2>
        <input
          ref={fileInputRef}
          type="file"
          multiple
          style={{ display: 'none' }}
          onChange={onPickFiles}
        />
        <button
          type="button"
          className="btn primary"
          onClick={() => fileInputRef.current?.click()}
          disabled={isClosed || busy}
          title={isClosed ? 'Closed incidents are read-only' : 'Upload files (non-malicious — screenshots, logs, notes)'}
        >
          {busy ? 'Working…' : '+ Upload files'}
        </button>
      </div>

      <p style={{ fontSize: 12, color: 'var(--dim)', marginBottom: 'var(--space-3)' }}>
        Working store for non-malicious supporting material. Encrypted at rest. Not chain-of-custody evidence
        and not for suspected-malicious samples — use Evidence or Artifacts for those.
      </p>

      {error && (
        <div className="alert error" role="alert">
          <span className="alert-icon">!</span><span>{error}</span>
        </div>
      )}

      {loading ? (
        <div className="panel-empty"><div>Loading…</div></div>
      ) : files.length === 0 ? (
        <div className="panel-empty">
          <div className="panel-empty-mark" aria-hidden="true">▤</div>
          <div>No files yet.</div>
          {!isClosed && <div style={{ color: 'var(--dim)', fontSize: 12 }}>Click "Upload files" to add screenshots, logs, or notes.</div>}
        </div>
      ) : (
        <table className="settings-table">
          <thead>
            <tr>
              <th>Name</th>
              <th style={{ width: 80 }}>Type</th>
              <th style={{ width: 90 }}>Size</th>
              <th style={{ width: 150 }}>Added</th>
              <th style={{ width: 130 }}>Added by</th>
              <th style={{ width: 150 }}>Entity</th>
              <th className="actions">Actions</th>
            </tr>
          </thead>
          <tbody>
            {files.map(f => (
              <tr key={f.id}>
                <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12, wordBreak: 'break-all' }}>
                  {f.original_name}
                </td>
                <td><span className="pill" style={{ fontSize: 10 }}>{fileType(f)}</span></td>
                <td style={{ fontSize: 12, color: 'var(--muted)', fontFamily: 'var(--font-mono)' }}>{fmtSize(f.file_size)}</td>
                <td
                  title={formatLocal(f.uploaded_at)}
                  style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--muted)' }}
                >
                  {formatLocal(f.uploaded_at).slice(0, 16)}
                </td>
                <td style={{ fontSize: 12, color: 'var(--muted)' }}>{f.uploaded_by_username || '—'}</td>
                <td style={{ fontSize: 12 }}>
                  {f.entity_name
                    ? <span className="pill" title={`Linked to ${f.entity_name}`}>{f.entity_name}</span>
                    : <span style={{ color: 'var(--dim)' }}>—</span>}
                </td>
                <td className="actions">
                  <a
                    className="btn ghost"
                    href={api.incidentFileDownloadUrl(inc.id, f.id)}
                    style={{ fontSize: 11 }}
                    title="Download"
                  >
                    Download
                  </a>
                  <button type="button" className="btn ghost" onClick={() => setLinkTarget(f)} disabled={isClosed} style={{ fontSize: 11 }}>
                    {f.entity_id ? 'Re-link' : 'Link'}
                  </button>
                  <button type="button" className="btn ghost" onClick={() => onRename(f)} disabled={isClosed || busy} style={{ fontSize: 11 }}>
                    Rename
                  </button>
                  <button type="button" className="btn ghost" onClick={() => onDelete(f)} disabled={isClosed || busy}>
                    Delete
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {linkTarget && (
        <LinkModal
          file={linkTarget}
          entities={entities}
          onClose={() => setLinkTarget(null)}
          onSave={(entityId) => onSaveLink(linkTarget, entityId)}
          busy={busy}
        />
      )}
    </section>
  )
}

// ── Link-to-entity modal ───────────────────────────────────────────────────────

function LinkModal({ file, entities, onClose, onSave, busy }) {
  const [entityId, setEntityId] = useState(file.entity_id || '')

  useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape' && !busy) onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [busy, onClose])

  return (
    <div className="modal-backdrop">
      <div className="modal" role="dialog" aria-labelledby="link-file-title" style={{ maxWidth: 440 }}>
        <div className="modal-head">
          <h2 id="link-file-title">Link file to entity</h2>
          <button type="button" className="modal-close" onClick={onClose} disabled={busy} aria-label="Close">×</button>
        </div>
        <div className="modal-body">
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--muted)', marginBottom: 'var(--space-3)', wordBreak: 'break-all' }}>
            {file.original_name}
          </div>
          <div className="field">
            <label className="field-label" htmlFor="link-entity">Entity</label>
            <select id="link-entity" className="select" value={entityId} onChange={(e) => setEntityId(e.target.value)}>
              <option value="">— none (unlink) —</option>
              {entities.map(en => (
                <option key={en.id} value={en.id}>{en.type}: {en.name || en.value}</option>
              ))}
            </select>
          </div>
        </div>
        <div className="modal-foot">
          <button type="button" className="btn ghost" onClick={onClose} disabled={busy}>Cancel</button>
          <button type="button" className="btn primary" onClick={() => onSave(entityId)} disabled={busy}>
            {busy ? 'Saving…' : 'Save'}
          </button>
        </div>
      </div>
    </div>
  )
}
