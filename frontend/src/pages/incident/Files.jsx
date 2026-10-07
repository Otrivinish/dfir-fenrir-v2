import { useCallback, useEffect, useRef, useState } from 'react'
import { useOutletContext } from 'react-router-dom'
import { api } from '../../api/client.js'
import { useDialogFocus } from '../../hooks/useDialogFocus.js'
import { formatLocal } from '../../lib/datetime.js'
import { ExhibitPill, FileHash, FileReasonModal, RegisterExhibitModal, fileRefsMessage } from '../../components/SupportingFile.jsx'

// Incident "Files" store — a working area for NON-malicious supporting material
// (screenshots, raw logs, notes). Shares one encrypted store with entity files;
// a file may be linked to an entity or stand alone at the incident level.

function fmtSize(bytes) {
  if (bytes == null) return '—'
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

// E4: only these can be report figures (the server re-checks the bytes on include).
const REPORT_IMAGE_TYPES = ['image/png', 'image/jpeg', 'image/gif', 'image/webp']
const REPORT_IMAGE_EXT = /\.(png|jpe?g|gif|webp)$/i
function isReportImage(f) {
  return REPORT_IMAGE_TYPES.includes(f.content_type) || REPORT_IMAGE_EXT.test(f.original_name || '')
}

function fileType(f) {
  const name = f.original_name || ''
  const dot = name.lastIndexOf('.')
  if (dot > 0 && dot < name.length - 1) return name.slice(dot + 1).toUpperCase()
  return f.content_type || '—'
}

export default function Files() {
  const { inc, bumpRail, canEdit } = useOutletContext()
  const isClosed = inc?.status === 'closed'
  // L2 (R43): canEdit = analyst/admin on an open incident; a viewer gets no write controls (the API refuses them).
  const ro = !canEdit
  const viewer = ro && !isClosed

  const [files, setFiles]       = useState([])
  const [entities, setEntities] = useState([])
  const [loading, setLoading]   = useState(true)
  const [error, setError]       = useState(null)
  const [busy, setBusy]         = useState(false)
  const [linkTarget, setLinkTarget] = useState(null) // file being (un)linked
  const [figureTarget, setFigureTarget] = useState(null) // file being included in the report / re-captioned
  const [figureError, setFigureError]   = useState(null)
  const [renaming, setRenaming] = useState(null)   // H4: file in the rename dialog (reason required)
  const [deleting, setDeleting] = useState(null)   // H4: file in the delete dialog (reason required)
  const [registering, setRegistering] = useState(null) // H4: file in the Register-as-exhibit dialog
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
  // After a write: re-read the list and the rail's counts.
  const reload = useCallback(() => { bumpRail?.(); return load() }, [bumpRail, load])
  useEffect(() => {
    api.listAllEntities(inc.id).then(setEntities).catch(() => {})   // every page
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
      await reload()
    } catch (err) {
      setError(err.message || 'Upload failed')
    } finally {
      setBusy(false)
    }
  }

  // H4: rename / delete go through dialogs that ask for the reason; they throw so the dialog shows why.
  const confirmRename = async (f, reason, name) => {
    await api.updateIncidentFile(inc.id, f.id, { original_name: name, reason })
    setRenaming(null)
    await reload()
  }

  const confirmDelete = async (f, reason) => {
    try {
      await api.deleteIncidentFile(inc.id, f.id, reason)
    } catch (e) {
      if (e.code === 'file_referenced') throw new Error(fileRefsMessage(e.data?.references))
      throw e
    }
    setDeleting(null)
    await reload()
  }

  const confirmRegister = async (f) => {
    const out = await api.registerFileExhibit(inc.id, f.id)
    await reload()
    return out
  }

  const onSaveLink = async (f, entityId) => {
    setBusy(true); setError(null)
    try {
      await api.updateIncidentFile(inc.id, f.id, { entity_id: entityId || null })
      setLinkTarget(null)
      await reload()
    } catch (err) {
      setError(err.message || 'Could not update link')
    } finally {
      setBusy(false)
    }
  }

  const onSaveFigure = async (f, caption) => {
    setBusy(true); setFigureError(null)
    try {
      await api.updateIncidentFile(inc.id, f.id, { include_in_report: true, report_caption: caption.trim() || null })
      setFigureTarget(null)
      await load()
    } catch (err) {
      setFigureError(err.message || 'Could not include the file in the report')
    } finally {
      setBusy(false)
    }
  }

  const onExcludeFigure = async (f) => {
    setBusy(true); setError(null)
    try {
      await api.updateIncidentFile(inc.id, f.id, { include_in_report: false })
      await load()
    } catch (err) {
      setError(err.message || 'Could not remove the file from the report')
    } finally {
      setBusy(false)
    }
  }

  const openFigure = (f) => { setFigureError(null); setFigureTarget(f) }

  return (
    <section className="panel">
      <div className="panel-toolbar">
        <h2 className="panel-h">Supporting documents</h2>
        <input
          ref={fileInputRef}
          type="file"
          multiple
          style={{ display: 'none' }}
          onChange={onPickFiles}
        />
        {!viewer && (
          <button
            type="button"
            className="btn primary"
            onClick={() => fileInputRef.current?.click()}
            disabled={isClosed || busy}
            title={isClosed ? 'Closed incidents are read-only' : 'Upload files (non-malicious — screenshots, logs, notes)'}
          >
            {busy ? 'Working…' : '+ Upload files'}
          </button>
        )}
      </div>

      <p style={{ fontSize: 12, color: 'var(--dim)', marginBottom: 'var(--space-3)' }}>
        Working store for non-malicious supporting material. Encrypted at rest and hashed (SHA-256) on upload.
        Not chain-of-custody evidence — use <b>Register as exhibit</b> when a file must become one — and not for
        suspected-malicious samples (Artifacts). Rename and delete ask for a reason; a file a report, case note,
        exhibit or entity relies on can't be deleted.
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
          {!ro && <div style={{ color: 'var(--dim)', fontSize: 12 }}>Click "Upload files" to add screenshots, logs, or notes.</div>}
        </div>
      ) : (
        <div className="table-scroll">
        <table className="settings-table compact">
          <thead>
            <tr>
              <th style={{ minWidth: 180 }}>Name</th>
              <th style={{ width: 80 }}>Type</th>
              <th style={{ width: 90 }}>Size</th>
              <th style={{ width: 110 }}>SHA-256</th>
              <th style={{ width: 150 }}>Added</th>
              <th style={{ width: 130 }}>Added by</th>
              <th style={{ width: 150 }}>Entity</th>
              <th style={{ width: 120 }}>Report</th>
              <th style={{ width: 130 }}>Exhibit</th>
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
                <td><FileHash file={f} /></td>
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
                <td className="file-report">
                  {isReportImage(f) ? (
                    <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-1)', flexWrap: 'wrap' }}>
                      <label style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 12, cursor: canEdit ? 'pointer' : 'default' }}
                             title={canEdit ? 'Include this screenshot as a numbered figure in generated reports' : undefined}>
                        <input
                          type="checkbox"
                          checked={!!f.include_in_report}
                          disabled={!canEdit || busy}
                          onChange={(e) => (e.target.checked ? openFigure(f) : onExcludeFigure(f))}
                          aria-label={`Include ${f.original_name} in the report`}
                        />
                        Include
                      </label>
                      {f.include_in_report && canEdit && (
                        <button type="button" className="btn ghost" onClick={() => openFigure(f)} disabled={busy}>
                          Caption
                        </button>
                      )}
                      {f.include_in_report && (
                        <div className="file-figure-caption" title={f.report_caption || undefined}
                             style={{ flexBasis: '100%', maxWidth: 150, fontSize: 11, color: 'var(--muted)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                          {f.report_caption || 'No caption'}
                        </div>
                      )}
                    </div>
                  ) : (
                    <span style={{ color: 'var(--dim)', fontSize: 12 }} title="Only PNG, JPEG, GIF or WebP images can go in a report">—</span>
                  )}
                </td>
                <td>
                  {f.evidence_id ? <ExhibitPill file={f} /> : canEdit ? (
                    <button type="button" className="btn ghost" onClick={() => setRegistering(f)} disabled={ro || busy}
                            style={{ whiteSpace: 'nowrap' }} title="Copy this file into Evidence as a draft exhibit with chain of custody">
                      Register as exhibit
                    </button>
                  ) : <span style={{ color: 'var(--dim)', fontSize: 12 }}>—</span>}
                </td>
                <td className="actions">
                  <a
                    className="btn ghost"
                    href={api.incidentFileDownloadUrl(inc.id, f.id)}
                    title="Download"
                  >
                    Download
                  </a>
                  <button type="button" className="btn ghost" onClick={() => setLinkTarget(f)} disabled={ro}>
                    {f.entity_id ? 'Re-link' : 'Link'}
                  </button>
                  <button type="button" className="btn ghost" onClick={() => setRenaming(f)} disabled={ro || busy}>
                    Rename
                  </button>
                  <button type="button" className="btn ghost" onClick={() => setDeleting(f)} disabled={ro || busy}>
                    Delete
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        </div>
      )}

      {figureTarget && (
        <ReportFigureModal
          file={figureTarget}
          onClose={() => setFigureTarget(null)}
          onSave={(caption) => onSaveFigure(figureTarget, caption)}
          busy={busy}
          error={figureError}
        />
      )}

      {renaming && (
        <FileReasonModal file={renaming} rename onClose={() => setRenaming(null)}
                         onConfirm={(reason, name) => confirmRename(renaming, reason, name)} />
      )}
      {deleting && (
        <FileReasonModal file={deleting} onClose={() => setDeleting(null)}
                         onConfirm={(reason) => confirmDelete(deleting, reason)} />
      )}
      {registering && (
        <RegisterExhibitModal file={registering} onClose={() => setRegistering(null)}
                              onConfirm={() => confirmRegister(registering)} />
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

// ── Include-in-report modal (caption + personal-data / TLP:RED warning) ───────

function ReportFigureModal({ file, onClose, onSave, busy, error }) {
  const [caption, setCaption] = useState(file.report_caption || '')
  const editing = !!file.include_in_report
  // Focus moves in (caption field), Tab stays inside, Esc closes (not mid-save), focus returns on close.
  const dialogRef = useRef(null)
  useDialogFocus(dialogRef, () => { if (!busy) onClose() })

  return (
    <div className="modal-backdrop">
      <div className="modal" ref={dialogRef} role="dialog" aria-modal="true" aria-labelledby="figure-title" style={{ maxWidth: 520 }}>
        <div className="modal-head">
          <h2 id="figure-title">{editing ? 'Report figure caption' : 'Include in report'}</h2>
          <button type="button" className="modal-close" onClick={onClose} disabled={busy} aria-label="Close">×</button>
        </div>
        <div className="modal-body">
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--muted)', marginBottom: 'var(--space-3)', wordBreak: 'break-all' }}>
            {file.original_name}
          </div>
          <div className="alert warn figure-warning" role="note" style={{ marginBottom: 'var(--space-3)' }}>
            <span className="alert-icon">!</span>
            <span style={{ color: 'var(--text)' }}>
              Screenshots can show personal data or TLP:RED material. The whole image goes into every report generated
              for this incident, executive and full, and travels with it. Check it first; upload a cropped or redacted
              copy if needed.
            </span>
          </div>
          <div className="field">
            <label className="field-label" htmlFor="figure-caption">Caption (optional)</label>
            <textarea
              id="figure-caption"
              className="input"
              rows={3}
              maxLength={512}
              value={caption}
              onChange={(e) => setCaption(e.target.value)}
              placeholder="e.g. Phishing landing page captured from the user's browser"
            />
            <div className="field-hint">{caption.length}/512 · printed under the figure with the file's SHA-256</div>
          </div>
          {error && (
            <div className="alert error" role="alert" style={{ marginTop: 'var(--space-3)' }}>
              <span className="alert-icon">!</span><span>{error}</span>
            </div>
          )}
        </div>
        <div className="modal-foot">
          <button type="button" className="btn ghost" onClick={onClose} disabled={busy}>Cancel</button>
          <button type="button" className="btn primary" onClick={() => onSave(caption)} disabled={busy}>
            {busy ? 'Saving…' : editing ? 'Save caption' : 'Include in report'}
          </button>
        </div>
      </div>
    </div>
  )
}
