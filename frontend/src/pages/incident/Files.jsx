import { useCallback, useEffect, useRef, useState } from 'react'
import { useOutletContext } from 'react-router-dom'
import { api } from '../../api/client.js'
import { useAuth } from '../../hooks/useAuth.jsx'
import { useDialogFocus } from '../../hooks/useDialogFocus.js'
import { formatLocal } from '../../lib/datetime.js'
import { ExhibitPill, FileHash, FileReasonModal, RegisterExhibitModal, fileRefsMessage } from '../../components/SupportingFile.jsx'
import { CaptureFields, CaptureRecord, EMPTY_CAPTURE, captureBody, captureFrom, captureSummary } from '../../components/FileCapture.jsx'

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
  const [uploadOpen, setUploadOpen] = useState(false)  // S5: the upload dialog (files + capture details)
  const [detailId, setDetailId]     = useState(null)   // S5: file in the details dialog (capture record, links)
  const { user: me } = useAuth()

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

  // S5: after the upload dialog stored some files (all: close it).
  const onUploaded = async (allDone) => {
    await reload()
    if (allDone) setUploadOpen(false)
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
        {!viewer && (
          <button
            type="button"
            className="btn primary"
            onClick={() => setUploadOpen(true)}
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
        suspected-malicious samples (Artifacts). Record how a screenshot was captured, and <b>Link</b> a file to the
        exhibit, timeline event or IOC it corroborates, in <b>Details</b>. Rename and delete ask for a reason; a file
        a report, case note, exhibit, link or entity relies on can't be deleted.
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
                  {(captureSummary(f) || f.links?.length > 0) && (
                    <div style={{ fontFamily: 'var(--font-body)', fontSize: 11, color: 'var(--muted)', wordBreak: 'normal' }}
                         data-testid="file-capture-line">
                      {[captureSummary(f), f.links?.length ? `linked to ${f.links.length}` : ''].filter(Boolean).join(' · ')}
                    </div>
                  )}
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
                  <button type="button" className="btn ghost" onClick={() => setDetailId(f.id)}
                          title="Capture record and what this file corroborates">
                    Details
                  </button>
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

      {uploadOpen && (
        <UploadModal incidentId={inc.id} me={me} onClose={() => setUploadOpen(false)} onUploaded={onUploaded} />
      )}
      {detailId && files.some(f => f.id === detailId) && (
        <FileDetailModal incidentId={inc.id} file={files.find(f => f.id === detailId)} me={me} canEdit={canEdit}
                         onClose={() => setDetailId(null)} onChanged={reload} />
      )}
    </section>
  )
}

// ── S5: upload dialog (files + optional capture details) ──────────────────────

function UploadModal({ incidentId, me, onClose, onUploaded }) {
  const [picked, setPicked]   = useState([])     // still to upload
  const [inputKey, setInputKey] = useState(0)
  const [capture, setCapture] = useState(EMPTY_CAPTURE)
  const [busy, setBusy]       = useState(false)
  const [error, setError]     = useState(null)
  const dialogRef = useRef(null)
  useDialogFocus(dialogRef, () => { if (!busy) onClose() })
  const single = picked.length === 1

  // One request per file, same capture details. On an error the files already stored drop out of the
  // selection, so trying again never uploads one twice.
  const submit = async (e) => {
    e.preventDefault()
    if (capture.by === 'other' && !capture.captured_by_name.trim()) { setError('Give the capturer’s name, or choose another option.'); return }
    const body = captureBody(single ? capture : { ...capture, capture_sha256: '' }, me, { upload: true })
    setBusy(true); setError(null)
    let left = picked
    try {
      while (left.length) {
        await api.uploadIncidentFile(incidentId, left[0], null, body)
        left = left.slice(1)
      }
    } catch (err) {
      const done = picked.length - left.length
      setError(`${err.message || 'Upload failed'}${done ? ` (${done} of ${picked.length} uploaded; the rest are still selected)` : ''}`)
    }
    setPicked(left)
    if (left.length && left.length < picked.length) setInputKey(k => k + 1)
    setBusy(false)
    if (left.length < picked.length) await onUploaded(left.length === 0)
  }

  return (
    <div className="modal-backdrop">
      <div className="modal" ref={dialogRef} role="dialog" aria-modal="true" aria-labelledby="files-upload-title" style={{ maxWidth: 680 }}>
        <div className="modal-head">
          <h2 id="files-upload-title">Upload supporting documents</h2>
          <button type="button" className="modal-close" onClick={onClose} disabled={busy} aria-label="Close">×</button>
        </div>
        <form onSubmit={submit}>
          <div className="modal-body">
            <div className="form">
              <div className="field">
                <label className="field-label" htmlFor="files-upload-pick">Files</label>
                <input key={inputKey} id="files-upload-pick" type="file" multiple className="input" disabled={busy}
                       onChange={e => setPicked(Array.from(e.target.files || []))} />
                <div className="field-hint">
                  {picked.length > 0 && inputKey > 0 ? `Still to upload: ${picked.map(f => f.name).join(', ')}. `
                    : 'Non-malicious material only, at most 50 MB each. Encrypted at rest and hashed on upload.'}
                </div>
              </div>
              <details>
                <summary style={{ cursor: 'pointer', fontSize: 13, color: 'var(--muted)' }}>Capture details (optional)</summary>
                <div style={{ marginTop: 'var(--space-2)' }}>
                  <div className="field-hint" style={{ marginBottom: 'var(--space-2)' }}>
                    How a screenshot was taken (ISO 27037 §7.1.1.1). Applies to every file picked; register a file as an
                    exhibit later and these fill its acquisition record.
                  </div>
                  <CaptureFields value={capture} onChange={setCapture} me={me} withHash idPrefix="files-upload"
                                 disabled={busy}
                                 hashDisabledHint={single ? null : 'Pick exactly one file to give its SHA-256 at capture.'} />
                </div>
              </details>
              {error && (
                <div className="alert error" role="alert">
                  <span className="alert-icon">!</span><span>{error}</span>
                </div>
              )}
            </div>
          </div>
          <div className="modal-foot">
            <button type="button" className="btn ghost" onClick={onClose} disabled={busy}>Cancel</button>
            <button type="submit" className="btn primary" disabled={busy || picked.length === 0}>
              {busy ? 'Uploading…' : picked.length > 1 ? `Upload ${picked.length} files` : 'Upload'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ── S5: file details — capture record (edit) and links (what the file corroborates) ──

const TARGETS = [
  { value: 'exhibit',        label: 'Exhibit' },
  { value: 'timeline_event', label: 'Timeline event' },
  { value: 'ioc',            label: 'IOC' },
]
const TARGET_LIST = {
  exhibit:        [api.listEvidence,       x => `${x.identifier} · ${x.name}`],
  timeline_event: [api.listTimelineEvents, x => `${formatLocal(x.event_time)} · ${(x.description || '').slice(0, 80)}`],
  ioc:            [api.listIocs,           x => `${x.type} ${x.value}`],
}

function FileDetailModal({ incidentId, file, me, canEdit, onClose, onChanged }) {
  const [editing, setEditing] = useState(false)
  const [capture, setCapture] = useState(() => captureFrom(file, me))
  const [kind, setKind]       = useState('exhibit')
  const [options, setOptions] = useState(null)
  const [targetId, setTargetId] = useState('')
  const [note, setNote]       = useState('')
  const [busy, setBusy]       = useState(false)
  const [error, setError]     = useState(null)
  const dialogRef = useRef(null)
  useDialogFocus(dialogRef, () => { if (!busy) onClose() })

  useEffect(() => {
    if (!canEdit) return
    const ctl = new AbortController()
    const [fn, label] = TARGET_LIST[kind]
    setOptions(null); setTargetId('')
    api.listAllPages(fn, incidentId, {}, 200, { signal: ctl.signal, maxPages: 10 })
      .then(all => setOptions(all.map(x => ({ id: x.id, label: label(x) }))))
      .catch(e => { if (!ctl.signal.aborted) { setOptions([]); setError(e.message || 'Could not list the targets.') } })
    return () => ctl.abort()
  }, [incidentId, kind, canEdit])

  const run = async (fn) => {
    setBusy(true); setError(null)
    try {
      await fn()
      await onChanged()
      return true
    } catch (err) {
      setError(err.message || 'Could not save.')
      return false
    } finally {
      setBusy(false)
    }
  }
  const saveCapture = async () => {
    if (capture.by === 'other' && !capture.captured_by_name.trim()) { setError('Give the capturer’s name, or choose another option.'); return }
    if (await run(() => api.updateIncidentFile(incidentId, file.id, captureBody(capture, me)))) setEditing(false)
  }
  const addLink = () => run(async () => {
    await api.linkIncidentFile(incidentId, file.id, { target_type: kind, target_id: targetId, note: note.trim() || null })
    setTargetId(''); setNote('')
  })
  const linked = new Set((file.links || []).filter(l => l.target_type === kind).map(l => l.target_id))

  return (
    <div className="modal-backdrop">
      <div className="modal" ref={dialogRef} role="dialog" aria-modal="true" aria-labelledby="file-detail-title" style={{ maxWidth: 720 }}>
        <div className="modal-head">
          <h2 id="file-detail-title">File details</h2>
          <button type="button" className="modal-close" onClick={onClose} disabled={busy} aria-label="Close">×</button>
        </div>
        <div className="modal-body">
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--muted)', marginBottom: 'var(--space-3)', wordBreak: 'break-all' }}>
            {file.original_name}{file.sha256 ? ` · SHA-256 ${file.sha256}` : ''}
          </div>

          <h3 className="panel-h">Capture record <span style={{ fontWeight: 400, color: 'var(--muted)', fontSize: 12 }}>· ISO 27037 §7.1.1.1</span></h3>
          {editing ? (
            <>
              <CaptureFields value={capture} onChange={setCapture} me={me} idPrefix="file-detail" disabled={busy} />
              <div className="field-hint">Each change is recorded in the audit log with its old and new value. The SHA-256 at capture can’t be changed.</div>
              <div style={{ display: 'flex', gap: 'var(--space-2)', marginTop: 'var(--space-2)' }}>
                <button type="button" className="btn primary" onClick={saveCapture} disabled={busy}>{busy ? 'Saving…' : 'Save capture record'}</button>
                <button type="button" className="btn ghost" onClick={() => { setEditing(false); setCapture(captureFrom(file, me)) }} disabled={busy}>Cancel</button>
              </div>
            </>
          ) : (
            <>
              <CaptureRecord file={file} />
              {canEdit && (
                <button type="button" className="btn ghost" style={{ marginTop: 'var(--space-2)' }}
                        onClick={() => { setCapture(captureFrom(file, me)); setEditing(true) }} disabled={busy}>
                  Edit capture record
                </button>
              )}
            </>
          )}

          <h3 className="panel-h" style={{ marginTop: 'var(--space-4)' }}>Corroborates</h3>
          <div className="field-hint" style={{ marginBottom: 'var(--space-2)' }}>
            Exhibits, timeline events and IOCs this file supports. It stays a supporting document (no chain of custody, never in a
            disclosure package); use Register as exhibit when the file itself is the evidence.
          </div>
          {(file.links || []).length === 0 ? (
            <div style={{ color: 'var(--muted)', fontSize: 13 }}>Not linked to anything yet.</div>
          ) : (
            <ul style={{ listStyle: 'none', padding: 0, margin: 0 }} data-testid="file-links">
              {file.links.map(l => (
                <li key={l.id} style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'baseline', fontSize: 13, marginBottom: 'var(--space-1)' }}>
                  <span className="pill" style={{ fontSize: 10 }}>{TARGETS.find(t => t.value === l.target_type)?.label}</span>
                  <span style={{ flex: 1, minWidth: 0, wordBreak: 'break-word' }}>
                    {l.target_label || l.target_id}
                    {l.note && <span style={{ color: 'var(--muted)' }}> — {l.note}</span>}
                    <span style={{ color: 'var(--dim)', fontSize: 11 }}> · {l.linked_by_username || 'unknown'}, {formatLocal(l.linked_at)}</span>
                  </span>
                  {canEdit && (
                    <button type="button" className="btn ghost" disabled={busy}
                            onClick={() => run(() => api.unlinkIncidentFile(incidentId, file.id, l.id))}>
                      Unlink
                    </button>
                  )}
                </li>
              ))}
            </ul>
          )}
          {canEdit && (
            <div className="form" style={{ marginTop: 'var(--space-3)' }}>
              <div className="form-row">
                <div className="field">
                  <label className="field-label" htmlFor="file-link-kind">Link to…</label>
                  <select id="file-link-kind" className="select" value={kind} disabled={busy}
                          onChange={e => setKind(e.target.value)}>
                    {TARGETS.map(t => <option key={t.value} value={t.value}>{t.label}</option>)}
                  </select>
                </div>
                <div className="field">
                  <label className="field-label" htmlFor="file-link-target">{TARGETS.find(t => t.value === kind).label}</label>
                  <select id="file-link-target" className="select" value={targetId} disabled={busy || options === null}
                          onChange={e => setTargetId(e.target.value)}>
                    <option value="">{options === null ? 'Loading…' : options.length ? '— choose —' : 'None in this incident'}</option>
                    {(options || []).map(o => (
                      <option key={o.id} value={o.id} disabled={linked.has(o.id)}>{o.label}{linked.has(o.id) ? ' — linked' : ''}</option>
                    ))}
                  </select>
                </div>
              </div>
              <div className="field">
                <label className="field-label" htmlFor="file-link-note">Note (optional)</label>
                <input id="file-link-note" className="input" value={note} maxLength={1000} disabled={busy}
                       onChange={e => setNote(e.target.value)} placeholder="What the file shows about it" />
              </div>
              <button type="button" className="btn" style={{ alignSelf: 'flex-start' }} onClick={addLink} disabled={busy || !targetId}>
                {busy ? 'Saving…' : 'Link'}
              </button>
            </div>
          )}
          {error && (
            <div className="alert error" role="alert" style={{ marginTop: 'var(--space-3)' }}>
              <span className="alert-icon">!</span><span>{error}</span>
            </div>
          )}
        </div>
        <div className="modal-foot">
          <button type="button" className="btn ghost" onClick={onClose} disabled={busy}>Close</button>
        </div>
      </div>
    </div>
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
