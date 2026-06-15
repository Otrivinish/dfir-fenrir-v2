import { useCallback, useEffect, useRef, useState } from 'react'
import { api } from '../../../api/client.js'
import { formatLocal } from '../../../lib/datetime.js'
import UtcDateTimeInput from '../../../components/UtcDateTimeInput.jsx'

const ENTITY_TYPES = [
  { value: 'host',          label: 'Host'          },
  { value: 'user',          label: 'User'          },
  { value: 'ip',            label: 'IP'            },
  { value: 'domain',        label: 'Domain'        },
  { value: 'email',         label: 'Email'         },
  { value: 'service',       label: 'Service'       },
  { value: 'network_range', label: 'Network Range' },
  { value: 'group',         label: 'Group'         },
  { value: 'other',         label: 'Other'         },
]

const CRITICALITY = [
  { value: 'low',      label: 'Low'      },
  { value: 'medium',   label: 'Medium'   },
  { value: 'high',     label: 'High'     },
  { value: 'critical', label: 'Critical' },
]

// Maps entity type → its CSS token name
const TYPE_VAR = {
  host:          '--entity-host',
  user:          '--entity-user',
  ip:            '--entity-ip',
  domain:        '--entity-domain',
  email:         '--entity-email',
  service:       '--entity-service',
  network_range: '--entity-network',
  group:         '--entity-group',
  other:         '--entity-other',
}

const labelOfType = (v) => ENTITY_TYPES.find(t => t.value === v)?.label || v
const typeColor   = (v) => `var(${TYPE_VAR[v] || '--muted'})`

export default function EntityDetailDrawer({
  entity,          // EntityOut object
  relations,       // all EntityRelationOut[] for this incident
  allEntities,     // all EntityOut[] for this incident (for relation targets)
  incidentId,
  isClosed,
  onClose,
  onEntityUpdated, // () => void — triggers reload in parent
  onEntityDeleted, // () => void
  onAddConnection, // (entity) => void — opens ConnectModal with entity pre-filled
}) {
  const [busy, setBusy]   = useState(false)
  const [error, setError] = useState(null)

  // Asset log state
  const [log,        setLog]        = useState([])
  const [logLoading, setLogLoading] = useState(false)
  const [logError,   setLogError]   = useState(null)
  const [showAddNote, setShowAddNote] = useState(false)
  const [noteTitle,   setNoteTitle]   = useState('')
  const [noteBody,    setNoteBody]    = useState('')
  const [noteOccurredAt, setNoteOccurredAt] = useState('')
  const [noteBusy,    setNoteBusy]    = useState(false)

  const loadLog = useCallback(async () => {
    setLogLoading(true)
    setLogError(null)
    try {
      const data = await api.listEntityEvents(incidentId, entity.id)
      setLog(data.items || [])
    } catch (e) {
      setLogError(e.message || 'Could not load asset log')
    } finally {
      setLogLoading(false)
    }
  }, [incidentId, entity.id])

  useEffect(() => { loadLog() }, [loadLog])

  // Collected files state
  const [files,        setFiles]        = useState([])
  const [filesLoading, setFilesLoading] = useState(true)
  const [filesError,   setFilesError]   = useState(null)
  const [uploading,    setUploading]    = useState(false)
  const [dragOver,     setDragOver]     = useState(false)
  const fileInputRef = useRef(null)

  const loadFiles = useCallback(async () => {
    setFilesLoading(true)
    setFilesError(null)
    try {
      const data = await api.listEntityFiles(incidentId, entity.id)
      setFiles(data.items || [])
    } catch (e) {
      setFilesError(e.message || 'Could not load files')
    } finally {
      setFilesLoading(false)
    }
  }, [incidentId, entity.id])

  useEffect(() => { loadFiles() }, [loadFiles])

  const uploadFile = async (file) => {
    if (!file) return
    setUploading(true)
    setFilesError(null)
    try {
      await api.uploadEntityFile(incidentId, entity.id, file)
      await loadFiles()
      // Refresh parent so file_count pill updates in the table
      onEntityUpdated()
    } catch (e) {
      setFilesError(e.message || 'Upload failed')
    } finally {
      setUploading(false)
    }
  }

  const deleteFile = async (ef) => {
    if (!window.confirm(`Delete file "${ef.original_name}"?`)) return
    setFilesError(null)
    try {
      await api.deleteEntityFile(incidentId, entity.id, ef.id)
      await loadFiles()
      onEntityUpdated()
    } catch (e) {
      setFilesError(e.message || 'Could not delete file')
    }
  }

  const handleDrop = (e) => {
    e.preventDefault()
    setDragOver(false)
    const file = e.dataTransfer.files[0]
    if (file) uploadFile(file)
  }

  // Close on Escape
  useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  const myRelations = relations.filter(
    (r) => r.from_entity_id === entity.id || r.to_entity_id === entity.id
  )

  const entityById = (id) => allEntities.find((e) => e.id === id)

  const toggleCompromised = async () => {
    setBusy(true)
    setError(null)
    try {
      await api.updateEntity(incidentId, entity.id, { compromised: !entity.compromised })
      onEntityUpdated()
    } catch (e) {
      setError(e.message || 'Could not update entity')
    } finally {
      setBusy(false)
    }
  }

  const setCriticality = async (value) => {
    if (value === entity.criticality) return
    setBusy(true)
    setError(null)
    try {
      await api.updateEntity(incidentId, entity.id, { criticality: value })
      onEntityUpdated()
    } catch (e) {
      setError(e.message || 'Could not update criticality')
    } finally {
      setBusy(false)
    }
  }

  const onDisconnect = async (rel) => {
    if (!window.confirm('Remove this relationship?')) return
    setBusy(true)
    setError(null)
    try {
      await api.deleteEntityRelation(incidentId, rel.id)
      onEntityUpdated()
    } catch (e) {
      setError(e.message || 'Could not remove relationship')
    } finally {
      setBusy(false)
    }
  }

  const onDelete = async () => {
    const label = `${labelOfType(entity.type)}: ${entity.value}`
    if (!window.confirm(`Delete entity?\n\n${label}`)) return
    if (!window.confirm(`Confirm permanent deletion of:\n\n${label}\n\nThis cannot be undone.`)) return
    setBusy(true)
    setError(null)
    try {
      await api.deleteEntity(incidentId, entity.id)
      onEntityDeleted()
    } catch (e) {
      setError(e.message || 'Could not delete entity')
    } finally {
      setBusy(false)
    }
  }

  const submitNote = async (e) => {
    e.preventDefault()
    if (!noteTitle.trim()) return
    setNoteBusy(true)
    try {
      const payload = { title: noteTitle.trim(), body: noteBody.trim() || null }
      if (noteOccurredAt) payload.occurred_at = noteOccurredAt
      await api.createEntityEvent(incidentId, entity.id, payload)
      setNoteTitle('')
      setNoteBody('')
      setNoteOccurredAt('')
      setShowAddNote(false)
      await loadLog()
    } catch (e) {
      setLogError(e.message || 'Could not add note')
    } finally {
      setNoteBusy(false)
    }
  }

  const deleteNote = async (ev) => {
    if (!window.confirm('Delete this note?')) return
    setNoteBusy(true)
    try {
      await api.deleteEntityEvent(incidentId, entity.id, ev.id)
      await loadLog()
    } catch (e) {
      setLogError(e.message || 'Could not delete note')
    } finally {
      setNoteBusy(false)
    }
  }

  const color = typeColor(entity.type)

  return (
    <>
      <div className="entity-drawer-backdrop" onClick={onClose} />
      <aside className="entity-drawer" role="complementary" aria-label="Entity detail">
        {/* ── Head ── */}
        <div className="entity-drawer-head">
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', minWidth: 0 }}>
            <span style={{
              width: 10, height: 10, borderRadius: '50%',
              background: color, flexShrink: 0,
            }} />
            <span style={{
              fontFamily: 'var(--font-mono)', fontSize: 10, fontWeight: 700,
              letterSpacing: '0.1em', textTransform: 'uppercase', color,
            }}>
              {labelOfType(entity.type)}
            </span>
            {entity.compromised && (
              <span className="pill pill-crit" style={{ marginLeft: 4 }}>Compromised</span>
            )}
          </div>
          <button type="button" className="modal-close" onClick={onClose} aria-label="Close drawer">×</button>
        </div>

        {/* ── Body ── */}
        <div className="entity-drawer-body">
          {error && (
            <div className="alert error" role="alert">
              <span className="alert-icon">!</span><span>{error}</span>
            </div>
          )}

          {/* Identity */}
          <div className="entity-drawer-section">
            <div style={{
              fontFamily: 'var(--font-mono)', fontSize: 13, color: 'var(--text)',
              wordBreak: 'break-all', lineHeight: 1.4,
            }}>
              {entity.value}
            </div>
            {entity.name && (
              <div style={{ fontSize: 12, color: 'var(--muted)' }}>{entity.name}</div>
            )}
          </div>

          {/* Criticality + compromised */}
          <div className="entity-drawer-section">
            <div className="entity-drawer-section-label">Status</div>
            <div style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'center', flexWrap: 'wrap' }}>
              <select
                className="select"
                value={entity.criticality}
                onChange={(e) => setCriticality(e.target.value)}
                disabled={isClosed || busy}
                aria-label="Criticality"
                style={{ fontSize: 12 }}
              >
                {CRITICALITY.map(c => (
                  <option key={c.value} value={c.value}>{c.label}</option>
                ))}
              </select>

              <button
                type="button"
                className={`compromised-toggle ${entity.compromised ? 'is-compromised' : 'not-compromised'}`}
                onClick={toggleCompromised}
                disabled={isClosed || busy}
                title={entity.compromised ? 'Clear compromised flag' : 'Mark as compromised'}
              >
                {entity.compromised ? '⚠ Compromised' : '○ Mark compromised'}
              </button>
            </div>
          </div>

          {/* Description */}
          {entity.description && (
            <div className="entity-drawer-section">
              <div className="entity-drawer-section-label">Description</div>
              <div style={{ fontSize: 12, color: 'var(--text)', lineHeight: 1.55, whiteSpace: 'pre-wrap' }}>
                {entity.description}
              </div>
            </div>
          )}

          {/* Attributes */}
          {entity.attributes && Object.keys(entity.attributes).length > 0 && (
            <div className="entity-drawer-section">
              <div className="entity-drawer-section-label">Attributes</div>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11 }}>
                <tbody>
                  {Object.entries(entity.attributes).map(([k, v]) => (
                    <tr key={k}>
                      <td style={{
                        fontFamily: 'var(--font-mono)', color: 'var(--muted)',
                        paddingRight: 12, paddingBottom: 4, verticalAlign: 'top',
                        whiteSpace: 'nowrap',
                      }}>{k}</td>
                      <td style={{
                        fontFamily: 'var(--font-mono)', color: 'var(--text)',
                        paddingBottom: 4, wordBreak: 'break-all',
                      }}>{String(v)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* Relationships */}
          <div className="entity-drawer-section">
            <div className="entity-drawer-section-label">
              Relationships{myRelations.length > 0 && ` (${myRelations.length})`}
            </div>

            {myRelations.length === 0 ? (
              <div style={{ fontSize: 12, color: 'var(--dim)' }}>No connections yet.</div>
            ) : (
              myRelations.map((rel) => {
                const isFrom  = rel.from_entity_id === entity.id
                const otherId = isFrom ? rel.to_entity_id : rel.from_entity_id
                const other   = entityById(otherId)
                return (
                  <div key={rel.id} className="relation-row">
                    <span className="relation-arrow">{isFrom ? '→' : '←'}</span>
                    <span className="relation-type-label">{rel.relationship_type}</span>
                    <span className="relation-target" style={{ fontSize: 11, color: 'var(--text)', fontFamily: 'var(--font-mono)' }}>
                      {other ? (other.name || other.value) : otherId}
                    </span>
                    {!isClosed && (
                      <button
                        type="button"
                        className="btn ghost"
                        style={{ padding: '2px 6px', fontSize: 11 }}
                        onClick={() => onDisconnect(rel)}
                        disabled={busy}
                        title="Remove this relationship"
                      >✕</button>
                    )}
                  </div>
                )
              })
            )}

            {!isClosed && (
              <button
                type="button"
                className="btn ghost"
                style={{ marginTop: 'var(--space-1)', fontSize: 12 }}
                onClick={() => onAddConnection(entity)}
              >
                + Add connection
              </button>
            )}
          </div>

          {/* Collected Files */}
          <div className="entity-drawer-section">
            <div className="entity-drawer-section-label" style={{ marginBottom: 'var(--space-2)' }}>
              Collected Files{files.length > 0 && ` (${files.length})`}
            </div>

            {filesError && (
              <div style={{ fontSize: 11, color: 'var(--crit)', marginBottom: 'var(--space-1)' }}>
                {filesError}
              </div>
            )}

            {/* Drop zone (only when not closed) */}
            {!isClosed && (
              <div
                onDragOver={(e) => { e.preventDefault(); setDragOver(true) }}
                onDragLeave={() => setDragOver(false)}
                onDrop={handleDrop}
                onClick={() => !uploading && fileInputRef.current?.click()}
                style={{
                  border: `1px dashed ${dragOver ? 'var(--accent)' : 'var(--border)'}`,
                  borderRadius: 'var(--radius)',
                  padding: 'var(--space-2) var(--space-3)',
                  textAlign: 'center',
                  fontSize: 11,
                  color: dragOver ? 'var(--accent)' : 'var(--dim)',
                  cursor: uploading ? 'not-allowed' : 'pointer',
                  background: dragOver ? 'var(--accent-soft)' : 'transparent',
                  transition: 'border-color 0.15s, color 0.15s',
                  marginBottom: 'var(--space-2)',
                }}
              >
                {uploading ? 'Uploading…' : 'Drop file here or click to upload'}
              </div>
            )}
            <input
              ref={fileInputRef}
              type="file"
              style={{ display: 'none' }}
              onChange={(e) => { const f = e.target.files[0]; if (f) uploadFile(f); e.target.value = '' }}
            />

            {filesLoading && files.length === 0 ? (
              <div style={{ fontSize: 12, color: 'var(--dim)' }}>Loading…</div>
            ) : files.length === 0 ? (
              <div style={{ fontSize: 12, color: 'var(--dim)' }}>No files collected yet.</div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                {files.map(ef => (
                  <div key={ef.id} style={{
                    display: 'flex', alignItems: 'center', gap: 8,
                    padding: '5px 8px',
                    borderRadius: 'var(--radius-sm)',
                    border: '1px solid var(--border)',
                    background: 'var(--surface-2)',
                  }}>
                    <span style={{ flex: 1, minWidth: 0, fontSize: 11, fontFamily: 'var(--font-mono)', wordBreak: 'break-all', color: 'var(--text)' }}>
                      {ef.original_name}
                    </span>
                    <span style={{ fontSize: 10, color: 'var(--dim)', flexShrink: 0 }}>
                      {(ef.file_size / 1024).toFixed(0)} KB
                    </span>
                    <a
                      href={api.entityFileDownloadUrl(incidentId, entity.id, ef.id)}
                      download={ef.original_name}
                      style={{ fontSize: 11, color: 'var(--accent)', flexShrink: 0, textDecoration: 'none' }}
                      title="Download"
                    >↓</a>
                    {!isClosed && (
                      <button
                        type="button"
                        className="btn ghost"
                        style={{ padding: '1px 5px', fontSize: 11, color: 'var(--dim)', flexShrink: 0 }}
                        onClick={() => deleteFile(ef)}
                        title="Delete file"
                      >✕</button>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Asset Log */}
          <div className="entity-drawer-section">
            <div className="entity-drawer-section-label" style={{ marginBottom: 'var(--space-2)' }}>
              Asset Log{log.length > 0 && ` (${log.length})`}
            </div>

            {logError && (
              <div style={{ fontSize: 11, color: 'var(--crit)', marginBottom: 'var(--space-1)' }}>
                {logError}
              </div>
            )}

            {logLoading && log.length === 0 ? (
              <div style={{ fontSize: 12, color: 'var(--dim)' }}>Loading…</div>
            ) : log.length === 0 ? (
              <div style={{ fontSize: 12, color: 'var(--dim)' }}>No events yet.</div>
            ) : (
              <div className="asset-log-timeline">
                {log.map((ev) => (
                  <div key={ev.id} className={`asset-log-item is-${ev.event_type}`}>
                    <div className="asset-log-item-head">
                      <span className={`asset-log-type-pill ${ev.event_type}`}>
                        {ev.event_type === 'system' ? 'auto' : 'note'}
                      </span>
                      <span className="asset-log-title">{ev.title}</span>
                      {ev.event_type === 'note' && !isClosed && (
                        <button
                          type="button"
                          className="asset-log-delete"
                          onClick={() => deleteNote(ev)}
                          disabled={noteBusy}
                          title="Delete note"
                        >✕</button>
                      )}
                    </div>
                    {ev.body && (
                      <div className="asset-log-body">{ev.body}</div>
                    )}
                    <div className="asset-log-meta">
                      <span>{formatLocal(ev.occurred_at)}</span>
                    </div>
                  </div>
                ))}
              </div>
            )}

            {!isClosed && !showAddNote && (
              <button
                type="button"
                className="btn ghost"
                style={{ marginTop: 'var(--space-2)', fontSize: 12 }}
                onClick={() => setShowAddNote(true)}
              >+ Add note</button>
            )}

            {showAddNote && (
              <form className="add-note-form" onSubmit={submitNote}>
                <input
                  className="input"
                  type="text"
                  placeholder="Note title (required)"
                  value={noteTitle}
                  onChange={(e) => setNoteTitle(e.target.value)}
                  required
                  style={{ fontSize: 12 }}
                />
                <textarea
                  className="input"
                  placeholder="Details (optional)"
                  value={noteBody}
                  onChange={(e) => setNoteBody(e.target.value)}
                  rows={3}
                  style={{ fontSize: 12, resize: 'vertical' }}
                />
                <div className="add-note-occurred-wrap">
                  <span>When (UTC):</span>
                  <UtcDateTimeInput
                    value={noteOccurredAt}
                    onChange={setNoteOccurredAt}
                    hint={false}
                  />
                  <span style={{ color: 'var(--dim)' }}>(leave blank for now)</span>
                </div>
                <div className="add-note-form-row">
                  <button
                    type="submit"
                    className="btn primary"
                    style={{ fontSize: 12 }}
                    disabled={noteBusy || !noteTitle.trim()}
                  >{noteBusy ? 'Saving…' : 'Save note'}</button>
                  <button
                    type="button"
                    className="btn ghost"
                    style={{ fontSize: 12 }}
                    onClick={() => { setShowAddNote(false); setNoteTitle(''); setNoteBody(''); setNoteOccurredAt('') }}
                  >Cancel</button>
                </div>
              </form>
            )}
          </div>

          {/* Meta */}
          <div className="entity-drawer-section" style={{ marginTop: 'auto', paddingTop: 'var(--space-2)' }}>
            <div style={{ fontSize: 10, color: 'var(--dim)', fontFamily: 'var(--font-mono)' }}>
              Added {formatLocal(entity.added_at)}
            </div>
          </div>
        </div>

        {/* ── Foot ── */}
        <div className="entity-drawer-foot">
          <button
            type="button"
            className="btn ghost"
            onClick={onDelete}
            disabled={isClosed || busy}
            style={{ color: 'var(--crit)' }}
          >Delete</button>
          <div style={{ flex: 1 }} />
          <button
            type="button"
            className="btn ghost"
            onClick={onClose}
          >Close</button>
        </div>
      </aside>
    </>
  )
}
