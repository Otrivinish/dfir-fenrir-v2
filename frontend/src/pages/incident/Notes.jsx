import { useState, useEffect, useCallback } from 'react'
import { useOutletContext } from 'react-router-dom'
import ReactMarkdown from 'react-markdown'
import { useAuth } from '../../hooks/useAuth.jsx'
import { api } from '../../api/client.js'
import { relative, formatLocal } from '../../lib/datetime.js'
import { lineDiff } from '../../lib/diff.js'

function DiffView({ oldText, newText }) {
  const lines = lineDiff(oldText, newText)
  return (
    <pre className="note-diff">
      {lines.map((l, i) => (
        <div key={i} className={`note-diff-line note-diff-${l.type}`}>
          {l.type === 'add' ? '+ ' : l.type === 'del' ? '- ' : '  '}{l.line}
        </div>
      ))}
    </pre>
  )
}

function NoteHistory({ incidentId, note, onClose }) {
  const [versions, setVersions] = useState(null)
  const [error,    setError]    = useState('')
  const [openDiff, setOpenDiff] = useState(null)

  useEffect(() => {
    api.listNoteVersions(incidentId, note.id)
      .then(d => setVersions(d.items))
      .catch(e => setError(e.message || 'Failed to load history.'))
  }, [incidentId, note.id])

  return (
    <div className="note-history">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 'var(--space-2)' }}>
        <strong style={{ fontSize: 13 }}>History</strong>
        <button className="btn-link" type="button" onClick={onClose}>Close</button>
      </div>

      {error && (
        <div className="alert error" role="alert"><span className="alert-icon">!</span><span>{error}</span></div>
      )}
      {!versions && !error && <div className="panel-empty">Loading history…</div>}

      {versions && versions.map((v, idx) => {
        const prev = versions[idx + 1] // older neighbor -- list is newest-first
        return (
          <div key={v.version_number} style={{ marginBottom: 'var(--space-2)' }}>
            <div className="comment-meta">
              <span className="comment-author">v{v.version_number}</span>
              <span className="comment-time" title={formatLocal(v.created_at)}>{relative(v.created_at)}</span>
              {v.is_private && <span className="comment-edited">Private</span>}
              {prev && (
                <button className="btn-link" type="button"
                  onClick={() => setOpenDiff(openDiff === v.version_number ? null : v.version_number)}>
                  {openDiff === v.version_number ? 'Hide diff' : `Diff vs v${prev.version_number}`}
                </button>
              )}
            </div>
            {openDiff === v.version_number && prev && (
              <DiffView oldText={prev.body} newText={v.body} />
            )}
          </div>
        )
      })}
    </div>
  )
}

function NoteCard({ incidentId, note, mine, canDelete, isClosed, onSaved, onDeleted }) {
  const [editing,      setEditing]      = useState(false)
  const [draftBody,    setDraftBody]    = useState('')
  const [draftPrivate, setDraftPrivate] = useState(true)
  const [preview,      setPreview]      = useState(false)
  const [saving,       setSaving]       = useState(false)
  const [showHistory,  setShowHistory]  = useState(false)
  const [error,        setError]        = useState('')

  const startEdit = () => {
    setDraftBody(note?.body ?? '')
    setDraftPrivate(note?.is_private ?? true)
    setPreview(false)
    setEditing(true)
  }
  const cancelEdit = () => setEditing(false)

  const save = async () => {
    if (!draftBody.trim()) return
    setSaving(true)
    try {
      const saved = await api.saveNote(incidentId, { body: draftBody.trim(), is_private: draftPrivate })
      onSaved(saved)
      setEditing(false)
    } catch (e) {
      setError(e.message || 'Failed to save note.')
    } finally {
      setSaving(false)
    }
  }

  const del = async () => {
    if (!confirm(mine ? 'Delete your note?' : `Delete ${note.author_username ?? 'this'}'s note?`)) return
    try {
      await api.deleteNote(incidentId, note.id)
      onDeleted(note.id)
    } catch (e) {
      setError(e.message || 'Failed to delete note.')
    }
  }

  return (
    <section className="panel" style={{ marginBottom: 'var(--space-4)' }}>
      <div className="panel-toolbar">
        <h3 className="panel-h" style={{ margin: 0 }}>
          {mine ? 'My note' : (note.author_username ?? 'Unknown')}
        </h3>
        {!editing && (
          <div style={{ display: 'flex', gap: 'var(--space-3)', alignItems: 'center' }}>
            {note && note.version > 1 && (
              <button className="btn-link" type="button" onClick={() => setShowHistory(v => !v)}>
                {showHistory ? 'Hide history' : `History (v${note.version})`}
              </button>
            )}
            {mine && !isClosed && (
              <button className="btn" type="button" onClick={startEdit}>{note ? 'Edit' : 'Add a note'}</button>
            )}
            {note && canDelete && !isClosed && (
              <button className="btn-link danger" type="button" onClick={del}>Delete</button>
            )}
          </div>
        )}
      </div>

      {error && (
        <div className="alert error" role="alert" style={{ marginBottom: 'var(--space-2)' }}>
          <span className="alert-icon">!</span><span>{error}</span>
        </div>
      )}

      {editing ? (
        <div>
          <div className="det-add-tabs" style={{ marginBottom: 'var(--space-2)' }}>
            <button type="button" className={`btn ghost ${!preview ? 'active' : ''}`}
              style={{ fontSize: 12, padding: '2px 10px' }} onClick={() => setPreview(false)}>Write</button>
            <button type="button" className={`btn ghost ${preview ? 'active' : ''}`}
              style={{ fontSize: 12, padding: '2px 10px' }} onClick={() => setPreview(true)}>Preview</button>
          </div>
          {!preview ? (
            <textarea
              className="input"
              placeholder="Your notes on this incident (markdown supported)…"
              value={draftBody}
              onChange={e => setDraftBody(e.target.value)}
              rows={12}
              style={{ width: '100%', resize: 'vertical' }}
              disabled={saving}
              autoFocus
            />
          ) : (
            draftBody
              ? <div className="md-body"><ReactMarkdown>{draftBody}</ReactMarkdown></div>
              : <div style={{ color: 'var(--dim)', fontStyle: 'italic', fontSize: 13 }}>Nothing to preview yet.</div>
          )}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 'var(--space-2)' }}>
            <label style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-1)', fontSize: 13 }}>
              <input type="checkbox" checked={draftPrivate} onChange={e => setDraftPrivate(e.target.checked)} />
              Private (only visible to you)
            </label>
            <div style={{ display: 'flex', gap: 'var(--space-2)' }}>
              <button className="btn primary" type="button" onClick={save} disabled={!draftBody.trim() || saving}>
                {saving ? 'Saving…' : 'Save'}
              </button>
              <button className="btn" type="button" onClick={cancelEdit}>Cancel</button>
            </div>
          </div>
        </div>
      ) : note ? (
        <div>
          <div className="comment-meta" style={{ marginBottom: 'var(--space-2)' }}>
            <span className="comment-time" title={formatLocal(note.updated_at)}>Updated {relative(note.updated_at)}</span>
            {note.is_private && <span className="comment-edited">Private</span>}
          </div>
          <div className="md-body comment-body"><ReactMarkdown>{note.body}</ReactMarkdown></div>
          {showHistory && <NoteHistory incidentId={incidentId} note={note} onClose={() => setShowHistory(false)} />}
        </div>
      ) : (
        <div className="panel-empty">No note yet.</div>
      )}
    </section>
  )
}

export default function Notes() {
  const { inc, isClosed } = useOutletContext()
  const { user }          = useAuth()

  const [notes,   setNotes]   = useState([])
  const [loading, setLoading] = useState(true)
  const [error,   setError]   = useState('')

  const load = useCallback(async () => {
    try {
      const data = await api.listNotes(inc.id)
      setNotes(data.items)
    } catch (e) {
      setError(e.message || 'Failed to load notes.')
    } finally {
      setLoading(false)
    }
  }, [inc.id])

  useEffect(() => { load() }, [load])

  if (loading) return <div className="panel-empty">Loading notes…</div>

  const myNote = notes.find(n => n.author_id === user?.id) ?? null
  const others = notes.filter(n => n.author_id !== user?.id)

  const handleSaved = (saved) => setNotes(prev => [saved, ...prev.filter(n => n.id !== saved.id)])
  const handleDeleted = (id) => setNotes(prev => prev.filter(n => n.id !== id))

  return (
    <div className="comments-wrap">
      {error && (
        <div className="alert error" role="alert" style={{ marginBottom: 'var(--space-3)' }}>
          <span className="alert-icon">!</span><span>{error}</span>
        </div>
      )}

      <NoteCard
        incidentId={inc.id}
        note={myNote}
        mine
        canDelete
        isClosed={isClosed}
        onSaved={handleSaved}
        onDeleted={handleDeleted}
      />

      {others.length > 0 && (
        <>
          <h3 className="panel-h">Other analysts' notes</h3>
          {others.map(n => (
            <NoteCard
              key={n.id}
              incidentId={inc.id}
              note={n}
              mine={false}
              canDelete={user?.role === 'admin'}
              isClosed={isClosed}
              onSaved={handleSaved}
              onDeleted={handleDeleted}
            />
          ))}
        </>
      )}
    </div>
  )
}
