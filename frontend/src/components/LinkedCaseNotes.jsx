import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import ReactMarkdown from 'react-markdown'
import { useAuth } from '../hooks/useAuth.jsx'
import { api } from '../api/client.js'
import { formatLocal } from '../lib/datetime.js'

// H2 — the case notes linked to one exhibit / entity / IOC / timeline event: a read-only list of each
// note's current revision (CN-2; edit and history live on the Case notes page) plus "Add note", which
// posts a new entry pre-linked to it.
// kind → [list filter, create field]
export const CASE_NOTE_LINK = {
  evidence:       ['evidence_id', 'evidence_ids'],
  entity:         ['entity_id', 'entity_ids'],
  ioc:            ['ioc_id', 'ioc_ids'],
  timeline_event: ['timeline_event_id', 'timeline_event_ids'],
}

// Who saved this revision, as recorded with it (CN-2), plus server time and the entry's SHA-256.
// Entries from before CN-2 carry no signature: the author's username is shown instead.
export function CaseNoteSignature({ note }) {
  return (
    <div className="case-note-sig" data-testid="case-note-signature">
      {note.hash_v >= 2 ? (
        <>
          <span>Signed</span>
          <span className="case-note-author">{note.signed_name}</span>
          {note.author_username && note.author_username !== note.signed_name && <span>({note.author_username})</span>}
          <span className="mono" title="Operational roles held on this incident when saved (else the platform role)">
            {note.signed_as.split(',').join(', ')}
          </span>
        </>
      ) : (
        <>
          <span className="case-note-author">{note.author_username || 'unknown'}</span>
          <span className="case-note-flag" title="Written before signed case notes: no signature was recorded">unsigned</span>
        </>
      )}
      <span className="mono" title={`${note.created_at} (UTC)`}>{formatLocal(note.created_at)}</span>
      <span className="case-note-hash mono" title={`SHA-256 ${note.content_sha256}`}>#{note.content_sha256.slice(0, 12)}</span>
    </div>
  )
}

export default function LinkedCaseNotes({ incidentId, kind, targetId, isClosed }) {
  const { user } = useAuth()
  const canWrite = !!user && user.role !== 'viewer'
  const [filter, field] = CASE_NOTE_LINK[kind]
  const [notes, setNotes] = useState(null)
  const [error, setError] = useState('')
  const [adding, setAdding] = useState(false)
  const [draft, setDraft] = useState('')
  const [busy, setBusy] = useState(false)

  const load = useCallback(() => {
    api.listAllPages(api.listCaseNotes, incidentId, { current: true, [filter]: targetId }, 200)
      .then(setNotes)
      .catch(e => { setNotes([]); setError(e.message || 'Could not load case notes.') })
  }, [incidentId, filter, targetId])
  useEffect(() => { load() }, [load])

  const post = async () => {
    setBusy(true); setError('')
    try {
      await api.createCaseNote(incidentId, { body: draft.trim(), [field]: [targetId] })
      setDraft(''); setAdding(false); load()
    } catch (e) {
      setError(e.message || 'Could not add the case note.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="case-notes-linked" data-testid={`linked-case-notes-${kind}`}>
      <div className="case-notes-linked-head">
        <span className="case-notes-linked-title">Case notes{notes ? ` (${notes.length})` : ''}</span>
        <Link className="btn-link" to={`/incidents/${incidentId}/notes`}>All case notes</Link>
      </div>
      {error && <div className="alert error" role="alert"><span className="alert-icon">!</span><span>{error}</span></div>}
      {notes === null ? <div className="case-note-empty">Loading…</div>
        : notes.length === 0 ? <div className="case-note-empty">No case notes linked yet.</div>
        : notes.map(n => (
          <div key={n.id} className="case-note compact">
            {n.revision > 1 && (
              <div className="case-note-meta">
                <span className="case-note-flag">edited · revision {n.revision}</span>
              </div>
            )}
            <div className="md-body case-note-body">
              <ReactMarkdown>{n.body}</ReactMarkdown>
            </div>
            <CaseNoteSignature note={n} />
          </div>
        ))}
      {canWrite && !isClosed && (adding ? (
        <div className="case-note-quick">
          <textarea className="input" rows={3} value={draft} maxLength={16384} autoFocus
                    aria-label="New case note" placeholder="Case note (markdown) — linked to this item"
                    onChange={e => setDraft(e.target.value)} disabled={busy} />
          <div className="case-note-actions">
            <button type="button" className="btn primary" onClick={post} disabled={busy || !draft.trim()}>
              {busy ? 'Posting…' : 'Post note'}
            </button>
            <button type="button" className="btn ghost" onClick={() => { setAdding(false); setDraft('') }} disabled={busy}>Cancel</button>
          </div>
        </div>
      ) : (
        <button type="button" className="btn ghost case-note-add" onClick={() => setAdding(true)}>+ Add note</button>
      ))}
    </div>
  )
}
