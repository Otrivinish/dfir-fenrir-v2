import { useState, useEffect, useCallback, useMemo } from 'react'
import { useOutletContext } from 'react-router-dom'
import ReactMarkdown from 'react-markdown'
import { useAuth } from '../../hooks/useAuth.jsx'
import { api } from '../../api/client.js'
import { relative, formatLocal } from '../../lib/datetime.js'
import { lineDiff } from '../../lib/diff.js'

// H2 — Case notes: shared, append-only entries (they replace the private scratchpad, which stays
// as a read-only legacy view for its author with "Post as case note"). Nothing is edited or
// deleted here: a correction is a new entry and the original is shown struck through.

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

// Link kinds: create field, list label, how an item of that kind is named.
const KINDS = [
  { field: 'evidence_ids',       group: 'Exhibits',        list: api.listEvidence,       name: x => `${x.identifier} · ${x.name}` },
  { field: 'entity_ids',         group: 'Entities',        list: api.listEntities,       name: x => `[${x.type}] ${x.value}` },
  { field: 'ioc_ids',            group: 'IOCs',            list: api.listIocs,           name: x => `[${x.type}] ${x.value}` },
  { field: 'timeline_event_ids', group: 'Timeline events', list: api.listTimelineEvents, name: x => `${formatLocal(x.event_time)} ${x.description}` },
]
const MAX_CHARS = 16384

function Alert({ text }) {
  return text ? <div className="alert error" role="alert"><span className="alert-icon">!</span><span>{text}</span></div> : null
}

// Picked links as chips; "Add link" is one grouped select over the incident's exhibits,
// entities, IOCs and timeline events (the Respond target-picker pattern).
function LinkPicker({ targets, links, setLinks, disabled }) {
  const picked = new Set(KINDS.flatMap(k => links[k.field].map(id => `${k.field}:${id}`)))
  const add = (e) => {
    const [field, id] = e.target.value.split(':')
    if (field && id) setLinks(l => ({ ...l, [field]: [...l[field], id] }))
  }
  return (
    <div className="case-note-links">
      {KINDS.flatMap(k => links[k.field].map(id => (
        <span key={`${k.field}:${id}`} className="case-note-chip">
          {k.group.replace(/s$/, '')}: {targets.byId[id] ? k.name(targets.byId[id]) : id.slice(0, 8)}
          {!disabled && (
            <button type="button" className="case-note-chip-x" aria-label="Remove link"
                    onClick={() => setLinks(l => ({ ...l, [k.field]: l[k.field].filter(x => x !== id) }))}>×</button>
          )}
        </span>
      )))}
      <select className="select compact" aria-label="Add link" value="" onChange={add}
              disabled={disabled || !targets.loaded} data-testid="case-note-link-pick">
        <option value="">{targets.loaded ? '+ Link an item…' : 'Loading items…'}</option>
        {KINDS.map(k => targets[k.field].length > 0 && (
          <optgroup key={k.field} label={k.group}>
            {targets[k.field].filter(x => !picked.has(`${k.field}:${x.id}`)).map(x => (
              <option key={x.id} value={`${k.field}:${x.id}`}>{k.name(x)}</option>
            ))}
          </optgroup>
        ))}
      </select>
    </div>
  )
}

function Composer({ incidentId, targets, correcting, onCancelCorrect, onPosted }) {
  const empty = Object.fromEntries(KINDS.map(k => [k.field, []]))
  const [body, setBody]       = useState('')
  const [links, setLinks]     = useState(empty)
  const [preview, setPreview] = useState(false)
  const [busy, setBusy]       = useState(false)
  const [error, setError]     = useState('')

  const post = async () => {
    setBusy(true); setError('')
    try {
      const n = await api.createCaseNote(incidentId, {
        body: body.trim(), ...links, ...(correcting ? { corrects_id: correcting.id } : {}),
      })
      setBody(''); setLinks(empty); setPreview(false)
      onPosted(n)
    } catch (e) {
      setError(e.message || 'Could not post the case note.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="panel case-note-composer" data-testid="case-note-composer">
      <div className="panel-toolbar">
        <h3 className="panel-h">{correcting ? 'Post a correction' : 'New case note'}</h3>
        <div className="det-add-tabs">
          <button type="button" className={`btn ghost ${!preview ? 'active' : ''}`} onClick={() => setPreview(false)}>Write</button>
          <button type="button" className={`btn ghost ${preview ? 'active' : ''}`} onClick={() => setPreview(true)}>Preview</button>
        </div>
      </div>
      {correcting && (
        <div className="case-note-correcting">
          Correcting the entry by <strong>{correcting.author_username || 'unknown'}</strong> at{' '}
          <span className="mono">{formatLocal(correcting.created_at)}</span>. The original stays as written and is shown struck through.
          <button type="button" className="btn-link" onClick={onCancelCorrect}>Cancel correction</button>
        </div>
      )}
      <Alert text={error} />
      {!preview ? (
        <textarea className="input" rows={6} value={body} maxLength={MAX_CHARS} disabled={busy}
                  aria-label="Case note text" placeholder="What you did, saw or decided, and why (markdown)…"
                  onChange={e => setBody(e.target.value)} />
      ) : body.trim()
        ? <div className="md-body"><ReactMarkdown>{body}</ReactMarkdown></div>
        : <div className="case-note-empty">Nothing to preview yet.</div>}
      <LinkPicker targets={targets} links={links} setLinks={setLinks} disabled={busy} />
      <div className="case-note-actions">
        <span className="case-note-hint">Entries can't be edited or deleted once posted. Time is set by the server.</span>
        <button type="button" className="btn primary" onClick={post} disabled={busy || !body.trim()}>
          {busy ? 'Posting…' : correcting ? 'Post correction' : 'Post note'}
        </button>
      </div>
    </section>
  )
}

function CaseNoteEntry({ note, byNoteId, targets, canCorrect, onCorrect }) {
  const fix = note.corrected_by_id && byNoteId[note.corrected_by_id]
  return (
    <article id={`cn-${note.id}`} className="case-note" data-testid="case-note">
      <div className="case-note-meta">
        <span className="case-note-author">{note.author_username || 'unknown'}</span>
        <span className="mono" title={`${note.created_at} (UTC)`}>{formatLocal(note.created_at)}</span>
        {note.source_scratchpad_id && <span className="case-note-flag">from scratchpad</span>}
        {note.corrects_id && (
          <a className="case-note-flag" href={`#cn-${note.corrects_id}`}>correction of an earlier entry ↑</a>
        )}
        {note.corrected_by_id && (
          <a className="case-note-flag" href={`#cn-${note.corrected_by_id}`}>
            corrected{fix ? ` by ${fix.author_username || 'unknown'} at ${formatLocal(fix.created_at)}` : ''} ↓
          </a>
        )}
        <span className="case-note-hash mono" title={`SHA-256 ${note.content_sha256}`}>#{note.content_sha256.slice(0, 12)}</span>
      </div>
      <div className={`md-body case-note-body${note.corrected_by_id ? ' case-note-struck' : ''}`}>
        <ReactMarkdown>{note.body}</ReactMarkdown>
      </div>
      {KINDS.some(k => note[k.field].length) && (
        <div className="case-note-links">
          {KINDS.flatMap(k => note[k.field].map(id => (
            <span key={`${k.field}:${id}`} className="case-note-chip">
              {k.group.replace(/s$/, '')}: {targets.byId[id] ? k.name(targets.byId[id]) : `${id.slice(0, 8)} (not found)`}
            </span>
          )))}
        </div>
      )}
      {canCorrect && (
        <div className="case-note-actions">
          <button type="button" className="btn-link" onClick={() => onCorrect(note)}>Correct</button>
        </div>
      )}
    </article>
  )
}

function LegacyScratchpad({ incidentId, note, mine, canPost, onPosted }) {
  const [showHistory, setShowHistory] = useState(false)
  const [busy, setBusy]   = useState(false)
  const [error, setError] = useState('')
  const post = async () => {
    setBusy(true); setError('')
    try {
      onPosted(await api.createCaseNote(incidentId, { source_scratchpad_id: note.id }))
    } catch (e) {
      setError(e.message || 'Could not post the scratchpad.')
    } finally {
      setBusy(false)
    }
  }
  return (
    <section className="panel case-note-legacy" data-testid={mine ? 'legacy-scratchpad-mine' : 'legacy-scratchpad'}>
      <div className="panel-toolbar">
        <h3 className="panel-h">{mine ? 'Your scratchpad (legacy, read-only)' : `${note.author_username ?? 'Unknown'}'s scratchpad (legacy, read-only)`}</h3>
        <div className="case-note-actions">
          {note.version > 1 && (
            <button className="btn-link" type="button" onClick={() => setShowHistory(v => !v)}>
              {showHistory ? 'Hide history' : `History (v${note.version})`}
            </button>
          )}
          {mine && canPost && (
            <button className="btn" type="button" onClick={post} disabled={busy}>{busy ? 'Posting…' : 'Post as case note'}</button>
          )}
        </div>
      </div>
      <Alert text={error} />
      <div className="comment-meta">
        <span className="comment-time" title={formatLocal(note.updated_at)}>Last saved {relative(note.updated_at)}</span>
        {note.is_private && <span className="comment-edited">Private — only you can see it</span>}
      </div>
      <div className="md-body comment-body"><ReactMarkdown>{note.body}</ReactMarkdown></div>
      {showHistory && <NoteHistory incidentId={incidentId} note={note} onClose={() => setShowHistory(false)} />}
    </section>
  )
}

export default function Notes() {
  const { inc, isClosed } = useOutletContext()
  const { user }          = useAuth()
  const canWrite = !!user && user.role !== 'viewer'

  const [notes,   setNotes]   = useState(null)
  const [legacy,  setLegacy]  = useState([])
  const [targets, setTargets] = useState({ loaded: false, byId: {}, ...Object.fromEntries(KINDS.map(k => [k.field, []])) })
  const [author,  setAuthor]  = useState('')
  const [exhibit, setExhibit] = useState('')
  const [correcting, setCorrecting] = useState(null)
  const [error,   setError]   = useState('')

  const load = useCallback(async () => {
    try {
      setNotes(await api.listAllPages(api.listCaseNotes, inc.id, { author_id: author, evidence_id: exhibit }, 200))
    } catch (e) {
      setNotes([]); setError(e.message || 'Failed to load case notes.')
    }
  }, [inc.id, author, exhibit])
  useEffect(() => { load() }, [load])

  useEffect(() => {
    api.listNotes(inc.id).then(d => setLegacy(d.items)).catch(() => setLegacy([]))
    Promise.allSettled(KINDS.map(k => api.listAllPages(k.list, inc.id, {}, 200))).then(res => {
      const t = { loaded: true, byId: {} }
      KINDS.forEach((k, i) => {
        t[k.field] = res[i].status === 'fulfilled' ? res[i].value : []
        for (const x of t[k.field]) t.byId[x.id] = x
      })
      setTargets(t)
    })
  }, [inc.id])

  const byNoteId = useMemo(() => Object.fromEntries((notes || []).map(n => [n.id, n])), [notes])
  const authors  = useMemo(() => {
    const m = new Map((notes || []).map(n => [n.author_id, n.author_username]))
    if (author && !m.has(author)) m.set(author, 'selected author')
    return [...m.entries()]
  }, [notes, author])

  const posted = () => { setCorrecting(null); load() }
  const mayCorrect = n => canWrite && !isClosed && !n.corrected_by_id && (n.author_id === user?.id || user?.role === 'admin')
  const myLegacy = legacy.filter(n => n.author_id === user?.id)
  const otherLegacy = legacy.filter(n => n.author_id !== user?.id)

  return (
    <div className="comments-wrap case-notes" data-testid="case-notes-page">
      <p className="case-note-intro">
        Shared, append-only case notes: everyone who can see this incident reads them. Entries can't be edited or
        deleted — post a correction instead. Each entry's SHA-256 is recorded in the audit log and exported with the
        LE package and the full report.
      </p>
      <Alert text={error} />

      {canWrite && !isClosed && (
        <Composer incidentId={inc.id} targets={targets} correcting={correcting}
                  onCancelCorrect={() => setCorrecting(null)} onPosted={posted} />
      )}
      {isClosed && <div className="case-note-empty">The incident is closed: case notes are read-only. Re-open it to add one.</div>}

      <div className="panel-toolbar case-note-filters">
        <h3 className="panel-h">Entries{notes ? ` (${notes.length})` : ''}</h3>
        <select className="select" aria-label="Filter by author" value={author} onChange={e => setAuthor(e.target.value)}>
          <option value="">All authors</option>
          {authors.map(([id, name]) => <option key={id} value={id}>{name || id.slice(0, 8)}</option>)}
        </select>
        <select className="select" aria-label="Filter by exhibit" value={exhibit} onChange={e => setExhibit(e.target.value)}>
          <option value="">All exhibits</option>
          {targets.evidence_ids.map(x => <option key={x.id} value={x.id}>{KINDS[0].name(x)}</option>)}
        </select>
      </div>

      {notes === null ? <div className="panel-empty">Loading case notes…</div>
        : notes.length === 0 ? <div className="panel-empty">No case notes{author || exhibit ? ' match these filters' : ' yet'}.</div>
        : notes.map(n => (
          <CaseNoteEntry key={n.id} note={n} byNoteId={byNoteId} targets={targets}
                         canCorrect={mayCorrect(n)}
                         onCorrect={note => { setCorrecting(note); window.scrollTo({ top: 0, behavior: 'smooth' }) }} />
        ))}

      {(myLegacy.length > 0 || otherLegacy.length > 0) && (
        <details className="case-note-legacy-wrap" open={myLegacy.length > 0}>
          <summary>Legacy scratchpads ({legacy.length})</summary>
          <p className="case-note-hint">
            Scratchpads were replaced by case notes. They are kept read-only and are never published for you —
            use <strong>Post as case note</strong> to share yours.
          </p>
          {myLegacy.map(n => (
            <LegacyScratchpad key={n.id} incidentId={inc.id} note={n} mine canPost={canWrite && !isClosed} onPosted={posted} />
          ))}
          {otherLegacy.map(n => (
            <LegacyScratchpad key={n.id} incidentId={inc.id} note={n} mine={false} canPost={false} onPosted={posted} />
          ))}
        </details>
      )}
    </div>
  )
}
