import { useState, useEffect, useCallback, useRef } from 'react'
import { useOutletContext } from 'react-router-dom'
import { useAuth } from '../../../hooks/useAuth.jsx'
import { api } from '../../../api/client.js'
import { relative, formatLocal } from '../../../lib/datetime.js'
import PromoteDialog from '../../../components/PromoteDialog.jsx'

export default function Comments() {
  const { inc, isClosed } = useOutletContext()
  const { user }          = useAuth()

  const [comments,    setComments]    = useState([])
  const [loading,     setLoading]     = useState(true)
  const [error,       setError]       = useState('')
  const [body,        setBody]        = useState('')
  const [submitting,  setSubmitting]  = useState(false)
  const [editId,      setEditId]      = useState(null)
  const [editBody,    setEditBody]    = useState('')
  const bottomRef = useRef(null)

  // Each load gets a sequence number; only the newest one may set state, so an
  // older multi-page load that finishes late can't overwrite a newer view.
  const loadSeq = useRef(0)
  // The running load's controller: a newer load, an incident change or unmount aborts it.
  const loadAbort = useRef(null)
  const load = useCallback(async () => {
    const seq = ++loadSeq.current
    loadAbort.current?.abort()
    const { signal } = (loadAbort.current = new AbortController())
    try {
      // Every page (oldest first), so the newest comments are never cut off.
      const all = await api.listAllPages(api.listComments, inc.id, {}, 200, { signal })
      if (seq === loadSeq.current) setComments(all)
    } catch (e) {
      if (seq === loadSeq.current && !signal.aborted) setError(e.message || 'Failed to load comments.')
    } finally {
      if (seq === loadSeq.current) setLoading(false)
    }
  }, [inc.id])

  useEffect(() => { load(); return () => loadAbort.current?.abort() }, [load])

  const submit = async (e) => {
    e.preventDefault()
    if (!body.trim()) return
    setSubmitting(true)
    try {
      const c = await api.createComment(inc.id, { body: body.trim() })
      setComments(prev => [...prev, c])
      setBody('')
      setTimeout(() => bottomRef.current?.scrollIntoView({ behavior: 'smooth' }), 50)
    } catch (e) {
      setError(e.message || 'Failed to post comment.')
    } finally {
      setSubmitting(false)
    }
  }

  const startEdit = (c) => { setEditId(c.id); setEditBody(c.body) }
  const cancelEdit = () => { setEditId(null); setEditBody('') }

  const saveEdit = async (commentId) => {
    try {
      const updated = await api.updateComment(inc.id, commentId, { body: editBody.trim() })
      setComments(prev => prev.map(c => c.id === commentId ? updated : c))
      setEditId(null)
    } catch (e) {
      setError(e.message || 'Failed to update comment.')
    }
  }

  const del = async (commentId) => {
    if (!confirm('Delete this comment?')) return
    try {
      await api.deleteComment(inc.id, commentId)
      setComments(prev => prev.filter(c => c.id !== commentId))
    } catch (e) {
      setError(e.message || 'Failed to delete comment.')
    }
  }

  const canEdit = (c) => !isClosed && (c.author_id === user?.id || user?.role === 'admin')
  // J4 (R33): any analyst / admin may promote a comment to a timeline event or a decision.
  const canPromote = !isClosed && !!user && user.role !== 'viewer'
  const [promoting, setPromoting] = useState(null)
  const [promoted,  setPromoted]  = useState({})   // comment id -> 'timeline_event' | 'decision'

  if (loading) return <div className="panel-empty">Loading comments…</div>

  return (
    <div className="comments-wrap">
      {error && (
        <div className="alert error" role="alert" style={{ marginBottom: 'var(--space-3)' }}>
          <span className="alert-icon">!</span><span>{error}</span>
        </div>
      )}

      <div className="comments-thread">
        {comments.length === 0 && (
          <div className="panel-empty" style={{ padding: 'var(--space-4) 0' }}>No comments yet.</div>
        )}
        {comments.map(c => (
          <div key={c.id} className={`comment-item ${c.author_id === user?.id ? 'own' : ''}`}>
            <div className="comment-meta">
              <span className="comment-author">
                {c.author_username ?? '?'}{c.author_id === user?.id ? ' (you)' : ''}
              </span>
              <span className="comment-time" title={formatLocal(c.created_at)}>
                {relative(c.created_at)}
              </span>
              {c.edited_at && <span className="comment-edited">edited</span>}
            </div>

            {editId === c.id ? (
              <div>
                <textarea
                  className="input"
                  value={editBody}
                  onChange={e => setEditBody(e.target.value)}
                  rows={3}
                  style={{ width: '100%', resize: 'vertical' }}
                />
                <div style={{ display: 'flex', gap: 'var(--space-2)', marginTop: 'var(--space-2)' }}>
                  <button className="btn primary" type="button" onClick={() => saveEdit(c.id)} disabled={!editBody.trim()}>Save</button>
                  <button className="btn" type="button" onClick={cancelEdit}>Cancel</button>
                </div>
              </div>
            ) : (
              <div className="comment-body">{c.body}</div>
            )}

            {(canEdit(c) || canPromote) && editId !== c.id && (
              <div className="comment-actions">
                {canEdit(c) && <button className="btn-link" type="button" onClick={() => startEdit(c)}>Edit</button>}
                {canEdit(c) && <button className="btn-link danger" type="button" onClick={() => del(c.id)}>Delete</button>}
                {canPromote && (
                  <button className="btn-link" type="button" data-promote-comment onClick={() => setPromoting(c)}>
                    {promoted[c.id] ? `Promoted ✓ (${promoted[c.id] === 'decision' ? 'decision' : 'timeline'})` : 'Promote'}
                  </button>
                )}
              </div>
            )}
          </div>
        ))}
        <div ref={bottomRef} />
      </div>

      {promoting && (
        <PromoteDialog
          incidentId={inc.id}
          source={{ kind: 'comment', id: promoting.id, body: promoting.body, created_at: promoting.created_at }}
          onClose={() => setPromoting(null)}
          onDone={(res) => { setPromoted(p => ({ ...p, [promoting.id]: res.target })); setPromoting(null) }}
        />
      )}

      {!isClosed && (
        <form className="comment-compose" onSubmit={submit}>
          <textarea
            className="input"
            placeholder="Add a comment…"
            value={body}
            onChange={e => setBody(e.target.value)}
            rows={3}
            style={{ width: '100%', resize: 'vertical' }}
            disabled={submitting}
          />
          <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 'var(--space-2)' }}>
            <button
              className="btn primary"
              type="submit"
              disabled={!body.trim() || submitting}
            >{submitting ? 'Posting…' : 'Post comment'}</button>
          </div>
        </form>
      )}
    </div>
  )
}
