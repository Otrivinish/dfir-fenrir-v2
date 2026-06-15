import { useState, useEffect, useCallback, useRef } from 'react'
import { useOutletContext } from 'react-router-dom'
import { useAuth } from '../../../hooks/useAuth.jsx'
import { api } from '../../../api/client.js'
import { relative, formatLocal } from '../../../lib/datetime.js'

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

  const load = useCallback(async () => {
    try {
      const data = await api.listComments(inc.id, { limit: 200 })
      setComments(data.items)
    } catch (e) {
      setError(e.message || 'Failed to load comments.')
    } finally {
      setLoading(false)
    }
  }, [inc.id])

  useEffect(() => { load() }, [load])

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

            {canEdit(c) && editId !== c.id && (
              <div className="comment-actions">
                <button className="btn-link" type="button" onClick={() => startEdit(c)}>Edit</button>
                <button className="btn-link danger" type="button" onClick={() => del(c.id)}>Delete</button>
              </div>
            )}
          </div>
        ))}
        <div ref={bottomRef} />
      </div>

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
