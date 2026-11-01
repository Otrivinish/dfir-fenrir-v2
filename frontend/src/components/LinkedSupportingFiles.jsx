import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api/client.js'
import { captureSummary } from './FileCapture.jsx'

// S5 (EG-7) — the supporting documents linked to one exhibit / timeline event / IOC as corroborating it
// (read-only; link and unlink on Evidence › Supporting documents). kind = the API's target_type.
export default function LinkedSupportingFiles({ incidentId, kind, targetId }) {
  const [files, setFiles] = useState(null)
  const [error, setError] = useState('')

  useEffect(() => {
    let cancelled = false
    setFiles(null); setError('')
    api.listIncidentFiles(incidentId, { linked_type: kind, linked_id: targetId })
      .then(d => { if (!cancelled) setFiles(d.items || []) })
      .catch(e => { if (!cancelled) { setFiles([]); setError(e.message || 'Could not load supporting documents.') } })
    return () => { cancelled = true }
  }, [incidentId, kind, targetId])

  return (
    <div className="case-notes-linked" data-testid={`linked-files-${kind}`}>
      <div className="case-notes-linked-head">
        <span className="case-notes-linked-title">Supporting documents{files ? ` (${files.length})` : ''}</span>
        <Link className="btn-link" to={`/incidents/${incidentId}/evidence/documents`}>All supporting documents</Link>
      </div>
      {error && <div className="alert error" role="alert"><span className="alert-icon">!</span><span>{error}</span></div>}
      {files === null ? <div className="case-note-empty">Loading…</div>
        : files.length === 0 ? <div className="case-note-empty">No supporting documents linked.</div>
        : files.map(f => {
          const link = (f.links || []).find(l => l.target_type === kind && l.target_id === targetId)
          const summary = captureSummary(f)
          return (
            <div key={f.id} style={{ fontSize: 12, marginBottom: 'var(--space-2)' }}>
              <a href={api.incidentFileDownloadUrl(incidentId, f.id)} title="Download"
                 style={{ fontFamily: 'var(--font-mono)', wordBreak: 'break-all' }}>{f.original_name}</a>
              {f.sha256 && (
                <span title={`SHA-256 ${f.sha256}`} style={{ marginLeft: 'var(--space-2)', color: 'var(--dim)', fontFamily: 'var(--font-mono)' }}>
                  {f.sha256.slice(0, 12)}…
                </span>
              )}
              {summary && <div style={{ color: 'var(--muted)' }}>{summary}</div>}
              {link?.note && <div style={{ color: 'var(--text)', whiteSpace: 'pre-wrap' }}>{link.note}</div>}
            </div>
          )
        })}
    </div>
  )
}
