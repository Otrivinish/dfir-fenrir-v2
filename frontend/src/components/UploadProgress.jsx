import { useEffect, useRef, useState } from 'react'
import { api } from '../api/client.js'
import { formatLocal } from '../lib/datetime.js'

// G1 stage 3b — a chunked upload in progress (api/client.js uploadInChunks): bar, bytes, percent and
// Cancel. The server encrypts each chunk as it arrives and stores nothing until the upload completes;
// cancelling (or leaving the page) deletes what it has received. While the server completes the upload
// (checks the hash and stores it) there is no Cancel: its result would be unknown.

const MIB = 1024 * 1024
const fmt = (n) => (n >= MIB ? `${(n / MIB).toFixed(1)} MiB` : `${Math.max(0, Math.round(n / 1024))} KiB`)

// One upload at a time per page: start() → { onProgress, signal, onLimit } for the api call, done() after it.
// `limit` = the caller's open sessions after a 409 upload_limit_reached ([] when the server doesn't list
// them), shown by <UploadProgress limit=…> with a Cancel per session.
export function useChunkedUpload() {
  const [progress, setProgress] = useState(null)
  const [limit, setLimit] = useState(null)
  const ctrl = useRef(null)
  useEffect(() => () => ctrl.current?.abort(), [])      // leaving the page cancels the upload
  const start = (total = 0) => {
    ctrl.current = new AbortController()
    setProgress({ sent: 0, total, phase: null })
    setLimit(null)
    return {
      onProgress: (sent, t, phase = null) => setProgress({ sent, total: t, phase }),
      signal: ctrl.current.signal,
      onLimit: (open) => setLimit(open || []),
    }
  }
  const done = () => { ctrl.current = null; setProgress(null) }
  const cancel = () => ctrl.current?.abort()
  return { progress, start, done, cancel, limit }
}

// FE-M2 — an upload the server kept after a refused complete (err.retained): finish it with
// retry(body, opts) or drop it with discard(). Discarded when the component unmounts.
export function useRetainedUpload() {
  const [held, setHeld] = useState(null)       // { retry, discard, filename, size }
  const ref = useRef(null)
  useEffect(() => () => { ref.current?.discard() }, [])
  const keep = (err, file) => {
    const h = { retry: err.retryComplete, discard: err.discard, filename: file?.name, size: file?.size }
    ref.current = h; setHeld(h)
  }
  const drop = ({ cancel = true } = {}) => {
    if (cancel) ref.current?.discard()
    ref.current = null; setHeld(null)
  }
  return { held, keep, drop }
}

export default function UploadProgress({ progress, onCancel, label = 'Uploading', testid = 'upload-progress',
                                         limit = null, incidentId = null }) {
  return (
    <>
      {progress && <Bar progress={progress} onCancel={onCancel} label={label} testid={testid} />}
      {limit && <OpenUploads open={limit} incidentId={incidentId} testid={`${testid}-limit`} />}
    </>
  )
}

function Bar({ progress, onCancel, label, testid }) {
  const { sent, total, phase } = progress
  const pct = total > 0 ? Math.min(100, Math.floor((sent * 100) / total)) : 0
  const finishing = phase === 'completing' || (total > 0 && sent >= total)
  return (
    <div className="upload-progress" data-testid={testid} data-phase={finishing ? 'completing' : 'sending'}
         role="status" aria-live="polite">
      <div className="upload-progress-head">
        <span>{finishing ? 'Checking the hash and storing…' : `${label} — encrypted as it arrives`}</span>
        <span className="upload-progress-num" data-testid={`${testid}-num`}>{fmt(sent)} / {fmt(total)} · {pct}%</span>
        {onCancel && !finishing && (
          <button type="button" className="btn ghost" onClick={onCancel} data-testid={`${testid}-cancel`}>Cancel upload</button>
        )}
      </div>
      <div className="upload-progress-bar" role="progressbar" aria-label={label}
           aria-valuemin={0} aria-valuemax={100} aria-valuenow={pct}>
        <div className="upload-progress-fill" style={{ width: `${pct}%` }} />
      </div>
    </div>
  )
}

// FE-M5 / M7 — 409 upload_limit_reached: the caller's open upload sessions (e.g. left by another tab),
// each with Cancel. When the server doesn't list them, say how they end.
function OpenUploads({ open, incidentId, testid }) {
  const [rows, setRows] = useState(open)
  const [err, setErr] = useState(null)
  useEffect(() => { setRows(open) }, [open])
  const cancel = async (u) => {
    setErr(null)
    try {
      await api.cancelUpload(u.incident_id || incidentId, u.upload_id)
    } catch (e) {
      if (e.code !== 'upload_not_found') { setErr(e.message || 'Could not cancel the upload'); return }
    }
    setRows(rows.filter(x => x.upload_id !== u.upload_id))
  }
  return (
    <div className="alert warn" role="status" data-testid={testid} style={{ marginTop: 'var(--space-2)' }}>
      <span className="alert-icon">!</span>
      <div style={{ minWidth: 0, flex: 1 }}>
        {open.length ? (
          <>
            <div>Your open uploads (at most 3 at a time). Cancel one you no longer need, then upload again:</div>
            <ul style={{ listStyle: 'none', margin: 'var(--space-1) 0 0', padding: 0, display: 'flex', flexDirection: 'column', gap: 4 }}>
              {rows.map(u => (
                <li key={u.upload_id} data-testid={`${testid}-row`}
                    style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'center', flexWrap: 'wrap', fontSize: 12 }}>
                  <span style={{ fontFamily: 'var(--font-mono)', overflowWrap: 'anywhere' }}>{u.filename || u.upload_id}</span>
                  <span style={{ color: 'var(--muted)' }}>
                    {u.purpose ? `${u.purpose} · ` : ''}{u.size != null ? `${fmt(u.received_bytes || 0)} / ${fmt(u.size)}` : ''}
                    {u.expires_at ? ` · ends ${formatLocal(u.expires_at)} if idle` : ''}
                  </span>
                  <button type="button" className="btn ghost" onClick={() => cancel(u)}>Cancel</button>
                </li>
              ))}
            </ul>
            {!rows.length && <div style={{ marginTop: 4 }}>All cancelled: upload again.</div>}
          </>
        ) : (
          <div>You have 3 uploads open (another tab, or a page closed mid-upload). Each ends after 30 minutes
            without progress; finish or cancel one there, then upload again.</div>
        )}
        {err && <div style={{ color: 'var(--crit)', marginTop: 4 }}>{err}</div>}
      </div>
    </div>
  )
}
