import { useRef, useState } from 'react'
import { useDialogFocus } from '../hooks/useDialogFocus.js'
import { DraftBadge } from './ExhibitPicker.jsx'

// H4 — shared by Supporting documents (incident Files) and the entity drawer's attachments: the
// server hash, the exhibit pill, the rename / delete dialogs (a reason is required) and the
// "can't delete: still referenced" message. The server enforces all of it; this only asks.

export const REASON_MIN = 10

// Esc inside a dialog closes only the dialog: it is marked handled (defaultPrevented) so a surrounding
// panel's own Esc handler (the entity drawer's) leaves it alone.
const markEscHandled = (e) => { if (e.key === 'Escape') e.preventDefault() }

// The server's SHA-256 of the original, shortened; the full hashes on hover.
export function FileHash({ file }) {
  if (!file.sha256) {
    return <span style={{ color: 'var(--dim)', fontSize: 11 }} title="Not hashed yet (uploaded before server hashing)">—</span>
  }
  const all = `SHA-256 ${file.sha256}` + (file.sha1 ? `\nSHA-1 ${file.sha1}` : '') + (file.md5 ? `\nMD5 ${file.md5}` : '')
  return (
    <span data-testid="file-hash" title={all}
          style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--muted)', whiteSpace: 'nowrap' }}>
      {file.sha256.slice(0, 12)}…
    </span>
  )
}

// The exhibit this file was registered as (with the draft badge while unsealed).
export function ExhibitPill({ file }) {
  if (!file.evidence_id) return null
  return (
    <span style={{ display: 'inline-flex', gap: 'var(--space-1)', alignItems: 'center', flexWrap: 'wrap' }}>
      <span className="pill" data-testid="file-exhibit-pill" style={{ fontSize: 10, fontFamily: 'var(--font-mono)' }}
            title="Registered as this exhibit (chain of custody in Evidence)">
        ⛁ {file.evidence_identifier || 'exhibit'}
      </span>
      {file.evidence_sealed === false && <DraftBadge />}
    </span>
  )
}

const REF_LABELS = {
  report_figure: 'it is a report figure (untick Include)',
  generated_report: 'a saved report shows it',
  case_note: 'a case note cites it',
  exhibit: 'it is registered as an exhibit',
  entity: 'it is attached to an entity (unlink it first)',
}

// 409 file_referenced → one sentence naming what still relies on the file.
export function fileRefsMessage(refs) {
  const kinds = [...new Set((refs || []).map(r => REF_LABELS[r.type] || r.type))]
  return `This file can't be deleted: ${kinds.join('; ') || 'another record relies on it'}.`
}

// Rename (`rename`: a name field too) or delete, with the required reason. onConfirm(reason, name)
// throws to show why it failed.
export function FileReasonModal({ file, rename = false, onConfirm, onClose }) {
  const [name, setName]   = useState(file.original_name || '')
  const [text, setText]   = useState('')
  const [busy, setBusy]   = useState(false)
  const [error, setError] = useState(null)
  const dialogRef = useRef(null)
  useDialogFocus(dialogRef, () => { if (!busy) onClose() })
  const n = text.trim().length
  const nameOk = !rename || (name.trim() && name.trim() !== file.original_name)
  const id = rename ? 'file-rename' : 'file-delete'

  const submit = async (e) => {
    e.preventDefault()
    setError(null); setBusy(true)
    try {
      await onConfirm(text.trim(), name.trim())
    } catch (err) {
      setError(err.message || (rename ? 'Rename failed.' : 'Delete failed.'))
      setBusy(false)
    }
  }

  return (
    <div className="modal-backdrop">
      <div className="modal" ref={dialogRef} role="dialog" aria-modal="true" aria-labelledby={`${id}-title`} style={{ maxWidth: 520 }}
           onKeyDown={markEscHandled}>
        <div className="modal-head">
          <h2 id={`${id}-title`}>{rename ? 'Rename file' : 'Delete file'}</h2>
          <button type="button" className="modal-close" onClick={onClose} disabled={busy} aria-label="Close">×</button>
        </div>
        <form onSubmit={submit}>
          <div className="modal-body">
            <div className="form">
              <p style={{ margin: 0, color: 'var(--text)', fontSize: 14, lineHeight: 1.6, wordBreak: 'break-all' }}>
                <b>{file.original_name}</b>{rename
                  ? ' — the stored bytes and their hashes don’t change. The audit log keeps the old and new name and your reason.'
                  : ' — the file and its record are removed permanently. The audit log keeps its hashes and your reason.'}
              </p>
              {rename && (
                <div className="field">
                  <label className="field-label" htmlFor={`${id}-name`}>New name</label>
                  <input id={`${id}-name`} className="input" maxLength={512} required value={name}
                         onChange={e => setName(e.target.value)} />
                </div>
              )}
              <div className="field">
                <label className="field-label" htmlFor={`${id}-reason`}>Reason</label>
                <textarea id={`${id}-reason`} className="input" rows={3} maxLength={2000} required
                          placeholder={rename ? 'e.g. Name it after the host it was captured on' : 'e.g. Uploaded to the wrong incident'}
                          value={text} onChange={e => setText(e.target.value)} />
                <span className="field-hint">
                  {n < REASON_MIN ? `At least ${REASON_MIN} characters (${n} so far).` : 'Recorded in the audit log.'}
                </span>
              </div>
              {error && (
                <div className="alert error" role="alert">
                  <span className="alert-icon">!</span><span>{error}</span>
                </div>
              )}
            </div>
          </div>
          <div className="modal-foot">
            <button type="button" className="btn ghost" onClick={onClose} disabled={busy}>Cancel</button>
            <button type="submit" className="btn primary" disabled={busy || n < REASON_MIN || !nameOk}>
              {busy ? (rename ? 'Renaming…' : 'Deleting…') : (rename ? 'Rename' : 'Delete file')}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

// "Register as exhibit" confirmation: what it does, then the result (new draft / linked / already).
export function RegisterExhibitModal({ file, onConfirm, onClose }) {
  const [busy, setBusy]     = useState(false)
  const [error, setError]   = useState(null)
  const [result, setResult] = useState(null)
  const dialogRef = useRef(null)
  useDialogFocus(dialogRef, () => { if (!busy) onClose() })

  const go = async () => {
    setError(null); setBusy(true)
    try {
      setResult(await onConfirm())
    } catch (err) {
      setError(err.message || 'Could not register the exhibit.')
    } finally {
      setBusy(false)
    }
  }

  const done = {
    registered: `Registered as draft exhibit ${result?.evidence_identifier}. Complete its acquisition record and seal it in Evidence › Items.`,
    sha256_match: `An exhibit with the same SHA-256 already exists: linked to ${result?.evidence_identifier} (no second copy).`,
    already_registered: `Already registered as ${result?.evidence_identifier}.`,
  }[result?.exhibit_link]

  return (
    <div className="modal-backdrop">
      <div className="modal" ref={dialogRef} role="dialog" aria-modal="true" aria-labelledby="file-register-title" style={{ maxWidth: 520 }}
           onKeyDown={markEscHandled}>
        <div className="modal-head">
          <h2 id="file-register-title">Register as exhibit</h2>
          <button type="button" className="modal-close" onClick={onClose} disabled={busy} aria-label="Close">×</button>
        </div>
        <div className="modal-body">
          <div className="form">
            <p style={{ margin: 0, color: 'var(--text)', fontSize: 14, lineHeight: 1.6, wordBreak: 'break-all' }}>
              <b>{file.original_name}</b> is copied into the evidence store as an unsealed draft exhibit, collected by you
              and in your custody, after its SHA-256 is checked against the one recorded at upload. If the incident
              already holds an exhibit with the same SHA-256, that one is linked instead. The file stays here as a
              supporting document.
            </p>
            {done && (
              <div className="alert info" role="status" data-testid="file-register-result">
                <span className="alert-icon">✓</span><span style={{ color: 'var(--text)' }}>{done}</span>
              </div>
            )}
            {error && (
              <div className="alert error" role="alert">
                <span className="alert-icon">!</span><span>{error}</span>
              </div>
            )}
          </div>
        </div>
        <div className="modal-foot">
          <button type="button" className="btn ghost" onClick={onClose} disabled={busy}>{result ? 'Close' : 'Cancel'}</button>
          {!result && (
            <button type="button" className="btn primary" onClick={go} disabled={busy}>
              {busy ? 'Registering…' : 'Register as exhibit'}
            </button>
          )}
        </div>
      </div>
    </div>
  )
}
