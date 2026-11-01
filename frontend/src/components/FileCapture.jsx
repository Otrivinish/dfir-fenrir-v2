import { Fragment } from 'react'
import LocalDateTimePicker from './LocalDateTimePicker.jsx'
import { formatLocal } from '../lib/datetime.js'

// S5 (EG-6) — a supporting document's capture record: when, by whom, with what tool, how, on which host or
// display, which URL, and what was visible (ISO/IEC 27037 §7.1.1.1). The server checks every field
// (files/capture.py); this only collects and shows them. Nothing is trimmed: the source and URL feed an
// exhibit's verbatim source record when the file is registered as an exhibit.

export const CAPTURE_METHODS = [
  { value: 'screen',          label: 'Whole screen' },
  { value: 'window',          label: 'One window' },
  { value: 'region',          label: 'Region of the screen' },
  { value: 'full_page',       label: 'Full web page' },
  { value: 'scrolling',       label: 'Scrolling capture' },
  { value: 'photo_of_screen', label: 'Photo of a screen' },
  { value: 'other',           label: 'Other' },
]
const METHOD_LABEL = Object.fromEntries(CAPTURE_METHODS.map(m => [m.value, m.label]))
const TEXT = ['capture_tool', 'capture_tool_version', 'capture_method', 'capture_source', 'capture_url', 'capture_context']
const MONO = { fontFamily: 'var(--font-mono)', fontSize: 12, whiteSpace: 'pre-wrap', wordBreak: 'break-all' }

// Form state. by: '' not recorded · 'me' · 'user' (another account, as recorded) · 'other' (a name).
export const EMPTY_CAPTURE = {
  captured_at: '', by: '', byId: null, byUsername: null, captured_by_name: '', capture_tool: '',
  capture_tool_version: '', capture_method: '', capture_source: '', capture_url: '', capture_context: '',
  capture_sha256: '',
}

export function captureFrom(file, me) {
  const by = file.captured_by_id ? (file.captured_by_id === me?.id ? 'me' : 'user') : file.captured_by_name ? 'other' : ''
  return {
    ...EMPTY_CAPTURE,
    ...Object.fromEntries(TEXT.map(k => [k, file[k] ?? ''])),
    captured_at: file.captured_at || '', by, byId: file.captured_by_id || null,
    byUsername: file.captured_by_username || null, captured_by_name: file.captured_by_name || '',
  }
}

// The request fields. Upload: only those filled in (form fields). Edit: every editable field, '' sent as null
// (the server records only what changed); capture_sha256 is never sent on an edit.
export function captureBody(s, me, { upload = false } = {}) {
  const byId = s.by === 'me' ? me?.id : s.by === 'user' ? s.byId : null
  const body = {
    ...Object.fromEntries(TEXT.map(k => [k, s[k] || null])),
    captured_at: s.captured_at || null,
    captured_by_id: byId || null,
    captured_by_name: s.by === 'other' ? (s.captured_by_name || null) : null,
  }
  if (!upload) return body
  return Object.fromEntries(Object.entries({ ...body, capture_sha256: s.capture_sha256 || null }).filter(([, v]) => v))
}

export function hasCapture(f) {
  return !!(f.captured_at || f.captured_by_id || f.captured_by_name || f.capture_sha256
            || TEXT.some(k => f[k]))
}

// One line under the file name: when · who · tool · how.
export function captureSummary(f) {
  const who = f.captured_by_username || f.captured_by_name
  return [f.captured_at && `Captured ${formatLocal(f.captured_at)}`, who && `by ${who}`,
          [f.capture_tool, f.capture_tool_version].filter(Boolean).join(' '), METHOD_LABEL[f.capture_method]]
    .filter(Boolean).join(' · ')
}

export function CaptureFields({ value: s, onChange, me, withHash = false, hashDisabledHint, idPrefix = 'cap', disabled }) {
  const set = (k, v) => onChange({ ...s, [k]: v })
  const text = (k, label, { max, placeholder, mono } = {}) => (
    <div className="field">
      <label className="field-label" htmlFor={`${idPrefix}-${k}`}>{label}</label>
      <input id={`${idPrefix}-${k}`} className="input" value={s[k]} maxLength={max} disabled={disabled}
             onChange={e => set(k, e.target.value)} placeholder={placeholder} spellCheck={!mono}
             autoComplete="off" style={mono ? MONO : undefined} />
    </div>
  )
  return (
    <div className="form" data-testid={`${idPrefix}-capture-fields`}>
      <div className="form-row">
        <div className="field">
          <label className="field-label" htmlFor={`${idPrefix}-at`}>Captured at</label>
          <LocalDateTimePicker id={`${idPrefix}-at`} value={s.captured_at} onChange={v => set('captured_at', v)}
                               clearable disabled={disabled} />
        </div>
        <div className="field">
          <label className="field-label" htmlFor={`${idPrefix}-by`}>Captured by</label>
          <select id={`${idPrefix}-by`} className="select" value={s.by} disabled={disabled}
                  onChange={e => set('by', e.target.value)}>
            <option value="">— not recorded —</option>
            <option value="me">Me{me?.username ? ` (${me.username})` : ''}</option>
            {s.byId && s.byId !== me?.id && <option value="user">{s.byUsername || 'Another user'} (as recorded)</option>}
            <option value="other">Someone else (name)</option>
          </select>
        </div>
        {s.by === 'other' && text('captured_by_name', 'Capturer’s name', { max: 128, placeholder: 'e.g. Jane Doe, IT helpdesk' })}
      </div>
      <div className="form-row">
        {text('capture_tool', 'Capture tool', { max: 128, placeholder: 'e.g. Snagit, Greenshot, Firefox screenshot' })}
        {text('capture_tool_version', 'Tool version', { max: 64 })}
        <div className="field">
          <label className="field-label" htmlFor={`${idPrefix}-method`}>Method</label>
          <select id={`${idPrefix}-method`} className="select" value={s.capture_method} disabled={disabled}
                  onChange={e => set('capture_method', e.target.value)}>
            <option value="">— not recorded —</option>
            {CAPTURE_METHODS.map(m => <option key={m.value} value={m.value}>{m.label}</option>)}
          </select>
        </div>
      </div>
      <div className="form-row">
        {text('capture_source', 'Captured on (host, device or display)', { max: 256, mono: true, placeholder: 'e.g. WS-FIN-017, display 2' })}
        {text('capture_url', 'URL', { max: 8192, mono: true, placeholder: 'e.g. https://login.example.com/…' })}
      </div>
      <div className="field">
        <label className="field-label" htmlFor={`${idPrefix}-context`}>What is visible</label>
        <textarea id={`${idPrefix}-context`} className="input" rows={2} maxLength={4096} value={s.capture_context}
                  disabled={disabled} onChange={e => set('capture_context', e.target.value)}
                  placeholder="Window title, application, where the window sits, what it shows" />
      </div>
      {withHash && (
        <div className="field">
          <label className="field-label" htmlFor={`${idPrefix}-sha256`}>SHA-256 at capture</label>
          <input id={`${idPrefix}-sha256`} className="input" value={s.capture_sha256} maxLength={64}
                 disabled={disabled || !!hashDisabledHint} onChange={e => set('capture_sha256', e.target.value)}
                 spellCheck={false} autoComplete="off" style={MONO} placeholder="64 hex characters" />
          <div className="field-hint">
            {hashDisabledHint || 'From the capture tool or your notes. The server compares it with the file before storing it and refuses a mismatch. It can’t be changed later.'}
          </div>
        </div>
      )}
    </div>
  )
}

// Read-only capture record.
export function CaptureRecord({ file }) {
  const rows = [
    ['Captured at', file.captured_at && formatLocal(file.captured_at)],
    ['Captured by', file.captured_by_username || file.captured_by_name],
    ['Tool', [file.capture_tool, file.capture_tool_version].filter(Boolean).join(' ')],
    ['Method', METHOD_LABEL[file.capture_method] || file.capture_method],
    ['Captured on', file.capture_source, true],
    ['URL', file.capture_url, true],
    ['What is visible', file.capture_context],
    ['SHA-256 at capture', file.capture_sha256, true],
  ].filter(([, v]) => v)
  if (rows.length === 0) return <div style={{ color: 'var(--muted)', fontSize: 13 }}>No capture record.</div>
  return (
    <dl className="kv" data-testid="file-capture-record">
      {rows.map(([k, v, mono]) => (
        <Fragment key={k}><dt>{k}</dt><dd style={mono ? MONO : { whiteSpace: 'pre-wrap' }}>{v}</dd></Fragment>
      ))}
    </dl>
  )
}
