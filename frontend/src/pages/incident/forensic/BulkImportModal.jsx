import { useEffect, useRef, useState } from 'react'
import { api } from '../../../api/client.js'

const IOC_TYPES_SET = new Set([
  'ip', 'domain', 'url', 'hash_md5', 'hash_sha1', 'hash_sha256',
  'email', 'registry_key', 'file_path', 'other',
])

const IOC_TYPE_LABELS = {
  ip: 'IP address', domain: 'Domain', url: 'URL',
  hash_md5: 'Hash (MD5)', hash_sha1: 'Hash (SHA1)', hash_sha256: 'Hash (SHA256)',
  email: 'Email', registry_key: 'Registry key', file_path: 'File path', other: 'Other',
}

const EXAMPLE_PLAIN = `# One value per line — type is auto-detected
44d88612fea8a8f36de82e1278abb02f
evil.example.com
192.0.2.10
https://c2.example.com/payload.exe`

const EXAMPLE_CSV = `type,value,notes,source
ip,192.0.2.10,C2 server,TI feed
domain,evil.example.com,,VirusTotal
hash_sha256,44d88612fea8a8f36de82e1278abb02f,Malware,sandbox`

function detectType(value) {
  const v = value.trim()
  if (/^[a-fA-F0-9]{64}$/.test(v)) return 'hash_sha256'
  if (/^[a-fA-F0-9]{40}$/.test(v)) return 'hash_sha1'
  if (/^[a-fA-F0-9]{32}$/.test(v)) return 'hash_md5'
  if (/^https?:\/\//i.test(v)) return 'url'
  if (/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(v)) return 'email'
  if (/^(HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG)\\/i.test(v)) return 'registry_key'
  if (/^[a-zA-Z]:\\/.test(v) || /^\/(?!\/)[^\s]/.test(v)) return 'file_path'
  if (/^(\d{1,3}\.){3}\d{1,3}(\/\d+)?$/.test(v)) return 'ip'
  if (/^[0-9a-fA-F]{0,4}(:[0-9a-fA-F]{0,4}){2,7}$/.test(v)) return 'ip'
  if (/^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+$/.test(v)) return 'domain'
  return 'other'
}

function splitCsvLine(line) {
  const cols = []; let cur = ''; let inQ = false
  for (const c of line) {
    if (c === '"') { inQ = !inQ }
    else if (c === ',' && !inQ) { cols.push(cur.trim()); cur = '' }
    else { cur += c }
  }
  cols.push(cur.trim())
  return cols
}

function parseInput(text, defaultSource) {
  const entries = text
    .split(/\r?\n/)
    .map((raw, i) => ({ raw, _line: i + 1 }))
    .filter(l => l.raw.trim() && !l.raw.trim().startsWith('#'))

  if (entries.length === 0) return []

  // CSV mode: first data line looks like a header row
  const firstLower = entries[0].raw.toLowerCase().trim()
  if (firstLower.startsWith('type') && firstLower.includes(',')) {
    const headers = splitCsvLine(entries[0].raw).map(h => h.toLowerCase().trim())
    return entries.slice(1).map(({ raw, _line }) => {
      const vals = splitCsvLine(raw)
      const row = {}
      headers.forEach((h, j) => { row[h] = vals[j] ?? '' })
      return {
        _line,
        type:   (row.type   || '').toLowerCase().trim() || 'other',
        value:  (row.value  || '').trim(),
        notes:  (row.notes  || '').trim(),
        source: (row.source || '').trim() || defaultSource || '',
      }
    })
  }

  // Plain mode: one IOC value per line, auto-detect type
  return entries.map(({ raw, _line }) => {
    const value = raw.trim()
    return { _line, type: detectType(value), value, notes: '', source: defaultSource || '' }
  })
}

function validateRow(row) {
  const errors = []
  if (!row.value) errors.push('Value is required')
  if (!IOC_TYPES_SET.has(row.type)) errors.push(`Unknown type "${row.type}"`)
  if (row.value.length > 2048) errors.push('Value too long (max 2048)')
  return { ...row, _valid: errors.length === 0, _errors: errors }
}

const STAGES = { INPUT: 'input', PREVIEW: 'preview', IMPORTING: 'importing', DONE: 'done' }

export default function BulkImportModal({ incidentId, onClose, onImported }) {
  const [stage, setStage]               = useState(STAGES.INPUT)
  const [rawText, setRawText]           = useState('')
  const [defaultSource, setDefaultSource] = useState('')
  const [parseError, setParseError]     = useState(null)
  const [rows, setRows]                 = useState([])
  const [results, setResults]           = useState(null)
  const fileRef                         = useRef(null)

  useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape' && stage !== STAGES.IMPORTING) onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [stage, onClose])

  const onFileChange = (e) => {
    const file = e.target.files?.[0]
    if (!file) return
    const reader = new FileReader()
    reader.onload = (ev) => setRawText(ev.target.result || '')
    reader.readAsText(file)
  }

  const onPreview = () => {
    setParseError(null)
    try {
      const parsed = parseInput(rawText, defaultSource.trim())
      if (parsed.length === 0) { setParseError('No IOCs found in input'); return }
      if (parsed.length > 500) { setParseError(`Too many IOCs (${parsed.length}). Maximum is 500 per import.`); return }
      setRows(parsed.map(validateRow))
      setStage(STAGES.PREVIEW)
    } catch (e) {
      setParseError(e.message)
    }
  }

  const validRows   = rows.filter(r => r._valid)
  const invalidRows = rows.filter(r => !r._valid)

  const onImport = async () => {
    setStage(STAGES.IMPORTING)
    let ok = 0, skipped = 0, failed = 0
    for (const row of validRows) {
      try {
        await api.createIoc(incidentId, {
          type:   row.type,
          value:  row.value,
          notes:  row.notes  || null,
          source: row.source || 'bulk-import',
          tags:   ['bulk-import'],
        })
        ok++
      } catch (e) {
        if (e.status === 409 || (e.message || '').includes('already exists')) skipped++
        else failed++
      }
    }
    setResults({ ok, skipped, failed })
    setStage(STAGES.DONE)
    if (ok > 0) onImported()
  }

  return (
    <div
      className="modal-backdrop"
    >
      <div
        className="modal"
        role="dialog"
        aria-labelledby="ioc-bulk-title"
        style={{ maxWidth: 700 }}
      >
        <div className="modal-head">
          <h2 id="ioc-bulk-title">Bulk import IOCs</h2>
          <button
            type="button"
            className="modal-close"
            onClick={onClose}
            disabled={stage === STAGES.IMPORTING}
            aria-label="Close"
          >×</button>
        </div>

        {/* ── Input stage ── */}
        {stage === STAGES.INPUT && (
          <>
            <div className="modal-body">
              <div className="form">
                <div style={{ display: 'flex', gap: 'var(--space-4)' }}>
                  <div className="field" style={{ flex: 1 }}>
                    <label className="field-label">Plain text (auto-detect type)</label>
                    <div style={{
                      background: 'var(--surface-2)', border: '1px solid var(--border)',
                      borderRadius: 'var(--radius)', padding: '8px 12px',
                      fontFamily: 'var(--font-mono)', fontSize: 11,
                      color: 'var(--muted)', lineHeight: 1.6, whiteSpace: 'pre',
                    }}>
                      {EXAMPLE_PLAIN}
                    </div>
                  </div>
                  <div className="field" style={{ flex: 1 }}>
                    <label className="field-label">CSV (explicit types)</label>
                    <div style={{
                      background: 'var(--surface-2)', border: '1px solid var(--border)',
                      borderRadius: 'var(--radius)', padding: '8px 12px',
                      fontFamily: 'var(--font-mono)', fontSize: 11,
                      color: 'var(--muted)', lineHeight: 1.6, whiteSpace: 'pre',
                    }}>
                      {EXAMPLE_CSV}
                    </div>
                  </div>
                </div>
                <div className="field-hint" style={{ marginTop: 0 }}>
                  Plain: one IOC per line, type auto-detected from value.
                  CSV: header row with <code>type</code>, <code>value</code>; optional <code>notes</code>, <code>source</code>.
                  Lines starting with <code>#</code> are ignored. Max 500 IOCs per import.
                </div>

                <div className="field">
                  <label className="field-label" htmlFor="ioc-bulk-source">Default source (optional)</label>
                  <input
                    id="ioc-bulk-source"
                    className="input"
                    value={defaultSource}
                    onChange={(e) => setDefaultSource(e.target.value)}
                    maxLength={256}
                    placeholder="e.g. TI feed · VirusTotal · sandbox"
                    style={{ maxWidth: 340 }}
                  />
                  <div className="field-hint">Applied to all IOCs. CSV rows with their own source column override this.</div>
                </div>

                <div className="field">
                  <label className="field-label" htmlFor="ioc-bulk-file">Upload file</label>
                  <input
                    id="ioc-bulk-file"
                    ref={fileRef}
                    type="file"
                    accept=".txt,.csv,text/plain,text/csv"
                    onChange={onFileChange}
                    style={{ fontSize: 12, color: 'var(--text)' }}
                  />
                </div>

                <div className="field">
                  <label className="field-label" htmlFor="ioc-bulk-paste">Or paste directly</label>
                  <textarea
                    id="ioc-bulk-paste"
                    className="input"
                    value={rawText}
                    onChange={(e) => setRawText(e.target.value)}
                    rows={8}
                    placeholder={EXAMPLE_PLAIN}
                    style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}
                  />
                </div>

                {parseError && (
                  <div className="alert error" role="alert">
                    <span className="alert-icon">!</span><span>{parseError}</span>
                  </div>
                )}
              </div>
            </div>
            <div className="modal-foot">
              <button type="button" className="btn ghost" onClick={onClose}>Cancel</button>
              <button
                type="button"
                className="btn primary"
                onClick={onPreview}
                disabled={!rawText.trim()}
              >
                Preview →
              </button>
            </div>
          </>
        )}

        {/* ── Preview stage ── */}
        {stage === STAGES.PREVIEW && (
          <>
            <div className="modal-body" style={{ padding: 0 }}>
              {invalidRows.length > 0 && (
                <div style={{ padding: 'var(--space-3) var(--space-4)', borderBottom: '1px solid var(--border)' }}>
                  <div className="alert error" role="alert" style={{ marginBottom: 0 }}>
                    <span className="alert-icon">!</span>
                    <span>
                      {invalidRows.length} row{invalidRows.length > 1 ? 's' : ''} have errors and will be skipped:{' '}
                      {invalidRows.map(r => `line ${r._line} (${r._errors.join(', ')})`).join(' · ')}
                    </span>
                  </div>
                </div>
              )}
              <div style={{ overflowX: 'auto', maxHeight: 360, overflowY: 'auto' }}>
                <table className="settings-table" style={{ fontSize: 12 }}>
                  <thead>
                    <tr>
                      <th style={{ width: 24 }}>#</th>
                      <th style={{ width: 130 }}>Type</th>
                      <th>Value</th>
                      <th style={{ width: 100 }}>Source</th>
                      <th style={{ width: 60 }}>Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {rows.map((row) => (
                      <tr key={row._line} style={{ opacity: row._valid ? 1 : 0.4 }}>
                        <td style={{ color: 'var(--dim)', fontFamily: 'var(--font-mono)', fontSize: 10 }}>
                          {row._line}
                        </td>
                        <td>
                          <span className="pill">{IOC_TYPE_LABELS[row.type] || row.type}</span>
                        </td>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11, wordBreak: 'break-all' }}>
                          {row.value || <span style={{ color: 'var(--crit)' }}>—</span>}
                        </td>
                        <td style={{ color: 'var(--muted)', fontSize: 11 }}>{row.source || '—'}</td>
                        <td>
                          {row._valid
                            ? <span className="pill pill-ok">✓</span>
                            : <span className="pill pill-crit" title={row._errors.join(', ')}>skip</span>
                          }
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <div style={{
                padding: 'var(--space-3) var(--space-4)',
                borderTop: '1px solid var(--border)',
                fontSize: 12, color: 'var(--muted)',
              }}>
                {validRows.length} of {rows.length} IOC{rows.length !== 1 ? 's' : ''} will be imported.
                {invalidRows.length > 0 && ` ${invalidRows.length} will be skipped due to errors.`}
              </div>
            </div>
            <div className="modal-foot">
              <button type="button" className="btn ghost" onClick={() => setStage(STAGES.INPUT)}>← Back</button>
              <div style={{ flex: 1 }} />
              <button type="button" className="btn ghost" onClick={onClose}>Cancel</button>
              <button
                type="button"
                className="btn primary"
                onClick={onImport}
                disabled={validRows.length === 0}
              >
                Import {validRows.length} IOC{validRows.length !== 1 ? 's' : ''}
              </button>
            </div>
          </>
        )}

        {/* ── Importing stage ── */}
        {stage === STAGES.IMPORTING && (
          <div className="modal-body" style={{ textAlign: 'center', padding: 'var(--space-6)' }}>
            <div style={{ color: 'var(--muted)', fontSize: 13 }}>Importing…</div>
          </div>
        )}

        {/* ── Done stage ── */}
        {stage === STAGES.DONE && results && (
          <>
            <div className="modal-body">
              <div style={{ display: 'flex', gap: 'var(--space-3)', justifyContent: 'center' }}>
                <div style={{
                  flex: 1, textAlign: 'center',
                  background: 'color-mix(in srgb, var(--ok) 10%, transparent)',
                  border: '1px solid color-mix(in srgb, var(--ok) 35%, transparent)',
                  borderRadius: 'var(--radius)',
                  padding: 'var(--space-4)',
                }}>
                  <div style={{ fontSize: 28, fontFamily: 'var(--font-mono)', fontWeight: 700, color: 'var(--ok)' }}>
                    {results.ok}
                  </div>
                  <div style={{ fontSize: 11, color: 'var(--muted)', marginTop: 4 }}>Imported</div>
                </div>
                {results.skipped > 0 && (
                  <div style={{
                    flex: 1, textAlign: 'center',
                    background: 'color-mix(in srgb, var(--high) 10%, transparent)',
                    border: '1px solid color-mix(in srgb, var(--high) 35%, transparent)',
                    borderRadius: 'var(--radius)',
                    padding: 'var(--space-4)',
                  }}>
                    <div style={{ fontSize: 28, fontFamily: 'var(--font-mono)', fontWeight: 700, color: 'var(--high)' }}>
                      {results.skipped}
                    </div>
                    <div style={{ fontSize: 11, color: 'var(--muted)', marginTop: 4 }}>Already existed (skipped)</div>
                  </div>
                )}
                {results.failed > 0 && (
                  <div style={{
                    flex: 1, textAlign: 'center',
                    background: 'color-mix(in srgb, var(--crit) 10%, transparent)',
                    border: '1px solid color-mix(in srgb, var(--crit) 35%, transparent)',
                    borderRadius: 'var(--radius)',
                    padding: 'var(--space-4)',
                  }}>
                    <div style={{ fontSize: 28, fontFamily: 'var(--font-mono)', fontWeight: 700, color: 'var(--crit)' }}>
                      {results.failed}
                    </div>
                    <div style={{ fontSize: 11, color: 'var(--muted)', marginTop: 4 }}>Failed</div>
                  </div>
                )}
              </div>
            </div>
            <div className="modal-foot">
              <button type="button" className="btn primary" onClick={onClose}>Done</button>
            </div>
          </>
        )}
      </div>
    </div>
  )
}
