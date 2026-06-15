import { useEffect, useRef, useState } from 'react'
import { api } from '../../../api/client.js'

const ENTITY_TYPES = [
  'host', 'user', 'ip', 'domain', 'email',
  'service', 'network_range', 'group', 'other',
]

const CRITICALITY_VALUES = ['low', 'medium', 'high', 'critical']

const EXAMPLE_CSV = `type,value,name,criticality
host,WIN-DC01.corp.local,Primary DC,critical
user,jdoe,John Doe,high
ip,10.0.0.5,,medium
domain,evil.example.com,,high
email,phish@attacker.com,,medium`

// Parse a CSV string into rows. Returns { headers, rows } or throws.
function parseCSV(text) {
  const lines = text.trim().split(/\r?\n/).filter(Boolean)
  if (lines.length < 2) throw new Error('CSV must have a header row and at least one data row')

  // Simple CSV split that handles quoted fields
  const splitLine = (line) => {
    const cols = []; let cur = ''; let inQ = false
    for (let i = 0; i < line.length; i++) {
      const c = line[i]
      if (c === '"') { inQ = !inQ }
      else if (c === ',' && !inQ) { cols.push(cur.trim()); cur = '' }
      else { cur += c }
    }
    cols.push(cur.trim())
    return cols
  }

  const headers = splitLine(lines[0]).map(h => h.toLowerCase().replace(/\s+/g, '_'))
  const rows = lines.slice(1).map((line, i) => {
    const vals = splitLine(line)
    const row = {}
    headers.forEach((h, j) => { row[h] = vals[j] ?? '' })
    return { _line: i + 2, ...row }
  })
  return { headers, rows }
}

// Validate a parsed row and return a display row with status
function validateRow(row) {
  const type        = (row.type || '').toLowerCase().trim()
  const value       = (row.value || '').trim()
  const name        = (row.name || '').trim() || null
  const criticality = (row.criticality || 'medium').toLowerCase().trim()

  const errors = []
  if (!ENTITY_TYPES.includes(type))       errors.push(`Unknown type "${type}"`)
  if (!value)                             errors.push('Value is required')
  if (!CRITICALITY_VALUES.includes(criticality)) errors.push(`Unknown criticality "${criticality}"`)

  return {
    _line: row._line,
    type,
    value,
    name,
    criticality: CRITICALITY_VALUES.includes(criticality) ? criticality : 'medium',
    _valid: errors.length === 0,
    _errors: errors,
  }
}

const STAGES = { INPUT: 'input', PREVIEW: 'preview', IMPORTING: 'importing', DONE: 'done' }

export default function BulkImportModal({ incidentId, onClose, onImported }) {
  const [stage, setStage]         = useState(STAGES.INPUT)
  const [csvText, setCsvText]     = useState('')
  const [parseError, setParseError] = useState(null)
  const [rows, setRows]           = useState([])          // validated rows
  const [results, setResults]     = useState(null)        // { ok, skipped, failed }
  const fileRef                   = useRef(null)

  useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape' && stage !== STAGES.IMPORTING) onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [stage, onClose])

  const onFileChange = (e) => {
    const file = e.target.files?.[0]
    if (!file) return
    const reader = new FileReader()
    reader.onload = (ev) => setCsvText(ev.target.result || '')
    reader.readAsText(file)
  }

  const onPreview = () => {
    setParseError(null)
    try {
      const { rows: parsed } = parseCSV(csvText)
      const validated = parsed.map(validateRow)
      if (validated.length === 0) { setParseError('No rows found in CSV'); return }
      setRows(validated)
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
        await api.createEntity(incidentId, {
          type:        row.type,
          value:       row.value,
          name:        row.name || null,
          criticality: row.criticality,
        })
        ok++
      } catch (e) {
        // 409 = already exists (dedup) → counts as skipped, not error
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
        aria-labelledby="bulk-import-title"
        style={{ maxWidth: 680 }}
      >
        <div className="modal-head">
          <h2 id="bulk-import-title">Bulk import entities</h2>
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
                <div className="field">
                  <label className="field-label">CSV format</label>
                  <div style={{
                    background: 'var(--surface-2)', border: '1px solid var(--border)',
                    borderRadius: 'var(--radius)', padding: '8px 12px',
                    fontFamily: 'var(--font-mono)', fontSize: 11,
                    color: 'var(--muted)', lineHeight: 1.6, whiteSpace: 'pre',
                  }}>
                    {EXAMPLE_CSV}
                  </div>
                  <div className="field-hint">
                    Required columns: <code>type</code>, <code>value</code>. Optional: <code>name</code>, <code>criticality</code> (low/medium/high/critical, defaults to medium).
                    Existing entities are skipped (dedup on type + value).
                  </div>
                </div>

                <div className="field">
                  <label className="field-label" htmlFor="bulk-file">Upload CSV file</label>
                  <input
                    id="bulk-file"
                    ref={fileRef}
                    type="file"
                    accept=".csv,text/csv,text/plain"
                    onChange={onFileChange}
                    style={{ fontSize: 12, color: 'var(--text)' }}
                  />
                </div>

                <div className="field">
                  <label className="field-label" htmlFor="bulk-paste">Or paste CSV directly</label>
                  <textarea
                    id="bulk-paste"
                    className="input"
                    value={csvText}
                    onChange={(e) => setCsvText(e.target.value)}
                    rows={8}
                    placeholder={EXAMPLE_CSV}
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
                disabled={!csvText.trim()}
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
                      <th style={{ width: 110 }}>Type</th>
                      <th>Value</th>
                      <th>Name</th>
                      <th style={{ width: 90 }}>Criticality</th>
                      <th style={{ width: 60 }}>Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {rows.map((row) => (
                      <tr
                        key={row._line}
                        style={{ opacity: row._valid ? 1 : 0.4 }}
                      >
                        <td style={{ color: 'var(--dim)', fontFamily: 'var(--font-mono)', fontSize: 10 }}>
                          {row._line}
                        </td>
                        <td><span className="pill">{row.type}</span></td>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11, wordBreak: 'break-all' }}>
                          {row.value || <span style={{ color: 'var(--crit)' }}>—</span>}
                        </td>
                        <td style={{ color: 'var(--muted)', fontSize: 11 }}>{row.name || '—'}</td>
                        <td><span className="pill pill-gray">{row.criticality}</span></td>
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
                {validRows.length} of {rows.length} rows will be imported.
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
                Import {validRows.length} entit{validRows.length === 1 ? 'y' : 'ies'}
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
