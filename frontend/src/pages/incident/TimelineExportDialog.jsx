import { useEffect, useRef, useState } from 'react'
import { api } from '../../api/client.js'
import { getStoredTz } from '../../lib/timezone.js'

// TX: the server renders every export (GET …/timeline/export); this dialog only picks the options.
// raw = the layout can print raw log lines (the CSV always can).
const LAYOUTS = [
  { id: 'rail',      name: 'Rail',      kind: 'Vertical',       raw: true,
    desc: 'One-sided spine. Every event as a card with its flags and provenance.' },
  { id: 'horizon',   name: 'Horizon',   kind: 'Horizontal',     raw: false,
    desc: 'Time-scaled. Over several days, quiet stretches over 6 h fold.' },
  { id: 'swimlanes', name: 'Swimlanes', kind: 'By entity',      raw: false,
    desc: 'One lane per linked entity. Malicious IOCs are target lanes.' },
  { id: 'ledger',    name: 'Ledger',    kind: 'Forensic table', raw: true,
    desc: 'Every field, time since the previous row, provenance, CSV hash.' },
  { id: 'brief',     name: 'Brief',     kind: 'Executive',      raw: false,
    desc: 'One page: milestones, key moments, impact, ATT&CK stages.' },
  { id: 'zigzag',    name: 'Zig-zag',   kind: 'Alternating',    raw: true,
    desc: 'The original export. Cards alternate around a centre spine.' },
]
const SHAPES = { rail: 4, horizon: 6, swimlanes: 7, ledger: 6, brief: 7, zigzag: 4 }

function Thumb({ id }) {
  // A CSS sketch of the layout (styles/timeline-export.css); the spans are fixed, so an index key is stable.
  return (
    <span className={`tx-thumb tx-${id}`} aria-hidden="true">
      {Array.from({ length: SHAPES[id] }, (_, i) => <span key={i} />)}
    </span>
  )
}

function download(blob, filename) {
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url; a.download = filename
  document.body.appendChild(a); a.click()
  document.body.removeChild(a); URL.revokeObjectURL(url)
}

// filters / showSystem: the Timeline page's current view — the export holds the same events.
export default function TimelineExportDialog({ inc, filters, showSystem, events, onClose }) {
  const total = events.length
  const keyCount = events.filter(e => e.key_event).length
  const fenrirTz = getStoredTz()
  const [layout, setLayout] = useState('rail')
  const [format, setFormat] = useState('html')
  const [keyOnly, setKeyOnly] = useState(filters.key === 'true')
  const [raw, setRaw] = useState(false)
  // TXF: external-safe events only. Each layout sets its default (on for the Brief); the operator can change it.
  const [safeOnly, setSafeOnly] = useState(false)
  const [tz, setTz] = useState(fenrirTz)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)
  const [preview, setPreview] = useState(null)
  const firstRef = useRef(null)

  const current = LAYOUTS.find(l => l.id === layout)
  const rawApplies = format === 'csv' || current.raw
  const safeCount = events.filter(e => e.external_safe).length
  const count = events.filter(e => (!keyOnly || e.key_event) && (!safeOnly || e.external_safe)).length
  const filtered = Object.keys(filters).some(k => k !== 'key') || !showSystem

  useEffect(() => { firstRef.current?.focus() }, [])
  useEffect(() => {
    const onKey = e => {
      if (e.key !== 'Escape' || busy) return
      if (preview != null) setPreview(null); else onClose()
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [busy, preview, onClose])

  const params = () => {
    const p = { ...filters, format }
    if (!showSystem) p.include_system = 'false'
    if (keyOnly) p.key = 'true'
    else if (p.key === 'true') delete p.key
    p.external_safe_only = safeOnly ? 'true' : 'false'
    if (format === 'html') { p.layout = layout; p.tz = tz }
    if (raw && rawApplies) p.include_raw_logs = 'true'
    return p
  }

  const run = async (asPreview) => {
    setBusy(true); setError(null)
    try {
      const { blob, filename } = await api.exportTimeline(inc.id, params())
      if (asPreview) setPreview(await blob.text())
      else { download(blob, filename); onClose() }
    } catch (e) {
      setError(e.message || 'Export failed')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="modal-backdrop">
      <div className="modal tx-dialog" role="dialog" aria-modal="true" aria-labelledby="tx-title" data-testid="tx-dialog">
        <div className="modal-head">
          <div>
            <h2 id="tx-title">Export timeline</h2>
            <div className="tx-sub">{inc.ref} · {total} event{total === 1 ? '' : 's'}, {keyCount} key</div>
          </div>
          <button type="button" className="modal-close" onClick={onClose} disabled={busy} aria-label="Close">×</button>
        </div>

        <div className="modal-body">
          <fieldset className="tx-fs" disabled={format === 'csv'}>
            <legend>Layout</legend>
            <div className="tx-grid">
              {LAYOUTS.map((l, i) => (
                <button key={l.id} ref={i === 0 ? firstRef : undefined} type="button" className="tx-card"
                        aria-pressed={layout === l.id} onClick={() => { setLayout(l.id); setSafeOnly(l.id === 'brief') }}
                        data-layout={l.id}>
                  <Thumb id={l.id} />
                  <span className="tx-name">{l.name}</span>
                  <span className="tx-kind">{l.kind}</span>
                  <span className="tx-desc">{l.desc}</span>
                </button>
              ))}
            </div>
            {format === 'csv' && (
              <p className="field-hint">The layout applies to HTML. CSV is always the flat 29-column file.</p>
            )}
          </fieldset>

          <div className="tx-row">
            <fieldset className="tx-fs">
              <legend>Content</legend>
              <label className="tx-switch">
                <input type="checkbox" role="switch" checked={keyOnly} onChange={e => setKeyOnly(e.target.checked)}
                       data-testid="tx-key" />
                <span>Key events only</span>
                <span className="tx-count">{keyCount} of {total}</span>
              </label>
              <label className="tx-switch">
                <input type="checkbox" role="switch" checked={safeOnly} onChange={e => setSafeOnly(e.target.checked)}
                       data-testid="tx-safe" />
                <span>External-safe events only</span>
                <span className="tx-count">{safeCount} of {total}</span>
              </label>
              <p className="field-hint">
                Leaves out internal-only events: system records, response actions, legal, PCAP and browser history.
              </p>
              <label className="tx-switch">
                <input type="checkbox" role="switch" checked={raw && rawApplies} disabled={!rawApplies}
                       onChange={e => setRaw(e.target.checked)} data-testid="tx-raw" />
                <span>Include raw logs</span>
              </label>
              <p className="field-hint">
                {rawApplies
                  ? 'Rail, Ledger, Zig-zag and CSV. Raw lines can hold secrets — check before sharing.'
                  : `${current.name} never shows raw logs.`}
              </p>
            </fieldset>

            <fieldset className="tx-fs">
              <legend>Format</legend>
              {[['html', 'HTML'], ['csv', 'CSV']].map(([v, label]) => (
                <label key={v} className="tx-radio">
                  <input type="radio" name="tx-format" value={v} checked={format === v} onChange={() => setFormat(v)} />
                  {label}
                </label>
              ))}
            </fieldset>

            <fieldset className="tx-fs" disabled={format === 'csv'}>
              <legend>Time zone</legend>
              {[...new Set(['UTC', fenrirTz])].map(z => (
                <label key={z} className="tx-radio">
                  <input type="radio" name="tx-tz" value={z} checked={tz === z} onChange={() => setTz(z)} />
                  {z === fenrirTz && z !== 'UTC' ? `Fenrir TZ · ${z}` : z}
                </label>
              ))}
              {format === 'csv' && <p className="field-hint">The CSV is always UTC.</p>}
            </fieldset>
          </div>

          {filtered && (
            <div className="alert info" role="note">
              <span className="alert-icon">ⓘ</span>
              <span>The page's filters apply: the export holds the events the timeline shows.</span>
            </div>
          )}
          {error && <div className="alert error" role="alert">{error}</div>}
        </div>

        <div className="modal-foot">
          <button type="button" className="btn ghost" onClick={onClose} disabled={busy}>Cancel</button>
          {format === 'html' && (
            <button type="button" className="btn" onClick={() => run(true)} disabled={busy || count === 0}>Preview</button>
          )}
          <button type="button" className="btn primary" onClick={() => run(false)} disabled={busy || count === 0}
                  data-testid="tx-export">
            {busy ? 'Exporting…' : count === 0 ? 'Nothing to export' : `Export ${format.toUpperCase()}`}
          </button>
        </div>
      </div>

      {preview != null && (
        <div className="modal-backdrop">
          <div className="modal tx-preview" role="dialog" aria-modal="true" aria-labelledby="tx-preview-title">
            <div className="modal-head">
              <h2 id="tx-preview-title">Preview · {current.name}</h2>
              <button type="button" className="modal-close" onClick={() => setPreview(null)} aria-label="Close preview">×</button>
            </div>
            {/* No script runs in the export: an empty sandbox, and the page's own CSP blocks scripts and loads. */}
            <iframe className="tx-frame" title={`Timeline export preview, ${current.name}`} sandbox="" srcDoc={preview} />
            <div className="modal-foot">
              <button type="button" className="btn ghost" onClick={() => setPreview(null)} disabled={busy}>Back</button>
              <button type="button" className="btn primary" onClick={() => run(false)} disabled={busy}>
                {busy ? 'Exporting…' : 'Export HTML'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
