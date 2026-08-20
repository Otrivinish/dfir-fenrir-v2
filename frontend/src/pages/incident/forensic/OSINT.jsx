import { useEffect, useMemo, useRef, useState } from 'react'
import { useOutletContext } from 'react-router-dom'
import { api } from '../../../api/client.js'
import { useAuth } from '../../../hooks/useAuth.jsx'
import { formatLocal } from '../../../lib/datetime.js'

// ─── Extraction regexes ───────────────────────────────────────────────────────

const RE_IPV4 = /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g
const RE_IPV6 = /(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}|:(?::[0-9a-fA-F]{1,4}){1,7}|::(?:ffff(?::0{1,4})?:)?(?:(?:25[0-5]|(?:2[0-4]|1?\d)?\d)\.){3}(?:25[0-5]|(?:2[0-4]|1?\d)?\d)|(?:[0-9a-fA-F]{1,4}:){1,4}:(?:(?:25[0-5]|(?:2[0-4]|1?\d)?\d)\.){3}(?:25[0-5]|(?:2[0-4]|1?\d)?\d)/g
const RE_SHA256 = /\b[0-9a-fA-F]{64}\b/g
const RE_SHA1   = /\b[0-9a-fA-F]{40}\b/g
const RE_MD5    = /\b[0-9a-fA-F]{32}\b/g
const RE_URL    = /https?:\/\/[^\s"'<>`\])\}]+/g
const RE_DOMAIN = /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|gov|mil|edu|co|uk|de|fr|nl|se|no|fi|dk|au|nz|ca|jp|cn|ru|br|in|info|biz|tech|cloud|app|dev|security|ai|sh|xyz)\b/g

const PRIVATE_BLOCKS = [
  /^10\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^192\.168\./,
  /^127\./,
  /^169\.254\./,
  /^::1$/,
  /^fc/i,
  /^fd/i,
]
function isPrivate(ip) {
  return PRIVATE_BLOCKS.some(re => re.test(ip))
}

// Reverses common IOC "defanging" (hxxp://evil[.]com, 1[.]2[.]3[.]4) before
// extraction runs -- reports, phishing writeups, and threat-intel feeds quote
// indicators this way specifically so they don't render as live links/addresses.
// Only used to find matches; the analyst's original pasted text is never rewritten.
function refang(text) {
  return text
    .replace(/\[\.\]|\(\.\)|\{\.\}/g, '.')
    .replace(/hxxps/gi, 'https')
    .replace(/hxxp/gi, 'http')
    .replace(/\[:\]|\(:\)/g, ':')
}

function extractAll(text) {
  const items = []
  const addedKeys = new Set()
  const refanged = refang(text)

  function add(type, value) {
    const key = `${type}:${value.toLowerCase()}`
    if (addedKeys.has(key)) return
    addedKeys.add(key)
    items.push({ type, value })
  }

  // URLs first (before domain extraction picks up URL hostnames)
  for (const m of refanged.matchAll(RE_URL)) add('url', m[0])

  // Hashes longest-first (SHA256 > SHA1 > MD5)
  for (const m of refanged.matchAll(RE_SHA256)) add('hash_sha256', m[0].toLowerCase())
  // SHA1 — must not already be captured as SHA256 prefix (40 < 64, separate words)
  for (const m of refanged.matchAll(RE_SHA1))   add('hash_sha1',   m[0].toLowerCase())
  for (const m of refanged.matchAll(RE_MD5))    add('hash_md5',    m[0].toLowerCase())

  // IPs
  for (const m of refanged.matchAll(RE_IPV4)) add('ip', m[0])
  for (const m of refanged.matchAll(RE_IPV6)) add('ip', m[0].toLowerCase())

  // Domains — skip if it looks like an IP or already captured in a URL
  for (const m of refanged.matchAll(RE_DOMAIN)) {
    const val = m[0].toLowerCase()
    if (!addedKeys.has(`ip:${val}`)) add('domain', val)
  }

  return items.slice(0, 100)
}

// ─── Type metadata ────────────────────────────────────────────────────────────

const TYPE_LABELS = {
  ip:          'IP',
  domain:      'Domain',
  url:         'URL',
  hash_md5:    'MD5',
  hash_sha1:   'SHA-1',
  hash_sha256: 'SHA-256',
}

// ─── IOC type mapping ─────────────────────────────────────────────────────────

const IOC_TYPES_QUICK = [
  { value: 'ip',           label: 'IP address' },
  { value: 'domain',       label: 'Domain' },
  { value: 'url',          label: 'URL' },
  { value: 'hash_md5',     label: 'Hash (MD5)' },
  { value: 'hash_sha1',    label: 'Hash (SHA1)' },
  { value: 'hash_sha256',  label: 'Hash (SHA256)' },
  { value: 'other',        label: 'Other' },
]

// ─── Export: CSV + printable report (HTML → browser "Save as PDF") ───────────
// Same client-side Blob + temporary <a download> pattern Timeline.jsx and
// Reports.jsx already use elsewhere in this app -- no backend export endpoint,
// no PDF library; "PDF" means a self-contained HTML page the analyst prints
// (Ctrl+P → Save as PDF), matching Reports.jsx's own convention exactly.

function triggerDownload(blob, filename) {
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url; a.download = filename
  document.body.appendChild(a); a.click()
  document.body.removeChild(a); URL.revokeObjectURL(url)
}

function csvEsc(v) {
  if (v == null) return ''
  const s = String(v).replace(/"/g, '""')
  return /[,"\n\r]/.test(s) ? `"${s}"` : s
}

// Flattens a nested enrichment result object into ["key", "value"] pairs for
// display -- generic on purpose, since each OSINT source returns a different
// shape and a per-source renderer isn't worth it for an export.
function flattenForDisplay(obj, prefix = '') {
  if (obj == null) return []
  const out = []
  for (const [k, v] of Object.entries(obj)) {
    const key = prefix ? `${prefix}.${k}` : k
    if (v && typeof v === 'object' && !Array.isArray(v)) {
      out.push(...flattenForDisplay(v, key))
    } else if (Array.isArray(v)) {
      // Elements can themselves be objects (e.g. DNSBL's `checked`, PassiveDNS's
      // `records`) -- stringify those individually rather than joining, which
      // would otherwise produce "[object Object]".
      const render = (el) => (el && typeof el === 'object') ? JSON.stringify(el) : String(el)
      const shown = v.length > 8
        ? `${v.slice(0, 8).map(render).join(' | ')} … (+${v.length - 8} more)`
        : v.map(render).join(' | ')
      out.push([key, shown])
    } else {
      out.push([key, String(v)])
    }
  }
  return out
}

function exportPlainCsv(extracted, incRef) {
  const rows = [
    'Type,Value,Private',
    ...extracted.map(i => [
      csvEsc(TYPE_LABELS[i.type] || i.type),
      csvEsc(i.value),
      csvEsc(i.type === 'ip' && isPrivate(i.value) ? 'yes' : ''),
    ].join(',')),
  ]
  triggerDownload(
    new Blob([rows.join('\r\n')], { type: 'text/csv;charset=utf-8' }),
    `osint-${incRef || 'export'}-indicators.csv`,
  )
}

function exportEnrichedCsv(extracted, results, sources, incRef) {
  const rows = ['Type,Value,Source,Cached,Error,Details']
  for (const item of extracted) {
    const itemResults = results[item.id]
    if (!itemResults || !itemResults.length) continue
    for (const r of itemResults) {
      const label = sources.find(s => s.id === r.source)?.label || r.source
      const details = r.data ? flattenForDisplay(r.data).map(([k, v]) => `${k}=${v}`).join('; ') : ''
      rows.push([
        csvEsc(TYPE_LABELS[item.type] || item.type),
        csvEsc(item.value),
        csvEsc(label),
        csvEsc(r.from_cache ? 'yes' : ''),
        csvEsc(r.error || ''),
        csvEsc(details),
      ].join(','))
    }
  }
  triggerDownload(
    new Blob([rows.join('\r\n')], { type: 'text/csv;charset=utf-8' }),
    `osint-${incRef || 'export'}-enriched.csv`,
  )
}

function buildReportHtml(extracted, results, sources, inc, user) {
  const esc = (s) => String(s ?? '').replace(/[&<>]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]))
  const generated = new Date().toISOString()

  const indicatorRows = extracted.map(i => `
    <tr>
      <td>${esc(TYPE_LABELS[i.type] || i.type)}</td>
      <td class="mono">${esc(i.value)}</td>
      <td>${i.type === 'ip' && isPrivate(i.value) ? 'Private' : ''}</td>
    </tr>`).join('')

  const enrichedSections = extracted
    .filter(i => results[i.id]?.length)
    .map(i => {
      const cards = results[i.id].map(r => {
        const label = sources.find(s => s.id === r.source)?.label || r.source
        if (r.error) return `<div class="card"><h4>${esc(label)}</h4><p class="err">${esc(r.error)}</p></div>`
        const pairs = r.data ? flattenForDisplay(r.data) : []
        const kv = pairs.map(([k, v]) => `<div class="kv"><span class="k">${esc(k)}</span><span class="v">${esc(v)}</span></div>`).join('')
        return `<div class="card"><h4>${esc(label)}${r.from_cache ? ' <small>(cached)</small>' : ''}</h4>${kv || '<p class="dim">No data.</p>'}</div>`
      }).join('')
      return `<h3>${esc(TYPE_LABELS[i.type] || i.type)} — <span class="mono">${esc(i.value)}</span></h3><div class="cards">${cards}</div>`
    }).join('')

  return `<!doctype html>
<html><head><meta charset="utf-8"><title>OSINT Report — ${esc(inc?.ref || '')}</title>
<style>
  body { font-family: -apple-system, "Segoe UI", sans-serif; color: #1a1a1a; max-width: 960px; margin: 32px auto; padding: 0 16px; }
  h1 { font-size: 20px; margin-bottom: 4px; }
  .meta { color: #666; font-size: 12px; margin-bottom: 24px; }
  h2 { font-size: 15px; margin-top: 32px; border-bottom: 1px solid #ddd; padding-bottom: 4px; }
  h3 { font-size: 13px; margin-top: 20px; }
  table { width: 100%; border-collapse: collapse; font-size: 12px; margin-top: 8px; }
  th, td { text-align: left; padding: 4px 8px; border-bottom: 1px solid #eee; }
  th { color: #666; font-weight: 600; }
  .mono { font-family: ui-monospace, "SF Mono", Menlo, monospace; word-break: break-all; }
  .cards { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 8px; }
  .card { border: 1px solid #ddd; border-radius: 4px; padding: 8px 10px; min-width: 220px; max-width: 320px; font-size: 12px; overflow-wrap: anywhere; }
  .card h4 { margin: 0 0 6px; font-size: 12px; }
  .kv { border-bottom: 1px dotted #eee; padding: 3px 0; }
  .kv .k { display: block; color: #666; font-size: 10px; text-transform: uppercase; letter-spacing: 0.02em; }
  .kv .v { display: block; overflow-wrap: anywhere; word-break: break-word; }
  .err { color: #b91c1c; }
  .dim { color: #999; font-style: italic; }
  .print-hint { background: #f3f4f6; border-radius: 4px; padding: 8px 12px; font-size: 12px; margin-bottom: 24px; }
  @media print { .print-hint { display: none; } body { margin: 0; } }
</style></head>
<body>
  <div class="print-hint">To save as PDF: press Ctrl+P (Cmd+P on Mac), choose "Save as PDF" as the destination.</div>
  <h1>OSINT Lookup Report</h1>
  <div class="meta">
    Incident: ${esc(inc?.ref || inc?.title || '—')} &middot;
    Generated ${esc(generated)} by ${esc(user?.username || '—')}
  </div>

  <h2>Extracted Indicators (${extracted.length})</h2>
  <table><thead><tr><th>Type</th><th>Value</th><th>Private</th></tr></thead>
  <tbody>${indicatorRows}</tbody></table>

  <h2>Enrichment Results</h2>
  ${enrichedSections || '<p class="dim">No indicators enriched yet.</p>'}
</body></html>`
}

function previewReport(extracted, results, sources, inc, user) {
  const html = buildReportHtml(extracted, results, sources, inc, user)
  const w = window.open('', '_blank')
  if (!w) { alert('Pop-up blocked — please allow pop-ups for this site.'); return }
  w.document.write(html)
  w.document.close()
}

function downloadReport(extracted, results, sources, inc, user) {
  const html = buildReportHtml(extracted, results, sources, inc, user)
  triggerDownload(
    new Blob([html], { type: 'text/html;charset=utf-8' }),
    `osint-${inc?.ref || 'report'}.html`,
  )
}

// ─── Main component ───────────────────────────────────────────────────────────

export default function OSINTLookup() {
  const { inc } = useOutletContext()
  const { user } = useAuth()
  const isClosed = inc?.status === 'closed'

  const [text, setText]               = useState('')
  const [extracted, setExtracted]     = useState([])  // [{id, type, value}]
  const [sources, setSources]         = useState([])
  const [enabledSources, setEnabled]  = useState(new Set())
  const [results, setResults]         = useState({})  // { id: [EnrichResultItem] }
  const [enriching, setEnriching]     = useState(new Set())
  const [selected, setSelected]       = useState(new Set())
  const [iocTarget, setIocTarget]     = useState(null)
  const [filterType, setFilterType]   = useState('')
  const [sourcesErr, setSourcesErr]   = useState(null)
  const [sessionId, setSessionId]     = useState(null)
  const [sessions, setSessions]       = useState([])
  const [correlations, setCorrelations] = useState({})  // { "type:value": IncidentRef[] }

  useEffect(() => {
    api.osintSources().then(res => {
      setSources(res.sources)
      // Default: enable all available non-public sources
      setEnabled(new Set(res.sources.filter(s => s.available && !s.public).map(s => s.id)))
    }).catch(e => setSourcesErr(e.message || 'Could not load sources'))
  }, [])

  useEffect(() => {
    if (!inc?.id) return
    api.listOsintSessions(inc.id).then(res => {
      setSessions(res.sessions)
      if (res.sessions.length > 0) {
        const s = res.sessions[0]
        setSessionId(s.id)
        if (s.raw_text) setText(s.raw_text)
        if (s.indicators?.length) setExtracted(s.indicators)
        if (s.results && Object.keys(s.results).length) setResults(s.results)
      }
    }).catch(() => {})
  }, [inc?.id])

  // Correlation hint: does this indicator already exist as an IOC on this or
  // another accessible incident? Re-runs whenever the extracted set changes
  // (fresh extraction or a saved session load).
  useEffect(() => {
    if (!extracted.length) { setCorrelations({}); return }
    const items = extracted.map(({ type, value }) => ({ type, value }))
    api.correlateLookup({ items }).then(res => {
      const map = {}
      for (const hit of res.items) map[`${hit.type}:${hit.value}`] = hit.matched_incidents
      setCorrelations(map)
    }).catch(() => {})
  }, [extracted])

  async function onExtract() {
    if (!text.trim()) return
    const raw = extractAll(text)
    const items = raw.map((item, i) => ({ ...item, id: `${i}:${item.type}:${item.value}` }))
    setExtracted(items)
    setResults({})
    setSelected(new Set())
    try {
      const s = await api.createOsintSession(inc.id, { raw_text: text, indicators: items })
      setSessionId(s.id)
      setSessions(prev => [s, ...prev])
    } catch {
      // non-fatal — extraction still works offline
    }
  }

  const visible = useMemo(
    () => filterType ? extracted.filter(e => e.type === filterType) : extracted,
    [extracted, filterType]
  )

  const hasPublicEnabled = sources.some(s => s.public && enabledSources.has(s.id))

  // ── Enrichment ─────────────────────────────────────────────────────────────

  async function enrichOne(item) {
    const applicableSources = [...enabledSources].filter(sid => {
      const src = sources.find(s => s.id === sid)
      return src && src.available && src.supported_types.includes(item.type)
    })
    if (!applicableSources.length) return

    setEnriching(prev => new Set([...prev, item.id]))
    let itemResults
    try {
      const res = await api.osintEnrich({
        indicator: item.value,
        ioc_type: item.type,
        sources: applicableSources,
      })
      itemResults = res.results
    } catch (e) {
      itemResults = applicableSources.map(s => ({
        source: s, available: true, from_cache: false, data: null, error: e.message,
      }))
    } finally {
      setEnriching(prev => { const n = new Set(prev); n.delete(item.id); return n })
    }
    setResults(prev => {
      const updated = { ...prev, [item.id]: itemResults }
      if (sessionId) {
        api.updateOsintSession(inc.id, sessionId, { results: updated }).catch(() => {})
      }
      return updated
    })
  }

  async function enrichAll() {
    const toEnrich = visible.filter(item => !enriching.has(item.id))
    // Sequential to avoid hammering rate limits
    for (const item of toEnrich) await enrichOne(item)
  }

  function loadSession(s) {
    setSessionId(s.id)
    setText(s.raw_text || '')
    setExtracted(s.indicators || [])
    setResults(s.results || {})
    setSelected(new Set())
    setFilterType('')
  }

  async function removeSession(sid) {
    try {
      await api.deleteOsintSession(inc.id, sid)
      setSessions(prev => prev.filter(s => s.id !== sid))
      if (sessionId === sid) {
        setSessionId(null); setText(''); setExtracted([]); setResults({}); setSelected(new Set())
      }
    } catch {
      // non-fatal
    }
  }

  // ── Selection ──────────────────────────────────────────────────────────────

  const allVisibleSelected = visible.length > 0 && visible.every(e => selected.has(e.id))

  function toggleAll() {
    if (allVisibleSelected) {
      setSelected(prev => { const n = new Set(prev); visible.forEach(e => n.delete(e.id)); return n })
    } else {
      setSelected(prev => { const n = new Set(prev); visible.forEach(e => n.add(e.id)); return n })
    }
  }

  // ─────────────────────────────────────────────────────────────────────────

  return (
    <section className="panel">
      <div className="panel-toolbar">
        <h2 className="panel-h">OSINT Lookup</h2>
        <span style={{ color: 'var(--muted)', fontSize: 13 }}>
          Paste raw text → extract indicators → enrich selectively
        </span>
      </div>

      {sourcesErr && (
        <div className="alert error" role="alert" style={{ marginBottom: 'var(--space-3)' }}>
          <span className="alert-icon">!</span><span>{sourcesErr}</span>
        </div>
      )}

      {/* Source toggles */}
      {sources.length > 0 && (
        <div
          style={{
            display: 'flex',
            flexWrap: 'wrap',
            gap: 'var(--space-3)',
            padding: 'var(--space-3)',
            background: 'var(--surface-2)',
            borderRadius: 'var(--radius)',
            marginBottom: 'var(--space-3)',
            alignItems: 'flex-start',
          }}
        >
          <span style={{ color: 'var(--muted)', fontSize: 12, fontWeight: 600, letterSpacing: '0.05em', alignSelf: 'center' }}>
            SOURCES
          </span>
          {sources.map(s => (
            <label
              key={s.id}
              title={s.description}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 'var(--space-1)',
                cursor: s.available ? 'pointer' : 'not-allowed',
                opacity: s.available ? 1 : 0.45,
                fontSize: 13,
                userSelect: 'none',
              }}
            >
              <input
                type="checkbox"
                checked={enabledSources.has(s.id)}
                disabled={!s.available}
                onChange={(e) => {
                  setEnabled(prev => {
                    const n = new Set(prev)
                    e.target.checked ? n.add(s.id) : n.delete(s.id)
                    return n
                  })
                }}
              />
              <span>{s.label}</span>
              {s.public && (
                <span
                  title="Queries submitted to this source are visible to third parties (OPSEC risk)"
                  style={{ color: 'var(--high)', fontSize: 11, cursor: 'help' }}
                >
                  ⚠ PUBLIC
                </span>
              )}
              {!s.available && (
                <span style={{ color: 'var(--dim)', fontSize: 11 }}>(no key)</span>
              )}
            </label>
          ))}
        </div>
      )}

      {/* OPSEC warning */}
      {hasPublicEnabled && (
        <div className="alert warn" role="alert" style={{ marginBottom: 'var(--space-3)' }}>
          <span className="alert-icon">⚠</span>
          <span>
            One or more selected sources (e.g. VirusTotal) submit your indicators to third-party
            platforms where they may be logged and made public. Disable these sources if the
            indicators are sensitive.
          </span>
        </div>
      )}

      {/* Input area */}
      <div style={{ marginBottom: 'var(--space-3)' }}>
        <textarea
          className="input"
          value={text}
          onChange={e => setText(e.target.value)}
          rows={5}
          placeholder="Paste log output, alert text, IOC feeds, or raw data — IPv4, IPv6, domains, hashes, URLs are auto-extracted"
          style={{ width: '100%', fontFamily: 'var(--font-mono)', fontSize: 12, resize: 'vertical' }}
        />
        <div style={{ display: 'flex', gap: 'var(--space-2)', marginTop: 'var(--space-2)', alignItems: 'center' }}>
          <button type="button" className="btn primary" onClick={onExtract} disabled={!text.trim()}>
            Extract indicators
          </button>
          {extracted.length > 0 && (
            <button type="button" className="btn ghost" onClick={() => { setExtracted([]); setResults({}); setSelected(new Set()) }}>
              Clear
            </button>
          )}
          {sessionId && (
            <span style={{ color: 'var(--dim)', fontSize: 11, marginLeft: 'var(--space-1)' }}>
              Session saved — results persist across reloads
            </span>
          )}
        </div>
      </div>

      {/* Results table */}
      {extracted.length > 0 && (
        <>
          {/* Toolbar */}
          <div style={{ display: 'flex', gap: 'var(--space-2)', marginBottom: 'var(--space-2)', flexWrap: 'wrap', alignItems: 'center' }}>
            <select
              className="select"
              value={filterType}
              onChange={e => setFilterType(e.target.value)}
              aria-label="Filter by type"
            >
              <option value="">All types ({extracted.length})</option>
              {Object.entries(TYPE_LABELS).map(([v, l]) => {
                const n = extracted.filter(e => e.type === v).length
                return n > 0 ? <option key={v} value={v}>{l} ({n})</option> : null
              })}
            </select>
            <button
              type="button"
              className="btn ghost"
              onClick={enrichAll}
              disabled={enriching.size > 0 || enabledSources.size === 0}
              style={{ fontSize: 13 }}
            >
              {enriching.size > 0 ? `Enriching…` : `Enrich all visible (${visible.length})`}
            </button>
            {selected.size > 0 && (
              <button
                type="button"
                className="btn primary"
                onClick={() => {
                  const items = visible.filter(e => selected.has(e.id))
                  if (items.length === 1) { setIocTarget(items[0]); return }
                  // For bulk, open modal with first item and note count
                  setIocTarget({ ...items[0], _bulkItems: items })
                }}
                disabled={isClosed}
              >
                Add {selected.size} to IOCs
              </button>
            )}
            <button type="button" className="btn ghost" style={{ fontSize: 13 }}
              onClick={() => exportPlainCsv(extracted, inc.ref)}>
              Export CSV
            </button>
            <button type="button" className="btn ghost" style={{ fontSize: 13 }}
              onClick={() => exportEnrichedCsv(extracted, results, sources, inc.ref)}
              disabled={Object.keys(results).length === 0}>
              Export CSV (enriched)
            </button>
            <button type="button" className="btn ghost" style={{ fontSize: 13 }}
              onClick={() => previewReport(extracted, results, sources, inc, user)}>
              Preview report
            </button>
            <button type="button" className="btn ghost" style={{ fontSize: 13 }}
              onClick={() => downloadReport(extracted, results, sources, inc, user)}>
              Download report (HTML)
            </button>
            <span style={{ marginLeft: 'auto', color: 'var(--dim)', fontSize: 12 }}>
              {visible.length} indicator{visible.length !== 1 ? 's' : ''}
            </span>
          </div>

          <div style={{ overflowX: 'auto' }}>
            <table className="settings-table">
              <thead>
                <tr>
                  <th style={{ width: 32 }}>
                    <input type="checkbox" checked={allVisibleSelected} onChange={toggleAll} aria-label="Select all" />
                  </th>
                  <th style={{ width: 90 }}>Type</th>
                  <th>Indicator</th>
                  <th style={{ width: 80, textAlign: 'center' }}>Private</th>
                  <th style={{ width: 110 }}>Seen</th>
                  <th style={{ width: 100 }}>Enrich</th>
                  <th style={{ width: 60 }}>Add IOC</th>
                </tr>
              </thead>
              <tbody>
                {visible.map(item => (
                  <IndicatorRow
                    key={item.id}
                    item={item}
                    incId={inc.id}
                    matches={correlations[`${item.type}:${item.value}`] || []}
                    sources={sources}
                    enabledSources={enabledSources}
                    result={results[item.id]}
                    isEnriching={enriching.has(item.id)}
                    selected={selected.has(item.id)}
                    onToggle={() => setSelected(prev => {
                      const n = new Set(prev)
                      n.has(item.id) ? n.delete(item.id) : n.add(item.id)
                      return n
                    })}
                    onEnrich={() => enrichOne(item)}
                    onAddIoc={() => setIocTarget(item)}
                    isClosed={isClosed}
                  />
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}

      {/* Previous sessions */}
      {sessions.length > 0 && (
        <div style={{ marginTop: 'var(--space-5)', borderTop: '1px solid var(--border)', paddingTop: 'var(--space-3)' }}>
          <div style={{ fontWeight: 600, color: 'var(--muted)', fontSize: 12, letterSpacing: '0.05em', marginBottom: 'var(--space-2)' }}>
            SAVED SESSIONS
          </div>
          <div>
            {sessions.map(s => {
              const isActive = s.id === sessionId
              const indicatorCount = s.indicators?.length ?? 0
              const hasResults = s.results && Object.keys(s.results).length > 0
              return (
                <div
                  key={s.id}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: 'var(--space-2)',
                    padding: 'var(--space-2) 0',
                    borderBottom: '1px solid var(--border)',
                    background: isActive ? 'var(--surface-2)' : undefined,
                    paddingLeft: isActive ? 'var(--space-2)' : undefined,
                    borderRadius: isActive ? 'var(--radius-sm)' : undefined,
                  }}
                >
                  <span style={{ flex: 1, fontSize: 12, color: 'var(--text)' }}>
                    <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--muted)' }}>
                      {formatLocal(s.created_at)}
                    </span>
                    <span style={{ color: 'var(--dim)', marginLeft: 'var(--space-2)' }}>
                      {indicatorCount} indicator{indicatorCount !== 1 ? 's' : ''}
                      {hasResults ? ' · enriched' : ''}
                      {s.created_by ? ` · ${s.created_by}` : ''}
                    </span>
                  </span>
                  <button
                    type="button"
                    className="btn ghost"
                    style={{ fontSize: 12, padding: '2px 8px' }}
                    onClick={() => loadSession(s)}
                    disabled={isActive}
                  >
                    {isActive ? 'Active' : 'Load'}
                  </button>
                  <button
                    type="button"
                    className="btn ghost"
                    style={{ fontSize: 12, padding: '2px 8px', color: 'var(--crit)' }}
                    onClick={() => removeSession(s.id)}
                    aria-label="Delete session"
                  >
                    ×
                  </button>
                </div>
              )
            })}
          </div>
        </div>
      )}

      {iocTarget && (
        <IocQuickModal
          incidentId={inc.id}
          target={iocTarget}
          onClose={() => setIocTarget(null)}
          onCreated={() => setIocTarget(null)}
        />
      )}
    </section>
  )
}

// ─── Indicator row ────────────────────────────────────────────────────────────

function IndicatorRow({ item, incId, matches, sources, enabledSources, result, isEnriching, selected, onToggle, onEnrich, onAddIoc, isClosed }) {
  const [expanded, setExpanded] = useState(false)
  const priv = item.type === 'ip' && isPrivate(item.value)
  const hasResults = result && result.length > 0
  const trackedHere = matches.some(m => m.id === incId)
  const elsewhere    = matches.filter(m => m.id !== incId)

  return (
    <>
      <tr
        style={{ cursor: hasResults ? 'pointer' : undefined }}
        onClick={() => hasResults && setExpanded(x => !x)}
      >
        <td onClick={e => e.stopPropagation()}>
          <input type="checkbox" checked={selected} onChange={onToggle} />
        </td>
        <td>
          <span className="pill" style={{ fontSize: 11 }}>{TYPE_LABELS[item.type] || item.type}</span>
        </td>
        <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12, wordBreak: 'break-all' }}>
          {item.value}
        </td>
        <td style={{ textAlign: 'center' }}>
          {priv && <span style={{ color: 'var(--muted)', fontSize: 11 }}>Private</span>}
        </td>
        <td onClick={e => e.stopPropagation()}>
          {trackedHere && (
            <span className="pill" style={{ fontSize: 10, marginRight: 4 }}>Tracked here</span>
          )}
          {elsewhere.length > 0 && (
            <span
              className="pill"
              style={{ fontSize: 10, color: 'var(--high)' }}
              title={elsewhere.map(m => `${m.title} (${m.severity ?? '?'})`).join('\n')}
            >
              ⟲ {elsewhere.length} other{elsewhere.length !== 1 ? 's' : ''}
            </span>
          )}
        </td>
        <td onClick={e => e.stopPropagation()}>
          <button
            type="button"
            className="btn ghost"
            style={{ fontSize: 12, padding: '2px 8px' }}
            onClick={onEnrich}
            disabled={isEnriching || enabledSources.size === 0}
          >
            {isEnriching ? '…' : result ? '↻ Re-enrich' : 'Enrich'}
          </button>
        </td>
        <td className="actions" onClick={e => e.stopPropagation()}>
          <button
            type="button"
            className="btn ghost"
            style={{ fontSize: 12, padding: '2px 6px' }}
            onClick={onAddIoc}
            disabled={isClosed}
          >
            + IOC
          </button>
        </td>
      </tr>
      {expanded && result && (
        <tr>
          <td colSpan={6} style={{ paddingTop: 0, paddingBottom: 'var(--space-3)' }}>
            <div style={{ display: 'flex', gap: 'var(--space-3)', flexWrap: 'wrap', padding: 'var(--space-2)' }}>
              {result.map(r => (
                <EnrichCard key={r.source} result={r} sources={sources} />
              ))}
            </div>
          </td>
        </tr>
      )}
    </>
  )
}

// ─── Enrichment result card ───────────────────────────────────────────────────

function EnrichCard({ result: r, sources }) {
  const meta = sources.find(s => s.id === r.source)
  const label = meta?.label || r.source

  const cardStyle = {
    minWidth: 200,
    maxWidth: 280,
    padding: 'var(--space-3)',
    background: 'var(--surface-2)',
    borderRadius: 'var(--radius)',
    border: '1px solid var(--border)',
    fontSize: 12,
  }

  if (!r.available) {
    return (
      <div style={cardStyle}>
        <div style={{ fontWeight: 600, color: 'var(--muted)', marginBottom: 'var(--space-1)' }}>{label}</div>
        <div style={{ color: 'var(--dim)' }}>No API key configured</div>
      </div>
    )
  }

  if (r.error) {
    return (
      <div style={cardStyle}>
        <div style={{ fontWeight: 600, color: 'var(--muted)', marginBottom: 'var(--space-1)' }}>{label}</div>
        <div style={{ color: 'var(--crit)', fontSize: 11 }}>{r.error}</div>
      </div>
    )
  }

  return (
    <div style={cardStyle}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', marginBottom: 'var(--space-2)' }}>
        <span style={{ fontWeight: 600, color: 'var(--text)' }}>{label}</span>
        {r.from_cache && <span style={{ color: 'var(--dim)', fontSize: 10 }}>cached</span>}
        {meta?.public && <span style={{ color: 'var(--high)', fontSize: 10 }}>⚠ public</span>}
      </div>
      {r.source === 'geoip'      && <GeoIPDetail data={r.data} />}
      {r.source === 'greynoise'  && <GreyNoiseDetail data={r.data} />}
      {r.source === 'abuseipdb'  && <AbuseIPDBDetail data={r.data} />}
      {r.source === 'virustotal' && <VirusTotalDetail data={r.data} />}
      {r.source === 'shodan'     && <ShodanDetail data={r.data} />}
      {r.source === 'asn'        && <AsnDetail data={r.data} />}
      {r.source === 'crt_sh'     && <CrtShDetail data={r.data} />}
      {r.source === 'whois'      && <WhoisDetail data={r.data} />}
      {r.source === 'dns'        && <DnsDetail data={r.data} />}
      {r.source === 'dnsbl'      && <DnsblDetail data={r.data} />}
      {r.source === 'passivedns' && <PassiveDnsDetail data={r.data} />}
    </div>
  )
}

function WhoisDetail({ data: d }) {
  if (!d) return null
  if (d.private || d.found === false)
    return <div style={{ color: 'var(--dim)', fontSize: 11 }}>{d.message}</div>
  const e = d.events || {}
  const list = (arr) => (arr && arr.length) ? arr.join(', ') : null
  return (
    <div style={{ fontSize: 12 }}>
      <Row label="Handle"      value={d.handle} mono />
      <Row label="Name"        value={d.name} mono />
      <Row label="Registrar"   value={list(d.registrar)} />
      <Row label="Registrant"  value={list(d.registrant)} />
      <Row label="Tech"        value={list(d.tech)} />
      <Row label="Abuse"       value={list(d.abuse)} />
      <Row label="Status"      value={list(d.status)} />
      <Row label="Registered"  value={e.registration} mono />
      <Row label="Expires"     value={e.expiration} mono />
      <Row label="Updated"     value={e['last changed']} mono />
      <Row label="Nameservers" value={list(d.nameservers)} mono />
    </div>
  )
}

function DnsDetail({ data: d }) {
  if (!d) return null
  const r = d.records || {}
  if (!d.total) return <div style={{ color: 'var(--dim)', fontSize: 11 }}>No DNS records found.</div>
  const order = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA']
  return (
    <div style={{ fontSize: 12 }}>
      {order.filter(t => (r[t] || []).length).map(t => (
        <div key={t} style={{ marginBottom: 4 }}>
          <span style={{ color: 'var(--muted)', minWidth: 60, display: 'inline-block' }}>{t}</span>
          <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text)', wordBreak: 'break-all' }}>
            {r[t].join(', ')}
          </span>
        </div>
      ))}
    </div>
  )
}

function DnsblDetail({ data: d }) {
  if (!d) return null
  if (d.private || d.error || d.message)
    return <div style={{ color: 'var(--dim)', fontSize: 11 }}>{d.error || d.message}</div>
  const listed = d.listed_count || 0
  return (
    <div style={{ fontSize: 12 }}>
      <Row
        label="Verdict"
        value={listed > 0 ? `LISTED in ${listed} / ${(d.checked || []).length}` : `Not listed (${(d.checked || []).length} zones checked)`}
        danger={listed > 0}
      />
      <div style={{ marginTop: 6, display: 'flex', flexDirection: 'column', gap: 2 }}>
        {(d.checked || []).map(c => (
          <div key={c.zone} style={{ display: 'flex', gap: 'var(--space-1)' }}>
            <span style={{
              minWidth: 14, color: c.listed ? 'var(--crit)' : 'var(--ok)', fontWeight: 700,
            }}>{c.listed ? '⚠' : '✓'}</span>
            <span style={{ color: 'var(--text)' }}>{c.label}</span>
            <span style={{ marginLeft: 'auto', fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--dim)' }}>
              {c.listed ? (c.codes || []).join(' ') : (c.error || '—')}
            </span>
          </div>
        ))}
      </div>
    </div>
  )
}

function PassiveDnsDetail({ data: d }) {
  if (!d) return null
  if (d.available === false)
    return <div style={{ color: 'var(--dim)', fontSize: 11 }}>{d.message}</div>
  const recs = d.records || []
  if (!recs.length) return <div style={{ color: 'var(--dim)', fontSize: 11 }}>No passive DNS records.</div>
  const fmtTs = (n) => n ? new Date(n).toISOString().slice(0, 10) : '—'
  return (
    <div style={{ fontSize: 12 }}>
      <Row label="Total" value={d.total} />
      <div style={{ marginTop: 6, maxHeight: 240, overflowY: 'auto', borderTop: '1px solid var(--border)' }}>
        <table style={{ width: '100%', fontSize: 11, borderCollapse: 'collapse' }}>
          <thead>
            <tr style={{ position: 'sticky', top: 0, background: 'var(--surface)' }}>
              <th style={{ textAlign: 'left', padding: '4px 6px', color: 'var(--muted)' }}>Query</th>
              <th style={{ textAlign: 'left', padding: '4px 6px', color: 'var(--muted)' }}>Answer</th>
              <th style={{ textAlign: 'left', padding: '4px 6px', color: 'var(--muted)' }}>Type</th>
              <th style={{ textAlign: 'left', padding: '4px 6px', color: 'var(--muted)' }}>First</th>
              <th style={{ textAlign: 'left', padding: '4px 6px', color: 'var(--muted)' }}>Last</th>
            </tr>
          </thead>
          <tbody>
            {recs.map((rec, i) => (
              <tr key={i}>
                <td style={{ padding: '3px 6px', fontFamily: 'var(--font-mono)' }}>{rec.query}</td>
                <td style={{ padding: '3px 6px', fontFamily: 'var(--font-mono)' }}>{rec.answer}</td>
                <td style={{ padding: '3px 6px', color: 'var(--muted)' }}>{rec.rrtype}</td>
                <td style={{ padding: '3px 6px', color: 'var(--dim)' }}>{fmtTs(rec.first_seen)}</td>
                <td style={{ padding: '3px 6px', color: 'var(--dim)' }}>{fmtTs(rec.last_seen)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function AsnDetail({ data: d }) {
  if (!d) return null
  if (d.private) {
    return <div style={{ color: 'var(--dim)', fontSize: 11 }}>{d.message}</div>
  }
  return (
    <div style={{ fontSize: 12 }}>
      <Row label="ASN"    value={d.asn ? `AS${d.asn}` : null} mono />
      <Row label="Holder" value={d.holder} />
      <Row label="Prefix" value={d.prefix} mono />
      {(d.asns?.length ?? 0) > 1 && (
        <Row label="Other ASNs" value={d.asns.slice(1).map(a => `AS${a}`).join(', ')} mono />
      )}
    </div>
  )
}

function CrtShDetail({ data: d }) {
  if (!d) return null
  const subs = d.subdomains || []
  const certs = d.certs || []
  return (
    <div style={{ fontSize: 12 }}>
      <Row label="Total certs"  value={d.total} mono />
      <Row label="Subdomains"   value={subs.length} mono />
      {subs.length > 0 && (
        <details style={{ marginTop: 4 }}>
          <summary style={{ cursor: 'pointer', color: 'var(--accent)', fontSize: 11 }}>
            Subdomains ({subs.length})
          </summary>
          <div style={{
            marginTop: 4, padding: 6,
            background: 'var(--surface-2)', border: '1px solid var(--border)',
            borderRadius: 'var(--radius-sm)',
            fontFamily: 'var(--font-mono)', fontSize: 11,
            maxHeight: 180, overflowY: 'auto', wordBreak: 'break-all',
          }}>
            {subs.map(s => <div key={s}>{s}</div>)}
          </div>
        </details>
      )}
      {certs.length > 0 && (
        <details style={{ marginTop: 4 }}>
          <summary style={{ cursor: 'pointer', color: 'var(--accent)', fontSize: 11 }}>
            Recent certificates ({certs.length})
          </summary>
          <div style={{ marginTop: 4, fontFamily: 'var(--font-mono)', fontSize: 11 }}>
            {certs.map(c => (
              <div key={c.id} style={{
                padding: 6, marginBottom: 4,
                background: 'var(--surface-2)', border: '1px solid var(--border)',
                borderRadius: 'var(--radius-sm)',
              }}>
                <div style={{ fontWeight: 600 }}>{c.common_name || '(no CN)'}</div>
                <div style={{ color: 'var(--muted)', fontSize: 10 }}>
                  {c.issuer} · {c.not_before?.slice(0, 10)} → {c.not_after?.slice(0, 10)}
                </div>
                {c.names?.length > 0 && (
                  <div style={{ color: 'var(--dim)', fontSize: 10, marginTop: 2, wordBreak: 'break-all' }}>
                    SANs: {c.names.slice(0, 5).join(', ')}{c.names.length > 5 ? ` +${c.names.length - 5} more` : ''}
                  </div>
                )}
              </div>
            ))}
          </div>
        </details>
      )}
    </div>
  )
}

function Row({ label, value, mono, danger }) {
  if (!value && value !== 0) return null
  return (
    <div style={{ display: 'flex', gap: 'var(--space-1)', marginBottom: 2 }}>
      <span style={{ color: 'var(--muted)', minWidth: 80 }}>{label}</span>
      <span
        style={{
          fontFamily: mono ? 'var(--font-mono)' : undefined,
          color: danger ? 'var(--crit)' : 'var(--text)',
          wordBreak: 'break-all',
        }}
      >
        {String(value)}
      </span>
    </div>
  )
}

function GeoIPDetail({ data: d }) {
  if (!d) return null
  if (d.private) return <div style={{ color: 'var(--dim)' }}>{d.message}</div>
  if (d.status === 'fail') return <div style={{ color: 'var(--crit)' }}>{d.message}</div>
  return (
    <>
      <Row label="Location" value={[d.city, d.regionName, d.countryCode].filter(Boolean).join(', ')} />
      <Row label="ISP"      value={d.isp} />
      <Row label="Org"      value={d.org !== d.isp ? d.org : null} />
      <Row label="ASN"      value={d.as} />
      <Row label="rDNS"     value={d.reverse} mono />
      {d.proxy   && <div style={{ color: 'var(--high)', marginTop: 4 }}>Proxy/VPN detected</div>}
      {d.hosting && <div style={{ color: 'var(--med)',  marginTop: 4 }}>Hosting / datacenter</div>}
      {d.mobile  && <div style={{ color: 'var(--muted)', marginTop: 4 }}>Mobile network</div>}
    </>
  )
}

function GreyNoiseDetail({ data: d }) {
  if (!d) return null
  if (d.message && !d.noise && !d.riot) return <div style={{ color: 'var(--dim)' }}>{d.message}</div>
  const cls = d.classification
  const clsColor = cls === 'malicious' ? 'var(--crit)' : cls === 'benign' ? 'var(--ok)' : 'var(--muted)'
  return (
    <>
      {cls && (
        <div style={{ color: clsColor, fontWeight: 600, marginBottom: 4, textTransform: 'capitalize' }}>
          {cls}
        </div>
      )}
      <Row label="Noise"  value={d.noise  ? 'Yes — internet scanner' : 'No'} danger={d.noise} />
      <Row label="RIOT"   value={d.riot   ? 'Yes — known good service' : null} />
      {d.name    && <Row label="Name"   value={d.name} />}
      {d.message && <div style={{ color: 'var(--muted)', marginTop: 4, fontSize: 11 }}>{d.message}</div>}
    </>
  )
}

function AbuseIPDBDetail({ data: d }) {
  if (!d) return null
  if (d.message && !d.data) return <div style={{ color: 'var(--dim)' }}>{d.message}</div>
  const x = d.data || d
  const score = x.abuseConfidenceScore ?? x.abuse_confidence_score
  const scoreColor = score >= 80 ? 'var(--crit)' : score >= 40 ? 'var(--high)' : score > 0 ? 'var(--med)' : 'var(--ok)'
  return (
    <>
      {score !== undefined && (
        <div style={{ display: 'flex', alignItems: 'baseline', gap: 'var(--space-1)', marginBottom: 'var(--space-1)' }}>
          <span style={{ fontSize: 22, fontWeight: 700, color: scoreColor, fontFamily: 'var(--font-mono)' }}>
            {score}%
          </span>
          <span style={{ color: 'var(--muted)', fontSize: 11 }}>confidence</span>
        </div>
      )}
      <Row label="Reports"  value={x.totalReports ?? x.total_reports} />
      <Row label="Last seen" value={x.lastReportedAt ? x.lastReportedAt.slice(0, 10) : null} />
      <Row label="Type"      value={x.usageType ?? x.usage_type} />
      <Row label="ISP"       value={x.isp} />
      {x.isTor && <div style={{ color: 'var(--crit)', marginTop: 4 }}>Tor exit node</div>}
    </>
  )
}

function VirusTotalDetail({ data: d }) {
  if (!d) return null
  if (d.found === false) return <div style={{ color: 'var(--dim)' }}>Not found in VirusTotal</div>
  const attrs = d.data?.attributes || {}
  const stats = attrs.last_analysis_stats || {}
  const malicious  = stats.malicious  || 0
  const suspicious = stats.suspicious || 0
  const total = Object.values(stats).reduce((a, b) => a + b, 0)
  const mal = malicious + suspicious
  return (
    <>
      {total > 0 && (
        <div style={{ display: 'flex', alignItems: 'baseline', gap: 'var(--space-1)', marginBottom: 'var(--space-1)' }}>
          <span style={{
            fontSize: 22, fontWeight: 700,
            color: mal > 0 ? 'var(--crit)' : 'var(--ok)',
            fontFamily: 'var(--font-mono)',
          }}>
            {mal}/{total}
          </span>
          <span style={{ color: 'var(--muted)', fontSize: 11 }}>engines</span>
        </div>
      )}
      {attrs.meaningful_name && <Row label="Name" value={attrs.meaningful_name} />}
      {attrs.type_description && <Row label="Type" value={attrs.type_description} />}
      {attrs.country          && <Row label="Country" value={attrs.country} />}
      {attrs.as_owner         && <Row label="ASN owner" value={attrs.as_owner} />}
    </>
  )
}

function ShodanDetail({ data: d }) {
  if (!d) return null
  if (d.found === false) return <div style={{ color: 'var(--dim)' }}>No Shodan data for this host</div>
  if (d.message) return <div style={{ color: 'var(--dim)' }}>{d.message}</div>
  const ports = d.ports?.slice(0, 20) || []
  return (
    <>
      <Row label="Org"      value={d.org} />
      <Row label="ISP"      value={d.isp !== d.org ? d.isp : null} />
      <Row label="ASN"      value={d.asn} />
      <Row label="Country"  value={[d.city, d.country_code].filter(Boolean).join(', ')} />
      {ports.length > 0 && (
        <div style={{ marginTop: 4 }}>
          <span style={{ color: 'var(--muted)' }}>Ports: </span>
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>
            {ports.join(', ')}{d.ports?.length > 20 ? '…' : ''}
          </span>
        </div>
      )}
      {d.tags?.length > 0 && (
        <div style={{ marginTop: 4, display: 'flex', gap: 4, flexWrap: 'wrap' }}>
          {d.tags.map(t => (
            <span key={t} className="pill" style={{ fontSize: 10 }}>{t}</span>
          ))}
        </div>
      )}
    </>
  )
}

// ─── IOC quick-add modal ──────────────────────────────────────────────────────

function IocQuickModal({ incidentId, target, onClose, onCreated }) {
  // target may be a single item or have _bulkItems for bulk
  const isBulk = Boolean(target._bulkItems)
  const items  = isBulk ? target._bulkItems : [target]

  const iocTypeForIndicatorType = (t) => {
    if (t === 'ip')          return 'ip'
    if (t === 'domain')      return 'domain'
    if (t === 'url')         return 'url'
    if (t === 'hash_md5')    return 'hash_md5'
    if (t === 'hash_sha1')   return 'hash_sha1'
    if (t === 'hash_sha256') return 'hash_sha256'
    return 'other'
  }

  // Single-item state
  const [type,  setType]  = useState(iocTypeForIndicatorType(target.type))
  const [value, setValue] = useState(target.value)
  const [notes, setNotes] = useState('')
  const [busy,  setBusy]  = useState(false)
  const [error, setError] = useState(null)
  const [done,  setDone]  = useState(null) // {created, skipped}

  const onSubmit = async (e) => {
    e.preventDefault()
    setError(null)
    setBusy(true)
    try {
      if (isBulk) {
        let created = 0, skipped = 0
        for (const item of items) {
          try {
            await api.createIoc(incidentId, {
              type:   iocTypeForIndicatorType(item.type),
              value:  item.value,
              notes:  notes.trim() || null,
              source: 'OSINT lookup',
            })
            created++
          } catch (err) {
            if (err.status === 409) skipped++
            else throw err
          }
        }
        setDone({ created, skipped })
      } else {
        const v = value.trim()
        if (!v) { setError('Value is required.'); setBusy(false); return }
        await api.createIoc(incidentId, {
          type:   type,
          value:  v,
          notes:  notes.trim() || null,
          source: 'OSINT lookup',
        })
        onCreated()
      }
    } catch (err) {
      setError(err.message || 'Could not add IOC.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="modal-backdrop">
      <div className="modal" role="dialog" aria-labelledby="osint-ioc-title" style={{ maxWidth: 480 }}>
        <div className="modal-head">
          <h2 id="osint-ioc-title">{isBulk ? `Add ${items.length} indicators as IOCs` : 'Add as IOC'}</h2>
          <button type="button" className="modal-close" onClick={onClose} disabled={busy} aria-label="Close">×</button>
        </div>

        {done ? (
          <div className="modal-body">
            <div className="alert info" role="alert">
              <span className="alert-icon">✓</span>
              <span>
                Added {done.created} IOC{done.created !== 1 ? 's' : ''}.
                {done.skipped > 0 ? ` ${done.skipped} already existed (skipped).` : ''}
              </span>
            </div>
            <div className="modal-foot" style={{ marginTop: 'var(--space-3)' }}>
              <button type="button" className="btn primary" onClick={onClose}>Close</button>
            </div>
          </div>
        ) : (
          <form onSubmit={onSubmit}>
            <div className="modal-body">
              {error && (
                <div className="alert error" style={{ marginBottom: 'var(--space-3)' }}>
                  <span className="alert-icon">!</span><span>{error}</span>
                </div>
              )}
              <div className="form">
                {!isBulk && (
                  <div className="form-row">
                    <div className="field">
                      <label className="field-label" htmlFor="osint-ioc-type">Type</label>
                      <select id="osint-ioc-type" className="select" value={type} onChange={e => setType(e.target.value)}>
                        {IOC_TYPES_QUICK.map(t => <option key={t.value} value={t.value}>{t.label}</option>)}
                      </select>
                    </div>
                  </div>
                )}
                {!isBulk && (
                  <div className="field">
                    <label className="field-label" htmlFor="osint-ioc-value">Value</label>
                    <input
                      id="osint-ioc-value"
                      autoFocus
                      className="input"
                      value={value}
                      onChange={e => setValue(e.target.value)}
                      maxLength={2048}
                      required
                      style={{ fontFamily: 'var(--font-mono)' }}
                    />
                  </div>
                )}
                {isBulk && (
                  <div style={{ fontSize: 12, color: 'var(--muted)', marginBottom: 'var(--space-2)' }}>
                    {items.map(i => (
                      <div key={i.id} style={{ fontFamily: 'var(--font-mono)', marginBottom: 2 }}>
                        <span style={{ color: 'var(--accent)' }}>{TYPE_LABELS[i.type] || i.type}</span>
                        {' '}
                        {i.value}
                      </div>
                    ))}
                  </div>
                )}
                <div className="field">
                  <label className="field-label" htmlFor="osint-ioc-notes">Notes (optional)</label>
                  <textarea
                    id="osint-ioc-notes"
                    className="input"
                    value={notes}
                    onChange={e => setNotes(e.target.value)}
                    rows={2}
                    maxLength={4096}
                    placeholder="Enrichment context, analyst observations…"
                  />
                </div>
              </div>
            </div>
            <div className="modal-foot">
              <button type="button" className="btn ghost" onClick={onClose} disabled={busy}>Cancel</button>
              <button type="submit" className="btn primary" disabled={busy}>
                {busy ? 'Adding…' : isBulk ? `Add ${items.length} IOCs` : 'Add IOC'}
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  )
}
