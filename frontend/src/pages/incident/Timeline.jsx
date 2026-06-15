import { useCallback, useEffect, useMemo, useState } from 'react'
import { useOutletContext } from 'react-router-dom'
import { api } from '../../api/client.js'
import { formatLocal, formatLocalShort } from '../../lib/datetime.js'
import { MITRE_TACTICS, MITRE_TECHNIQUES, tacticColor } from '../../lib/mitre.js'
import UtcDateTimeInput from '../../components/UtcDateTimeInput.jsx'

// Maps 800-61 R3 phase keys to display labels.
const IR_PHASE_LABELS = {
  preparation: 'Preparation',
  detection_and_analysis: 'Detection & Analysis',
  containment_eradication_recovery: 'Containment / Eradication / Recovery',
  post_incident: 'Post-Incident',
}

// ─── Export helpers ───────────────────────────────────────────────────────────

function triggerDownload(blob, filename) {
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url; a.download = filename
  document.body.appendChild(a); a.click()
  document.body.removeChild(a); URL.revokeObjectURL(url)
}

function exportCsv(events, incRef) {
  const COLS = ['event_time', 'description', 'event_type', 'ir_phase',
                'mitre_tactic_id', 'mitre_tactic_name', 'mitre_technique_id',
                'mitre_technique_name', 'hostname', 'source', 'origin', 'raw_log']
  const esc = v => {
    if (v == null) return ''
    const s = String(v).replace(/"/g, '""')
    return /[,"\n\r]/.test(s) ? `"${s}"` : s
  }
  const rows = [COLS.join(','), ...events.map(ev => COLS.map(c => esc(ev[c])).join(','))]
  triggerDownload(
    new Blob([rows.join('\r\n')], { type: 'text/csv;charset=utf-8' }),
    `timeline-${incRef || 'export'}.csv`,
  )
}

const TACTIC_HEX = {
  TA0001: '#f43f5e', TA0002: '#f59e0b', TA0003: '#a78bfa',
  TA0004: '#f59e0b', TA0005: '#22d3ee', TA0006: '#f43f5e',
  TA0007: '#10b981', TA0008: '#f59e0b', TA0009: '#a78bfa',
  TA0010: '#f59e0b', TA0011: '#22d3ee', TA0040: '#f43f5e',
}

const SEV_HEX = {
  critical: '#dc2626', high: '#ea580c', medium: '#ca8a04',
  low: '#2563eb', informational: '#6b7280',
}

function fmtDtHtml(iso) {
  if (!iso) return ''
  const d = new Date(iso)
  const off = -d.getTimezoneOffset()
  const sign = off >= 0 ? '+' : '-'
  const hh = String(Math.floor(Math.abs(off) / 60)).padStart(2, '0')
  const mm = String(Math.abs(off) % 60).padStart(2, '0')
  return d.toISOString().slice(0, 19).replace('T', ' ') + ` ${sign}${hh}:${mm}`
}

function exportHtml(events, inc) {
  const slug = (inc.ref || 'timeline').replace(/[^a-z0-9]/gi, '-').toLowerCase()

  const escHtml = s => s == null ? '' : String(s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')

  const sevHex = SEV_HEX[(inc.severity || '').toLowerCase()] || '#6b7280'

  // Build zig-zag rows. Alternation runs across all events regardless of
  // date-divider position so the rhythm stays stable visually.
  const rows = []
  let prevDate = null
  events.forEach((ev, i) => {
    const d = new Date(ev.event_time)
    const dateLabel = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`
    const timeLabel = `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}:${String(d.getSeconds()).padStart(2, '0')}`

    if (dateLabel !== prevDate) {
      rows.push(`<div class="date-divider"><span>${escHtml(dateLabel)}</span></div>`)
      prevDate = dateLabel
    }

    const side  = i % 2 === 0 ? 'left' : 'right'
    const color = TACTIC_HEX[ev.mitre_tactic_id] || '#6b7280'
    const phase = IR_PHASE_LABELS[ev.ir_phase] || ''

    const headerBits = [`<span class="event-time">${escHtml(timeLabel)}</span>`]
    if (ev.event_type) {
      headerBits.push(`<span class="pill" style="background:${color}22;color:${color};border-color:${color}55">${escHtml(ev.event_type)}</span>`)
    }
    if (phase) {
      headerBits.push(`<span class="pill pill-muted">${escHtml(phase)}</span>`)
    }
    if (ev.hostname) {
      headerBits.push(`<span class="event-host">${escHtml(ev.hostname)}</span>`)
    }

    let mitreBadge = ''
    const mitreLabel = [ev.mitre_technique_id, ev.mitre_technique_name].filter(Boolean).join(' ') || ev.mitre_tactic_name
    if (mitreLabel) {
      mitreBadge = `<div class="mitre-badge" style="color:${color};border-color:${color}66;background:${color}1a">${escHtml(mitreLabel)}</div>`
    }

    const metaBits = []
    if (ev.source) metaBits.push(`source: ${escHtml(ev.source)}`)
    if (ev.origin) metaBits.push(`origin: ${escHtml(ev.origin)}`)
    const metaLine = metaBits.length ? `<div class="event-meta">${metaBits.join(' · ')}</div>` : ''

    const rawSection = ev.raw_log
      ? `<details class="event-raw-wrap"><summary>Raw log</summary><pre class="event-raw">${escHtml(ev.raw_log)}</pre></details>`
      : ''

    rows.push(`
      <div class="event-item ${side}">
        <div class="event-dot" style="background:${color};box-shadow:0 0 8px ${color}66"></div>
        <div class="event-card" style="border-left:3px solid ${color}">
          <div class="event-header">${headerBits.join('')}</div>
          <div class="event-desc">${escHtml(ev.description)}</div>
          ${mitreBadge}
          ${metaLine}
          ${rawSection}
        </div>
      </div>`)
  })

  const eventsHtml = rows.join('\n')
  const generated = fmtDtHtml(new Date().toISOString())

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Timeline · ${escHtml(inc.ref || '')} ${escHtml(inc.title)}</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#07080b;color:#d9dde5;font-family:-apple-system,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif;font-size:13px;line-height:1.6}
.mono{font-family:'JetBrains Mono','Fira Mono',Consolas,monospace}

.header{background:linear-gradient(135deg,#07070f,#140008);padding:32px 48px;border-bottom:3px solid ${sevHex}}
.header-eyebrow{font-family:'JetBrains Mono','Fira Mono',Consolas,monospace;font-size:11px;color:#555570;letter-spacing:3px;margin-bottom:8px}
.header-title{font-size:24px;font-weight:700;color:#fff;margin-bottom:6px}
.header-badges{display:flex;gap:8px;margin-top:12px;flex-wrap:wrap}
.header-badge{padding:4px 12px;border-radius:4px;font-size:11px;font-weight:700;letter-spacing:.08em;text-transform:uppercase}
.badge-sev{background:${sevHex};color:#fff}
.badge-tlp{border:2px solid #dc2626;color:#dc2626}
.badge-count{background:#0e1015;border:1px solid #1f242d;color:#8888aa}
.header-meta{margin-top:14px;font-family:'JetBrains Mono','Fira Mono',Consolas,monospace;font-size:11px;color:#555570}

.timeline-container{max-width:1100px;margin:0 auto;padding:40px 24px;position:relative}
.timeline-container::before{content:'';position:absolute;left:50%;top:0;bottom:0;width:2px;background:#1f242d;transform:translateX(-50%)}

.date-divider{text-align:center;position:relative;margin:28px 0 16px;z-index:2}
.date-divider span{display:inline-block;background:#07080b;border:1px solid #1f242d;padding:4px 14px;border-radius:20px;font-family:'JetBrains Mono','Fira Mono',Consolas,monospace;font-size:11px;color:#8888aa;letter-spacing:.08em}

.event-item{display:flex;width:50%;position:relative;margin-bottom:18px}
.event-item.left{padding-right:32px;justify-content:flex-end}
.event-item.right{padding-left:32px;margin-left:50%}
.event-dot{position:absolute;width:12px;height:12px;border-radius:50%;top:18px;z-index:3;border:2px solid #07080b}
.event-item.left .event-dot{right:-7px}
.event-item.right .event-dot{left:-7px}

.event-card{background:#0e1015;border:1px solid #1f242d;border-radius:6px;padding:12px 14px;width:100%;max-width:460px}
.event-header{display:flex;flex-wrap:wrap;gap:6px 8px;align-items:center;margin-bottom:8px;row-gap:6px}
.event-time{font-family:'JetBrains Mono','Fira Mono',Consolas,monospace;font-size:11px;font-weight:600;color:#a8b0c0;flex-shrink:0}
.pill{font-size:10px;font-weight:700;padding:2px 8px;border-radius:3px;letter-spacing:.04em;white-space:nowrap;border:1px solid transparent}
.pill-muted{background:#1f242d33;color:#8888aa;border-color:#1f242d}
.event-host{font-family:'JetBrains Mono','Fira Mono',Consolas,monospace;font-size:10px;color:#555570;margin-left:auto;flex-shrink:0}
.event-desc{font-size:13px;color:#d9dde5;line-height:1.5;margin-bottom:6px;word-break:break-word}
.mitre-badge{display:inline-block;font-family:'JetBrains Mono','Fira Mono',Consolas,monospace;font-size:10px;font-weight:600;padding:2px 8px;border-radius:3px;border:1px solid;margin-top:4px}
.event-meta{font-size:10px;color:#8888aa;margin-top:6px}
.event-raw-wrap{margin-top:8px}
.event-raw-wrap summary{cursor:pointer;font-family:'JetBrains Mono','Fira Mono',Consolas,monospace;font-size:11px;color:#555570;list-style:'▶ '}
.event-raw-wrap[open] summary{list-style:'▼ ';color:#8888aa}
.event-raw{font-family:'JetBrains Mono','Fira Mono',Consolas,monospace;font-size:10px;color:#8888aa;background:#050508;padding:8px;border-radius:4px;margin-top:4px;white-space:pre-wrap;word-break:break-all;max-height:240px;overflow:auto;border:1px solid #1f242d}

.footer{padding:20px 48px;border-top:1px solid #1f242d;font-family:'JetBrains Mono','Fira Mono',Consolas,monospace;font-size:10px;color:#555570;display:flex;justify-content:space-between;flex-wrap:wrap;gap:8px}

@media (max-width:768px){
  .timeline-container::before{left:20px}
  .event-item,.event-item.right{width:100%;margin-left:0;padding-left:40px;padding-right:0;justify-content:flex-start}
  .event-item.left .event-dot,.event-item.right .event-dot{left:13px;right:auto}
  .event-card{max-width:100%}
}
@media print{
  body{background:#fff;color:#111}
  .header{background:#f5f5f5;color:#111}
  .header-title{color:#000}
  .timeline-container::before{background:#bbb}
  .date-divider span{background:#fff;border-color:#ccc;color:#555}
  .event-card{background:#fff;border-color:#ccc;color:#111}
  .event-desc{color:#000}
  .event-dot{border-color:#fff}
  .event-raw-wrap[open] .event-raw{display:block !important}
  .footer{background:#f5f5f5;color:#555;border-top-color:#ccc}
}
</style>
</head>
<body>

<div class="header">
  <div class="header-eyebrow">DFIR-FENRIR // INCIDENT TIMELINE</div>
  <div class="header-title">${escHtml(inc.title || '')}</div>
  <div class="header-badges">
    ${inc.ref ? `<span class="header-badge badge-count">${escHtml(inc.ref)}</span>` : ''}
    ${inc.severity ? `<span class="header-badge badge-sev">${escHtml(String(inc.severity).toUpperCase())}</span>` : ''}
    ${inc.tlp ? `<span class="header-badge badge-tlp">TLP:${escHtml(String(inc.tlp).toUpperCase())}</span>` : ''}
    <span class="header-badge badge-count">${events.length} event${events.length !== 1 ? 's' : ''}</span>
  </div>
  <div class="header-meta">Exported ${escHtml(generated)}</div>
</div>

<div class="timeline-container">
  ${events.length ? eventsHtml : '<div style="text-align:center;color:#555570;padding:60px;font-family:\'JetBrains Mono\',monospace;font-size:12px">No timeline events recorded.</div>'}
</div>

<div class="footer">
  <span>DFIR-FENRIR v2 — ${escHtml(inc.title || '')}</span>
  ${inc.tlp ? `<span>TLP:${escHtml(String(inc.tlp).toUpperCase())} — Handle accordingly</span>` : ''}
  <span>Generated ${escHtml(generated)}</span>
</div>

</body>
</html>`

  triggerDownload(
    new Blob([html], { type: 'text/html;charset=utf-8' }),
    `timeline-${slug}.html`,
  )
}

// ─── Main component ───────────────────────────────────────────────────────────

export default function Timeline() {
  const { inc } = useOutletContext()
  const isClosed = inc?.status === 'closed'

  const [events, setEvents]       = useState([])
  const [loading, setLoading]     = useState(true)
  const [error, setError]         = useState(null)
  const [expandedId, setExpandedId] = useState(null)
  const [modalOpen, setModalOpen] = useState(false)
  const [busy, setBusy]           = useState(false)

  // LOLBin correlation state
  const [lolbinHits,   setLolbinHits]   = useState([])
  const [lolbinHitIds, setLolbinHitIds] = useState(new Set())
  const [lolbinOpen,   setLolbinOpen]   = useState(true)

  // System event visibility — persisted per-incident
  const sysKey = `fenrir_timeline_system_${inc.id}`
  const [showSystem,   setShowSystem]   = useState(() => {
    const v = localStorage.getItem(`fenrir_timeline_system_${inc.id}`)
    return v === null ? true : v === 'true'
  })
  const [systemCount,  setSystemCount]  = useState(0)
  const [sysModalOpen, setSysModalOpen] = useState(false)

  const toggleSystem = () => setShowSystem(prev => {
    const next = !prev
    localStorage.setItem(sysKey, String(next))
    return next
  })

  const load = useCallback(async () => {
    setError(null)
    try {
      const res = await api.listTimelineEvents(inc.id, { limit: 500, include_system: showSystem })
      setEvents(res.items)
      setSystemCount(res.system_event_count ?? 0)
    } catch (e) {
      setError(e.message || 'Could not load timeline')
    } finally {
      setLoading(false)
    }
    // LOLBin scan fires after events load — non-blocking, no loading state.
    api.lolbinsTimelineScan(inc.id)
      .then(data => {
        const hits = data.hits || []
        setLolbinHits(hits)
        setLolbinHitIds(new Set(hits.map(h => h.event_id)))
      })
      .catch(() => {}) // enrichment failure is silent
  }, [inc.id, showSystem])

  const lolbinHitMap = useMemo(() => {
    const m = new Map()
    for (const hit of lolbinHits) m.set(hit.event_id, hit.matches || [])
    return m
  }, [lolbinHits])

  useEffect(() => { load() }, [load])

  const toggle = (id) => setExpandedId(prev => prev === id ? null : id)

  const onDelete = async (ev) => {
    if (!window.confirm(`Remove this timeline event?\n\n${ev.description}`)) return
    setBusy(true)
    try {
      await api.deleteTimelineEvent(inc.id, ev.id)
      setExpandedId(null)
      await load()
    } catch (e) {
      setError(e.message || 'Could not delete event')
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="panel">
      <div className="panel-toolbar">
        <h2 className="panel-h">Incident Timeline</h2>
        <button
          type="button"
          className="btn"
          onClick={() => exportCsv(events, inc.ref)}
          disabled={events.length === 0}
          title="Export timeline as CSV"
        >
          Export CSV
        </button>
        <button
          type="button"
          className="btn"
          onClick={() => exportHtml(events, inc)}
          disabled={events.length === 0}
          title="Export timeline as standalone HTML"
        >
          Export HTML
        </button>
        <button
          type="button"
          className="btn"
          onClick={toggleSystem}
          title={showSystem ? 'Hide system-generated events' : 'Show system-generated events'}
          style={!showSystem ? { color: 'var(--accent)' } : undefined}
        >
          ⚙ {showSystem ? 'Hide system' : 'Show system'}
        </button>
        <button
          type="button"
          className="btn"
          onClick={() => setSysModalOpen(true)}
          disabled={isClosed}
          title="Add an operational annotation (system event)"
        >
          ⚙ Annotate
        </button>
        <button
          type="button"
          className="btn primary"
          onClick={() => setModalOpen(true)}
          disabled={isClosed}
          title={isClosed ? 'Closed incidents are read-only' : 'Add event'}
        >
          + Add event
        </button>
      </div>

      {error && (
        <div className="alert error" role="alert">
          <span className="alert-icon">!</span><span>{error}</span>
        </div>
      )}

      {!showSystem && systemCount > 0 && (
        <div style={{
          fontSize: 12,
          color: 'var(--dim)',
          padding: 'var(--space-2) var(--space-3)',
          background: 'var(--surface)',
          border: '1px solid var(--border)',
          borderRadius: 'var(--radius)',
          marginBottom: 'var(--space-3)',
          textAlign: 'center',
        }}>
          {systemCount} system event{systemCount !== 1 ? 's' : ''} hidden
          {' · '}
          <span
            role="button"
            tabIndex={0}
            onClick={toggleSystem}
            onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') toggleSystem() }}
            style={{ cursor: 'pointer', color: 'var(--accent)', userSelect: 'none' }}
          >
            show
          </span>
        </div>
      )}

      {/* LOLBin correlation panel — only when hits exist */}
      {lolbinHits.length > 0 && (
        <div style={{
          marginBottom: 'var(--space-3)',
          border: `1px solid color-mix(in srgb, var(--high) 35%, transparent)`,
          borderLeft: `3px solid var(--high)`,
          borderRadius: 'var(--radius)',
          background: `color-mix(in srgb, var(--high) 6%, var(--surface))`,
          overflow: 'hidden',
        }}>
          <div
            role="button"
            tabIndex={0}
            style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', padding: 'var(--space-2) var(--space-3)', cursor: 'pointer', userSelect: 'none' }}
            onClick={() => setLolbinOpen(o => !o)}
            onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setLolbinOpen(o => !o) } }}
          >
            <span style={{ color: 'var(--high)', fontSize: 13 }}>⚑</span>
            <span style={{ fontWeight: 600, fontSize: 12, color: 'var(--high)' }}>
              LOLBin correlations
            </span>
            <span style={{
              fontSize: 10, fontWeight: 700, fontFamily: 'var(--font-mono)',
              padding: '1px 6px', borderRadius: 'var(--radius-sm)',
              background: `color-mix(in srgb, var(--high) 18%, transparent)`,
              color: 'var(--high)',
            }}>{lolbinHits.length}</span>
            <span style={{ marginLeft: 'auto', fontSize: 11, color: 'var(--muted)' }}>
              {lolbinOpen ? '▲' : '▼'}
            </span>
          </div>

          {lolbinOpen && (
            <div style={{ borderTop: `1px solid color-mix(in srgb, var(--high) 20%, transparent)` }}>
              {lolbinHits.map((hit, i) => (
                <div key={hit.event_id} style={{
                  padding: 'var(--space-2) var(--space-3)',
                  borderTop: i > 0 ? '1px solid var(--border)' : undefined,
                  display: 'flex', gap: 'var(--space-3)', flexWrap: 'wrap', alignItems: 'flex-start',
                }}>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontSize: 12, color: 'var(--text)', marginBottom: 4, wordBreak: 'break-word' }}>
                      {hit.description}
                    </div>
                    <div style={{ display: 'flex', gap: 'var(--space-1)', flexWrap: 'wrap' }}>
                      {hit.matches.map(m => (
                        <span key={m.name} style={{
                          fontSize: 10, fontFamily: 'var(--font-mono)', fontWeight: 700,
                          padding: '1px 6px', borderRadius: 'var(--radius-sm)',
                          color: m.platform === 'windows' ? 'var(--high)' : 'var(--accent)',
                          background: m.platform === 'windows'
                            ? 'color-mix(in srgb, var(--high) 14%, transparent)'
                            : 'color-mix(in srgb, var(--accent) 14%, transparent)',
                          border: m.platform === 'windows'
                            ? '1px solid color-mix(in srgb, var(--high) 30%, transparent)'
                            : '1px solid color-mix(in srgb, var(--accent) 30%, transparent)',
                        }}>
                          {m.full_name || m.name}
                          &nbsp;·&nbsp;{m.source === 'lolbas' ? 'LOLBAS' : 'GTFOBins'}
                        </span>
                      ))}
                    </div>
                  </div>
                  {hit.hostname && (
                    <span style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--dim)', flexShrink: 0 }}>
                      {hit.hostname}
                    </span>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {loading ? (
        <div className="panel-empty"><div>Loading…</div></div>
      ) : events.length === 0 ? (
        <div className="panel-empty">
          <div className="panel-empty-mark" aria-hidden="true">◌</div>
          <div>No timeline events yet.</div>
          {!isClosed && (
            <div style={{ color: 'var(--dim)', fontSize: 12 }}>
              Click &ldquo;Add event&rdquo; to record the first observed event.
            </div>
          )}
        </div>
      ) : (
        <TimelineSpine
          events={events}
          expandedId={expandedId}
          onToggle={toggle}
          onDelete={onDelete}
          isClosed={isClosed}
          busy={busy}
          lolbinHitIds={lolbinHitIds}
          lolbinHitMap={lolbinHitMap}
        />
      )}

      {modalOpen && (
        <EventModal
          incidentId={inc.id}
          onClose={() => setModalOpen(false)}
          onCreated={() => { setModalOpen(false); load() }}
        />
      )}

      {sysModalOpen && (
        <SystemEventModal
          incidentId={inc.id}
          onClose={() => setSysModalOpen(false)}
          onCreated={() => { setSysModalOpen(false); load() }}
        />
      )}
    </section>
  )
}

// ─── Vertical spine ───────────────────────────────────────────────────────────

function TimelineSpine({ events, expandedId, onToggle, onDelete, isClosed, busy, lolbinHitIds, lolbinHitMap }) {
  // Group events by date so we can insert date separators.
  const groups = []
  let currentDate = null
  for (const ev of events) {
    const d = new Date(ev.event_time)
    const label = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`
    if (label !== currentDate) {
      currentDate = label
      groups.push({ type: 'date', label })
    }
    groups.push({ type: 'event', ev })
  }

  return (
    <div style={{ position: 'relative', paddingTop: 8, paddingBottom: 24 }}>
      {/* vertical spine line */}
      <div style={{
        position: 'absolute',
        left: 94,
        top: 0,
        bottom: 0,
        width: 2,
        background: 'var(--border)',
        zIndex: 0,
      }} />

      {groups.map((item, i) => {
        if (item.type === 'date') {
          return (
            <div
              key={`date-${item.label}-${i}`}
              style={{
                display: 'flex',
                alignItems: 'center',
                marginBottom: 12,
                marginTop: i === 0 ? 0 : 20,
                position: 'relative',
              }}
            >
              {/* align with spine */}
              <div style={{ width: 80, flexShrink: 0 }} />
              <div style={{
                marginLeft: 28,
                fontSize: 11,
                fontWeight: 700,
                fontFamily: 'var(--font-mono)',
                color: 'var(--muted)',
                letterSpacing: '0.05em',
                textTransform: 'uppercase',
              }}>
                {item.label}
              </div>
            </div>
          )
        }

        const { ev } = item
        const isExpanded = expandedId === ev.id
        const isSystem   = !!ev.is_system
        const dotColor   = tacticColor(ev.mitre_tactic_id)

        return (
          <div
            key={ev.id}
            style={{
              display: 'flex',
              alignItems: 'flex-start',
              marginBottom: 16,
              position: 'relative',
              opacity: isSystem ? 0.72 : 1,
            }}
          >
            {/* timestamp column */}
            <div style={{
              width: 80,
              flexShrink: 0,
              paddingRight: 8,
              textAlign: 'right',
              paddingTop: 10,
            }}>
              <span
                title={formatLocal(ev.event_time)}
                style={{
                  fontSize: 11,
                  fontFamily: 'var(--font-mono)',
                  color: 'var(--muted)',
                  lineHeight: 1.3,
                  display: 'block',
                  whiteSpace: 'pre',
                }}
              >
                {formatLocalShort(ev.event_time).slice(11, 16)}
              </span>
            </div>

            {/* spine dot — system events show a gear glyph instead */}
            {isSystem ? (
              <div style={{
                flexShrink: 0,
                width: 14,
                height: 14,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                marginTop: 10,
                zIndex: 1,
                fontSize: 12,
                lineHeight: 1,
                color: 'var(--dim)',
                background: 'var(--bg)',
              }}>⚙</div>
            ) : (
              <div style={{
                flexShrink: 0,
                width: 14,
                height: 14,
                borderRadius: '50%',
                background: dotColor,
                border: '2px solid var(--bg)',
                marginTop: 10,
                zIndex: 1,
                boxShadow: `0 0 0 1px ${dotColor}`,
              }} />
            )}

            {/* card */}
            <div style={{ flex: 1, marginLeft: 12, minWidth: 0 }}>
              {/* card header — always visible, clickable to expand */}
              <div
                role="button"
                tabIndex={0}
                onClick={() => onToggle(ev.id)}
                onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onToggle(ev.id) } }}
                style={{
                  background: 'var(--surface)',
                  border: `1px solid ${isExpanded ? 'var(--border-strong)' : 'var(--border)'}`,
                  borderRadius: isExpanded ? 'var(--radius) var(--radius) 0 0' : 'var(--radius)',
                  padding: 'var(--space-3)',
                  cursor: 'pointer',
                  userSelect: 'none',
                }}
              >
                {/* badges row */}
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginBottom: 6, alignItems: 'center' }}>
                  {ev.event_type && (
                    <span className="pill" style={{ fontSize: 11 }}>{ev.event_type}</span>
                  )}
                  {ev.mitre_tactic_id && (
                    <span className="pill" style={{ fontSize: 11, fontFamily: 'var(--font-mono)' }}>
                      {ev.mitre_tactic_id} · {ev.mitre_tactic_name}
                    </span>
                  )}
                  {ev.origin === 'forensic_import' && (
                    <span className="pill" style={{ fontSize: 10, color: 'var(--muted)' }}>import</span>
                  )}
                  {isSystem && (
                    <span className="pill" style={{ fontSize: 10, color: 'var(--dim)' }}>
                      ⚙ system{ev.system_source && ev.system_source !== 'manual' ? ` · ${ev.system_source}` : ''}
                    </span>
                  )}
                  {lolbinHitIds?.has(ev.id) && (
                    <span style={{
                      fontSize: 10, fontFamily: 'var(--font-mono)', fontWeight: 700,
                      padding: '1px 5px', borderRadius: 'var(--radius-sm)',
                      color: 'var(--high)',
                      background: 'color-mix(in srgb, var(--high) 14%, transparent)',
                      border: '1px solid color-mix(in srgb, var(--high) 30%, transparent)',
                    }}>⚑ LOLBIN</span>
                  )}
                  <span style={{
                    marginLeft: 'auto',
                    fontSize: 11,
                    color: 'var(--dim)',
                    fontFamily: 'var(--font-mono)',
                  }}>
                    {isExpanded ? '▲' : '▼'}
                  </span>
                </div>

                {/* description */}
                <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text)', marginBottom: 4, wordBreak: 'break-word' }}>
                  {ev.description}
                </div>

                {/* meta row */}
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 12, fontSize: 11, color: 'var(--muted)' }}>
                  {ev.hostname && (
                    <span style={{ fontFamily: 'var(--font-mono)' }}>{ev.hostname}</span>
                  )}
                  {ev.source && (
                    <span>{ev.source}</span>
                  )}
                  {ev.ir_phase && (
                    <span style={{ color: 'var(--dim)' }}>{IR_PHASE_LABELS[ev.ir_phase] || ev.ir_phase}</span>
                  )}
                </div>
              </div>

              {/* expanded body */}
              {isExpanded && (
                <div style={{
                  background: 'var(--surface-2)',
                  border: '1px solid var(--border-strong)',
                  borderTop: 'none',
                  borderRadius: '0 0 var(--radius) var(--radius)',
                  padding: 'var(--space-3)',
                }}>
                  {ev.mitre_technique_id && (
                    <div style={{ marginBottom: 12 }}>
                      <div style={{ fontSize: 11, color: 'var(--muted)', marginBottom: 4 }}>MITRE technique</div>
                      <span className="pill" style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>
                        {ev.mitre_technique_id} · {ev.mitre_technique_name}
                      </span>
                    </div>
                  )}

                  {(lolbinHitMap?.get(ev.id) || []).length > 0 && (
                    <div style={{ marginBottom: 12 }}>
                      <div style={{ fontSize: 11, color: 'var(--high)', marginBottom: 6, fontWeight: 600 }}>
                        ⚑ LOLBin / GTFOBin reference
                      </div>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                        {lolbinHitMap.get(ev.id).map((m, i) => (
                          <LolbinMatchCard key={`${m.source}-${m.name}-${i}`} match={m} />
                        ))}
                      </div>
                    </div>
                  )}

                  {ev.raw_log && (
                    <div style={{ marginBottom: 12 }}>
                      <div style={{ fontSize: 11, color: 'var(--muted)', marginBottom: 4 }}>Raw log</div>
                      <pre style={{
                        fontSize: 11,
                        fontFamily: 'var(--font-mono)',
                        color: 'var(--text)',
                        background: 'var(--bg)',
                        border: '1px solid var(--border)',
                        borderRadius: 'var(--radius-sm)',
                        padding: '8px 10px',
                        overflowX: 'auto',
                        whiteSpace: 'pre-wrap',
                        wordBreak: 'break-all',
                        margin: 0,
                        maxHeight: 200,
                        overflowY: 'auto',
                      }}>
                        {ev.raw_log}
                      </pre>
                    </div>
                  )}

                  <div style={{ fontSize: 11, color: 'var(--dim)', marginBottom: 12 }}>
                    Added {formatLocal(ev.created_at)}
                  </div>

                  <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
                    <button
                      type="button"
                      className="btn ghost"
                      onClick={(e) => { e.stopPropagation(); onDelete(ev) }}
                      disabled={isClosed || busy}
                    >
                      Delete
                    </button>
                  </div>
                </div>
              )}
            </div>
          </div>
        )
      })}
    </div>
  )
}

// ─── Add event modal ──────────────────────────────────────────────────────────

function EventModal({ incidentId, onClose, onCreated }) {
  const [eventTime, setEventTime]     = useState(() => new Date().toISOString())
  const [hostname, setHostname]       = useState('')
  const [source, setSource]           = useState('')
  const [eventType, setEventType]     = useState('')
  const [description, setDescription] = useState('')
  const [rawLog, setRawLog]           = useState('')
  const [showRaw, setShowRaw]         = useState(false)
  const [tacticId, setTacticId]       = useState('')
  const [tacticName, setTacticName]   = useState('')
  const [techniqueId, setTechniqueId]     = useState('')
  const [techniqueName, setTechniqueName] = useState('')
  const [busy, setBusy]   = useState(false)
  const [error, setError] = useState(null)

  useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape' && !busy) onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [busy, onClose])

  const onTacticChange = (e) => {
    const id   = e.target.value
    const tact = MITRE_TACTICS.find(t => t.id === id)
    setTacticId(id)
    setTacticName(tact?.name || '')
    setTechniqueId('')
    setTechniqueName('')
  }

  const onTechniqueChange = (e) => {
    const id   = e.target.value
    const tech = (MITRE_TECHNIQUES[tacticId] || []).find(t => t.id === id)
    setTechniqueId(id)
    setTechniqueName(tech?.name || '')
  }

  const onSubmit = async (e) => {
    e.preventDefault()
    setError(null)
    const desc = description.trim()
    if (!desc) { setError('Description is required.'); return }
    if (!eventTime) { setError('Event time is required.'); return }

    setBusy(true)
    try {
      await api.createTimelineEvent(incidentId, {
        event_time:           eventTime,
        hostname:             hostname.trim()  || null,
        source:               source.trim()   || null,
        event_type:           eventType.trim() || null,
        description:          desc,
        raw_log:              rawLog.trim()   || null,
        mitre_tactic_id:      tacticId        || null,
        mitre_tactic_name:    tacticName      || null,
        mitre_technique_id:   techniqueId     || null,
        mitre_technique_name: techniqueName   || null,
      })
      onCreated()
    } catch (err) {
      setError(err.message || 'Could not add event.')
    } finally {
      setBusy(false)
    }
  }

  const techniques = MITRE_TECHNIQUES[tacticId] || []

  return (
    <div
      className="modal-backdrop"
     
    >
      <div className="modal" role="dialog" aria-labelledby="tl-modal-title" style={{ maxWidth: 560 }}>
        <div className="modal-head">
          <h2 id="tl-modal-title">Add timeline event</h2>
          <button
            type="button"
            className="modal-close"
            onClick={onClose}
            disabled={busy}
            aria-label="Close"
          >×</button>
        </div>

        <form onSubmit={onSubmit}>
          <div className="modal-body">
            <div className="form">

              {/* Event time + event type */}
              <div className="form-row">
                <div className="field">
                  <label className="field-label" htmlFor="tl-event-time">
                    Event time (UTC)
                  </label>
                  <UtcDateTimeInput
                    id="tl-event-time"
                    value={eventTime}
                    onChange={setEventTime}
                    required
                  />
                </div>
                <div className="field">
                  <label className="field-label" htmlFor="tl-event-type">Event type</label>
                  <input
                    id="tl-event-type"
                    className="input"
                    value={eventType}
                    onChange={(e) => setEventType(e.target.value)}
                    maxLength={128}
                    placeholder="e.g. Process Execution"
                  />
                </div>
              </div>

              {/* Description */}
              <div className="field">
                <label className="field-label" htmlFor="tl-description">Description *</label>
                <textarea
                  id="tl-description"
                  className="input"
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  rows={2}
                  maxLength={4096}
                  required
                  autoFocus
                  placeholder="What happened? Be concise — one observable event per entry."
                />
              </div>

              {/* Hostname + Source */}
              <div className="form-row">
                <div className="field">
                  <label className="field-label" htmlFor="tl-hostname">Hostname</label>
                  <input
                    id="tl-hostname"
                    className="input"
                    value={hostname}
                    onChange={(e) => setHostname(e.target.value)}
                    maxLength={256}
                    placeholder="e.g. WORKSTATION-07"
                    style={{ fontFamily: 'var(--font-mono)' }}
                  />
                </div>
                <div className="field">
                  <label className="field-label" htmlFor="tl-source">Log source</label>
                  <input
                    id="tl-source"
                    className="input"
                    value={source}
                    onChange={(e) => setSource(e.target.value)}
                    maxLength={128}
                    placeholder="e.g. Sysmon, Windows Security"
                  />
                </div>
              </div>



              {/* MITRE tactic + technique */}
              <div className="form-row">
                <div className="field">
                  <label className="field-label" htmlFor="tl-tactic">MITRE tactic (optional)</label>
                  <select
                    id="tl-tactic"
                    className="select"
                    value={tacticId}
                    onChange={onTacticChange}
                  >
                    <option value="">— none —</option>
                    {MITRE_TACTICS.map(t => (
                      <option key={t.id} value={t.id}>{t.id} · {t.name}</option>
                    ))}
                  </select>
                </div>
                <div className="field">
                  <label className="field-label" htmlFor="tl-technique">Technique (optional)</label>
                  <select
                    id="tl-technique"
                    className="select"
                    value={techniqueId}
                    onChange={onTechniqueChange}
                    disabled={!tacticId}
                  >
                    <option value="">— select tactic first —</option>
                    {techniques.map(t => (
                      <option key={t.id} value={t.id}>{t.id} · {t.name}</option>
                    ))}
                  </select>
                </div>
              </div>

              {/* Raw log (collapsible) */}
              <div className="field">
                <button
                  type="button"
                  className="btn ghost"
                  onClick={() => setShowRaw(v => !v)}
                  style={{ padding: '2px 0', fontSize: 12, color: 'var(--muted)' }}
                >
                  {showRaw ? '▲ Hide raw log' : '▼ Add raw log snippet'}
                </button>
                {showRaw && (
                  <textarea
                    className="input"
                    value={rawLog}
                    onChange={(e) => setRawLog(e.target.value)}
                    rows={5}
                    maxLength={4000}
                    placeholder="Paste the relevant raw log entry here…"
                    style={{ fontFamily: 'var(--font-mono)', fontSize: 11, marginTop: 6 }}
                  />
                )}
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
            <button type="submit" className="btn primary" disabled={busy}>
              {busy ? 'Adding…' : 'Add event'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ─── LOLBin / GTFOBin reference cards ─────────────────────────────────────────
// Renders the technique details enriched by /api/incidents/{id}/timeline/lolbin-scan
// so analysts know what the binary does, command examples, MITRE refs, and
// detection hints — without leaving the timeline.

const LOLBIN_TECHNIQUE_COLOR = {
  download: 'var(--crit)', 'file-download': 'var(--crit)',
  upload:   'var(--high)', 'file-upload':   'var(--high)',
  execute:  'var(--crit)', shell:           'var(--crit)',
  suid:     'var(--crit)', sudo:            'var(--crit)',
  capabilities: 'var(--high)', 'file-write': 'var(--high)',
  'file-read':  'var(--med)',  library:     'var(--med)',
  'bind-shell': 'var(--crit)', 'reverse-shell': 'var(--crit)',
  'non-interactive-bind-shell':    'var(--crit)',
  'non-interactive-reverse-shell': 'var(--crit)',
}
const lolbinTechniqueColor = (type) =>
  LOLBIN_TECHNIQUE_COLOR[(type || '').toLowerCase()] || 'var(--muted)'

function LolbinMatchCard({ match }) {
  const platformColor = match.platform === 'windows' ? 'var(--high)' : 'var(--accent)'
  const sourceLabel = match.source === 'lolbas' ? 'LOLBAS' : 'GTFOBins'
  const techniques = match.techniques || []
  const paths = (match.paths || []).filter(Boolean)

  return (
    <div style={{
      background: 'var(--surface)',
      border: '1px solid var(--border)',
      borderLeft: `3px solid ${platformColor}`,
      borderRadius: 'var(--radius-sm)',
      padding: 'var(--space-2) var(--space-3)',
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', flexWrap: 'wrap', marginBottom: 6 }}>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 13, fontWeight: 700, color: 'var(--text)' }}>
          {match.full_name || match.name}
        </span>
        <span style={{
          fontSize: 10, fontWeight: 700,
          padding: '1px 6px', borderRadius: 'var(--radius-sm)',
          color: platformColor,
          background: `color-mix(in srgb, ${platformColor} 14%, transparent)`,
          border: `1px solid color-mix(in srgb, ${platformColor} 30%, transparent)`,
        }}>
          {sourceLabel}
        </span>
        <span style={{ fontSize: 10, color: 'var(--dim)', fontFamily: 'var(--font-mono)' }}>
          {match.platform}
        </span>
        <span style={{ marginLeft: 'auto', fontSize: 11, color: 'var(--dim)' }}>
          {techniques.length} technique{techniques.length !== 1 ? 's' : ''}
        </span>
      </div>

      {match.description && (
        <div style={{ fontSize: 12, color: 'var(--muted)', marginBottom: 8, lineHeight: 1.4 }}>
          {match.description}
        </div>
      )}

      {paths.length > 0 && (
        <div style={{ marginBottom: 8 }}>
          <div style={{ fontSize: 10, color: 'var(--dim)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 3 }}>
            Paths
          </div>
          {paths.map((p, i) => (
            <code key={i} style={{
              display: 'block', fontSize: 11, fontFamily: 'var(--font-mono)',
              color: 'var(--muted)', background: 'var(--surface-2)',
              padding: '2px 6px', borderRadius: 'var(--radius-sm)',
              marginBottom: 2, wordBreak: 'break-all',
            }}>{p}</code>
          ))}
        </div>
      )}

      {techniques.length > 0 && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
          {techniques.map((t, i) => <LolbinTechniqueRow key={i} technique={t} />)}
        </div>
      )}
    </div>
  )
}

function LolbinTechniqueRow({ technique }) {
  const [open, setOpen] = useState(false)
  const color = lolbinTechniqueColor(technique.type)
  const hasDetail = !!(technique.command || technique.detect)

  return (
    <div style={{
      background: 'var(--surface-2)',
      border: `1px solid color-mix(in srgb, ${color} 22%, transparent)`,
      borderRadius: 'var(--radius-sm)',
      padding: '6px 8px',
    }}>
      <div
        role={hasDetail ? 'button' : undefined}
        tabIndex={hasDetail ? 0 : undefined}
        onClick={() => hasDetail && setOpen(o => !o)}
        onKeyDown={hasDetail ? (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setOpen(o => !o) } } : undefined}
        style={{
          display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap',
          cursor: hasDetail ? 'pointer' : 'default', userSelect: 'none',
        }}
      >
        {technique.type && (
          <span style={{
            fontSize: 10, fontWeight: 700, textTransform: 'uppercase',
            padding: '1px 6px', borderRadius: 'var(--radius-sm)',
            color,
            background: `color-mix(in srgb, ${color} 14%, transparent)`,
          }}>{technique.type}</span>
        )}
        {technique.privileges && (
          <span style={{
            fontSize: 10, color: 'var(--dim)', fontFamily: 'var(--font-mono)',
            padding: '1px 5px', borderRadius: 'var(--radius-sm)',
            background: 'var(--surface)', border: '1px solid var(--border)',
          }}>{technique.privileges}</span>
        )}
        {(technique.mitre || []).map(id => (
          <span key={id} style={{
            fontSize: 10, fontFamily: 'var(--font-mono)',
            color: 'var(--accent)',
            background: 'color-mix(in srgb, var(--accent) 14%, transparent)',
            padding: '1px 5px', borderRadius: 'var(--radius-sm)',
          }}>{id}</span>
        ))}
        {technique.description && (
          <span style={{
            fontSize: 12, color: 'var(--muted)',
            flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
            minWidth: 0,
          }}>{technique.description}</span>
        )}
        {hasDetail && (
          <span style={{ fontSize: 10, color: 'var(--dim)', marginLeft: 'auto', flexShrink: 0 }}>
            {open ? '▲' : '▼'}
          </span>
        )}
      </div>

      {open && technique.command && (
        <pre style={{
          marginTop: 6, marginBottom: 0,
          background: 'var(--bg)',
          border: '1px solid var(--border)',
          borderRadius: 'var(--radius-sm)',
          padding: '6px 8px',
          fontSize: 11, fontFamily: 'var(--font-mono)',
          color: 'var(--ok)',
          overflowX: 'auto', whiteSpace: 'pre-wrap', wordBreak: 'break-all',
        }}>{technique.command}</pre>
      )}
      {open && technique.detect && (
        <div style={{ marginTop: 5, fontSize: 11, color: 'var(--dim)', fontStyle: 'italic' }}>
          ⚑ {technique.detect}
        </div>
      )}
    </div>
  )
}

// ─── System event modal (operational annotation) ──────────────────────────────

function SystemEventModal({ incidentId, onClose, onCreated }) {
  const [eventTime, setEventTime]     = useState(() => new Date().toISOString())
  const [description, setDescription] = useState('')
  const [busy, setBusy]   = useState(false)
  const [error, setError] = useState(null)

  useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape' && !busy) onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [busy, onClose])

  const onSubmit = async (e) => {
    e.preventDefault()
    setError(null)
    const desc = description.trim()
    if (!desc)      { setError('Description is required.'); return }
    if (!eventTime) { setError('Event time is required.');  return }

    setBusy(true)
    try {
      await api.createTimelineEvent(incidentId, {
        event_time:    eventTime,
        description:   desc,
        is_system:     true,
        system_source: 'manual',
      })
      onCreated()
    } catch (err) {
      setError(err.message || 'Could not add event.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="modal-backdrop">
      <div className="modal" role="dialog" aria-labelledby="sys-modal-title" style={{ maxWidth: 440 }}>
        <div className="modal-head">
          <h2 id="sys-modal-title">⚙ Annotate timeline</h2>
          <button
            type="button"
            className="modal-close"
            onClick={onClose}
            disabled={busy}
            aria-label="Close"
          >×</button>
        </div>

        <form onSubmit={onSubmit}>
          <div className="modal-body">
            <div className="form">
              <div style={{ fontSize: 12, color: 'var(--muted)', marginBottom: 'var(--space-2)' }}>
                System events appear with a ⚙ glyph and can be filtered out of the
                timeline view and final report.
              </div>

              <div className="field">
                <label className="field-label" htmlFor="sys-event-time">Event time (UTC)</label>
                <UtcDateTimeInput
                  id="sys-event-time"
                  value={eventTime}
                  onChange={setEventTime}
                  required
                />
              </div>

              <div className="field">
                <label className="field-label" htmlFor="sys-description">Description *</label>
                <textarea
                  id="sys-description"
                  className="input"
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  rows={3}
                  maxLength={4096}
                  required
                  autoFocus
                  placeholder="e.g. Malware sample identified · IR lead reassigned · War room opened"
                />
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
            <button type="submit" className="btn primary" disabled={busy}>
              {busy ? 'Adding…' : 'Add system event'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
