// ─── Utilities ────────────────────────────────────────────────────────────────

function esc(s) {
  if (s == null) return ''
  return String(s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;')
}

function fmtTs(iso) {
  if (!iso) return '—'
  try {
    return new Date(iso).toLocaleString(undefined, {
      year: 'numeric', month: '2-digit', day: '2-digit',
      hour: '2-digit', minute: '2-digit', hour12: false, timeZoneName: 'short',
    })
  } catch { return iso }
}

function fmtDate(iso) {
  if (!iso) return '—'
  try { return new Date(iso).toLocaleDateString(undefined, { year: 'numeric', month: 'long', day: 'numeric' }) }
  catch { return iso }
}

function calcDuration(start, end) {
  if (!start) return null
  const ms = (end ? new Date(end) : new Date()) - new Date(start)
  const totalMins = Math.floor(ms / 60_000)
  const d = Math.floor(totalMins / 1440)
  const h = Math.floor((totalMins % 1440) / 60)
  const m = totalMins % 60
  if (d >= 1) return `${d}d ${h}h`
  if (h >= 1) return `${h}h ${m}m`
  return `${m}m`
}

const SEV_HEX = { critical: '#ef4444', high: '#f97316', medium: '#f59e0b', low: '#22c55e' }
const TLP_HEX = { red: '#ef4444', amber: '#f59e0b', 'amber+strict': '#f97316', green: '#22c55e', clear: '#94a3b8' }
const PHASE_LABEL = {
  preparation: 'Preparation',
  detection_and_analysis: 'Detection & Analysis',
  containment_eradication_recovery: 'Containment, Eradication & Recovery',
  post_incident_activity: 'Post-Incident Activity',
}

function sevHex(s)  { return SEV_HEX[s]  || '#64748b' }
function tlpHex(t)  { return TLP_HEX[t]  || '#64748b' }
function phaseLabel(p) { return PHASE_LABEL[p] || p || '—' }

function pct(done, total) { return total ? Math.round((done / total) * 100) : 0 }

// ─── Shared section renderers ─────────────────────────────────────────────────

function renderCover(data, logo, t, classification, audience) {
  const inc = data.incident
  const dur = calcDuration(inc.created_at, inc.closed_at)
  const sev = (inc.severity || 'medium').toLowerCase()
  const tlp = (inc.tlp || 'amber').toLowerCase()
  // Use explicit classification if provided, otherwise fall back to the incident TLP.
  const classLabel = (classification || `TLP:${(inc.tlp || 'AMBER').toUpperCase()}`).toUpperCase()
  return `
<div class="cover">
  <div class="cover-top">
    ${logo ? `<img class="cover-logo" src="${esc(logo)}" alt="Logo">` : ''}
    <div class="cover-org">INCIDENT REPORT</div>
  </div>
  <div class="cover-title">${esc(inc.title)}</div>
  <div class="cover-pills">
    <span class="pill pill-sev" style="background:${sevHex(sev)}20;color:${sevHex(sev)};border-color:${sevHex(sev)}40">${esc((inc.severity || 'Medium').toUpperCase())}</span>
    <span class="pill pill-tlp" style="background:${tlpHex(tlp)}20;color:${tlpHex(tlp)};border-color:${tlpHex(tlp)}40">${esc(classLabel)}</span>
    <span class="pill pill-status">${esc((inc.status || 'open').toUpperCase())}</span>
  </div>
  <div class="cover-meta">
    ${audience ? `<div class="cover-meta-row"><span>Audience</span><span>${esc(audience)}</span></div>` : ''}
    <div class="cover-meta-row"><span>Opened</span><span>${esc(fmtTs(inc.created_at))}</span></div>
    ${inc.closed_at ? `<div class="cover-meta-row"><span>Closed</span><span>${esc(fmtTs(inc.closed_at))}</span></div>` : ''}
    ${dur ? `<div class="cover-meta-row"><span>Duration</span><span>${esc(dur)}</span></div>` : ''}
    ${inc.reporter ? `<div class="cover-meta-row"><span>Reporter</span><span>${esc(inc.reporter)}</span></div>` : ''}
    <div class="cover-meta-row"><span>Phase</span><span>${esc(phaseLabel(inc.phase))}</span></div>
    ${(inc.tags || []).length > 0 ? `<div class="cover-meta-row"><span>Tags</span><span>${(inc.tags || []).map(t => `<code style="font-size:11px;padding:1px 5px;border-radius:3px;background:rgba(128,128,128,0.18);margin-right:3px">${esc(t)}</code>`).join('')}</span></div>` : ''}
    <div class="cover-meta-row"><span>Generated</span><span>${esc(fmtTs(data.generated_at))}</span></div>
  </div>
</div>`
}

function renderOverview(data) {
  const inc = data.incident
  if (!inc.description) return ''
  return `
<div class="section">
  <div class="section-title">Incident Overview</div>
  <p class="narrative">${esc(inc.description)}</p>
</div>`
}

function renderKPIs(data, mode) {
  const cl   = data.closure_checklist || []
  const done = cl.filter(i => i.checked).length
  const acts = data.respond_actions || []
  const actsDone = acts.filter(a => a.status === 'done').length
  return `
<div class="section">
  <div class="section-title">Key Metrics</div>
  <div class="kpi-grid">
    <div class="kpi-card">
      <div class="kpi-val">${data.iocs.length}</div>
      <div class="kpi-lbl">Indicators of Compromise</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-val">${data.entities.length}</div>
      <div class="kpi-lbl">Affected Entities</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-val">${data.timeline_events.length}</div>
      <div class="kpi-lbl">Timeline Events</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-val">${actsDone}/${acts.length}</div>
      <div class="kpi-lbl">Response Actions Complete</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-val">${data.mitre_summary.length}</div>
      <div class="kpi-lbl">MITRE Tactics Observed</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-val">${pct(done, cl.length)}%</div>
      <div class="kpi-lbl">Closure Checklist</div>
    </div>
  </div>
</div>`
}

function renderRespondSummary(data) {
  const acts = data.respond_actions || []
  if (!acts.length) return ''
  const cats = ['containment', 'eradication', 'recovery']
  const rows = cats.map(cat => {
    const subset = acts.filter(a => a.category === cat)
    const done   = subset.filter(a => a.status === 'done').length
    const p      = pct(done, subset.length)
    return `<tr>
      <td style="text-transform:capitalize">${esc(cat)}</td>
      <td>${subset.length}</td>
      <td>${done}</td>
      <td>
        <div style="display:flex;align-items:center;gap:8px">
          <div style="flex:1;height:8px;background:rgba(128,128,128,0.2);border-radius:4px;overflow:hidden">
            <div style="width:${p}%;height:100%;background:var(--accent);border-radius:4px"></div>
          </div>
          <span style="min-width:32px;font-size:11px">${p}%</span>
        </div>
      </td>
    </tr>`
  }).join('')
  return `
<div class="section">
  <div class="section-title">Response Summary</div>
  <table>
    <thead><tr><th>Category</th><th>Total</th><th>Complete</th><th>Progress</th></tr></thead>
    <tbody>${rows}</tbody>
  </table>
</div>`
}

function renderIOCSummary(data) {
  const iocs = data.iocs || []
  if (!iocs.length) return ''
  const counts = {}
  for (const i of iocs) counts[i.type] = (counts[i.type] || 0) + 1
  const rows = Object.entries(counts)
    .sort((a, b) => b[1] - a[1])
    .map(([t, n]) => `<tr><td>${esc(t.replace(/_/g, ' '))}</td><td>${n}</td></tr>`)
    .join('')
  return `
<div class="section">
  <div class="section-title">IOC Type Summary</div>
  <table style="max-width:360px">
    <thead><tr><th>Type</th><th>Count</th></tr></thead>
    <tbody>${rows}</tbody>
  </table>
</div>`
}

function renderIOCsFull(data) {
  const iocs = data.iocs || []
  if (!iocs.length) return ''
  const tagsCell = (tags) =>
    (tags || []).map(t => `<code style="font-size:10px;padding:1px 4px;border-radius:3px;background:rgba(128,128,128,0.18);margin-right:2px">${esc(t)}</code>`).join('')
  const statusPill = (m) => {
    if (m === true)  return '<span class="pill" style="background:rgba(239,68,68,0.14);color:#ef4444;border:1px solid rgba(239,68,68,0.4)">⚠ Malicious</span>'
    if (m === false) return '<span class="pill" style="background:rgba(34,197,94,0.14);color:#22c55e;border:1px solid rgba(34,197,94,0.4)">✓ Clean</span>'
    return '<span class="pill" style="background:rgba(148,163,184,0.14);color:#94a3b8;border:1px solid rgba(148,163,184,0.4)">? Unknown</span>'
  }
  const confidenceCell = (c) => {
    const n = (c ?? 50)
    const label = n >= 70 ? 'High' : n >= 30 ? 'Medium' : 'Low'
    return `<span class="mono">${n}%</span> <span style="color:var(--muted);font-size:11px">${label}</span>`
  }
  const enrichCell = (i) => {
    const bits = []
    if (i.ti_matched) bits.push(`<span class="pill" style="background:rgba(239,68,68,0.10);color:#fca5a5;border:1px solid rgba(239,68,68,0.3)">⚠ TI: ${esc(i.ti_match_source || 'matched')}</span>`)
    if (i.lolbin_hit) bits.push(`<span class="pill" style="background:rgba(245,158,11,0.10);color:#fbbf24;border:1px solid rgba(245,158,11,0.3)">LOL: ${esc(i.lolbin_name || '')}</span>`)
    if (i.source)     bits.push(`<span class="mono" style="color:var(--muted);font-size:10px">src: ${esc(i.source)}</span>`)
    return bits.length ? bits.join(' ') : '<span style="color:var(--muted)">—</span>'
  }
  const rows = iocs.map(i => `<tr>
    <td>${esc(i.type.replace(/_/g, ' '))}</td>
    <td class="mono">${esc(i.value)}</td>
    <td>${statusPill(i.malicious)}</td>
    <td>${confidenceCell(i.confidence)}</td>
    <td>${enrichCell(i)}</td>
    <td>${tagsCell(i.tags)}</td>
  </tr>`).join('')
  // Type-count summary (matches the FIXES.md "IOCs Summary" pattern).
  const counts = {}
  for (const i of iocs) counts[i.type] = (counts[i.type] || 0) + 1
  const summary = Object.entries(counts)
    .sort((a, b) => b[1] - a[1])
    .map(([t, n]) => `<strong>${esc(t.replace(/_/g, ' '))}:</strong> ${n}`)
    .join(' · ')
  return `
<div class="section break">
  <div class="section-title">Indicators of Compromise (${iocs.length})</div>
  <div style="margin-bottom:12px;font-size:12px;color:var(--muted)">${summary}</div>
  <table>
    <thead><tr><th>Type</th><th>Value</th><th>Status</th><th>Confidence</th><th>Enrichment</th><th>Tags</th></tr></thead>
    <tbody>${rows}</tbody>
  </table>
</div>`
}

function renderEntitiesFull(data) {
  const ents = data.entities || []
  if (!ents.length) return ''
  const rows = ents.map(e => `<tr>
    <td>${esc(e.type)}</td>
    <td>${esc(e.name || e.value)}</td>
    <td><span style="color:${sevHex(e.criticality)}">${esc(e.criticality || '')}</span></td>
    <td>${e.compromised ? '<span style="color:#ef4444">Yes</span>' : 'No'}</td>
    <td>${esc(e.description || '')}</td>
  </tr>`).join('')
  return `
<div class="section break">
  <div class="section-title">Affected Entities (${ents.length})</div>
  <table>
    <thead><tr><th>Type</th><th>Name / Value</th><th>Criticality</th><th>Compromised</th><th>Description</th></tr></thead>
    <tbody>${rows}</tbody>
  </table>
</div>`
}

// Static SVG entity graph — circular layout, deterministic.
// Optional report section (default OFF). Shows every entity and every
// relation as a self-contained inline SVG; no JS at render time.
const ENTITY_HEX = {
  host:          '#22d3ee',
  user:          '#f59e0b',
  ip:            '#a78bfa',
  domain:        '#38bdf8',
  email:         '#10b981',
  service:       '#fb923c',
  network_range: '#8b5cf6',
  group:         '#94a3b8',
  other:         '#6b7280',
}
const entityHex = (t) => ENTITY_HEX[t] || '#6b7280'

function renderEntityGraph(data) {
  const ents = data.entities || []
  const rels = data.entity_relations || []
  if (!ents.length) return ''

  const W = 760, H = 560
  const cx = W / 2, cy = H / 2
  const radius = Math.max(160, Math.min(240, ents.length * 22))

  const pos = new Map()
  ents.forEach((e, i) => {
    const angle = (2 * Math.PI * i / ents.length) - Math.PI / 2
    pos.set(e.id, { x: cx + radius * Math.cos(angle), y: cy + radius * Math.sin(angle) })
  })

  const edges = rels.map(r => {
    const a = pos.get(r.from_entity_id)
    const b = pos.get(r.to_entity_id)
    if (!a || !b) return ''
    const label = esc((r.relationship_type || '').replace(/_/g, ' '))
    const midX = (a.x + b.x) / 2
    const midY = (a.y + b.y) / 2
    return `
      <line x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}"
            stroke="#94a3b8" stroke-width="1.2" stroke-opacity="0.55" marker-end="url(#rg-arrow)" />
      ${label ? `<text x="${midX}" y="${midY - 4}" text-anchor="middle"
                       font-family="ui-sans-serif,system-ui,sans-serif" font-size="9"
                       fill="#64748b">${label}</text>` : ''}`
  }).join('')

  const nodes = ents.map(e => {
    const p = pos.get(e.id)
    const color = entityHex(e.type)
    const label = esc(e.name || e.value || '')
    const type  = esc((e.type || '').replace(/_/g, ' '))
    const ring  = e.compromised ? '#ef4444' : color
    const trunc = label.length > 22 ? `${label.slice(0, 21)}…` : label
    return `
      <g>
        <circle cx="${p.x}" cy="${p.y}" r="10" fill="${color}" stroke="${ring}" stroke-width="${e.compromised ? 3 : 1}" />
        <text x="${p.x}" y="${p.y + 24}" text-anchor="middle"
              font-family="ui-sans-serif,system-ui,sans-serif" font-size="11" font-weight="600"
              fill="#0f172a">${trunc}</text>
        <text x="${p.x}" y="${p.y + 36}" text-anchor="middle"
              font-family="ui-monospace,SFMono-Regular,Menlo,monospace" font-size="9"
              fill="${color}">${type}</text>
      </g>`
  }).join('')

  const usedTypes = [...new Set(ents.map(e => e.type))]
  const legend = usedTypes.map((t, i) => `
    <g transform="translate(${12 + i * 110}, 12)">
      <circle cx="6" cy="6" r="5" fill="${entityHex(t)}" />
      <text x="16" y="10" font-family="ui-sans-serif,system-ui,sans-serif" font-size="10" fill="#475569">
        ${esc((t || '').replace(/_/g, ' '))}
      </text>
    </g>`).join('')

  return `
<div class="section break">
  <div class="section-title">Entity Graph (${ents.length} entities · ${rels.length} relation${rels.length !== 1 ? 's' : ''})</div>
  <div style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:6px;padding:8px;overflow:hidden">
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} ${H}" width="100%" style="display:block;max-width:${W}px;margin:0 auto">
      <defs>
        <marker id="rg-arrow" viewBox="0 0 10 10" refX="14" refY="5"
                markerWidth="6" markerHeight="6" orient="auto-start-reverse">
          <path d="M 0 0 L 10 5 L 0 10 z" fill="#94a3b8" />
        </marker>
      </defs>
      ${legend}
      ${edges}
      ${nodes}
    </svg>
  </div>
</div>`
}

function renderTimeline(data) {
  const evs = data.timeline_events || []
  if (!evs.length) return ''
  const rows = evs.map(ev => `<tr>
    <td class="mono" style="white-space:nowrap">${esc(fmtTs(ev.event_time))}</td>
    <td>${esc(ev.hostname || '')}</td>
    <td>${esc(ev.source || '')}</td>
    <td>${esc(ev.event_type || '')}</td>
    <td>${esc(ev.description)}</td>
    <td>${ev.mitre_technique_id ? `<span class="mono" style="font-size:11px">${esc(ev.mitre_technique_id)}</span>` : ''}</td>
  </tr>`).join('')
  return `
<div class="section break">
  <div class="section-title">Timeline (${evs.length} events)</div>
  <table>
    <thead><tr><th>Time</th><th>Host</th><th>Source</th><th>Event Type</th><th>Description</th><th>Technique</th></tr></thead>
    <tbody>${rows}</tbody>
  </table>
</div>`
}

function renderActions(data) {
  const acts = data.respond_actions || []
  const decs = data.decisions || []
  if (!acts.length && !decs.length) return ''
  const STATUS_COLOR = { done: '#22c55e', in_progress: '#f59e0b', open: '#64748b', deferred: '#94a3b8' }
  const actRows = acts.map(a => `<tr>
    <td style="text-transform:capitalize">${esc(a.category)}</td>
    <td>${esc(a.title)}</td>
    <td><span style="color:${STATUS_COLOR[a.status] || '#64748b'}">${esc(a.status.replace(/_/g, ' '))}</span></td>
    <td>${esc(a.notes || '')}</td>
  </tr>`).join('')
  const decRows = decs.map(d => `<tr>
    <td>${esc(d.summary)}</td>
    <td>${esc(d.outcome)}</td>
    <td>${esc(d.rationale || '')}</td>
  </tr>`).join('')
  return `
<div class="section break">
  <div class="section-title">Response Actions</div>
  ${acts.length ? `<table>
    <thead><tr><th>Category</th><th>Action</th><th>Status</th><th>Notes</th></tr></thead>
    <tbody>${actRows}</tbody>
  </table>` : ''}
  ${decs.length ? `<div style="margin-top:24px"><div class="section-subtitle">Decisions Log</div>
  <table>
    <thead><tr><th>Decision</th><th>Outcome</th><th>Rationale</th></tr></thead>
    <tbody>${decRows}</tbody>
  </table></div>` : ''}
</div>`
}

function renderPlaybook(data) {
  const tasks = data.playbook_tasks || []
  if (!tasks.length) return ''
  const STATUS_ICON = { done: '✓', in_progress: '◑', open: '○', skipped: '—' }
  const STATUS_COLOR = { done: '#22c55e', in_progress: '#f59e0b', open: '#64748b', skipped: '#94a3b8' }
  const byPhase = {}
  for (const t of tasks) { (byPhase[t.phase] = byPhase[t.phase] || []).push(t) }
  const sections = Object.entries(byPhase).map(([phase, ts]) => {
    const done = ts.filter(t => t.status === 'done').length
    const rows = ts.map(t => `<tr>
      <td style="color:${STATUS_COLOR[t.status]};font-size:14px;width:24px">${STATUS_ICON[t.status] || '○'}</td>
      <td>${esc(t.title)}</td>
      <td style="color:${STATUS_COLOR[t.status]};text-transform:capitalize">${esc(t.status.replace('_', ' '))}</td>
    </tr>`).join('')
    return `<div class="playbook-phase">
      <div class="section-subtitle">${esc(phaseLabel(phase))} — ${done}/${ts.length}</div>
      <table><tbody>${rows}</tbody></table>
    </div>`
  }).join('')
  return `
<div class="section break">
  <div class="section-title">Playbook Progress</div>
  ${sections}
</div>`
}

function renderEvidence(data) {
  const ev = data.evidence_summary || {}
  if (!ev.total) return ''
  return `
<div class="section">
  <div class="section-title">Evidence</div>
  <div class="kpi-grid" style="grid-template-columns:repeat(4,1fr)">
    <div class="kpi-card"><div class="kpi-val">${ev.total}</div><div class="kpi-lbl">Total items</div></div>
    <div class="kpi-card"><div class="kpi-val">${ev.active}</div><div class="kpi-lbl">Active</div></div>
    <div class="kpi-card"><div class="kpi-val">${ev.digital}</div><div class="kpi-lbl">Digital files</div></div>
    <div class="kpi-card"><div class="kpi-val">${ev.physical}</div><div class="kpi-lbl">Physical items</div></div>
  </div>
</div>`
}

function renderMitre(data) {
  const tactics = data.mitre_summary || []
  if (!tactics.length) return ''
  const TACTIC_COLORS = {
    'TA0001':'#ef4444','TA0002':'#f97316','TA0003':'#f59e0b','TA0004':'#eab308',
    'TA0005':'#22c55e','TA0006':'#14b8a6','TA0007':'#06b6d4','TA0008':'#3b82f6',
    'TA0009':'#8b5cf6','TA0010':'#ec4899','TA0011':'#f43f5e','TA0040':'#94a3b8',
  }
  const blocks = tactics.map(t => {
    const color = TACTIC_COLORS[t.tactic_id] || '#64748b'
    const techs = t.techniques.map(te =>
      `<span class="tech-pill">${esc(te.technique_id)} ${esc(te.technique_name)} ×${te.count}</span>`
    ).join(' ')
    return `<div class="tactic-block" style="border-left-color:${color}">
      <div class="tactic-head">
        <span class="tactic-dot" style="background:${color}"></span>
        <span class="tactic-name">${esc(t.tactic_name)}</span>
        <span class="tactic-id">${esc(t.tactic_id)}</span>
        <span class="tactic-count">${t.total} event${t.total !== 1 ? 's' : ''}</span>
      </div>
      ${techs ? `<div class="tactic-techs">${techs}</div>` : ''}
    </div>`
  }).join('')
  return `
<div class="section break">
  <div class="section-title">MITRE ATT&amp;CK Coverage</div>
  <div class="tactic-list">${blocks}</div>
</div>`
}

function renderMitreSummaryOnly(data) {
  const tactics = data.mitre_summary || []
  if (!tactics.length) return ''
  const names = tactics.map(t => `<span class="tech-pill">${esc(t.tactic_name)}</span>`).join(' ')
  return `
<div class="section">
  <div class="section-title">MITRE ATT&amp;CK Tactics Observed</div>
  <div style="margin-top:12px">${names}</div>
</div>`
}

// Plain-text → HTML: escape, preserve paragraphs (blank-line splits), keep
// single-line breaks as <br>. Returns '' for empty/whitespace-only input.
function narrativeToHtml(s) {
  if (!s) return ''
  const trimmed = String(s).trim()
  if (!trimmed) return ''
  return trimmed.split(/\n\s*\n/).map(p =>
    `<p class="narrative">${esc(p).replace(/\n/g, '<br>')}</p>`
  ).join('')
}

function renderLessons(data, full) {
  const ll = data.lessons_learned
  if (!ll) return ''
  const parts = []
  if (ll.incident_narrative) parts.push(`<div class="section-subtitle">Incident Narrative</div><p class="narrative">${esc(ll.incident_narrative)}</p>`)
  if (full) {
    if (ll.root_cause_category) parts.push(`<div class="section-subtitle" style="margin-top:16px">Root Cause</div><p class="narrative">${esc(ll.root_cause_category.replace(/_/g,' '))}${ll.root_cause_description ? ` — ${ll.root_cause_description}` : ''}</p>`)

    // Prefer the Reports-tab narratives when set; fall back to the structured lists.
    const worked   = narrativeToHtml(ll.report_what_worked_well)
    const improve  = narrativeToHtml(ll.report_what_could_improve)
    const recs     = narrativeToHtml(ll.report_security_recommendations)

    if (worked) {
      parts.push(`<div class="section-subtitle" style="margin-top:16px;color:#22c55e">What Worked Well</div>${worked}`)
    } else if (ll.what_went_well?.length) {
      parts.push(`<div class="section-subtitle" style="margin-top:16px;color:#22c55e">What Worked Well</div><ul>${ll.what_went_well.map(s => `<li>${esc(s)}</li>`).join('')}</ul>`)
    }
    if (improve) {
      parts.push(`<div class="section-subtitle" style="margin-top:16px;color:#f97316">What Could Be Improved</div>${improve}`)
    } else if (ll.friction_points?.length) {
      parts.push(`<div class="section-subtitle" style="margin-top:16px;color:#f97316">What Could Be Improved</div><ul>${ll.friction_points.map(s => `<li>${esc(s)}</li>`).join('')}</ul>`)
    }
    if (recs) {
      parts.push(`<div class="section-subtitle" style="margin-top:16px">Security Recommendations / Control Improvements</div>${recs}`)
    } else if (ll.control_improvements?.length) {
      const ciRows = ll.control_improvements.map(ci =>
        `<tr><td>${esc(ci.recommendation)}</td><td style="text-transform:capitalize">${esc(ci.category)}</td><td style="text-transform:capitalize">${esc(ci.priority)}</td></tr>`
      ).join('')
      parts.push(`<div class="section-subtitle" style="margin-top:16px">Security Recommendations / Control Improvements</div>
        <table><thead><tr><th>Recommendation</th><th>Category</th><th>Priority</th></tr></thead>
        <tbody>${ciRows}</tbody></table>`)
    }
  }
  if (ll.action_items?.length) {
    const aiRows = ll.action_items.map(ai =>
      `<tr><td>${esc(ai.action)}</td><td>${esc(ai.owner)}</td><td>${esc(ai.due_date || '')}</td><td style="text-transform:capitalize">${esc(ai.priority)}</td><td>${esc(ai.status.replace('_',' '))}</td></tr>`
    ).join('')
    parts.push(`<div class="section-subtitle" style="margin-top:16px">Action Items</div>
      <table><thead><tr><th>Action</th><th>Owner</th><th>Due</th><th>Priority</th><th>Status</th></tr></thead>
      <tbody>${aiRows}</tbody></table>`)
  }
  if (!parts.length) return ''
  return `
<div class="section break">
  <div class="section-title">Lessons Learned</div>
  ${parts.join('')}
</div>`
}

// ─── Remediation Plan (short / medium / long-term action items) ──────────────
// Derived from lessons_learned.action_items grouped by due_date bucket.
// Mirrors v1 §10 Remediation Plan structure: short-term (0–30d) red border,
// medium-term (30–90d) amber border, long-term (90+d / undated) blue border.

function renderRemediationPlan(data) {
  const ll = data.lessons_learned || {}
  const items = Array.isArray(ll.action_items) ? ll.action_items : []

  // Bucket the structured action_items by due-date (fallback source).
  const now = Date.now()
  const DAY = 86400000
  const buckets = { short: [], medium: [], long: [] }
  for (const it of items) {
    const due = it.due_date ? new Date(it.due_date).getTime() : null
    if (!due || isNaN(due)) { buckets.long.push(it); continue }
    const daysOut = (due - now) / DAY
    if      (daysOut <= 30) buckets.short.push(it)
    else if (daysOut <= 90) buckets.medium.push(it)
    else                    buckets.long.push(it)
  }

  const sub = (title, color, narrative, list) => {
    const narrativeHtml = narrativeToHtml(narrative)
    const head = `<div class="section-subtitle" style="margin-top:16px;color:${color};border-left:3px solid ${color};padding-left:10px">${esc(title)}</div>`
    if (narrativeHtml) return head + narrativeHtml
    if (!list.length) return ''
    const rows = list.map(ai =>
      `<tr><td>${esc(ai.action || '')}</td><td>${esc(ai.owner || '')}</td><td>${esc(ai.due_date || '—')}</td><td style="text-transform:capitalize">${esc(ai.priority || '')}</td><td>${esc((ai.status || '').replace('_',' '))}</td></tr>`
    ).join('')
    return head +
      `<table style="margin-top:8px"><thead><tr><th>Action</th><th>Owner</th><th>Due</th><th>Priority</th><th>Status</th></tr></thead>
      <tbody>${rows}</tbody></table>`
  }

  const body = sub('Short-Term (0–30 days)',         '#dc2626', ll.report_remediation_short,  buckets.short)
             + sub('Medium-Term (30–90 days)',       '#ea580c', ll.report_remediation_medium, buckets.medium)
             + sub('Long-Term (90+ days / undated)', '#2563eb', ll.report_remediation_long,   buckets.long)
  if (!body) return ''
  return `
<div class="section break">
  <div class="section-title">Remediation Plan</div>
  ${body}
</div>`
}

function renderClosure(data) {
  const cl = data.closure_checklist || []
  if (!cl.length) return ''
  const done = cl.filter(i => i.checked).length
  const p = pct(done, cl.length)
  const items = cl.map(i => `<li class="${i.checked ? 'cl-done' : 'cl-open'}">
    <span class="cl-icon">${i.checked ? '✓' : '○'}</span>
    <span>${esc(i.label)}</span>
  </li>`).join('')
  return `
<div class="section">
  <div class="section-title">Closure Checklist — ${done}/${cl.length} (${p}%)</div>
  <div class="progress-wrap">
    <div class="progress-bar"><div class="progress-fill" style="width:${p}%"></div></div>
  </div>
  <ul class="cl-list">${items}</ul>
</div>`
}

// Sentinel string that lives in the footer until `injectReportSha256()` is
// awaited. Verifiers reverse the substitution to recompute and check.
export const REPORT_SHA256_PLACEHOLDER = '___FENRIR_REPORT_SHA256_PLACEHOLDER___'

function renderFooter(footerText, generated, mode) {
  return `
<footer>
  <div class="footer-content">
    <span>${footerText ? esc(footerText) : 'Generated by DFIR-FENRIR v2'}</span>
    <span>${esc(mode === 'executive' ? 'Executive Summary' : 'Full Technical Report')} · ${esc(fmtTs(generated))}</span>
  </div>
  <div class="footer-sha">
    <span class="footer-sha-label">Integrity (SHA-256):</span>
    <span class="report-sha256">${REPORT_SHA256_PLACEHOLDER}</span>
  </div>
</footer>`
}

// Self-describing footer hash. The placeholder lives in the rendered HTML;
// we hash the full document *while the placeholder is still in place*, then
// substitute the hash back. Verifier: extract the hash from the footer,
// replace it with the placeholder, recompute, compare. Async because Web
// Crypto's SHA-256 returns a Promise.
export async function injectReportSha256(html) {
  if (!html.includes(REPORT_SHA256_PLACEHOLDER)) return html
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(html))
  const hex = Array.from(new Uint8Array(buf))
    .map(b => b.toString(16).padStart(2, '0')).join('')
  return html.replace(REPORT_SHA256_PLACEHOLDER, hex)
}

export async function verifyReportSha256(html) {
  const m = html.match(/<span class="report-sha256">([0-9a-f]{64})<\/span>/)
  if (!m) return { ok: false, reason: 'no SHA-256 marker found' }
  const claimed = m[1]
  const restored = html.replace(claimed, REPORT_SHA256_PLACEHOLDER)
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(restored))
  const hex = Array.from(new Uint8Array(buf))
    .map(b => b.toString(16).padStart(2, '0')).join('')
  return { ok: hex === claimed, claimed, computed: hex }
}

// ─── Chapter helpers (11-chapter canonical structure) ───────────────────────

// Re-titles the first .section-title inside a rendered HTML chunk to "§NN — Title".
// When `html` is empty, renders a stub section indicating no data.
function ch(num, title, html) {
  if (!html || !html.trim()) {
    return `<div class="section">
      <div class="section-title">§${num} — ${esc(title)}</div>
      <p style="color:var(--muted);font-size:13px;margin:0">No data recorded for this section.</p>
    </div>`
  }
  return html.replace(
    /<div class="section-title">[\s\S]*?<\/div>/,
    `<div class="section-title">§${num} — ${esc(title)}</div>`
  )
}

// §02 — Incident Details (full metadata table).
function renderIncidentDetails(data) {
  const inc = data.incident || {}
  const fmt = (v) => v == null || v === '' ? '—' : v
  const rows = [
    ['Reference',        fmt(inc.ref)],
    ['Title',            fmt(inc.title)],
    ['Severity',         fmt(inc.severity)],
    ['TLP',              fmt(inc.tlp)],
    ['Phase',            phaseLabel(inc.phase)],
    ['Status',           fmt(inc.status)],
    ['Triage state',     fmt(inc.triage_state)],
    ['Type',             fmt(inc.incident_type)],
    ['Detection method', fmt(inc.detection_method)],
    ['Opened',           fmtTs(inc.created_at)],
    ['Occurred at',      inc.occurred_at ? fmtTs(inc.occurred_at) : '—'],
    ['Contained at',     inc.contained_at ? fmtTs(inc.contained_at) : '—'],
    ['Closed at',        inc.closed_at ? fmtTs(inc.closed_at) : '—'],
    ['Duration',         inc.created_at ? (calcDuration(inc.created_at, inc.closed_at) || 'open') : '—'],
  ]
  const tags = (inc.tags || []).map(t =>
    `<code style="font-size:10px;padding:1px 4px;background:rgba(128,128,128,0.18);border-radius:3px;margin-right:2px">${esc(t)}</code>`
  ).join('') || '—'
  return `
<div class="section">
  <div class="section-title">Incident Details</div>
  <table style="max-width:640px">
    <tbody>
      ${rows.map(([k, v]) => `<tr><th style="width:200px">${esc(k)}</th><td>${esc(v)}</td></tr>`).join('')}
      <tr><th>Tags</th><td>${tags}</td></tr>
    </tbody>
  </table>
</div>`
}

// §05 — Impact Assessment.
function renderImpactAssessment(data) {
  const bia = data.business_impact
  if (!bia) return ''
  const dims = [
    ['Financial',     bia.financial],
    ['Operational',   bia.operational],
    ['Data exposure', bia.data_exposure],
    ['Reputational',  bia.reputational],
    ['Regulatory',    bia.regulatory],
    ['Legal',         bia.legal],
    ['Notes',         bia.notes],
  ].filter(([, v]) => v && String(v).trim())
  if (!dims.length) return ''
  const rows = dims.map(([k, v]) =>
    `<tr><th style="width:180px">${esc(k)}</th><td>${esc(v)}</td></tr>`
  ).join('')
  return `
<div class="section">
  <div class="section-title">Impact Assessment</div>
  <table style="max-width:760px"><tbody>${rows}</tbody></table>
</div>`
}

// §06 — Root Cause Analysis (extracted from lessons learned).
function renderRootCauseAnalysis(data) {
  const ll = data.lessons_learned
  if (!ll) return ''
  const has = ll.root_cause_category || ll.root_cause_description ||
              (ll.contributing_factors && ll.contributing_factors.length)
  if (!has) return ''
  const cat = ll.root_cause_category
    ? `<tr><th style="width:200px">Category</th><td>${esc(ll.root_cause_category.replace(/_/g, ' '))}</td></tr>` : ''
  const desc = ll.root_cause_description
    ? `<tr><th>Description</th><td class="narrative">${esc(ll.root_cause_description)}</td></tr>` : ''
  const factors = (ll.contributing_factors && ll.contributing_factors.length)
    ? `<tr><th>Contributing factors</th><td><ul style="margin:0">${ll.contributing_factors.map(f => `<li>${esc(f)}</li>`).join('')}</ul></td></tr>` : ''
  return `
<div class="section">
  <div class="section-title">Root Cause Analysis</div>
  <table style="max-width:760px"><tbody>${cat}${desc}${factors}</tbody></table>
</div>`
}

// §11 — Cost Tracking.
function renderCostTracking(data) {
  const costs = data.costs || []
  const bia = data.business_impact
  const hasFinancial = bia && bia.financial && bia.financial.trim()
  if (!costs.length && !hasFinancial) return ''

  let total = 0
  const byCat = {}
  for (const c of costs) {
    const amt = Number(c.amount) || 0
    total += amt
    byCat[c.category] = (byCat[c.category] || 0) + amt
  }
  const currency = (n) => n.toLocaleString(undefined, { maximumFractionDigits: 2 })

  const summaryRows = Object.entries(byCat)
    .sort((a, b) => b[1] - a[1])
    .map(([cat, sum]) => `<tr><td>${esc(cat.replace(/_/g, ' '))}</td><td class="mono" style="text-align:right">${esc(currency(sum))}</td></tr>`)
    .join('')
  const itemRows = costs.map(c => `<tr>
    <td style="text-transform:capitalize">${esc((c.category || '').replace(/_/g, ' '))}</td>
    <td>${esc(c.description || '')}</td>
    <td class="mono" style="text-align:right">${esc(currency(Number(c.amount) || 0))}</td>
    <td style="text-transform:capitalize">${esc((c.phase || '').replace(/_/g, ' '))}</td>
  </tr>`).join('')

  return `
<div class="section">
  <div class="section-title">Cost Tracking</div>
  ${hasFinancial ? `<div class="section-subtitle">Financial impact narrative</div>
    <p class="narrative">${esc(bia.financial)}</p>` : ''}
  ${costs.length ? `
    <div class="section-subtitle" style="margin-top:16px">Total: <span class="mono">${esc(currency(total))}</span> across ${costs.length} item${costs.length !== 1 ? 's' : ''}</div>
    ${summaryRows ? `<table style="max-width:480px;margin-top:8px">
      <thead><tr><th>Category</th><th style="text-align:right">Sum</th></tr></thead>
      <tbody>${summaryRows}</tbody>
    </table>` : ''}
    <div class="section-subtitle" style="margin-top:16px">Items</div>
    <table style="margin-top:8px">
      <thead><tr><th>Category</th><th>Description</th><th style="text-align:right">Amount</th><th>Phase</th></tr></thead>
      <tbody>${itemRows}</tbody>
    </table>
  ` : ''}
</div>`
}

// ─── CSS themes ───────────────────────────────────────────────────────────────

const BASE_CSS = `
*{box-sizing:border-box;margin:0;padding:0}
p{margin-bottom:8px}
ul{padding-left:20px;margin-bottom:8px}
li{margin-bottom:4px;font-size:13px}
a{color:inherit}
.break{page-break-before:always}
.narrative{font-size:14px;line-height:1.7;color:var(--narrative)}
.kpi-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-bottom:8px}
@media(min-width:900px){.kpi-grid{grid-template-columns:repeat(6,1fr)}}
.kpi-card{padding:16px;border-radius:8px;border:1px solid var(--border);background:var(--surface)}
.kpi-val{font-size:28px;font-weight:700;color:var(--accent);font-family:var(--mono)}
.kpi-lbl{font-size:11px;color:var(--muted);margin-top:4px;line-height:1.3}
table{width:100%;border-collapse:collapse;font-size:12px;margin-bottom:8px}
th{text-align:left;padding:8px 10px;background:var(--th-bg);color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.04em;border-bottom:1px solid var(--border)}
td{padding:7px 10px;border-bottom:1px solid var(--border-light);vertical-align:top;word-break:break-word}
.mono{font-family:var(--mono);font-size:12px}
.pill{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;border:1px solid transparent}
.tactic-list{display:flex;flex-direction:column;gap:12px}
.tactic-block{border-left:3px solid #64748b;padding:8px 12px;background:var(--surface);border-radius:0 6px 6px 0}
.tactic-head{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.tactic-dot{width:10px;height:10px;border-radius:50%;flex-shrink:0}
.tactic-name{font-weight:600;font-size:13px}
.tactic-id{font-size:11px;color:var(--muted);font-family:var(--mono)}
.tactic-count{margin-left:auto;font-size:11px;color:var(--muted)}
.tactic-techs{margin-top:6px;display:flex;flex-wrap:wrap;gap:6px}
.tech-pill{background:var(--pill-bg);color:var(--pill-text);padding:2px 8px;border-radius:4px;font-size:11px;border:1px solid var(--border)}
.progress-wrap{margin:12px 0}
.progress-bar{height:8px;background:var(--border);border-radius:4px;overflow:hidden}
.progress-fill{height:100%;background:var(--accent);border-radius:4px;transition:width .3s}
.cl-list{list-style:none;padding:0;margin-top:12px}
.cl-list li{display:flex;align-items:flex-start;gap:8px;padding:6px 0;border-bottom:1px solid var(--border-light);font-size:13px}
.cl-icon{flex-shrink:0;font-size:14px}
.cl-done .cl-icon{color:var(--ok)}
.cl-open .cl-icon{color:var(--muted)}
.cl-done span:last-child{color:var(--muted);text-decoration:line-through}
.section-subtitle{font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);margin-bottom:8px;margin-top:4px}
.playbook-phase{margin-bottom:16px}
.cover-top{display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:24px}
.cover-logo{max-height:56px;max-width:200px;object-fit:contain}
.cover-org{font-size:11px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;color:var(--muted)}
.cover-title{font-size:clamp(22px,4vw,34px);font-weight:700;line-height:1.2;margin-bottom:16px}
.cover-pills{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:20px}
.cover-meta{display:grid;grid-template-columns:repeat(2,auto);gap:4px 24px;align-items:baseline;max-width:480px}
.cover-meta-row{display:contents}
.cover-meta-row span:first-child{font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
.cover-meta-row span:last-child{font-size:13px}
footer{margin-top:48px;padding:16px var(--pad);border-top:1px solid var(--border)}
.footer-content{display:flex;justify-content:space-between;font-size:11px;color:var(--muted);flex-wrap:wrap;gap:8px}
.footer-sha{font-family:var(--mono);font-size:10px;color:var(--muted);margin-top:10px;padding-top:8px;border-top:1px dashed var(--border-light,var(--border));word-break:break-all;line-height:1.6}
.footer-sha-label{font-weight:700;margin-right:4px;text-transform:uppercase;letter-spacing:0.06em}
.report-sha256{user-select:all;color:var(--text)}
@media print{
  @page{size:A4;margin:1.5cm}
  .break{page-break-before:always}
  footer{position:running(footer)}
  body{font-size:11px}
  .kpi-val{font-size:22px}
}
`

const THEMES = {
  mission_control: {
    name: 'Mission Control',
    css: `
:root{--bg:#070b14;--surface:#0d1117;--surface-2:#111827;--border:#1e2d3d;--border-light:#1a2744;--text:#e2e8f0;--muted:#64748b;--accent:#22d3ee;--ok:#22c55e;--mono:'JetBrains Mono','Courier New',monospace;--narrative:#cbd5e1;--th-bg:#0d1117;--pill-bg:rgba(34,211,238,.08);--pill-text:#94a3b8;--pad:48px}
body{background:var(--bg);color:var(--text);font-family:-apple-system,'Segoe UI',Arial,sans-serif;font-size:14px;line-height:1.6;min-height:100vh}
.cover{padding:40px var(--pad);background:var(--surface);border-bottom:1px solid var(--border)}
.section{padding:32px var(--pad);border-bottom:1px solid var(--border)}
.section-title{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.12em;color:var(--accent);margin-bottom:20px}
tr:nth-child(even) td{background:rgba(255,255,255,.02)}
@media print{body{background:#fff;color:#111}.cover{background:#1a1a2e;-webkit-print-color-adjust:exact;print-color-adjust:exact}.section{border-color:#e5e7eb}.kpi-card{background:#f9fafb;border-color:#e5e7eb}.kpi-val{color:#1a1a2e}.tactic-block{background:#f9fafb}}
`,
  },
  executive: {
    name: 'Executive',
    css: `
:root{--bg:#ffffff;--surface:#f8fafc;--surface-2:#f1f5f9;--border:#e2e8f0;--border-light:#f1f5f9;--text:#0f172a;--muted:#64748b;--accent:#1e3a5f;--ok:#15803d;--mono:'Courier New',monospace;--narrative:#334155;--th-bg:#f8fafc;--pill-bg:#eff6ff;--pill-text:#1e40af;--pad:56px}
body{background:var(--bg);color:var(--text);font-family:'Georgia','Times New Roman',serif;font-size:14px;line-height:1.8}
.cover{padding:56px var(--pad) 48px;background:var(--accent);color:#fff}
.cover-org{color:rgba(255,255,255,.6)}
.cover .cover-meta-row span:first-child{color:rgba(255,255,255,.5)}
.cover .cover-meta-row span:last-child{color:rgba(255,255,255,.9)}
.cover .cover-pills .pill{border-color:rgba(255,255,255,.3)!important;background:rgba(255,255,255,.1)!important;color:#fff!important}
.section{padding:40px var(--pad);border-bottom:2px solid var(--border)}
.section-title{font-family:-apple-system,'Segoe UI',Arial,sans-serif;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.12em;color:var(--accent);margin-bottom:20px;padding-bottom:8px;border-bottom:2px solid var(--accent)}
table{font-family:-apple-system,'Segoe UI',Arial,sans-serif}
th{background:#1e3a5f;color:#fff}
.kpi-card{border-left:4px solid var(--accent)}
.kpi-val{color:var(--accent)}
`,
  },
  nordic: {
    name: 'Nordic Calm',
    css: `
:root{--bg:#f0f4f8;--surface:#ffffff;--surface-2:#e8edf2;--border:#dde3ea;--border-light:#eef1f4;--text:#1a202c;--muted:#718096;--accent:#4f46e5;--ok:#059669;--mono:'Courier New',monospace;--narrative:#2d3748;--th-bg:#f7f8fa;--pill-bg:#eef2ff;--pill-text:#4338ca;--pad:48px}
body{background:var(--bg);color:var(--text);font-family:-apple-system,'Segoe UI',Arial,sans-serif;font-size:14px;line-height:1.7}
.cover{padding:48px var(--pad);background:var(--surface);border-bottom:1px solid var(--border);border-top:4px solid var(--accent)}
.section{padding:36px var(--pad);background:var(--surface);margin-bottom:16px;border-radius:8px}
.section-title{font-size:13px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:var(--accent);margin-bottom:20px}
.kpi-card{box-shadow:0 1px 4px rgba(0,0,0,.06)}
.kpi-val{color:var(--accent)}
tr:hover td{background:var(--surface-2)}
`,
  },
  forensic: {
    name: 'Forensic',
    css: `
:root{--bg:#fafafa;--surface:#f3f4f6;--surface-2:#e5e7eb;--border:#d1d5db;--border-light:#e5e7eb;--text:#111827;--muted:#6b7280;--accent:#1f2937;--ok:#047857;--mono:'Courier New','Lucida Console',monospace;--narrative:#374151;--th-bg:#e5e7eb;--pill-bg:#f3f4f6;--pill-text:#374151;--pad:48px}
body{background:var(--bg);color:var(--text);font-family:'Courier New','Lucida Console',monospace;font-size:12px;line-height:1.6}
.tlp-banner{text-align:center;padding:8px;font-weight:700;font-size:12px;letter-spacing:.1em}
.cover{padding:32px var(--pad);border:2px solid var(--border);margin:16px}
.cover-title{font-family:'Courier New',monospace;font-size:20px;font-weight:700}
.section{padding:24px var(--pad);border-bottom:1px solid var(--border)}
.section-title{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.1em;color:var(--text);margin-bottom:16px;border-bottom:1px solid var(--border);padding-bottom:6px}
.kpi-val{font-size:24px;font-family:var(--mono)}
th{font-family:var(--mono);background:var(--th-bg)}
td{font-family:var(--mono)}
`,
  },
  compact: {
    name: 'Compact',
    css: `
:root{--bg:#fff;--surface:#fafafa;--surface-2:#f5f5f5;--border:#e0e0e0;--border-light:#efefef;--text:#212121;--muted:#757575;--accent:#0d47a1;--ok:#2e7d32;--mono:'Courier New',monospace;--narrative:#424242;--th-bg:#f5f5f5;--pill-bg:#e3f2fd;--pill-text:#0d47a1;--pad:32px}
body{background:var(--bg);color:var(--text);font-family:-apple-system,Arial,sans-serif;font-size:11px;line-height:1.5}
.cover{padding:24px var(--pad) 20px;border-bottom:3px solid var(--accent)}
.cover-title{font-size:18px;font-weight:700}
.section{padding:16px var(--pad);border-bottom:1px solid var(--border)}
.section-title{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.1em;color:var(--accent);margin-bottom:12px}
.kpi-grid{gap:8px}
.kpi-card{padding:10px;border-radius:4px}
.kpi-val{font-size:20px}
table{font-size:11px}
th,td{padding:5px 8px}
.narrative{font-size:12px}
`,
  },
  // ── v1 Tactical — dark indigo + red accent, matches the original FENRIR look.
  // Palette ported from ../fenrir/core/backend/services/report_themes.py "tactical" theme.
  tactical: {
    name: 'Tactical (v1)',
    css: `
:root{--bg:#070710;--surface:#0e0e1a;--surface-2:#0b0b16;--border:#1e1e30;--border-light:#16162a;--text:#e2e2f0;--muted:#8888aa;--accent:#dc2626;--ok:#22c55e;--mono:'JetBrains Mono','Courier New',monospace;--narrative:#c8c8e0;--th-bg:#0a0a18;--pill-bg:rgba(220,38,38,.10);--pill-text:#fca5a5;--pad:48px}
body{background:var(--bg);color:var(--text);font-family:'Inter',-apple-system,'Segoe UI',Arial,sans-serif;font-size:14px;line-height:1.7;min-height:100vh}
.cover{padding:48px var(--pad) 40px;background:linear-gradient(135deg,#07070f 0%,#140008 50%,#070710 100%);border-bottom:1px solid var(--accent)}
.cover-title{font-size:28px;font-weight:800;letter-spacing:-0.01em}
.cover-org{color:rgba(255,255,255,.4);font-size:11px;text-transform:uppercase;letter-spacing:.12em}
.cover-meta-row span:first-child{color:rgba(255,255,255,.5);text-transform:uppercase;font-size:10px;letter-spacing:.08em}
.cover-pills .pill{border-color:rgba(255,255,255,.18)!important;background:rgba(220,38,38,.12)!important;color:#fca5a5!important}
.section{padding:32px var(--pad);border-bottom:1px solid var(--border);background:var(--surface-2)}
.section + .section{margin-top:1px}
.section-title{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.12em;color:var(--accent);margin-bottom:20px;padding-bottom:8px;border-bottom:1px solid var(--accent)}
.kpi-card{background:var(--surface);border:1px solid var(--border);border-left:3px solid var(--accent)}
.kpi-val{color:var(--accent);font-family:var(--mono)}
tr:nth-child(even) td{background:rgba(255,255,255,.02)}
table th{background:var(--th-bg);color:var(--accent);text-transform:uppercase;font-size:11px;letter-spacing:.06em;border-bottom:1px solid var(--accent)}
.narrative{color:var(--narrative)}
@media print{body{background:#fff;color:#111}.cover{background:#1a0008;-webkit-print-color-adjust:exact;print-color-adjust:exact}.section{background:#fff;border-color:#e5e7eb;color:#111}.kpi-card{background:#f9fafb;border-color:#e5e7eb}.section-title{color:#7f1d1d;border-color:#7f1d1d}.kpi-val{color:#7f1d1d}}
`,
  },
}

// ─── Pro themes ───────────────────────────────────────────────────────────────
// Ported directly from v1's report_themes.py. All four themes share one
// structure (renderProReport below); only CSS variables differ. Severity and
// TLP colours override --red and --tlp at render time.

const PRO_THEMES = {
  // Original FENRIR dark/red look.
  tactical: {
    fonts: "@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap');",
    vars: {
      'bg':           '#070710',
      'bg-card':      '#0e0e1a',
      'bg-section':   '#0b0b16',
      'border':       '#1e1e30',
      'border-light': '#16162a',
      'text':         '#e2e2f0',
      'text-muted':   '#8888aa',
      'text-dim':     '#555570',
      'text-strong':  '#ffffff',
      'th-bg':        '#0a0a18',
      'th-color':     '#8888aa',
      'tr-hover':     '#0f0f1e',
      'enrich-bg':    '#1e2a1e',
      'enrich-fg':    '#4ade80',
      'task-done':    '#4ade80',
      'green':        '#16a34a',
      'amber':        '#d97706',
      'blue':         '#2563eb',
      'font':         "'Inter', sans-serif",
      'mono':         "'JetBrains Mono', monospace",
    },
    cover_gradient: 'linear-gradient(135deg, #07070f 0%, #140008 50%, #070710 100%)',
    prose_color:    '#c8c8e0',
  },
  // Light, formal, neutral navy (matches the user's example HTML).
  executive: {
    fonts: "@import url('https://fonts.googleapis.com/css2?family=Source+Serif+Pro:wght@400;600;700&family=Inter:wght@400;500;600;700&display=swap');",
    vars: {
      'bg':           '#ffffff',
      'bg-card':      '#f8fafc',
      'bg-section':   '#f1f5f9',
      'border':       '#cbd5e1',
      'border-light': '#e2e8f0',
      'text':         '#0f172a',
      'text-muted':   '#475569',
      'text-dim':     '#64748b',
      'text-strong':  '#0f172a',
      'th-bg':        '#1e293b',
      'th-color':     '#ffffff',
      'tr-hover':     '#f1f5f9',
      'enrich-bg':    '#dcfce7',
      'enrich-fg':    '#15803d',
      'task-done':    '#15803d',
      'green':        '#15803d',
      'amber':        '#b45309',
      'blue':         '#1e40af',
      'font':         "'Source Serif Pro', Georgia, serif",
      'mono':         "'Inter', sans-serif",
    },
    cover_gradient: 'linear-gradient(135deg, #f8fafc 0%, #e0e7ff 50%, #f1f5f9 100%)',
    prose_color:    '#1e293b',
  },
  // High-contrast B/W, optimised for paper.
  print: {
    fonts: "@import url('https://fonts.googleapis.com/css2?family=Source+Serif+Pro:wght@400;600;700&family=Source+Code+Pro:wght@400;600&display=swap');",
    vars: {
      'bg':           '#ffffff',
      'bg-card':      '#ffffff',
      'bg-section':   '#fafafa',
      'border':       '#000000',
      'border-light': '#666666',
      'text':         '#000000',
      'text-muted':   '#333333',
      'text-dim':     '#555555',
      'text-strong':  '#000000',
      'th-bg':        '#000000',
      'th-color':     '#ffffff',
      'tr-hover':     '#f5f5f5',
      'enrich-bg':    '#eeeeee',
      'enrich-fg':    '#000000',
      'task-done':    '#000000',
      'green':        '#000000',
      'amber':        '#000000',
      'blue':         '#000000',
      'font':         "'Source Serif Pro', Georgia, serif",
      'mono':         "'Source Code Pro', monospace",
    },
    cover_gradient: '#ffffff',
    prose_color:    '#000000',
  },
  // Court-ready blue/grey.
  forensic: {
    fonts: "@import url('https://fonts.googleapis.com/css2?family=Roboto:wght@400;500;700&family=Roboto+Mono:wght@400;500&display=swap');",
    vars: {
      'bg':           '#fafbfc',
      'bg-card':      '#ffffff',
      'bg-section':   '#f0f4f8',
      'border':       '#94a3b8',
      'border-light': '#cbd5e1',
      'text':         '#1e293b',
      'text-muted':   '#475569',
      'text-dim':     '#64748b',
      'text-strong':  '#0c4a6e',
      'th-bg':        '#e0f2fe',
      'th-color':     '#0c4a6e',
      'tr-hover':     '#f0f9ff',
      'enrich-bg':    '#dbeafe',
      'enrich-fg':    '#1e40af',
      'task-done':    '#0369a1',
      'green':        '#15803d',
      'amber':        '#b45309',
      'blue':         '#0c4a6e',
      'font':         "'Roboto', Arial, sans-serif",
      'mono':         "'Roboto Mono', monospace",
    },
    cover_gradient: 'linear-gradient(135deg, #f0f4f8 0%, #dbeafe 50%, #f0f9ff 100%)',
    prose_color:    '#1e293b',
  },
}

function _renderProCssVars(theme, sevColor, tlpColor) {
  const lines = Object.entries(theme.vars).map(([k, v]) => `  --${k}: ${v};`)
  lines.push(`  --red: ${sevColor};`)
  lines.push(`  --tlp: ${tlpColor};`)
  return `:root {\n${lines.join('\n')}\n}`
}

const TLP_MESSAGES = {
  RED:    'This information may not be shared outside your organization',
  AMBER:  'Limited disclosure — recipients only',
  GREEN:  'Community sharing permitted',
  WHITE:  'Unlimited public disclosure',
  CLEAR:  'Unlimited public disclosure',
}

// ─── Pro report: 11-chapter v1-style template ────────────────────────────────

function _proIocRows(iocs) {
  return iocs.map(i => {
    const statusHtml =
      i.malicious === true  ? '<span class="status-bad">⚠ Malicious</span>' :
      i.malicious === false ? '<span class="status-ok">✓ Clean</span>' :
                              '<span class="status-unk">? Unknown</span>'
    const enrichBits = []
    if (i.ti_matched)  enrichBits.push(`<span class="enrich-badge">TI: ${esc(i.ti_match_source || 'matched')}</span>`)
    if (i.lolbin_hit)  enrichBits.push(`<span class="enrich-badge" style="background:#fef3c7;color:#92400e">LOL: ${esc(i.lolbin_name || '')}</span>`)
    if (i.source)      enrichBits.push(`<span class="tiny" style="color:var(--text-dim)">src: ${esc(i.source)}</span>`)
    const enrich = enrichBits.length ? enrichBits.join(' ') : '—'
    const tags = (i.tags && i.tags.length)
      ? i.tags.slice(0, 3).map(t => `<span class="tag">${esc(t)}</span>`).join(' ')
      : '—'
    return `<tr>
      <td><span class="tag">${esc(i.type.replace(/_/g, ' '))}</span></td>
      <td class="mono small">${esc(i.value)}</td>
      <td>${statusHtml}</td>
      <td>${i.confidence ?? 50}%</td>
      <td>${enrich}</td>
      <td class="small">${tags}</td>
    </tr>`
  }).join('')
}

function _proCERSubsection(actions, category, title) {
  const subset = (actions || []).filter(a => (a.category || '').toLowerCase() === category)
  if (!subset.length) {
    return `<h3>${title}</h3><div class="placeholder-box"><strong>[ NO ${title.toUpperCase()} ACTIONS RECORDED ]</strong></div>`
  }
  const rows = subset.map(a => `<tr>
    <td>${esc(a.title || '')}</td>
    <td>${esc((a.status || '').replace(/_/g, ' '))}</td>
    <td class="small">${esc(a.notes || '—')}</td>
    <td class="mono small">${esc(a.performed_by || '—')}</td>
  </tr>`).join('')
  return `<h3>${title}</h3>
    <div class="table-wrap"><table>
      <thead><tr><th>Action</th><th>Status</th><th>Notes</th><th>By</th></tr></thead>
      <tbody>${rows}</tbody>
    </table></div>`
}

function _proRemBucket(items, label, color) {
  if (!items.length) {
    return `<h3>${label}</h3><div class="placeholder-box"><strong>[ NO ${label.toUpperCase()} ITEMS ]</strong></div>`
  }
  const rows = items.map(ai =>
    `<tr><td>${esc(ai.action || '')}</td><td>${esc(ai.owner || '—')}</td><td class="mono small">${esc(ai.due_date || '—')}</td><td style="text-transform:capitalize">${esc(ai.priority || '')}</td><td>${esc((ai.status || '').replace(/_/g, ' '))}</td></tr>`
  ).join('')
  return `<h3>${esc(label)}</h3>
    <div class="table-wrap" style="border-left:3px solid ${color}">
      <table>
        <thead><tr><th>Action</th><th>Owner</th><th>Due</th><th>Priority</th><th>Status</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`
}

// Per-bucket renderer that prefers the Reports-tab narrative over the
// structured action-items table.
function _proRemSection(narrative, items, label, color) {
  const narrativeHtml = narrativeToHtml(narrative)
  if (narrativeHtml) {
    return `<h3>${esc(label)}</h3>
      <div style="border-left:3px solid ${color};padding:6px 12px;margin-bottom:8px">${narrativeHtml}</div>`
  }
  return _proRemBucket(items, label, color)
}

// ── Appendix timeline renderer ────────────────────────────────────────────────
// Inline zig-zag spine matching the standalone Timeline HTML export format.
// Scoped under .atl-* CSS classes added to the pro report stylesheet.
function _proTimelineAppendix(evs) {
  if (!evs || !evs.length) return '<div class="placeholder-box"><strong>[ NO TIMELINE EVENTS ]</strong></div>'
  const TACTIC_COLORS = {
    'TA0001':'#ef4444','TA0002':'#f97316','TA0003':'#f59e0b','TA0004':'#eab308',
    'TA0005':'#22c55e','TA0006':'#14b8a6','TA0007':'#06b6d4','TA0008':'#3b82f6',
    'TA0009':'#8b5cf6','TA0010':'#ec4899','TA0011':'#f43f5e','TA0040':'#94a3b8',
  }
  const rows = []
  let prevDate = null
  evs.forEach((ev, i) => {
    const d = new Date(ev.event_time)
    const dateLabel = `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}`
    const timeLabel = `${String(d.getHours()).padStart(2,'0')}:${String(d.getMinutes()).padStart(2,'0')}:${String(d.getSeconds()).padStart(2,'0')}`
    if (dateLabel !== prevDate) {
      rows.push(`<div class="atl-date"><span>${esc(dateLabel)}</span></div>`)
      prevDate = dateLabel
    }
    const side  = i % 2 === 0 ? 'left' : 'right'
    const color = TACTIC_COLORS[ev.mitre_tactic_id] || '#6b7280'
    const mitreLabel = [ev.mitre_technique_id, ev.mitre_technique_name].filter(Boolean).join(' ') || ev.mitre_tactic_name || ''
    rows.push(`
      <div class="atl-item ${side}">
        <div class="atl-dot" style="background:${color};box-shadow:0 0 6px ${color}55"></div>
        <div class="atl-card" style="border-left:3px solid ${color}">
          <div class="atl-header">
            <span class="atl-time">${esc(timeLabel)}</span>
            ${ev.event_type ? `<span class="atl-pill" style="background:${color}22;color:${color};border-color:${color}55">${esc(ev.event_type)}</span>` : ''}
            ${ev.hostname   ? `<span class="atl-host">${esc(ev.hostname)}</span>` : ''}
          </div>
          <div class="atl-desc">${esc(ev.description || '')}</div>
          ${mitreLabel ? `<div class="atl-mitre" style="color:${color};border-color:${color}55;background:${color}1a">${esc(mitreLabel)}</div>` : ''}
          ${ev.source  ? `<div class="atl-meta">source: ${esc(ev.source)}</div>` : ''}
        </div>
      </div>`)
  })
  return `<div class="atl-wrap"><div class="atl-spine">${rows.join('\n')}</div></div>`
}

// Main pro renderer. Emits the full HTML with v1's structure + v2's data.
function generateProReport(data, opts = {}) {
  const {
    templateId = 'executive',
    mode = 'full',
    logo = null,
    footer = '',
    classification = '',
    audience = '',
    includeTimelineAppendix = false,
  } = opts

  const inc = (data && data.incident) || {}
  const theme = PRO_THEMES[templateId] || PRO_THEMES.executive
  const sev = (inc.severity || 'medium').toLowerCase()
  const tlp = (inc.tlp || 'amber').toLowerCase()
  const sevColor = sevHex(sev)
  const tlpColor = tlpHex(tlp)
  const cssVars  = _renderProCssVars(theme, sevColor, tlpColor)
  const generated = fmtTs(data.generated_at || new Date().toISOString())

  const iocs        = data.iocs    || []
  const ents        = data.entities || []
  const evs         = data.timeline_events || []
  const acts        = data.respond_actions  || []
  const tasks       = data.playbook_tasks   || []
  const decs        = data.decisions        || []
  const ll          = data.lessons_learned
  const ev          = data.evidence_summary || {}
  const bia         = data.business_impact
  const costs       = data.costs   || []
  const mitre       = data.mitre_summary || []
  const cl          = data.closure_checklist || []
  const assignments = data.assignments || []
  const malicIocs = iocs.filter(i => i.malicious === true).length
  const taskDone  = tasks.filter(t => t.status === 'done').length
  const taskPct   = pct(taskDone, tasks.length)

  // §03 — IOC type summary badges
  const iocTypes = {}
  for (const i of iocs) iocTypes[i.type] = (iocTypes[i.type] || 0) + 1
  const iocTypeBadges = Object.entries(iocTypes)
    .map(([t, n]) => `<span class="ioc-type-badge">${esc(t.replace(/_/g, ' '))}: <strong>${n}</strong></span>`)
    .join('')

  // §06 — MITRE attack chain rows (events tagged with techniques)
  const mitreRows = evs.filter(e => e.mitre_technique_id).map(e => `<tr>
    <td class="mono small">${esc(fmtTs(e.event_time))}</td>
    <td class="mono small">${esc(e.mitre_technique_id)}: ${esc(e.mitre_technique_name || '')}</td>
    <td>${esc(e.description || '')}</td>
  </tr>`).join('')

  // §07 — Entities rows
  const entityRows = ents.map(e => `<tr>
    <td><span class="tag">${esc(e.type || '')}</span></td>
    <td class="mono">${esc(e.name || e.value || '')}</td>
    <td><span style="color:${sevHex(e.criticality)};text-transform:capitalize">${esc(e.criticality || '')}</span></td>
    <td>${e.compromised ? '<span class="status-bad">COMPROMISED</span>' : '<span class="status-ok">Not compromised</span>'}</td>
    <td class="small">${esc(e.description || '—')}</td>
  </tr>`).join('')

  // Closure checklist items
  const closureItems = cl.length
    ? `<div class="progress-outer"><div class="progress-inner" style="width:${pct(cl.filter(c => c.checked).length, cl.length)}%"></div></div>
       <div class="progress-label">${cl.filter(c => c.checked).length} / ${cl.length} closure items complete</div>
       <ul style="margin-top:12px;padding-left:0;list-style:none">${cl.map(c => `<li class="task-row ${c.checked ? 'task-done' : 'task-pending'}"><span class="task-icon">${c.checked ? '✓' : '○'}</span><span class="task-title">${esc(c.label)}</span>${c.assigned_to ? `<span class="task-time">${esc(c.assigned_to)}</span>` : ''}</li>`).join('')}</ul>`
    : ''

  // §03 — Assignments table
  const assignmentsHtml = assignments.length
    ? `<div class="table-wrap"><table>
        <thead><tr><th>Role</th><th>Analyst</th><th>Assigned by</th><th>Assigned at</th><th>Notes</th></tr></thead>
        <tbody>${assignments.map(a => `<tr>
          <td style="font-weight:600">${esc(a.role_label)}</td>
          <td class="mono">${esc(a.username)}</td>
          <td class="mono small">${esc(a.assigned_by_username || '—')}</td>
          <td class="mono small">${esc(fmtTs(a.assigned_at))}</td>
          <td class="small">${esc(a.notes || '—')}</td>
        </tr>`).join('')}</tbody>
      </table></div>`
    : '<div class="placeholder-box"><strong>[ NO ASSIGNMENTS RECORDED ]</strong></div>'

  // §11 — Playbook tasks grouped by phase
  const playbookSections = (() => {
    if (!tasks.length) return ''
    const STATUS_ICON = { done: '✓', in_progress: '◑', open: '○', skipped: '—' }
    const byPhase = {}
    for (const t of tasks) { (byPhase[t.phase] = byPhase[t.phase] || []).push(t) }
    return Object.entries(byPhase).map(([phase, ts]) => {
      const done = ts.filter(t => t.status === 'done').length
      const rows = ts.map(t =>
        `<li class="task-row ${t.status === 'done' ? 'task-done' : 'task-pending'}">`
        + `<span class="task-icon">${STATUS_ICON[t.status] || '○'}</span>`
        + `<span class="task-title">${esc(t.title)}</span>`
        + (t.assignee ? `<span class="task-time">${esc(t.assignee)}</span>` : '')
        + `</li>`
      ).join('')
      return `<h3>${esc(phaseLabel(phase))} — ${done}/${ts.length} complete</h3>`
        + `<div class="progress-outer"><div class="progress-inner" style="width:${pct(done, ts.length)}%"></div></div>`
        + `<ul style="margin-top:8px;padding-left:0;list-style:none">${rows}</ul>`
    }).join('')
  })()

  // §10 — Remediation buckets from action items
  const now = Date.now()
  const DAY = 86400000
  const aiItems = (ll && Array.isArray(ll.action_items)) ? ll.action_items : []
  const buckets = { short: [], medium: [], long: [] }
  for (const it of aiItems) {
    const due = it.due_date ? new Date(it.due_date).getTime() : null
    if (!due || isNaN(due)) { buckets.long.push(it); continue }
    const daysOut = (due - now) / DAY
    if      (daysOut <= 30) buckets.short.push(it)
    else if (daysOut <= 90) buckets.medium.push(it)
    else                    buckets.long.push(it)
  }

  // §11 — Cost summary
  let costTotal = 0
  const costByCat = {}
  for (const c of costs) {
    const amt = Number(c.amount) || 0
    costTotal += amt
    costByCat[c.category] = (costByCat[c.category] || 0) + amt
  }
  const costCurrency = (n) => n.toLocaleString(undefined, { maximumFractionDigits: 2 })

  // TLP message
  const tlpUpper = tlp.toUpperCase()
  const tlpMsg = TLP_MESSAGES[tlpUpper] || 'Handle according to TLP guidelines'

  // Classification / audience derived
  const classDisplay = classification || `TLP:${tlpUpper}`

  // Logo block: data-URL <img> if provided, else placeholder.
  const logoHtml = logo
    ? `<img class="logo-image" src="${esc(logo)}" alt="Company logo">`
    : '<div class="logo-placeholder">[ COMPANY LOGO ]</div>'

  const audienceNote = audience
    ? `<div style="margin-bottom:16px;padding:10px 16px;background:var(--bg-card);border:1px solid var(--border);border-radius:6px;font-size:12px;color:var(--text-muted);font-family:var(--mono)">Prepared for: ${esc(audience)}</div>`
    : ''

  // ── Body ─────────────────────────────────────────────────────────────────
  const body = `
<div class="tlp-banner">TLP:${tlpUpper} — ${esc(tlpMsg)}</div>

<div class="cover">
  <div class="cover-inner">
    ${logoHtml}
    <div class="cover-eyebrow">Incident Response Report // DFIR-FENRIR v2</div>
    <div class="cover-title">${esc(inc.title || '')}</div>
    <div class="cover-subtitle">Post-Incident Analysis &amp; Forensic Report</div>
    <div class="cover-badges">
      <span class="badge badge-sev">${esc(sev.toUpperCase())} SEVERITY</span>
      <span class="badge badge-tlp">TLP:${tlpUpper}</span>
      <span class="badge badge-phase">${esc(phaseLabel(inc.phase))}</span>
      ${inc.status === 'closed'
        ? '<span class="badge" style="background:#1a1a2e;color:#dc2626;border:1px solid #dc2626">CLOSED</span>'
        : '<span class="badge" style="background:#1a1a0a;color:#ca8a04;border:1px solid #ca8a04">ACTIVE</span>'}
    </div>
    <div class="cover-meta">
      <div class="cover-meta-item"><strong>Incident ID</strong>${esc((inc.id || '').slice(0, 8).toUpperCase())}...</div>
      <div class="cover-meta-item"><strong>Opened</strong>${esc(fmtTs(inc.created_at))}</div>
      ${inc.closed_at ? `<div class="cover-meta-item"><strong>Closed</strong>${esc(fmtTs(inc.closed_at))}</div>` : ''}
      <div class="cover-meta-item"><strong>Generated</strong>${esc(generated)}</div>
    </div>
  </div>
</div>

<div class="doc-control">
  <div class="doc-control-item"><div class="label">Classification</div><div class="value">${esc(classDisplay)}</div></div>
  <div class="doc-control-item"><div class="label">Severity</div><div class="value" style="color:${sevColor}">${esc(sev.toUpperCase())}</div></div>
  <div class="doc-control-item"><div class="label">IR Phase</div><div class="value">${esc(phaseLabel(inc.phase))}</div></div>
  <div class="doc-control-item"><div class="label">Timeline Events</div><div class="value">${evs.length}</div></div>
  <div class="doc-control-item"><div class="label">IOCs</div><div class="value">${iocs.length} (${malicIocs} malicious)</div></div>
  <div class="doc-control-item"><div class="label">Report Type</div><div class="value">${mode === 'executive' ? 'Exec' : 'Full'}</div></div>
</div>

<div class="stats-bar">
  <div class="stat"><div class="stat-value">${evs.length}</div><div class="stat-label">Timeline Events</div></div>
  <div class="stat"><div class="stat-value">${iocs.length}</div><div class="stat-label">IOCs</div></div>
  <div class="stat"><div class="stat-value" style="color:#dc2626">${malicIocs}</div><div class="stat-label">Malicious IOCs</div></div>
  <div class="stat"><div class="stat-value">${ents.length}</div><div class="stat-label">Entities</div></div>
  <div class="stat"><div class="stat-value">${ev.total || 0}</div><div class="stat-label">Evidence Items</div></div>
  <div class="stat"><div class="stat-value" style="color:${taskPct === 100 ? '#16a34a' : '#d97706'}">${taskPct}%</div><div class="stat-label">Playbook Done</div></div>
</div>

<!-- §01 Executive Summary -->
<div class="section">
  <div class="section-header"><span class="section-number">§ 01</span><h2>Executive Summary</h2></div>
  ${audienceNote}
  ${inc.description
    ? `<div class="prose" style="white-space:pre-wrap">${esc(inc.description)}</div>`
    : '<div class="placeholder-box"><strong>[ PLACEHOLDER — EXECUTIVE SUMMARY ]</strong>On [DATE], [ORGANIZATION] identified a security incident with [SEVERITY] severity. The response team achieved initial containment by [TIME]. This report details the full findings and recommended remediation actions.</div>'}
</div>

<!-- §02 Incident Details -->
<div class="section section-alt">
  <div class="section-header"><span class="section-number">§ 02</span><h2>Incident Details</h2></div>
  <div class="two-col" style="margin-bottom:24px">
    <div class="info-card"><div class="label">Incident Type</div><div class="value">${esc(inc.incident_type ? inc.incident_type.replace(/_/g, ' ') : '[Not specified]')}</div></div>
    <div class="info-card"><div class="label">Severity</div><div class="value" style="color:${sevColor}">${esc(sev.toUpperCase())}</div></div>
    <div class="info-card"><div class="label">TLP Classification</div><div class="value" style="color:${tlpColor}">TLP:${tlpUpper}</div></div>
    <div class="info-card"><div class="label">Current Phase</div><div class="value">${esc(phaseLabel(inc.phase))}</div></div>
    <div class="info-card"><div class="label">Triage State</div><div class="value">${esc(inc.triage_state || '—')}</div></div>
    <div class="info-card"><div class="label">Detected At</div><div class="value mono">${esc(fmtTs(inc.occurred_at || inc.created_at))}</div></div>
    <div class="info-card"><div class="label">Contained At</div><div class="value mono">${inc.contained_at ? esc(fmtTs(inc.contained_at)) : '<span style="color:#d97706">Pending</span>'}</div></div>
    <div class="info-card"><div class="label">Closed At</div><div class="value mono">${inc.closed_at ? esc(fmtTs(inc.closed_at)) : '<span style="color:#d97706">Open / Ongoing</span>'}</div></div>
  </div>
  <h3>Incident Description</h3>
  ${inc.description
    ? `<div class="prose" style="white-space:pre-wrap">${esc(inc.description)}</div>`
    : '<div class="placeholder-box"><strong>[ PLACEHOLDER — DESCRIPTION ]</strong></div>'}
  ${(inc.tags && inc.tags.length)
    ? `<h3>Tags</h3><div>${inc.tags.map(t => `<span class="tag" style="margin-right:6px">${esc(t)}</span>`).join('')}</div>`
    : ''}
</div>

<!-- §03 Assignments -->
<div class="section">
  <div class="section-header"><span class="section-number">§ 03</span><h2>Assignments</h2></div>
  ${assignmentsHtml}
</div>

<!-- §04 Detection & Identification -->
<div class="section section-alt">
  <div class="section-header"><span class="section-number">§ 04</span><h2>Detection &amp; Identification</h2></div>
  <h3>Detection Method</h3>
  ${inc.detection_method
    ? `<div class="prose" style="white-space:pre-wrap">${esc(inc.detection_method)}</div>`
    : '<div class="placeholder-box"><strong>[ PLACEHOLDER — DETECTION METHOD ]</strong></div>'}
  <h3>Timeline of Key Events</h3>
  ${evs.length
    ? `<div class="table-wrap"><table>
        <thead><tr><th>Timestamp</th><th>Hostname</th><th>Event Type</th><th>Description</th><th>MITRE Technique</th></tr></thead>
        <tbody>${evs.map(e => `<tr>
          <td class="mono small">${esc(fmtTs(e.event_time))}</td>
          <td class="mono">${esc(e.hostname || '—')}</td>
          <td><span class="tag">${esc(e.event_type || '—')}</span></td>
          <td>${esc(e.description || '')}</td>
          <td class="mono small">${e.mitre_technique_id ? `${esc(e.mitre_technique_id)}: ${esc(e.mitre_technique_name || '')}` : '—'}</td>
        </tr>`).join('')}</tbody>
      </table></div>`
    : '<div class="placeholder-box"><strong>[ NO TIMELINE EVENTS ]</strong></div>'}
  <h3>IOCs Summary</h3>
  ${iocs.length
    ? `<div style="margin-bottom:14px">${iocTypeBadges}</div>
       <div class="table-wrap"><table>
         <thead><tr><th>Type</th><th>Value</th><th>Status</th><th>Confidence</th><th>Enrichment</th><th>Tags</th></tr></thead>
         <tbody>${_proIocRows(iocs)}</tbody>
       </table></div>`
    : '<div class="placeholder-box"><strong>[ NO IOCs RECORDED ]</strong></div>'}
</div>

<!-- §05 Containment, Eradication & Recovery -->
<div class="section">
  <div class="section-header"><span class="section-number">§ 05</span><h2>Containment, Eradication &amp; Recovery</h2></div>
  ${_proCERSubsection(acts, 'containment', 'Containment Actions')}
  ${_proCERSubsection(acts, 'eradication', 'Eradication Actions')}
  ${_proCERSubsection(acts, 'recovery',    'Recovery Actions')}
  ${decs.length
    ? `<h3>Decisions Log</h3>
       <div class="table-wrap"><table>
         <thead><tr><th>Decision</th><th>Outcome</th><th>Rationale</th></tr></thead>
         <tbody>${decs.map(d => `<tr><td>${esc(d.summary || '')}</td><td>${esc(d.outcome || '')}</td><td class="small">${esc(d.rationale || '—')}</td></tr>`).join('')}</tbody>
       </table></div>`
    : ''}
</div>

<!-- §06 Impact Assessment -->
<div class="section section-alt">
  <div class="section-header"><span class="section-number">§ 06</span><h2>Impact Assessment</h2></div>
  <div class="two-col" style="margin-bottom:24px">
    <div class="info-card"><div class="label">Financial Impact</div><div class="value">${bia && bia.financial ? esc(bia.financial) : '[ To be assessed ]'}</div></div>
    <div class="info-card"><div class="label">Operational Downtime</div><div class="value">${bia && bia.operational ? esc(bia.operational) : '[ To be assessed ]'}</div></div>
    <div class="info-card"><div class="label">Data Exposure</div><div class="value">${bia && bia.data_exposure ? esc(bia.data_exposure) : '[ To be assessed ]'}</div></div>
    <div class="info-card"><div class="label">Reputational Impact</div><div class="value">${bia && bia.reputational ? esc(bia.reputational) : '[ To be assessed ]'}</div></div>
    <div class="info-card"><div class="label">Regulatory Risk</div><div class="value">${bia && bia.regulatory ? esc(bia.regulatory) : '[ To be assessed ]'}</div></div>
    <div class="info-card"><div class="label">Legal Obligations</div><div class="value">${bia && bia.legal ? esc(bia.legal) : '[ GDPR Art.33 / NIS2 ]'}</div></div>
  </div>
  ${bia && bia.notes
    ? `<div class="prose" style="white-space:pre-wrap;margin-top:16px;padding:16px;background:var(--bg-card);border-radius:6px;border-left:3px solid #d97706">${esc(bia.notes)}</div>`
    : ''}
</div>

<!-- §07 Root Cause Analysis -->
<div class="section">
  <div class="section-header"><span class="section-number">§ 07</span><h2>Root Cause Analysis</h2></div>
  <h3>Initial Attack Vector / Root Cause Category</h3>
  ${ll && ll.root_cause_category
    ? `<div class="prose" style="white-space:pre-wrap"><strong>${esc(ll.root_cause_category.replace(/_/g, ' ').toUpperCase())}</strong>${ll.root_cause_description ? ' — ' + esc(ll.root_cause_description) : ''}</div>`
    : '<div class="placeholder-box"><strong>[ PLACEHOLDER — INITIAL ACCESS ]</strong></div>'}
  <h3>Contributing Factors</h3>
  ${ll && ll.contributing_factors && ll.contributing_factors.length
    ? `<ul style="padding-left:20px">${ll.contributing_factors.map(f => `<li>${esc(f)}</li>`).join('')}</ul>`
    : '<div class="placeholder-box"><strong>[ PLACEHOLDER ]</strong></div>'}
  <h3>Attack Chain (MITRE ATT&amp;CK)</h3>
  ${mitreRows
    ? `<div class="table-wrap"><table>
         <thead><tr><th>Timestamp</th><th>Technique</th><th>Description</th></tr></thead>
         <tbody>${mitreRows}</tbody>
       </table></div>`
    : '<div class="placeholder-box"><strong>[ NO MITRE TECHNIQUES MAPPED ]</strong></div>'}
</div>

<!-- §08 Entities & Attack Path -->
<div class="section section-alt">
  <div class="section-header"><span class="section-number">§ 08</span><h2>Entities &amp; Attack Path</h2></div>
  ${ents.length
    ? `<div class="table-wrap"><table>
         <thead><tr><th>Type</th><th>Name / Value</th><th>Criticality</th><th>Status</th><th>Notes</th></tr></thead>
         <tbody>${entityRows}</tbody>
       </table></div>`
    : '<div class="placeholder-box"><strong>[ NO ENTITIES RECORDED ]</strong></div>'}
</div>

<!-- §09 Evidence & Artifacts -->
<div class="section">
  <div class="section-header"><span class="section-number">§ 09</span><h2>Evidence &amp; Artifacts</h2></div>
  ${ev.total
    ? `<div class="two-col" style="margin-bottom:24px">
         <div class="info-card"><div class="label">Total Items</div><div class="value">${ev.total}</div></div>
         <div class="info-card"><div class="label">Active</div><div class="value">${ev.active || 0}</div></div>
         <div class="info-card"><div class="label">Digital Files</div><div class="value">${ev.digital || 0}</div></div>
         <div class="info-card"><div class="label">Physical Items</div><div class="value">${ev.physical || 0}</div></div>
       </div>`
    : '<div class="placeholder-box"><strong>[ NO EVIDENCE ITEMS COLLECTED ]</strong></div>'}
</div>

<!-- §10 Lessons Learned & Recommendations -->
<div class="section section-alt">
  <div class="section-header"><span class="section-number">§ 10</span><h2>Lessons Learned &amp; Recommendations</h2></div>
  <h3>What Worked Well</h3>
  ${narrativeToHtml(ll && ll.report_what_worked_well)
    || (ll && ll.what_went_well && ll.what_went_well.length
        ? `<ul style="padding-left:20px">${ll.what_went_well.map(s => `<li>${esc(s)}</li>`).join('')}</ul>`
        : '<div class="placeholder-box"><strong>[ PLACEHOLDER ]</strong></div>')}
  <h3>What Could Be Improved</h3>
  ${narrativeToHtml(ll && ll.report_what_could_improve)
    || (ll && ll.friction_points && ll.friction_points.length
        ? `<ul style="padding-left:20px">${ll.friction_points.map(s => `<li>${esc(s)}</li>`).join('')}</ul>`
        : '<div class="placeholder-box"><strong>[ PLACEHOLDER ]</strong></div>')}
  <h3>Security Recommendations / Control Improvements</h3>
  ${narrativeToHtml(ll && ll.report_security_recommendations)
    || (ll && ll.control_improvements && ll.control_improvements.length
        ? `<div class="table-wrap"><table>
             <thead><tr><th>Recommendation</th><th>Category</th><th>Priority</th></tr></thead>
             <tbody>${ll.control_improvements.map(ci => `<tr><td>${esc(ci.recommendation || '')}</td><td style="text-transform:capitalize">${esc(ci.category || '')}</td><td style="text-transform:capitalize">${esc(ci.priority || '')}</td></tr>`).join('')}</tbody>
           </table></div>`
        : '<div class="placeholder-box"><strong>[ PLACEHOLDER ]</strong></div>')}
</div>

<!-- §11 Playbook -->
<div class="section">
  <div class="section-header"><span class="section-number">§ 11</span><h2>Playbook</h2></div>
  ${playbookSections || '<div class="placeholder-box"><strong>[ NO PLAYBOOK TASKS RECORDED ]</strong></div>'}
</div>

<!-- §12 Closure Checklist Completion -->
<div class="section section-alt">
  <div class="section-header"><span class="section-number">§ 12</span><h2>Closure Checklist Completion</h2></div>
  ${closureItems || '<div class="placeholder-box"><strong>[ NO CLOSURE CHECKLIST ITEMS ]</strong></div>'}
</div>

<!-- §13 Remediation Plan -->
<div class="section">
  <div class="section-header"><span class="section-number">§ 13</span><h2>Remediation Plan</h2></div>
  ${_proRemSection(ll && ll.report_remediation_short,  buckets.short,  'Short-Term (0–30 days)',         '#dc2626')}
  ${_proRemSection(ll && ll.report_remediation_medium, buckets.medium, 'Medium-Term (30–90 days)',       '#ea580c')}
  ${_proRemSection(ll && ll.report_remediation_long,   buckets.long,   'Long-Term (90+ days / undated)', '#2563eb')}
</div>

<!-- §14 Cost Tracking -->
<div class="section section-alt">
  <div class="section-header"><span class="section-number">§ 14</span><h2>Cost Tracking</h2></div>
  ${bia && bia.financial
    ? `<h3>Financial Impact Narrative</h3><div class="prose" style="white-space:pre-wrap">${esc(bia.financial)}</div>`
    : ''}
  ${costs.length
    ? `<h3>Cost Summary — Total: <span class="mono">${esc(costCurrency(costTotal))}</span></h3>
       <div class="two-col" style="margin-bottom:16px">
         ${Object.entries(costByCat).sort((a, b) => b[1] - a[1]).map(([cat, sum]) =>
           `<div class="info-card"><div class="label">${esc(cat.replace(/_/g, ' '))}</div><div class="value mono">${esc(costCurrency(sum))}</div></div>`
         ).join('')}
       </div>
       <h3>Itemised Costs</h3>
       <div class="table-wrap"><table>
         <thead><tr><th>Category</th><th>Description</th><th style="text-align:right">Amount</th><th>Phase</th></tr></thead>
         <tbody>${costs.map(c => `<tr>
           <td style="text-transform:capitalize">${esc((c.category || '').replace(/_/g, ' '))}</td>
           <td>${esc(c.description || '')}</td>
           <td class="mono" style="text-align:right">${esc(costCurrency(Number(c.amount) || 0))}</td>
           <td style="text-transform:capitalize">${esc((c.phase || '').replace(/_/g, ' '))}</td>
         </tr>`).join('')}</tbody>
       </table></div>`
    : ((bia && bia.financial) ? '' : '<div class="placeholder-box"><strong>[ NO COSTS RECORDED ]</strong></div>')}
</div>

${includeTimelineAppendix ? `
<!-- Appendix A — Incident Timeline -->
<div class="section" style="page-break-before:always">
  <div class="section-header">
    <span class="section-number" style="letter-spacing:1px">A</span>
    <h2>Appendix A — Incident Timeline</h2>
  </div>
  <p style="font-size:12px;color:var(--text-muted);margin-bottom:24px">${evs.length} event${evs.length !== 1 ? 's' : ''} · chronological · all phases</p>
  ${_proTimelineAppendix(evs)}
</div>
` : ''}

<div class="footer">
  <div>
    <div style="margin-bottom:4px">DFIR-FENRIR v2 Incident Response Platform // Generated Report</div>
    <div style="color:var(--text-dim)">Incident ID: ${esc(inc.id || '')} // Generated: ${esc(generated)}</div>
    ${footer ? `<div style="margin-top:4px;color:var(--text-dim)">${esc(footer)}</div>` : ''}
  </div>
  <div class="footer-tlp">TLP:${tlpUpper}</div>
  <div style="text-align:right;font-size:10px;color:var(--text-dim)">
    <div>Integrity (SHA-256)</div>
    <div class="report-sha256" style="user-select:all;color:var(--text);word-break:break-all;max-width:280px">${REPORT_SHA256_PLACEHOLDER}</div>
  </div>
</div>`

  // ── CSS (v1's full pro stylesheet, theme-driven) ─────────────────────────
  const css = `
  ${theme.fonts}
  ${cssVars}
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: var(--font); background: var(--bg); color: var(--text); font-size: 14px; line-height: 1.6; }
  a { color: var(--blue); }
  .cover { background: ${theme.cover_gradient}; padding: 0; min-height: 360px; position: relative; overflow: hidden; border-bottom: 3px solid ${sevColor}; }
  .cover-inner { padding: 60px 64px 48px; position: relative; z-index: 2; }
  .cover::before { content: ''; position: absolute; top: -100px; right: -100px; width: 500px; height: 500px; border-radius: 50%; background: radial-gradient(circle, ${sevColor}18 0%, transparent 70%); z-index: 1; }
  .logo-placeholder { width: 160px; height: 56px; border: 2px dashed var(--border); border-radius: 6px; display: flex; align-items: center; justify-content: center; color: var(--text-dim); font-size: 11px; letter-spacing: 1px; margin-bottom: 36px; font-family: var(--mono); }
  .logo-image { max-width: 240px; max-height: 80px; width: auto; height: auto; margin-bottom: 36px; display: block; }
  .cover-eyebrow { font-size: 11px; color: var(--text-dim); letter-spacing: 3px; text-transform: uppercase; margin-bottom: 12px; font-family: var(--mono); }
  .cover-title { font-size: 38px; font-weight: 800; color: var(--text-strong); line-height: 1.15; max-width: 700px; letter-spacing: -0.5px; }
  .cover-subtitle { font-size: 16px; color: var(--text-muted); margin-top: 10px; font-weight: 400; }
  .cover-badges { display: flex; gap: 10px; margin-top: 24px; flex-wrap: wrap; }
  .badge { padding: 5px 14px; border-radius: 4px; font-size: 12px; font-weight: 700; letter-spacing: 1.5px; text-transform: uppercase; }
  .badge-sev { background: ${sevColor}; color: #fff; }
  .badge-tlp { background: transparent; border: 2px solid ${tlpColor}; color: ${tlpColor}; }
  .badge-phase { background: var(--bg-card); border: 1px solid var(--border); color: var(--text-muted); letter-spacing: 1px; }
  .cover-meta { margin-top: 32px; display: flex; gap: 32px; flex-wrap: wrap; }
  .cover-meta-item { font-size: 12px; color: var(--text-dim); font-family: var(--mono); }
  .cover-meta-item strong { color: var(--text-muted); display: block; margin-bottom: 2px; }
  .tlp-banner { background: ${tlpColor}22; border-bottom: 1px solid ${tlpColor}44; padding: 8px 64px; font-size: 11px; font-weight: 700; letter-spacing: 2px; color: ${tlpColor}; text-align: center; font-family: var(--mono); }
  .doc-control { background: var(--bg-card); border-bottom: 1px solid var(--border); padding: 20px 64px; display: flex; justify-content: space-between; flex-wrap: wrap; gap: 12px; }
  .doc-control-item { font-size: 12px; }
  .doc-control-item .label { color: var(--text-dim); font-family: var(--mono); letter-spacing: 1px; font-size: 10px; text-transform: uppercase; }
  .doc-control-item .value { color: var(--text); font-weight: 600; margin-top: 2px; }
  .stats-bar { display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); background: var(--bg-card); border-bottom: 1px solid var(--border); padding: 0; }
  .stat { padding: 20px 24px; border-right: 1px solid var(--border); text-align: center; }
  .stat:last-child { border-right: none; }
  .stat-value { font-size: 28px; font-weight: 800; color: var(--text-strong); line-height: 1; }
  .stat-label { font-size: 10px; color: var(--text-dim); letter-spacing: 1.5px; text-transform: uppercase; margin-top: 4px; font-family: var(--mono); }
  .section { padding: 48px 64px; border-bottom: 1px solid var(--border-light); }
  .section-alt { background: var(--bg-section); }
  .section-header { display: flex; align-items: center; gap: 14px; margin-bottom: 28px; }
  .section-number { font-size: 11px; font-family: var(--mono); color: var(--red); border: 1px solid var(--red); padding: 2px 8px; border-radius: 3px; letter-spacing: 2px; flex-shrink: 0; }
  .section h2 { font-size: 20px; font-weight: 700; color: var(--text-strong); }
  .section h3 { font-size: 14px; font-weight: 600; color: var(--text-muted); text-transform: uppercase; letter-spacing: 1px; margin: 28px 0 12px; }
  .prose { color: ${theme.prose_color}; line-height: 1.8; font-size: 14px; }
  .placeholder-box { border: 2px dashed var(--border); border-radius: 8px; padding: 24px; color: var(--text-dim); font-style: italic; font-size: 13px; line-height: 1.7; background: var(--bg-card); }
  .placeholder-box strong { color: var(--text-muted); font-style: normal; display: block; margin-bottom: 8px; font-family: var(--mono); font-size: 11px; letter-spacing: 1px; }
  .table-wrap { overflow-x: auto; border-radius: 8px; border: 1px solid var(--border); margin-bottom: 12px; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th { background: var(--th-bg); color: var(--th-color); padding: 10px 14px; text-align: left; font-size: 10px; letter-spacing: 1.5px; text-transform: uppercase; font-family: var(--mono); border-bottom: 1px solid var(--border); white-space: nowrap; }
  td { padding: 10px 14px; border-bottom: 1px solid var(--border-light); vertical-align: top; }
  tr:last-child td { border-bottom: none; }
  tr:hover td { background: var(--tr-hover); }
  .mono { font-family: var(--mono); }
  .small { font-size: 12px; }
  .tiny { font-size: 11px; }
  .tag { display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 11px; font-weight: 600; background: var(--bg-card); border: 1px solid var(--border); color: var(--text-muted); letter-spacing: 0.5px; font-family: var(--mono); }
  .status-ok { color: var(--green); font-weight: 600; }
  .status-bad { color: #dc2626; font-weight: 600; }
  .status-unk { color: var(--text-dim); }
  .enrich-badge { display: inline-block; padding: 1px 6px; border-radius: 3px; font-size: 10px; font-weight: 700; background: var(--enrich-bg); color: var(--enrich-fg); margin-right: 3px; font-family: var(--mono); }
  .ioc-type-badge { display: inline-block; padding: 4px 12px; border-radius: 4px; font-size: 12px; background: var(--bg-card); border: 1px solid var(--border); color: var(--text-muted); margin: 3px; font-family: var(--mono); }
  .progress-outer { background: var(--border); border-radius: 6px; height: 10px; margin: 12px 0; overflow: hidden; }
  .progress-inner { height: 10px; border-radius: 6px; background: linear-gradient(90deg, ${sevColor}, ${sevColor}99); width: 0%; }
  .progress-label { font-size: 12px; color: var(--text-muted); margin-top: 4px; font-family: var(--mono); }
  .task-row { display: flex; align-items: baseline; gap: 10px; padding: 5px 0; font-size: 13px; list-style: none; }
  .task-done { color: var(--task-done); }
  .task-pending { color: var(--text-dim); }
  .task-icon { font-family: var(--mono); font-size: 12px; flex-shrink: 0; width: 14px; }
  .task-title { flex: 1; }
  .task-time { color: var(--text-dim); font-family: var(--mono); font-size: 10px; margin-left: auto; white-space: nowrap; }
  .two-col { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
  .info-card { background: var(--bg-card); border: 1px solid var(--border); border-radius: 8px; padding: 20px; }
  .info-card .label { font-size: 10px; color: var(--text-dim); letter-spacing: 1.5px; text-transform: uppercase; font-family: var(--mono); margin-bottom: 6px; }
  .info-card .value { font-size: 15px; font-weight: 600; color: var(--text); }
  .footer { padding: 24px 64px; display: flex; justify-content: space-between; align-items: flex-start; color: var(--text-dim); font-size: 11px; background: var(--bg-card); border-top: 1px solid var(--border); font-family: var(--mono); gap: 12px; flex-wrap: wrap; }
  .footer-tlp { color: ${tlpColor}; font-weight: 700; letter-spacing: 1px; }
  @media print { .section { padding: 32px 48px; } table { font-size: 11px; } }
  .atl-wrap{position:relative}
  .atl-spine{position:relative;padding:8px 0}
  .atl-spine::before{content:'';position:absolute;left:50%;top:0;bottom:0;width:2px;background:var(--border);transform:translateX(-50%)}
  .atl-date{text-align:center;position:relative;margin:18px 0 10px;z-index:2}
  .atl-date span{display:inline-block;background:var(--bg);border:1px solid var(--border);padding:3px 12px;border-radius:20px;font-family:var(--mono);font-size:10px;color:var(--text-dim);letter-spacing:.06em}
  .atl-item{display:flex;width:50%;position:relative;margin-bottom:12px}
  .atl-item.left{padding-right:26px;justify-content:flex-end}
  .atl-item.right{padding-left:26px;margin-left:50%}
  .atl-dot{position:absolute;width:10px;height:10px;border-radius:50%;top:13px;z-index:3;border:2px solid var(--bg)}
  .atl-item.left .atl-dot{right:-6px}
  .atl-item.right .atl-dot{left:-6px}
  .atl-card{background:var(--bg-card);border:1px solid var(--border);border-radius:5px;padding:9px 11px;width:100%}
  .atl-header{display:flex;flex-wrap:wrap;gap:4px 6px;align-items:center;margin-bottom:5px}
  .atl-time{font-family:var(--mono);font-size:10px;font-weight:600;color:var(--text-muted);flex-shrink:0}
  .atl-host{font-family:var(--mono);font-size:9px;color:var(--text-dim);margin-left:auto}
  .atl-pill{font-size:9px;font-weight:700;padding:1px 6px;border-radius:3px;letter-spacing:.03em;white-space:nowrap;border:1px solid}
  .atl-desc{font-size:12px;color:var(--text);line-height:1.45;word-break:break-word}
  .atl-mitre{display:inline-block;font-family:var(--mono);font-size:9px;font-weight:600;padding:1px 6px;border-radius:3px;border:1px solid;margin-top:3px}
  .atl-meta{font-size:10px;color:var(--text-dim);margin-top:3px}
  @media(max-width:768px){.atl-spine::before{left:14px}.atl-item,.atl-item.right{width:100%;margin-left:0;padding-left:28px;padding-right:0;justify-content:flex-start}.atl-item.left .atl-dot,.atl-item.right .atl-dot{left:9px;right:auto}}
  @media print{.atl-spine::before{background:#ccc}.atl-card{background:#fff;border-color:#ccc}.atl-date span{background:#fff}}`

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>IR Report — ${esc(inc.title || 'Incident')}</title>
<style>${css}</style>
</head>
<body>${body}</body>
</html>`
}

// ─── Main export ──────────────────────────────────────────────────────────────

export const TEMPLATE_META = [
  { id: 'executive', name: 'Executive (light · serif)',  desc: 'Light, formal, navy/serif. Suitable for leadership and stakeholder delivery.' },
  { id: 'tactical',  name: 'Tactical (v1 · dark red)',   desc: 'The original FENRIR look — dark indigo with red accents. For operators who want the v1 visual identity.' },
  { id: 'forensic',  name: 'Forensic (court-ready)',     desc: 'Light blue/grey, monospace data fields. For regulatory, legal, or law enforcement handoff.' },
  { id: 'print',     name: 'Print (B/W, paper)',         desc: 'High-contrast black & white. Dense, paper-optimised.' },
]

// ─── Skeleton preview ─────────────────────────────────────────────────────────
// Renders a structural preview of the report: every dynamic field appears as a
// pill marking where the data comes from. Static prose stays as-is so the user
// can see the difference between "you wrote this" and "we'll fill it in".
// Honours the same section toggles / mode as generateReport — sections you
// excluded show up greyed out so the structure stays honest.

const SKELETON_CSS = `
  body { background: #0b0b16; color: #e2e2f0; font: 14px/1.55 -apple-system, BlinkMacSystemFont, 'Segoe UI', Inter, sans-serif; padding: 32px 48px; max-width: 920px; margin: 0 auto; }
  h1 { font-size: 22px; margin: 0 0 4px; letter-spacing: 0.02em; }
  h2 { font-size: 14px; margin: 24px 0 8px; color: #93c5fd; text-transform: uppercase; letter-spacing: 0.1em; font-weight: 700; }
  h3 { font-size: 13px; margin: 12px 0 6px; color: #c8c8e0; font-weight: 600; }
  p, li { color: #b8b8d0; }
  ul { margin: 0; padding-left: 18px; }
  li { margin: 4px 0; }
  .sk-banner { background: #1e3a5f; border: 1px solid #60a5fa55; color: #93c5fd; padding: 10px 14px; border-radius: 6px; margin-bottom: 24px; font-size: 13px; }
  .sk-section { background: #0e0e1a; border: 1px solid #1e1e30; border-radius: 8px; padding: 16px 20px; margin-bottom: 14px; position: relative; }
  .sk-section.excluded { opacity: 0.55; border-color: #7f1d1d; background: #1a0a0a; }
  .sk-section.excluded h3 { text-decoration: line-through; color: #fca5a5; }
  .sk-section.excluded ul { text-decoration: line-through; }
  .sk-section .excluded-badge { position: absolute; top: 12px; right: 16px; font-size: 10px; font-weight: 800; letter-spacing: 0.12em; text-transform: uppercase; color: #fff; background: #b91c1c; padding: 3px 8px; border-radius: 3px; font-family: 'JetBrains Mono', monospace; }
  .ph { display: inline-block; padding: 1px 8px; background: #1e3a5f33; color: #93c5fd; border: 1px solid #60a5fa55; border-radius: 4px; font-family: 'JetBrains Mono', Consolas, monospace; font-size: 11px; font-weight: 600; letter-spacing: 0.02em; }
  .ph-auto { color: #86efac; background: #14532d33; border-color: #4ade8055; }
  .ph-user { color: #fbbf24; background: #78350f33; border-color: #f59e0b55; }
  .static { color: #c8c8e0; }
  .legend { display: flex; gap: 10px; margin-bottom: 24px; font-size: 11px; color: #8888aa; flex-wrap: wrap; }
  .legend > span { display: inline-flex; align-items: center; gap: 6px; }
  .meta { font-size: 11px; color: #555570; font-family: 'JetBrains Mono', Consolas, monospace; margin-top: 32px; padding-top: 16px; border-top: 1px solid #1e1e30; }
`

// `kind` is 'auto' (filled from incident data), 'user' (filled from form input),
// or undefined (generic data field).
function ph(label, kind) {
  const cls = kind === 'auto' ? 'ph ph-auto' : kind === 'user' ? 'ph ph-user' : 'ph'
  return `<span class="${cls}">${esc(label)}</span>`
}

// Returns { title, items } describing each section. `items` is a list of
// HTML fragments (rendered with ph() helpers above) and prose strings.
function _skeletonSections(opts) {
  const isExec = opts.mode === 'executive'
  return [
    { key: 'cover', title: 'Cover', always: true, items: [
      `Title: ${ph('incident.title', 'auto')}`,
      `Severity: ${ph('incident.severity', 'auto')}`,
      `Classification: ${ph('your input', 'user')} or fallback ${ph('incident.tlp', 'auto')}`,
      `Audience: ${ph('your input', 'user')}`,
      `Opened / Closed / Duration: ${ph('incident.created_at / closed_at', 'auto')}`,
      `Phase: ${ph('incident.phase', 'auto')}`,
      `Tags (when set): ${ph('incident.tags[]', 'auto')}`,
    ]},
    { key: 'overview', title: 'Overview', items: [
      `Narrative: ${ph('incident.description', 'auto')}`,
    ]},
    { key: 'kpis', title: 'Key Metrics', items: [
      `${ph('iocs.count', 'auto')} indicators · ${ph('entities.count', 'auto')} entities · ${ph('timeline.count', 'auto')} events`,
      `${ph('actions.done / actions.total', 'auto')} response actions complete · ${ph('mitre.tactics.count', 'auto')} tactics observed`,
      `${ph('closure.percent', 'auto')} closure checklist`,
    ]},
    { key: 'iocs', title: isExec ? 'IOC Summary' : 'Indicators of Compromise', items: [
      isExec
        ? `Counts by type: ${ph('iocs grouped by type', 'auto')}`
        : `Full table: ${ph('iocs[*] (type, value, source, tags[], added_at, notes)', 'auto')}`,
    ]},
    { key: 'entities', title: 'Affected Entities', items: [
      `Table: ${ph('entities[*] (type, value, criticality, attributes)', 'auto')}`,
    ], hideOnExec: true },
    { key: 'entity_graph', title: 'Entity Graph', items: [
      `Inline SVG: all entities + entity_relations as a circular graph. ${ph('entities[*] + entity_relations[*]', 'auto')}`,
      `<span class="static">Optional — off by default. Enable in "Include sections".</span>`,
    ]},
    { key: 'actions', title: isExec ? 'Response Summary' : 'Response Actions', items: [
      isExec
        ? `Completion by category: ${ph('respond_actions grouped by category', 'auto')}`
        : `Cards: ${ph('respond_actions[*] (title, status, target, notes, performed_by)', 'auto')}`,
    ]},
    { key: 'timeline', title: 'Timeline', items: [
      `Events: ${ph('timeline_events[*] (event_time, description, mitre, hostname, source)', 'auto')}`,
      !opts.includeInternalEvents && isExec
        ? `<span class="static">⚠ Filtered to events where <code>external_safe = true</code>. Enable "Include internal-only events" to override.</span>`
        : `<span class="static">Includes all timeline events.</span>`,
    ], hideOnExec: false },
    { key: 'playbook', title: 'Playbook Tasks', items: [
      `Per-phase tasks: ${ph('playbook_tasks[*] (title, phase, status, assignee)', 'auto')}`,
    ], hideOnExec: true },
    { key: 'evidence', title: 'Evidence', items: [
      `Counts: ${ph('evidence_summary (total, active, disposed, digital, physical)', 'auto')}`,
    ], hideOnExec: true },
    { key: 'mitre', title: isExec ? 'MITRE Tactics' : 'MITRE ATT&CK Mapping', items: [
      isExec
        ? `Observed tactics: ${ph('mitre_summary[*].tactic_name', 'auto')}`
        : `Full mapping: ${ph('mitre_summary[*] (tactic + techniques + counts)', 'auto')}`,
    ]},
    { key: 'lessons', title: 'Lessons Learned & Recommendations', items: [
      `Narrative: ${ph('lessons_learned.incident_narrative', 'auto')}`,
      `Root cause: ${ph('lessons_learned.root_cause_category + description', 'auto')}`,
      `What went well / friction points / near misses: ${ph('lessons_learned.what_went_well[], friction_points[], near_misses[]', 'auto')}`,
      `Control improvements: ${ph('lessons_learned.control_improvements[] (recommendation, category, priority)', 'auto')}`,
    ]},
    { key: 'remediation', title: 'Remediation Plan', items: [
      `<strong style="color:#dc2626">Short-term (0–30 days):</strong> ${ph('action_items[] where due_date ≤ today + 30d', 'auto')}`,
      `<strong style="color:#ea580c">Medium-term (30–90 days):</strong> ${ph('action_items[] where due_date in 30–90d', 'auto')}`,
      `<strong style="color:#2563eb">Long-term (90+ days or undated):</strong> ${ph('action_items[] where due_date > 90d / null', 'auto')}`,
      `<span class="static">Each item: action · owner · due date · priority · status.</span>`,
    ]},
    { key: 'closure', title: 'Closure Checklist', items: [
      `Items: ${ph('closure_checklist[*] (item, checked, notes, assignee)', 'auto')}`,
    ]},
  ]
}

export function generateSkeleton(opts = {}) {
  const {
    mode = 'full',
    classification = '',
    audience = '',
    footer = '',
    includeInternalEvents = false,
    sections = {},
  } = opts
  const isExec = mode === 'executive'
  const include = { overview: true, kpis: true, iocs: true, entities: true,
                    entity_graph: false,
                    timeline: true, actions: true, playbook: true, evidence: true,
                    mitre: true, lessons: true, closure: true, ...sections }

  const summary = `
    <div class="sk-banner">
      Structure preview · <strong>${esc(mode === 'executive' ? 'Executive Summary' : 'Full Technical Report')}</strong>
      ${classification ? ` · ${esc(classification)}` : ''}
      ${audience ? ` · for ${esc(audience)}` : ''}
    </div>
    <div class="legend">
      <span>${ph('auto from incident data', 'auto')}</span>
      <span>${ph('your input', 'user')}</span>
      <span style="color:#555570">strikethrough = section excluded</span>
    </div>`

  const secs = _skeletonSections(opts).map(s => {
    if (s.hideOnExec && isExec) return ''
    const excluded = !s.always && include[s.key] === false
    return `
      <div class="sk-section${excluded ? ' excluded' : ''}">
        ${excluded ? '<span class="excluded-badge">EXCLUDED</span>' : ''}
        <h3>${esc(s.title)}</h3>
        <ul>${s.items.filter(Boolean).map(item => `<li>${item}</li>`).join('')}</ul>
      </div>`
  }).join('')

  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>Report structure preview</title>
<style>${SKELETON_CSS}</style>
</head><body>
<h1>Report Structure</h1>
<p style="color:#8888aa;font-size:12px;margin-top:0">What the analyst sees on Preview / Download — every coloured pill is a field the system fills in for you.</p>
${summary}
${secs}
<div class="meta">Footer: ${footer ? `<span class="static">"${esc(footer)}"</span>` : ph('your input', 'user')}</div>
</body></html>`
}


// generateReport — delegates to the new pro template. `includeInternalEvents`
// still filters timeline events for executive mode. Legacy `templateId` values
// from the old THEMES map (mission_control / nordic / compact) fall back to
// the closest pro theme.
const LEGACY_TEMPLATE_MAP = {
  mission_control: 'tactical',
  nordic:          'executive',
  compact:         'print',
}

export function generateReport(data, opts = {}) {
  const {
    mode = 'full',
    includeInternalEvents = false,
    templateId = 'executive',
  } = opts

  const resolvedId = PRO_THEMES[templateId]
    ? templateId
    : (LEGACY_TEMPLATE_MAP[templateId] || 'executive')

  const filteredData = { ...data }
  if (mode === 'executive' && !includeInternalEvents) {
    filteredData.timeline_events = (data.timeline_events || [])
      .filter(ev => ev.external_safe !== false)
  }

  return generateProReport(filteredData, { ...opts, templateId: resolvedId })
}
