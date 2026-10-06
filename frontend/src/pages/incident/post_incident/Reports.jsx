import { useCallback, useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../../../api/client.js'
import { REPORT_SECTION_OPTIONS, TEMPLATE_META, generateReport, generateSkeleton, injectReportSha256 } from '../../../lib/reportTemplates.js'
import LePackage from './LePackage.jsx'

// ── Lessons & Remediation (report narratives) ───────────────────────────────
// Six plain-text fields that feed §09 Lessons Learned and §10 Remediation Plan, on the
// `lessons_learned` row. J3 (R30): edited only on Post-Incident → Lessons Learned (which
// imports these definitions); this tab shows them read-only.

export const LR_FIELDS = [
  { key: 'report_what_worked_well',         label: 'What worked well',
    placeholder: 'Detection was fast; the on-call rota was clear; comms were calm…' },
  { key: 'report_what_could_improve',       label: 'What could be improved',
    placeholder: 'Containment took longer than target; runbook for X was missing…' },
  { key: 'report_security_recommendations', label: 'Security recommendations / control improvements',
    placeholder: 'Enforce MFA on remaining VPN endpoints; tighten egress filtering on tier-1 hosts…' },
]

export const LR_REMEDIATION = [
  { key: 'report_remediation_short',  label: 'Short-term (0–30 days)',          color: 'var(--crit)',
    placeholder: 'Rotate exposed credentials; deploy EDR on tier-1 assets…' },
  { key: 'report_remediation_medium', label: 'Medium-term (30–90 days)',         color: 'var(--high)',
    placeholder: 'Roll out conditional access policy; segment file-server VLAN…' },
  { key: 'report_remediation_long',   label: 'Long-term (90+ days)',             color: 'var(--accent)',
    placeholder: 'Replace legacy auth proxy; full IAM review; tabletop exercise cadence…' },
]

function LessonsAndRemediationSummary({ inc }) {
  const [ll,    setLl]    = useState(null)
  const [error, setError] = useState(null)

  useEffect(() => {
    api.getLessonsLearned(inc.id)
      .then(setLl)
      .catch(e => setError(e.message || 'Failed to load lessons'))
  }, [inc.id])

  if (error) return <div className="alert error"><span className="alert-icon">!</span><span>{error}</span></div>
  if (!ll)   return <div style={{ padding: 'var(--space-3)', color: 'var(--muted)', fontSize: 13 }}>Loading…</div>

  const block = (title, fields) => (
    <>
      <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 'var(--space-2)' }}>
        {title}
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)', marginBottom: 'var(--space-4)' }}>
        {fields.map(f => (
          <div key={f.key} data-ll-field={f.key}>
            <div className="field-label">{f.label}</div>
            {(ll[f.key] || '').trim()
              ? <div style={{ whiteSpace: 'pre-wrap', fontSize: 13, color: 'var(--text)' }}>{ll[f.key]}</div>
              : <div style={{ fontSize: 13, color: 'var(--dim)', fontStyle: 'italic' }}>Not recorded</div>}
          </div>
        ))}
      </div>
    </>
  )

  return (
    <div data-ll-summary="reports">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 'var(--space-2)', flexWrap: 'wrap', marginBottom: 'var(--space-3)' }}>
        <span style={{ fontSize: 12, color: 'var(--muted)', lineHeight: 1.5, flex: '1 1 320px' }}>
          Fills §09 Lessons Learned and §10 Remediation Plan in the generated report. Empty fields
          fall back to the structured entries on Lessons Learned.
        </span>
        <Link to="../lessons" className="btn ghost" data-ll-edit-link>Edit in Lessons learned</Link>
      </div>
      {block('Lessons Learned & Recommendations', LR_FIELDS)}
      {block('Remediation Plan', LR_REMEDIATION)}
    </div>
  )
}

// ── Section wrapper ───────────────────────────────────────────────────────────

export function PISection({ title, children }) {
  return (
    <div style={{ border: '1px solid var(--border)', borderRadius: 'var(--radius)', marginBottom: 'var(--space-5)', overflow: 'hidden' }}>
      <div style={{ background: 'var(--surface-2)', padding: 'var(--space-2) var(--space-3)', fontWeight: 700, fontSize: 13, borderBottom: '1px solid var(--border)', letterSpacing: '0.04em' }}>
        {title}
      </div>
      <div style={{ padding: 'var(--space-4)' }}>
        {children}
      </div>
    </div>
  )
}

const LS_LOGO   = 'fenrir:report:logo'
const LS_FOOTER = 'fenrir:report:footer'

function loadLogo()   { try { return localStorage.getItem(LS_LOGO)   || null } catch { return null } }
function loadFooter() { try { return localStorage.getItem(LS_FOOTER) || ''   } catch { return ''   } }

const SWATCH = {
  mission_control: '#070b14',
  executive:       '#1e3a5f',
  nordic:          '#4f46e5',
  forensic:        '#374151',
  compact:         '#0d47a1',
  tactical:        '#dc2626',
}

// ── Report figures (E4) ───────────────────────────────────────────────────────
// Each file picked in Supporting documents (report data `report_files`) is fetched
// from the download endpoint, hashed (SHA-256 of the original bytes) and embedded
// as a data: URI. Images over 1.5 MB are downscaled to at most 1920 px (JPEG).
// Embedded images are capped at 7 MiB in total: a saved report is a JSON body and
// Caddy caps those at 10 MiB. Figures past the cap are listed without the image.

const FIG_DOWNSCALE_BYTES = 1.5 * 1024 * 1024
const FIG_MAX_PX          = 1920
const FIG_CAP_CHARS       = 7 * 1024 * 1024
// The whole saved-report JSON body (HTML + metadata) must stay under Caddy's 10 MiB request limit.
const SAVE_MAX_BYTES      = 9.5 * 1024 * 1024
const INTEGRITY_FAILED_NOTE = 'Integrity check failed: the stored file is missing, tampered with or does not match its recorded SHA-256, so it is not embedded.'

// Raster formats a report may embed, from the magic bytes (never the stored type).
function sniffImage(b) {
  if (b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47) return 'image/png'
  if (b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return 'image/jpeg'
  if (b[0] === 0x47 && b[1] === 0x49 && b[2] === 0x46 && b[3] === 0x38) return 'image/gif'
  if (b[0] === 0x52 && b[1] === 0x49 && b[2] === 0x46 && b[3] === 0x46
      && b[8] === 0x57 && b[9] === 0x45 && b[10] === 0x42 && b[11] === 0x50) return 'image/webp'
  return null
}

function hexOf(buf) {
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('')
}

function blobToDataUrl(blob) {
  return new Promise((resolve, reject) => {
    const r = new FileReader()
    r.onload = () => resolve(r.result)
    r.onerror = () => reject(r.error)
    r.readAsDataURL(blob)
  })
}

async function downscaleToJpeg(blob) {
  const bmp = await createImageBitmap(blob)
  const scale = Math.min(1, FIG_MAX_PX / Math.max(bmp.width, bmp.height))
  const w = Math.max(1, Math.round(bmp.width * scale))
  const h = Math.max(1, Math.round(bmp.height * scale))
  const canvas = document.createElement('canvas')
  canvas.width = w
  canvas.height = h
  const ctx = canvas.getContext('2d')
  ctx.fillStyle = '#ffffff'   // JPEG has no alpha: flatten transparent screenshots onto white
  ctx.fillRect(0, 0, w, h)
  ctx.drawImage(bmp, 0, 0, w, h)
  bmp.close()
  return { src: canvas.toDataURL('image/jpeg', 0.85), w, h }
}

async function prepareFigures(incId, files) {
  let total = 0
  const figures = []
  for (const [i, f] of files.entries()) {
    const fig = { n: i + 1, name: f.name, caption: f.caption, mime: f.mime, size: f.size, sha256: f.sha256, integrity: f.integrity, src: null, note: null }
    figures.push(fig)
    // The server could not verify the stored file: never fetch or embed it.
    if (f.integrity === 'failed') { fig.sha256 = null; fig.note = INTEGRITY_FAILED_NOTE; continue }
    try {
      const res = await fetch(api.incidentFileDownloadUrl(incId, f.id), { credentials: 'same-origin' })
      if (res.status === 409) { fig.integrity = 'failed'; fig.sha256 = null; fig.note = INTEGRITY_FAILED_NOTE; continue }
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const buf = await res.arrayBuffer()
      const sha = hexOf(await crypto.subtle.digest('SHA-256', buf))
      if (f.sha256 && sha !== f.sha256) {
        fig.integrity = 'failed'
        fig.sha256 = null
        fig.note = INTEGRITY_FAILED_NOTE
        continue
      }
      fig.sha256 = sha
      const mime = sniffImage(new Uint8Array(buf.slice(0, 12)))
      if (!mime) { fig.note = 'Not embedded: the file is not a PNG, JPEG, GIF or WebP image.'; continue }
      let src
      if (buf.byteLength > FIG_DOWNSCALE_BYTES) {
        const d = await downscaleToJpeg(new Blob([buf], { type: mime }))
        src = d.src
        fig.note = `Downscaled for the report to ${d.w}×${d.h} px (JPEG); the SHA-256 is of the original file.`
      } else {
        src = await blobToDataUrl(new Blob([buf], { type: mime }))
      }
      if (total + src.length > FIG_CAP_CHARS) {
        fig.overCap = true
        fig.note = 'Not embedded: the report’s 7 MiB limit for embedded images was reached. Open the original in Supporting documents.'
        continue
      }
      total += src.length
      fig.src = src
    } catch (e) {
      fig.note = `Not embedded: the image could not be loaded (${e.message || 'error'}).`
    }
  }
  return { figures, total, overCap: figures.filter(f => f.overCap).length }
}

// ── Report generation ─────────────────────────────────────────────────────────

// The preview tab is opened inside the click (a tab opened after an await is a blocked pop-up in
// most browsers) and the report is written into it once ready. null when the browser blocked it.
function openPreviewWindow() {
  const w = window.open('', '_blank')
  if (w) {
    w.document.write('<!doctype html><title>Generating report…</title><p>Generating the report…</p>')
    w.document.close()
  }
  return w
}

function closeWindow(w) {
  if (w && !w.closed) w.close()
}

// "Include sections": one checkbox per report section (+ the cover stats strip),
// from the same list the report uses. Everything is included by default.
const DEFAULT_SECTIONS = Object.fromEntries(REPORT_SECTION_OPTIONS.map(o => [o.key, true]))

const TLP_OPTIONS = ['TLP:CLEAR', 'TLP:GREEN', 'TLP:AMBER', 'TLP:AMBER+STRICT', 'TLP:RED']

export default function Reports({ inc }) {
  const [templateId, setTemplateId] = useState('executive')
  const [mode,       setMode]       = useState('full')
  const [logo,       setLogo]       = useState(loadLogo)
  const [footer,     setFooter]     = useState(loadFooter)
  const [loading,    setLoading]    = useState(false)
  const [error,      setError]      = useState(null)
  const [advancedOpen, setAdvancedOpen] = useState(false)
  const [classification,        setClassification]        = useState('')   // '' = inherit incident TLP
  const [audience,              setAudience]              = useState('')
  const [includeInternalEvents,  setIncludeInternalEvents]  = useState(false)
  const [includeTimelineAppendix, setIncludeTimelineAppendix] = useState(false)
  const [sections,               setSections]               = useState(DEFAULT_SECTIONS)
  const toggleSection = (key) => setSections(s => ({ ...s, [key]: !s[key] }))
  const fileRef = useRef(null)
  // E4: figures over the 7 MiB embed cap — the prepared report waits here for Continue / Cancel.
  const [capWarning, setCapWarning] = useState(null)   // { action, overCap, count }
  const pendingRef = useRef(null)

  const [history,        setHistory]        = useState([])
  const [historyLoading, setHistoryLoading] = useState(true)
  const [downloadTarget, setDownloadTarget] = useState(null)   // history row to download
  const [accessReason,   setAccessReason]   = useState('')
  const [downloading,    setDownloading]    = useState(false)

  const loadHistory = useCallback(async () => {
    setHistoryLoading(true)
    try {
      const items = await api.listReportHistory(inc.id)
      setHistory(items || [])
    } catch {
      setHistory([])
    } finally {
      setHistoryLoading(false)
    }
  }, [inc.id])

  useEffect(() => { loadHistory() }, [loadHistory])

  async function confirmDownload() {
    const row = downloadTarget
    if (!row || !accessReason.trim()) return
    setDownloading(true)
    setError(null)
    try {
      const resp = await fetch(api.downloadSavedReportUrl(inc.id, row.id), {
        method:      'POST',
        credentials: 'same-origin',
        headers:     { 'Content-Type': 'application/json' },
        body:        JSON.stringify({ access_reason: accessReason.trim() }),
      })
      if (!resp.ok) {
        const err = await resp.json().catch(() => ({}))
        throw new Error(err.detail || `HTTP ${resp.status}`)
      }
      const headerSha = resp.headers.get('X-Report-SHA256') || ''
      const blob = await resp.blob()

      // Optional client-side integrity check — flag a tampered transport.
      try {
        const buf = await blob.arrayBuffer()
        const digest = await crypto.subtle.digest('SHA-256', buf)
        const got = Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, '0')).join('')
        if (headerSha && got !== headerSha) {
          setError(`SHA-256 mismatch — expected ${headerSha.slice(0,12)}…, got ${got.slice(0,12)}…`)
          return
        }
      } catch { /* SubtleCrypto unavailable — skip verify, server already audited */ }

      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `fenrir-report-${row.report_type}-${row.id.slice(0,8)}.html`
      document.body.appendChild(a); a.click(); document.body.removeChild(a)
      URL.revokeObjectURL(url)
      setDownloadTarget(null)
      setAccessReason('')
      loadHistory()
    } catch (e) {
      setError(e.message || 'Download failed.')
    } finally {
      setDownloading(false)
    }
  }

  function handleLogoFile(e) {
    const file = e.target.files?.[0]
    if (!file) return
    const reader = new FileReader()
    reader.onload = ev => {
      const url = ev.target.result
      setLogo(url)
      try { localStorage.setItem(LS_LOGO, url) } catch { /* quota */ }
    }
    reader.readAsDataURL(file)
  }

  function clearLogo() {
    setLogo(null)
    try { localStorage.removeItem(LS_LOGO) } catch { /* ok */ }
    if (fileRef.current) fileRef.current.value = ''
  }

  function handleFooter(val) {
    setFooter(val)
    try { localStorage.setItem(LS_FOOTER, val) } catch { /* quota */ }
  }

  function showStructure() {
    setError(null)
    const html = generateSkeleton({
      mode, footer,
      classification, audience,
      includeInternalEvents,
      includeTimelineAppendix,
      sections,
    })
    const w = window.open('', '_blank')
    if (!w) { setError('Pop-up blocked — please allow pop-ups for this site.'); return }
    w.document.write(html)
    w.document.close()
  }

  async function generate(action) {
    const win = action === 'preview' ? openPreviewWindow() : null   // synchronously, in the click
    setLoading(true)
    setError(null)
    setCapWarning(null)
    pendingRef.current = null
    try {
      const data = await api.getReportData(inc.id)
      // Figures: fetched, hashed and embedded only when the section is ticked.
      let figures = []
      const picked = data.report_files || []
      if (sections.attachments !== false && picked.length) {
        const prep = await prepareFigures(inc.id, picked)
        figures = prep.figures
        if (prep.overCap) {
          // Warn before anything is shown or saved; Continue is a fresh click that opens
          // its own preview tab, so this one is closed (the warning is in this tab).
          closeWindow(win)
          pendingRef.current = { data, figures }
          setCapWarning({ action, overCap: prep.overCap, count: picked.length })
          return
        }
      }
      await renderAndSave(action, data, figures, win)
    } catch (e) {
      closeWindow(win)
      setError(e.message || 'Failed to generate report')
    } finally {
      setLoading(false)
    }
  }

  async function continueOverCap() {
    const pending = pendingRef.current
    const action = capWarning?.action
    pendingRef.current = null
    setCapWarning(null)
    if (!pending) return
    const win = action === 'preview' ? openPreviewWindow() : null   // synchronously, in the click
    setLoading(true)
    setError(null)
    try {
      await renderAndSave(action, pending.data, pending.figures, win)
    } catch (e) {
      closeWindow(win)
      setError(e.message || 'Failed to generate report')
    } finally {
      setLoading(false)
    }
  }

  async function renderAndSave(action, data, figures, win) {
    const rawHtml = generateReport(data, {
      templateId, mode, logo, footer,
      classification, audience,
      includeInternalEvents,
      includeTimelineAppendix,
      sections,
      figures,
    })
    // Self-describing SHA-256: the placeholder in the footer is replaced
    // with the SHA-256 of the document while the placeholder was still in
    // place. Verifiers reverse the substitution to confirm integrity.
    const html = await injectReportSha256(rawHtml)
    const problems = []
    if (action === 'preview') {
      if (win && !win.closed) {
        win.document.open()
        win.document.write(html)
        win.document.close()
      } else {
        problems.push('Pop-up blocked: allow pop-ups for this site to preview the report.')
      }
    } else {
      const blob = new Blob([html], { type: 'text/html;charset=utf-8' })
      const url  = URL.createObjectURL(blob)
      const a    = document.createElement('a')
      const slug = inc.title.slice(0, 30).replace(/[^a-zA-Z0-9]/g, '-').replace(/-+/g, '-')
      a.href     = url
      a.download = `fenrir-report-${mode}-${slug}.html`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)
    }

    // Persist to history for audit-grade re-download with SHA-256 integrity — also when the
    // preview pop-up was blocked. The preview/download above has already happened, so a failed
    // save is reported, not thrown. The whole JSON body must fit the 10 MiB request limit.
    const payload = {
      report_type:    mode === 'executive' ? 'exec' : 'full',
      template_id:    templateId,
      classification: classification || `TLP:${(inc.tlp || 'AMBER').toUpperCase()}`,
      audience:       audience || null,
      footer_text:    footer || null,
      html,
    }
    const bytes = new Blob([JSON.stringify(payload)]).size
    if (bytes > SAVE_MAX_BYTES) {
      problems.push(`Not saved to report history: the report is ${fmtBytes(bytes)}, over the ${fmtBytes(SAVE_MAX_BYTES)} `
        + 'save limit. Untick some figures in Supporting documents (or the Figures section) and generate it again.')
    } else {
      try {
        await api.saveReport(inc.id, payload)
        loadHistory()
        if (problems.length) problems.push('The report was saved to Report history below.')
      } catch (e) {
        problems.push(`Not saved to report history: ${e?.message || 'the save failed'}.`)
      }
    }
    if (problems.length) setError(problems.join(' '))
  }

  return (
    <div style={{ maxWidth: 960 }}>

      {/* Lessons Learned & Remediation Plan: read-only, edited on Lessons Learned (J3) */}
      <PISection title="Lessons Learned & Remediation Plan">
        <LessonsAndRemediationSummary inc={inc} />
      </PISection>

      {/* Template picker */}
      <div style={{ marginBottom: 'var(--space-4)' }}>
        <div style={{ fontSize: 12, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--muted)', marginBottom: 'var(--space-2)' }}>
          Report Layout
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill,minmax(170px,1fr))', gap: 'var(--space-2)' }}>
          {TEMPLATE_META.map(t => (
            <button
              key={t.id}
              type="button"
              onClick={() => setTemplateId(t.id)}
              style={{
                textAlign: 'left',
                padding: 'var(--space-3)',
                borderRadius: 'var(--radius)',
                border: templateId === t.id
                  ? '2px solid var(--accent)'
                  : '2px solid var(--border)',
                background: templateId === t.id ? 'var(--surface-2)' : 'var(--surface)',
                cursor: 'pointer',
                transition: 'border-color .15s',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', marginBottom: 'var(--space-1)' }}>
                <div style={{ width: 12, height: 12, borderRadius: 3, background: SWATCH[t.id], flexShrink: 0 }} />
                <span style={{ fontWeight: 600, fontSize: 13 }}>{t.name}</span>
              </div>
              <span style={{ fontSize: 11, color: 'var(--muted)', lineHeight: 1.4, display: 'block' }}>{t.desc}</span>
            </button>
          ))}
        </div>
      </div>

      {/* Mode + branding in a row */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--space-4)', marginBottom: 'var(--space-4)' }}>

        {/* Mode */}
        <div>
          <div style={{ fontSize: 12, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--muted)', marginBottom: 'var(--space-2)' }}>
            Report Type
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-2)' }}>
            {[
              { value: 'executive', label: 'Executive Summary', desc: 'Key facts, KPIs, MITRE tactics, lessons & recommendations. No raw IOC values or full timeline.' },
              { value: 'full',      label: 'Full Technical Report', desc: 'All sections: complete IOC table, timeline, entities, respond actions, playbook, evidence.' },
            ].map(opt => (
              <label
                key={opt.value}
                style={{
                  display: 'flex',
                  alignItems: 'flex-start',
                  gap: 'var(--space-2)',
                  padding: 'var(--space-2) var(--space-3)',
                  borderRadius: 'var(--radius)',
                  border: mode === opt.value ? '1px solid var(--accent)' : '1px solid var(--border)',
                  background: mode === opt.value ? 'var(--surface-2)' : 'var(--surface)',
                  cursor: 'pointer',
                }}
              >
                <input
                  type="radio"
                  name="report-mode"
                  value={opt.value}
                  checked={mode === opt.value}
                  onChange={() => setMode(opt.value)}
                  style={{ marginTop: 3, flexShrink: 0 }}
                />
                <div>
                  <div style={{ fontWeight: 600, fontSize: 13 }}>{opt.label}</div>
                  <div style={{ fontSize: 11, color: 'var(--muted)', marginTop: 2, lineHeight: 1.4 }}>{opt.desc}</div>
                </div>
              </label>
            ))}
          </div>
        </div>

        {/* Branding */}
        <div>
          <div style={{ fontSize: 12, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--muted)', marginBottom: 'var(--space-2)' }}>
            Branding
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
            <div>
              <label className="field-label" style={{ marginBottom: 'var(--space-1)', display: 'block' }}>Company logo</label>
              <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', flexWrap: 'wrap' }}>
                {logo && (
                  <img
                    src={logo}
                    alt="Logo preview"
                    style={{ maxHeight: 36, maxWidth: 120, objectFit: 'contain', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', padding: 4, background: '#fff' }}
                  />
                )}
                <input
                  ref={fileRef}
                  type="file"
                  accept="image/*"
                  style={{ display: 'none' }}
                  onChange={handleLogoFile}
                />
                <button type="button" className="btn ghost" style={{ fontSize: 12 }} onClick={() => fileRef.current?.click()}>
                  {logo ? 'Change logo' : 'Upload logo'}
                </button>
                {logo && (
                  <button type="button" className="btn ghost" style={{ fontSize: 12, color: 'var(--crit)' }} onClick={clearLogo}>
                    Remove
                  </button>
                )}
              </div>
              <div style={{ fontSize: 11, color: 'var(--dim)', marginTop: 4 }}>Saved locally in browser. PNG or SVG recommended.</div>
            </div>

            <div>
              <label className="field-label" htmlFor="report-footer" style={{ marginBottom: 'var(--space-1)', display: 'block' }}>Footer text</label>
              <input
                id="report-footer"
                className="input"
                value={footer}
                onChange={e => handleFooter(e.target.value)}
                placeholder="e.g. Acme Security Operations Centre — Confidential"
                maxLength={256}
                style={{ fontSize: 12 }}
              />
            </div>
          </div>
        </div>
      </div>

      {/* Advanced options — classification, audience, visibility filter, section toggles */}
      <div style={{ marginBottom: 'var(--space-4)' }}>
        <button
          type="button"
          onClick={() => setAdvancedOpen(o => !o)}
          style={{
            background: 'transparent', border: 'none', padding: 0,
            fontSize: 12, fontWeight: 700, textTransform: 'uppercase',
            letterSpacing: '0.08em', color: 'var(--muted)', cursor: 'pointer',
            display: 'flex', alignItems: 'center', gap: 6, marginBottom: 'var(--space-2)',
          }}
        >
          {advancedOpen ? '▼' : '▶'} Advanced options
        </button>

        {advancedOpen && (
          <div style={{
            background: 'var(--surface-2)',
            border: '1px solid var(--border)',
            borderRadius: 'var(--radius)',
            padding: 'var(--space-3)',
            display: 'grid',
            gridTemplateColumns: '1fr 1fr',
            gap: 'var(--space-4)',
          }}>
            {/* Left: classification + audience + visibility */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
              <div>
                <label className="field-label" htmlFor="rpt-class" style={{ marginBottom: 'var(--space-1)', display: 'block' }}>
                  Classification marking
                </label>
                <select
                  id="rpt-class"
                  className="select"
                  value={classification}
                  onChange={e => setClassification(e.target.value)}
                  style={{ width: '100%', fontSize: 12 }}
                >
                  <option value="">— inherit from incident TLP —</option>
                  {TLP_OPTIONS.map(t => <option key={t} value={t}>{t}</option>)}
                </select>
              </div>

              <div>
                <label className="field-label" htmlFor="rpt-aud" style={{ marginBottom: 'var(--space-1)', display: 'block' }}>
                  Audience
                </label>
                <input
                  id="rpt-aud"
                  className="input"
                  value={audience}
                  onChange={e => setAudience(e.target.value)}
                  placeholder="e.g. CISO + Board"
                  maxLength={128}
                  style={{ fontSize: 12 }}
                />
              </div>

              {mode === 'executive' && (
                <label style={{ display: 'flex', alignItems: 'flex-start', gap: 8, fontSize: 12, cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={includeInternalEvents}
                    onChange={e => setIncludeInternalEvents(e.target.checked)}
                    style={{ marginTop: 2, flexShrink: 0 }}
                  />
                  <span>
                    <div>Include internal-only events</div>
                    <div style={{ fontSize: 11, color: 'var(--dim)', marginTop: 2 }}>
                      Default: executive reports only show events flagged <code>external_safe</code>.
                      Override for full disclosure to your audience.
                    </div>
                  </span>
                </label>
              )}
            </div>

            {/* Right: section toggles */}
            <div>
              <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 'var(--space-2)' }}>
                Include sections
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '4px 12px' }}>
                {REPORT_SECTION_OPTIONS.map(o => {
                  const execOnlyFull = mode === 'executive' && o.fullOnly
                  return (
                    <label key={o.key}
                           title={execOnlyFull ? 'Not part of the executive report' : undefined}
                           style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12,
                                    cursor: execOnlyFull ? 'default' : 'pointer', opacity: execOnlyFull ? 0.5 : 1 }}>
                      <input
                        type="checkbox"
                        checked={!!sections[o.key] && !execOnlyFull}
                        disabled={execOnlyFull}
                        onChange={() => toggleSection(o.key)}
                      />
                      <span>{o.title}{execOnlyFull ? ' (full report only)' : ''}</span>
                    </label>
                  )
                })}
              </div>
              <button
                type="button"
                onClick={() => setSections(DEFAULT_SECTIONS)}
                style={{
                  marginTop: 'var(--space-2)',
                  background: 'transparent', border: 'none', padding: 0,
                  fontSize: 11, color: 'var(--accent)', cursor: 'pointer',
                }}
              >
                Reset to defaults
              </button>

              <div style={{
                marginTop: 'var(--space-3)',
                paddingTop: 'var(--space-2)',
                borderTop: '1px solid var(--border)',
              }}>
                <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 6 }}>
                  Appendix
                </div>
                <label style={{ display: 'flex', alignItems: 'flex-start', gap: 6, fontSize: 12, cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={includeTimelineAppendix}
                    onChange={e => setIncludeTimelineAppendix(e.target.checked)}
                    style={{ marginTop: 2, flexShrink: 0 }}
                  />
                  <span>
                    <div>Appendix B — Timeline</div>
                    <div style={{ fontSize: 11, color: 'var(--dim)', marginTop: 2 }}>
                      Visual zig-zag spine appended after Appendix A (Affected Systems), for C-tier readers.
                    </div>
                  </span>
                </label>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Error */}
      {error && (
        <div className="alert error report-error" role="alert" style={{ marginBottom: 'var(--space-3)' }}>
          <span className="alert-icon">!</span><span style={{ color: 'var(--text)' }}>{error}</span>
        </div>
      )}

      {/* Figures over the embedded-image cap: warn before anything is shown or saved */}
      {capWarning && (
        <div className="alert warn report-cap-warning" role="alert" style={{ marginBottom: 'var(--space-3)' }}>
          <span className="alert-icon">!</span>
          <div style={{ color: 'var(--text)' }}>
            <div>
              {capWarning.overCap} of {capWarning.count} report figure{capWarning.count !== 1 ? 's' : ''} would
              take the embedded images over the 7 MiB limit (a saved report may be at most 10 MiB).
              {capWarning.overCap === 1 ? ' It' : ' They'} will be listed with caption and SHA-256, without the image.
              Untick some figures in Supporting documents to embed them all.
            </div>
            <div style={{ display: 'flex', gap: 'var(--space-2)', marginTop: 'var(--space-2)', flexWrap: 'wrap' }}>
              <button type="button" className="btn primary" onClick={continueOverCap}>Continue and save</button>
              <button type="button" className="btn ghost" onClick={() => { pendingRef.current = null; setCapWarning(null) }}>Cancel</button>
            </div>
          </div>
        </div>
      )}

      {/* Generate actions */}
      <div style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'center', flexWrap: 'wrap' }}>
        <button
          type="button"
          className="btn primary"
          onClick={() => generate('preview')}
          disabled={loading}
          style={{ fontSize: 14, padding: '8px 20px' }}
        >
          {loading ? 'Building report…' : 'Preview in new tab'}
        </button>
        <button
          type="button"
          className="btn ghost"
          onClick={() => generate('download')}
          disabled={loading}
        >
          Download HTML
        </button>
        <button
          type="button"
          className="btn ghost"
          onClick={showStructure}
          disabled={loading}
          title="Show the report structure with autogen-field placeholders"
        >
          Show structure
        </button>
        <span style={{ fontSize: 11, color: 'var(--dim)', marginLeft: 'var(--space-1)' }}>
          Self-contained HTML — open in browser and print / save as PDF
        </span>
      </div>
      <div style={{ fontSize: 12, color: 'var(--muted)', marginTop: 'var(--space-2)' }}>
        Figures: tick <strong>Include in report</strong> on screenshots in Supporting documents. They are embedded with
        their SHA-256 (images over 1.5 MB downscaled to 1920 px), up to 7 MiB in total.
      </div>

      {/* Tip */}
      <div style={{ marginTop: 'var(--space-4)', padding: 'var(--space-3)', background: 'var(--surface-2)', borderRadius: 'var(--radius)', fontSize: 12, color: 'var(--muted)', lineHeight: 1.6 }}>
        <strong style={{ color: 'var(--text)' }}>To save as PDF:</strong> Open the preview, then press{' '}
        <kbd style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 3, padding: '1px 5px', fontFamily: 'var(--font-mono)', fontSize: 11 }}>Ctrl+P</kbd>{' '}
        (Windows/Linux) or{' '}
        <kbd style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 3, padding: '1px 5px', fontFamily: 'var(--font-mono)', fontSize: 11 }}>⌘+P</kbd>{' '}
        (macOS), choose "Save as PDF" as the destination, and set margins to "None" or "Minimum" for best results.
      </div>

      {/* Report history — audit-grade re-download with SHA-256 + access reason */}
      <PISection title="Report History">
        <div style={{ fontSize: 12, color: 'var(--muted)', marginBottom: 'var(--space-2)' }}>
          Every generated report is persisted with a SHA-256 integrity hash.
          Re-downloads require an audit-logged access reason.
        </div>
        {historyLoading ? (
          <div style={{ color: 'var(--muted)', fontSize: 12 }}>Loading…</div>
        ) : history.length === 0 ? (
          <div style={{ color: 'var(--dim)', fontSize: 12, fontStyle: 'italic' }}>
            No reports generated for this incident yet.
          </div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table className="settings-table" style={{ fontSize: 12 }}>
              <thead>
                <tr>
                  <th>Type</th>
                  <th>Layout</th>
                  <th>Classification</th>
                  <th>Generated</th>
                  <th>SHA-256</th>
                  <th>Size</th>
                  <th>Accesses</th>
                  <th style={{ textAlign: 'right' }}></th>
                </tr>
              </thead>
              <tbody>
                {history.map(r => (
                  <tr key={r.id}>
                    <td>
                      <span className="pill" style={{ fontSize: 10 }}>
                        {r.report_type === 'exec' ? 'Executive' : 'Full'}
                      </span>
                    </td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--muted)' }}>
                      {r.template_id}
                    </td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>
                      {r.classification}
                      {r.audience && <div style={{ color: 'var(--dim)', fontSize: 10 }}>{r.audience}</div>}
                    </td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--muted)', whiteSpace: 'nowrap' }}>
                      {new Date(r.generated_at).toISOString().replace('T', ' ').slice(0, 19) + 'Z'}
                    </td>
                    <td>
                      <button
                        type="button"
                        className="btn ghost"
                        title={`Click to copy:\n${r.sha256}`}
                        onClick={() => navigator.clipboard?.writeText(r.sha256)}
                        style={{ padding: '1px 6px', fontFamily: 'var(--font-mono)', fontSize: 10 }}
                      >{r.sha256.slice(0, 12)}…</button>
                    </td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--muted)' }}>
                      {fmtBytes(r.file_size)}
                    </td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--muted)', textAlign: 'right' }}>
                      {r.access_count}
                    </td>
                    <td style={{ textAlign: 'right' }}>
                      <button
                        type="button"
                        className="btn ghost"
                        style={{ fontSize: 11 }}
                        onClick={() => { setDownloadTarget(r); setAccessReason('') }}
                      >↓ Download</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </PISection>

      {/* Re-download modal — captures mandatory access reason */}
      {downloadTarget && (
        <div className="modal-backdrop" onClick={() => !downloading && setDownloadTarget(null)}>
          <div className="modal" style={{ maxWidth: 480 }} onClick={e => e.stopPropagation()}>
            <div className="modal-head">
              <h2>Download report</h2>
              <button
                type="button"
                className="modal-close"
                onClick={() => setDownloadTarget(null)}
                disabled={downloading}
                aria-label="Close"
              >×</button>
            </div>
            <div className="modal-body">
              <div style={{ fontSize: 12, color: 'var(--muted)', marginBottom: 'var(--space-3)' }}>
                Provide a reason for accessing this report. The reason is
                audit-logged alongside your username and IP.
              </div>
              <div style={{
                fontSize: 11, color: 'var(--dim)', fontFamily: 'var(--font-mono)',
                background: 'var(--surface-2)', padding: 'var(--space-2)',
                borderRadius: 'var(--radius-sm)', marginBottom: 'var(--space-3)',
                wordBreak: 'break-all',
              }}>
                {downloadTarget.report_type === 'exec' ? 'Executive Summary' : 'Full Report'}
                {' · '}
                {downloadTarget.classification}
                {' · '}
                SHA-256: {downloadTarget.sha256.slice(0, 24)}…
              </div>
              <div className="field">
                <label className="field-label" htmlFor="rpt-reason">Access reason *</label>
                <textarea
                  id="rpt-reason"
                  className="input"
                  rows={3}
                  value={accessReason}
                  onChange={e => setAccessReason(e.target.value)}
                  placeholder="e.g. Preparing executive briefing for CISO meeting"
                  autoFocus
                />
              </div>
            </div>
            <div className="modal-foot">
              <button
                type="button"
                className="btn ghost"
                onClick={() => setDownloadTarget(null)}
                disabled={downloading}
              >Cancel</button>
              <button
                type="button"
                className="btn primary"
                onClick={confirmDownload}
                disabled={downloading || !accessReason.trim()}
              >{downloading ? 'Downloading…' : '↓ Download'}</button>
            </div>
          </div>
        </div>
      )}

      <LePackage inc={inc} />
    </div>
  )
}

function fmtBytes(n) {
  if (n == null) return '—'
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`
  return `${(n / (1024 * 1024)).toFixed(2)} MiB`
}
