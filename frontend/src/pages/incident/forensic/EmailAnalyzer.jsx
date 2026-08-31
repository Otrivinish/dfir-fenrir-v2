import { useEffect, useState } from 'react'
import { useOutletContext } from 'react-router-dom'
import { api } from '../../../api/client.js'
import { formatLocal } from '../../../lib/datetime.js'

// U8.1 — Email analyzer (phishing triage). One input control: paste raw headers, pick a
// single .eml/.msg, pick several, or a single .zip of them (multi/zip silently routes to
// the batch endpoint) → verdict + findings, a message summary (subject/sender/recipient/
// source IP), a sanitized+sandboxed email preview, full raw headers, hop chain,
// Safelink-unwrapped URLs (→ IOC), attachments (→ quarantine Artifact), and "mint as
// Evidence". Parsing itself never hits the network; SPF/DMARC/DKIM are additionally
// cross-checked against a live DNS lookup so the header's own claim isn't trusted blindly
// (queries go to the claimed sender domain, same as any receiving mail server would do —
// never to a URL/host found inside the message).

const VERDICT_COLOR = { red: 'var(--crit)', amber: 'var(--med)', green: 'var(--ok)' }
const SEV_COLOR     = { high: 'var(--crit)', medium: 'var(--med)', low: 'var(--muted)' }

export default function EmailAnalyzer() {
  const { inc } = useOutletContext()
  const incidentId = inc.id

  const [raw, setRaw]         = useState('')
  const [files, setFiles]     = useState([])   // one file, many files, or a single .zip -- one control
  const [busy, setBusy]       = useState(false)
  const [error, setError]     = useState(null)
  const [analysis, setAnalysis] = useState(null)
  const [history, setHistory] = useState([])
  const [pickedUrls, setPickedUrls] = useState({})   // url -> bool
  const [note, setNote]       = useState(null)
  const [showHtmlPreview, setShowHtmlPreview] = useState(false)

  const [batchResult, setBatchResult] = useState(null)
  const [batchFilter, setBatchFilter] = useState(null)

  const loadHistory = () => api.listEmailAnalyses(incidentId).then(r => setHistory(r.items || [])).catch(() => {})
  useEffect(() => { loadHistory() }, [incidentId])

  // Multiple files, or a single .zip, go through the batch endpoint; a lone
  // .eml/.msg (or pasted text) goes through the single endpoint -- one input
  // control, the choice of endpoint is just plumbing the analyst never sees.
  const isBatchUpload = !raw.trim() && (files.length > 1 || (files.length === 1 && files[0].name.toLowerCase().endsWith('.zip')))

  // Default to the rendered view whenever a *different* email is loaded (a
  // real preview, not a raw-text dump) -- an action on the SAME email
  // (act(), below) must not fight the analyst's own toggle.
  useEffect(() => { setShowHtmlPreview(!!analysis?.body_html) }, [analysis?.id])

  async function run() {
    if (!raw.trim() && files.length === 0) { setError('Paste raw headers or choose one or more .eml/.msg files (or a .zip).'); return }
    setBusy(true); setError(null); setNote(null); setBatchResult(null)
    try {
      if (isBatchUpload) {
        const r = await api.analyzeEmailBulk(incidentId, files)
        setBatchResult(r); setBatchFilter(r.batch_id)
        if (r.analyzed.length) { setAnalysis(r.analyzed[r.analyzed.length - 1]); setPickedUrls({}) }
      } else {
        const a = await api.analyzeEmail(incidentId, { raw: raw.trim() || null, file: files[0] || null })
        setAnalysis(a); setPickedUrls({})
      }
      setRaw(''); setFiles([])
      loadHistory()
    } catch (e) { setError(e.message || 'Analyze failed') }
    finally { setBusy(false) }
  }

  async function open(aid) {
    setBusy(true); setError(null); setNote(null)
    try { setAnalysis(await api.getEmailAnalysis(incidentId, aid)); setPickedUrls({}) }
    catch (e) { setError(e.message) } finally { setBusy(false) }
  }

  async function act(fn, msg) {
    setBusy(true); setError(null); setNote(null)
    try { const a = await fn(); setAnalysis(a); setNote(msg); loadHistory() }
    catch (e) { setError(e.message || 'Action failed') } finally { setBusy(false) }
  }

  function urlIocPayload() {
    const out = []
    for (const u of analysis.urls || []) {
      if (!pickedUrls[u.url]) continue
      // Promote the real destination when it's a Safelink wrapper -- the
      // safelinks.protection.outlook.com host itself isn't a useful indicator.
      out.push({ type: 'url', value: u.safelink_target || u.url })
      if (u.safelink_host || u.host) out.push({ type: 'domain', value: u.safelink_host || u.host })
    }
    const oip = analysis.headers?.origin_ip
    if (oip && pickedUrls.__origin__) out.push({ type: 'ip', value: oip })
    return out
  }

  const a = analysis
  const auth = a?.headers?.auth || {}
  const hops = a?.headers?.hops || []
  const av = a?.auth_verified || null

  return (
    <div className="stack" style={{ gap: 'var(--space-4)' }}>
      <div className="panel" style={{ padding: 'var(--space-3)' }}>
        <h3 className="panel-h">Email analyzer <span style={{ fontWeight: 400, color: 'var(--muted)', fontSize: 12 }}>· phishing triage</span></h3>
        <p style={{ fontSize: 12, color: 'var(--muted)', marginTop: 0 }}>
          Paste raw headers/source, or choose one or more <code>.eml</code>/<code>.msg</code> files — or a single{' '}
          <code>.zip</code> of them to analyze as a batch. Parsing, header inspection, and Safelink decoding all
          happen locally — no URL from the message is ever fetched and no attachment is executed. SPF/DMARC/DKIM
          are additionally checked live against the claimed sender domain's own DNS.
        </p>
        <textarea className="input" rows={6} value={raw} onChange={e => setRaw(e.target.value)}
                  placeholder="Paste raw email headers or full source here…"
                  style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }} disabled={busy || files.length > 0} />
        <div style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'center', marginTop: 'var(--space-2)', flexWrap: 'wrap' }}>
          <input type="file" multiple accept=".eml,.msg,.zip,message/rfc822,application/vnd.ms-outlook,application/zip,text/plain"
                 disabled={busy || !!raw.trim()} onChange={e => setFiles(Array.from(e.target.files || []))} />
          <button className="btn primary" onClick={run} disabled={busy || (!raw.trim() && files.length === 0)}>
            {busy ? 'Analyzing…' : (isBatchUpload ? `Analyze (${files.length})` : 'Analyze')}
          </button>
        </div>
        {error && <div className="alert error" role="alert" style={{ marginTop: 'var(--space-2)' }}><span className="alert-icon">!</span><span>{error}</span></div>}
        {note  && <div className="alert info"  role="status" style={{ marginTop: 'var(--space-2)' }}><span className="alert-icon">✓</span><span>{note}</span></div>}
        {batchResult && (
          <div style={{ marginTop: 'var(--space-2)', fontSize: 12 }}>
            <div>
              Batch complete: <strong>{batchResult.analyzed.length}</strong> analyzed
              {batchResult.skipped.length > 0 && <>, <strong>{batchResult.skipped.length}</strong> skipped</>}
              {batchResult.errors.length > 0 && <>, <strong style={{ color: 'var(--crit)' }}>{batchResult.errors.length}</strong> errors</>}.
              {' '}<button className="btn ghost" style={{ fontSize: 11, padding: '2px 8px' }} onClick={() => setBatchFilter(batchResult.batch_id)}>Filter history to this batch</button>
              {batchFilter && <button className="btn ghost" style={{ fontSize: 11, padding: '2px 8px' }} onClick={() => setBatchFilter(null)}>Clear filter</button>}
            </div>
            {(batchResult.skipped.length > 0 || batchResult.errors.length > 0) && (
              <details style={{ marginTop: 4 }}>
                <summary style={{ cursor: 'pointer', color: 'var(--accent)' }}>Skipped / error details</summary>
                {batchResult.skipped.map((s, i) => <div key={`s${i}`} style={{ color: 'var(--muted)' }}>{s}</div>)}
                {batchResult.errors.map((s, i) => <div key={`e${i}`} style={{ color: 'var(--crit)' }}>{s}</div>)}
              </details>
            )}
          </div>
        )}
      </div>

      {a && (
        <div className="panel" style={{ padding: 'var(--space-3)' }}>
          {/* Verdict banner */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)', flexWrap: 'wrap' }}>
            <span style={{ background: VERDICT_COLOR[a.verdict], color: '#000', fontWeight: 700,
                           padding: '4px 12px', borderRadius: 'var(--radius)', textTransform: 'uppercase' }}>
              {a.verdict} · {a.score}
            </span>
            <div style={{ minWidth: 0 }}>
              <div style={{ fontWeight: 600 }}>{a.subject || '(no subject)'}</div>
              <div style={{ fontSize: 12, color: 'var(--muted)', fontFamily: 'var(--font-mono)' }}>
                {a.from_display ? `${a.from_display} ` : ''}&lt;{a.from_addr || '?'}&gt;
              </div>
            </div>
            <div style={{ marginLeft: 'auto', display: 'flex', gap: 'var(--space-2)', flexWrap: 'wrap' }}>
              <button className="btn ghost" disabled={busy || !hops.length}
                      onClick={() => act(() => api.importEmailHops(incidentId, a.id), 'Hops imported to Timeline.')}>Import hops → Timeline</button>
              <button className="btn ghost" disabled={busy || !!a.evidence_id}
                      onClick={() => act(() => api.mintEmailEvidence(incidentId, a.id), 'Minted as Evidence.')}>
                {a.evidence_id ? 'Evidence minted ✓' : 'Mint as Evidence'}</button>
            </div>
          </div>

          {/* Message summary — the fields analysts hunt for first, all in one place */}
          <div style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', columnGap: 'var(--space-3)', rowGap: 4,
                        fontSize: 12, marginTop: 'var(--space-3)', maxWidth: 640 }}>
            <div style={{ color: 'var(--muted)' }}>Subject</div>
            <div>{a.subject || '(no subject)'}</div>
            <div style={{ color: 'var(--muted)' }}>Sender</div>
            <div style={{ fontFamily: 'var(--font-mono)' }}>{a.from_display ? `${a.from_display} ` : ''}&lt;{a.from_addr || '?'}&gt;</div>
            <div style={{ color: 'var(--muted)' }}>Recipient</div>
            <div style={{ fontFamily: 'var(--font-mono)' }}>{a.headers?.notable?.To || '—'}</div>
            <div style={{ color: 'var(--muted)' }}>Date</div>
            <div>{a.date_hdr || '—'}</div>
            <div style={{ color: 'var(--muted)' }}>Source IP</div>
            <div style={{ fontFamily: 'var(--font-mono)' }}>{a.headers?.origin_ip || '—'}</div>
          </div>

          {/* Email preview — sanitized + rendered inside a fully sandboxed, offline iframe */}
          {(a.body_text || a.body_html) && (
            <>
              <h4 className="panel-h" style={{ marginTop: 'var(--space-4)', display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
                Email preview
                {a.body_html && (
                  <button className="btn ghost" style={{ fontSize: 11, padding: '2px 8px', fontWeight: 400 }}
                          onClick={() => setShowHtmlPreview(v => !v)}>
                    {showHtmlPreview ? 'Show plain text' : 'Show sanitized HTML'}
                  </button>
                )}
              </h4>
              {showHtmlPreview && a.body_html ? (
                <>
                  <p style={{ fontSize: 11, color: 'var(--dim)', marginTop: 0 }}>
                    Sanitized (scripts/styles/on-handlers/remote images all stripped server-side) and rendered in a
                    fully sandboxed iframe — nothing here can execute or phone home. Inline images embedded in the
                    message itself may still appear; nothing is ever fetched from a remote host.
                  </p>
                  <iframe
                    title="Email preview (sanitized, offline)"
                    sandbox=""
                    srcDoc={buildPreviewDoc(a.body_html)}
                    style={{ width: '100%', height: 420, border: '1px solid var(--border)', borderRadius: 'var(--radius)', background: '#fff' }}
                  />
                </>
              ) : (
                <pre style={{ fontFamily: 'var(--font-mono)', fontSize: 12, whiteSpace: 'pre-wrap', wordBreak: 'break-word',
                              border: '1px solid var(--border)', borderRadius: 'var(--radius)', padding: 'var(--space-2)',
                              maxHeight: 420, overflow: 'auto' }}>
                  {a.body_text || '(no plain-text body found — try the sanitized HTML view)'}
                </pre>
              )}
            </>
          )}

          {/* Full raw headers */}
          {a.raw_headers && (
            <details style={{ marginTop: 'var(--space-3)' }}>
              <summary style={{ cursor: 'pointer', color: 'var(--accent)', fontSize: 12 }}>Full raw headers</summary>
              <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 4 }}>
                <button className="btn ghost" style={{ fontSize: 11, padding: '2px 8px' }}
                        onClick={() => navigator.clipboard?.writeText(a.raw_headers)}>Copy</button>
              </div>
              <pre style={{ fontFamily: 'var(--font-mono)', fontSize: 11, whiteSpace: 'pre-wrap', wordBreak: 'break-all',
                            background: 'var(--bg-alt, transparent)', border: '1px solid var(--border)',
                            borderRadius: 'var(--radius)', padding: 'var(--space-2)', maxHeight: 400, overflow: 'auto' }}>
                {a.raw_headers}
              </pre>
            </details>
          )}

          {/* Findings */}
          <h4 className="panel-h" style={{ marginTop: 'var(--space-4)' }}>Findings ({(a.findings || []).length})</h4>
          {(a.findings || []).length === 0
            ? <div style={{ color: 'var(--muted)', fontSize: 13 }}>No risk signals fired.</div>
            : (a.findings || []).map((f, i) => (
              <div key={i} style={{ display: 'flex', gap: 'var(--space-2)', padding: '4px 0', borderBottom: '1px solid var(--border)' }}>
                <span style={{ color: SEV_COLOR[f.severity] || 'var(--muted)', fontWeight: 700, fontSize: 11, minWidth: 56 }}>{f.severity}</span>
                <span style={{ fontSize: 12, color: 'var(--dim)', minWidth: 72 }}>{f.layer}</span>
                <span style={{ fontSize: 13 }}><strong>{f.title}.</strong> {f.detail}</span>
              </div>
            ))}

          {/* Auth alignment */}
          <h4 className="panel-h" style={{ marginTop: 'var(--space-4)' }}>Authentication <span style={{ fontWeight: 400, color: 'var(--muted)', fontSize: 12 }}>· header claim vs. live DNS</span></h4>
          <table className="table" style={{ fontSize: 12, maxWidth: 520 }}>
            <thead><tr><th>Check</th><th>Header claims</th><th>Live DNS</th><th>Domain</th></tr></thead>
            <tbody>
              <tr>
                <td>SPF</td>
                <td><AuthBadge value={auth.spf} /></td>
                <td><LiveSpfBadge av={av} /></td>
                <td style={{ fontFamily: 'var(--font-mono)' }}>{auth.spf_domain || av?.domain || '—'}</td>
              </tr>
              <tr>
                <td>DKIM</td>
                <td><AuthBadge value={auth.dkim} /></td>
                <td><LiveDkimBadge av={av} /></td>
                <td style={{ fontFamily: 'var(--font-mono)' }}>{auth.dkim_domain || '—'}</td>
              </tr>
              <tr>
                <td>DMARC</td>
                <td><AuthBadge value={auth.dmarc} /></td>
                <td><LiveDmarcBadge av={av} /></td>
                <td>—</td>
              </tr>
            </tbody>
          </table>
          {av?.error && <div style={{ fontSize: 11, color: 'var(--dim)', marginTop: 4 }}>Live validation unavailable: {av.error}</div>}

          {/* Hop chain */}
          <h4 className="panel-h" style={{ marginTop: 'var(--space-4)' }}>Received chain ({hops.length})</h4>
          {a.headers?.origin_ip && (
            <div style={{ fontSize: 12, marginBottom: 4 }}>
              Source IP (connecting client): <strong style={{ fontFamily: 'var(--font-mono)' }}>{a.headers.origin_ip}</strong>
              {av && !av.error && (
                av.ip_in_spf === true
                  ? <span style={{ color: 'var(--ok)', marginLeft: 8 }}>✓ authorized by {av.domain}'s live SPF record</span>
                  : av.ip_in_spf === false
                    ? <span style={{ color: 'var(--crit)', marginLeft: 8 }}>⚠ not authorized by {av.domain}'s live SPF record</span>
                    : <span style={{ color: 'var(--muted)', marginLeft: 8 }}>— SPF authorization unknown (record uses a/mx/other mechanisms not evaluated)</span>
              )}
            </div>
          )}
          {hops.length > 0 && (
            <table className="table" style={{ fontSize: 12, fontFamily: 'var(--font-mono)' }}>
              <thead><tr><th>#</th><th>From</th><th>By</th><th>IP</th><th>Timestamp</th><th>Delay</th></tr></thead>
              <tbody>
                {hops.map((h, i) => {
                  const suspicious = h.delay_seconds != null && h.delay_seconds < -60
                  return (
                    <tr key={i} style={{ color: suspicious ? 'var(--crit)' : 'inherit' }}>
                      <td>{i + 1}</td>
                      <td>{h.from || '?'}</td>
                      <td>{h.by || '?'}</td>
                      <td>{h.ip || '—'}</td>
                      <td>{h.timestamp || '—'}</td>
                      <td>{h.delay_seconds != null ? `${h.delay_seconds >= 0 ? '+' : ''}${Math.round(h.delay_seconds)}s${suspicious ? ' ⚠' : ''}` : '—'}</td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          )}

          <DomainAuthCheck
            incidentId={incidentId}
            defaultDomain={av?.domain || (auth.spf_domain || auth.dkim_domain || '').split('@').pop()}
            defaultSelector={auth.dkim_selector || ''}
          />

          {/* URLs */}
          <h4 className="panel-h" style={{ marginTop: 'var(--space-4)' }}>URLs ({(a.urls || []).length})</h4>
          {(a.urls || []).length > 0 && (
            <>
              <table className="table" style={{ fontSize: 12 }}>
                <thead><tr><th></th><th>Defanged URL</th><th>Host</th><th>Link text</th></tr></thead>
                <tbody>
                  {a.urls.map((u, i) => {
                    const realHost = u.safelink_host || u.host
                    return (
                      <tr key={i}>
                        <td><input type="checkbox" checked={!!pickedUrls[u.url]}
                                   onChange={e => setPickedUrls(p => ({ ...p, [u.url]: e.target.checked }))} /></td>
                        <td style={{ fontFamily: 'var(--font-mono)', wordBreak: 'break-all' }}>
                          {u.defanged}
                          {u.safelink_target && (
                            <div style={{ color: 'var(--med)', marginTop: 2 }}>
                              Safelink → <span style={{ color: 'inherit' }}>{u.safelink_target.replace(/^http/i, 'hxxp').replace(/\./g, '[.]')}</span>
                            </div>
                          )}
                        </td>
                        <td>{realHost || '—'}{u.display_host && u.display_host !== realHost ? <span style={{ color: 'var(--crit)' }}> ≠ {u.display_host}</span> : ''}</td>
                        <td style={{ color: 'var(--muted)' }}>{u.display_text || ''}</td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
              <label style={{ fontSize: 12, display: 'block', marginTop: 4 }}>
                <input type="checkbox" checked={!!pickedUrls.__origin__}
                       onChange={e => setPickedUrls(p => ({ ...p, __origin__: e.target.checked }))} disabled={!a.headers?.origin_ip} />
                {' '}also promote originating IP{a.headers?.origin_ip ? ` (${a.headers.origin_ip})` : ''}
              </label>
              <button className="btn" style={{ marginTop: 'var(--space-2)' }} disabled={busy}
                      onClick={() => act(() => api.promoteEmailIocs(incidentId, a.id, urlIocPayload()), 'Selected indicators promoted to IOCs.')}>
                Promote selected → IOC
              </button>
            </>
          )}

          {/* Attachments */}
          <h4 className="panel-h" style={{ marginTop: 'var(--space-4)' }}>Attachments ({(a.attachments || []).length})</h4>
          {(a.attachments || []).length > 0 && (
            <table className="table" style={{ fontSize: 12 }}>
              <thead><tr><th>Filename</th><th>Declared</th><th>True type</th><th>Size</th><th>SHA-256</th><th></th></tr></thead>
              <tbody>
                {a.attachments.map((at, i) => {
                  const mismatch = at.declared_type && at.true_type && at.declared_type !== at.true_type
                  return (
                    <tr key={i}>
                      <td>{at.filename}</td>
                      <td>{at.declared_type}</td>
                      <td style={{ color: mismatch ? 'var(--crit)' : 'inherit' }}>{at.true_type}</td>
                      <td>{at.size}</td>
                      <td style={{ fontFamily: 'var(--font-mono)' }}>{(at.sha256 || '').slice(0, 12)}…</td>
                      <td>{at.artifact_id
                        ? <span style={{ color: 'var(--ok)' }}>extracted ✓</span>
                        : <button className="btn ghost" disabled={busy}
                                  onClick={() => act(() => api.extractEmailAttachment(incidentId, a.id, i), 'Attachment extracted to quarantine Artifact.')}>Extract → Artifact</button>}</td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          )}
        </div>
      )}

      {/* History */}
      {history.length > 0 && (
        <div className="panel" style={{ padding: 'var(--space-3)' }}>
          <h4 className="panel-h" style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
            Previous analyses
            {batchFilter && (
              <span style={{ fontWeight: 400, fontSize: 12, color: 'var(--muted)' }}>
                · filtered to batch {batchFilter.slice(0, 8)}
                <button className="btn ghost" style={{ fontSize: 11, padding: '1px 6px', marginLeft: 6 }} onClick={() => setBatchFilter(null)}>clear</button>
              </span>
            )}
          </h4>
          <table className="table" style={{ fontSize: 12 }}>
            <thead><tr><th>When</th><th>Verdict</th><th>From</th><th>Subject</th></tr></thead>
            <tbody>
              {history.filter(h => !batchFilter || h.batch_id === batchFilter).map(h => (
                <tr key={h.id} style={{ cursor: 'pointer' }} onClick={() => open(h.id)}>
                  <td>{formatLocal(h.created_at)}</td>
                  <td><span style={{ color: VERDICT_COLOR[h.verdict], fontWeight: 700 }}>{h.verdict} · {h.score}</span></td>
                  <td style={{ fontFamily: 'var(--font-mono)' }}>{h.from_addr || '—'}</td>
                  <td>{h.subject || '(no subject)'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

// ─── Email preview document ──────────────────────────────────────────────────
// `html` is already sanitized server-side (nh3 — no script/style/on*/remote
// img survives). This CSP is a second, independent layer on top of that, and
// the frontend also renders it inside an `iframe sandbox=""` (blocks script
// execution, forms, popups, top navigation entirely) -- three layers, not one,
// because email HTML is the most hostile input this app ever displays.

function buildPreviewDoc(html) {
  return `<!doctype html><html><head><meta charset="utf-8">` +
    `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src data:; style-src 'unsafe-inline';">` +
    `<style>
      body{font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;font-size:14px;line-height:1.5;
           color:#1a1a1a;background:#fff;padding:16px;word-break:break-word;max-width:720px;margin:0 auto;}
      p{margin:0 0 1em;} h1,h2,h3,h4,h5,h6{margin:0.6em 0 0.4em;}
      table{border-collapse:collapse;} td,th{padding:2px 4px;}
      img{max-width:100%;height:auto;}
      a{color:#1a56db;}
      blockquote{margin:0 0 1em;padding-left:12px;border-left:3px solid #ddd;color:#555;}
    </style>` +
    `</head><body>${html}</body></html>`
}

// ─── Authentication badge ────────────────────────────────────────────────────

const AUTH_BADGE_COLOR = { pass: 'var(--ok)', fail: 'var(--crit)', softfail: 'var(--med)', neutral: 'var(--muted)', none: 'var(--dim)' }

function AuthBadge({ value }) {
  const v = (value || 'none').toLowerCase()
  return (
    <span style={{
      color: AUTH_BADGE_COLOR[v] || 'var(--muted)', fontWeight: 700, textTransform: 'uppercase', fontSize: 11,
    }}>
      {value || '—'}
    </span>
  )
}

// ─── Live-DNS badges (automatic cross-check vs. the header's own claim) ─────
// `av` is the analysis's `auth_verified` blob -- null if a domain couldn't be
// determined, or `{error}` if the lookup timed out/failed. Tri-state: true
// (green), false (red), null/undetermined (muted) -- never guessed.

function LiveBadge({ tone, label, title }) {
  const color = tone === true ? 'var(--ok)' : tone === false ? 'var(--crit)' : 'var(--muted)'
  return <span title={title} style={{ color, fontWeight: 700, fontSize: 11 }}>{label}</span>
}

function LiveSpfBadge({ av }) {
  if (!av) return <LiveBadge tone={null} label="—" />
  if (av.error) return <LiveBadge tone={null} label="N/A" title={av.error} />
  if (!av.spf?.found) return <LiveBadge tone={false} label="NO RECORD" title={av.spf?.verdict} />
  if (av.ip_in_spf === true) return <LiveBadge tone={true} label="IP AUTHORIZED" />
  if (av.ip_in_spf === false) return <LiveBadge tone={false} label="IP NOT AUTHORIZED" />
  return <LiveBadge tone={null} label="RECORD FOUND" title="Source IP authorization couldn't be evaluated (a/mx/other mechanisms)." />
}

function LiveDkimBadge({ av }) {
  if (!av || !av.dkim) return <LiveBadge tone={null} label="—" title="No DKIM selector available to check." />
  return <LiveBadge tone={av.dkim.found} label={av.dkim.found ? 'KEY FOUND' : 'NOT FOUND'} title={av.dkim.verdict} />
}

function LiveDmarcBadge({ av }) {
  if (!av) return <LiveBadge tone={null} label="—" />
  if (av.error) return <LiveBadge tone={null} label="N/A" title={av.error} />
  if (!av.dmarc?.found) return <LiveBadge tone={false} label="NO RECORD" title={av.dmarc?.verdict} />
  const enforced = /^(reject|quarantine)$/i.test(av.dmarc.fields?.p || '')
  return <LiveBadge tone={enforced ? true : null} label={enforced ? 'ENFORCED' : 'MONITOR ONLY'} title={av.dmarc.verdict} />
}

// ─── Domain auth check (manual mode — live SPF/DMARC, optional DKIM) ────────
// SPF/DMARC come from a live DNS lookup; DKIM requires a selector, which
// can't be discovered from a bare domain — pre-filled from the parsed
// email's own DKIM-Signature when one was found, otherwise left blank for
// the analyst to supply if they know it from elsewhere.

function DomainAuthCheck({ incidentId, defaultDomain, defaultSelector }) {
  const [domain,   setDomain]   = useState(defaultDomain || '')
  const [selector, setSelector] = useState(defaultSelector || '')
  const [busy,   setBusy]   = useState(false)
  const [error,  setError]  = useState(null)
  const [result, setResult] = useState(null)

  useEffect(() => { if (defaultDomain) setDomain(defaultDomain) }, [defaultDomain])
  useEffect(() => { if (defaultSelector) setSelector(defaultSelector) }, [defaultSelector])

  const run = async () => {
    if (!domain.trim()) return
    setBusy(true); setError(null); setResult(null)
    try {
      setResult(await api.checkEmailDomain(incidentId, domain.trim(), selector.trim() || undefined))
    } catch (e) {
      setError(e.message || 'Check failed')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="panel" style={{ padding: 'var(--space-3)', marginTop: 'var(--space-4)' }}>
      <h4 className="panel-h" style={{ marginTop: 0 }}>Domain auth check <span style={{ fontWeight: 400, color: 'var(--muted)', fontSize: 12 }}>· live SPF/DMARC, manual mode</span></h4>
      <div style={{ display: 'flex', gap: 'var(--space-2)', flexWrap: 'wrap', alignItems: 'center' }}>
        <input className="input" style={{ maxWidth: 220 }} placeholder="domain.com"
               value={domain} onChange={e => setDomain(e.target.value)} disabled={busy} />
        <input className="input" style={{ maxWidth: 180 }} placeholder="DKIM selector (optional)"
               value={selector} onChange={e => setSelector(e.target.value)} disabled={busy} />
        <button className="btn primary" onClick={run} disabled={busy || !domain.trim()}>
          {busy ? 'Checking…' : 'Check'}
        </button>
      </div>
      <p style={{ fontSize: 11, color: 'var(--dim)', marginTop: 4, marginBottom: 0 }}>
        DKIM can't be checked from a domain alone — its selector only exists in an already-signed
        email's header. Leave it blank to check SPF/DMARC only.
      </p>

      {error && <div className="alert error" role="alert" style={{ marginTop: 'var(--space-2)' }}><span className="alert-icon">!</span><span>{error}</span></div>}

      {result && (
        <div style={{ marginTop: 'var(--space-3)', display: 'flex', gap: 'var(--space-3)', flexWrap: 'wrap' }}>
          <div style={{ minWidth: 260, flex: 1 }}>
            <div style={{ fontWeight: 600, fontSize: 12, marginBottom: 4 }}>SPF</div>
            {result.spf.found ? (
              <>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, wordBreak: 'break-all', color: 'var(--muted)' }}>{result.spf.record}</div>
                <div style={{ fontSize: 12, marginTop: 4 }}>{result.spf.verdict}</div>
                {result.spf.multiple_records && (
                  <div style={{ fontSize: 12, color: 'var(--high)', marginTop: 2 }}>⚠ Multiple SPF records found — invalid per RFC 7208.</div>
                )}
                {result.spf.includes?.length > 0 && (
                  <details style={{ marginTop: 4 }}>
                    <summary style={{ cursor: 'pointer', color: 'var(--accent)', fontSize: 11 }}>Includes ({result.spf.includes.length})</summary>
                    {result.spf.includes.map((inc, i) => (
                      <div key={i} style={{ fontSize: 11, marginTop: 4, paddingLeft: 8, borderLeft: '1px solid var(--border)' }}>
                        <strong>{inc.domain}</strong>: {inc.verdict}
                      </div>
                    ))}
                  </details>
                )}
              </>
            ) : (
              <div style={{ fontSize: 12, color: 'var(--high)' }}>{result.spf.verdict}</div>
            )}
          </div>

          <div style={{ minWidth: 260, flex: 1 }}>
            <div style={{ fontWeight: 600, fontSize: 12, marginBottom: 4 }}>DMARC</div>
            {result.dmarc.found ? (
              <>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, wordBreak: 'break-all', color: 'var(--muted)' }}>{result.dmarc.record}</div>
                <div style={{ fontSize: 12, marginTop: 4 }}>{result.dmarc.verdict}</div>
                {result.dmarc.fields?.rua && <div style={{ fontSize: 11, color: 'var(--dim)', marginTop: 2 }}>Aggregate reports: {result.dmarc.fields.rua}</div>}
              </>
            ) : (
              <div style={{ fontSize: 12, color: 'var(--high)' }}>{result.dmarc.verdict}</div>
            )}
          </div>

          {result.dkim && (
            <div style={{ minWidth: 260, flex: 1 }}>
              <div style={{ fontWeight: 600, fontSize: 12, marginBottom: 4 }}>DKIM ({result.dkim.selector})</div>
              <div style={{ fontSize: 12, color: result.dkim.found ? 'var(--ok)' : 'var(--high)' }}>{result.dkim.verdict}</div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
