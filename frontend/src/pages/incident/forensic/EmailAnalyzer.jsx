import { useEffect, useState } from 'react'
import { useOutletContext } from 'react-router-dom'
import { api } from '../../../api/client.js'
import { formatLocal } from '../../../lib/datetime.js'

// U8.1 — Email analyzer (offline phishing triage). Paste raw headers or upload an .eml →
// verdict + findings, hop chain, auth alignment, defanged URLs (→ IOC), attachments
// (→ quarantine Artifact), and "mint as Evidence". Nothing here hits the network.

const VERDICT_COLOR = { red: 'var(--crit)', amber: 'var(--med)', green: 'var(--ok)' }
const SEV_COLOR     = { high: 'var(--crit)', medium: 'var(--med)', low: 'var(--muted)' }

export default function EmailAnalyzer() {
  const { inc } = useOutletContext()
  const incidentId = inc.id

  const [raw, setRaw]         = useState('')
  const [file, setFile]       = useState(null)
  const [busy, setBusy]       = useState(false)
  const [error, setError]     = useState(null)
  const [analysis, setAnalysis] = useState(null)
  const [history, setHistory] = useState([])
  const [pickedUrls, setPickedUrls] = useState({})   // url -> bool
  const [note, setNote]       = useState(null)

  const loadHistory = () => api.listEmailAnalyses(incidentId).then(r => setHistory(r.items || [])).catch(() => {})
  useEffect(() => { loadHistory() }, [incidentId])

  async function run() {
    if (!raw.trim() && !file) { setError('Paste raw headers or choose an .eml file.'); return }
    setBusy(true); setError(null); setNote(null)
    try {
      const a = await api.analyzeEmail(incidentId, { raw: raw.trim() || null, file })
      setAnalysis(a); setPickedUrls({}); setRaw(''); setFile(null)
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
      out.push({ type: 'url', value: u.url })
      if (u.host) out.push({ type: 'domain', value: u.host })
    }
    const oip = analysis.headers?.origin_ip
    if (oip && pickedUrls.__origin__) out.push({ type: 'ip', value: oip })
    return out
  }

  const a = analysis
  const auth = a?.headers?.auth || {}
  const hops = a?.headers?.hops || []

  return (
    <div className="stack" style={{ gap: 'var(--space-4)' }}>
      <div className="panel" style={{ padding: 'var(--space-3)' }}>
        <h3 className="panel-h">Email analyzer <span style={{ fontWeight: 400, color: 'var(--muted)', fontSize: 12 }}>· offline phishing triage</span></h3>
        <p style={{ fontSize: 12, color: 'var(--muted)', marginTop: 0 }}>
          Paste the raw message/headers or upload an <code>.eml</code> / <code>.msg</code>. Parsed locally — no URL is fetched and no attachment is executed.
        </p>
        <textarea className="input" rows={6} value={raw} onChange={e => setRaw(e.target.value)}
                  placeholder="Paste raw email headers or full source here…"
                  style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }} disabled={busy} />
        <div style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'center', marginTop: 'var(--space-2)', flexWrap: 'wrap' }}>
          <input type="file" accept=".eml,.msg,message/rfc822,application/vnd.ms-outlook,text/plain" disabled={busy}
                 onChange={e => setFile(e.target.files?.[0] || null)} />
          <button className="btn primary" onClick={run} disabled={busy}>{busy ? 'Analyzing…' : 'Analyze'}</button>
        </div>
        {error && <div className="alert error" role="alert" style={{ marginTop: 'var(--space-2)' }}><span className="alert-icon">!</span><span>{error}</span></div>}
        {note  && <div className="alert info"  role="status" style={{ marginTop: 'var(--space-2)' }}><span className="alert-icon">✓</span><span>{note}</span></div>}
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
          <h4 className="panel-h" style={{ marginTop: 'var(--space-4)' }}>Authentication</h4>
          <div style={{ display: 'flex', gap: 'var(--space-3)', flexWrap: 'wrap', fontSize: 13, fontFamily: 'var(--font-mono)' }}>
            <span>SPF: <strong>{auth.spf || '—'}</strong></span>
            <span>DKIM: <strong>{auth.dkim || '—'}</strong> {auth.dkim_domain ? `(${auth.dkim_domain})` : ''}</span>
            <span>DMARC: <strong>{auth.dmarc || '—'}</strong></span>
            {auth.spf_domain && <span>mailfrom: {auth.spf_domain}</span>}
          </div>

          {/* Hop chain */}
          <h4 className="panel-h" style={{ marginTop: 'var(--space-4)' }}>Received chain ({hops.length})</h4>
          {a.headers?.origin_ip && <div style={{ fontSize: 12, marginBottom: 4 }}>Originating IP: <strong style={{ fontFamily: 'var(--font-mono)' }}>{a.headers.origin_ip}</strong></div>}
          <ol style={{ fontSize: 12, fontFamily: 'var(--font-mono)', paddingLeft: 18, margin: 0 }}>
            {hops.map((h, i) => (
              <li key={i} style={{ color: h.delay_seconds != null && h.delay_seconds < -60 ? 'var(--crit)' : 'inherit' }}>
                {h.from || '?'} → {h.by || '?'} {h.ip ? `[${h.ip}]` : ''} {h.timestamp ? `· ${h.timestamp}` : ''} {h.delay_seconds != null ? `(+${Math.round(h.delay_seconds)}s)` : ''}
              </li>
            ))}
          </ol>

          {/* URLs */}
          <h4 className="panel-h" style={{ marginTop: 'var(--space-4)' }}>URLs ({(a.urls || []).length})</h4>
          {(a.urls || []).length > 0 && (
            <>
              <table className="table" style={{ fontSize: 12 }}>
                <thead><tr><th></th><th>Defanged URL</th><th>Host</th><th>Link text</th></tr></thead>
                <tbody>
                  {a.urls.map((u, i) => (
                    <tr key={i}>
                      <td><input type="checkbox" checked={!!pickedUrls[u.url]}
                                 onChange={e => setPickedUrls(p => ({ ...p, [u.url]: e.target.checked }))} /></td>
                      <td style={{ fontFamily: 'var(--font-mono)', wordBreak: 'break-all' }}>{u.defanged}</td>
                      <td>{u.host || '—'}{u.display_host && u.display_host !== u.host ? <span style={{ color: 'var(--crit)' }}> ≠ {u.display_host}</span> : ''}</td>
                      <td style={{ color: 'var(--muted)' }}>{u.display_text || ''}</td>
                    </tr>
                  ))}
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
          <h4 className="panel-h">Previous analyses</h4>
          <table className="table" style={{ fontSize: 12 }}>
            <thead><tr><th>When</th><th>Verdict</th><th>From</th><th>Subject</th></tr></thead>
            <tbody>
              {history.map(h => (
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
