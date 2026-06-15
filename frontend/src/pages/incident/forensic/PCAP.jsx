import { Fragment, useCallback, useEffect, useRef, useState } from 'react'
import { useOutletContext } from 'react-router-dom'
import { api } from '../../../api/client.js'
import { formatLocal, formatLocalShort } from '../../../lib/datetime.js'

function fmtBytes(n) {
  if (!n) return '0 B'
  if (n < 1024) return `${n} B`
  if (n < 1_048_576) return `${(n / 1024).toFixed(1)} KB`
  if (n < 1_073_741_824) return `${(n / 1_048_576).toFixed(1)} MB`
  return `${(n / 1_073_741_824).toFixed(2)} GB`
}

function isPrivateIP(ip) {
  if (!ip) return true
  return (
    ip.startsWith('10.') ||
    ip.startsWith('192.168.') ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(ip) ||
    ip === '127.0.0.1' ||
    ip === '::1'
  )
}

function extractCandidates(result) {
  const seen = new Set()
  const out   = []

  const add = (type, value, notes, suspicious = false) => {
    const v = (value || '').trim()
    if (!v || seen.has(v)) return
    seen.add(v)
    out.push({ type, value: v, notes, suspicious })
  }

  result.top_talkers?.forEach(t => {
    if (!isPrivateIP(t.ip))
      add('ip', t.ip, `Top talker: ${fmtBytes(t.bytes)}`)
  })

  result.conversations?.tcp?.forEach(c => {
    [c.src?.split(':')[0], c.dst?.split(':')[0]].forEach(ip => {
      if (!isPrivateIP(ip)) add('ip', ip, 'TCP conversation')
    })
  })

  result.dns_queries?.forEach(d => {
    if (d.query && !d.query.endsWith('.local') && !d.query.endsWith('.arpa')) {
      const sus = Object.keys(d.suspicious || {}).length > 0
      add('domain', d.query, `DNS query → ${d.resolved_ip || 'unresolved'}`, sus)
    }
    if (d.resolved_ip && !isPrivateIP(d.resolved_ip))
      add('ip', d.resolved_ip, `DNS response for ${d.query}`)
  })

  result.tls_info?.forEach(t => {
    if (t.sni) {
      const sus = Object.keys(t.suspicious || {}).length > 0
      add('domain', t.sni, 'TLS SNI', sus)
    }
  })

  result.http_requests?.filter(r => r.host && r.uri).slice(0, 20).forEach(r => {
    const url = `${r.host}${r.uri}`.slice(0, 2000)
    const sus = Object.keys(r.suspicious || {}).length > 0
    add('url', url, `${r.method} ${r.response_code}`, sus)
  })

  return out
}

// ── IOC Import Modal ──────────────────────────────────────────────────────────

function IOCImportModal({ result, incidentId, onClose, onDone }) {
  const candidates = extractCandidates(result)

  const [selected, setSelected]         = useState(() => {
    const s = {}
    candidates.forEach((c, i) => { if (c.suspicious) s[i] = true })
    return s
  })
  const [importing, setImporting]       = useState(false)
  const [importResult, setImportResult] = useState(null)
  const [error, setError]               = useState(null)

  const selectedCount = Object.values(selected).filter(Boolean).length

  const toggleAll = (val) => {
    const s = {}
    candidates.forEach((_, i) => { s[i] = val })
    setSelected(s)
  }

  const handleImport = async () => {
    const iocs = candidates
      .filter((_, i) => selected[i])
      .map(c => ({ type: c.type, value: c.value, notes: c.notes || null }))
    if (!iocs.length) return
    setImporting(true)
    setError(null)
    try {
      const r = await api.importPcapIocs(incidentId, result.result_id, { iocs })
      setImportResult(r)
    } catch (e) {
      setError(e.message || 'Import failed')
    } finally {
      setImporting(false)
    }
  }

  const TYPE_COLOR = {
    ip:     'var(--crit)',
    domain: 'var(--high)',
    url:    'var(--med)',
  }

  return (
    <div
      className="modal-backdrop"
    >
      <div className="modal" style={{ maxWidth: 680 }}>
        <div className="modal-head">
          <h2>Import IOCs from PCAP</h2>
          <button className="modal-close" onClick={onClose} disabled={importing}>×</button>
        </div>

        {!importResult ? (
          <>
            <div className="modal-body" style={{ paddingBottom: 0 }}>
              <p style={{ margin: '0 0 var(--space-3)', color: 'var(--muted)', fontSize: 13 }}>
                {candidates.length} unique indicators extracted — suspicious ones are pre-selected.
              </p>

              {error && (
                <div className="alert error" role="alert" style={{ marginBottom: 'var(--space-3)' }}>
                  <span className="alert-icon">!</span><span>{error}</span>
                </div>
              )}

              <div style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'center', marginBottom: 'var(--space-2)' }}>
                <span style={{ fontSize: 12, color: 'var(--muted)', flex: 1 }}>
                  {selectedCount} of {candidates.length} selected
                </span>
                <button type="button" className="btn ghost" style={{ fontSize: 11, padding: '3px 8px' }} onClick={() => toggleAll(true)}>All</button>
                <button type="button" className="btn ghost" style={{ fontSize: 11, padding: '3px 8px' }} onClick={() => toggleAll(false)}>None</button>
                <button type="button" className="btn ghost" style={{ fontSize: 11, padding: '3px 8px', color: 'var(--crit)' }}
                  onClick={() => {
                    const s = {}
                    candidates.forEach((c, i) => { if (c.suspicious) s[i] = true })
                    setSelected(s)
                  }}>
                  Suspicious only
                </button>
              </div>
            </div>

            <div style={{ maxHeight: 320, overflowY: 'auto', borderTop: '1px solid var(--border)', borderBottom: '1px solid var(--border)' }}>
              <table className="settings-table" style={{ marginBottom: 0 }}>
                <thead>
                  <tr>
                    <th style={{ width: 32 }}></th>
                    <th style={{ width: 80 }}>Type</th>
                    <th>Value</th>
                    <th style={{ width: 200 }}>Context</th>
                  </tr>
                </thead>
                <tbody>
                  {candidates.map((c, i) => (
                    <tr key={i} style={{ background: c.suspicious ? 'color-mix(in srgb, var(--crit) 5%, transparent)' : 'transparent' }}>
                      <td style={{ textAlign: 'center' }}>
                        <input
                          type="checkbox"
                          checked={!!selected[i]}
                          onChange={() => setSelected(s => ({ ...s, [i]: !s[i] }))}
                        />
                      </td>
                      <td>
                        <span className="pill" style={{ background: `color-mix(in srgb, ${TYPE_COLOR[c.type] || 'var(--accent)'} 15%, transparent)`, color: TYPE_COLOR[c.type] || 'var(--accent)', border: 'none', fontSize: 10 }}>
                          {c.type}
                        </span>
                        {c.suspicious && <span style={{ marginLeft: 4, fontSize: 10, color: 'var(--crit)' }}>⚠</span>}
                      </td>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11, maxWidth: 240, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {c.value}
                      </td>
                      <td style={{ fontSize: 11, color: 'var(--muted)', maxWidth: 180, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {c.notes}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div className="modal-foot">
              <button type="button" className="btn ghost" onClick={onClose} disabled={importing}>Cancel</button>
              <button type="button" className="btn primary" onClick={handleImport}
                disabled={selectedCount === 0 || importing}>
                {importing ? 'Importing…' : `Import ${selectedCount} IOC${selectedCount !== 1 ? 's' : ''}`}
              </button>
            </div>
          </>
        ) : (
          <>
            <div className="modal-body" style={{ textAlign: 'center', padding: 'var(--space-6) var(--space-4)' }}>
              <div style={{ fontSize: 36, marginBottom: 'var(--space-3)' }}>✓</div>
              <div style={{ fontFamily: 'var(--font-heading)', fontSize: 16, marginBottom: 'var(--space-4)' }}>Import Complete</div>
              <div style={{ display: 'flex', justifyContent: 'center', gap: 'var(--space-6)' }}>
                <div style={{ textAlign: 'center' }}>
                  <div style={{ fontSize: 28, fontWeight: 800, color: 'var(--ok)' }}>{importResult.imported}</div>
                  <div style={{ fontSize: 12, color: 'var(--muted)' }}>IOCs imported</div>
                </div>
                {importResult.skipped_duplicates > 0 && (
                  <div style={{ textAlign: 'center' }}>
                    <div style={{ fontSize: 28, fontWeight: 800, color: 'var(--dim)' }}>{importResult.skipped_duplicates}</div>
                    <div style={{ fontSize: 12, color: 'var(--muted)' }}>duplicates skipped</div>
                  </div>
                )}
              </div>
            </div>
            <div className="modal-foot">
              <button type="button" className="btn primary" onClick={() => { onDone(); onClose() }}>Done</button>
            </div>
          </>
        )}
      </div>
    </div>
  )
}

// ── Saved results panel ───────────────────────────────────────────────────────

function SavedPanel({ incidentId, onLoad, onDelete }) {
  const [rows, setRows]       = useState([])
  const [loading, setLoading] = useState(true)

  const load = useCallback(async () => {
    try {
      const res = await api.listPcap(incidentId)
      setRows(res || [])
    } catch {
      setRows([])
    } finally {
      setLoading(false)
    }
  }, [incidentId])

  useEffect(() => { load() }, [load])

  if (loading) return <div style={{ color: 'var(--muted)', fontSize: 12, padding: 'var(--space-2)' }}>Loading…</div>
  if (!rows.length) return <div style={{ color: 'var(--dim)', fontSize: 12, fontStyle: 'italic', padding: 'var(--space-2)' }}>No saved analyses for this incident.</div>

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
      {rows.map(r => (
        <div key={r.id} style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'center', padding: '6px var(--space-3)', background: 'var(--surface-2)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)' }}>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ fontWeight: 600, fontSize: 13, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{r.filename}</div>
            <div style={{ fontSize: 11, color: 'var(--muted)', fontFamily: 'var(--font-mono)' }}>
              {fmtBytes(r.file_size)} · {r.uploaded_by} · {formatLocalShort(r.created_at)}
            </div>
          </div>
          <button type="button" className="btn ghost" style={{ fontSize: 11, padding: '3px 8px' }} onClick={() => onLoad(r.id)}>Load</button>
          <button type="button" className="btn ghost" style={{ fontSize: 11, padding: '3px 8px', color: 'var(--crit)' }} onClick={() => onDelete(r.id, r.filename)}>✕</button>
        </div>
      ))}
    </div>
  )
}

// ── Stat card ─────────────────────────────────────────────────────────────────

function Stat({ label, value, color }) {
  return (
    <div style={{ background: 'var(--surface-2)', border: '1px solid var(--border)', borderRadius: 'var(--radius)', padding: 'var(--space-3) var(--space-4)', textAlign: 'center' }}>
      <div style={{ fontSize: 22, fontWeight: 800, color: color || 'var(--text)' }}>{value}</div>
      <div style={{ fontSize: 11, color: 'var(--muted)', marginTop: 2 }}>{label}</div>
    </div>
  )
}

// ── Section heading ───────────────────────────────────────────────────────────

function SectionHead({ title, count, color }) {
  return (
    <div style={{ fontSize: 11, fontWeight: 700, letterSpacing: '0.08em', textTransform: 'uppercase', color: color || 'var(--muted)', marginBottom: 'var(--space-2)', marginTop: 'var(--space-4)', paddingBottom: 6, borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between' }}>
      <span>{title}</span>
      {count !== undefined && <span style={{ fontWeight: 400, color: 'var(--dim)' }}>{count}</span>}
    </div>
  )
}

// ── Main component ────────────────────────────────────────────────────────────

const RESULT_TABS = [
  { id: 'suspicious',    label: (r) => `Suspicious${r?.suspicious?.length ? ` (${r.suspicious.length})` : ''}` },
  { id: 'conversations', label: () => 'Conversations' },
  { id: 'dns',           label: (r) => `DNS${r?.dns_queries?.length ? ` (${r.dns_queries.length})` : ''}` },
  { id: 'dns-recon',     label: () => 'DNS Recon' },
  { id: 'http',          label: (r) => `HTTP${r?.http_requests?.length ? ` (${r.http_requests.length})` : ''}` },
  { id: 'tls',           label: (r) => `TLS${r?.tls_info?.length ? ` (${r.tls_info.length})` : ''}` },
  { id: 'talkers',       label: () => 'Top Talkers' },
]

export default function PCAP() {
  const { inc } = useOutletContext()
  const isClosed = inc?.status === 'closed'

  const [file, setFile]         = useState(null)
  const [dragging, setDragging] = useState(false)
  const [loading, setLoading]   = useState(false)
  const [result, setResult]     = useState(null)
  const [error, setError]       = useState(null)
  const [activeTab, setActiveTab] = useState('suspicious')
  const [showImport, setShowImport] = useState(false)
  const [showSaved, setShowSaved]   = useState(true)
  const [savedKey, setSavedKey]     = useState(0)   // bump to refresh SavedPanel
  // DNS recon (lazy-loaded the first time the tab is opened for this result)
  const [dnsRecon, setDnsRecon]               = useState(null)
  const [dnsReconLoading, setDnsReconLoading] = useState(false)
  const [dnsReconError, setDnsReconError]     = useState(null)
  const fileRef = useRef()

  const loadResult = async (id) => {
    setLoading(true)
    setError(null)
    setDnsRecon(null)
    setDnsReconError(null)
    try {
      const data = await api.getPcap(inc.id, id)
      setResult(data)
      setFile({ name: data.filename })
      setActiveTab(data.suspicious?.length > 0 ? 'suspicious' : 'conversations')
      setShowSaved(false)
    } catch (e) {
      setError(e.message || 'Could not load result')
    } finally {
      setLoading(false)
    }
  }

  // Lazy-load the DNS recon view on first activation. Refetch path keyed by
  // result.result_id so switching between saved PCAPs re-fetches correctly.
  useEffect(() => {
    if (activeTab !== 'dns-recon' || !result?.result_id) return
    if (dnsRecon || dnsReconLoading) return
    setDnsReconLoading(true)
    setDnsReconError(null)
    api.getPcapDnsRecon(inc.id, result.result_id)
      .then(setDnsRecon)
      .catch(e => setDnsReconError(e.message || 'Could not load DNS recon'))
      .finally(() => setDnsReconLoading(false))
  }, [activeTab, result?.result_id, inc.id, dnsRecon, dnsReconLoading])

  // Auto-load the most recent result for this incident on mount
  useEffect(() => {
    api.listPcap(inc.id)
      .then(rows => { if (rows?.length > 0) loadResult(rows[0].id) })
      .catch(() => {})
  }, [inc.id])

  const analyze = async (f) => {
    setFile(f)
    setLoading(true)
    setError(null)
    setResult(null)
    try {
      const data = await api.uploadPcap(inc.id, f)
      setResult(data)
      setActiveTab(data.suspicious?.length > 0 ? 'suspicious' : 'conversations')
      setSavedKey(k => k + 1)
    } catch (e) {
      setError(e.message || 'Analysis failed')
    } finally {
      setLoading(false)
    }
  }

  const deleteSaved = async (id, filename) => {
    if (!window.confirm(`Delete saved analysis for "${filename}"?`)) return
    try {
      await api.deletePcap(inc.id, id)
      setSavedKey(k => k + 1)
      if (result?.result_id === id) { setResult(null); setFile(null) }
    } catch (e) {
      setError(e.message || 'Delete failed')
    }
  }

  const onDrop = (e) => {
    e.preventDefault(); setDragging(false)
    const f = e.dataTransfer.files[0]
    if (f && !isClosed) analyze(f)
  }

  const SEV_COLOR = { high: 'var(--crit)', medium: 'var(--med)', low: 'var(--low)' }

  return (
    <section className="panel">
      <div className="panel-toolbar">
        <h2 className="panel-h">PCAP Analysis</h2>
        <div style={{ display: 'flex', gap: 'var(--space-2)' }}>
          {result && !isClosed && (
            <button type="button" className="btn ghost" style={{ fontSize: 12 }}
              onClick={() => { setResult(null); setFile(null); setTimeout(() => fileRef.current?.click(), 0) }}>
              Analyze Another
            </button>
          )}
          <button type="button" className="btn ghost" style={{ fontSize: 12 }}
            onClick={() => setShowSaved(s => !s)}>
            {showSaved ? 'Hide Saved' : 'Saved Results'}
          </button>
        </div>
      </div>

      {error && (
        <div className="alert error" role="alert">
          <span className="alert-icon">!</span><span>{error}</span>
        </div>
      )}

      {showSaved && (
        <div style={{ marginBottom: 'var(--space-4)', background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 'var(--radius)', padding: 'var(--space-3)' }}>
          <div style={{ fontSize: 12, fontWeight: 700, letterSpacing: '0.06em', textTransform: 'uppercase', color: 'var(--muted)', marginBottom: 'var(--space-2)' }}>Saved Analyses</div>
          <SavedPanel key={savedKey} incidentId={inc.id} onLoad={loadResult} onDelete={deleteSaved} />
        </div>
      )}

      <input
        ref={fileRef}
        type="file"
        accept=".pcap,.pcapng,.cap"
        style={{ display: 'none' }}
        onChange={e => e.target.files[0] && !isClosed && analyze(e.target.files[0])}
      />

      {!result && !loading && (
        <div
          onDragOver={e => { e.preventDefault(); if (!isClosed) setDragging(true) }}
          onDragLeave={() => setDragging(false)}
          onDrop={onDrop}
          onClick={() => !isClosed && fileRef.current?.click()}
          style={{
            border: `2px dashed ${dragging ? 'var(--accent)' : 'var(--border)'}`,
            borderRadius: 'var(--radius-lg)',
            padding: '48px var(--space-4)',
            textAlign: 'center',
            cursor: isClosed ? 'default' : 'pointer',
            background: dragging ? 'color-mix(in srgb, var(--accent) 5%, transparent)' : 'var(--surface)',
          }}
        >
          <div style={{ fontSize: 40, marginBottom: 'var(--space-3)', opacity: 0.6 }}>≋</div>
          <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 6 }}>
            {isClosed ? 'No PCAP analyses — incident is closed' : 'Drop a PCAP file here'}
          </div>
          {!isClosed && (
            <div style={{ fontSize: 13, color: 'var(--muted)' }}>
              Supports .pcap, .pcapng, .cap — analyzed in the air-gapped worker
            </div>
          )}
        </div>
      )}

      {loading && (
        <div style={{ textAlign: 'center', padding: '48px var(--space-4)', background: 'var(--surface)', borderRadius: 'var(--radius-lg)', border: '1px solid var(--border)' }}>
          <div style={{ fontSize: 13, color: 'var(--muted)' }}>Analyzing {file?.name}…</div>
          <div style={{ fontSize: 11, color: 'var(--dim)', marginTop: 6 }}>Extracting conversations, DNS, HTTP, TLS</div>
        </div>
      )}

      {result && (
        <>
          {/* File info + actions */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 'var(--space-3)', flexWrap: 'wrap', gap: 'var(--space-2)' }}>
            <div>
              <div style={{ fontWeight: 700, fontSize: 14 }}>{file?.name || result.filename}</div>
              <div style={{ fontSize: 12, color: 'var(--muted)', fontFamily: 'var(--font-mono)' }}>
                {fmtBytes(result.file_size)} · {result.format?.toUpperCase()}
                {result.saved_at && <span title={formatLocal(result.saved_at)}> · {formatLocalShort(result.saved_at)}</span>}
              </div>
            </div>
            {result.result_id && !isClosed && (
              <button type="button" className="btn primary" style={{ fontSize: 12 }}
                onClick={() => setShowImport(true)}>
                Import IOCs to Incident
              </button>
            )}
          </div>

          {/* Worker errors */}
          {result.errors?.map((e, i) => (
            <div key={i} style={{ marginBottom: 'var(--space-2)', padding: '6px var(--space-3)', background: 'color-mix(in srgb, var(--high) 8%, transparent)', border: '1px solid color-mix(in srgb, var(--high) 30%, transparent)', borderRadius: 'var(--radius-sm)', fontSize: 12, color: 'var(--high)' }}>
              ⚠ {e}
            </div>
          ))}

          {/* Stats */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(120px, 1fr))', gap: 'var(--space-2)', marginBottom: 'var(--space-4)' }}>
            <Stat label="TCP Conversations" value={result.conversations?.tcp?.length || 0} color="var(--accent)" />
            <Stat label="UDP Conversations" value={result.conversations?.udp?.length || 0} color="var(--accent)" />
            <Stat label="DNS Queries"       value={result.dns_queries?.length   || 0}  color="var(--ok)" />
            <Stat label="HTTP Requests"     value={result.http_requests?.length || 0}  color="var(--high)" />
            <Stat label="TLS Sessions"      value={result.tls_info?.length      || 0}  color="var(--med)" />
            <Stat label="Suspicious"        value={result.suspicious?.length    || 0}
              color={result.suspicious?.length > 0 ? 'var(--crit)' : 'var(--dim)'} />
          </div>

          {/* Tab bar */}
          <div style={{ display: 'flex', gap: 2, background: 'var(--surface-2)', border: '1px solid var(--border)', borderRadius: 'var(--radius)', padding: 2, marginBottom: 'var(--space-3)', flexWrap: 'wrap' }}>
            {RESULT_TABS.map(tab => (
              <button key={tab.id} type="button" onClick={() => setActiveTab(tab.id)}
                style={{ padding: '5px 12px', borderRadius: 'var(--radius-sm)', fontSize: 12, cursor: 'pointer', border: 'none', transition: 'background 0.1s',
                  background: activeTab === tab.id ? 'var(--accent)' : 'transparent',
                  color: activeTab === tab.id ? 'var(--bg)' : 'var(--muted)',
                  fontWeight: activeTab === tab.id ? 700 : 400,
                }}>
                {tab.label(result)}
              </button>
            ))}
          </div>

          {/* ── Suspicious ── */}
          {activeTab === 'suspicious' && (
            <div>
              {!result.suspicious?.length ? (
                <div className="panel-empty">
                  <div style={{ fontSize: 13 }}>No suspicious patterns detected.</div>
                </div>
              ) : result.suspicious.map((s, i) => (
                <div key={i} style={{ marginBottom: 'var(--space-2)', padding: 'var(--space-2) var(--space-3)', borderRadius: 'var(--radius-sm)', border: `1px solid color-mix(in srgb, ${SEV_COLOR[s.severity] || 'var(--med)'} 25%, transparent)`, borderLeft: `3px solid ${SEV_COLOR[s.severity] || 'var(--med)'}`, background: `color-mix(in srgb, ${SEV_COLOR[s.severity] || 'var(--med)'} 5%, transparent)` }}>
                  <div style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'center', marginBottom: 3 }}>
                    <span className="pill" style={{ fontSize: 10, padding: '1px 6px', background: `color-mix(in srgb, ${SEV_COLOR[s.severity] || 'var(--med)'} 15%, transparent)`, color: SEV_COLOR[s.severity] || 'var(--med)', border: 'none', textTransform: 'uppercase' }}>{s.severity}</span>
                    <span className="pill" style={{ fontSize: 10, padding: '1px 6px', border: 'none' }}>{s.category}</span>
                    <span style={{ fontWeight: 600, fontSize: 13 }}>{s.description}</span>
                  </div>
                  {s.detail && <div style={{ fontSize: 12, color: 'var(--muted)', fontFamily: 'var(--font-mono)' }}>{s.detail}</div>}
                </div>
              ))}
            </div>
          )}

          {/* ── Conversations ── */}
          {activeTab === 'conversations' && (
            <div>
              <SectionHead title="TCP Conversations" count={result.conversations?.tcp?.length} color="var(--accent)" />
              <div style={{ overflowX: 'auto', border: '1px solid var(--border)', borderRadius: 'var(--radius)' }}>
                <table className="settings-table">
                  <thead>
                    <tr>
                      {['Source', 'Destination', 'Frames →', 'Bytes →', 'Frames ←', 'Bytes ←', 'Total'].map(h => (
                        <th key={h} style={{ whiteSpace: 'nowrap' }}>{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {result.conversations.tcp.slice(0, 50).map((c, i) => (
                      <tr key={i}>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>{c.src}</td>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>{c.dst}</td>
                        <td style={{ color: 'var(--muted)' }}>{c.frames_ab?.toLocaleString()}</td>
                        <td style={{ color: 'var(--muted)' }}>{fmtBytes(c.bytes_ab)}</td>
                        <td style={{ color: 'var(--muted)' }}>{c.frames_ba?.toLocaleString()}</td>
                        <td style={{ color: 'var(--muted)' }}>{fmtBytes(c.bytes_ba)}</td>
                        <td style={{ fontWeight: 600 }}>{fmtBytes(c.total_bytes)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <SectionHead title="UDP Conversations" count={result.conversations?.udp?.length} color="var(--accent)" />
              <div style={{ overflowX: 'auto', border: '1px solid var(--border)', borderRadius: 'var(--radius)' }}>
                <table className="settings-table">
                  <thead>
                    <tr>
                      {['Source', 'Destination', 'Frames', 'Total Bytes'].map(h => (
                        <th key={h}>{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {result.conversations.udp.slice(0, 30).map((c, i) => (
                      <tr key={i}>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>{c.src}</td>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>{c.dst}</td>
                        <td style={{ color: 'var(--muted)' }}>{c.total_frames?.toLocaleString()}</td>
                        <td style={{ fontWeight: 600 }}>{fmtBytes(c.total_bytes)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* ── DNS ── */}
          {activeTab === 'dns' && (
            <div style={{ overflowX: 'auto', border: '1px solid var(--border)', borderRadius: 'var(--radius)' }}>
              <table className="settings-table">
                <thead>
                  <tr>
                    {['Time', 'Source', 'Query', 'Resolved IP', 'CNAME', '⚠'].map(h => (
                      <th key={h} style={{ whiteSpace: 'nowrap' }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {result.dns_queries.map((d, i) => {
                    const sus = d.suspicious && Object.keys(d.suspicious).length > 0
                    return (
                      <tr key={i} style={{ background: sus ? 'color-mix(in srgb, var(--crit) 5%, transparent)' : 'transparent' }}>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--dim)', whiteSpace: 'nowrap' }}>{d.time?.slice(0, 8)}</td>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>{d.src}</td>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11, maxWidth: 280, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{d.query}</td>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--muted)' }}>{d.resolved_ip}</td>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--dim)', maxWidth: 160, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{d.cname}</td>
                        <td>{sus && <span style={{ fontSize: 10, color: 'var(--crit)', fontWeight: 700 }}>⚠ {Object.keys(d.suspicious)[0].replace(/_/g, ' ')}</span>}</td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}

          {/* ── DNS Recon ── */}
          {activeTab === 'dns-recon' && (
            <DnsReconTab
              incidentId={inc.id}
              resultId={result.result_id}
              data={dnsRecon}
              loading={dnsReconLoading}
              error={dnsReconError}
              isClosed={isClosed}
              onPromoted={() => {}}
            />
          )}

          {/* ── HTTP ── */}
          {activeTab === 'http' && (
            <div style={{ overflowX: 'auto', border: '1px solid var(--border)', borderRadius: 'var(--radius)' }}>
              <table className="settings-table">
                <thead>
                  <tr>
                    {['Time', 'Method', 'Host', 'URI', 'Code', 'User-Agent', '⚠'].map(h => (
                      <th key={h} style={{ whiteSpace: 'nowrap' }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {result.http_requests.map((r, i) => {
                    const sus = r.suspicious && Object.keys(r.suspicious).length > 0
                    const methodColor = { GET: 'var(--ok)', POST: 'var(--high)', PUT: 'var(--med)', DELETE: 'var(--crit)', CONNECT: 'var(--crit)' }
                    return (
                      <tr key={i} style={{ background: sus ? 'color-mix(in srgb, var(--crit) 5%, transparent)' : 'transparent' }}>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--dim)', whiteSpace: 'nowrap' }}>{r.time?.slice(0, 8)}</td>
                        <td style={{ fontWeight: 700, fontSize: 11, color: methodColor[r.method] || 'var(--muted)', whiteSpace: 'nowrap' }}>{r.method}</td>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11, maxWidth: 160, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{r.host}</td>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--muted)', maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{r.uri}</td>
                        <td style={{ fontSize: 11, color: r.response_code?.startsWith('4') || r.response_code?.startsWith('5') ? 'var(--crit)' : 'var(--muted)' }}>{r.response_code}</td>
                        <td style={{ fontSize: 10, color: 'var(--dim)', maxWidth: 140, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{r.user_agent}</td>
                        <td>{sus && <span style={{ fontSize: 10, color: 'var(--crit)', fontWeight: 700 }}>⚠</span>}</td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}

          {/* ── TLS ── */}
          {activeTab === 'tls' && (
            <div style={{ overflowX: 'auto', border: '1px solid var(--border)', borderRadius: 'var(--radius)' }}>
              <table className="settings-table">
                <thead>
                  <tr>
                    {['Source', 'Destination', 'SNI', 'Version', '⚠'].map(h => (
                      <th key={h} style={{ whiteSpace: 'nowrap' }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {result.tls_info.map((t, i) => {
                    const sus = t.suspicious && Object.keys(t.suspicious).length > 0
                    const oldTLS = t.version?.includes('1.0') || t.version?.includes('1.1') || t.version?.includes('SSL')
                    return (
                      <tr key={i} style={{ background: sus ? 'color-mix(in srgb, var(--crit) 5%, transparent)' : 'transparent' }}>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>{t.src}</td>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>{t.dst}</td>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11, fontWeight: 600 }}>
                          {t.sni || <span style={{ color: 'var(--dim)', fontStyle: 'italic', fontWeight: 400 }}>no SNI</span>}
                        </td>
                        <td style={{ fontSize: 11, color: oldTLS ? 'var(--crit)' : 'var(--muted)' }}>{t.version}</td>
                        <td>{sus && <span style={{ fontSize: 10, color: 'var(--crit)', fontWeight: 700 }}>⚠ {Object.keys(t.suspicious)[0].replace(/_/g, ' ')}</span>}</td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}

          {/* ── Top Talkers ── */}
          {activeTab === 'talkers' && (
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--space-4)' }}>
              <div>
                <SectionHead title="Top Talkers by Bytes" color="var(--accent)" />
                {result.top_talkers?.slice(0, 15).map((t, i) => {
                  const max = result.top_talkers[0]?.bytes || 1
                  return (
                    <div key={i} style={{ marginBottom: 'var(--space-2)' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, marginBottom: 2 }}>
                        <span style={{ fontFamily: 'var(--font-mono)' }}>{t.ip}</span>
                        <span style={{ color: 'var(--muted)' }}>{fmtBytes(t.bytes)} · {t.packets?.toLocaleString()} pkts</span>
                      </div>
                      <div style={{ background: 'var(--border)', borderRadius: 3, height: 4 }}>
                        <div style={{ width: `${(t.bytes / max) * 100}%`, height: '100%', background: 'var(--accent)', borderRadius: 3 }} />
                      </div>
                    </div>
                  )
                })}
              </div>
              <div>
                <SectionHead title="Protocol Summary" color="var(--med)" />
                {Object.entries(result.protocol_summary || {}).slice(0, 15).map(([proto, count]) => (
                  <div key={proto} style={{ display: 'flex', justifyContent: 'space-between', padding: '4px 0', borderBottom: '1px solid var(--border)', fontSize: 12 }}>
                    <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text)' }}>{proto}</span>
                    <span style={{ fontWeight: 600 }}>{count?.toLocaleString()}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </>
      )}

      {showImport && result && (
        <IOCImportModal
          result={result}
          incidentId={inc.id}
          onClose={() => setShowImport(false)}
          onDone={() => setShowImport(false)}
        />
      )}
    </section>
  )
}


// ── DNS Recon tab ─────────────────────────────────────────────────────────────
// Renders a per-domain analyst view over the existing tshark DNS output.
// Lets the analyst bulk-promote suspicious/DGA-candidate domains as IOCs
// tagged "dns-recon" (the auto-source tag for this surface — distinct from
// the broader "pcap" tag used by the main Import IOCs button).

function DnsReconTab({ incidentId, resultId, data, loading, error, isClosed, onPromoted }) {
  const [selected, setSelected]       = useState({})  // index → bool
  const [importing, setImporting]     = useState(false)
  const [importResult, setImportResult] = useState(null)
  const [importError, setImportError] = useState(null)
  const [expanded, setExpanded]       = useState(null)

  // Pre-select suspicious + DGA candidates on first data arrival
  useEffect(() => {
    if (!data) return
    const s = {}
    data.domains.forEach((d, i) => {
      if ((d.suspicious_flags && d.suspicious_flags.length) || d.is_dga_candidate) s[i] = true
    })
    setSelected(s)
    setImportResult(null)
    setImportError(null)
  }, [data])

  if (loading) return <div style={{ padding: 'var(--space-4)', color: 'var(--muted)' }}>Loading DNS recon…</div>
  if (error)   return <div className="alert error"><span className="alert-icon">!</span><span>{error}</span></div>
  if (!data)   return null

  const { stats, domains } = data
  const selectedIndices = Object.keys(selected).filter(k => selected[k]).map(k => Number(k))
  const selectedCount = selectedIndices.length

  const toggleAll = (val) => {
    const s = {}
    domains.forEach((_, i) => { s[i] = val })
    setSelected(s)
  }

  const promote = async (indices) => {
    if (isClosed || importing || !indices.length) return
    const iocs = indices.map(i => {
      const d = domains[i]
      const flags = [...(d.suspicious_flags || [])]
      if (d.is_dga_candidate) flags.push('dga-candidate')
      const note = flags.length ? `DNS recon: ${flags.join(', ')}` : 'DNS recon'
      return { type: 'domain', value: d.query, notes: note }
    })
    setImporting(true)
    setImportError(null)
    try {
      const r = await api.importPcapIocs(incidentId, resultId, {
        iocs,
        tags_override: ['dns-recon'],
      })
      setImportResult(r)
      onPromoted && onPromoted(r)
    } catch (e) {
      setImportError(e.message || 'Promote failed')
    } finally {
      setImporting(false)
    }
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
      {/* Stats bar */}
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 'var(--space-2)' }}>
        <Stat label="Queries"        value={stats.total_queries}       color="var(--accent)" />
        <Stat label="Unique domains" value={stats.unique_domains}      color="var(--text)" />
        <Stat label="Clients"        value={stats.unique_clients}      color="var(--muted)" />
        <Stat label="Suspicious"     value={stats.suspicious_count}    color="var(--crit)" />
        <Stat label="DGA candidates" value={stats.dga_candidate_count} color="var(--high)" />
      </div>

      {/* Top resolvers */}
      {stats.top_clients?.length > 0 && (
        <div style={{ border: '1px solid var(--border)', borderRadius: 'var(--radius)', padding: 'var(--space-2) var(--space-3)' }}>
          <div style={{ fontSize: 11, color: 'var(--muted)', marginBottom: 4 }}>Top resolvers (by query volume)</div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 'var(--space-2)' }}>
            {stats.top_clients.slice(0, 8).map(c => (
              <span key={c.ip} style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>
                {c.ip} <span style={{ color: 'var(--dim)' }}>× {c.query_count}</span>
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Action bar */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
        <span style={{ flex: 1, fontSize: 12, color: 'var(--muted)' }}>
          {selectedCount} of {domains.length} domain{domains.length === 1 ? '' : 's'} selected
        </span>
        <button type="button" className="btn ghost" style={{ fontSize: 11 }} onClick={() => toggleAll(true)}>All</button>
        <button type="button" className="btn ghost" style={{ fontSize: 11 }} onClick={() => toggleAll(false)}>None</button>
        <button
          type="button"
          className="btn primary"
          disabled={isClosed || importing || selectedCount === 0}
          onClick={() => promote(selectedIndices)}
          title={isClosed ? 'Closed incidents are read-only' : 'Promote selected domains as IOCs (tagged dns-recon)'}
        >
          {importing ? 'Promoting…' : `Promote ${selectedCount} → IOC`}
        </button>
      </div>

      {importError && (
        <div className="alert error"><span className="alert-icon">!</span><span>{importError}</span></div>
      )}
      {importResult && (
        <div className="alert" style={{ background: 'color-mix(in srgb, var(--ok) 12%, transparent)', border: '1px solid var(--ok)' }}>
          Imported {importResult.imported}, skipped {importResult.skipped_duplicates} duplicate{importResult.skipped_duplicates === 1 ? '' : 's'}.
        </div>
      )}

      {/* Domain table */}
      <div style={{ overflowX: 'auto', border: '1px solid var(--border)', borderRadius: 'var(--radius)' }}>
        <table className="settings-table">
          <thead>
            <tr>
              <th style={{ width: 32 }}></th>
              <th>Domain</th>
              <th style={{ width: 64 }}>#</th>
              <th>Resolved</th>
              <th style={{ width: 110 }}>Types</th>
              <th style={{ width: 140 }}>Clients</th>
              <th style={{ width: 160 }}>Flags</th>
              <th style={{ width: 64, textAlign: 'right' }}></th>
            </tr>
          </thead>
          <tbody>
            {domains.map((d, i) => {
              const sus = d.suspicious_flags?.length > 0
              const isExp = expanded === i
              const rowBg = sus
                ? 'color-mix(in srgb, var(--crit) 6%, transparent)'
                : d.is_dga_candidate
                ? 'color-mix(in srgb, var(--high) 6%, transparent)'
                : 'transparent'
              return (
                <Fragment key={i}>
                  <tr style={{ background: rowBg }}>
                    <td style={{ textAlign: 'center' }}>
                      <input
                        type="checkbox"
                        checked={!!selected[i]}
                        onChange={() => setSelected(s => ({ ...s, [i]: !s[i] }))}
                      />
                    </td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11, wordBreak: 'break-all' }}>
                      <button
                        type="button"
                        className="btn ghost"
                        style={{ fontSize: 10, padding: '0 4px', marginRight: 4 }}
                        onClick={() => setExpanded(isExp ? null : i)}
                        title={isExp ? 'Collapse' : 'Show CNAMEs / clients / timing'}
                      >{isExp ? '▲' : '▼'}</button>
                      {d.query}
                    </td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--muted)' }}>{d.query_count}</td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--muted)', maxWidth: 220, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {d.resolved_ips.length ? d.resolved_ips.slice(0, 2).join(', ') + (d.resolved_ips.length > 2 ? ` +${d.resolved_ips.length - 2}` : '') : <span style={{ color: 'var(--dim)' }}>—</span>}
                    </td>
                    <td>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 3 }}>
                        {d.record_types.map(t => (
                          <span key={t} className="pill" style={{ fontSize: 10 }}>{rrName(t)}</span>
                        ))}
                      </div>
                    </td>
                    <td style={{ fontSize: 11, color: 'var(--muted)' }}>
                      {d.clients.length ? d.clients.slice(0, 2).join(', ') + (d.clients.length > 2 ? ` +${d.clients.length - 2}` : '') : '—'}
                    </td>
                    <td>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 3 }}>
                        {d.is_dga_candidate && (
                          <span title={`Entropy ${d.entropy}`} style={{ fontSize: 10, padding: '1px 6px', borderRadius: 'var(--radius-sm)', background: 'color-mix(in srgb, var(--high) 18%, transparent)', color: 'var(--high)', fontWeight: 600 }}>
                            DGA
                          </span>
                        )}
                        {d.suspicious_flags.map(f => (
                          <span key={f} style={{ fontSize: 10, padding: '1px 6px', borderRadius: 'var(--radius-sm)', background: 'color-mix(in srgb, var(--crit) 15%, transparent)', color: 'var(--crit)', fontWeight: 600 }}>
                            {f.replace(/_/g, ' ')}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td style={{ textAlign: 'right' }}>
                      <button
                        type="button"
                        className="btn ghost"
                        style={{ fontSize: 11 }}
                        disabled={isClosed || importing}
                        onClick={() => promote([i])}
                        title={isClosed ? 'Closed incidents are read-only' : 'Promote this domain as an IOC (tagged dns-recon)'}
                      >→ IOC</button>
                    </td>
                  </tr>
                  {isExp && (
                    <tr key={`${i}-x`}>
                      <td></td>
                      <td colSpan={7} style={{ background: 'var(--surface-2)', fontSize: 11, padding: 'var(--space-2) var(--space-3)' }}>
                        <div style={{ display: 'grid', gridTemplateColumns: '120px 1fr', rowGap: 4 }}>
                          <span style={{ color: 'var(--muted)' }}>All resolved IPs</span>
                          <span style={{ fontFamily: 'var(--font-mono)' }}>{d.resolved_ips.join(', ') || '—'}</span>
                          <span style={{ color: 'var(--muted)' }}>CNAME chain</span>
                          <span style={{ fontFamily: 'var(--font-mono)' }}>{d.cnames.join(' → ') || '—'}</span>
                          <span style={{ color: 'var(--muted)' }}>All clients</span>
                          <span style={{ fontFamily: 'var(--font-mono)' }}>{d.clients.join(', ') || '—'}</span>
                          <span style={{ color: 'var(--muted)' }}>First seen</span>
                          <span style={{ fontFamily: 'var(--font-mono)' }}>{d.first_seen || '—'}</span>
                          <span style={{ color: 'var(--muted)' }}>Last seen</span>
                          <span style={{ fontFamily: 'var(--font-mono)' }}>{d.last_seen || '—'}</span>
                          <span style={{ color: 'var(--muted)' }}>Label entropy</span>
                          <span style={{ fontFamily: 'var(--font-mono)' }}>{d.entropy} bits/char</span>
                        </div>
                      </td>
                    </tr>
                  )}
                </Fragment>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// DNS query-type numeric codes → mnemonics (subset; tshark sometimes emits ints).
function rrName(t) {
  const map = { '1': 'A', '2': 'NS', '5': 'CNAME', '6': 'SOA', '12': 'PTR',
                '15': 'MX', '16': 'TXT', '28': 'AAAA', '33': 'SRV', '99': 'SPF',
                '255': 'ANY', '257': 'CAA' }
  return map[t] || t
}
