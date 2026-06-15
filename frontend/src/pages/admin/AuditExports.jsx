// Admin: signed audit-log exports.
//   • Filter form → Generate (key shown ONCE) → download URL.
//   • History list with status, row count, bundle/JSONL hashes, pubkey fingerprint.
//   • Offline verifier — WebCrypto verifies bundle audit.jsonl against audit.jsonl.sig
//     using public_key.pem (or any pasted PEM). No server round-trip.
//
// All writes are admin-only at the backend; this page is mounted under
// <RequireAdmin> (Admin shell already enforces that).

import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { api } from '../../api/client.js'
import { formatLocal, relative } from '../../lib/datetime.js'
import UtcDateTimeInput from '../../components/UtcDateTimeInput.jsx'

// ─── Helpers ─────────────────────────────────────────────────────────────────

function statusColor(s) {
  if (s === 'ready')    return 'var(--ok)'
  if (s === 'consumed') return 'var(--muted)'
  if (s === 'expired')  return 'var(--high)'
  if (s === 'purged')   return 'var(--dim)'
  return 'var(--dim)'
}

function shortHash(h) {
  return h ? h.slice(0, 12) + '…' : '—'
}

function rowScopeLabel(row) {
  if (!row.incident_id) return 'global'
  return `incident:${row.incident_id.slice(0, 8)}`
}

// ─── Generate modal ──────────────────────────────────────────────────────────

function GenerateModal({ onClose, onCreated }) {
  const [dateFrom, setDateFrom]     = useState('')
  const [dateTo,   setDateTo]       = useState('')
  const [action,   setAction]       = useState('')
  const [username, setUsername]     = useState('')
  const [resourceType, setResourceType] = useState('')
  const [outcome,  setOutcome]      = useState('')
  const [purpose,  setPurpose]      = useState('')
  const [busy,     setBusy]         = useState(false)
  const [error,    setError]        = useState(null)
  const [result,   setResult]       = useState(null)
  const [keyShown, setKeyShown]     = useState(false)

  const submit = async () => {
    setBusy(true); setError(null)
    try {
      const filters = {
        date_from:     dateFrom    || null,
        date_to:       dateTo      || null,
        action:        action.trim()       || null,
        username:      username.trim()     || null,
        resource_type: resourceType.trim() || null,
        outcome:       outcome             || null,
      }
      const payload = { purpose: purpose.trim() || null, filters }
      const r = await api.createGlobalAuditExport(payload)
      setResult(r)
      onCreated?.(r)
    } catch (e) {
      setError(e.message || 'Generation failed')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="modal-backdrop">
      <div className="modal" role="dialog" aria-labelledby="ae-gen-title" style={{ maxWidth: 560 }}>
        <div className="modal-head">
          <h2 id="ae-gen-title">Generate audit-log export</h2>
          <button type="button" className="modal-close" onClick={onClose} disabled={busy} aria-label="Close">×</button>
        </div>

        {!result && (
          <>
            <div className="modal-body" style={{ display: 'grid', gap: 'var(--space-3)' }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--space-2)' }}>
                <label style={{ display: 'grid', gap: 4, fontSize: 12 }}>
                  <span style={{ color: 'var(--muted)' }}>From (UTC)</span>
                  <UtcDateTimeInput value={dateFrom} onChange={setDateFrom} hint={false} />
                </label>
                <label style={{ display: 'grid', gap: 4, fontSize: 12 }}>
                  <span style={{ color: 'var(--muted)' }}>To (UTC)</span>
                  <UtcDateTimeInput value={dateTo} onChange={setDateTo} hint={false} />
                </label>
              </div>
              <label style={{ display: 'grid', gap: 4, fontSize: 12 }}>
                <span style={{ color: 'var(--muted)' }}>Action (substring)</span>
                <input value={action} onChange={e => setAction(e.target.value)} placeholder="e.g. login" className="input" />
              </label>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--space-2)' }}>
                <label style={{ display: 'grid', gap: 4, fontSize: 12 }}>
                  <span style={{ color: 'var(--muted)' }}>Username</span>
                  <input value={username} onChange={e => setUsername(e.target.value)} className="input" />
                </label>
                <label style={{ display: 'grid', gap: 4, fontSize: 12 }}>
                  <span style={{ color: 'var(--muted)' }}>Resource type</span>
                  <input value={resourceType} onChange={e => setResourceType(e.target.value)} className="input" />
                </label>
              </div>
              <label style={{ display: 'grid', gap: 4, fontSize: 12 }}>
                <span style={{ color: 'var(--muted)' }}>Outcome</span>
                <select value={outcome} onChange={e => setOutcome(e.target.value)} className="input">
                  <option value="">— any —</option>
                  <option value="success">success</option>
                  <option value="failure">failure</option>
                  <option value="denied">denied</option>
                </select>
              </label>
              <label style={{ display: 'grid', gap: 4, fontSize: 12 }}>
                <span style={{ color: 'var(--muted)' }}>Purpose (recorded in manifest + audit chain)</span>
                <textarea
                  value={purpose} onChange={e => setPurpose(e.target.value)}
                  rows={2} className="input"
                  placeholder="e.g. regulator subpoena ABC-123 / internal review"
                />
              </label>
              {error && <div className="alert err">{error}</div>}
              <div style={{ fontSize: 11, color: 'var(--dim)' }}>
                Slice ceiling is 50,000 rows. Tighten filters if your scope is broader.
                Bundle on disk retains for 30 days; the download token is single-use, 24 h.
              </div>
            </div>
            <div className="modal-foot">
              <button type="button" className="btn ghost" onClick={onClose} disabled={busy}>Cancel</button>
              <button type="button" className="btn primary" onClick={submit} disabled={busy}>
                {busy ? 'Generating…' : 'Generate'}
              </button>
            </div>
          </>
        )}

        {result && (
          <>
            <div className="modal-body" style={{ display: 'grid', gap: 'var(--space-3)' }}>
              <div className="alert ok">
                <b>Password — copy it now.</b> Shown ONCE. The platform does not store it;
                lose it and the encrypted ZIP is unrecoverable. Deliver out-of-band to the
                recipient (Signal, in-person, etc.) — never alongside the download URL.
              </div>

              <div style={{ display: 'grid', gap: 6 }}>
                <label style={{ fontSize: 12, color: 'var(--muted)' }}>Bundle password (AES-256 ZIP)</label>
                <div style={{ position: 'relative' }}>
                  <input
                    readOnly
                    value={keyShown ? result.bundle_password : '••••••••••••••••••••••••'}
                    className="input"
                    style={{ fontFamily: 'var(--font-mono)', fontSize: 13, paddingRight: 80 }}
                  />
                  <button
                    type="button"
                    onClick={() => setKeyShown(s => !s)}
                    style={{
                      position: 'absolute', right: 4, top: 4, bottom: 4,
                      padding: '0 8px', fontSize: 11,
                      background: 'var(--surface)', border: '1px solid var(--border)',
                      color: 'var(--text)', borderRadius: 'var(--radius-sm)',
                    }}
                  >{keyShown ? 'Hide' : 'Reveal'}</button>
                </div>
                <button
                  type="button" className="btn"
                  onClick={() => navigator.clipboard?.writeText(result.bundle_password)}
                >Copy password to clipboard</button>
              </div>

              <div style={{ display: 'grid', gap: 6 }}>
                <label style={{ fontSize: 12, color: 'var(--muted)' }}>Download URL (single-use, 24 h)</label>
                <input readOnly value={result.download_url} className="input"
                       style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }} />
                <a
                  href={result.download_url}
                  className="btn primary"
                  style={{ textAlign: 'center' }}
                  download
                >Download bundle (.zip)</a>
                <div style={{ fontSize: 11, color: 'var(--muted)', marginTop: 4 }}>
                  Recipient opens with any standard archive tool — double-click on macOS,
                  7-Zip / WinRAR on Windows, <code>unzip -P</code> on Linux. Inside the ZIP
                  is the signed audit JSONL + PDF + verification README.
                </div>
              </div>

              <details>
                <summary style={{ cursor: 'pointer', fontSize: 12, color: 'var(--muted)' }}>Integrity details</summary>
                <div style={{ display: 'grid', gap: 4, fontSize: 11, fontFamily: 'var(--font-mono)', marginTop: 8 }}>
                  <div><span style={{ color: 'var(--muted)' }}>row_count   </span>{result.row_count}</div>
                  <div><span style={{ color: 'var(--muted)' }}>bundle_sha256 </span>{result.bundle_sha256}</div>
                  <div><span style={{ color: 'var(--muted)' }}>jsonl_sha256  </span>{result.jsonl_sha256}</div>
                  <div><span style={{ color: 'var(--muted)' }}>pubkey_fpr    </span>{result.pubkey_fpr}</div>
                  <div><span style={{ color: 'var(--muted)' }}>chain_head    </span>{result.chain_head_hash}</div>
                </div>
              </details>
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

// ─── Offline verifier ────────────────────────────────────────────────────────
// Verifies an audit.jsonl ↔ audit.jsonl.sig pair against a PEM public key,
// purely in the browser via WebCrypto. No server round-trip; no upload.

function VerifierCard({ defaultPem }) {
  const [pem,        setPem]       = useState(defaultPem || '')
  const [jsonlFile,  setJsonlFile] = useState(null)
  const [sigFile,    setSigFile]   = useState(null)
  const [result,     setResult]    = useState(null)
  const [busy,       setBusy]      = useState(false)
  const [err,        setErr]       = useState(null)

  useEffect(() => { if (defaultPem && !pem) setPem(defaultPem) }, [defaultPem, pem])

  // PEM → SubjectPublicKeyInfo (DER) → CryptoKey
  async function importPem(pemText) {
    const trimmed = pemText
      .replace(/-----BEGIN PUBLIC KEY-----/, '')
      .replace(/-----END PUBLIC KEY-----/, '')
      .replace(/\s+/g, '')
    const der = Uint8Array.from(atob(trimmed), c => c.charCodeAt(0))
    return crypto.subtle.importKey(
      'spki', der,
      { name: 'Ed25519' },
      true,
      ['verify'],
    )
  }

  async function fpr(spkiPem) {
    // SHA-256 of the RAW 32-byte public key bytes (not SPKI). The last 32
    // bytes of an Ed25519 SPKI are the raw key (12-byte SPKI prefix + 32-byte key).
    const trimmed = spkiPem
      .replace(/-----BEGIN PUBLIC KEY-----/, '')
      .replace(/-----END PUBLIC KEY-----/, '')
      .replace(/\s+/g, '')
    const der = Uint8Array.from(atob(trimmed), c => c.charCodeAt(0))
    const raw = der.slice(der.length - 32)
    const hash = await crypto.subtle.digest('SHA-256', raw)
    return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('')
  }

  async function verify() {
    setBusy(true); setErr(null); setResult(null)
    try {
      if (!pem.includes('BEGIN PUBLIC KEY')) throw new Error('Public key must be in PEM format.')
      if (!jsonlFile)  throw new Error('Select the audit.jsonl file from the bundle.')
      if (!sigFile)    throw new Error('Select the audit.jsonl.sig file from the bundle.')
      const [jsonlBytes, sigBytes] = await Promise.all([jsonlFile.arrayBuffer(), sigFile.arrayBuffer()])
      const sigArr = new Uint8Array(sigBytes)
      if (sigArr.length !== 64) throw new Error(`audit.jsonl.sig must be 64 bytes; got ${sigArr.length}.`)
      const key = await importPem(pem)
      const ok = await crypto.subtle.verify('Ed25519', key, sigArr, jsonlBytes)
      const fp = await fpr(pem)
      const jsonlHash = await crypto.subtle.digest('SHA-256', jsonlBytes)
      const jsonlHex  = Array.from(new Uint8Array(jsonlHash)).map(b => b.toString(16).padStart(2, '0')).join('')
      setResult({ ok, fpr: fp, jsonl_sha256: jsonlHex })
    } catch (e) {
      setErr(e.message || 'Verification failed.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div style={{
      background: 'var(--surface-2)',
      border:     '1px solid var(--border)',
      borderRadius: 'var(--radius)',
      padding:    'var(--space-3)',
      display:    'grid',
      gap:        'var(--space-2)',
    }}>
      <div style={{ fontWeight: 600, fontSize: 13 }}>Offline verifier</div>
      <div style={{ fontSize: 11, color: 'var(--muted)' }}>
        Verify an unzipped <code>audit.jsonl</code> against its <code>audit.jsonl.sig</code> using
        the platform Ed25519 public key (pre-filled) or a pasted PEM. WebCrypto runs the verification
        in your browser — no data leaves this page.
      </div>
      <label style={{ display: 'grid', gap: 4, fontSize: 12 }}>
        <span style={{ color: 'var(--muted)' }}>Public key (PEM)</span>
        <textarea
          rows={5} value={pem} onChange={e => setPem(e.target.value)}
          className="input" style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}
        />
      </label>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--space-2)' }}>
        <label style={{ display: 'grid', gap: 4, fontSize: 12 }}>
          <span style={{ color: 'var(--muted)' }}>audit.jsonl</span>
          <input type="file" onChange={e => setJsonlFile(e.target.files?.[0] || null)} />
        </label>
        <label style={{ display: 'grid', gap: 4, fontSize: 12 }}>
          <span style={{ color: 'var(--muted)' }}>audit.jsonl.sig</span>
          <input type="file" onChange={e => setSigFile(e.target.files?.[0] || null)} />
        </label>
      </div>
      <div>
        <button type="button" className="btn primary" onClick={verify} disabled={busy}>
          {busy ? 'Verifying…' : 'Verify'}
        </button>
      </div>
      {err && <div className="alert err">{err}</div>}
      {result && (
        <div className="alert" style={{
          background: result.ok ? 'var(--surface-2)' : 'rgba(248,81,73,0.12)',
          border:     `1px solid ${result.ok ? 'var(--ok)' : 'var(--crit)'}`,
          color:      'var(--text)',
        }}>
          <b>{result.ok ? '✓ Signature valid' : '✗ Signature INVALID'}</b>
          <div style={{ fontSize: 11, fontFamily: 'var(--font-mono)', marginTop: 4 }}>
            pubkey_fpr   {result.fpr}<br/>
            jsonl_sha256 {result.jsonl_sha256}
          </div>
        </div>
      )}
    </div>
  )
}

// ─── Page ────────────────────────────────────────────────────────────────────

export default function AuditExports() {
  const [items,  setItems]  = useState([])
  const [loading, setLoading] = useState(true)
  const [error,  setError]   = useState(null)
  const [genOpen, setGenOpen] = useState(false)
  const [scope,   setScope]   = useState('')     // '' | 'global' | 'incident'
  const [pem,     setPem]     = useState('')
  const [pemFpr,  setPemFpr]  = useState('')

  const reload = useCallback(async () => {
    setLoading(true); setError(null)
    try {
      const r = await api.listGlobalAuditExports(scope ? { scope } : {})
      setItems(r.items || [])
    } catch (e) {
      setError(e.message || 'Load failed')
    } finally {
      setLoading(false)
    }
  }, [scope])

  useEffect(() => { reload() }, [reload])

  useEffect(() => {
    let alive = true
    api.getVersion().then(v => {
      if (!alive) return
      setPem(v?.audit_signing?.public_key || '')
      setPemFpr(v?.audit_signing?.fingerprint || '')
    }).catch(() => {})
    return () => { alive = false }
  }, [])

  return (
    <div style={{ display: 'grid', gap: 'var(--space-4)' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div>
          <h2 style={{ margin: 0, fontSize: 16 }}>Audit exports</h2>
          <div style={{ color: 'var(--muted)', fontSize: 12, marginTop: 2 }}>
            Signed PDF + JSONL extracts of the tamper-evident audit log. Bundle on disk retains 30d;
            download token single-use, 24h. Ed25519 fingerprint:{' '}
            <span style={{ fontFamily: 'var(--font-mono)' }}>{pemFpr || '—'}</span>
          </div>
        </div>
        <div style={{ display: 'flex', gap: 'var(--space-2)' }}>
          <select value={scope} onChange={e => setScope(e.target.value)} className="input" style={{ width: 160 }}>
            <option value="">All scopes</option>
            <option value="global">Global</option>
            <option value="incident">Incident-scoped</option>
          </select>
          <button className="btn primary" onClick={() => setGenOpen(true)}>+ Generate</button>
        </div>
      </div>

      {error && <div className="alert err">{error}</div>}

      <div style={{
        background:   'var(--surface-2)',
        border:       '1px solid var(--border)',
        borderRadius: 'var(--radius)',
        overflow:     'hidden',
      }}>
        <div style={{
          display: 'grid',
          gridTemplateColumns: '170px 90px 70px 90px 1fr 130px 60px',
          gap: 'var(--space-3)',
          padding: 'var(--space-2) var(--space-3)',
          background: 'var(--surface)',
          fontSize: 11, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: 0.4,
        }}>
          <div>Created</div>
          <div>Scope</div>
          <div>Rows</div>
          <div>Status</div>
          <div>Bundle SHA</div>
          <div>JSONL SHA</div>
          <div></div>
        </div>
        {loading && <div style={{ padding: 'var(--space-3)', color: 'var(--muted)' }}>Loading…</div>}
        {!loading && items.length === 0 && (
          <div style={{ padding: 'var(--space-3)', color: 'var(--dim)' }}>
            No audit exports yet. Generate one with the button above.
          </div>
        )}
        {!loading && items.map(r => (
          <div key={r.id} style={{
            display: 'grid',
            gridTemplateColumns: '170px 90px 70px 90px 1fr 130px 60px',
            gap: 'var(--space-3)',
            padding: 'var(--space-2) var(--space-3)',
            borderTop: '1px solid var(--border)',
            alignItems: 'center', fontSize: 12,
          }}>
            <div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>{formatLocal(r.created_at)}</div>
              <div style={{ fontSize: 10, color: 'var(--dim)' }}>{relative(r.created_at)}</div>
            </div>
            <div style={{ fontSize: 11 }}>{rowScopeLabel(r)}</div>
            <div style={{ fontFamily: 'var(--font-mono)' }}>{r.row_count}</div>
            <div>
              <span style={{
                display: 'inline-block', padding: '2px 8px', borderRadius: 999,
                background: 'var(--surface)', border: `1px solid ${statusColor(r.status)}`,
                color: statusColor(r.status), fontSize: 11,
              }}>{r.status}</span>
            </div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>{shortHash(r.bundle_sha256)}</div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>{shortHash(r.jsonl_sha256)}</div>
            <div style={{ textAlign: 'right' }}>
              <details>
                <summary style={{ cursor: 'pointer', fontSize: 11, color: 'var(--muted)' }}>Info</summary>
                <div style={{
                  position: 'absolute', right: 24, marginTop: 6, width: 360,
                  background: 'var(--surface)', border: '1px solid var(--border)',
                  borderRadius: 'var(--radius)', padding: 'var(--space-3)',
                  fontSize: 11, fontFamily: 'var(--font-mono)', zIndex: 5,
                  boxShadow: 'var(--shadow)',
                }}>
                  <div><span style={{ color: 'var(--muted)' }}>id            </span>{r.id}</div>
                  <div><span style={{ color: 'var(--muted)' }}>purpose       </span>{r.purpose || '—'}</div>
                  <div><span style={{ color: 'var(--muted)' }}>first_prev    </span>{shortHash(r.first_prev_hash)}</div>
                  <div><span style={{ color: 'var(--muted)' }}>last_row      </span>{shortHash(r.last_row_hash)}</div>
                  <div><span style={{ color: 'var(--muted)' }}>chain_head    </span>{shortHash(r.chain_head_hash)}</div>
                  <div><span style={{ color: 'var(--muted)' }}>pubkey_fpr    </span>{shortHash(r.pubkey_fpr)}</div>
                  <div><span style={{ color: 'var(--muted)' }}>key_hint      </span>{r.key_hint || '—'}</div>
                  <div><span style={{ color: 'var(--muted)' }}>file_size     </span>{r.file_size}</div>
                  <div><span style={{ color: 'var(--muted)' }}>expires       </span>{formatLocal(r.expires_at)}</div>
                  <div><span style={{ color: 'var(--muted)' }}>retain_until  </span>{formatLocal(r.retention_until)}</div>
                </div>
              </details>
            </div>
          </div>
        ))}
      </div>

      <VerifierCard defaultPem={pem} />

      {genOpen && (
        <GenerateModal
          onClose={() => setGenOpen(false)}
          onCreated={() => { reload() }}
        />
      )}
    </div>
  )
}
