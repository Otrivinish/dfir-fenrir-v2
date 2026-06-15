import { useCallback, useEffect, useState } from 'react'
import { useOutletContext } from 'react-router-dom'
import { useAuth } from '../../../hooks/useAuth.jsx'
import { api } from '../../../api/client.js'
import { formatLocal, relative } from '../../../lib/datetime.js'

const STATUS_LABEL = {
  ready:    'Ready',
  consumed: 'Consumed',
  expired:  'Expired',
  revoked:  'Revoked',
  pending:  'Pending',
}
const STATUS_PILL = {
  ready:    'pill-ok',
  consumed: 'pill-gray',
  expired:  'pill-gray',
  revoked:  'pill-crit',
  pending:  'pill-med',
}

function shorten(s, n = 12) {
  if (!s) return '—'
  return s.length > n ? `${s.slice(0, n)}…` : s
}

function fmtBytes(n) {
  if (!n && n !== 0) return '—'
  const units = ['B', 'KiB', 'MiB', 'GiB']
  let v = n, i = 0
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++ }
  return `${v.toFixed(i === 0 ? 0 : 1)} ${units[i]}`
}

export default function Export() {
  const { inc } = useOutletContext()
  const { user } = useAuth()
  const isAdmin = user?.role === 'admin'

  const [items, setItems]     = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError]     = useState(null)
  const [wizard, setWizard]   = useState(null)   // null | { stage, ... }

  const load = useCallback(async () => {
    setError(null)
    try {
      const res = await api.listExports(inc.id, { limit: 200 })
      setItems(res.items)
    } catch (e) {
      // Non-admins get 403 here — that's expected; show a friendlier message.
      if (e.status === 403) setError(null)
      else setError(e.message || 'Could not load exports')
    } finally {
      setLoading(false)
    }
  }, [inc.id])

  useEffect(() => { load() }, [load])

  if (!isAdmin) {
    return (
      <div className="panel">
        <div className="panel-empty">
          <div className="panel-empty-mark" aria-hidden="true">⇪</div>
          <div>Evidence exports are admin only.</div>
          <div style={{ color: 'var(--dim)', fontSize: 12 }}>
            Ask an administrator to generate the legal handoff bundle.
          </div>
        </div>
      </div>
    )
  }

  return (
    <section className="panel">
      <div className="panel-toolbar">
        <h2 className="panel-h">Evidence exports</h2>
        <button
          type="button"
          className="btn primary"
          onClick={() => setWizard({ stage: 'pick' })}
        >+ New export</button>
      </div>

      {error && (
        <div className="alert error" role="alert">
          <span className="alert-icon">!</span><span>{error}</span>
        </div>
      )}

      {loading ? (
        <div className="panel-empty"><div>Loading…</div></div>
      ) : items.length === 0 ? (
        <div className="panel-empty">
          <div className="panel-empty-mark" aria-hidden="true">⇪</div>
          <div>No exports yet.</div>
          <div style={{ color: 'var(--dim)', fontSize: 12 }}>
            Click "+ New export" to build a legal handoff bundle.
          </div>
        </div>
      ) : (
        <table className="settings-table">
          <thead>
            <tr>
              <th>Recipient</th>
              <th>Items</th>
              <th>Size</th>
              <th>Bundle SHA-256</th>
              <th>Created</th>
              <th>Expires</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {items.map(e => (
              <tr key={e.id}>
                <td>
                  <div style={{ fontWeight: 600 }}>{e.recipient}</div>
                  <div style={{ color: 'var(--muted)', fontSize: 11 }}
                       title={e.purpose}>
                    {shorten(e.purpose, 60)}
                  </div>
                </td>
                <td style={{ fontFamily: 'var(--font-mono)' }}>{e.item_ids?.length || 0}</td>
                <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>{fmtBytes(e.file_size)}</td>
                <td>
                  {e.bundle_sha256 ? (
                    <button
                      type="button"
                      className="btn ghost"
                      onClick={() => navigator.clipboard?.writeText(e.bundle_sha256)}
                      title={`Click to copy:\n${e.bundle_sha256}`}
                      style={{ padding: '2px 6px', fontFamily: 'var(--font-mono)', fontSize: 10, fontWeight: 400 }}
                    >{e.bundle_sha256.slice(0, 12)}…</button>
                  ) : <span style={{ color: 'var(--dim)' }}>—</span>}
                </td>
                <td title={formatLocal(e.created_at)} style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--muted)' }}>
                  {relative(e.created_at)}
                </td>
                <td title={formatLocal(e.expires_at)} style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--muted)' }}>
                  {relative(e.expires_at)}
                </td>
                <td>
                  <span className={`pill ${STATUS_PILL[e.status] || 'pill-gray'}`}>
                    {STATUS_LABEL[e.status] || e.status}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {wizard && (
        <ExportWizard
          incidentId={inc.id}
          onClose={() => setWizard(null)}
          onCreated={() => { load() }}
        />
      )}
    </section>
  )
}

// ── Wizard: pick → details → result ────────────────────────────────────────

function ExportWizard({ incidentId, onClose, onCreated }) {
  const [stage, setStage] = useState('pick')          // pick | details | result
  const [evidenceItems, setEvidenceItems] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError]     = useState(null)
  const [picked, setPicked]   = useState(new Set())

  const [recipient, setRecipient]             = useState('')
  const [purpose, setPurpose]                 = useState('')
  const [acknowledgments, setAcknowledgments] = useState('')

  const [busy, setBusy]   = useState(false)
  const [result, setResult] = useState(null)          // { export, key, download_url, bundle_sha256 }

  useEffect(() => {
    let cancelled = false
    api.listEvidence(incidentId, { limit: 200 })
      .then(res => { if (!cancelled) setEvidenceItems(res.items) })
      .catch(e => { if (!cancelled) setError(e.message || 'Could not load evidence') })
      .finally(() => { if (!cancelled) setLoading(false) })
    return () => { cancelled = true }
  }, [incidentId])

  useEffect(() => {
    const onKey = (e) => {
      if (e.key === 'Escape' && !busy && stage !== 'result') onClose()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [busy, stage, onClose])

  const togglePick = (id) => {
    setPicked(prev => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id); else next.add(id)
      return next
    })
  }

  const create = async () => {
    setError(null); setBusy(true)
    try {
      const res = await api.createExport(incidentId, {
        item_ids:        Array.from(picked),
        recipient:       recipient.trim(),
        purpose:         purpose.trim(),
        acknowledgments: acknowledgments.trim() || null,
      })
      setResult(res)
      setStage('result')
      onCreated()
    } catch (e) {
      setError(e.message || 'Could not create export')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div
      className="modal-backdrop"
    >
      <div className="modal" role="dialog" aria-labelledby="ex-wiz-title" style={{ width: 'min(720px, 96vw)' }}>
        <div className="modal-head">
          <h2 id="ex-wiz-title">
            {stage === 'pick'    && 'New export — pick items'}
            {stage === 'details' && 'New export — recipient + purpose'}
            {stage === 'result'  && 'Export ready — key shown ONCE'}
          </h2>
          {stage !== 'result' && (
            <button type="button" className="modal-close" onClick={onClose} disabled={busy}>×</button>
          )}
        </div>

        {stage === 'pick' && (
          <>
            <div className="modal-body">
              {loading ? (
                <div style={{ color: 'var(--muted)' }}>Loading evidence…</div>
              ) : evidenceItems.length === 0 ? (
                <div className="panel-empty">
                  <div>No evidence in this incident to export.</div>
                </div>
              ) : (
                <ItemPicker items={evidenceItems} picked={picked} onToggle={togglePick} />
              )}
              {error && (
                <div className="alert error" role="alert" style={{ marginTop: 'var(--space-3)' }}>
                  <span className="alert-icon">!</span><span>{error}</span>
                </div>
              )}
            </div>
            <div className="modal-foot">
              <button type="button" className="btn ghost" onClick={onClose} disabled={busy}>Cancel</button>
              <button
                type="button"
                className="btn primary"
                onClick={() => setStage('details')}
                disabled={picked.size === 0 || loading}
              >
                Continue ({picked.size} selected)
              </button>
            </div>
          </>
        )}

        {stage === 'details' && (
          <>
            <div className="modal-body">
              <div className="form">
                <div className="field">
                  <label className="field-label" htmlFor="ex-recipient">Recipient</label>
                  <input
                    id="ex-recipient" className="input"
                    value={recipient} onChange={(e) => setRecipient(e.target.value)}
                    autoFocus required maxLength={256}
                    placeholder="e.g. Det. Jane Doe — Cybercrime Unit, jdoe@agency.example"
                  />
                </div>
                <div className="field">
                  <label className="field-label" htmlFor="ex-purpose">Purpose / authorisation</label>
                  <textarea
                    id="ex-purpose" className="input"
                    value={purpose} onChange={(e) => setPurpose(e.target.value)}
                    required rows={3} maxLength={4096}
                    placeholder="e.g. Court-ordered handoff per case #2026-CR-042, dated 2026-05-11"
                  />
                </div>
                <div className="field">
                  <label className="field-label" htmlFor="ex-ack">Acknowledgments (optional)</label>
                  <textarea
                    id="ex-ack" className="input"
                    value={acknowledgments} onChange={(e) => setAcknowledgments(e.target.value)}
                    rows={2} maxLength={4096}
                    placeholder="Any chain-of-custody acknowledgments recipient must agree to"
                  />
                </div>
                <div className="alert info" role="status">
                  <span className="alert-icon">i</span>
                  <span>
                    The ephemeral AES-256 key is shown <b>once</b> after creation and is never
                    retrievable again. Deliver it to the recipient out-of-band
                    (Signal, encrypted email, in person). The download URL is single-use and expires in 24 hours.
                  </span>
                </div>
                {error && (
                  <div className="alert error" role="alert">
                    <span className="alert-icon">!</span><span>{error}</span>
                  </div>
                )}
              </div>
            </div>
            <div className="modal-foot">
              <button type="button" className="btn ghost" onClick={() => setStage('pick')} disabled={busy}>← Back</button>
              <button
                type="button"
                className="btn primary"
                onClick={create}
                disabled={busy || !recipient.trim() || !purpose.trim()}
              >
                {busy ? 'Building bundle…' : 'Create export'}
              </button>
            </div>
          </>
        )}

        {stage === 'result' && result && (
          <ResultPanel result={result} onClose={onClose} />
        )}
      </div>
    </div>
  )
}

function ItemPicker({ items, picked, onToggle }) {
  const allSelected = picked.size === items.length
  const someSelected = picked.size > 0 && !allSelected

  return (
    <div>
      <div style={{ marginBottom: 'var(--space-2)', display: 'flex', gap: 'var(--space-2)', alignItems: 'center' }}>
        <button
          type="button"
          className="btn ghost"
          onClick={() => {
            if (allSelected) picked.clear()
            else items.forEach(i => picked.add(i.id))
            onToggle('') // force render via fake toggle (set already mutated)
          }}
        >{allSelected ? 'Unselect all' : 'Select all'}</button>
        <span style={{ color: 'var(--muted)', fontSize: 12 }}>
          {picked.size} of {items.length} selected
        </span>
      </div>
      <table className="settings-table">
        <thead>
          <tr>
            <th style={{ width: 32 }}></th>
            <th>Kind</th>
            <th>Name / identifier</th>
            <th>SHA-256</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          {items.map(i => {
            const isChecked = picked.has(i.id)
            return (
              <tr key={i.id} style={{ cursor: 'pointer' }} onClick={() => onToggle(i.id)}>
                <td>
                  <input
                    type="checkbox"
                    checked={isChecked}
                    onChange={() => onToggle(i.id)}
                    onClick={(e) => e.stopPropagation()}
                  />
                </td>
                <td>
                  <span className="pill">{i.kind === 'digital_file' ? 'File' : 'Physical'}</span>
                </td>
                <td>
                  <div style={{ fontWeight: 600 }}>{i.name}</div>
                  <div style={{ color: 'var(--muted)', fontFamily: 'var(--font-mono)', fontSize: 11 }}>{i.identifier}</div>
                </td>
                <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--muted)' }}>
                  {i.sha256 ? `${i.sha256.slice(0, 12)}…` : '—'}
                </td>
                <td><span className="pill">{i.status}</span></td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

function ResultPanel({ result, onClose }) {
  const [keyCopied, setKeyCopied] = useState(false)
  const [urlCopied, setUrlCopied] = useState(false)
  const fullUrl = `${window.location.origin}${result.download_url}`

  return (
    <>
      <div className="modal-body">
        <div className="alert warn" role="status" style={{ marginBottom: 'var(--space-3)' }}>
          <span className="alert-icon">!</span>
          <span>
            <b>This is the only time the key is shown.</b> Copy it now and deliver
            it to <b>{result.export.recipient}</b> out-of-band. You will not be able
            to retrieve the key again. If lost, you must create a new export.
          </span>
        </div>

        <dl className="kv">
          <dt>Recipient</dt><dd>{result.export.recipient}</dd>
          <dt>Items</dt><dd>{result.export.item_ids?.length || 0}</dd>
          <dt>Bundle size</dt><dd>{fmtBytes(result.export.file_size)}</dd>
          <dt>Expires</dt><dd style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>{formatLocal(result.export.expires_at)}</dd>
          <dt>Bundle SHA-256</dt>
          <dd style={{ fontFamily: 'var(--font-mono)', fontSize: 11, wordBreak: 'break-all' }}>
            {result.bundle_sha256}
          </dd>
          <dt>Key hint</dt>
          <dd style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>{result.export.key_hint}</dd>
        </dl>

        <h3 className="panel-h" style={{ marginTop: 'var(--space-4)' }}>One-time AES-256 key</h3>
        <div style={{
          fontFamily: 'var(--font-mono)', fontSize: 12, padding: 'var(--space-3)',
          background: 'var(--surface-2)', border: '1px solid var(--crit)',
          borderRadius: 'var(--radius)', wordBreak: 'break-all', userSelect: 'all',
        }}>
          {result.key}
        </div>
        <div style={{ display: 'flex', gap: 'var(--space-2)', marginTop: 'var(--space-2)' }}>
          <button
            type="button"
            className="btn"
            onClick={() => {
              navigator.clipboard?.writeText(result.key)
              setKeyCopied(true)
              setTimeout(() => setKeyCopied(false), 2000)
            }}
          >
            {keyCopied ? 'Copied ✓' : 'Copy key'}
          </button>
        </div>

        <h3 className="panel-h" style={{ marginTop: 'var(--space-4)' }}>Download URL (single use, 24h)</h3>
        <div style={{
          fontFamily: 'var(--font-mono)', fontSize: 12, padding: 'var(--space-3)',
          background: 'var(--surface-2)', border: '1px solid var(--border)',
          borderRadius: 'var(--radius)', wordBreak: 'break-all',
        }}>
          {fullUrl}
        </div>
        <div style={{ display: 'flex', gap: 'var(--space-2)', marginTop: 'var(--space-2)' }}>
          <button
            type="button"
            className="btn"
            onClick={() => {
              navigator.clipboard?.writeText(fullUrl)
              setUrlCopied(true)
              setTimeout(() => setUrlCopied(false), 2000)
            }}
          >
            {urlCopied ? 'Copied ✓' : 'Copy URL'}
          </button>
          <a className="btn primary" href={result.download_url} target="_blank" rel="noreferrer">
            Download now (consumes the URL)
          </a>
        </div>

        <DecryptionInstructions bundleSha={result.bundle_sha256} />

        <div className="alert info" role="status" style={{ marginTop: 'var(--space-3)' }}>
          <span className="alert-icon">i</span>
          <span>
            Send the recipient the AES-256 key, the download URL, the bundle
            SHA-256 (for integrity verification), and the decryption recipe above.
            The README inside the bundle restates these instructions for their records.
          </span>
        </div>
      </div>
      <div className="modal-foot">
        <button type="button" className="btn primary" onClick={onClose}>I've copied the key — close</button>
      </div>
    </>
  )
}

// ── Decryption instructions panel ──────────────────────────────────────────
// Shown alongside the key so the sender can deliver the recipe out-of-band
// without the recipient needing to open the (encrypted) README first.
function DecryptionInstructions({ bundleSha }) {
  const [copied, setCopied] = useState(false)
  const recipe = `# Python 3 — requires: pip install cryptography
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import hashlib, sys

bundle = open(sys.argv[1], "rb").read()
# (Optional) Verify integrity against the bundle SHA-256 provided by sender:
#   expected = "${bundleSha || '<bundle-sha-256-hex>'}"
#   assert hashlib.sha256(bundle).hexdigest() == expected, "bundle hash mismatch"

nonce, ct = bundle[:12], bundle[12:]
key = bytes.fromhex(sys.argv[2])
plain = AESGCM(key).decrypt(nonce, ct, None)
open(sys.argv[1] + ".zip", "wb").write(plain)
# Output: <bundle>.zip — standard ZIP containing files/, coc/, audit/, manifest.json, README.txt`

  const oneliner = `python3 decrypt.py bundle.enc <key-hex>`

  return (
    <>
      <h3 className="panel-h" style={{ marginTop: 'var(--space-4)' }}>Decryption instructions</h3>
      <div style={{ fontSize: 12, color: 'var(--muted)', marginBottom: 'var(--space-2)' }}>
        Send this recipe with the key + URL so the recipient can open the bundle.
        AES-256-GCM, wire format <code style={{ fontFamily: 'var(--font-mono)' }}>[12-byte nonce][ciphertext + 16-byte GCM tag]</code>.
      </div>
      <pre style={{
        fontFamily: 'var(--font-mono)', fontSize: 11, padding: 'var(--space-3)',
        background: 'var(--surface-2)', border: '1px solid var(--border)',
        borderRadius: 'var(--radius)', overflowX: 'auto', margin: 0,
        whiteSpace: 'pre-wrap', wordBreak: 'break-all', color: 'var(--text)',
      }}>{recipe}</pre>
      <div style={{ display: 'flex', gap: 'var(--space-2)', marginTop: 'var(--space-2)', flexWrap: 'wrap', alignItems: 'center' }}>
        <button
          type="button"
          className="btn"
          onClick={() => {
            navigator.clipboard?.writeText(recipe)
            setCopied(true)
            setTimeout(() => setCopied(false), 2000)
          }}
        >
          {copied ? 'Copied ✓' : 'Copy recipe'}
        </button>
        <span style={{ fontSize: 11, color: 'var(--muted)' }}>
          Save as <code style={{ fontFamily: 'var(--font-mono)' }}>decrypt.py</code> and run:
        </span>
        <code style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--accent)', background: 'var(--surface-2)', padding: '2px 6px', borderRadius: 3 }}>
          {oneliner}
        </code>
      </div>
    </>
  )
}
