import { useMemo, useState } from 'react'
import { useOutletContext } from 'react-router-dom'
import { api } from '../../../api/client.js'

// ─── Wallet extraction ──────────────────────────────────────────────────────
// Address-format regexes for the cryptocurrencies most commonly seen in
// ransomware demands. USDT/BNB aren't listed separately -- they ride on the
// ETH (ERC-20) or TRX (TRC-20) address format, so they're already covered.
// Known, accepted ambiguity: Litecoin's deprecated legacy P2SH addresses
// share Bitcoin's "3..." prefix -- there is no way to tell them apart from
// the address string alone, same category of false-positive risk the OSINT
// page's TLD-based domain matching already accepts.

const WALLETS = [
  {
    type: 'btc', label: 'Bitcoin (BTC)',
    patterns: [/\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b/g, /\bbc1[a-z0-9]{25,90}\b/g],
    explorer: (v) => `https://blockchair.com/bitcoin/address/${v}`,
  },
  {
    type: 'xmr', label: 'Monero (XMR)',
    patterns: [/\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b/g, /\b8[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b/g],
    explorer: null, // privacy chain -- no address-level balance/history lookup is possible
    note: 'Monero is a privacy chain — this address cannot be looked up for balance or transaction history.',
  },
  {
    type: 'eth', label: 'Ethereum (ETH)',
    patterns: [/\b0x[a-fA-F0-9]{40}\b/g],
    explorer: (v) => `https://etherscan.io/address/${v}`,
  },
  {
    type: 'ltc', label: 'Litecoin (LTC)',
    patterns: [/\b[LM][a-km-zA-HJ-NP-Z1-9]{26,33}\b/g, /\bltc1[a-z0-9]{25,90}\b/g],
    explorer: (v) => `https://blockchair.com/litecoin/address/${v}`,
  },
  {
    type: 'bch', label: 'Bitcoin Cash (BCH)',
    patterns: [/\b(?:bitcoincash:)?[qp][a-z0-9]{41}\b/g],
    explorer: (v) => `https://blockchair.com/bitcoin-cash/address/${v.replace(/^bitcoincash:/, '')}`,
  },
  {
    type: 'dash', label: 'Dash',
    patterns: [/\bX[1-9A-HJ-NP-Za-km-z]{33}\b/g],
    explorer: (v) => `https://blockchair.com/dash/address/${v}`,
  },
  {
    type: 'zec', label: 'Zcash (ZEC)',
    patterns: [/\bt[13][0-9A-Za-z]{33}\b/g],
    explorer: (v) => `https://blockchair.com/zcash/address/${v}`,
  },
  {
    type: 'xrp', label: 'Ripple (XRP)',
    patterns: [/\br[0-9A-Za-z]{24,34}\b/g],
    explorer: (v) => `https://xrpscan.com/account/${v}`,
  },
  {
    type: 'trx', label: 'Tron (TRX)',
    patterns: [/\bT[1-9A-HJ-NP-Za-km-z]{33}\b/g],
    explorer: (v) => `https://tronscan.org/#/address/${v}`,
  },
]

function extractWallets(text) {
  const items = []
  const seen = new Set()
  for (const w of WALLETS) {
    for (const re of w.patterns) {
      for (const m of text.matchAll(re)) {
        const key = `${w.type}:${m[0]}`
        if (seen.has(key)) continue
        seen.add(key)
        items.push({ id: key, type: w.type, label: w.label, value: m[0], explorer: w.explorer, note: w.note })
      }
    }
  }
  return items
}

// ─── Ransom-note field extraction ───────────────────────────────────────────
// Plain keyword/pattern scanning, not NLP -- flags lines and substrings worth
// an analyst's attention rather than claiming to parse structured meaning.

const THREAT_KEYWORDS = [
  'deadline', 'hours', 'days', 'delete', 'destroy', 'leak', 'publish', 'expose',
  'sold', 'auction', 'double', 'increase', 'price will', 'contact us within',
  'do not', "don't", 'otherwise', 'permanently',
]
const RE_ONION   = /\b[a-z2-7]{16,56}\.onion\b/gi
const RE_EMAIL   = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g
const RE_TELEGRAM = /\bt\.me\/[A-Za-z0-9_]+\b/g
const RE_AMOUNT   = /(?:\$|USD\s?|EUR\s?|€)\s?[\d][\d,.]*|\b[\d][\d,.]*\s?(?:BTC|XMR|ETH|LTC|BCH|USD|EUR)\b/gi

function extractRansomFields(text) {
  const lines = text.split('\n').map(l => l.trim()).filter(Boolean)
  const threatLines = lines.filter(l => {
    const lower = l.toLowerCase()
    return THREAT_KEYWORDS.some(k => lower.includes(k))
  })

  const dedupe = (arr) => [...new Set(arr)]
  return {
    threatLines: dedupe(threatLines),
    onionLinks:  dedupe([...text.matchAll(RE_ONION)].map(m => m[0].toLowerCase())),
    emails:      dedupe([...text.matchAll(RE_EMAIL)].map(m => m[0].toLowerCase())),
    telegram:    dedupe([...text.matchAll(RE_TELEGRAM)].map(m => m[0])),
    amounts:     dedupe([...text.matchAll(RE_AMOUNT)].map(m => m[0].trim())),
  }
}

// ─── IOC quick-add modal (crypto wallets only) ──────────────────────────────

function AddWalletIocModal({ incidentId, wallet, onClose, onCreated }) {
  const [notes, setNotes] = useState('')
  const [busy,  setBusy]  = useState(false)
  const [error, setError] = useState(null)

  const onSubmit = async (e) => {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      await api.createIoc(incidentId, {
        type: 'crypto_wallet',
        value: wallet.value,
        notes: notes.trim() || `${wallet.label} wallet`,
        source: 'Ransomware lookup',
      })
      onCreated()
    } catch (err) {
      setError(err.message || 'Could not add IOC.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="modal-backdrop">
      <div className="modal" role="dialog" aria-labelledby="ransom-ioc-title" style={{ maxWidth: 480 }}>
        <div className="modal-head">
          <h2 id="ransom-ioc-title">Add as IOC</h2>
          <button type="button" className="modal-close" onClick={onClose} disabled={busy} aria-label="Close">×</button>
        </div>
        <form onSubmit={onSubmit}>
          <div className="modal-body">
            {error && (
              <div className="alert error" style={{ marginBottom: 'var(--space-3)' }}>
                <span className="alert-icon">!</span><span>{error}</span>
              </div>
            )}
            <div className="form">
              <div className="field">
                <label className="field-label">Type</label>
                <div style={{ fontSize: 13, color: 'var(--muted)' }}>Crypto wallet — {wallet.label}</div>
              </div>
              <div className="field">
                <label className="field-label">Value</label>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, wordBreak: 'break-all' }}>{wallet.value}</div>
              </div>
              <div className="field">
                <label className="field-label" htmlFor="ransom-ioc-notes">Notes (optional)</label>
                <textarea
                  id="ransom-ioc-notes"
                  className="input"
                  value={notes}
                  onChange={e => setNotes(e.target.value)}
                  rows={2}
                  maxLength={4096}
                  placeholder="Ransom note context, payment status observed…"
                />
              </div>
            </div>
          </div>
          <div className="modal-foot">
            <button type="button" className="btn ghost" onClick={onClose} disabled={busy}>Cancel</button>
            <button type="submit" className="btn primary" disabled={busy}>{busy ? 'Adding…' : 'Add IOC'}</button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ─── Main component ──────────────────────────────────────────────────────────

export default function Ransomware() {
  const { inc } = useOutletContext()
  const isClosed = inc?.status === 'closed'

  const [text, setText] = useState('')
  const [wallets, setWallets] = useState([])
  const [fields, setFields] = useState(null)
  const [iocTarget, setIocTarget] = useState(null)
  const [addedIds, setAddedIds] = useState(new Set())

  const onExtract = () => {
    if (!text.trim()) return
    setWallets(extractWallets(text))
    setFields(extractRansomFields(text))
  }

  const onClear = () => { setText(''); setWallets([]); setFields(null); setAddedIds(new Set()) }

  return (
    <section className="panel">
      <div className="panel-toolbar">
        <h2 className="panel-h">Ransomware Note Analysis</h2>
        <span style={{ color: 'var(--muted)', fontSize: 13 }}>
          Paste the ransom note or related text → extract wallets, deadlines, and contact channels
        </span>
      </div>

      <div style={{ marginBottom: 'var(--space-3)' }}>
        <textarea
          className="input"
          value={text}
          onChange={e => setText(e.target.value)}
          rows={8}
          placeholder="Paste the ransom note text here…"
          style={{ width: '100%', fontFamily: 'var(--font-mono)', fontSize: 12, resize: 'vertical' }}
        />
        <div style={{ display: 'flex', gap: 'var(--space-2)', marginTop: 'var(--space-2)' }}>
          <button type="button" className="btn primary" onClick={onExtract} disabled={!text.trim()}>
            Extract
          </button>
          {fields && (
            <button type="button" className="btn ghost" onClick={onClear}>Clear</button>
          )}
        </div>
      </div>

      {fields && (
        <>
          <div className="panel-toolbar" style={{ marginTop: 'var(--space-4)' }}>
            <h3 className="panel-h" style={{ margin: 0 }}>Wallet addresses ({wallets.length})</h3>
          </div>
          {wallets.length === 0 ? (
            <div className="panel-empty">No wallet addresses found.</div>
          ) : (
            <div style={{ overflowX: 'auto' }}>
              <table className="settings-table">
                <thead>
                  <tr>
                    <th style={{ width: 120 }}>Currency</th>
                    <th>Address</th>
                    <th style={{ width: 100 }}>Explorer</th>
                    <th style={{ width: 80 }}>Add IOC</th>
                  </tr>
                </thead>
                <tbody>
                  {wallets.map(w => (
                    <tr key={w.id}>
                      <td><span className="pill" style={{ fontSize: 11 }}>{w.label}</span></td>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12, wordBreak: 'break-all' }}>{w.value}</td>
                      <td>
                        {w.explorer ? (
                          <a href={w.explorer(w.value)} target="_blank" rel="noreferrer noopener" className="btn-link">
                            View
                          </a>
                        ) : (
                          <span title={w.note} style={{ color: 'var(--dim)', fontSize: 11, cursor: 'help' }}>N/A</span>
                        )}
                      </td>
                      <td>
                        {addedIds.has(w.id) ? (
                          <span style={{ color: 'var(--ok)', fontSize: 12 }}>✓ Added</span>
                        ) : (
                          <button
                            type="button"
                            className="btn ghost"
                            style={{ fontSize: 12, padding: '2px 8px' }}
                            onClick={() => setIocTarget(w)}
                            disabled={isClosed}
                          >
                            + IOC
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          <div className="panel-toolbar" style={{ marginTop: 'var(--space-4)' }}>
            <h3 className="panel-h" style={{ margin: 0 }}>Deadline / threat language ({fields.threatLines.length})</h3>
          </div>
          {fields.threatLines.length === 0 ? (
            <div className="panel-empty">No flagged lines.</div>
          ) : (
            <ul style={{ fontSize: 13, margin: 0, paddingLeft: 20 }}>
              {fields.threatLines.map((l, i) => <li key={i} style={{ marginBottom: 4 }}>{l}</li>)}
            </ul>
          )}

          <div className="panel-toolbar" style={{ marginTop: 'var(--space-4)' }}>
            <h3 className="panel-h" style={{ margin: 0 }}>Ransom amount mentions ({fields.amounts.length})</h3>
          </div>
          {fields.amounts.length === 0 ? (
            <div className="panel-empty">None found.</div>
          ) : (
            <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
              {fields.amounts.map((a, i) => <span key={i} className="pill" style={{ fontFamily: 'var(--font-mono)' }}>{a}</span>)}
            </div>
          )}

          <div className="panel-toolbar" style={{ marginTop: 'var(--space-4)' }}>
            <h3 className="panel-h" style={{ margin: 0 }}>
              Contact channels ({fields.onionLinks.length + fields.emails.length + fields.telegram.length})
            </h3>
          </div>
          {(fields.onionLinks.length + fields.emails.length + fields.telegram.length) === 0 ? (
            <div className="panel-empty">None found.</div>
          ) : (
            <div style={{ fontSize: 13, fontFamily: 'var(--font-mono)' }}>
              {fields.onionLinks.map((v, i) => (
                <div key={`o${i}`}><span className="pill" style={{ fontSize: 10 }}>Tor</span> {v}</div>
              ))}
              {fields.emails.map((v, i) => (
                <div key={`e${i}`}><span className="pill" style={{ fontSize: 10 }}>Email</span> {v}</div>
              ))}
              {fields.telegram.map((v, i) => (
                <div key={`t${i}`}><span className="pill" style={{ fontSize: 10 }}>Telegram</span> {v}</div>
              ))}
            </div>
          )}
        </>
      )}

      {iocTarget && (
        <AddWalletIocModal
          incidentId={inc.id}
          wallet={iocTarget}
          onClose={() => setIocTarget(null)}
          onCreated={() => {
            setAddedIds(prev => new Set([...prev, iocTarget.id]))
            setIocTarget(null)
          }}
        />
      )}
    </section>
  )
}
