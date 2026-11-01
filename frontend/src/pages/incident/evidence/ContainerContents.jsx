import { useCallback, useEffect, useState } from 'react'
import { api } from '../../../api/client.js'
import { formatLocal } from '../../../lib/datetime.js'

// S6 (EG-4) — a container exhibit's "Contents": the manifest FENRIR built from the stored ZIP / TAR (API:
// GET …/evidence/{id}/manifest, …?format=csv, POST …/manifest/rebuild). Everything shown comes from the server.

const STATUS = {
  pending:     { pill: 'pill-med',  text: 'Building' },
  built:       { pill: 'pill-ok',   text: 'Built' },
  failed:      { pill: 'pill-crit', text: 'Failed' },
  not_indexed: { pill: 'pill-gray', text: 'Not indexed' },
}
const FORMAT_LABEL = { zip: 'ZIP', tar: 'TAR', ad1: 'AD1', l01: 'L01', aff4l: 'AFF4-L', other: 'Other' }
const SLOT = { m: 'modified', a: 'accessed', c: 'changed', b: 'born' }
const mono = { fontFamily: 'var(--font-mono)', fontSize: 11, wordBreak: 'break-all' }

function timeText(t) {
  return t.utc ? formatLocal(t.utc) : `${t.as_recorded} (timezone unknown)`
}

function Times({ times }) {
  if (!times) return null
  const rows = Object.entries(SLOT).filter(([k]) => times[k]).map(([k, label]) => (
    <div key={k} title={times[k].basis}>{label} {timeText(times[k])}</div>
  ))
  const src = times.source
  return (
    <div style={{ fontSize: 11, whiteSpace: 'nowrap' }}>
      {rows}
      {src && Object.entries(SLOT).filter(([k]) => src[k]).map(([k, label]) => (
        <div key={`s${k}`} title={src.basis} style={{ color: 'var(--muted)' }}>source {label} {timeText(src[k])}</div>
      ))}
    </div>
  )
}

function listingLine(s) {
  const name = `${s.parser} v${s.version}${s.member ? ` (${s.member})` : ''}`
  if (s.status !== 'merged') return `${name}: not merged — ${s.note || 'unknown reason'}`
  return `${name}: ${s.matched} of ${s.rows} rows merged; tool hash ${s.tool_hash_matches} match, ${s.tool_hash_mismatches} differ`
    + (s.note ? ` — ${s.note}` : '')
}

export default function ContainerContents({ incidentId, item, canWrite, onReplaceItem }) {
  const [q, setQ] = useState('')
  const [shownQ, setShownQ] = useState('')
  const [items, setItems] = useState([])
  const [cursor, setCursor] = useState(null)
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)
  const built = item.manifest_status === 'built'

  const load = useCallback(async (query, after) => {
    setBusy(true); setError(null)
    try {
      const r = await api.evidenceManifest(incidentId, item.id, { limit: 100, cursor: after, q: query })
      setItems(prev => (after ? [...prev, ...r.items] : r.items))
      setCursor(r.next_cursor)
      setShownQ(query)
    } catch (e) {
      setError(e.message || 'Could not load the contents')
    } finally {
      setBusy(false)
    }
  }, [incidentId, item.id])

  useEffect(() => { if (built) load('', null) }, [built, load])

  // While the manifest is being built, refresh the item every few seconds (its status comes from the server).
  useEffect(() => {
    if (item.manifest_status !== 'pending') return undefined
    const t = setInterval(async () => {
      try { onReplaceItem(await api.getEvidence(incidentId, item.id)) } catch { /* the next tick retries */ }
    }, 5000)
    return () => clearInterval(t)
  }, [incidentId, item.id, item.manifest_status, onReplaceItem])

  if (!item.container_format) return null
  const st = STATUS[item.manifest_status] || { pill: 'pill-gray', text: item.manifest_status || '—' }

  async function rebuild() {
    setBusy(true); setError(null)
    try {
      onReplaceItem(await api.rebuildEvidenceManifest(incidentId, item.id))
    } catch (e) {
      setError(e.message || 'Could not queue the rebuild')
    } finally {
      setBusy(false)
    }
  }

  return (
    <section data-testid="ev-contents" data-status={item.manifest_status || ''}>
      <h3 className="panel-h" style={{ marginTop: 'var(--space-4)' }}>
        Contents{' '}
        <span style={{ fontWeight: 400, color: 'var(--muted)', fontSize: 12 }}>· ISO 27037 §7.1.3.4</span>
      </h3>
      <dl className="kv">
        <dt>Container</dt><dd>{FORMAT_LABEL[item.container_format] || item.container_format}</dd>
        <dt>Manifest</dt>
        <dd>
          <span className={`pill ${st.pill}`}>{st.text}</span>
          {item.manifest_status === 'pending' && <span style={{ color: 'var(--muted)', fontSize: 12 }}> — the seal waits until it is built</span>}
          {item.manifest_status === 'not_indexed' && <span style={{ color: 'var(--muted)', fontSize: 12 }}> — FENRIR lists ZIP and TAR containers only; attach the tool’s own listing</span>}
          {canWrite && (item.manifest_status === 'failed' || item.manifest_status === 'pending') && (
            <button type="button" className="btn ghost" onClick={rebuild} disabled={busy} style={{ marginLeft: 'var(--space-2)' }}
                    data-testid="ev-contents-rebuild">Rebuild</button>
          )}
        </dd>
        {item.manifest_error && <><dt>Why it failed</dt><dd style={mono}>{item.manifest_error}</dd></>}
        {built && <><dt>Entries</dt><dd>{item.manifest_entries}</dd></>}
        {item.manifest_builder && <><dt>Built by</dt><dd style={{ fontSize: 12 }}>{item.manifest_builder}</dd></>}
        {item.manifest_sha256 && (
          <>
            <dt>Manifest SHA-256</dt>
            <dd>
              <button type="button" className="btn ghost" onClick={() => { navigator.clipboard?.writeText(item.manifest_sha256) }}
                      title="Click to copy" style={{ ...mono, fontWeight: 400, textAlign: 'left' }}>
                {item.manifest_sha256}
              </button>
            </dd>
          </>
        )}
        {(item.manifest_listing || []).length > 0 && (
          <>
            <dt>Tool listing</dt>
            <dd style={{ fontSize: 12 }}>{item.manifest_listing.map((s, i) => <div key={i}>{listingLine(s)}</div>)}</dd>
          </>
        )}
      </dl>
      {error && <div style={{ color: 'var(--crit)', fontSize: 13 }}>{error}</div>}
      {built && (
        <>
          <form className="panel-toolbar" style={{ display: 'flex', gap: 'var(--space-2)', marginTop: 'var(--space-2)' }}
                onSubmit={(e) => { e.preventDefault(); load(q, null) }}>
            <input className="input" type="search" value={q} onChange={e => setQ(e.target.value)} maxLength={1024}
                   placeholder="Search entry or source path" aria-label="Search entry or source path" />
            <button type="submit" className="btn ghost" disabled={busy}>Search</button>
            <a className="btn ghost" href={api.evidenceManifestCsvUrl(incidentId, item.id, shownQ)} download
               data-testid="ev-contents-csv">Download CSV</a>
          </form>
          {items.length === 0 ? (
            <div style={{ color: 'var(--muted)', fontSize: 13 }}>{busy ? 'Loading…' : shownQ ? 'No entry matches.' : 'No entries.'}</div>
          ) : (
            <div className="table-scroll">
              <table className="settings-table compact" data-testid="ev-contents-table">
                <thead>
                  <tr>
                    <th>#</th><th style={{ minWidth: 220 }}>Entry path</th><th style={{ minWidth: 200 }}>Source path</th>
                    <th>Type</th><th>Size</th><th>Times</th><th>SHA-256</th><th>Tool hash</th>
                  </tr>
                </thead>
                <tbody>
                  {items.map(e => (
                    <tr key={e.seq}>
                      <td style={{ ...mono, color: 'var(--muted)' }}>{e.seq}</td>
                      <td style={mono} title={e.entry_name_encoding !== 'utf8' ? `name read as ${e.entry_name_encoding}` : undefined}>
                        {e.entry_path}
                        {e.notes && <div style={{ fontFamily: 'var(--font-body)', color: 'var(--muted)' }}>{e.notes}</div>}
                      </td>
                      <td style={mono}>{e.source_path || <span style={{ color: 'var(--dim)' }}>—</span>}</td>
                      <td style={{ fontSize: 12 }}>{e.entry_type}{e.encrypted ? ' · encrypted' : ''}</td>
                      <td style={{ ...mono, whiteSpace: 'nowrap' }}>{e.size ?? '—'}</td>
                      <td><Times times={e.times} /></td>
                      <td style={mono} title={e.sha256 || undefined}>{e.sha256 ? `${e.sha256.slice(0, 16)}…` : '—'}</td>
                      <td style={{ fontSize: 12, whiteSpace: 'nowrap' }} title={e.tool_hash ? `${e.tool_hash.algorithm} ${e.tool_hash.value}` : undefined}>
                        {e.tool_hash_match === true ? <span style={{ color: 'var(--ok)' }}>✓ matches</span>
                          : e.tool_hash_match === false ? <span style={{ color: 'var(--crit)' }}>✗ differs</span>
                          : e.tool_hash ? <span style={{ color: 'var(--muted)' }}>not compared</span> : '—'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {cursor && (
            <button type="button" className="btn ghost" onClick={() => load(shownQ, cursor)} disabled={busy}
                    style={{ marginTop: 'var(--space-2)' }}>Load more</button>
          )}
        </>
      )}
    </section>
  )
}
