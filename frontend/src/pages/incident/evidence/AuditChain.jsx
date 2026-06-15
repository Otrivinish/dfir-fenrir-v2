import { useCallback, useEffect, useState } from 'react'
import { useOutletContext } from 'react-router-dom'
import { api } from '../../../api/client.js'
import { formatLocal } from '../../../lib/datetime.js'

export default function AuditChain() {
  const { inc } = useOutletContext()
  const [events, setEvents]   = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError]     = useState(null)
  const [verifying, setVerifying] = useState(false)
  const [result, setResult]   = useState(null)   // ChainVerifyResult

  const load = useCallback(async () => {
    setError(null)
    try {
      const rows = await api.incidentCustodyLog(inc.id)
      setEvents(rows)
    } catch (e) {
      setError(e.message || 'Could not load chain')
    } finally {
      setLoading(false)
    }
  }, [inc.id])

  useEffect(() => { load() }, [load])

  const onVerify = async () => {
    setVerifying(true); setResult(null); setError(null)
    try {
      const r = await api.verifyCustodyChain(inc.id)
      setResult(r)
    } catch (e) {
      setError(e.message || 'Verify failed')
    } finally {
      setVerifying(false)
    }
  }

  return (
    <section className="panel">
      <div className="panel-toolbar">
        <h2 className="panel-h">Audit chain — evidence events</h2>
        <button
          type="button"
          className="btn primary"
          onClick={onVerify}
          disabled={verifying || events.length === 0}
        >
          {verifying ? 'Verifying…' : 'Verify chain'}
        </button>
      </div>

      <div className="alert info" role="status" style={{ marginBottom: 'var(--space-3)' }}>
        <span className="alert-icon">i</span>
        <span>
          Each row is the canonical record of an evidence event. <b>Verify chain</b> recomputes
          every row's SHA-256 from its payload + `prev_hash` and compares to the stored value —
          any after-the-fact tampering of a stored row will fail. The full-audit cross-row linkage
          check is a broader operation; this view focuses on evidence events in this incident.
        </span>
      </div>

      {error && (
        <div className="alert error" role="alert">
          <span className="alert-icon">!</span><span>{error}</span>
        </div>
      )}

      {result && (
        <div
          className={`alert ${result.ok ? 'info' : 'error'}`}
          role={result.ok ? 'status' : 'alert'}
          style={{ marginBottom: 'var(--space-3)' }}
        >
          <span className="alert-icon">{result.ok ? '✓' : '!'}</span>
          <span>
            {result.message}
            {!result.ok && result.broken_reason && (
              <>
                {' '}<span style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>
                  ({result.broken_reason}, first bad id {result.broken_at_id?.slice(0, 8)}…)
                </span>
              </>
            )}
          </span>
        </div>
      )}

      {loading ? (
        <div className="panel-empty"><div>Loading…</div></div>
      ) : events.length === 0 ? (
        <div className="panel-empty">
          <div className="panel-empty-mark" aria-hidden="true">⛓</div>
          <div>No evidence events recorded yet.</div>
        </div>
      ) : (
        <table className="settings-table">
          <thead>
            <tr>
              <th style={{ width: 60 }}>#</th>
              <th style={{ width: 160 }}>Timestamp</th>
              <th>Action</th>
              <th>Actor</th>
              <th>Resource</th>
              <th>prev_hash</th>
              <th>row_hash</th>
              <th style={{ width: 60 }}></th>
            </tr>
          </thead>
          <tbody>
            {events.map((ev, idx) => (
              <ChainRow
                key={ev.id}
                idx={idx}
                ev={ev}
                broken={!!result && !result.ok && result.broken_at_id === ev.id}
                priorRowHash={idx > 0 ? events[idx - 1].hash : null}
              />
            ))}
          </tbody>
        </table>
      )}
    </section>
  )
}

function ChainRow({ idx, ev, broken, priorRowHash }) {
  // Visual hint: if this row's prev_hash matches the prior row's hash in our
  // filtered set, the segment is internally linked. (NB: across the full audit
  // log there are interleaved non-evidence rows, so this only proves linkage
  // within the evidence segment, not absolute chain integrity.)
  const linkedToPrior =
    idx === 0 || (priorRowHash && ev.prev_hash && ev.prev_hash === priorRowHash)

  return (
    <tr style={broken ? { background: 'color-mix(in srgb, var(--crit) 14%, transparent)' } : undefined}>
      <td style={{ fontFamily: 'var(--font-mono)', color: 'var(--muted)' }}>{idx}</td>
      <td title={ev.created_at} style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>
        {formatLocal(ev.created_at)}
      </td>
      <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>{ev.event_type}</td>
      <td style={{ fontFamily: 'var(--font-mono)' }}>{ev.username || '—'}</td>
      <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--muted)' }}>
        {ev.resource_type}/{ev.resource_id ? ev.resource_id.slice(0, 8) + '…' : '—'}
      </td>
      <td
        title={ev.prev_hash || '—'}
        style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--muted)' }}
      >
        {ev.prev_hash ? ev.prev_hash.slice(0, 12) + '…' : '—'}
      </td>
      <td
        title={ev.hash || '—'}
        style={{ fontFamily: 'var(--font-mono)', fontSize: 10 }}
      >
        {ev.hash ? ev.hash.slice(0, 12) + '…' : '—'}
      </td>
      <td title={linkedToPrior ? 'Links to prior evidence event' : 'Different prior (non-evidence event in between)'}>
        <span className={`pill ${linkedToPrior ? 'pill-ok' : 'pill-gray'}`} style={{ padding: '1px 6px' }}>
          {linkedToPrior ? '✓' : '~'}
        </span>
      </td>
    </tr>
  )
}
