import { useEffect, useState } from 'react'
import { api } from '../api/client.js'
import { SEV_PALETTE } from './SevBadge.jsx'

// G3 — "From a registered exhibit": pick a digital evidence item of the incident to analyse instead
// of re-uploading it. Items the server would refuse are listed but disabled with the reason (the
// same rules as the from-evidence routes: active, internal custody, no pending transfer, size cap).

/** Why an exhibit can't be analysed right now, or null. */
export function exhibitBlock(ev, maxBytes, maxLabel) {
  if (ev.status !== 'active') return `status ${ev.status}`
  if (!ev.current_custodian_id) return 'not in internal custody'
  if (ev.pending_custodian_id) return 'custody transfer pending'
  if (maxBytes && (ev.file_size_bytes || 0) > maxBytes) return `larger than ${maxLabel}`
  return null
}

/** "Draft · unsealed" marker for an exhibit that has not been sealed yet (SEV_PALETTE.medium). */
export function DraftBadge({ title }) {
  const p = SEV_PALETTE.medium
  return (
    <span className="pill" data-testid="draft-badge"
          title={title || 'Unsealed draft exhibit: complete its acquisition record and seal it in Evidence › Exhibits'}
          style={{ fontSize: 10, whiteSpace: 'nowrap', background: p.bg, color: p.text, borderColor: p.border }}>
      Draft · unsealed
    </span>
  )
}

export default function ExhibitPicker({
  incidentId, id, label = 'Exhibit *', value, onChange, maxBytes, maxLabel, reloadKey, disabled, optional = false,
}) {
  const [items, setItems] = useState(null)
  const [err, setErr]     = useState(null)

  useEffect(() => {
    const ctl = new AbortController()
    setItems(null); setErr(null)
    api.listAllPages(api.listEvidence, incidentId, { kind: 'digital_file' }, 200, { signal: ctl.signal })
      .then(all => setItems(all))
      .catch(e => { if (!ctl.signal.aborted) { setItems([]); setErr(e.message || 'Could not list exhibits.') } })
    return () => ctl.abort()
  }, [incidentId, reloadKey])

  const pick = (v) => onChange(v, (items || []).find(x => x.id === v) || null)

  return (
    <div className="field">
      <label className="field-label" htmlFor={id}>{label}</label>
      <select id={id} className="select" value={value} onChange={(e) => pick(e.target.value)}
              disabled={disabled || items === null}>
        <option value="">
          {items === null ? 'Loading exhibits…'
            : items.length ? (optional ? '— none —' : '— choose an exhibit —') : 'No digital exhibits registered'}
        </option>
        {(items || []).map(x => {
          const block = exhibitBlock(x, maxBytes, maxLabel)
          return (
            <option key={x.id} value={x.id} disabled={!!block}>
              {x.identifier} · {x.name}{x.original_filename ? ` (${x.original_filename})` : ''}
              {x.coc_sealed ? '' : ' — draft'}{block ? ` — ${block}` : ''}
            </option>
          )
        })}
      </select>
      {err && <div className="field-hint" role="alert" style={{ color: 'var(--crit)' }}>{err}</div>}
    </div>
  )
}
