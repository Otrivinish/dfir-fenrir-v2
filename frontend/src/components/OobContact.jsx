import { CHANNEL_LABELS } from '../pages/incident/comms/Stakeholders.jsx'

// A responder's out-of-band contact methods (E2), as the API returns them on the roster and the
// on-call schedule. The API sends the list to analysts and admins only; for viewers the key is
// absent, so callers render this only when the key is present (`'oob_contact_methods' in entry`).
// Preferred method first. `compact` = just the preferred (or first) method on one line, all in
// --text (it sits on --surface-2 in the Dashboard strip, where --muted is below 4.5:1 in nordic-calm).
export default function OobContact({ methods, compact = false }) {
  const secondary = compact ? 'var(--text)' : 'var(--muted)'
  if (!methods || methods.length === 0) {
    return <span className="oob-none" style={{ color: secondary }}>No out-of-band contact</span>
  }
  const sorted = [...methods].sort((a, b) => Number(!!b.preferred) - Number(!!a.preferred))
  const shown = compact ? sorted.slice(0, 1) : sorted
  return (
    <span className="oob-list" style={{ display: 'inline-flex', flexWrap: 'wrap', gap: '2px var(--space-3)' }}>
      {shown.map((m, i) => (
        <span key={i} className="oob-method" style={{ whiteSpace: 'nowrap' }}>
          <span style={{ color: secondary }}>{CHANNEL_LABELS[m.channel] || m.channel}</span>{' '}
          <span style={{ color: 'var(--text)', fontFamily: 'var(--font-mono)' }}>{m.value}</span>
        </span>
      ))}
    </span>
  )
}
