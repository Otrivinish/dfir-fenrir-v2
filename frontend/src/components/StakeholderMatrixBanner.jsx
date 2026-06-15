import { useEffect, useState } from 'react'
import { api } from '../api/client.js'

function formatMinutes(mins) {
  if (mins < 60)   return `${mins}m`
  if (mins < 1440) return `${Math.round(mins / 60 * 10) / 10}h`
  return `${Math.round(mins / 1440 * 10) / 10}d`
}

// Banner showing required Stakeholder Matrix rules that match the current
// incident's severity. Used on Incident Details and Comms tab.
export default function StakeholderMatrixBanner({ severity }) {
  const [rules,  setRules]  = useState([])
  const [loaded, setLoaded] = useState(false)

  useEffect(() => {
    if (!severity) return
    api.listStakeholderMatrix()
      .then(d => setRules(d.items || []))
      .catch(() => setRules([]))
      .finally(() => setLoaded(true))
  }, [severity])

  if (!loaded || !severity) return null
  const matching = rules.filter(r => r.severity === severity && r.required)
  if (matching.length === 0) return null

  return (
    <div role="status" style={{
      marginBottom: 'var(--space-3)',
      padding: 'var(--space-3)',
      border: '1px solid color-mix(in srgb, var(--accent) 35%, transparent)',
      background: 'color-mix(in srgb, var(--accent) 8%, transparent)',
      borderLeft: '3px solid var(--accent)',
      borderRadius: 'var(--radius)',
    }}>
      <div style={{
        fontSize: 12, fontWeight: 700, letterSpacing: '0.06em',
        textTransform: 'uppercase', color: 'var(--accent)',
        marginBottom: 6,
      }}>
        ★ Required notifications for {severity} incidents
      </div>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 'var(--space-2)' }}>
        {matching.map(r => (
          <span key={r.id} style={{
            fontSize: 12, padding: '4px 10px',
            background: 'var(--surface)',
            border: '1px solid var(--border)',
            borderRadius: 'var(--radius-sm)',
            display: 'inline-flex', alignItems: 'center', gap: 6,
          }}>
            <strong style={{ color: 'var(--text)' }}>{r.role}</strong>
            <span style={{ color: 'var(--muted)' }}>· within {formatMinutes(r.notify_within_minutes)}</span>
            <span style={{
              fontSize: 10, padding: '1px 6px', borderRadius: 'var(--radius-sm)',
              background: 'var(--surface-2)', color: 'var(--muted)',
              textTransform: 'capitalize',
            }}>{r.category}</span>
          </span>
        ))}
      </div>
    </div>
  )
}
