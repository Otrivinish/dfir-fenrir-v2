import { useState, useRef, useEffect } from 'react'
import { getStoredTz, setStoredTz, TIMEZONE_GROUPS } from '../lib/timezone.js'

function tzAbbr(tz) {
  if (tz === 'UTC') return 'UTC'
  try {
    return new Intl.DateTimeFormat('en', { timeZone: tz, timeZoneName: 'short' })
      .formatToParts(new Date())
      .find(p => p.type === 'timeZoneName')?.value || tz
  } catch { return tz }
}

export default function TimezonePicker({ variant = 'floating' }) {
  const tz = getStoredTz()
  const [open, setOpen] = useState(false)
  const [filter, setFilter] = useState('')
  const ref = useRef(null)

  useEffect(() => {
    if (!open) return
    function handler(e) {
      if (ref.current && !ref.current.contains(e.target)) setOpen(false)
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [open])

  const q = filter.toLowerCase().trim()
  const groups = q
    ? TIMEZONE_GROUPS
        .map(g => ({ ...g, zones: g.zones.filter(z => z.label.toLowerCase().includes(q) || z.id.toLowerCase().includes(q)) }))
        .filter(g => g.zones.length > 0)
    : TIMEZONE_GROUPS

  const handleSelect = (id) => {
    setStoredTz(id)
    setOpen(false)
    window.location.reload()
  }

  return (
    <div className={`tz-picker ${variant === 'inline' ? 'inline' : ''}`} ref={ref}>
      <button
        className="tz-btn"
        type="button"
        onClick={() => { setOpen(v => !v); setFilter('') }}
        aria-expanded={open}
        aria-label="Select timezone"
        title={tz}
      >
        {tzAbbr(tz)}
      </button>
      {open && (
        <div className="tz-dropdown" role="dialog" aria-label="Timezone picker">
          <input
            className="tz-filter"
            type="text"
            placeholder="Filter timezones…"
            value={filter}
            onChange={e => setFilter(e.target.value)}
            autoFocus
          />
          <div className="tz-list">
            {groups.map(({ group, zones }) => (
              <div key={group} className="tz-group">
                <div className="tz-group-label">{group}</div>
                {zones.map(z => (
                  <button
                    key={z.id}
                    type="button"
                    className={`tz-opt ${z.id === tz ? 'active' : ''}`}
                    onClick={() => handleSelect(z.id)}
                  >
                    {z.label}
                  </button>
                ))}
              </div>
            ))}
            {groups.length === 0 && (
              <div className="tz-empty">No matches</div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
