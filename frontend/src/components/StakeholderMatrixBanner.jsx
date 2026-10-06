import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api/client.js'
import { formatLocal } from '../lib/datetime.js'
import { span } from './ClockChips.jsx'
import { CHANNEL_LABEL, dueChip } from '../pages/incident/comms/Notifications.jsx'

// I2: the summary of the incident's stakeholder notification tracker (it replaced the plain list
// of matching matrix rules): "x of y required notified", how many are overdue, and one chip per
// active obligation (countdown while pending). Used on the Situation board and above the Comms
// tabs; `to` is the relative link to Comms › Notifications. Renders nothing when no matrix rule
// applies to the incident. `rev` changes after a write so the banner re-reads.
export default function StakeholderMatrixBanner({ incidentId, rev, to = 'notifications' }) {
  const [data, setData] = useState(null)
  const [now, setNow] = useState(() => Date.now())

  useEffect(() => {
    if (!incidentId) return undefined
    let alive = true
    api.listStakeholderNotifications(incidentId, { active: true, limit: 100 })
      .then(d => { if (alive) setData(d) })
      .catch(() => { if (alive) setData(null) })
    return () => { alive = false }
  }, [incidentId, rev])

  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 60_000)
    return () => clearInterval(t)
  }, [])

  if (!data?.items?.length) return null
  const s = data.summary
  return (
    <div role="status" className={`sn-banner${s.overdue > 0 ? ' overdue' : ''}`} data-sn-banner>
      <div className="sn-banner-head">
        <span>★ Stakeholder notifications</span>
        <span className="sn-banner-count">
          {s.notified} of {s.required_total} required notified
          {s.overdue > 0 && <> · {s.overdue} overdue</>}
          {s.not_required > 0 && <> · {s.not_required} not required</>}
        </span>
        <Link to={to} className="sn-banner-link">Open tracker</Link>
      </div>
      <div className="sn-banner-items">
        {data.items.map(x => {
          const chip = dueChip(x, now)
          return (
            <span key={x.id} className="sn-banner-item" data-status={x.status}
                  title={`Due ${formatLocal(x.due_at)} (within ${span(x.notify_within_minutes * 60_000)} of reaching ${x.severity})`}>
              <strong>{x.role}</strong>
              {!x.required && <span className="sn-dim">advisory</span>}
              {x.status === 'notified' && <span className="sn-done">✓ {CHANNEL_LABEL[x.channel] || x.channel}</span>}
              {x.status === 'not_required' && <span className="sn-dim">not required</span>}
              {chip && <span className={`clock-chip ${chip.cls}`}><span className="clock-chip-left">{chip.text}</span></span>}
            </span>
          )
        })}
      </div>
    </div>
  )
}
