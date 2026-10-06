import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api/client.js'
import { formatLocal } from '../lib/datetime.js'
import { span } from './ClockChips.jsx'

// I2: "Notifications x of y" in the incident status band, from the tracker's roll-up (required
// stakeholder-matrix rules only). Overdue → --crit; otherwise coloured by the next due time with
// the legal-clock thresholds (under 2 h --crit, under 12 h --high, else --ok); all done → muted.
// Renders nothing when no required rule applies. `rev` changes after a write elsewhere.

const MIN = 60_000
const HOUR = 60 * MIN

export function notificationsChip(s, now) {
  if (!s || s.required_total === 0) return null
  const head = `${s.notified} of ${s.required_total}`
  if (s.overdue > 0) {
    return { cls: 'crit', text: `${head} · ${s.overdue} overdue`,
             title: `${s.notified} of ${s.required_total} required stakeholder notifications recorded; ${s.overdue} overdue` }
  }
  if (!s.next_due_at) {
    return { cls: 'done', text: head, title: `All ${s.required_total} required stakeholder notifications recorded` }
  }
  const ms = new Date(s.next_due_at).getTime() - now
  return { cls: ms <= 2 * HOUR ? 'crit' : ms <= 12 * HOUR ? 'high' : 'ok',
           text: `${head} · next ${ms <= 0 ? 'due now' : `in ${span(ms)}`}`,
           title: `${s.notified} of ${s.required_total} required stakeholder notifications recorded; next due ${formatLocal(s.next_due_at)}` }
}

export default function NotificationsChip({ incidentId, rev }) {
  const [summary, setSummary] = useState(null)
  const [now, setNow] = useState(() => Date.now())

  useEffect(() => {
    let alive = true
    api.listStakeholderNotifications(incidentId, { limit: 1 })
      .then(r => { if (alive) setSummary(r.summary) })
      .catch(() => { if (alive) setSummary(null) })
    return () => { alive = false }
  }, [incidentId, rev])

  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 30_000)
    return () => clearInterval(t)
  }, [])

  const c = notificationsChip(summary, now)
  if (!c) return null
  return (
    <Link to="comms/notifications" className={`clock-chip ${c.cls}`} title={c.title} data-notify-chip>
      <span className="clock-chip-reg">Notifications</span>
      <span className="clock-chip-left">{c.text}</span>
    </Link>
  )
}
