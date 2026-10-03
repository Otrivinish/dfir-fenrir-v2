import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api/client.js'
import { formatLocal } from '../lib/datetime.js'

// Legal clocks in the incident status band: one chip per regulation showing its nearest
// open deadline (pending / in progress) as a countdown, coloured by urgency — overdue or
// under 2 h = --crit, under 12 h = --high, otherwise --ok (the same thresholds as the
// in-app reminders). Most urgent first; a regulation with nothing open shows a muted
// "done" chip, last. Renders nothing when the incident has no deadlines. Each chip links
// to the Legal tab.
// `rev` changes when the Legal tab edits deadlines, so the chips refetch.

const REG_LABELS = { PCI_DSS: 'PCI-DSS' }
const OPEN = ['pending', 'in_progress']
const MIN = 60_000
const HOUR = 60 * MIN

// A duration as "2d 3h" / "4h 12m" / "38m" (sign ignored).
export function span(ms) {
  const m = Math.floor(Math.abs(ms) / MIN)
  const d = Math.floor(m / 1440), h = Math.floor((m % 1440) / 60), mm = m % 60
  return d > 0 ? `${d}d ${h}h` : h > 0 ? `${h}h ${mm}m` : `${mm}m`
}

// One clock per regulation from GET …/legal/deadlines rows, most urgent first: {reg, cls, label,
// text, ms, title}; ms = Infinity (cls "done") when nothing is open. Also used by the Situation
// board for its nearest-deadline line.
export function legalClocks(rows, now) {
  const byReg = new Map()
  for (const d of rows) {
    if (!byReg.has(d.regulation)) byReg.set(d.regulation, [])
    byReg.get(d.regulation).push(d)
  }

  return [...byReg.entries()].map(([reg, items]) => {
    const label = REG_LABELS[reg] || reg
    const open = items.filter(d => OPEN.includes(d.status))
                      .sort((a, b) => new Date(a.deadline_at) - new Date(b.deadline_at))
    if (!open.length) {
      return { reg, cls: 'done', label, text: 'done', ms: Infinity,
               title: `${label}: all ${items.length} completed or waived` }
    }
    const next = open[0]
    const ms = new Date(next.deadline_at).getTime() - now
    const cls = ms <= 2 * HOUR ? 'crit' : ms <= 12 * HOUR ? 'high' : 'ok'
    const kind = next.internal_target ? 'internal target' : 'due'
    const more = open.length > 1 ? ` (+${open.length - 1} more open)` : ''
    return {
      reg, cls, label, ms,
      text: ms <= 0 ? `overdue ${span(ms)}` : `${span(ms)} left`,
      title: `${label} ${next.article_label || next.article || ''} — ${kind} ${formatLocal(next.deadline_at)}${more}`.replace(/\s+—/, ' —'),
    }
  }).sort((a, b) => a.ms - b.ms)
}

export default function ClockChips({ incidentId, rev }) {
  const [rows, setRows] = useState(null)
  const [now, setNow]   = useState(() => Date.now())

  useEffect(() => {
    let alive = true
    api.listDeadlines(incidentId)
      .then(r => { if (alive) setRows(Array.isArray(r) ? r : []) })
      .catch(() => { if (alive) setRows([]) })
    return () => { alive = false }
  }, [incidentId, rev])

  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 30_000)
    return () => clearInterval(t)
  }, [])

  if (!rows?.length) return null

  const chips = legalClocks(rows, now)

  return (
    <span className="clock-chips" aria-label="Legal clocks">
      {chips.map(c => (
        <Link key={c.reg} to="legal" className={`clock-chip ${c.cls}`} title={c.title} data-reg={c.reg}>
          <span className="clock-chip-reg">{c.label}</span>
          <span className="clock-chip-left">{c.text}</span>
        </Link>
      ))}
    </span>
  )
}
