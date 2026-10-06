import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api/client.js'
import { formatLocal } from '../lib/datetime.js'

// I4: "Start checks x/y" in the incident status band, from GET …/start-checks (computed by the API).
// Overdue → --crit, open warnings → --high, all met → muted. Links to the Situation board, which
// lists each open check with a link to fix it. Hidden on a closed incident. `rev` changes after a write.

export function startChecksChip(sc) {
  if (!sc || !sc.total) return null
  const head = `${sc.ok}/${sc.total}`
  const open = sc.warning + sc.overdue
  if (sc.overdue > 0) {
    return { cls: 'crit', text: `${head} · ${sc.overdue} overdue`,
             title: `${sc.ok} of ${sc.total} incident-start checks met; ${sc.overdue} overdue` }
  }
  if (open > 0) {
    return { cls: 'high', text: `${head} · ${open} open`,
             title: `${sc.ok} of ${sc.total} incident-start checks met; the rest turn overdue at ${formatLocal(sc.overdue_at)}` }
  }
  return { cls: 'done', text: head, title: `All ${sc.total} incident-start checks met` }
}

export default function StartChecksChip({ incidentId, rev, closed }) {
  const [sc, setSc] = useState(null)
  const [tick, setTick] = useState(0)

  useEffect(() => {
    if (closed) return
    let alive = true
    api.getIncidentStartChecks(incidentId)
      .then(r => { if (alive) setSc(r) })
      .catch(() => { if (alive) setSc(null) })
    return () => { alive = false }
  }, [incidentId, rev, closed, tick])

  // Re-read when open warnings turn overdue (the API decides; the page may stay open that long).
  useEffect(() => {
    if (!sc?.warning) return
    const ms = new Date(sc.overdue_at).getTime() - Date.now()
    if (ms <= 0) return
    const t = setTimeout(() => setTick(n => n + 1), ms + 1000)
    return () => clearTimeout(t)
  }, [sc])

  const c = closed ? null : startChecksChip(sc)
  if (!c) return null
  return (
    <Link to="situation" className={`clock-chip ${c.cls}`} title={c.title} data-start-chip>
      <span className="clock-chip-reg">Start checks</span>
      <span className="clock-chip-left">{c.text}</span>
    </Link>
  )
}
