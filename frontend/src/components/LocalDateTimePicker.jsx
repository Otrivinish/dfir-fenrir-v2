import { useEffect, useMemo, useRef, useState } from 'react'
import { formatLocal, isoToZonedParts, zonedPartsToIso } from '../lib/datetime.js'
import { getStoredTz } from '../lib/timezone.js'

// Datetime entry in the user's stored (Fenrir) timezone, offset visible — the
// same zone + format used when rendering times elsewhere. A read-only trigger
// opens a calendar-grid + time popup; the emitted `onChange` value is canonical
// UTC ISO-8601 (`…Z`), so storage/transmit stay UTC.
//
// Contract matches UtcDateTimeInput so it is a drop-in swap:
//   value:    canonical ISO string (`…Z`) or ''
//   onChange: receives a canonical ISO string for a valid pick

const WEEKDAYS = ['Mo', 'Tu', 'We', 'Th', 'Fr', 'Sa', 'Su']

function nowParts() { return isoToZonedParts(new Date().toISOString()) }
function clamp(n, lo, hi) { return Math.max(lo, Math.min(hi, n)) }
function daysInMonth(y, mo) { return new Date(Date.UTC(y, mo, 0)).getUTCDate() }
// Monday-first weekday index (0=Mon … 6=Sun) of the 1st of the month.
function firstWeekday(y, mo) { return (new Date(Date.UTC(y, mo - 1, 1)).getUTCDay() + 6) % 7 }

export default function LocalDateTimePicker({
  id,
  value,
  onChange,
  required = false,
  disabled = false,
}) {
  const [open, setOpen] = useState(false)
  const [parts, setParts] = useState(() => isoToZonedParts(value) || nowParts())
  const [view, setView] = useState(() => ({ y: parts.y, mo: parts.mo }))
  const wrapRef = useRef(null)

  // Mirror external value changes while the popup is closed.
  useEffect(() => {
    if (open) return
    const p = isoToZonedParts(value)
    if (p) { setParts(p); setView({ y: p.y, mo: p.mo }) }
  }, [value, open])

  // Close on outside-click / Escape while open.
  useEffect(() => {
    if (!open) return
    const onDown = (e) => { if (wrapRef.current && !wrapRef.current.contains(e.target)) setOpen(false) }
    const onKey = (e) => { if (e.key === 'Escape') setOpen(false) }
    document.addEventListener('mousedown', onDown)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('mousedown', onDown)
      document.removeEventListener('keydown', onKey)
    }
  }, [open])

  const commit = (next) => {
    setParts(next)
    const iso = zonedPartsToIso(next)
    if (iso) onChange(iso)
  }

  const pickDay = (d) => commit({ ...parts, y: view.y, mo: view.mo, d })
  const setTime = (key, raw) => {
    const n = parseInt(raw, 10)
    if (Number.isNaN(n)) return
    const max = key === 'h' ? 23 : 59
    commit({ ...parts, [key]: clamp(n, 0, max) })
  }
  const setNow = () => {
    const iso = new Date().toISOString()
    const p = isoToZonedParts(iso)
    setParts(p); setView({ y: p.y, mo: p.mo })
    onChange(iso)
  }
  const stepMonth = (delta) => {
    let y = view.y, mo = view.mo + delta
    if (mo < 1) { mo = 12; y -= 1 }
    if (mo > 12) { mo = 1; y += 1 }
    setView({ y, mo })
  }

  const grid = useMemo(() => {
    const lead = firstWeekday(view.y, view.mo)
    const total = daysInMonth(view.y, view.mo)
    const cells = Array(lead).fill(null)
    for (let d = 1; d <= total; d++) cells.push(d)
    return cells
  }, [view])

  const isSelected = (d) =>
    d === parts.d && view.y === parts.y && view.mo === parts.mo

  const display = value ? formatLocal(value) : ''
  const monthLabel = `${view.y}-${String(view.mo).padStart(2, '0')}`

  return (
    <div ref={wrapRef} style={{ position: 'relative' }}>
      <button
        id={id}
        type="button"
        className="input"
        disabled={disabled}
        aria-haspopup="dialog"
        aria-expanded={open}
        onClick={() => !disabled && setOpen(o => !o)}
        style={{
          width: '100%', textAlign: 'left', cursor: disabled ? 'default' : 'pointer',
          fontFamily: 'var(--font-mono)', display: 'flex', alignItems: 'center', gap: 'var(--space-2)',
          color: display ? 'var(--text)' : 'var(--dim)',
        }}
      >
        <span style={{ fontSize: 13 }} aria-hidden="true">🗓</span>
        <span>{display || 'YYYY-MM-DD HH:mm:ss'}</span>
      </button>
      <div className="field-hint">{getStoredTz()} · 24-hour · offset shown</div>

      {open && (
        <div
          role="dialog"
          aria-label="Pick date and time"
          style={{
            position: 'absolute', top: 'calc(100% + 4px)', left: 0, zIndex: 50,
            background: 'var(--surface)', border: '1px solid var(--border-strong)',
            borderRadius: 'var(--radius)', boxShadow: 'var(--shadow)',
            padding: 'var(--space-3)', width: 268,
          }}
        >
          {/* month nav */}
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 'var(--space-2)' }}>
            <button type="button" className="btn ghost" onClick={() => stepMonth(-1)} aria-label="Previous month"
              style={{ padding: '2px 8px' }}>‹</button>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12, fontWeight: 700, color: 'var(--text)' }}>
              {monthLabel}
            </span>
            <button type="button" className="btn ghost" onClick={() => stepMonth(1)} aria-label="Next month"
              style={{ padding: '2px 8px' }}>›</button>
          </div>

          {/* weekday header */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(7, 1fr)', gap: 2, marginBottom: 2 }}>
            {WEEKDAYS.map(w => (
              <div key={w} style={{
                textAlign: 'center', fontSize: 10, fontWeight: 700, color: 'var(--dim)',
                fontFamily: 'var(--font-mono)', padding: '2px 0',
              }}>{w}</div>
            ))}
          </div>

          {/* day grid */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(7, 1fr)', gap: 2 }}>
            {grid.map((d, i) => d === null ? (
              <div key={`b-${i}`} />
            ) : (
              <button
                key={d}
                type="button"
                onClick={() => pickDay(d)}
                style={{
                  fontFamily: 'var(--font-mono)', fontSize: 12, padding: '5px 0',
                  border: '1px solid transparent', borderRadius: 'var(--radius-sm)',
                  cursor: 'pointer',
                  background: isSelected(d) ? 'var(--accent)' : 'transparent',
                  color: isSelected(d) ? 'var(--bg)' : 'var(--text)',
                }}
              >{d}</button>
            ))}
          </div>

          {/* time row */}
          <div style={{
            display: 'flex', alignItems: 'center', gap: 4, marginTop: 'var(--space-3)',
            paddingTop: 'var(--space-2)', borderTop: '1px solid var(--border)',
          }}>
            <TimeField label="HH" value={parts.h}  onChange={v => setTime('h', v)}  max={23} />
            <span style={{ color: 'var(--dim)' }}>:</span>
            <TimeField label="MM" value={parts.mi} onChange={v => setTime('mi', v)} max={59} />
            <span style={{ color: 'var(--dim)' }}>:</span>
            <TimeField label="SS" value={parts.s}  onChange={v => setTime('s', v)}  max={59} />
            <button type="button" className="btn ghost" onClick={setNow}
              style={{ marginLeft: 'auto', fontSize: 11, padding: '2px 8px' }}>Now</button>
          </div>

          {/* live preview */}
          <div style={{
            marginTop: 'var(--space-2)', fontFamily: 'var(--font-mono)', fontSize: 11,
            color: 'var(--muted)', wordBreak: 'break-word',
          }}>
            {value ? formatLocal(value) : '—'}
          </div>

          <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 'var(--space-2)' }}>
            <button type="button" className="btn primary" onClick={() => setOpen(false)}
              style={{ fontSize: 11, padding: '3px 12px' }}>Done</button>
          </div>
        </div>
      )}

      {/* keep native required semantics on the form */}
      {required && (
        <input type="text" value={value || ''} required readOnly aria-hidden="true" tabIndex={-1}
          style={{ position: 'absolute', width: 1, height: 1, opacity: 0, pointerEvents: 'none' }} />
      )}
    </div>
  )
}

function TimeField({ label, value, onChange, max }) {
  return (
    <input
      type="number"
      min={0}
      max={max}
      value={value}
      aria-label={label}
      onChange={(e) => onChange(e.target.value)}
      className="input"
      style={{
        width: 48, textAlign: 'center', fontFamily: 'var(--font-mono)', fontSize: 12,
        padding: '4px 2px',
      }}
    />
  )
}
