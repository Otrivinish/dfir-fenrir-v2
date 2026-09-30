import { useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import { formatLocal, isoToZonedParts, zonedPartsToIso } from '../lib/datetime.js'
import { getStoredTz } from '../lib/timezone.js'

// THE date+time entry component (UX standard — see CLAUDE.md "Date/time entry
// standard"). Use it for every date+time field; don't add another one.
//
// Datetime entry in the user's stored (Fenrir) timezone, offset visible — the
// same zone + format used when rendering times elsewhere. `utc` switches entry
// and display to UTC (+00:00) for filters over data that is itself shown in UTC. A read-only trigger
// opens a calendar-grid + time popup; the emitted `onChange` value is canonical
// UTC ISO-8601 (`…Z`), so storage/transmit stay UTC.
//
// Contract:
//   value:    canonical ISO string (`…Z`) or ''
//   onChange: receives a canonical ISO string for a valid pick ('' on Clear)
//
// The popup is portalled to <body> and pinned to the viewport next to the
// trigger (flipping above it when there's no room below), so it never needs
// the surrounding modal / page to be scrolled to reach the time row + Done.

const POPUP_W = 268
const GAP = 4
const MARGIN = 8

const WEEKDAYS = ['Mo', 'Tu', 'We', 'Th', 'Fr', 'Sa', 'Su']

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
  clearable = false,
  utc = false,
  hint = true,
  placeholder = 'YYYY-MM-DD HH:mm:ss',
}) {
  const tz = utc ? 'UTC' : getStoredTz()
  const nowParts = () => isoToZonedParts(new Date().toISOString(), tz)
  const [open, setOpen] = useState(false)
  const [pos, setPos] = useState(null)
  const popupRef = useRef(null)
  const [parts, setParts] = useState(() => isoToZonedParts(value, tz) || nowParts())
  const [view, setView] = useState(() => ({ y: parts.y, mo: parts.mo }))
  const wrapRef = useRef(null)

  // Mirror external value changes while the popup is closed.
  useEffect(() => {
    if (open) return
    const p = isoToZonedParts(value, tz)
    if (p) { setParts(p); setView({ y: p.y, mo: p.mo }) }
  }, [value, open, tz])

  // Close on outside-click / Escape while open.
  useEffect(() => {
    if (!open) return
    const onDown = (e) => {
      if (wrapRef.current?.contains(e.target) || popupRef.current?.contains(e.target)) return
      setOpen(false)
    }
    const onKey = (e) => { if (e.key === 'Escape') setOpen(false) }
    document.addEventListener('mousedown', onDown)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('mousedown', onDown)
      document.removeEventListener('keydown', onKey)
    }
  }, [open])

  // Pin the popup to the viewport beside the trigger; re-place on scroll/resize.
  useLayoutEffect(() => {
    if (!open) { setPos(null); return }
    const place = () => {
      const trigger = wrapRef.current?.querySelector('button')
      const popup = popupRef.current
      if (!trigger || !popup) return
      const r = trigger.getBoundingClientRect()
      const h = popup.offsetHeight
      const vh = window.innerHeight, vw = window.innerWidth
      let top = r.bottom + GAP
      if (top + h > vh - MARGIN) {
        top = r.top - GAP - h >= MARGIN ? r.top - GAP - h : Math.max(MARGIN, vh - MARGIN - h)
      }
      const left = Math.min(Math.max(MARGIN, r.left), Math.max(MARGIN, vw - MARGIN - POPUP_W))
      setPos({ top, left })
    }
    place()
    window.addEventListener('resize', place)
    window.addEventListener('scroll', place, true)
    return () => {
      window.removeEventListener('resize', place)
      window.removeEventListener('scroll', place, true)
    }
  }, [open])

  const commit = (next) => {
    setParts(next)
    const iso = zonedPartsToIso(next, tz)
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
    const p = isoToZonedParts(iso, tz)
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

  const display = value ? formatLocal(value, tz) : ''
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
        title={display || placeholder}
        aria-label={id ? undefined : (display || placeholder)}
        style={{
          width: '100%', textAlign: 'left', cursor: disabled ? 'default' : 'pointer',
          display: 'flex', alignItems: 'center', gap: 'var(--space-2)',
          whiteSpace: 'nowrap', overflow: 'hidden',
          color: display ? 'var(--text)' : 'var(--dim)',
        }}
      >
        <span style={{ fontSize: '0.95em', flexShrink: 0 }} aria-hidden="true">🗓</span>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.93em', minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis' }}>
          {display || placeholder}
        </span>
      </button>
      {hint && <div className="field-hint">{tz} · 24-hour · offset shown</div>}

      {open && createPortal(
        <div
          ref={popupRef}
          role="dialog"
          aria-label="Pick date and time"
          style={{
            position: 'fixed', top: pos?.top ?? 0, left: pos?.left ?? 0, zIndex: 1000,
            visibility: pos ? 'visible' : 'hidden',
            background: 'var(--surface)', border: '1px solid var(--border-strong)',
            borderRadius: 'var(--radius)', boxShadow: 'var(--shadow)',
            padding: 'var(--space-3)', width: POPUP_W,
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
            {value ? formatLocal(value, tz) : '—'}
          </div>

          <div style={{ display: 'flex', alignItems: 'center', marginTop: 'var(--space-2)' }}>
            {clearable && (
              <button type="button" className="btn-link" onClick={() => { onChange(''); setOpen(false) }}
                style={{ fontSize: 11 }}>Clear</button>
            )}
            <button type="button" className="btn primary" onClick={() => setOpen(false)}
              style={{ fontSize: 11, padding: '3px 12px', marginLeft: 'auto' }}>Done</button>
          </div>
        </div>,
        document.body,
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
