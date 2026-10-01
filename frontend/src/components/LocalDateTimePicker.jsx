import { useEffect, useId, useLayoutEffect, useMemo, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import { formatLocal, isoToZonedParts, zonedPartsToIso } from '../lib/datetime.js'
import { getStoredTz } from '../lib/timezone.js'

// THE date+time entry component (UX standard — see CLAUDE.md "Date/time entry
// standard"). Use it for every date+time field; don't add another one.
//
// A read-only trigger opens a popup: a month calendar, HH / MM / SS drums, a switch
// to enter the time in the user's stored (Fenrir) timezone or in UTC, and a readout
// of both. Edits are staged in the popup and reach `onChange` only on Apply;
// Cancel, Escape and an outside click discard them. `utc` makes UTC the zone the
// trigger shows and the popup starts in — for filters over data that is itself
// shown in UTC. Storage/transmit stay UTC either way.
//
// Contract:
//   value:    canonical ISO string (`…Z`) or ''
//   onChange: receives a canonical UTC ISO string on Apply ('' on Clear)
//
// The popup is portalled to <body> and pinned to the viewport next to the
// trigger (flipping above it when there's no room below); when it is taller than
// the viewport it scrolls itself. Styles: styles/datetime-picker.css (tokens only).

const GAP = 4
const MARGIN = 8
const WHEEL_STEP_PX = 40

const WEEKDAYS = ['Mo', 'Tu', 'We', 'Th', 'Fr', 'Sa', 'Su']
const MONTHS = ['January', 'February', 'March', 'April', 'May', 'June', 'July',
  'August', 'September', 'October', 'November', 'December']
const UNITS = [
  { key: 'h', label: 'HH', name: 'Hour', max: 24 },
  { key: 'mi', label: 'MM', name: 'Minute', max: 60 },
  { key: 's', label: 'SS', name: 'Second', max: 60 },
]
const DRUM_OFFSETS = [-2, -1, 0, 1, 2]

function pad(n) { return String(n).padStart(2, '0') }
function wrap(v, max) { return ((v % max) + max) % max }
function daysInMonth(y, mo) { return new Date(Date.UTC(y, mo, 0)).getUTCDate() }
// Monday-first weekday index (0=Mon … 6=Sun) of the 1st of the month.
function firstWeekday(y, mo) { return (new Date(Date.UTC(y, mo - 1, 1)).getUTCDay() + 6) % 7 }
// The calendar date `n` days after y-mo-d (rolls over months and years).
function addDays({ y, mo, d }, n) {
  const t = new Date(Date.UTC(y, mo - 1, d + n))
  return { y: t.getUTCFullYear(), mo: t.getUTCMonth() + 1, d: t.getUTCDate() }
}
function nowIn(zone) { return isoToZonedParts(new Date().toISOString(), zone) }

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
  const fenrirTz = getStoredTz()
  const tz = utc ? 'UTC' : fenrirTz          // zone the trigger shows + the popup starts in
  const uid = useId()
  const [open, setOpen] = useState(false)
  const [pos, setPos] = useState(null)
  const [zone, setZone] = useState(tz)        // entry zone while the popup is open
  const [parts, setParts] = useState(null)    // staged wall-clock {y,mo,d,h,mi,s} in `zone`
  const [view, setView] = useState(null)      // calendar month shown {y, mo}
  const [focusDay, setFocusDay] = useState(null)
  const wrapRef = useRef(null)
  const popupRef = useRef(null)
  const wheelAcc = useRef(0)

  // null when the staged wall-clock time doesn't exist in `zone` (DST gap).
  const draftIso = open && parts ? zonedPartsToIso(parts, zone) : null

  const focusTrigger = () => wrapRef.current?.querySelector('button')?.focus()
  const openPopup = () => {
    const p = isoToZonedParts(value, tz) || nowIn(tz)
    setZone(tz)
    setParts(p)
    setView({ y: p.y, mo: p.mo })
    setOpen(true)
  }
  const cancel = () => { setOpen(false); focusTrigger() }
  const apply = () => {
    if (!draftIso) return
    onChange(draftIso)
    setOpen(false)
    focusTrigger()
  }
  const clear = () => { onChange(''); setOpen(false); focusTrigger() }

  // Outside click discards; Escape discards and returns focus to the trigger.
  useEffect(() => {
    if (!open) return
    const onDown = (e) => {
      if (wrapRef.current?.contains(e.target) || popupRef.current?.contains(e.target)) return
      setOpen(false)
    }
    const onKey = (e) => { if (e.key === 'Escape') { setOpen(false); focusTrigger() } }
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
      const h = popup.offsetHeight, w = popup.offsetWidth
      const vh = window.innerHeight, vw = window.innerWidth
      let top = r.bottom + GAP
      if (top + h > vh - MARGIN) {
        top = r.top - GAP - h >= MARGIN ? r.top - GAP - h : Math.max(MARGIN, vh - MARGIN - h)
      }
      const left = Math.min(Math.max(MARGIN, r.left), Math.max(MARGIN, vw - MARGIN - w))
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

  // Move focus into the popup once it is placed: the calendar's tab stop.
  const placed = pos !== null
  useEffect(() => {
    if (open && placed) popupRef.current?.querySelector('.dtp-day[tabindex="0"]')?.focus()
  }, [open, placed])

  // After arrow-key navigation, focus the newly selected day.
  useEffect(() => {
    if (focusDay === null) return
    popupRef.current?.querySelector(`[data-day="${focusDay}"]`)?.focus()
    setFocusDay(null)
  }, [focusDay, view])

  const setUnit = (key, v) => setParts(p => ({ ...p, [key]: v }))
  const stepUnit = (key, delta) => {
    const max = UNITS.find(u => u.key === key).max
    setParts(p => ({ ...p, [key]: wrap(p[key] + delta, max) }))
  }

  // Mouse wheel over a drum steps it. Native non-passive listener: React's onWheel
  // is passive, so it couldn't stop the page (and this pinned popup) scrolling.
  useEffect(() => {
    const el = popupRef.current
    if (!open || !el) return
    const onWheel = (e) => {
      const drum = e.target.closest?.('[data-unit]')
      if (!drum) return
      e.preventDefault()
      wheelAcc.current += e.deltaMode === 1 ? e.deltaY * 16 : e.deltaY
      const steps = Math.trunc(wheelAcc.current / WHEEL_STEP_PX)
      if (steps) {
        wheelAcc.current -= steps * WHEEL_STEP_PX
        stepUnit(drum.dataset.unit, steps)
      }
    }
    el.addEventListener('wheel', onWheel, { passive: false })
    return () => el.removeEventListener('wheel', onWheel)
  }, [open])

  const cells = useMemo(() => {
    if (!view) return []
    const out = Array(firstWeekday(view.y, view.mo)).fill(null)
    for (let d = 1; d <= daysInMonth(view.y, view.mo); d++) out.push(d)
    while (out.length < 42) out.push(null)    // always 6 rows: the popup never jumps
    return out
  }, [view])

  const display = value ? formatLocal(value, tz) : ''
  const trigger = (
    <button
      id={id}
      type="button"
      className="input"
      disabled={disabled}
      aria-haspopup="dialog"
      aria-expanded={open}
      onClick={() => { if (disabled) return; if (open) setOpen(false); else openPopup() }}
      title={display || placeholder}
      aria-label={id ? undefined : (display || placeholder)}
      style={{
        width: '100%', textAlign: 'left', cursor: disabled ? 'default' : 'pointer',
        display: 'flex', alignItems: 'center', gap: 'var(--space-2)',
        whiteSpace: 'nowrap', overflow: 'hidden',
        color: display ? 'var(--text)' : 'var(--dim)',
      }}
    >
      <CalendarIcon />
      <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.93em', minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis' }}>
        {display || placeholder}
      </span>
    </button>
  )

  let popup = null
  if (open && parts && view) {
    const monthIso = `${view.y}-${pad(view.mo)}`
    const today = nowIn(zone)
    const inView = parts.y === view.y && parts.mo === view.mo
    const tabDay = inView ? parts.d : 1
    const isToday = (d) => d === today.d && view.y === today.y && view.mo === today.mo
    const offsetAt = formatLocal(draftIso || new Date().toISOString(), fenrirTz).slice(-6)

    const stepMonth = (delta) => setView(v => {
      let y = v.y, mo = v.mo + delta
      if (mo < 1) { mo = 12; y -= 1 }
      if (mo > 12) { mo = 1; y += 1 }
      return { y, mo }
    })
    const pickDay = (d) => setParts(p => ({ ...p, y: view.y, mo: view.mo, d }))
    const onDayKey = (e) => {
      const delta = { ArrowLeft: -1, ArrowRight: 1, ArrowUp: -7, ArrowDown: 7 }[e.key]
      if (delta === undefined) return
      e.preventDefault()
      const next = addDays({ y: view.y, mo: view.mo, d: +e.currentTarget.dataset.day }, delta)
      setParts(p => ({ ...p, ...next }))
      setView({ y: next.y, mo: next.mo })
      setFocusDay(next.d)
    }
    const onDrumKey = (u) => (e) => {
      const delta = { ArrowUp: -1, ArrowDown: 1, PageUp: -10, PageDown: 10 }[e.key]
      if (delta !== undefined) { e.preventDefault(); stepUnit(u.key, delta) }
      else if (e.key === 'Home') { e.preventDefault(); setUnit(u.key, 0) }
      else if (e.key === 'End') { e.preventDefault(); setUnit(u.key, u.max - 1) }
    }
    const switchZone = (z) => {
      if (z === zone) return
      const iso = zonedPartsToIso(parts, zone)
      const p = iso ? isoToZonedParts(iso, z) : parts
      setZone(z)
      setParts(p)
      setView({ y: p.y, mo: p.mo })
    }
    const setNow = () => {
      const p = nowIn(zone)
      setParts(p)
      setView({ y: p.y, mo: p.mo })
    }
    // Enter applies — except on a button, where it activates that button.
    const onPopupKey = (e) => {
      if (e.key === 'Enter' && e.target.tagName !== 'BUTTON') { e.preventDefault(); apply() }
    }

    popup = createPortal(
      <div
        ref={popupRef}
        className="dtp"
        role="dialog"
        aria-labelledby={`${uid}-title`}
        onKeyDown={onPopupKey}
        style={{ top: pos?.top ?? 0, left: pos?.left ?? 0, visibility: pos ? 'visible' : 'hidden' }}
      >
        <div className="dtp-head">
          <span id={`${uid}-title`} className="dtp-title">Pick date and time</span>
          {fenrirTz !== 'UTC' && (
            <div className="dtp-zone" role="group" aria-label="Enter the time in">
              <button type="button" aria-pressed={zone !== 'UTC'} onClick={() => switchZone(fenrirTz)}>
                {fenrirTz} {offsetAt}
              </button>
              <button type="button" aria-pressed={zone === 'UTC'} onClick={() => switchZone('UTC')}>
                UTC +00:00
              </button>
            </div>
          )}
        </div>

        <div className="dtp-body">
          <div className="dtp-cal">
            <div className="dtp-cal-nav">
              <button type="button" className="dtp-icon-btn" aria-label="Previous month" onClick={() => stepMonth(-1)}>
                <Chevron d="M15 6l-6 6 6 6" />
              </button>
              <span className="dtp-month" aria-live="polite">
                {monthIso}<span>{MONTHS[view.mo - 1]}</span>
              </span>
              <button type="button" className="dtp-icon-btn" aria-label="Next month" onClick={() => stepMonth(1)}>
                <Chevron d="M9 6l6 6-6 6" />
              </button>
            </div>
            <div className="dtp-wk" aria-hidden="true">
              {WEEKDAYS.map(w => <span key={w}>{w}</span>)}
            </div>
            <div className="dtp-days" role="group" aria-label={`Days of ${monthIso}`}>
              {cells.map((d, i) => d === null ? <span key={`b${i}`} /> : (
                <button
                  key={d}
                  type="button"
                  data-day={d}
                  tabIndex={d === tabDay ? 0 : -1}
                  className={`dtp-day${isToday(d) ? ' is-today' : ''}`}
                  aria-pressed={inView && d === parts.d}
                  aria-label={`${monthIso}-${pad(d)}${isToday(d) ? ', today' : ''}`}
                  onClick={() => pickDay(d)}
                  onKeyDown={onDayKey}
                >{d}</button>
              ))}
            </div>
          </div>

          <div className="dtp-time">
            <div className="dtp-drums">
              {UNITS.map(u => {
                const sel = parts[u.key]
                return (
                  <div key={u.key} className="dtp-drum" data-unit={u.key}>
                    <span className="dtp-drum-label" aria-hidden="true">{u.label}</span>
                    <button type="button" className="dtp-step" aria-label={`Previous ${u.name.toLowerCase()}`}
                      onClick={() => stepUnit(u.key, -1)}>
                      <Chevron d="M6 15l6-6 6 6" />
                    </button>
                    <div
                      className="dtp-list"
                      role="listbox"
                      tabIndex={0}
                      aria-label={u.name}
                      aria-activedescendant={`${uid}-${u.key}-sel`}
                      onKeyDown={onDrumKey(u)}
                    >
                      {DRUM_OFFSETS.map(k => {
                        const v = wrap(sel + k, u.max)
                        const cls = k === 0 ? 'is-sel' : Math.abs(k) === 1 ? 'is-near' : 'is-far'
                        return (
                          <div
                            key={k}
                            id={k === 0 ? `${uid}-${u.key}-sel` : undefined}
                            role="option"
                            aria-selected={k === 0}
                            aria-posinset={v + 1}
                            aria-setsize={u.max}
                            className={`dtp-opt ${cls}`}
                            onClick={() => setUnit(u.key, v)}
                          >{pad(v)}</div>
                        )
                      })}
                    </div>
                    <button type="button" className="dtp-step" aria-label={`Next ${u.name.toLowerCase()}`}
                      onClick={() => stepUnit(u.key, 1)}>
                      <Chevron d="M6 9l6 6 6-6" />
                    </button>
                  </div>
                )
              })}
            </div>
            <div className="dtp-quick">
              <button type="button" className="btn ghost" onClick={setNow}>Now</button>
              <button type="button" className="btn ghost" onClick={() => setParts(p => ({ ...p, h: 0, mi: 0, s: 0 }))}>
                Start of day
              </button>
            </div>
          </div>
        </div>

        <div className="dtp-readout" aria-live="polite">
          {draftIso ? (
            <>
              <span className={`dtp-readout-label${zone !== 'UTC' ? ' is-entry' : ''}`}>{fenrirTz}</span>
              <span className="dtp-mono">{formatLocal(draftIso, fenrirTz)}</span>
              <span className={`dtp-readout-label${zone === 'UTC' ? ' is-entry' : ''}`}>UTC · stored</span>
              <span className="dtp-mono">{draftIso.replace(/\.\d{3}Z$/, 'Z')}</span>
            </>
          ) : (
            <span className="dtp-error">
              {pad(parts.h)}:{pad(parts.mi)}:{pad(parts.s)} doesn't exist in {zone} on{' '}
              {parts.y}-{pad(parts.mo)}-{pad(parts.d)} — the clocks move forward then. Pick another time.
            </span>
          )}
        </div>

        <div className="dtp-foot">
          {clearable && (
            <button type="button" className="btn-link" onClick={clear}>Clear field</button>
          )}
          <div className="dtp-foot-actions">
            <button type="button" className="btn ghost" onClick={cancel}>Cancel</button>
            <button type="button" className="btn primary" onClick={apply} disabled={!draftIso}>Apply</button>
          </div>
        </div>
      </div>,
      document.body,
    )
  }

  return (
    <div ref={wrapRef} style={{ position: 'relative' }}>
      {trigger}
      {hint && <div className="field-hint">{tz} · 24-hour · offset shown</div>}
      {popup}

      {/* keep native required semantics on the form. Not readOnly: browsers skip
          constraint validation on read-only inputs, so `required` would never fire. */}
      {required && (
        <input type="text" value={value || ''} onChange={() => {}} required aria-hidden="true" tabIndex={-1}
          style={{ position: 'absolute', width: 1, height: 1, opacity: 0, pointerEvents: 'none' }} />
      )}
    </div>
  )
}

function Chevron({ d }) {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2"
      strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d={d} /></svg>
  )
}

function CalendarIcon() {
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"
      strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" style={{ flexShrink: 0, color: 'var(--muted)' }}>
      <rect x="3" y="5" width="18" height="16" rx="2" /><path d="M3 10h18M8 3v4M16 3v4" />
    </svg>
  )
}
