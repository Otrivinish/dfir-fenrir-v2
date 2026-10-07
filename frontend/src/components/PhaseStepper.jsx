import { Fragment, useEffect, useState } from 'react'
import { PHASE } from '../lib/incidentVocab.js'
import { formatLocal } from '../lib/datetime.js'
import { span } from './ClockChips.jsx'

// Visual stepper for the 800-61 R3 phases. Each phase is coloured by its NIST
// CSF 2.0 function (--phase-* tokens) and carries its glyph (aria-hidden; the
// label is the accessible name); state is shown by fill / trailing ✓ / dimming.
// When `onPhaseClick` is provided, non-current steps are click-targets that
// fire `onPhaseClick(value)` so the caller can show a confirmation modal.
// Preparation is never a target (the API refuses it: 409 phase_transition_invalid).
// When `disabled` is true (e.g. closed incident, or an Observer), the stepper is static.
// `hint` (with disabled) says why it can't be used right now: shown beside the steps and
// as each step's tooltip (e.g. while the Details form has unsaved edits).
const NOT_A_TARGET = 'preparation'

// K2 (R38): `history` = GET …/phase-history (or the snapshot's phase_history). The current step shows its
// time in phase (ticking each minute while open); a hover on any step gives how long it took before.
export function usePhaseTimes(history) {
  const [now, setNow] = useState(() => Date.now())
  const ticking = !!history && !history.closed
  useEffect(() => {
    if (!ticking) return undefined
    const t = setInterval(() => setNow(Date.now()), 60_000)
    return () => clearInterval(t)
  }, [ticking])
  if (!history) return null
  const last = history.periods?.[history.periods.length - 1]
  const inPhaseMs = history.closed ? (last?.duration_seconds ?? 0) * 1000 : now - new Date(history.entered_at).getTime()
  const took = Object.fromEntries((history.completed || []).map(c => [c.phase, c]))
  return { inPhase: span(inPhaseMs), since: formatLocal(history.entered_at), closed: history.closed, took }
}

const tookText = (t) => t ? `${span(t.seconds * 1000)}${t.periods > 1 ? ` over ${t.periods} periods` : ''}` : null

export default function PhaseStepper({ current, onPhaseClick, disabled = false, hint = null, history = null }) {
  const idx       = PHASE.findIndex(p => p.value === current)
  const clickable = !disabled && typeof onPhaseClick === 'function'
  const why       = disabled && hint ? hint : null
  const times     = usePhaseTimes(history)
  // Hover text on a step: how long it took (earlier periods), and for the current step since when.
  const timeNote = (p, isCurrent) => {
    if (!times) return ''
    const before = tookText(times.took[p.value])
    if (isCurrent) return ` · in this phase ${times.inPhase}${times.closed ? ' (closed)' : ''}, since ${times.since}` +
                          (before ? `; earlier ${before}` : '')
    return before ? ` · took ${before}` : ''
  }

  return (
    <>
    <div className="phase-steps" role={clickable ? 'group' : 'list'} aria-label="Incident phase"
         aria-describedby={why ? 'phase-steps-hint' : undefined}>
      {PHASE.map((p, i) => {
        const isCurrent = i === idx
        const target    = clickable && !isCurrent && p.value !== NOT_A_TARGET
        const cls =
          'phase-step'
          + (i < idx     ? ' done'     : '')
          + (isCurrent   ? ' current'  : '')
          + (target      ? ' clickable' : '')

        if (target) {
          return (
            <Fragment key={p.value}>
              <button
                type="button"
                className={cls}
                data-phase={p.value}
                onClick={() => onPhaseClick(p.value)}
                title={`Change phase to ${p.label}${timeNote(p, false)}`}
                aria-label={`Change phase to ${p.label}`}
              >
                <span className="phase-glyph" aria-hidden="true">{p.glyph}</span>
                {p.short || p.label}
              </button>
              {i < PHASE.length - 1 && (
                <span className="phase-step-sep" aria-hidden="true">→</span>
              )}
            </Fragment>
          )
        }

        return (
          <Fragment key={p.value}>
            <span
              role={clickable ? undefined : 'listitem'}
              aria-current={isCurrent ? 'step' : undefined}
              title={(clickable && p.value === NOT_A_TARGET && !isCurrent
                ? `${p.label} is the readiness work before an incident; an incident can't be moved to it`
                : why ? `${p.label} — ${why}` : p.label) + timeNote(p, isCurrent)}
              className={cls}
              data-phase={p.value}
            >
              <span className="phase-glyph" aria-hidden="true">{p.glyph}</span>
              {p.short || p.label}
              {isCurrent && times && <span className="phase-time" data-phase-time>{times.inPhase}</span>}
            </span>
            {i < PHASE.length - 1 && (
              <span className="phase-step-sep" aria-hidden="true">→</span>
            )}
          </Fragment>
        )
      })}
    </div>
    {why && <span id="phase-steps-hint" className="phase-steps-hint" role="note">{why}</span>}
    </>
  )
}
