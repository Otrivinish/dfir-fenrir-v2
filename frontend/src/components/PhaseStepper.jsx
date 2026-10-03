import { Fragment } from 'react'
import { PHASE } from '../lib/incidentVocab.js'

// Visual stepper for the 800-61 R3 phases. Each phase is coloured by its NIST
// CSF 2.0 function (--phase-* tokens) and carries its glyph (aria-hidden; the
// label is the accessible name); state is shown by fill / trailing ✓ / dimming.
// When `onPhaseClick` is provided, non-current steps are click-targets that
// fire `onPhaseClick(value)` so the caller can show a confirmation modal.
// Preparation is never a target (the API refuses it: 409 phase_transition_invalid).
// When `disabled` is true (e.g. closed incident, or an Observer), the stepper is static.
const NOT_A_TARGET = 'preparation'

export default function PhaseStepper({ current, onPhaseClick, disabled = false }) {
  const idx       = PHASE.findIndex(p => p.value === current)
  const clickable = !disabled && typeof onPhaseClick === 'function'

  return (
    <div className="phase-steps" role={clickable ? 'group' : 'list'} aria-label="Incident phase">
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
                title={`Change phase to ${p.label}`}
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
              title={clickable && p.value === NOT_A_TARGET && !isCurrent
                ? `${p.label} is the readiness work before an incident; an incident can't be moved to it`
                : p.label}
              className={cls}
              data-phase={p.value}
            >
              <span className="phase-glyph" aria-hidden="true">{p.glyph}</span>
              {p.short || p.label}
            </span>
            {i < PHASE.length - 1 && (
              <span className="phase-step-sep" aria-hidden="true">→</span>
            )}
          </Fragment>
        )
      })}
    </div>
  )
}
