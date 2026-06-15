import { Fragment } from 'react'
import { PHASE } from '../lib/incidentVocab.js'

// Visual stepper for the 800-61 R3 phases.
// When `onPhaseClick` is provided, non-current steps are click-targets that
// fire `onPhaseClick(value)` so the caller can show a confirmation modal.
// When `disabled` is true (e.g. closed incident), the stepper is static.
export default function PhaseStepper({ current, onPhaseClick, disabled = false }) {
  const idx       = PHASE.findIndex(p => p.value === current)
  const clickable = !disabled && typeof onPhaseClick === 'function'

  return (
    <div className="phase-steps" role={clickable ? 'group' : 'list'} aria-label="Incident phase">
      {PHASE.map((p, i) => {
        const isCurrent = i === idx
        const cls =
          'phase-step'
          + (i < idx     ? ' done'     : '')
          + (isCurrent   ? ' current'  : '')
          + (clickable && !isCurrent ? ' clickable' : '')

        if (clickable && !isCurrent) {
          return (
            <Fragment key={p.value}>
              <button
                type="button"
                className={cls}
                onClick={() => onPhaseClick(p.value)}
                title={`Change phase to ${p.label}`}
                aria-label={`Change phase to ${p.label}`}
              >
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
              title={p.label}
              className={cls}
            >
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
