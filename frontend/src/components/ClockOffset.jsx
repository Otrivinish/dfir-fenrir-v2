import { formatLocal } from '../lib/datetime.js'

// G4 (R35) — an exhibit's device clock offset: device clock minus true UTC, in whole seconds
// (+120 = the device clock ran 2 minutes ahead). Imports from the exhibit subtract it from the
// device's times and keep the time as recorded. The server does the correction; these only show it.

export const OFFSET_MAX_SECONDS = 3155760000   // 100 years either way (the API's bound)

/** "+120 s" · "−30 s" · "0 s" */
export function fmtOffset(seconds) {
  if (seconds === null || seconds === undefined) return ''
  if (seconds === 0) return '0 s'
  return `${seconds > 0 ? '+' : '−'}${Math.abs(seconds)} s`
}

/** Parse the offset field: a signed whole number of seconds. '' -> null; invalid -> undefined. */
export function parseOffsetSeconds(text) {
  const t = (text ?? '').trim().replace('−', '-')
  if (t === '') return null
  if (!/^[+-]?\d{1,10}$/.test(t)) return undefined
  const n = Number(t)
  return Math.abs(n) <= OFFSET_MAX_SECONDS ? n : undefined
}

/** Marker on an event whose time the exhibit's clock offset corrected; the recorded time on hover. */
export function OffsetMark({ seconds, recorded, size = 10 }) {
  if (seconds === null || seconds === undefined || !recorded) return null
  return (
    <span className="pill" data-offset={seconds}
          style={{ fontSize: size, padding: '0 4px', color: 'var(--accent)', borderColor: 'var(--accent)' }}
          title={`Device clock offset ${fmtOffset(seconds)} applied. Recorded by the device: ${formatLocal(recorded)}`}>
      offset-corrected ({fmtOffset(seconds)})
    </span>
  )
}

/** How an import of an exhibit relates to the exhibit's clock offset (clock_offset_status). */
export function ClockOffsetNotice({ imp }) {
  const st = imp?.clock_offset_status
  if (!st || st === 'none') return null
  if (st === 'not_applicable') {        // G-fix R78: the source's times aren't the device clock (Defender PDFs)
    return (
      <div className="alert info" role="status" data-testid="clock-offset-notice" data-status={st}
           style={{ marginBottom: 'var(--space-3)' }}>
        <span className="alert-icon">ⓘ</span>
        <span>
          Clock offset not applicable: these times come from the vendor&rsquo;s cloud service, not the device&rsquo;s clock, so
          {' '}the exhibit&rsquo;s offset is not applied to them.
        </span>
      </div>
    )
  }
  if (st === 'applied') {
    return (
      <div className="alert info" role="status" data-testid="clock-offset-notice" data-status={st}
           style={{ marginBottom: 'var(--space-3)' }}>
        <span className="alert-icon">ⓘ</span>
        <span>
          Clock offset applied: the exhibit records the device clock at <strong>{fmtOffset(imp.clock_offset_seconds)}</strong>
          {' '}from true time, so event times are corrected by it. Each event keeps the time the device recorded (hover a
          {' '}<em>offset-corrected</em> mark).
        </span>
      </div>
    )
  }
  if (st === 'changed') {
    return (
      <div className="alert warn" role="status" data-testid="clock-offset-notice" data-status={st}
           style={{ marginBottom: 'var(--space-3)' }}>
        <span className="alert-icon">!</span>
        <span>
          The exhibit&rsquo;s clock offset changed after this import: applied{' '}
          <strong>{imp.clock_offset_seconds === null || imp.clock_offset_seconds === undefined ? 'none' : fmtOffset(imp.clock_offset_seconds)}</strong>,
          {' '}now <strong>{imp.exhibit_time_offset_seconds === null || imp.exhibit_time_offset_seconds === undefined ? 'none' : fmtOffset(imp.exhibit_time_offset_seconds)}</strong>.
          {' '}This import and the events promoted from it keep their times. Import the exhibit again to apply the new offset.
        </span>
      </div>
    )
  }
  return (
    <div className="alert warn" role="status" data-testid="clock-offset-notice" data-status={st}
         style={{ marginBottom: 'var(--space-3)' }}>
      <span className="alert-icon">!</span>
      <span>
        Clock offset not applied: the exhibit records it only as text
        {imp.exhibit_time_offset ? <> (<strong>{imp.exhibit_time_offset}</strong>)</> : null}, which FENRIR never
        {' '}interprets. Set the offset in seconds on the exhibit (Evidence → item → Device clock), then import it again.
      </span>
    </div>
  )
}
