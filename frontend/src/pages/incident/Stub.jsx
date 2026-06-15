// Shared placeholder for incident sub-sections not yet implemented.
// Replaced piece-by-piece in later expansion steps.
export default function Stub({ title, mark = '·', hint }) {
  return (
    <div className="panel">
      <h2 className="panel-h">{title}</h2>
      <div className="panel-empty">
        <div className="panel-empty-mark" aria-hidden="true">{mark}</div>
        <div>{title} coming soon.</div>
        {hint && <div style={{ color: 'var(--dim)', fontSize: 12 }}>{hint}</div>}
      </div>
    </div>
  )
}
