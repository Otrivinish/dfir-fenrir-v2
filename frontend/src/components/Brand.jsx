export default function Brand({ tag = 'INCIDENT RESPONSE' }) {
  return (
    <div className="auth-brand">
      <div className="auth-brand-mark" aria-hidden="true">F</div>
      <div className="auth-brand-title">DFIR-FENRIR</div>
      <div className="auth-brand-sub">{tag}</div>
    </div>
  )
}
