// Advisory client-side password strength meter.
// Server is authoritative (min length 12). This is purely UX feedback.
// No third-party dep. Score 0..4 from length + character class variety.

function score(pw) {
  if (!pw) return 0
  let s = 0
  if (pw.length >= 12) s++
  if (pw.length >= 16) s++
  const classes = [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].reduce(
    (n, re) => n + (re.test(pw) ? 1 : 0), 0
  )
  if (classes >= 3) s++
  if (classes === 4 && pw.length >= 14) s++
  return Math.min(4, s)
}

const LABEL = ['', 'Weak', 'Fair', 'Strong', 'Excellent']

export default function StrengthMeter({ password }) {
  const n = score(password)
  return (
    <div className="strength" aria-live="polite">
      <div className="strength-bar" role="meter" aria-valuemin={0} aria-valuemax={4} aria-valuenow={n}>
        {[1, 2, 3, 4].map(i => (
          <div key={i} className={`strength-cell ${i <= n ? `on s${n}` : ''}`} />
        ))}
      </div>
      <div className="strength-label">{LABEL[n] || '—'}</div>
    </div>
  )
}
