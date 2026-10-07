// Shared severity badge — used on Dashboard and Incident detail.
// Canonical palette lives here so both views always match.
// L2 (R46): the text colour reads a per-theme override (--sev-*-text, set by the light theme only, where
// the bright hex is 1.9-2.5:1 on its tint); the canonical hex is the fallback, so the dark themes are unchanged.
export const SEV_PALETTE = {
  critical: { bg: '#ff000022', border: '#ff000055', text: 'var(--sev-crit-text, #ff4444)' },
  high:     { bg: '#ff800022', border: '#ff800055', text: 'var(--sev-high-text, #ff8800)' },
  medium:   { bg: '#ffcc0022', border: '#ffcc0055', text: 'var(--sev-med-text, #ccaa00)' },
  low:      { bg: '#00cc5522', border: '#00cc5555', text: 'var(--sev-low-text, #00aa44)' },
}

export default function SevBadge({ value }) {
  const p = SEV_PALETTE[value] ?? { bg: 'var(--surface-2)', border: 'var(--border)', text: 'var(--muted)' }
  return (
    <span style={{
      display: 'inline-block',
      padding: '2px 7px',
      borderRadius: 3,
      fontSize: 10,
      fontWeight: 700,
      textTransform: 'uppercase',
      letterSpacing: '0.07em',
      background: p.bg,
      color: p.text,
      border: `1px solid ${p.border}`,
      fontFamily: 'var(--font-mono)',
    }}>
      {value}
    </span>
  )
}
