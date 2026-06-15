// Shared severity badge — used on Dashboard and Incident detail.
// Canonical palette lives here so both views always match.
export const SEV_PALETTE = {
  critical: { bg: '#ff000022', border: '#ff000055', text: '#ff4444' },
  high:     { bg: '#ff800022', border: '#ff800055', text: '#ff8800' },
  medium:   { bg: '#ffcc0022', border: '#ffcc0055', text: '#ccaa00' },
  low:      { bg: '#00cc5522', border: '#00cc5555', text: '#00aa44' },
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
