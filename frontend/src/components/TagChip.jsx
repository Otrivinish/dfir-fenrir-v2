// Tag chip — hash-coloured pill rendered consistently across the app.
// Same string → same colour everywhere (stable hue from a tiny non-cryptographic
// hash). Per FENRIR2 design decision (2026-05-17) tags are lowercase-dashed
// at the API boundary, so this component only needs to render whatever string
// it receives.

const MAX_TAG_LENGTH = 64

function hueFromTag(s) {
  let h = 0
  for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) & 0xffff
  return h % 360
}

export default function TagChip({ tag, onRemove, dense = false, onClick = null, title }) {
  if (!tag) return null
  const hue = hueFromTag(tag)
  const bg     = `hsl(${hue}, 50%, 18%)`
  const border = `hsl(${hue}, 45%, 35%)`
  const text   = `hsl(${hue}, 70%, 78%)`
  return (
    <span
      role={onClick ? 'button' : undefined}
      tabIndex={onClick ? 0 : undefined}
      onClick={onClick || undefined}
      onKeyDown={onClick ? (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onClick() } } : undefined}
      title={title || tag}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 4,
        fontFamily: 'var(--font-mono)',
        fontSize: dense ? 9 : 10,
        fontWeight: 600,
        padding: dense ? '0 5px' : '1px 6px',
        borderRadius: 'var(--radius-sm)',
        color: text,
        background: bg,
        border: `1px solid ${border}`,
        cursor: onClick ? 'pointer' : 'default',
        userSelect: 'none',
        maxWidth: '100%',
        overflow: 'hidden',
        textOverflow: 'ellipsis',
        whiteSpace: 'nowrap',
      }}
    >
      <span>{tag}</span>
      {onRemove && (
        <button
          type="button"
          onClick={(e) => { e.stopPropagation(); onRemove(tag) }}
          aria-label={`Remove tag ${tag}`}
          style={{
            background: 'transparent', border: 'none', color: text,
            padding: 0, cursor: 'pointer', fontSize: dense ? 10 : 11,
            lineHeight: 1,
          }}
        >×</button>
      )}
    </span>
  )
}

export { MAX_TAG_LENGTH }
