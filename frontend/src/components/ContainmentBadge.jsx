import { SEV_PALETTE } from './SevBadge.jsx'

// Containment state of an entity / IOC, as computed by the API from the Respond
// board (`containment` on the entity and IOC lists). Done = SEV_PALETTE.low
// (green), pending = SEV_PALETTE.medium (amber).
const LABEL   = { isolated: 'Isolated', disabled: 'Disabled', blocked: 'Blocked' }
const PENDING = { isolated: 'Isolation', disabled: 'Disabling', blocked: 'Block' }

export default function ContainmentBadge({ containment }) {
  if (!containment) return null
  const pending = containment.state === 'pending'
  const p = pending ? SEV_PALETTE.medium : SEV_PALETTE.low
  const title = pending
    ? `${PENDING[containment.effect] ?? containment.effect} pending: its containment action on Respond is open or in progress`
    : `${LABEL[containment.effect] ?? containment.effect}: its containment action on Respond is done`
  return (
    <span className="pill" data-containment={containment.state} title={title}
          style={{ fontSize: 10, whiteSpace: 'nowrap', background: p.bg, color: p.text, borderColor: p.border }}>
      {pending ? 'Pending…' : (LABEL[containment.effect] ?? containment.effect)}
    </span>
  )
}
