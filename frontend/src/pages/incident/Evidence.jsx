import { NavLink, Outlet, useOutletContext } from 'react-router-dom'

// Evidence sub-section — chain of custody.
// Phase 1: Items (built). CustodyLog / AuditChain / Export are stubs until
// Phase 2 (export pipeline) and Phase 3 (chain verifier + global timeline).
const TABS = [
  { to: 'items',       label: 'Items' },
  { to: 'custody-log', label: 'Custody log' },
  { to: 'audit-chain', label: 'Audit chain' },
  { to: 'export',      label: 'Export' },
  { to: 'sop',         label: 'CoC SOP' },
]

export default function Evidence() {
  const ctx = useOutletContext()
  return (
    <>
      <nav className="tabs-h" aria-label="Evidence inner sections">
        {TABS.map(t => (
          <NavLink
            key={t.to}
            to={t.to}
            className={({ isActive }) => `tab-h ${isActive ? 'active' : ''}`}
          >
            {t.label}
          </NavLink>
        ))}
      </nav>
      <Outlet context={ctx} />
    </>
  )
}
