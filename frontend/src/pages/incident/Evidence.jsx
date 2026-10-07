import { NavLink, Outlet, useOutletContext } from 'react-router-dom'

// Evidence sub-section, in ISO/IEC 27037 lifecycle order (K1, R36): register an exhibit, work with the
// exhibits, follow their custody and its integrity, disclose them, and the SOP. Supporting documents (incident
// Files: not chain-of-custody, can be registered as exhibits) sit here too. Every tab has its own route;
// the old paths (items, audit-chain, export, ../files) redirect.
const TABS = [
  { to: 'register',    label: 'Register' },
  { to: 'exhibits',    label: 'Exhibits' },
  { to: 'custody-log', label: 'Custody log' },
  { to: 'integrity',   label: 'Integrity' },
  { to: 'disclosure',  label: 'Disclosure package' },
  { to: 'sop',         label: 'SOP' },
  { to: 'documents',   label: 'Supporting documents' },
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
