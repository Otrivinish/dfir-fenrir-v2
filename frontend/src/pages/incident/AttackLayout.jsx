import { NavLink, Outlet, useOutletContext } from 'react-router-dom'

// ATT&CK & attribution (route segment `mitre`): Coverage (index, Mitre.jsx) and
// Attribution (`mitre/attribution`, forensic/Attribution.jsx). Attribution is a
// conclusion drawn from the observed techniques, so it sits next to them.
const TABS = [
  { to: '.',           label: 'Coverage', end: true },
  { to: 'attribution', label: 'Attribution' },
]

export default function AttackLayout() {
  // Pass the parent IncidentDetail's Outlet context through: both tabs read `inc` from it.
  const ctx = useOutletContext()
  return (
    <>
      <nav className="tabs-h" aria-label="ATT&CK & attribution sections">
        {TABS.map(t => (
          <NavLink
            key={t.to}
            to={t.to}
            end={t.end}
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
