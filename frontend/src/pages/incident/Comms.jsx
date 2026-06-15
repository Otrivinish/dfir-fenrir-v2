import { NavLink, Outlet, useOutletContext } from 'react-router-dom'
import StakeholderMatrixBanner from '../../components/StakeholderMatrixBanner.jsx'

const TABS = [
  { to: 'comments',      label: 'Comments' },
  { to: 'oob',           label: 'OOB' },
  { to: 'stakeholders',  label: 'Stakeholders' },
]

export default function Comms() {
  const ctx = useOutletContext()
  return (
    <>
      <StakeholderMatrixBanner severity={ctx?.inc?.severity} />
      <nav className="tabs-h" aria-label="Comms sections">
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
