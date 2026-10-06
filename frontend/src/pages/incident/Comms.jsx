import { useCallback, useMemo, useState } from 'react'
import { NavLink, Outlet, useOutletContext } from 'react-router-dom'
import StakeholderMatrixBanner from '../../components/StakeholderMatrixBanner.jsx'

const TABS = [
  { to: 'comments',      label: 'Comments' },
  { to: 'oob',           label: 'OOB' },
  { to: 'stakeholders',  label: 'Stakeholders' },
  { to: 'notifications', label: 'Notifications' },
]

export default function Comms() {
  const ctx = useOutletContext()
  // I2: the Notifications tab bumps this after a write so the banner (its summary) re-reads.
  const [notifyRev, setNotifyRev] = useState(0)
  const bumpNotify = useCallback(() => setNotifyRev(r => r + 1), [])
  const outCtx = useMemo(() => ({ ...ctx, bumpNotify }), [ctx, bumpNotify])
  return (
    <>
      <StakeholderMatrixBanner incidentId={ctx?.inc?.id} rev={`${notifyRev}-${ctx?.inc?.updated_at}`} />
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
      <Outlet context={outCtx} />
    </>
  )
}
