import { NavLink, Outlet } from 'react-router-dom'
import { useAuth } from '../hooks/useAuth.jsx'

export default function Settings() {
  const { user } = useAuth()
  const isAdmin = user?.role === 'admin'

  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="page-title">Settings</h1>
          <div className="page-sub">
            Account{isAdmin ? ' · Users · Teams · Operational Roles · Stakeholder Matrix · Validated Tools · Feeds · Integrations · API Keys' : ''}
          </div>
        </div>
      </div>

      <div className="sub-layout">
        <nav className="sub-nav" aria-label="Settings sections">
          <NavLink to="account"  className={({ isActive }) => `sub-item ${isActive ? 'active' : ''}`}>Account</NavLink>
          {isAdmin && (
            <>
              <NavLink to="users"              className={({ isActive }) => `sub-item ${isActive ? 'active' : ''}`}>Users</NavLink>
              <NavLink to="teams"              className={({ isActive }) => `sub-item ${isActive ? 'active' : ''}`}>Teams</NavLink>
              <NavLink to="operational-roles"  className={({ isActive }) => `sub-item ${isActive ? 'active' : ''}`}>Operational Roles</NavLink>
              <NavLink to="stakeholder-matrix" className={({ isActive }) => `sub-item ${isActive ? 'active' : ''}`}>Stakeholder Matrix</NavLink>
              <NavLink to="validated-tools"    className={({ isActive }) => `sub-item ${isActive ? 'active' : ''}`}>Validated Tools</NavLink>
              <NavLink to="threat-intel"       className={({ isActive }) => `sub-item ${isActive ? 'active' : ''}`}>Feeds</NavLink>
              <NavLink to="integrations"       className={({ isActive }) => `sub-item ${isActive ? 'active' : ''}`}>Integrations</NavLink>
              <NavLink to="api-keys"           className={({ isActive }) => `sub-item ${isActive ? 'active' : ''}`}>API Keys</NavLink>
            </>
          )}
        </nav>

        <div className="sub-content">
          <Outlet />
        </div>
      </div>
    </>
  )
}
