import { NavLink, Outlet, Navigate } from 'react-router-dom'
import { useAuth } from '../hooks/useAuth.jsx'

export default function Admin() {
  const { user } = useAuth()
  if (user?.role !== 'admin') return <Navigate to="/" replace />

  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="page-title">Admin</h1>
          <div className="page-sub">Audit Log · Audit Exports · Sessions · Storage · Metrics · Backup · API Docs</div>
        </div>
      </div>

      <div className="sub-layout">
        <nav className="sub-nav" aria-label="Admin sections">
          <NavLink to="audit-log" className={({ isActive }) => `sub-item ${isActive ? 'active' : ''}`}>Audit Log</NavLink>
          <NavLink to="audit-exports" className={({ isActive }) => `sub-item ${isActive ? 'active' : ''}`}>Audit Exports</NavLink>
          <NavLink to="sessions"  className={({ isActive }) => `sub-item ${isActive ? 'active' : ''}`}>Sessions</NavLink>
          <NavLink to="storage"   className={({ isActive }) => `sub-item ${isActive ? 'active' : ''}`}>Storage</NavLink>
          <NavLink to="metrics"   className={({ isActive }) => `sub-item ${isActive ? 'active' : ''}`}>Metrics</NavLink>
          <NavLink to="backup"    className={({ isActive }) => `sub-item ${isActive ? 'active' : ''}`}>Backup</NavLink>
          <NavLink to="api-docs"  className={({ isActive }) => `sub-item ${isActive ? 'active' : ''}`}>API Docs</NavLink>
        </nav>

        <div className="sub-content">
          <Outlet />
        </div>
      </div>
    </>
  )
}
