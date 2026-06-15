import { NavLink } from 'react-router-dom'
import { useAuth } from '../hooks/useAuth.jsx'

const NAV = [
  { to: '/',           label: 'Dashboard',   icon: '▣', end: true },
  { to: '/incidents',  label: 'Incidents',   icon: '⚠' },
  { to: '/playbooks',  label: 'Playbooks',   icon: '▤' },
  { to: '/correlations', label: 'Correlations', icon: '⋈' },
  { to: '/threat-intel', label: 'Threat Intel', icon: '◎' },
  { to: '/threat-actors', label: 'Threat Actors', icon: '◇' },
  { to: '/mitre',       label: 'ATT&CK Matrix', icon: '▦' },
  { to: '/on-call',    label: 'On-Call',     icon: '⏱' },
  { to: '/handoffs',   label: 'Handoffs',    icon: '↔' },
  { to: '/roster',     label: 'IR Roster',   icon: '◈' },
  { to: '/help',       label: 'Help',        icon: '?' },
  { to: '/settings',   label: 'Settings',    icon: '⚙' },
]

const ADMIN_NAV = [
  { to: '/admin', label: 'Admin', icon: '⊕' },
]

export default function Sidebar({ collapsed, onToggle }) {
  const { user } = useAuth()
  const isAdmin = user?.role === 'admin'
  return (
    <aside className={`sb ${collapsed ? 'collapsed' : ''}`} aria-label="Primary navigation">
      <div className="sb-brand">
        <div className="sb-logo" aria-hidden="true">F</div>
        <div className="sb-name">FENRIR</div>
        <button
          className="sb-toggle"
          type="button"
          onClick={onToggle}
          aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          aria-expanded={!collapsed}
          title={collapsed ? 'Expand' : 'Collapse'}
        >{collapsed ? '›' : '‹'}</button>
      </div>

      {!collapsed && <div className="sb-section">Navigation</div>}

      <nav className="sb-nav">
        {NAV.map(item => (
          <NavLink
            key={item.to}
            to={item.to}
            end={item.end}
            className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
            title={collapsed ? item.label : undefined}
          >
            <span className="nav-icon" aria-hidden="true">{item.icon}</span>
            <span className="nav-label">{item.label}</span>
          </NavLink>
        ))}
        {isAdmin && ADMIN_NAV.map(item => (
          <NavLink
            key={item.to}
            to={item.to}
            className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
            title={collapsed ? item.label : undefined}
          >
            <span className="nav-icon" aria-hidden="true">{item.icon}</span>
            <span className="nav-label">{item.label}</span>
          </NavLink>
        ))}
      </nav>

      <div className="sb-foot">
        <span className="stat-dot" aria-hidden="true" title="System operational" />
        <div className="who">
          <span className="who-name">{user?.username || '—'}</span>
          <span className="who-role">{user?.role || ''}</span>
        </div>
      </div>
    </aside>
  )
}
