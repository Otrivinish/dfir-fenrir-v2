import { useMemo } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { useAuth } from '../hooks/useAuth.jsx'

// Global navigation in groups (D5, ignore/ir-workflow-audit-2026-10-01.md). `roles` lists who
// sees a link and mirrors the backend guard on that page's API: require_analyst = admin + analyst,
// require_admin = admin; no `roles` = every signed-in user. The API enforces the same rule.
const ANALYST = ['admin', 'analyst']
const ADMIN = ['admin']

const NAV_GROUPS = [
  { label: 'Operate', items: [
    { to: '/',             label: 'Dashboard',       icon: '▣', end: true, roles: ANALYST },
    { to: '/incidents',    label: 'Incidents',       icon: '⚠' },
    { to: '/handoffs',     label: 'Shift handoffs',  icon: '↔' },
    { to: '/on-call',      label: 'On-call',         icon: '⏱' },
  ] },
  { label: 'Investigate', items: [
    { to: '/correlations', label: 'Correlations',    icon: '⋈' },
    { to: '/mitre',        label: 'ATT&CK coverage', icon: '▦' },
  ] },
  { label: 'Intel', items: [
    { to: '/threat-intel', label: 'Threat intel',    icon: '◎', roles: ANALYST },
    { to: '/threat-actors', label: 'Threat actors',  icon: '◇' },
  ] },
  { label: 'Prepare', items: [
    { to: '/readiness',    label: 'Readiness',       icon: '⊙', roles: ANALYST },
    { to: '/playbooks',    label: 'Playbooks',       icon: '▤' },
    { to: '/roster',       label: 'IR roster',       icon: '◈' },
    { to: '/contacts',     label: 'Contacts',        icon: '☎', roles: ANALYST },
    { to: '/stakeholder-matrix', label: 'Stakeholder matrix', icon: '⊞', roles: ADMIN },
    { to: '/validated-tools',    label: 'Validated tools',    icon: '✓', roles: ADMIN },
  ] },
  { label: 'Report', items: [
    { to: '/metrics',      label: 'Metrics',         icon: '▥', roles: ANALYST },
  ] },
  { label: 'Admin', items: [
    { to: '/admin',        label: 'Admin',           icon: '⊕', roles: ADMIN },
    { to: '/settings',     label: 'Settings',        icon: '⚙' },
  ] },
]

const FOOT_NAV = [
  { to: '/help',             label: 'Help',    icon: '?' },
  { to: '/settings/account', label: 'Account', icon: '◍' },
]

const allowed = (item, role) => !item.roles || item.roles.includes(role)

// Exactly one link is active: the most specific match wins, so /settings/account lights
// Account and not Settings as well (NavLink would mark both).
function activeTarget(links, pathname) {
  let best = null
  for (const l of links) {
    const hit = l.end ? pathname === l.to : pathname === l.to || pathname.startsWith(`${l.to}/`)
    if (hit && (!best || l.to.length > best.length)) best = l.to
  }
  return best
}

// `title` is always set: below 700 px the sidebar collapses in CSS only, and the
// title is then the link's tooltip and accessible name.
function NavItem({ item, active }) {
  return (
    <Link
      to={item.to}
      className={`nav-item ${active ? 'active' : ''}`}
      aria-current={active ? 'page' : undefined}
      title={item.label}
    >
      <span className="nav-icon" aria-hidden="true">{item.icon}</span>
      <span className="nav-label">{item.label}</span>
    </Link>
  )
}

export default function Sidebar({ collapsed, onToggle }) {
  const { user } = useAuth()
  const role = user?.role
  const { pathname } = useLocation()

  const groups = useMemo(() => NAV_GROUPS
    .map(g => ({ ...g, items: g.items.filter(i => allowed(i, role)) }))
    .filter(g => g.items.length), [role])
  const active = useMemo(
    () => activeTarget([...groups.flatMap(g => g.items), ...FOOT_NAV], pathname),
    [groups, pathname])

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

      <nav className="sb-nav" aria-label="Sections">
        {groups.map(g => (
          <div key={g.label} className="sb-group" role="group" aria-label={g.label}>
            <div className="sb-group-label" aria-hidden="true">{g.label}</div>
            {g.items.map(item => <NavItem key={item.to} item={item} active={item.to === active} />)}
          </div>
        ))}
      </nav>

      <nav className="sb-nav sb-nav-foot" aria-label="Help and account">
        {FOOT_NAV.map(item => <NavItem key={item.to} item={item} active={item.to === active} />)}
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
