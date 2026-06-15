import { useLocation } from 'react-router-dom'
import { useAuth } from '../hooks/useAuth.jsx'
import ThemePicker from './ThemePicker.jsx'
import TimezonePicker from './TimezonePicker.jsx'
import NotificationBell from './NotificationBell.jsx'
import GlobalSearch from './GlobalSearch.jsx'

const CRUMB_FOR = {
  '/':          'DASHBOARD',
  '/incidents': 'INCIDENTS',
  '/team':      'TEAM',
  '/settings':  'SETTINGS',
}

function crumbFromPath(pathname) {
  if (CRUMB_FOR[pathname]) return CRUMB_FOR[pathname]
  const seg = '/' + (pathname.split('/').filter(Boolean)[0] || '')
  return CRUMB_FOR[seg] || pathname.toUpperCase()
}

export default function Topbar() {
  const loc = useLocation()
  const { signOut } = useAuth()
  const here = crumbFromPath(loc.pathname)
  return (
    <header className="topbar">
      <span className="crumb">FENRIR // <b>{here}</b></span>
      <span className="topbar-tag">Operational</span>

      {/* Bell sits left of the search bar — distinct from the top-right cluster */}
      <NotificationBell />

      <GlobalSearch />

      <div className="topbar-right">
        <TimezonePicker variant="inline" />
        <ThemePicker variant="inline" />
        <button className="icon-btn" type="button" onClick={signOut} title="Sign out" aria-label="Sign out">⏻</button>
      </div>
    </header>
  )
}
