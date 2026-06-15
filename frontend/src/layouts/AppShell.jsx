import { useState, useCallback, useEffect } from 'react'
import { Outlet } from 'react-router-dom'
import Sidebar from '../components/Sidebar.jsx'
import Topbar from '../components/Topbar.jsx'
import ToastContainer from '../components/ToastContainer.jsx'

const KEY = 'fenrir.sidebar.collapsed'

export default function AppShell() {
  const [collapsed, setCollapsed] = useState(() => {
    try { return localStorage.getItem(KEY) === '1' } catch { return false }
  })
  useEffect(() => {
    try { localStorage.setItem(KEY, collapsed ? '1' : '0') } catch {}
  }, [collapsed])

  const onToggle = useCallback(() => setCollapsed(c => !c), [])

  return (
    <div className="app-shell">
      <Sidebar collapsed={collapsed} onToggle={onToggle} />
      <div className="app-main">
        <Topbar />
        <main className="app-content">
          <Outlet />
        </main>
      </div>
      {/* Global toast stack — bottom-left, clear of the War Room drawer on the right */}
      <ToastContainer />
    </div>
  )
}
