import { useCallback, useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api, notifyUnauthorized } from '../api/client.js'

function wsBase() {
  return (location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host
}

const TYPE_LABEL = {
  warroom_message:  'War Room',
  warroom_mention:  'Mention',
  incident_created: 'New Incident',
  phase_changed:    'Phase Change',
  comment:          'Comment',
  comment_mention:  'Mention',
  handoff_pending:  'Handoff',
}

export default function NotificationBell() {
  const [notifications, setNotifications] = useState([])
  const [unreadCount, setUnreadCount] = useState(0)
  const [open, setOpen] = useState(false)
  const panelRef = useRef(null)
  const navigate = useNavigate()

  // Fetch initial notification list
  const fetchNotifications = useCallback(() => {
    api.listNotifications()
      .then(d => {
        setNotifications(d.items || [])
        setUnreadCount(d.unread_count || 0)
      })
      .catch(() => {})
  }, [])

  useEffect(() => {
    fetchNotifications()
  }, [fetchNotifications])

  // WebSocket for push
  useEffect(() => {
    const ws = new WebSocket(`${wsBase()}/api/notifications/ws`)

    ws.onmessage = (ev) => {
      try {
        const msg = JSON.parse(ev.data)
        if (msg.type === 'notification') {
          setNotifications(prev => [msg, ...prev].slice(0, 40))
          setUnreadCount(c => c + 1)
        }
      } catch {}
    }

    ws.onerror = () => {}
    ws.onclose = (e) => { if (e.code === 4001) notifyUnauthorized() }

    return () => ws.close()
  }, [])

  // Close panel on outside click
  useEffect(() => {
    if (!open) return
    function onDown(e) {
      if (panelRef.current && !panelRef.current.contains(e.target)) setOpen(false)
    }
    document.addEventListener('mousedown', onDown)
    return () => document.removeEventListener('mousedown', onDown)
  }, [open])

  const markRead = useCallback(async (n) => {
    if (!n.read) {
      try {
        await api.markNotificationRead(n.id)
        setNotifications(prev => prev.map(x => x.id === n.id ? { ...x, read: true } : x))
        setUnreadCount(c => Math.max(0, c - 1))
      } catch {}
    }
    if (n.incident_id) {
      setOpen(false)
      navigate(`/incidents/${n.incident_id}`)
    }
  }, [navigate])

  const markAllRead = useCallback(async () => {
    try {
      await api.markAllNotificationsRead()
      setNotifications(prev => prev.map(x => ({ ...x, read: true })))
      setUnreadCount(0)
    } catch {}
  }, [])

  return (
    <div className="notif-bell-wrap" ref={panelRef}>
      <button
        type="button"
        className={`icon-btn notif-bell-btn ${unreadCount > 0 ? 'has-unread' : ''}`}
        onClick={() => setOpen(o => !o)}
        aria-label={`Notifications${unreadCount > 0 ? ` (${unreadCount} unread)` : ''}`}
        aria-expanded={open}
        title="Notifications"
      >
        <span className="notif-bell-icon" aria-hidden="true">🔔</span>
        {unreadCount > 0 && (
          <span className="notif-badge" aria-hidden="true">
            {unreadCount > 99 ? '99+' : unreadCount}
          </span>
        )}
      </button>

      {open && (
        <div className="notif-panel" role="dialog" aria-label="Notifications">
          <div className="notif-panel-head">
            <span className="notif-panel-title">Notifications</span>
            {unreadCount > 0 && (
              <button type="button" className="notif-mark-all" onClick={markAllRead}>
                Mark all read
              </button>
            )}
          </div>

          <div className="notif-list">
            {notifications.length === 0 && (
              <div className="notif-empty">No notifications</div>
            )}
            {notifications.map(n => (
              <button
                key={n.id}
                type="button"
                className={`notif-item ${n.read ? 'read' : 'unread'}`}
                onClick={() => markRead(n)}
              >
                <div className="notif-item-head">
                  <span className="notif-type-chip">{TYPE_LABEL[n.type] || n.type}</span>
                  <span className="notif-time">{relTime(n.created_at)}</span>
                  {!n.read && <span className="notif-dot" aria-hidden="true" />}
                </div>
                <div className="notif-item-title">{n.title}</div>
                {n.body && <div className="notif-item-body">{n.body}</div>}
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

function relTime(iso) {
  if (!iso) return ''
  try {
    const diff = Date.now() - new Date(iso).getTime()
    const s = Math.floor(diff / 1000)
    if (s < 60)  return 'just now'
    const m = Math.floor(s / 60)
    if (m < 60)  return `${m}m ago`
    const h = Math.floor(m / 60)
    if (h < 24)  return `${h}h ago`
    return `${Math.floor(h / 24)}d ago`
  } catch {
    return ''
  }
}
