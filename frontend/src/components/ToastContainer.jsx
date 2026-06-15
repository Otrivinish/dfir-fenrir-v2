import { useCallback, useEffect, useRef, useState } from 'react'

function wsBase() {
  return (location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host
}

const DISMISS_MS = 5000

const TYPE_COLOR = {
  warroom_message:  'accent',
  warroom_mention:  'high',
  incident_created: 'ok',
  phase_changed:    'med',
  comment:          'muted',
  comment_mention:  'high',
  handoff_pending:  'med',
}

let toastId = 0

export default function ToastContainer() {
  const [toasts, setToasts] = useState([])
  const timers = useRef({})

  const dismiss = useCallback((id) => {
    clearTimeout(timers.current[id])
    delete timers.current[id]
    setToasts(prev => prev.filter(t => t.id !== id))
  }, [])

  const addToast = useCallback((notification) => {
    const id = ++toastId
    setToasts(prev => [{ id, ...notification }, ...prev].slice(0, 5))
    timers.current[id] = setTimeout(() => dismiss(id), DISMISS_MS)
  }, [dismiss])

  // Connect to the notifications WebSocket and show incoming notifications as toasts.
  useEffect(() => {
    const ws = new WebSocket(`${wsBase()}/api/notifications/ws`)

    ws.onmessage = (ev) => {
      try {
        const msg = JSON.parse(ev.data)
        if (msg.type === 'notification') addToast(msg)
      } catch {}
    }

    ws.onerror = () => {}
    ws.onclose = () => {}

    return () => {
      ws.close()
      Object.values(timers.current).forEach(clearTimeout)
    }
  }, [addToast])

  if (toasts.length === 0) return null

  return (
    <div className="toast-container" role="status" aria-live="polite" aria-atomic="false">
      {toasts.map(t => (
        <div
          key={t.id}
          className={`toast toast--${TYPE_COLOR[t.type] || 'muted'}`}
        >
          <div className="toast-bar" style={{ animationDuration: `${DISMISS_MS}ms` }} />
          <div className="toast-content">
            <div className="toast-head">
              <span className="toast-title">{t.title}</span>
              <button
                type="button"
                className="toast-close"
                onClick={() => dismiss(t.id)}
                aria-label="Dismiss notification"
              >×</button>
            </div>
            {t.body && <div className="toast-body">{t.body}</div>}
          </div>
        </div>
      ))}
    </div>
  )
}
