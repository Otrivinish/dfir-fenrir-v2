import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { api } from '../api/client.js'
import { useAuth } from '../hooks/useAuth.jsx'

// Derive ws:// or wss:// base from current page protocol.
function wsBase() {
  return (location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host
}

// Matches @<username> tokens; mirrors backend _MENTION_RE.
const MENTION_TOKEN_RE = /(@[a-zA-Z0-9_.-]+)/g
// Detects an in-progress @<partial> at the cursor position.
const MENTION_TRIGGER_RE = /(?:^|\s)@([a-zA-Z0-9_.-]*)$/
const MENTION_MAX_RESULTS = 6

export default function WarRoomDrawer({ incidentId }) {
  const storageKey = incidentId ? `fenrir.warroom.${incidentId}.open` : null
  const { user: me } = useAuth()
  const meUsername = me?.username?.toLowerCase() || ''

  const [open, setOpen] = useState(() => {
    if (!storageKey) return false
    try { return localStorage.getItem(storageKey) === '1' } catch { return false }
  })

  // Vertical position of the War Room tab — drag-to-move, persisted.
  const TAB_Y_KEY = 'fenrir.warroom.tab.y'
  const [tabY, setTabY] = useState(() => {
    try {
      const v = localStorage.getItem(TAB_Y_KEY)
      if (v !== null) return Number(v) || 140
    } catch { /* ignore */ }
    return 140
  })
  // Initialised to null so onTabPointerMove's `if (!drag) return` guard works
  // before the first pointerdown. Setting this to an object (even with zeros)
  // makes the first hover compute dy from clientY - 0 — a huge number that
  // instantly trips the drag threshold and yanks the tab to the cursor.
  const tabDragRef    = useRef(null)
  const tabJustMovedRef = useRef(false)

  // Drag activation: distance-threshold only. A click — even a slow one with
  // tiny pointer drift — never enters drag mode. The user must deliberately
  // pull the tab vertically beyond DRAG_DIST to start moving it.
  const DRAG_DIST = 30   // px

  function clampTabY(y) {
    const min = 60
    const max = (typeof window !== 'undefined' ? window.innerHeight : 800) - 100
    return Math.max(min, Math.min(max, y))
  }
  function onTabPointerDown(e) {
    if (e.pointerType === 'mouse' && e.button !== 0) return
    tabDragRef.current = {
      startClientY: e.clientY, startTabY: tabY,
      armed: false, moved: false,
    }
    try { e.currentTarget.setPointerCapture(e.pointerId) } catch { /* ignore */ }
  }
  function onTabPointerMove(e) {
    const drag = tabDragRef.current
    if (!drag) return
    if (typeof e.clientY !== 'number') return
    const dy = e.clientY - drag.startClientY
    if (!drag.armed && Math.abs(dy) > DRAG_DIST) {
      drag.armed = true
    }
    if (drag.armed) {
      drag.moved = true
      setTabY(clampTabY(drag.startTabY + dy))
    }
  }
  function onTabPointerUp(e) {
    const drag = tabDragRef.current
    if (drag?.moved) {
      tabJustMovedRef.current = true
      try {
        localStorage.setItem(TAB_Y_KEY,
          String(clampTabY(drag.startTabY + (e.clientY - drag.startClientY))))
      } catch { /* ignore */ }
    }
    try { e.currentTarget.releasePointerCapture?.(e.pointerId) } catch { /* ignore */ }
    tabDragRef.current = null
  }
  function onTabClick(e) {
    if (tabJustMovedRef.current) {
      tabJustMovedRef.current = false
      e.preventDefault()
      return
    }
    setOpen(o => !o)
  }

  // Incident picker — list of active incidents
  const [incidents, setIncidents] = useState([])
  const [selectedId, setSelectedId] = useState(incidentId || null)

  // Chat state
  const [messages, setMessages] = useState([])
  const [onlineCount, setOnlineCount] = useState(0)
  const [input, setInput] = useState('')
  const [sending, setSending] = useState(false)

  // @mention autocomplete state
  const [users, setUsers] = useState([])               // {id, username, full_name}
  const [mentionQuery, setMentionQuery] = useState(null) // null = closed; '' = open with no filter
  const [mentionIdx, setMentionIdx] = useState(0)

  const messagesEndRef = useRef(null)
  const wsRef = useRef(null)
  const inputRef = useRef(null)

  // Valid-username set for mention highlighting in messages
  const userSet = useMemo(
    () => new Set(users.map(u => u.username.toLowerCase())),
    [users],
  )

  // Filtered mention candidates (max N, prefix-match on username, contains on full_name)
  const mentionMatches = useMemo(() => {
    if (mentionQuery === null) return []
    const q = mentionQuery.toLowerCase()
    return users
      .filter(u => {
        if (u.username.toLowerCase() === meUsername) return false  // don't mention self
        if (!q) return true
        return u.username.toLowerCase().startsWith(q) ||
               (u.full_name || '').toLowerCase().includes(q)
      })
      .slice(0, MENTION_MAX_RESULTS)
  }, [mentionQuery, users, meUsername])

  // Persist open state
  useEffect(() => {
    if (!storageKey) return
    try { localStorage.setItem(storageKey, open ? '1' : '0') } catch {}
  }, [open, storageKey])

  // Load active incidents for the picker
  useEffect(() => {
    api.listIncidents({ status: 'open', limit: 30 })
      .then(d => setIncidents(d.items || []))
      .catch(() => {})
  }, [])

  // Load user list for @mention autocomplete + message highlighting
  useEffect(() => {
    api.listAssignableUsers()
      .then(d => setUsers(Array.isArray(d) ? d : (d?.items || [])))
      .catch(() => {})
  }, [])

  // When selected incident changes, sync online count from REST then connect WS
  useEffect(() => {
    if (!selectedId) return

    // Load messages
    api.listWarRoomMessages(selectedId)
      .then(d => {
        setMessages(d.items || [])
        setOnlineCount(d.online || 0)
      })
      .catch(() => {})

    // Close any existing WS
    if (wsRef.current) {
      wsRef.current.close()
      wsRef.current = null
    }

    const ws = new WebSocket(`${wsBase()}/api/incidents/${selectedId}/warroom/ws`)
    wsRef.current = ws

    ws.onmessage = (ev) => {
      try {
        const msg = JSON.parse(ev.data)
        if (msg.type === 'message') {
          setMessages(prev => [...prev, msg])
        } else if (msg.type === 'presence') {
          setOnlineCount(msg.online || 0)
        }
      } catch {}
    }

    ws.onerror = () => {}
    ws.onclose = () => {}

    return () => {
      ws.close()
      wsRef.current = null
    }
  }, [selectedId])

  // Auto-scroll to bottom when messages arrive
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages])

  // Sync selectedId when prop changes (navigating between incidents)
  useEffect(() => {
    if (incidentId) setSelectedId(incidentId)
  }, [incidentId])

  const send = useCallback(async () => {
    const body = input.trim()
    if (!body || !selectedId || sending) return
    setSending(true)
    setInput('')
    setMentionQuery(null)
    try {
      await api.sendWarRoomMessage(selectedId, body)
      // Message arrives via WebSocket broadcast; no local push needed.
    } catch {
      setInput(body)   // restore on error
    } finally {
      setSending(false)
      inputRef.current?.focus()
    }
  }, [input, selectedId, sending])

  // Update mention-trigger state after every input change or cursor move.
  const refreshMentionState = useCallback((value, cursorPos) => {
    const before = value.slice(0, cursorPos)
    const m = MENTION_TRIGGER_RE.exec(before)
    if (m) {
      setMentionQuery(m[1])
      setMentionIdx(0)
    } else {
      setMentionQuery(null)
    }
  }, [])

  const onInputChange = useCallback((e) => {
    const value = e.target.value
    setInput(value)
    refreshMentionState(value, e.target.selectionStart ?? value.length)
  }, [refreshMentionState])

  const onInputSelect = useCallback((e) => {
    refreshMentionState(e.target.value, e.target.selectionStart ?? 0)
  }, [refreshMentionState])

  const insertMention = useCallback((username) => {
    const el = inputRef.current
    const cursor = el?.selectionStart ?? input.length
    const before = input.slice(0, cursor)
    const after  = input.slice(cursor)
    const replaced = before.replace(/(@[a-zA-Z0-9_.-]*)$/, `@${username} `)
    const next = replaced + after
    setInput(next)
    setMentionQuery(null)
    // Restore cursor right after the inserted mention.
    requestAnimationFrame(() => {
      const newPos = replaced.length
      el?.setSelectionRange(newPos, newPos)
      el?.focus()
    })
  }, [input])

  const onKeyDown = useCallback((e) => {
    if (mentionQuery !== null && mentionMatches.length > 0) {
      if (e.key === 'ArrowDown') {
        e.preventDefault()
        setMentionIdx(i => Math.min(i + 1, mentionMatches.length - 1))
        return
      }
      if (e.key === 'ArrowUp') {
        e.preventDefault()
        setMentionIdx(i => Math.max(i - 1, 0))
        return
      }
      if (e.key === 'Enter' || e.key === 'Tab') {
        e.preventDefault()
        insertMention(mentionMatches[mentionIdx].username)
        return
      }
      if (e.key === 'Escape') {
        e.preventDefault()
        setMentionQuery(null)
        return
      }
    }
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      send()
    }
  }, [mentionQuery, mentionMatches, mentionIdx, insertMention, send])

  const selectedTitle = incidents.find(i => i.id === selectedId)?.title

  return (
    <>
      <button
        type="button"
        className={`warroom-tab ${open ? 'open' : ''}`}
        style={{ top: tabY, cursor: 'pointer' }}
        onPointerDown={onTabPointerDown}
        onPointerMove={onTabPointerMove}
        onPointerUp={onTabPointerUp}
        onPointerCancel={onTabPointerUp}
        onClick={onTabClick}
        aria-expanded={open}
        aria-controls="warroom-drawer"
        title={open ? 'Close War Room (press-and-hold to drag)' : 'Open War Room (press-and-hold to drag)'}
      >
        <span className="dot" aria-hidden="true" />
        <span>War Room · {onlineCount} online</span>
      </button>

      <aside
        id="warroom-drawer"
        className={`warroom-drawer ${open ? 'open' : ''}`}
        aria-hidden={!open}
        aria-label="War Room"
      >
        {/* Header */}
        <div className="warroom-head">
          <span>War Room</span>
          <span className="warroom-meta">{onlineCount} online</span>
          <button
            type="button"
            className="warroom-close"
            onClick={() => setOpen(false)}
            aria-label="Close War Room"
          >×</button>
        </div>

        {/* Incident picker */}
        <div className="warroom-incident-list" role="list" aria-label="Active incidents">
          {incidents.length === 0 && (
            <span className="warroom-no-incidents">No open incidents</span>
          )}
          {incidents.map(inc => (
            <button
              key={inc.id}
              type="button"
              role="listitem"
              className={`warroom-incident-item ${inc.id === selectedId ? 'active' : ''}`}
              onClick={() => setSelectedId(inc.id)}
              title={inc.title}
            >
              <span className={`warroom-sev warroom-sev--${inc.severity}`} aria-hidden="true" />
              {inc.ref && <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--accent)', marginRight: 4 }}>{inc.ref}</span>}
              <span className="warroom-incident-title">{inc.title}</span>
            </button>
          ))}
        </div>

        {/* Message feed */}
        <div className="warroom-messages" aria-live="polite" aria-label="Chat messages">
          {messages.length === 0 && (
            <div className="warroom-stub">
              <div className="panel-empty-mark" aria-hidden="true">◍</div>
              <div>No messages yet. Start the conversation.</div>
            </div>
          )}
          {messages.map(m => (
            <div key={m.id} className="warroom-msg">
              <div className="warroom-msg-meta">
                <span className="warroom-msg-user">{m.username}</span>
                <span className="warroom-msg-time">{fmtTime(m.created_at)}</span>
              </div>
              <div className="warroom-msg-body">
                {renderBody(m.body, meUsername, userSet)}
              </div>
            </div>
          ))}
          <div ref={messagesEndRef} />
        </div>

        {/* @mention dropdown — sits directly above the input row */}
        {mentionQuery !== null && mentionMatches.length > 0 && (
          <div
            className="warroom-mention-dropdown"
            role="listbox"
            aria-label="Mention a user"
          >
            {mentionMatches.map((u, i) => (
              <button
                key={u.id}
                type="button"
                role="option"
                aria-selected={i === mentionIdx}
                className={`warroom-mention-item ${i === mentionIdx ? 'active' : ''}`}
                onMouseDown={(e) => { e.preventDefault(); insertMention(u.username) }}
                onMouseEnter={() => setMentionIdx(i)}
              >
                <span className="warroom-mention-name">@{u.username}</span>
                {u.full_name && (
                  <span className="warroom-mention-full">{u.full_name}</span>
                )}
              </button>
            ))}
          </div>
        )}

        {/* Input row */}
        <div className="warroom-input-row">
          <textarea
            ref={inputRef}
            className="warroom-input"
            value={input}
            onChange={onInputChange}
            onSelect={onInputSelect}
            onKeyDown={onKeyDown}
            onBlur={() => setMentionQuery(null)}
            placeholder={selectedId ? 'Message…  (@ to mention, Enter to send)' : 'Select an incident above'}
            disabled={!selectedId || sending}
            rows={2}
            aria-label="War room message"
          />
          <button
            type="button"
            className="warroom-send"
            onClick={send}
            disabled={!input.trim() || !selectedId || sending}
            aria-label="Send message"
          >↑</button>
        </div>
      </aside>
    </>
  )
}

function fmtTime(iso) {
  if (!iso) return ''
  try {
    return new Date(iso).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', hour12: false })
  } catch {
    return ''
  }
}

// Splits body on @<username> tokens. Highlights only mentions matching a known user;
// when the mention matches the current viewer, the chip gets a stronger "is-me" treatment.
function renderBody(body, meUsername, userSet) {
  if (!body) return null
  const parts = body.split(MENTION_TOKEN_RE)
  return parts.map((part, i) => {
    if (part.startsWith('@')) {
      const name = part.slice(1).toLowerCase()
      if (userSet.has(name)) {
        const isMe = name === meUsername
        return (
          <span key={i} className={`warroom-mention${isMe ? ' is-me' : ''}`}>
            {part}
          </span>
        )
      }
    }
    return <span key={i}>{part}</span>
  })
}
