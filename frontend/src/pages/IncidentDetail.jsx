import { useEffect, useState, useCallback, useMemo, useRef } from 'react'
import { useParams, Link, NavLink, Outlet, useLocation, useNavigate } from 'react-router-dom'
import { api, notifyUnauthorized } from '../api/client.js'
import { formatTitle } from '../hooks/useDocumentTitle.jsx'
import { labelOf, pillOf } from '../lib/incidentVocab.js'
import { useAuth } from '../hooks/useAuth.jsx'
import PhaseStepper from '../components/PhaseStepper.jsx'
import PhaseChangeModal from '../components/PhaseChangeModal.jsx'
import WarRoomDrawer from '../components/WarRoomDrawer.jsx'
import SevBadge from '../components/SevBadge.jsx'
import TagChip from '../components/TagChip.jsx'

// Fields that flow through the Save button (form-style editing).
// `phase` is intentionally excluded — it has its own action path via the
// status-band stepper, with confirmation and audit logging.
// `occurred_at` and `contained_at` are handled separately (UTC datetime entry).
const EDITABLE = ['title', 'description', 'severity', 'tlp', 'triage_state', 'incident_type', 'detection_method', 'reporter']

// Value for the UTC datetime entry field: the canonical ISO-8601 (`…Z`) string
// as-is (UtcDateTimeInput renders/edits it in UTC). '' when absent.
function toEntryValue(iso) {
  return iso || ''
}

// Canonical ISO string → UTC epoch (ms), for change-detection that avoids
// display-string format mismatches.
function toEpoch(v) {
  if (!v) return null
  const t = new Date(v).getTime()
  return isNaN(t) ? null : t
}

// Left-rail nav, grouped by NIST SP 800-61 R3 phase (matches the project's
// Standards alignment in CLAUDE.md). Order is analyst-first: Details to orient,
// then process/meta tabs, then the substantive Detection & Analysis tabs, then
// response, then close-out. Admin-only group appended at runtime.
const NAV_GROUPS = [
  {
    label: null,                       // orient row — ungrouped at the top
    items: [
      { to: 'details', label: 'Details' },
    ],
  },
  {
    label: 'Process',
    items: [
      { to: 'playbook',    label: 'Playbook' },
      { to: 'assignments', label: 'Assignments' },
    ],
  },
  {
    label: 'Detection & Analysis',
    items: [
      { to: 'timeline', label: 'Timeline' },
      { to: 'entities', label: 'Entities' },
      { to: 'files',    label: 'Files' },
      { to: 'evidence', label: 'Evidence' },
      { to: 'forensic', label: 'Forensic' },
      { to: 'mitre',    label: 'MITRE ATT&CK' },
    ],
  },
  {
    label: 'Containment / Recovery',
    items: [
      { to: 'respond', label: 'Respond' },
      { to: 'comms',   label: 'Comms' },
    ],
  },
  {
    label: 'Post-Incident',
    items: [
      { to: 'legal',         label: 'Legal' },
      { to: 'handoffs',      label: 'Handoffs' },
      { to: 'post-incident', label: 'Post-Incident' },
    ],
  },
]
const ADMIN_GROUP = {
  label: 'Admin',
  items: [
    { to: 'audit-log', label: 'Audit Log' },
  ],
}

// section path-segment -> label, derived from the nav above so the tab title
// stays in sync with the left rail. Used for document.title.
const SECTION_LABELS = Object.fromEntries(
  [...NAV_GROUPS, ADMIN_GROUP].flatMap(g => g.items.map(i => [i.to, i.label]))
)

function wsBase() {
  return (location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host
}

// Derive initials from a username (up to 2 chars).
function initials(name) {
  const parts = (name || '').trim().split(/[\s._-]+/).filter(Boolean)
  if (parts.length >= 2) return (parts[0][0] + parts[1][0]).toUpperCase()
  return (name || '?').slice(0, 2).toUpperCase()
}

// Deterministic hue from a string so each user gets a stable avatar colour.
function avatarHue(name) {
  let h = 0
  for (let i = 0; i < name.length; i++) h = (h * 31 + name.charCodeAt(i)) & 0xffff
  return h % 360
}

function PresenceStrip({ viewers, currentUsername }) {
  if (!viewers || viewers.length === 0) return null
  const MAX_SHOWN = 5
  const shown    = viewers.slice(0, MAX_SHOWN)
  const overflow = viewers.length - MAX_SHOWN

  return (
    <span style={{ display: 'flex', alignItems: 'center', gap: 3, marginLeft: 'var(--space-2)' }}>
      {shown.map((v) => {
        const isSelf = v.username === currentUsername
        const hue    = avatarHue(v.username)
        return (
          <span
            key={v.user_id}
            title={isSelf ? `${v.username} (you)` : v.username}
            style={{
              display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
              width: 22, height: 22, borderRadius: '50%',
              fontFamily: 'var(--font-mono)', fontSize: 9, fontWeight: 700,
              color: `hsl(${hue}, 60%, 88%)`,
              background: `hsl(${hue}, 45%, ${isSelf ? 28 : 20}%)`,
              border: isSelf
                ? `1.5px solid hsl(${hue}, 60%, 55%)`
                : `1px solid hsl(${hue}, 40%, 35%)`,
              flexShrink: 0,
              userSelect: 'none',
            }}
          >
            {initials(v.username)}
          </span>
        )
      })}
      {overflow > 0 && (
        <span style={{
          display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
          width: 22, height: 22, borderRadius: '50%',
          fontSize: 9, fontWeight: 700, color: 'var(--muted)',
          background: 'var(--surface-2)', border: '1px solid var(--border)',
          flexShrink: 0,
        }}>+{overflow}</span>
      )}
    </span>
  )
}

function pickEditable(o) {
  const out = {}
  for (const k of EDITABLE) out[k] = o?.[k] ?? ''
  return out
}

function diff(draft, server) {
  const out = {}
  for (const k of EDITABLE) {
    const a = draft[k]
    const b = server?.[k] ?? ''
    if (a !== b) out[k] = a === '' ? null : a
  }
  return out
}

export default function IncidentDetail() {
  const { id } = useParams()
  const { user } = useAuth()
  const navigate = useNavigate()
  const location = useLocation()
  const navGroups = user?.role === 'admin' ? [...NAV_GROUPS, ADMIN_GROUP] : NAV_GROUPS
  const [inc, setInc]         = useState(null)
  const [draft, setDraft]     = useState({})
  const [loading, setLoading] = useState(true)
  const [error, setError]     = useState('')
  const [saving, setSaving]   = useState(false)
  const [closing, setClosing] = useState(false)
  const [savedAt, setSavedAt] = useState(0)
  const [editing, setEditing] = useState(false)
  const [phaseTarget, setPhaseTarget] = useState(null)
  const [occurredAt,  setOccurredAt]  = useState('')
  const [containedAt, setContainedAt] = useState('')
  const [presenceUsers, setPresenceUsers] = useState([])
  const presenceWsRef  = useRef(null)
  const presencePingRef = useRef(null)

  const refresh = useCallback(async () => {
    setLoading(true); setError('')
    try {
      const r = await api.getIncident(id)
      setInc(r)
      setDraft(pickEditable(r))
      setOccurredAt(toEntryValue(r.occurred_at))
      setContainedAt(toEntryValue(r.contained_at))
    } catch (e) {
      setError(e.message || 'Incident not found.')
    } finally {
      setLoading(false)
    }
  }, [id])
  useEffect(() => { refresh() }, [refresh])

  // Tab title: "<case ref> · <section> · FENRIR". Falls back to the title when
  // the incident has no human ref, and to a neutral label while loading.
  useEffect(() => {
    const section = SECTION_LABELS[location.pathname.split('/')[3]] || 'Details'
    const ref = inc ? (inc.ref || inc.title || 'Incident') : 'Incident'
    document.title = formatTitle(`${ref} · ${section}`)
  }, [location.pathname, inc])

  // Presence WebSocket — opens when the incident page mounts, closes on unmount.
  useEffect(() => {
    if (!id) return
    const ws = new WebSocket(`${wsBase()}/api/incidents/${id}/presence/ws`)
    presenceWsRef.current = ws

    ws.onmessage = (ev) => {
      try {
        const msg = JSON.parse(ev.data)
        if (msg.type === 'presence') setPresenceUsers(msg.viewers || [])
      } catch { /* ignore malformed frames */ }
    }
    ws.onerror = () => {}
    ws.onclose = (e) => { presenceWsRef.current = null; if (e.code === 4001) notifyUnauthorized() }

    // Ping every 30 s to keep the connection alive through idle proxies.
    presencePingRef.current = setInterval(() => {
      if (ws.readyState === WebSocket.OPEN) ws.send('ping')
    }, 30_000)

    return () => {
      clearInterval(presencePingRef.current)
      ws.close()
    }
  }, [id])

  const changes = useMemo(() => diff(draft, inc), [draft, inc])
  // Compare by instant (epoch ms), not display string — entry is canonical UTC ISO.
  const dtDirty = toEpoch(occurredAt)  !== toEpoch(inc?.occurred_at) ||
                  toEpoch(containedAt) !== toEpoch(inc?.contained_at)
  const dirty   = Object.keys(changes).length > 0 || dtDirty

  // Guard navigation when the form is dirty.
  useEffect(() => {
    if (!dirty) return
    const onBefore = (e) => { e.preventDefault(); e.returnValue = '' }
    window.addEventListener('beforeunload', onBefore)
    return () => window.removeEventListener('beforeunload', onBefore)
  }, [dirty])

  const setField = useCallback((k) => (e) => setDraft(d => ({ ...d, [k]: e.target.value })), [])

  const onSave = async () => {
    if (!dirty) { setEditing(false); return }
    if (draft.title?.trim().length < 3) { setError('Title must be at least 3 characters.'); return }
    setSaving(true); setError('')
    try {
      const dtChanges = {}
      if (toEpoch(occurredAt) !== toEpoch(inc.occurred_at)) {
        dtChanges.occurred_at = occurredAt || null
      }
      if (toEpoch(containedAt) !== toEpoch(inc.contained_at)) {
        dtChanges.contained_at = containedAt || null
      }
      const updated = await api.updateIncident(id, { ...changes, ...dtChanges })
      setInc(updated)
      setDraft(pickEditable(updated))
      setOccurredAt(toEntryValue(updated.occurred_at))
      setContainedAt(toEntryValue(updated.contained_at))
      setSavedAt(Date.now())
      setEditing(false)
    } catch (e) {
      setError(e.message || 'Save failed.')
    } finally {
      setSaving(false)
    }
  }

  const onDiscard = () => {
    setDraft(pickEditable(inc))
    setOccurredAt(toEntryValue(inc.occurred_at))
    setContainedAt(toEntryValue(inc.contained_at))
    setEditing(false)
    setError('')
  }

  const confirmPhaseChange = async (nextPhase) => {
    const updated = await api.updateIncident(id, { phase: nextPhase })
    setInc(updated)
    setDraft(pickEditable(updated))
    setOccurredAt(toEntryValue(updated.occurred_at))
    setContainedAt(toEntryValue(updated.contained_at))
    setPhaseTarget(null)
  }

  const onResolve = async () => {
    if (!confirm('Resolve this incident? Phase will move to Post-Incident.')) return
    setClosing(true); setError('')
    try {
      const r = await api.closeIncident(id)
      setInc(r)
      setDraft(pickEditable(r))
      setEditing(false)
    } catch (e) {
      setError(e.message || 'Resolve failed.')
    } finally {
      setClosing(false)
    }
  }

  const onReopen = async () => {
    if (!confirm('Re-open this incident? Phase will move to Containment / Eradication / Recovery.')) return
    setClosing(true); setError('')
    try {
      const r = await api.reopenIncident(id)
      setInc(r)
      setDraft(pickEditable(r))
    } catch (e) {
      setError(e.message || 'Re-open failed.')
    } finally {
      setClosing(false)
    }
  }

  if (loading && !inc) return (
    <div className="panel"><div className="panel-empty">Loading…</div></div>
  )
  if (error && !inc) return (
    <div className="panel">
      <div className="panel-empty">
        <div className="panel-empty-mark" aria-hidden="true">?</div>
        <div>{error}</div>
        <div><Link to="/incidents">← back to incidents</Link></div>
      </div>
    </div>
  )
  if (!inc) return null

  const isClosed  = inc.status === 'closed'
  const readOnly  = isClosed || !editing
  const justSaved = !dirty && savedAt > 0 && Date.now() - savedAt < 4000

  return (
    <div
      className="incident-detail-wrap"
      data-theme={inc.dark_operation ? 'mission-control' : undefined}
    >
      <div className="page-head">
        <div>
          <div className="page-sub">
            <Link to="/incidents">← Incidents</Link>
            {inc.ref && <span style={{ marginLeft: 'var(--space-3)', fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--accent)' }}>{inc.ref}</span>}
          </div>
          {readOnly ? (
            <h1 className="page-title">{inc.title}</h1>
          ) : (
            <input
              className="input title-input"
              value={draft.title}
              onChange={setField('title')}
              maxLength={200}
              aria-label="Incident title"
            />
          )}
        </div>
        <div style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'center' }}>
          {dirty     && <span className="dirty-dot" title="Unsaved changes">●</span>}
          {justSaved && <span className="saved-tag">SAVED</span>}
          {!isClosed && !editing && (
            <>
              <button
                className="btn"
                type="button"
                onClick={() => navigate('handoffs')}
              >Handoff</button>
              <button
                className="btn"
                type="button"
                onClick={() => setEditing(true)}
              >Edit</button>
              <button
                className="btn primary"
                type="button"
                onClick={onResolve}
                disabled={closing}
              >{closing ? 'Resolving…' : 'Resolve'}</button>
            </>
          )}
          {isClosed && (
            <button
              className="btn primary"
              type="button"
              onClick={onReopen}
              disabled={closing}
            >{closing ? 'Re-opening…' : 'Re-open'}</button>
          )}
          {!isClosed && editing && (
            <>
              <button
                className="btn"
                type="button"
                onClick={onDiscard}
                disabled={saving}
              >Discard</button>
              <button
                className="btn primary"
                type="button"
                onClick={onSave}
                disabled={saving}
              >{saving ? 'Saving…' : 'Save changes'}</button>
            </>
          )}
        </div>
      </div>

      <div className={`status-band ${isClosed ? 'closed' : ''}`}>
        <PhaseStepper
          current={inc.phase}
          disabled={isClosed}
          onPhaseClick={isClosed ? undefined : setPhaseTarget}
        />
        <span className="pills">
          <SevBadge value={inc.severity} />
          <span className={`pill ${pillOf('status',   inc.status)}`}>{labelOf('status',   inc.status)}</span>
          <span className={`pill ${pillOf('tlp',      inc.tlp)}`}>{labelOf('tlp',      inc.tlp)}</span>
          {inc.dark_operation && <span className="pill pill-crit">DARK OP</span>}
          <PresenceStrip viewers={presenceUsers} currentUsername={user?.username} />
        </span>
      </div>

      {/* Tags row — chips read-only here; full edit lives in Details > Edit mode. */}
      {(inc.tags || []).length > 0 && (
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginTop: 'var(--space-2)' }}>
          {inc.tags.map(t => <TagChip key={t} tag={t} />)}
        </div>
      )}

      {inc.dark_operation && (
        <div className="dark-op-banner" role="alert">
          ⬛ Dark Operation Active — communication blackout in effect
        </div>
      )}

      {error && (
        <div className="alert error" role="alert" style={{ marginBottom: 'var(--space-3)' }}>
          <span className="alert-icon">!</span><span>{error}</span>
        </div>
      )}

      <div className="sub-layout">
        <nav className="sub-nav" aria-label="Incident sections">
          {navGroups.map((group, gi) => (
            <div key={group.label || `g${gi}`} className="sub-group">
              {group.label && (
                <div className="sub-group-label" aria-hidden="true">{group.label}</div>
              )}
              {group.items.map(item => (
                <NavLink
                  key={item.to}
                  to={item.to}
                  className={({ isActive }) => `sub-item ${isActive ? 'active' : ''}`}
                >
                  {item.label}
                </NavLink>
              ))}
            </div>
          ))}
        </nav>
        <div className="sub-content">
          <Outlet context={{ inc, draft, setField, readOnly, editing, isClosed, refresh, occurredAt, setOccurredAt, containedAt, setContainedAt }} />
        </div>
      </div>

      <WarRoomDrawer incidentId={inc.id} />

      {phaseTarget && (
        <PhaseChangeModal
          currentPhase={inc.phase}
          targetPhase={phaseTarget}
          onConfirm={confirmPhaseChange}
          onClose={() => setPhaseTarget(null)}
        />
      )}
    </div>
  )
}
