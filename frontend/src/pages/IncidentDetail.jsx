import { useEffect, useState, useCallback, useMemo, useRef } from 'react'
import { useParams, Link, Outlet, useLocation, useNavigate } from 'react-router-dom'
import { api, notifyUnauthorized } from '../api/client.js'
import { formatTitle } from '../hooks/useDocumentTitle.jsx'
import { labelOf, pillOf } from '../lib/incidentVocab.js'
import { useAuth } from '../hooks/useAuth.jsx'
import PhaseStepper from '../components/PhaseStepper.jsx'
import PhaseChangeModal from '../components/PhaseChangeModal.jsx'
import DeclareMilestoneModal, { MILESTONES } from '../components/DeclareMilestoneModal.jsx'
import { CloseIncidentModal, ReopenIncidentModal } from '../components/IncidentClosureModals.jsx'
import WarRoomDrawer from '../components/WarRoomDrawer.jsx'
import ClockChips from '../components/ClockChips.jsx'
import IncidentRail from '../components/IncidentRail.jsx'
import SevBadge from '../components/SevBadge.jsx'
import TagChip from '../components/TagChip.jsx'

// Fields that flow through the Save button (form-style editing).
// `phase` is intentionally excluded — it has its own action path via the
// status-band stepper, with confirmation and audit logging.
// `occurred_at`, `detected_at` and the milestones (`contained_at`, `eradicated_at`,
// `recovered_at`) are handled separately (datetime entry).
const EDITABLE = ['title', 'description', 'severity', 'tlp', 'triage_state', 'incident_type', 'detection_method', 'reporter']

// Value for the datetime entry field: the canonical ISO-8601 (`…Z`) string
// as-is (LocalDateTimePicker renders/edits it in the Fenrir timezone and
// emits UTC). '' when absent.
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

// A rail count badge: hidden when there is nothing to count.
const badge = (n, title) => (n ? { text: String(n), title } : null)

// Left rail (IncidentRail), in NIST SP 800-61 R3 order: Situation and Details to orient, then
// Command and Notify (who runs the response, who must be told), then Detection &
// Analysis with evidence before the analysis built on it, then response and
// close-out. `phase` gives a group label that phase's glyph and --phase-* colour
// (Notify is not a phase: neutral). `count(snapshot)` is the item's live count.
// Labels only: the route segments never change, so bookmarks and links still work.
const NAV_GROUPS = [
  {
    label: null,                       // orient row — ungrouped at the top
    items: [
      { to: 'situation', label: 'Situation' },
      { to: 'details',   label: 'Details' },
    ],
  },
  {
    label: 'Command',
    phase: 'preparation',
    items: [
      { to: 'assignments', label: 'Team',           count: s => badge(s.assignments, `${s.assignments} assigned`) },
      { to: 'playbook',    label: 'Playbook',       count: s => s.playbook_total > 0
        ? { text: `${s.playbook_done}/${s.playbook_total}`, title: `${s.playbook_done} of ${s.playbook_total} tasks done` } : null },
      { to: 'handoffs',    label: 'Shift handoffs', count: s => badge(s.handoffs_pending, `${s.handoffs_pending} awaiting acknowledgement`) },
    ],
  },
  {
    label: 'Notify',
    items: [
      { to: 'comms', label: 'Comms & stakeholders' },
      { to: 'legal', label: 'Legal & regulatory' },
    ],
  },
  {
    label: 'Detection & Analysis',
    phase: 'detection_and_analysis',
    items: [
      { to: 'evidence', label: 'Evidence',             count: s => badge(s.evidence, `${s.evidence} evidence items`) },
      { to: 'files',    label: 'Supporting documents', count: s => badge(s.files, `${s.files} files`) },
      { to: 'forensic', label: 'Examine' },
      { to: 'timeline', label: 'Timeline',             count: s => badge(s.timeline, `${s.timeline} events`) },
      { to: 'entities', label: 'Entities',             count: s => badge(s.entities, `${s.entities} entities`) },
      { to: 'iocs',     label: 'IOCs',                 count: s => badge(s.iocs, `${s.iocs} IOCs`) },
      { to: 'mitre',    label: 'ATT&CK & attribution' },
      { to: 'notes',    label: 'Case notes' },
    ],
  },
  {
    label: 'Containment, Eradication & Recovery',
    phase: 'containment_eradication_recovery',
    items: [
      { to: 'respond', label: 'Respond', count: s => badge(s.respond_open, `${s.respond_open} of ${s.respond_total} actions open or in progress`) },
    ],
  },
  {
    label: 'Post-Incident Activity',
    phase: 'post_incident',
    items: [
      { to: 'post-incident', label: 'Post-Incident' },
    ],
  },
]
// Appended when GET …/access grants read_audit_log (admins, and the incident's
// IC / Deputy, E3). Not a phase: neutral label.
const RECORD_GROUP = {
  label: 'Record',
  items: [
    { to: 'audit-log', label: 'Audit log' },
  ],
}

// section path-segment -> label, derived from the nav above so the tab title
// stays in sync with the left rail. Used for document.title.
const SECTION_LABELS = Object.fromEntries(
  [...NAV_GROUPS, RECORD_GROUP].flatMap(g => g.items.map(i => [i.to, i.label]))
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
  const [inc, setInc]         = useState(null)
  // My rights on this incident beyond my platform role (E3): {is_lead, capabilities[]}
  // from the API. null while loading; no capabilities if it can't be loaded.
  const [access, setAccess]   = useState(null)
  const can = (cap) => !!access?.capabilities?.includes(cap)
  const canReadAudit = can('read_audit_log')
  // Stable while the capability is unchanged, so the memoised rail skips this page's re-renders.
  const navGroups = useMemo(() => canReadAudit ? [...NAV_GROUPS, RECORD_GROUP] : NAV_GROUPS, [canReadAudit])
  const [draft, setDraft]     = useState({})
  const [loading, setLoading] = useState(true)
  const [error, setError]     = useState('')
  const [saving, setSaving]   = useState(false)
  const [closureModal, setClosureModal] = useState(null)   // 'close' | 'reopen' | null
  const [savedAt, setSavedAt] = useState(0)
  const [editing, setEditing] = useState(false)
  const [phaseTarget, setPhaseTarget] = useState(null)
  const [occurredAt,  setOccurredAt]  = useState('')
  const [detectedAt,  setDetectedAt]  = useState('')
  const [containedAt, setContainedAt] = useState('')
  const [eradicatedAt, setEradicatedAt] = useState('')
  const [recoveredAt,  setRecoveredAt]  = useState('')
  // Sent as triage_reason with a triage change (the API requires it for a false / benign
  // positive outside Detection & Analysis: 422 triage_reason_required).
  const [triageReason, setTriageReason] = useState('')
  const [declaring, setDeclaring] = useState(null)   // MILESTONES entry whose modal is open
  const [legalRev, setLegalRev] = useState(0)        // bumped by the Legal tab → ClockChips refetch
  const bumpLegal = useCallback(() => setLegalRev(r => r + 1), [])
  // Bumped by a tab after a write that can change the rail's counts → IncidentRail re-reads the snapshot.
  const [railRev, setRailRev] = useState(0)
  const bumpRail = useCallback(() => setRailRev(r => r + 1), [])
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
      setDetectedAt(toEntryValue(r.detected_at))
      setContainedAt(toEntryValue(r.contained_at))
      setEradicatedAt(toEntryValue(r.eradicated_at))
      setRecoveredAt(toEntryValue(r.recovered_at))
    } catch (e) {
      setError(e.message || 'Incident not found.')
    } finally {
      setLoading(false)
    }
  }, [id])
  useEffect(() => { refresh() }, [refresh])

  // Re-read after anything that can change them (an assignment added or removed). Only the
  // newest request may set them: a slow /access for incident A can't land after B's.
  const accessSeq = useRef(0)
  const refreshAccess = useCallback(async () => {
    const n = ++accessSeq.current
    let next
    try { next = await api.getIncidentAccess(id) }
    catch { next = { is_lead: false, capabilities: [] } }
    if (n === accessSeq.current) setAccess(next)
  }, [id])
  useEffect(() => { setAccess(null); refreshAccess() }, [refreshAccess])

  // Tab title: "<case ref> · <section> · FENRIR". Falls back to the title when
  // the incident has no human ref, and to a neutral label while loading.
  useEffect(() => {
    const section = SECTION_LABELS[location.pathname.split('/')[3]] || 'Situation'
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
  const dtDirty = toEpoch(occurredAt)   !== toEpoch(inc?.occurred_at) ||
                  toEpoch(detectedAt)   !== toEpoch(inc?.detected_at) ||
                  toEpoch(containedAt)  !== toEpoch(inc?.contained_at) ||
                  toEpoch(eradicatedAt) !== toEpoch(inc?.eradicated_at) ||
                  toEpoch(recoveredAt)  !== toEpoch(inc?.recovered_at)
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
      if (toEpoch(detectedAt) !== toEpoch(inc.detected_at)) {
        dtChanges.detected_at = detectedAt || null
      }
      if (toEpoch(containedAt) !== toEpoch(inc.contained_at)) {
        dtChanges.contained_at = containedAt || null
      }
      if (toEpoch(eradicatedAt) !== toEpoch(inc.eradicated_at)) {
        dtChanges.eradicated_at = eradicatedAt || null
      }
      if (toEpoch(recoveredAt) !== toEpoch(inc.recovered_at)) {
        dtChanges.recovered_at = recoveredAt || null
      }
      const triage = changes.triage_state && triageReason.trim() ? { triage_reason: triageReason.trim() } : {}
      const updated = await api.updateIncident(id, { ...changes, ...dtChanges, ...triage })
      setTriageReason('')
      setInc(updated)
      setDraft(pickEditable(updated))
      setOccurredAt(toEntryValue(updated.occurred_at))
      setDetectedAt(toEntryValue(updated.detected_at))
      setContainedAt(toEntryValue(updated.contained_at))
      setEradicatedAt(toEntryValue(updated.eradicated_at))
      setRecoveredAt(toEntryValue(updated.recovered_at))
      setSavedAt(Date.now())
      setEditing(false)
    } catch (e) {
      setError(e.message || 'Save failed.')
    } finally {
      setSaving(false)
    }
  }

  const onDiscard = () => {
    setTriageReason('')
    setDraft(pickEditable(inc))
    setOccurredAt(toEntryValue(inc.occurred_at))
    setDetectedAt(toEntryValue(inc.detected_at))
    setContainedAt(toEntryValue(inc.contained_at))
    setEradicatedAt(toEntryValue(inc.eradicated_at))
    setRecoveredAt(toEntryValue(inc.recovered_at))
    setEditing(false)
    setError('')
  }

  // Latest incident, for applyUpdate: it runs after an await, when the
  // closure's `inc` may be stale.
  const incRef = useRef(null)
  useEffect(() => { incRef.current = inc }, [inc])

  // Sync the incident from a side-panel save (Tags, Teams) and rebase the
  // drafts per field: a field you changed keeps your value; every other field
  // takes the server value, so another responder's change shows and is not
  // reverted by your next Save. Not editing, this is a full re-seed.
  const applyUpdate = useCallback((r) => {
    const prev = incRef.current
    const base = pickEditable(prev)
    const next = pickEditable(r)
    setDraft(d => {
      const out = {}
      for (const k of EDITABLE) out[k] = d[k] !== base[k] ? d[k] : next[k]
      return out
    })
    const rebaseDate = (k) => (v) => toEpoch(v) !== toEpoch(prev?.[k]) ? v : toEntryValue(r[k])
    setOccurredAt(rebaseDate('occurred_at'))
    setDetectedAt(rebaseDate('detected_at'))
    setContainedAt(rebaseDate('contained_at'))
    setEradicatedAt(rebaseDate('eradicated_at'))
    setRecoveredAt(rebaseDate('recovered_at'))
    incRef.current = r
    setInc(r)
  }, [])

  // `extra` = { phase_reason?, override_gate? } from the modal (gates: the API decides).
  const confirmPhaseChange = async (nextPhase, extra = {}) => {
    const updated = await api.updateIncident(id, { phase: nextPhase, ...extra })
    setInc(updated)
    setDraft(pickEditable(updated))
    setOccurredAt(toEntryValue(updated.occurred_at))
    setDetectedAt(toEntryValue(updated.detected_at))
    setContainedAt(toEntryValue(updated.contained_at))
    setEradicatedAt(toEntryValue(updated.eradicated_at))
    setRecoveredAt(toEntryValue(updated.recovered_at))
    setPhaseTarget(null)
  }

  // Declare a milestone: a plain PATCH of that one field (the API adds the timeline event).
  const confirmDeclare = async (field, value) => {
    const updated = await api.updateIncident(id, { [field]: value })
    applyUpdate(updated)
    setDeclaring(null)
  }

  // Close / Re-open: the modal does the POST via these; errors stay in the modal.
  const confirmClose = async (reason, overrideGate) => {
    applyUpdate(await api.closeIncident(id, reason, overrideGate))
    setClosureModal(null)
  }

  const confirmReopen = async (reason, phase, overrideGate) => {
    applyUpdate(await api.reopenIncident(id, reason, phase, overrideGate))
    setClosureModal(null)
  }

  // Edit opens the Details form in edit mode (the header Edit and the board's "Edit details").
  const onDetails = location.pathname.endsWith('/details')
  const startEdit = useCallback(() => {
    setEditing(true)
    if (!onDetails) navigate('details')
  }, [onDetails, navigate])

  const isClosed  = inc?.status === 'closed'
  const readOnly  = isClosed || !editing
  const canWrite  = user?.role !== 'viewer'
  const canEdit   = canWrite && !isClosed
  // A phase change re-seeds the Details draft, so the stepper waits while the form is open or dirty.
  const editLock  = editing || dirty

  // Memoised so state that only the header uses (presence avatars, modals) doesn't re-render
  // the active tab: the Outlet's consumers re-render only when a value here changes.
  const outletContext = useMemo(() => ({
    inc, draft, setField, readOnly, editing, isClosed, refresh, applyUpdate,
    occurredAt, setOccurredAt, detectedAt, setDetectedAt, containedAt, setContainedAt,
    eradicatedAt, setEradicatedAt, recoveredAt, setRecoveredAt, triageReason, setTriageReason,
    bumpLegal, bumpRail, access, refreshAccess, startEdit, canEdit,
  }), [inc, draft, setField, readOnly, editing, isClosed, refresh, applyUpdate, occurredAt, detectedAt,
       containedAt, eradicatedAt, recoveredAt, triageReason, bumpLegal, bumpRail, access, refreshAccess, startEdit, canEdit])

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

  const justSaved = !dirty && savedAt > 0 && Date.now() - savedAt < 4000
  // Only the next undeclared milestone is offered; none once all three are set.
  const nextMilestone = canWrite ? MILESTONES.find(m => !inc[m.field]) : undefined
  // Close is offered in Post-Incident, and in any phase for a false / benign positive
  // (the API enforces the same rule). Resolve = move to Post-Incident via the phase modal.
  const canClose  = inc.phase === 'post_incident' || ['false_positive', 'benign_positive'].includes(inc.triage_state)

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
              {nextMilestone && (
                <button
                  className="btn"
                  type="button"
                  onClick={() => setDeclaring(nextMilestone)}
                >Declare {nextMilestone.label}</button>
              )}
              <button
                className="btn"
                type="button"
                onClick={() => navigate('handoffs')}
              >Shift handoff</button>
              {canWrite && (
                <button
                  className="btn"
                  type="button"
                  onClick={startEdit}
                >Edit</button>
              )}
              {canWrite && inc.phase !== 'post_incident' && (
                <button
                  className="btn"
                  type="button"
                  title="Move to Post-Incident; the incident stays open"
                  onClick={() => setPhaseTarget('post_incident')}
                >Resolve</button>
              )}
              {canWrite && canClose && (
                <button
                  className="btn primary"
                  type="button"
                  onClick={() => setClosureModal('close')}
                >Close</button>
              )}
            </>
          )}
          {isClosed && canWrite && (
            <button
              className="btn primary"
              type="button"
              onClick={() => setClosureModal('reopen')}
            >Re-open</button>
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
          disabled={isClosed || !canWrite || editLock}
          onPhaseClick={isClosed || !canWrite || editLock ? undefined : setPhaseTarget}
          hint={!isClosed && canWrite && editLock ? 'Save or discard your Details edits to change the phase.' : null}
        />
        <ClockChips incidentId={inc.id} rev={legalRev} />
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
      {/* H3: the API says why automatic outbound is off (dark_operation / tlp_red). */}
      {inc.outbound_suppressed_by?.includes('tlp_red') && (
        <div className="dark-op-banner" role="status" data-outbound-banner>
          ■ Automatic outbound suppressed (TLP:RED)
        </div>
      )}

      {error && (
        <div className="alert error" role="alert" style={{ marginBottom: 'var(--space-3)' }}>
          <span className="alert-icon">!</span><span>{error}</span>
        </div>
      )}

      <div className="sub-layout">
        <IncidentRail key={inc.id} incidentId={inc.id} groups={navGroups} rev={railRev} />
        <div className="sub-content">
          <Outlet context={outletContext} />
        </div>
      </div>

      <WarRoomDrawer incidentId={inc.id} incidentRef={inc.ref} />

      {phaseTarget && (
        <PhaseChangeModal
          incidentId={inc.id}
          currentPhase={inc.phase}
          targetPhase={phaseTarget}
          triageState={inc.triage_state}
          canOverride={can('override_gate')}
          onConfirm={confirmPhaseChange}
          onClose={() => setPhaseTarget(null)}
        />
      )}

      {declaring && (
        <DeclareMilestoneModal
          milestone={declaring}
          onConfirm={confirmDeclare}
          onClose={() => setDeclaring(null)}
        />
      )}

      {closureModal === 'close' && (
        <CloseIncidentModal
          inc={inc}
          canOverride={can('override_gate')}
          onConfirm={confirmClose}
          onClose={() => setClosureModal(null)}
        />
      )}
      {closureModal === 'reopen' && (
        <ReopenIncidentModal
          incidentId={inc.id}
          canOverride={can('override_gate')}
          onConfirm={confirmReopen}
          onClose={() => setClosureModal(null)}
        />
      )}
    </div>
  )
}
