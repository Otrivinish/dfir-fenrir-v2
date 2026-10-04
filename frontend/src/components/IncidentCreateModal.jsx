import { useEffect, useState } from 'react'
import { api } from '../api/client.js'
import { SEVERITY, PHASE, TLP, INCIDENT_TYPE, DETECTION_METHOD, TRIAGE_STATE } from '../lib/incidentVocab.js'
import { useAuth } from '../hooks/useAuth.jsx'
import TagInput from './TagInput.jsx'
import LocalDateTimePicker from './LocalDateTimePicker.jsx'

const INITIAL = {
  title: '',
  description: '',
  severity: 'medium',
  phase: 'detection_and_analysis',
  tlp: 'amber',
  incident_type: '',
  detection_method: '',
  triage_state: 'suspected',
  triage_reason: '',
  reporter: '',
  occurred_at: '',
  detected_at: '',
  dark_operation: false,
}

// An incident is opened because something was detected: the API accepts only these start phases.
const START_PHASES = PHASE.filter(p => p.value === 'detection_and_analysis' || p.value === 'containment_eradication_recovery')
const UUID_RE = /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi

export default function IncidentCreateModal({ open, onClose, onCreated }) {
  const { user } = useAuth()
  const isAdmin = user?.role === 'admin'
  // GET /api/readiness is admin + analyst only; viewers never ask for it.
  const readsReadiness = isAdmin || user?.role === 'analyst'
  // Admins may restrict a new incident to any team, analysts to their own (the API says 409 would_lock_out otherwise).
  const canPickTeams = readsReadiness
  const [form, setForm] = useState(INITIAL)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [allTeams, setAllTeams] = useState([])
  const [selectedTeamIds, setSelectedTeamIds] = useState([])
  const [tags, setTags] = useState([])
  const [blockers, setBlockers] = useState([])   // failing readiness blockers: shown, never blocking

  useEffect(() => {
    // Detected defaults to now (editable); the API never fills it in itself.
    if (open) { setForm({ ...INITIAL, detected_at: new Date().toISOString() }); setError(''); setBusy(false); setSelectedTeamIds([]); setTags([]) }
  }, [open])

  useEffect(() => {
    setBlockers([])
    if (!open || !readsReadiness) return
    let live = true
    api.getReadiness()
      .then(d => { if (live) setBlockers(d.checks.filter(c => c.level === 'blocker' && c.status === 'fail')) })
      .catch(() => {})   // 403 or offline: no callout
    return () => { live = false }
  }, [open, readsReadiness])

  useEffect(() => {
    if (open && canPickTeams && allTeams.length === 0) {
      api.listTeams().then(data => setAllTeams(data.items ?? data)).catch(() => {})
    }
  }, [open, canPickTeams])

  useEffect(() => {
    if (!open) return
    const onKey = (e) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [open, onClose])

  if (!open) return null

  const set = (k) => (e) => setForm(f => ({ ...f, [k]: e.target.value }))
  // A false / benign positive asks for a reason (the API requires one outside Detection &
  // Analysis: such an incident can be closed without Gate 2; 422 triage_reason_required).
  const askTriageReason = ['false_positive', 'benign_positive'].includes(form.triage_state)

  const onSubmit = async (e) => {
    e.preventDefault()
    setError('')
    if (form.title.trim().length < 3) { setError('Title must be at least 3 characters.'); return }
    setBusy(true)
    try {
      const created = await api.createIncident({
        title: form.title.trim(),
        description: form.description.trim() || null,
        severity: form.severity,
        phase: form.phase,
        tlp: form.tlp,
        incident_type: form.incident_type || null,
        detection_method: form.detection_method || null,
        triage_state: form.triage_state,
        ...(askTriageReason && form.triage_reason.trim() ? { triage_reason: form.triage_reason.trim() } : {}),
        reporter: form.reporter.trim() || null,
        occurred_at: form.occurred_at || null,
        detected_at: form.detected_at,
        team_ids: selectedTeamIds,
        tags,
        dark_operation: form.dark_operation,
      })
      onCreated(created)
    } catch (err) {
      // 409 would_lock_out / 422 team_not_found name teams by id: show their names instead.
      const names = new Map(allTeams.map(t => [String(t.id).toLowerCase(), t.name]))
      setError((err.message || 'Could not create incident.').replace(UUID_RE, id => names.has(id.toLowerCase()) ? `“${names.get(id.toLowerCase())}”` : id))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="modal-backdrop">
      <div className="modal" role="dialog" aria-labelledby="newinc-title">
        <div className="modal-head">
          <h2 id="newinc-title">New incident</h2>
          <button className="modal-close" type="button" onClick={onClose} aria-label="Close">×</button>
        </div>
        <form onSubmit={onSubmit}>
          <div className="modal-body">
            <div className="form">
              {blockers.length > 0 && (
                <div className="rd-callout" role="note" aria-labelledby="newinc-rd-head">
                  <div id="newinc-rd-head" className="rd-callout-head">
                    <span className="rd-banner-mark" aria-hidden="true">!</span>
                    {blockers.length} readiness blocker{blockers.length === 1 ? '' : 's'} failing
                  </div>
                  <ul className="rd-callout-list">{blockers.map(b => <li key={b.id}>{b.title}</li>)}</ul>
                  <div className="rd-callout-note">You can still create the incident. Details: Prepare → Readiness.</div>
                </div>
              )}

              <div className="field">
                <label className="field-label" htmlFor="inc-title">Title</label>
                <input id="inc-title" className="input" value={form.title} onChange={set('title')}
                       autoFocus required minLength={3} maxLength={200} placeholder="Short, descriptive headline" />
              </div>

              <div className="field">
                <label className="field-label" htmlFor="inc-desc">Description</label>
                <textarea id="inc-desc" className="input" value={form.description} onChange={set('description')}
                          placeholder="What was observed, when, on which systems" rows={4} />
              </div>

              <div className="field">
                <label className="field-label" htmlFor="inc-type">Incident type (optional)</label>
                <select id="inc-type" className="select" value={form.incident_type} onChange={set('incident_type')}>
                  <option value="">— unclassified —</option>
                  {INCIDENT_TYPE.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
                </select>
              </div>

              <div className="form-row">
                <div className="field">
                  <label className="field-label" htmlFor="inc-sev">Severity</label>
                  <select id="inc-sev" className="select" value={form.severity} onChange={set('severity')}>
                    {SEVERITY.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
                  </select>
                </div>
                <div className="field">
                  <label className="field-label" htmlFor="inc-tlp">TLP</label>
                  <select id="inc-tlp" className="select" value={form.tlp} onChange={set('tlp')}>
                    {TLP.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
                  </select>
                </div>
              </div>

              <div className="field">
                <label className="field-label" htmlFor="inc-phase">Phase (800-61 R3)</label>
                <select id="inc-phase" className="select" value={form.phase} onChange={set('phase')}>
                  {START_PHASES.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
                </select>
              </div>

              <div className="form-row">
                <div className="field">
                  <label className="field-label" htmlFor="inc-method">How detected (optional)</label>
                  <select id="inc-method" className="select" value={form.detection_method} onChange={set('detection_method')}>
                    <option value="">— not set —</option>
                    {DETECTION_METHOD.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
                  </select>
                </div>
                <div className="field">
                  <label className="field-label" htmlFor="inc-triage">Triage state</label>
                  <select id="inc-triage" className="select" value={form.triage_state} onChange={set('triage_state')}>
                    {TRIAGE_STATE.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
                  </select>
                </div>
              </div>

              {askTriageReason && (
                <div className="field">
                  <label className="field-label" htmlFor="inc-triage-reason">Reason for the triage state</label>
                  <textarea id="inc-triage-reason" className="input" rows={2} maxLength={2000}
                            aria-describedby="inc-triage-reason-hint"
                            value={form.triage_reason} onChange={set('triage_reason')}
                            placeholder="e.g. Alert fired on the scheduled pen test (ticket SEC-1234)…" />
                  <span id="inc-triage-reason-hint" className="field-hint" style={{ color: 'var(--muted)' }}>
                    Required outside Detection &amp; Analysis (at least 10 characters): a false or benign
                    positive can be closed without Gate 2. Saved to the audit log and the Timeline.
                  </span>
                </div>
              )}

              <div className="field">
                <label className="field-label" htmlFor="inc-reporter">Reporter (optional)</label>
                <input id="inc-reporter" className="input" value={form.reporter} onChange={set('reporter')}
                       maxLength={128} placeholder="e.g. SOC L1, soc@example.com" />
              </div>

              {canPickTeams && allTeams.length > 0 && (
                <div className="field">
                  <label className="field-label">Restrict to teams (optional)</label>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                    {allTeams.map(t => (
                      <label key={t.id} style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer', fontSize: 13 }}>
                        <input
                          type="checkbox"
                          checked={selectedTeamIds.includes(t.id)}
                          onChange={() => setSelectedTeamIds(s =>
                            s.includes(t.id) ? s.filter(x => x !== t.id) : [...s, t.id]
                          )}
                        />
                        <span style={{ width: 10, height: 10, borderRadius: '50%', background: t.color, flexShrink: 0 }} />
                        {t.name}
                      </label>
                    ))}
                  </div>
                  <span style={{ fontSize: 11, color: 'var(--muted)', marginTop: 2, display: 'block' }}>
                    {isAdmin ? '' : 'Pick only teams you belong to. '}Leave unchecked to make this incident visible to all users.
                  </span>
                </div>
              )}

              <div className="field">
                <label className="field-label" htmlFor="inc-occurred">When did it occur? (optional)</label>
                <LocalDateTimePicker id="inc-occurred" value={form.occurred_at}
                       onChange={v => setForm(f => ({ ...f, occurred_at: v }))} />
                <span style={{ fontSize: 11, color: 'var(--muted)', marginTop: 2, display: 'block' }}>Used for Mean Time to Detect. Leave blank if unknown.</span>
              </div>

              <div className="field">
                <label className="field-label" htmlFor="inc-detected">Detected</label>
                <LocalDateTimePicker id="inc-detected" value={form.detected_at} required
                       onChange={v => setForm(f => ({ ...f, detected_at: v }))} />
                <span className="field-hint">
                  When the alert fired or the report came in. Pre-filled with now; change it if detection was earlier.
                </span>
              </div>

              <div className="field">
                <label className="field-label">Tags (optional)</label>
                <TagInput value={tags} onChange={setTags} scope="incident" placeholder="Add tag and press Enter…" />
                <span style={{ fontSize: 11, color: 'var(--muted)', marginTop: 2, display: 'block' }}>
                  Lowercase-dashed (e.g. <code>credential-theft</code>, <code>apt28</code>). Max 20 per incident. Suggestions pull from existing tags.
                </span>
              </div>

              <div className="field">
                <label style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', cursor: 'pointer', fontSize: 13 }}>
                  <input id="inc-dark" type="checkbox" checked={form.dark_operation} aria-describedby="inc-dark-hint"
                         onChange={e => setForm(f => ({ ...f, dark_operation: e.target.checked }))} />
                  Open as Dark Operation
                </label>
                <span id="inc-dark-hint" className="field-hint">
                  Nothing about this incident goes to Teams, Slack or the alert mailbox, from the moment it is created. In-app notifications still reach people who can see it.
                </span>
              </div>

              {error && (
                <div className="alert error" role="alert">
                  <span className="alert-icon">!</span>
                  <span>{error}</span>
                </div>
              )}
            </div>
          </div>
          <div className="modal-foot">
            <button type="button" className="btn ghost" onClick={onClose} disabled={busy}>Cancel</button>
            <button type="submit" className="btn primary" disabled={busy}>
              {busy ? 'Creating…' : 'Create incident'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
