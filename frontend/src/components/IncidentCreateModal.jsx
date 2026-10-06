import { useEffect, useState } from 'react'
import { api } from '../api/client.js'
import { SEVERITY, PHASE, TLP, INCIDENT_TYPE, DETECTION_METHOD, TRIAGE_STATE,
         FUNCTIONAL_IMPACT, INFORMATION_IMPACT, RECOVERABILITY, IOC_TYPE } from '../lib/incidentVocab.js'
import { useAuth } from '../hooks/useAuth.jsx'
import TagInput from './TagInput.jsx'
import LocalDateTimePicker from './LocalDateTimePicker.jsx'

// Required by the API (I4, owner decision 2026-10-06): title, severity, type, how detected, detected.
// Severity, type, method and Detected start empty: the operator chooses; nothing is pre-filled.
const INITIAL = {
  title: '',
  description: '',
  severity: '',
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
  // I4 optional intake
  ic_user_id: '',
  functional_impact: '',
  information_impact: '',
  recoverability: '',
  severity_rationale: '',
  alert_reference: '',
  first_host: '',
  first_ioc_type: 'ip',
  first_ioc_value: '',
}

const REQUIRED = [
  ['title', 'Title'], ['severity', 'Severity'], ['incident_type', 'Incident type'],
  ['detection_method', 'How detected'], ['detected_at', 'Detected'],
]
const OPTIONAL_TEXT = ['functional_impact', 'information_impact', 'recoverability', 'severity_rationale',
                       'alert_reference', 'first_host']

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
  const [suggested, setSuggested] = useState([])  // playbook templates suggested for the chosen type (I3)
  const [people, setPeople] = useState([])        // Incident Commander picker (active users)

  useEffect(() => {
    // Detected starts empty: the operator enters it (the API never fills it in either).
    if (open) { setForm(INITIAL); setError(''); setBusy(false); setSelectedTeamIds([]); setTags([]) }
  }, [open])

  useEffect(() => {
    if (!open || !readsReadiness) return
    let live = true
    api.listAssignableUsers().then(d => { if (live) setPeople(d) }).catch(() => {})
    return () => { live = false }
  }, [open, readsReadiness])

  useEffect(() => {
    setBlockers([])
    if (!open || !readsReadiness) return
    let live = true
    api.getReadiness()
      .then(d => { if (live) setBlockers(d.checks.filter(c => c.level === 'blocker' && c.status === 'fail')) })
      .catch(() => {})   // 403 or offline: no callout
    return () => { live = false }
  }, [open, readsReadiness])

  // Suggest, never apply: the templates for the chosen type are named here and offered on the
  // incident's Playbook tab after it is created.
  useEffect(() => {
    setSuggested([])
    if (!open || !form.incident_type) return
    let live = true
    api.listPlaybookTemplates({ incident_type: form.incident_type })
      .then(d => { if (live) setSuggested(d) })
      .catch(() => {})
    return () => { live = false }
  }, [open, form.incident_type])

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
    const missing = REQUIRED.filter(([k]) => !String(form[k] ?? '').trim()).map(([, label]) => label)
    if (missing.length) { setError(`Required: ${missing.join(', ')}.`); return }
    if (form.title.trim().length < 3) { setError('Title must be at least 3 characters.'); return }
    const optional = Object.fromEntries(OPTIONAL_TEXT.map(k => [k, form[k].trim()]).filter(([, v]) => v))
    setBusy(true)
    try {
      const created = await api.createIncident({
        title: form.title.trim(),
        description: form.description.trim() || null,
        severity: form.severity,
        phase: form.phase,
        tlp: form.tlp,
        incident_type: form.incident_type,
        detection_method: form.detection_method,
        triage_state: form.triage_state,
        ...(askTriageReason && form.triage_reason.trim() ? { triage_reason: form.triage_reason.trim() } : {}),
        reporter: form.reporter.trim() || null,
        occurred_at: form.occurred_at || null,
        detected_at: form.detected_at,
        team_ids: selectedTeamIds,
        tags,
        // Sent only when ticked: an explicit choice records the Dark Operation decision (I4).
        ...(form.dark_operation ? { dark_operation: true } : {}),
        ...optional,
        ...(form.ic_user_id ? { ic_user_id: form.ic_user_id } : {}),
        ...(form.first_ioc_value.trim() ? { first_ioc: { type: form.first_ioc_type, value: form.first_ioc_value.trim() } } : {}),
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
                <label className="field-label" htmlFor="inc-type">Incident type</label>
                <select id="inc-type" className="select" value={form.incident_type} onChange={set('incident_type')} required>
                  <option value="">— choose —</option>
                  {INCIDENT_TYPE.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
                </select>
                {suggested.length > 0 && (
                  <div className="field-hint">
                    Suggested playbook{suggested.length === 1 ? '' : 's'}: {suggested.map(t => t.name).join(' · ')}.
                    After you create the incident, its start checks link to the Playbook tab to apply one.
                  </div>
                )}
              </div>

              <div className="form-row">
                <div className="field">
                  <label className="field-label" htmlFor="inc-sev">Severity</label>
                  <select id="inc-sev" className="select" value={form.severity} onChange={set('severity')} required>
                    <option value="">— choose —</option>
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
                  <label className="field-label" htmlFor="inc-method">How detected</label>
                  <select id="inc-method" className="select" value={form.detection_method} onChange={set('detection_method')} required>
                    <option value="">— choose —</option>
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
                  When the alert fired or the report came in. Required; nothing is filled in for you.
                </span>
              </div>

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

              <section className="newinc-optional" aria-labelledby="newinc-opt-head">
                <h3 id="newinc-opt-head" className="newinc-optional-head">Optional — fill in what you already know</h3>
                <div className="field">
                  <label className="field-label" htmlFor="inc-ic">Incident Commander</label>
                  <select id="inc-ic" className="select" value={form.ic_user_id} onChange={set('ic_user_id')}>
                    <option value="">— not yet —</option>
                    {people.map(u => <option key={u.id} value={u.id}>{u.username}{u.full_name ? ` (${u.full_name})` : ''}{u.id === user?.id ? ' — me' : ''}</option>)}
                  </select>
                  <span className="field-hint">Assigned with the incident. They must be able to see it (its teams) and get an in-app notification.</span>
                </div>
                <div className="form-row">
                  <div className="field">
                    <label className="field-label" htmlFor="inc-fimpact">Functional impact</label>
                    <select id="inc-fimpact" className="select" value={form.functional_impact} onChange={set('functional_impact')}>
                      <option value="">— not assessed —</option>
                      {FUNCTIONAL_IMPACT.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
                    </select>
                  </div>
                  <div className="field">
                    <label className="field-label" htmlFor="inc-iimpact">Information impact</label>
                    <select id="inc-iimpact" className="select" value={form.information_impact} onChange={set('information_impact')}>
                      <option value="">— not assessed —</option>
                      {INFORMATION_IMPACT.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
                    </select>
                  </div>
                </div>
                <div className="field">
                  <label className="field-label" htmlFor="inc-recover">Recoverability</label>
                  <select id="inc-recover" className="select" value={form.recoverability} onChange={set('recoverability')}>
                    <option value="">— not assessed —</option>
                    {RECOVERABILITY.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
                  </select>
                  <span className="field-hint">NIST SP 800-61 impact categories.</span>
                </div>
                <div className="field">
                  <label className="field-label" htmlFor="inc-sevwhy">Why this severity</label>
                  <textarea id="inc-sevwhy" className="input" rows={2} maxLength={2000} value={form.severity_rationale}
                            onChange={set('severity_rationale')} placeholder="e.g. Domain admin account used on 3 servers" />
                </div>
                <div className="field">
                  <label className="field-label" htmlFor="inc-alertref">Alert reference</label>
                  <input id="inc-alertref" className="input" maxLength={256} value={form.alert_reference}
                         onChange={set('alert_reference')} placeholder="Source system and alert id, e.g. Sentinel 4f2a91" />
                </div>
                <div className="field">
                  <label className="field-label" htmlFor="inc-host">First affected host</label>
                  <input id="inc-host" className="input" maxLength={255} value={form.first_host}
                         onChange={set('first_host')} placeholder="e.g. FIN-WS-07" />
                  <span className="field-hint">Added to Entities as a compromised host (in scope).</span>
                </div>
                <div className="form-row">
                  <div className="field">
                    <label className="field-label" htmlFor="inc-ioc-type">First IOC type</label>
                    <select id="inc-ioc-type" className="select" value={form.first_ioc_type} onChange={set('first_ioc_type')}>
                      {IOC_TYPE.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
                    </select>
                  </div>
                  <div className="field">
                    <label className="field-label" htmlFor="inc-ioc-value">First IOC value</label>
                    <input id="inc-ioc-value" className="input" maxLength={2048} value={form.first_ioc_value}
                           onChange={set('first_ioc_value')} placeholder="e.g. 203.0.113.7" />
                  </div>
                </div>
              </section>

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
