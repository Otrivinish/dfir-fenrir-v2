import { useEffect, useState } from 'react'
import { api } from '../api/client.js'
import { SEVERITY, PHASE, TLP, INCIDENT_TYPE } from '../lib/incidentVocab.js'
import { useAuth } from '../hooks/useAuth.jsx'
import TagInput from './TagInput.jsx'
import UtcDateTimeInput from './UtcDateTimeInput.jsx'

const INITIAL = {
  title: '',
  description: '',
  severity: 'medium',
  phase: 'detection_and_analysis',
  tlp: 'amber',
  incident_type: '',
  reporter: '',
  occurred_at: '',
}

export default function IncidentCreateModal({ open, onClose, onCreated }) {
  const { user } = useAuth()
  const isAdmin = user?.role === 'admin'
  const [form, setForm] = useState(INITIAL)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [allTeams, setAllTeams] = useState([])
  const [selectedTeamIds, setSelectedTeamIds] = useState([])
  const [tags, setTags] = useState([])

  useEffect(() => {
    if (open) { setForm(INITIAL); setError(''); setBusy(false); setSelectedTeamIds([]); setTags([]) }
  }, [open])

  useEffect(() => {
    if (open && isAdmin && allTeams.length === 0) {
      api.listTeams().then(data => setAllTeams(data.items ?? data)).catch(() => {})
    }
  }, [open, isAdmin])

  useEffect(() => {
    if (!open) return
    const onKey = (e) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [open, onClose])

  if (!open) return null

  const set = (k) => (e) => setForm(f => ({ ...f, [k]: e.target.value }))

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
        reporter: form.reporter.trim() || null,
        occurred_at: form.occurred_at || null,
        team_ids: selectedTeamIds,
        tags,
      })
      onCreated(created)
    } catch (err) {
      setError(err.message || 'Could not create incident.')
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
                  {PHASE.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
                </select>
              </div>

              <div className="field">
                <label className="field-label" htmlFor="inc-reporter">Reporter (optional)</label>
                <input id="inc-reporter" className="input" value={form.reporter} onChange={set('reporter')}
                       maxLength={128} placeholder="e.g. SOC L1, soc@example.com" />
              </div>

              {isAdmin && allTeams.length > 0 && (
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
                    Leave unchecked to make this incident visible to all users.
                  </span>
                </div>
              )}

              <div className="field">
                <label className="field-label" htmlFor="inc-occurred">When did it occur? (UTC, optional)</label>
                <UtcDateTimeInput id="inc-occurred" value={form.occurred_at}
                       onChange={v => setForm(f => ({ ...f, occurred_at: v }))} hint={false} />
                <span style={{ fontSize: 11, color: 'var(--muted)', marginTop: 2, display: 'block' }}>UTC · YYYY-MM-DD HH:mm:ss. Used for Mean Time to Detect. Leave blank if unknown.</span>
              </div>

              <div className="field">
                <label className="field-label">Tags (optional)</label>
                <TagInput value={tags} onChange={setTags} scope="incident" placeholder="Add tag and press Enter…" />
                <span style={{ fontSize: 11, color: 'var(--muted)', marginTop: 2, display: 'block' }}>
                  Lowercase-dashed (e.g. <code>credential-theft</code>, <code>apt28</code>). Max 20 per incident. Suggestions pull from existing tags.
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
