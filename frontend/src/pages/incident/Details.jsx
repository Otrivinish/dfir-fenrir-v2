import { Fragment, useState, useEffect, useCallback } from 'react'
import { useOutletContext, Link } from 'react-router-dom'
import ReactMarkdown from 'react-markdown'
import { formatLocal } from '../../lib/datetime.js'
import { SEVERITY, TLP, TRIAGE_STATE, INCIDENT_TYPE, DETECTION_METHOD, ENTITY_TYPE, labelOf } from '../../lib/incidentVocab.js'
import { api } from '../../api/client.js'
import { matchEntity } from '../../lib/entityMatch.js'
import TagChip from '../../components/TagChip.jsx'
import TagInput from '../../components/TagInput.jsx'
import LocalDateTimePicker from '../../components/LocalDateTimePicker.jsx'
import ClassificationStrip, { TeamChip } from '../../components/ClassificationStrip.jsx'

const UUID_RE = /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi

function TeamsSection({ inc, onUpdated }) {
  const [allTeams, setAllTeams]     = useState(null)
  const [editing, setEditing]       = useState(false)
  const [selected, setSelected]     = useState([])
  const [busy, setBusy]             = useState(false)
  const [error, setError]           = useState('')

  const openEdit = async () => {
    setError('')
    if (!allTeams) {
      try {
        const data = await api.listTeams()
        setAllTeams(data.items ?? data)
      } catch {
        setError('Could not load teams.')
        return
      }
    }
    setSelected((inc.teams ?? []).map(t => t.id))
    setEditing(true)
  }

  const toggle = (id) => setSelected(s => s.includes(id) ? s.filter(x => x !== id) : [...s, id])

  const save = async () => {
    setBusy(true); setError('')
    try {
      const updated = await api.updateIncident(inc.id, { team_ids: selected })
      onUpdated(updated)
      setEditing(false)
    } catch (e) {
      // The API's 409 would_lock_out / would_unrestrict (and 422 team_not_found) explain
      // themselves but name teams by id: show their names instead.
      const names = new Map((allTeams ?? []).map(t => [String(t.id).toLowerCase(), t.name]))
      setError((e.message || 'Save failed.').replace(UUID_RE, id => names.has(id.toLowerCase()) ? `“${names.get(id.toLowerCase())}”` : id))
    } finally {
      setBusy(false)
    }
  }

  const currentTeams = inc.teams ?? []

  return (
    <>
      <dt style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 4 }}>
        <span>Teams</span>
        {!editing && (
          <button type="button" className="btn ghost"
            style={{ fontSize: 11, padding: '1px 6px', marginTop: -1 }}
            onClick={openEdit}>Manage</button>
        )}
      </dt>
      <dd style={{ minWidth: 0 }}>
        {editing ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-2)' }}>
            {(allTeams ?? []).length === 0 ? (
              <span style={{ fontSize: 12, color: 'var(--muted)' }}>No teams configured.</span>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                {(allTeams ?? []).map(t => (
                  <label key={t.id} style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer', fontSize: 13 }}>
                    <input type="checkbox" checked={selected.includes(t.id)} onChange={() => toggle(t.id)} />
                    <span style={{ width: 10, height: 10, borderRadius: '50%', background: t.color, flexShrink: 0 }} />
                    {t.name}
                  </label>
                ))}
              </div>
            )}
            {error && <div className="team-picker-error" role="alert"><span className="team-picker-error-mark" aria-hidden="true">!</span><span>{error}</span></div>}
            <div style={{ display: 'flex', gap: 'var(--space-2)' }}>
              <button type="button" className="btn ghost" style={{ fontSize: 12 }}
                onClick={() => setEditing(false)} disabled={busy}>Cancel</button>
              <button type="button" className="btn primary" style={{ fontSize: 12 }}
                onClick={save} disabled={busy}>{busy ? 'Saving…' : 'Save'}</button>
            </div>
          </div>
        ) : (
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
            {currentTeams.length === 0
              ? <span style={{ fontSize: 12, color: 'var(--muted)' }}>Unrestricted</span>
              : currentTeams.map(t => <TeamChip key={t.id} team={t} />)
            }
          </div>
        )}
      </dd>
    </>
  )
}

function TagsSection({ inc, readOnly, onUpdated }) {
  const [editing, setEditing] = useState(false)
  const [draft, setDraft]     = useState([])
  const [busy, setBusy]       = useState(false)
  const [error, setError]     = useState('')

  const tags = inc.tags || []

  const openEdit = () => {
    setDraft([...tags])
    setError('')
    setEditing(true)
  }

  const save = async () => {
    setBusy(true); setError('')
    try {
      const updated = await api.updateIncident(inc.id, { tags: draft })
      onUpdated(updated)
      setEditing(false)
    } catch (e) {
      setError(e.message || 'Save failed.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <dt style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 4 }}>
        <span>Tags</span>
        {!editing && !readOnly && (
          <button type="button" className="btn ghost"
            style={{ fontSize: 11, padding: '1px 6px', marginTop: -1 }}
            onClick={openEdit}>Manage</button>
        )}
      </dt>
      <dd style={{ minWidth: 0 }}>
        {editing ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-2)' }}>
            <TagInput value={draft} onChange={setDraft} scope="incident" />
            {error && <span style={{ fontSize: 12, color: 'var(--crit)' }}>{error}</span>}
            <div style={{ display: 'flex', gap: 'var(--space-2)' }}>
              <button type="button" className="btn ghost" style={{ fontSize: 12 }}
                onClick={() => setEditing(false)} disabled={busy}>Cancel</button>
              <button type="button" className="btn primary" style={{ fontSize: 12 }}
                onClick={save} disabled={busy}>{busy ? 'Saving…' : 'Save'}</button>
            </div>
          </div>
        ) : (
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
            {tags.length === 0
              ? <span style={{ fontSize: 12, color: 'var(--muted)' }}>No tags</span>
              : tags.map(t => <TagChip key={t} tag={t} />)
            }
          </div>
        )}
      </dd>
    </>
  )
}

const BLANK_SYSTEM = { value: '', type: 'host', notes: '' }

// Affected systems = this incident's compromised entities (C2): one scope list, kept on the
// Entities tab. Add marks an existing entity compromised or creates a new one; Clear removes
// the flag only (the entity stays). Everything else about an entity is edited in Entities.
function AffectedSystemsSection({ incidentId, readOnly }) {
  const [systems, setSystems] = useState(null)
  const [loading, setLoading] = useState(false)
  const [adding, setAdding]   = useState(false)
  const [scope, setScope]     = useState([])     // every entity of the incident, for the Add picker
  const [form, setForm]       = useState(BLANK_SYSTEM)
  const [busy, setBusy]       = useState(false)
  const [error, setError]     = useState('')

  const load = useCallback(async () => {
    setLoading(true)
    try {
      setSystems(await api.listAllEntities(incidentId, { compromised: true }))
    } catch { setSystems([]) }
    finally { setLoading(false) }
  }, [incidentId])

  useEffect(() => { load() }, [load])

  const openAdd = async () => {
    setForm(BLANK_SYSTEM); setError(''); setScope([]); setAdding(true)
    try { setScope(await api.listAllEntities(incidentId)) } catch { /* picker stays empty; typing still works */ }
  }

  const value    = form.value.trim()
  // Case-insensitive (M6): "dc01" flags the existing "DC01" instead of adding a duplicate.
  const existing = matchEntity(scope.filter(e => e.type === form.type), value)

  // Picking a known value takes that entity's type, so it is flagged instead of duplicated.
  const onValueChange = (v) => {
    const match = matchEntity(scope, v.trim())
    setForm(f => ({ ...f, value: v, ...(match ? { type: match.type } : {}) }))
  }

  const handleSave = async () => {
    if (!value) { setError('Enter the host, account or service.'); return }
    setBusy(true); setError('')
    try {
      if (existing) {
        await api.updateEntity(incidentId, existing.id, { compromised: true })
      } else {
        await api.createEntity(incidentId, {
          type: form.type, value, description: form.notes.trim() || null,
          criticality: 'high', compromised: true,
        })
      }
      setAdding(false)
      await load()
    } catch (e) {
      setError(e.message || 'Save failed.')
    } finally {
      setBusy(false)
    }
  }

  const handleClear = async (s) => {
    if (!confirm(`Clear the compromised flag on "${s.value}"?\n\nIt stays in Entities.`)) return
    try {
      await api.updateEntity(incidentId, s.id, { compromised: false })
      setSystems(prev => prev.filter(x => x.id !== s.id))
    } catch (e) {
      alert(e.message || 'Could not clear the flag.')
    }
  }

  return (
    <section className="panel" style={{ marginTop: 'var(--space-4)' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 'var(--space-3)', gap: 'var(--space-2)', flexWrap: 'wrap' }}>
        <div>
          <h2 className="panel-h" style={{ margin: 0 }}>Affected systems</h2>
          <div style={{ color: 'var(--muted)', fontSize: 12 }}>Entities marked compromised</div>
        </div>
        <div style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'center', flexWrap: 'wrap' }}>
          <Link to={`/incidents/${incidentId}/entities`} className="btn ghost" style={{ fontSize: 12, textDecoration: 'none' }}>
            Manage in Entities →
          </Link>
          {!readOnly && (
            <button type="button" className="btn ghost" style={{ fontSize: 12 }} onClick={openAdd}>
              + Add system
            </button>
          )}
        </div>
      </div>

      {loading && <div style={{ color: 'var(--muted)', fontSize: 13 }}>Loading…</div>}

      {!loading && systems?.length === 0 && (
        <div style={{ color: 'var(--dim)', fontStyle: 'italic', fontSize: 13 }}>No affected systems recorded.</div>
      )}

      {!loading && systems?.length > 0 && (
        <table className="data-table" style={{ width: '100%' }}>
          <thead>
            <tr>
              <th>System</th>
              <th>Type</th>
              <th>Notes</th>
              {!readOnly && <th style={{ width: 80 }} />}
            </tr>
          </thead>
          <tbody>
            {systems.map(s => (
              <tr key={s.id}>
                <td>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>{s.value}</div>
                  {s.name && s.name !== s.value && (
                    <div style={{ color: 'var(--muted)', fontSize: 11 }}>{s.name}</div>
                  )}
                </td>
                <td>
                  {labelOf('entity_type', s.type)}
                  {s.attributes?.system_type && (
                    <span style={{ color: 'var(--muted)' }}> · {labelOf('system_type', s.attributes.system_type)}</span>
                  )}
                </td>
                <td style={{ color: s.description ? 'inherit' : 'var(--muted)', fontSize: 12 }}>{s.description || '—'}</td>
                {!readOnly && (
                  <td style={{ textAlign: 'right', whiteSpace: 'nowrap' }}>
                    <button type="button" className="btn ghost" style={{ fontSize: 11, padding: '1px 6px' }}
                      title="Clear the compromised flag; the entity stays in Entities"
                      onClick={() => handleClear(s)}>Clear</button>
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {adding && (
        <div className="modal-backdrop" onClick={() => setAdding(false)}>
          <div className="modal" style={{ maxWidth: 420 }} onClick={e => e.stopPropagation()}>
            <div className="modal-head">
              <span>Add affected system</span>
              <button type="button" className="modal-close" onClick={() => setAdding(false)}>×</button>
            </div>
            <div className="modal-body" style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
              <div className="field">
                <label className="field-label" htmlFor="as-value">System <span style={{ color: 'var(--crit)' }}>*</span></label>
                <input id="as-value" className="input" value={form.value} list="as-entity-options"
                  onChange={e => onValueChange(e.target.value)}
                  placeholder="Pick from Entities or type a hostname, account, service…" maxLength={2048} autoFocus />
                <datalist id="as-entity-options">
                  {scope.filter(e => !e.compromised).map(e => (
                    <option key={e.id} value={e.value}>
                      {labelOf('entity_type', e.type)}{e.name && e.name !== e.value ? ` · ${e.name}` : ''}
                    </option>
                  ))}
                </datalist>
              </div>
              <div className="field">
                <label className="field-label" htmlFor="as-type">Entity type</label>
                <select id="as-type" className="select" value={form.type}
                  onChange={e => setForm(f => ({ ...f, type: e.target.value }))}>
                  {ENTITY_TYPE.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
                </select>
              </div>
              {!existing && (
                <div className="field">
                  <label className="field-label" htmlFor="as-notes">Notes</label>
                  <textarea id="as-notes" className="input" value={form.notes}
                    onChange={e => setForm(f => ({ ...f, notes: e.target.value }))}
                    rows={3} placeholder="Optional context…" />
                </div>
              )}
              {value && (
                <div role="status" style={{ color: 'var(--muted)', fontSize: 12 }}>
                  {existing?.compromised
                    ? 'Already marked compromised.'
                    : existing
                      ? `Already in Entities${existing.value !== value ? ` as “${existing.value}”` : ''}: Add marks it compromised.`
                      : `New entity (${labelOf('entity_type', form.type)}), marked compromised.`}
                </div>
              )}
              {error && (
                <div className="alert error" role="alert">
                  <span className="alert-icon">!</span><span>{error}</span>
                </div>
              )}
            </div>
            <div className="modal-foot">
              <button type="button" className="btn ghost" onClick={() => setAdding(false)} disabled={busy}>Cancel</button>
              <button type="button" className="btn primary" onClick={handleSave} disabled={busy || existing?.compromised}>
                {busy ? 'Saving…' : 'Add system'}
              </button>
            </div>
          </div>
        </div>
      )}
    </section>
  )
}

// Resolution summary -- one of the Gate 2 (close) conditions (Close in the
// header; Resolve only moves it to Post-Incident). Backed by the existing
// LessonsLearned record (incident_narrative / root_cause_description /
// report_security_recommendations) rather than a separate field, so there's one
// narrative, not two. The close gate (`lessons_summary_incomplete`) uses the
// same "what's missing" wording as here.
function ResolutionSection({ incidentId, isClosed }) {
  const [ll,      setLl]      = useState(null)
  const [entities, setEntities] = useState(null)
  const [draft,   setDraft]   = useState(null)
  const [saving,  setSaving]  = useState(false)
  const [savedAt, setSavedAt] = useState(null)
  const [error,   setError]   = useState('')

  useEffect(() => {
    Promise.allSettled([
      api.getLessonsLearned(incidentId),
      api.listEntities(incidentId),
    ]).then(([l, e]) => {
      const rec = l.status === 'fulfilled' ? l.value : {}
      setLl(rec)
      setDraft({
        incident_narrative: rec.incident_narrative ?? '',
        root_cause_description: rec.root_cause_description ?? '',
        report_security_recommendations: rec.report_security_recommendations ?? '',
      })
      setEntities(e.status === 'fulfilled' ? (e.value.items ?? []) : [])
    })
  }, [incidentId])

  if (!draft) return null

  const missing = [
    !draft.incident_narrative.trim() && 'what happened',
    !draft.root_cause_description.trim() && 'root cause',
    !draft.report_security_recommendations.trim() && 'recommendations',
  ].filter(Boolean)

  const save = async () => {
    setSaving(true); setError('')
    try {
      const updated = await api.saveLessonsLearned(incidentId, draft)
      setLl(updated)
      setSavedAt(Date.now())
    } catch (e) {
      setError(e.message || 'Failed to save.')
    } finally {
      setSaving(false)
    }
  }

  const field = (key) => ({
    value: draft[key],
    onChange: (e) => setDraft(prev => ({ ...prev, [key]: e.target.value })),
  })

  return (
    <section className="panel" style={{ marginTop: 'var(--space-4)' }}>
      <div className="panel-toolbar">
        <h2 className="panel-h" style={{ margin: 0 }}>Resolution summary</h2>
        {missing.length > 0 ? (
          <span style={{ color: 'var(--high)', fontSize: 12 }}>
            Required to close — missing: {missing.join(', ')}
          </span>
        ) : (
          <span style={{ color: 'var(--ok)', fontSize: 12 }}>✓ Complete</span>
        )}
      </div>

      {error && (
        <div className="alert error" role="alert" style={{ marginBottom: 'var(--space-3)' }}>
          <span className="alert-icon">!</span><span>{error}</span>
        </div>
      )}

      {entities && entities.length > 0 && (
        <div style={{ marginBottom: 'var(--space-3)' }}>
          <div style={{ color: 'var(--muted)', fontSize: 12, marginBottom: 4 }}>
            Entities tracked on this incident (reference — edit on the Entities tab):
          </div>
          <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
            {entities.map(e => (
              <span key={e.id} className="pill" style={{ fontSize: 11 }}>{e.type}: {e.value}</span>
            ))}
          </div>
        </div>
      )}

      <div className="form">
        <div className="field">
          <label className="field-label">What happened</label>
          <textarea className="input" rows={4} readOnly={isClosed}
            placeholder="Summary of the incident for the record…" {...field('incident_narrative')} />
        </div>
        <div className="field">
          <label className="field-label">Root cause</label>
          <textarea className="input" rows={3} readOnly={isClosed}
            placeholder="What allowed this to happen…" {...field('root_cause_description')} />
        </div>
        <div className="field">
          <label className="field-label">Recommendations</label>
          <textarea className="input" rows={3} readOnly={isClosed}
            placeholder="What should change going forward…" {...field('report_security_recommendations')} />
        </div>
      </div>

      {!isClosed && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', marginTop: 'var(--space-2)' }}>
          <button type="button" className="btn primary" onClick={save} disabled={saving}>
            {saving ? 'Saving…' : 'Save resolution summary'}
          </button>
          {savedAt && <span style={{ color: 'var(--dim)', fontSize: 11 }}>Saved.</span>}
        </div>
      )}
    </section>
  )
}

export default function Details() {
  const { inc, draft, setField, readOnly, isClosed, occurredAt, setOccurredAt, detectedAt, setDetectedAt, containedAt, setContainedAt, eradicatedAt, setEradicatedAt, recoveredAt, setRecoveredAt, triageReason, setTriageReason, applyUpdate, access } = useOutletContext()
  // A change to False / Benign Positive asks for a reason (the API requires one outside
  // Detection & Analysis, since the incident can then be closed without Gate 2).
  const askTriageReason = !readOnly && setTriageReason && draft.triage_state !== inc.triage_state &&
    ['false_positive', 'benign_positive'].includes(draft.triage_state)
  const [preview, setPreview] = useState(false)
  // Team picker: the set_teams capability from GET …/access (admins and the incident's IC / Deputy).
  const canSetTeams = !!access?.capabilities?.includes('set_teams')

  return (
    <>
    {readOnly ? (
    <section className="panel classification-band">
      <h2 className="panel-h">Classification</h2>
      <ClassificationStrip inc={inc} />
    </section>
    ) : (
    <section className="panel classification-band">
      <h2 className="panel-h">Classification</h2>
      <div className="classification-grid">
        <div className="field">
          <label className="field-label" htmlFor="cls-type">Type</label>
          <select id="cls-type" className="select" disabled={readOnly}
                  value={draft.incident_type ?? ''} onChange={setField('incident_type')}>
            <option value="">— unclassified —</option>
            {INCIDENT_TYPE.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
          </select>
        </div>
        <div className="field">
          <label className="field-label" htmlFor="cls-severity">Severity</label>
          <select id="cls-severity" className="select" disabled={readOnly}
                  value={draft.severity} onChange={setField('severity')}>
            {SEVERITY.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
          </select>
        </div>
        <div className="field">
          <label className="field-label" htmlFor="cls-tlp">TLP</label>
          <select id="cls-tlp" className="select" disabled={readOnly}
                  value={draft.tlp} onChange={setField('tlp')}>
            {TLP.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
          </select>
        </div>
        <div className="field">
          <label className="field-label" htmlFor="cls-triage">Triage state</label>
          <select id="cls-triage" className="select" disabled={readOnly}
                  value={draft.triage_state ?? 'suspected'} onChange={setField('triage_state')}>
            {TRIAGE_STATE.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
          </select>
        </div>
        {askTriageReason && (
          <div className="field" style={{ gridColumn: '1 / -1' }}>
            <label className="field-label" htmlFor="cls-triage-reason">Reason for the triage change</label>
            <textarea id="cls-triage-reason" className="input" rows={2} maxLength={2000}
                      value={triageReason} onChange={e => setTriageReason(e.target.value)}
                      placeholder="e.g. Alert fired on the scheduled pen test (ticket SEC-1234)…" />
            <span className="field-hint">
              Required outside Detection &amp; Analysis (at least 10 characters): a false or benign
              positive can be closed without Gate 2. Saved to the audit log and the Timeline.
            </span>
          </div>
        )}
        <div className="field">
          <label className="field-label" htmlFor="cls-detection">Detection method</label>
          <select id="cls-detection" className="select" disabled={readOnly}
                  value={draft.detection_method ?? ''} onChange={setField('detection_method')}>
            <option value="">— unknown —</option>
            {DETECTION_METHOD.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
          </select>
        </div>
        <div className="field">
          <label className="field-label" htmlFor="cls-reporter">Reporter</label>
          <input id="cls-reporter" className="input" value={draft.reporter} onChange={setField('reporter')}
                 readOnly={readOnly} maxLength={128} placeholder="—" />
        </div>
        <div className="field">
          <label className="field-label" htmlFor="cls-occurred">Occurred</label>
          <LocalDateTimePicker id="cls-occurred" value={occurredAt} onChange={setOccurredAt}
                               disabled={readOnly} clearable />
        </div>
        <div className="field">
          <label className="field-label" htmlFor="cls-detected">Detected</label>
          <LocalDateTimePicker id="cls-detected" value={detectedAt} onChange={setDetectedAt}
                               disabled={readOnly} clearable />
        </div>
        {containedAt !== undefined && (
          <div className="field">
            <label className="field-label" htmlFor="cls-contained">Contained</label>
            <LocalDateTimePicker id="cls-contained" value={containedAt} onChange={setContainedAt}
                                 disabled={readOnly} clearable />
          </div>
        )}
        {eradicatedAt !== undefined && (
          <div className="field">
            <label className="field-label" htmlFor="cls-eradicated">Eradicated</label>
            <LocalDateTimePicker id="cls-eradicated" value={eradicatedAt} onChange={setEradicatedAt}
                                 disabled={readOnly} clearable />
          </div>
        )}
        {recoveredAt !== undefined && (
          <div className="field">
            <label className="field-label" htmlFor="cls-recovered">Recovered</label>
            <LocalDateTimePicker id="cls-recovered" value={recoveredAt} onChange={setRecoveredAt}
                                 disabled={readOnly} clearable />
          </div>
        )}
      </div>
    </section>
    )}
    <div className="detail-grid">
      <div className="panel">
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 'var(--space-2)' }}>
          <h2 className="panel-h" style={{ margin: 0 }}>Description</h2>
          {!readOnly && (
            <div className="det-add-tabs" style={{ marginBottom: 0 }}>
              <button type="button"
                className={`btn ghost ${!preview ? 'active' : ''}`}
                style={{ fontSize: 12, padding: '2px 10px' }}
                onClick={() => setPreview(false)}>Write</button>
              <button type="button"
                className={`btn ghost ${preview ? 'active' : ''}`}
                style={{ fontSize: 12, padding: '2px 10px' }}
                onClick={() => setPreview(true)}>Preview</button>
            </div>
          )}
        </div>

        {readOnly || !preview ? (
          readOnly ? (
            draft.description
              ? <div className="md-body"><ReactMarkdown>{draft.description}</ReactMarkdown></div>
              : <div style={{ color: 'var(--dim)', fontStyle: 'italic', fontSize: 13 }}>No description.</div>
          ) : (
            <textarea
              className="input"
              value={draft.description}
              onChange={setField('description')}
              rows={10}
              placeholder="What was observed, when, on which systems — Markdown supported"
              readOnly={readOnly}
            />
          )
        ) : (
          draft.description
            ? <div className="md-body"><ReactMarkdown>{draft.description}</ReactMarkdown></div>
            : <div style={{ color: 'var(--dim)', fontStyle: 'italic', fontSize: 13 }}>Nothing to preview yet.</div>
        )}
      </div>

      <aside style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)', minWidth: 0 }}>

        <section className="panel" style={{ overflow: 'hidden', minWidth: 0 }}>
          <h2 className="panel-h">Snapshot</h2>
          <dl className="kv" style={{ overflow: 'hidden' }}>
            <dt>Created</dt>
            <dd className="ts" style={{ fontFamily: 'var(--font-mono)', fontSize: 12, minWidth: 0, overflow: 'hidden' }}>
              {formatLocal(inc.created_at)}
            </dd>
            <dt>Updated</dt>
            <dd className="ts" style={{ fontFamily: 'var(--font-mono)', fontSize: 12, minWidth: 0, overflow: 'hidden' }}>
              {formatLocal(inc.updated_at)}
            </dd>
            {inc.closed_at && (
              <>
                <dt>Closed</dt>
                <dd className="ts" style={{ fontFamily: 'var(--font-mono)', fontSize: 12, minWidth: 0, overflow: 'hidden' }}>
                  {formatLocal(inc.closed_at)}
                </dd>
              </>
            )}
            {/* Outside edit mode the classification strip replaces the form, so its times are listed here. */}
            {readOnly && [['Occurred', inc.occurred_at], ['Detected', inc.detected_at], ['Contained', inc.contained_at],
                          ['Eradicated', inc.eradicated_at], ['Recovered', inc.recovered_at]].map(([label, at]) => (
              <Fragment key={label}>
                <dt>{label}</dt>
                <dd className={`ts kv-time${at ? '' : ' none'}`}>
                  {at ? formatLocal(at) : '—'}
                </dd>
              </Fragment>
            ))}
            <TagsSection inc={inc} readOnly={readOnly} onUpdated={applyUpdate} />
            {canSetTeams ? (
              <TeamsSection inc={inc} onUpdated={applyUpdate} />
            ) : (inc.teams ?? []).length > 0 && (
              <>
                <dt>Teams</dt>
                <dd style={{ minWidth: 0 }}>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                    {inc.teams.map(t => <TeamChip key={t.id} team={t} />)}
                  </div>
                </dd>
              </>
            )}

          </dl>
        </section>
      </aside>
    </div>
    <AffectedSystemsSection incidentId={inc.id} readOnly={readOnly} />
    <ResolutionSection incidentId={inc.id} isClosed={isClosed} />
    </>
  )
}
