import { useState, useEffect, useCallback } from 'react'
import { useOutletContext, Link } from 'react-router-dom'
import ReactMarkdown from 'react-markdown'
import { formatLocal } from '../../lib/datetime.js'
import { SEVERITY, TLP, TRIAGE_STATE, INCIDENT_TYPE, DETECTION_METHOD, SYSTEM_TYPE, byValue } from '../../lib/incidentVocab.js'
import { useAuth } from '../../hooks/useAuth.jsx'
import { api } from '../../api/client.js'
import TagChip from '../../components/TagChip.jsx'
import TagInput from '../../components/TagInput.jsx'
import UtcDateTimeInput from '../../components/UtcDateTimeInput.jsx'
import StakeholderMatrixBanner from '../../components/StakeholderMatrixBanner.jsx'

function TeamChip({ team }) {
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 4,
      padding: '2px 8px', borderRadius: 'var(--radius-sm)',
      fontSize: 12, fontWeight: 500,
      background: team.color + '22', color: team.color,
      border: `1px solid ${team.color}55`,
    }}>
      <span style={{ width: 7, height: 7, borderRadius: '50%', background: team.color, flexShrink: 0 }} />
      {team.name}
    </span>
  )
}

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
      setError(e.message || 'Save failed.')
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

// ─── Sidebar summary widgets ──────────────────────────────────────────────────

function AssignmentsWidget({ assignments }) {
  if (!assignments || assignments.length === 0) return null
  const shown = assignments.slice(0, 3)
  const rest  = assignments.length - shown.length
  return (
    <>
      <dt>Responders</dt>
      <dd style={{ minWidth: 0 }}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
          {shown.map(a => (
            <div key={a.id} style={{ display: 'flex', alignItems: 'baseline', gap: 6, fontSize: 12 }}>
              <span style={{ fontWeight: 600 }}>{a.username}</span>
              <span style={{ color: 'var(--muted)', fontSize: 11 }}>{a.role_label}</span>
            </div>
          ))}
          {rest > 0 && (
            <span style={{ fontSize: 11, color: 'var(--dim)' }}>+{rest} more</span>
          )}
        </div>
      </dd>
    </>
  )
}

function PlaybookWidget({ tasks }) {
  if (tasks === null) return null
  if (tasks.length === 0) return null
  const done    = tasks.filter(t => t.status === 'done').length
  const skipped = tasks.filter(t => t.status === 'skipped').length
  const total   = tasks.length - skipped
  const pct     = total > 0 ? Math.round((done / total) * 100) : 0
  const color   = pct === 100 ? 'var(--ok)' : pct > 0 ? 'var(--accent)' : 'var(--muted)'
  return (
    <>
      <dt>Playbook</dt>
      <dd style={{ minWidth: 0 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color }}>
            {done} / {total}
          </span>
          <span style={{ fontSize: 11, color: 'var(--muted)' }}>tasks done</span>
        </div>
      </dd>
    </>
  )
}

function LegalWidget({ deadlines }) {
  if (!deadlines) return null
  const active = deadlines.filter(d => d.status !== 'completed' && d.status !== 'waived')
  if (active.length === 0) return null
  const nearest = active.reduce((a, b) => a.hours_remaining < b.hours_remaining ? a : b)
  const h = nearest.hours_remaining
  const overdue  = h < 0
  const urgent   = !overdue && h < 24
  const color    = overdue ? 'var(--crit)' : urgent ? 'var(--high)' : 'var(--ok)'
  const label    = overdue
    ? `${nearest.regulation} · OVERDUE`
    : h < 1
      ? `${nearest.regulation} · <1h`
      : h < 48
        ? `${nearest.regulation} · ${Math.round(h)}h`
        : `${nearest.regulation} · ${Math.round(h / 24)}d`
  return (
    <>
      <dt>Legal</dt>
      <dd style={{ minWidth: 0 }}>
        <span style={{
          display: 'inline-block', fontSize: 11, fontWeight: 600,
          padding: '2px 7px', borderRadius: 'var(--radius-sm)',
          background: `color-mix(in srgb, ${color} 15%, transparent)`,
          color, border: `1px solid color-mix(in srgb, ${color} 40%, transparent)`,
        }}>
          {label}
        </span>
        {active.length > 1 && (
          <span style={{ fontSize: 11, color: 'var(--dim)', marginLeft: 6 }}>
            +{active.length - 1} more
          </span>
        )}
      </dd>
    </>
  )
}

const BLANK_SYSTEM = { name: '', system_type: '', notes: '' }

function AffectedSystemsSection({ incidentId, readOnly }) {
  const [systems, setSystems] = useState(null)
  const [loading, setLoading] = useState(false)
  const [modal, setModal]     = useState(null)  // null | 'add' | {id, name, system_type, notes}
  const [form, setForm]       = useState(BLANK_SYSTEM)
  const [busy, setBusy]       = useState(false)
  const [error, setError]     = useState('')
  const [selected, setSelected] = useState(() => new Set())
  const [promoteResult, setPromoteResult] = useState(null)
  const [promoting, setPromoting] = useState(false)

  const toggleSelected = (id) => setSelected(prev => {
    const next = new Set(prev)
    if (next.has(id)) next.delete(id); else next.add(id)
    return next
  })

  const allSelected = systems && systems.length > 0 && selected.size === systems.length
  const toggleSelectAll = () => {
    if (allSelected) setSelected(new Set())
    else setSelected(new Set((systems || []).map(s => s.id)))
  }

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const r = await api.listAffectedSystems(incidentId)
      setSystems(r.items)
    } catch { setSystems([]) }
    finally { setLoading(false) }
  }, [incidentId])

  useEffect(() => { load() }, [load])

  const openAdd = () => { setForm(BLANK_SYSTEM); setError(''); setModal('add') }
  const openEdit = (s) => { setForm({ name: s.name, system_type: s.system_type ?? '', notes: s.notes ?? '' }); setError(''); setModal(s) }

  const handleSave = async () => {
    if (!form.name.trim()) { setError('Name is required.'); return }
    setBusy(true); setError('')
    try {
      const payload = { name: form.name.trim(), system_type: form.system_type || null, notes: form.notes || null }
      if (modal === 'add') {
        await api.createAffectedSystem(incidentId, payload)
      } else {
        await api.updateAffectedSystem(incidentId, modal.id, payload)
      }
      await load()
      setModal(null)
    } catch (e) {
      setError(e.message || 'Save failed.')
    } finally {
      setBusy(false)
    }
  }

  const handleDelete = async (s) => {
    if (!confirm(`Remove "${s.name}" from affected systems?`)) return
    try {
      await api.deleteAffectedSystem(incidentId, s.id)
      setSystems(prev => prev.filter(x => x.id !== s.id))
      setSelected(prev => {
        const next = new Set(prev); next.delete(s.id); return next
      })
    } catch (e) {
      alert(e.message || 'Delete failed.')
    }
  }

  const handlePromote = async () => {
    const ids = Array.from(selected)
    const scope = ids.length > 0
      ? `${ids.length} selected system${ids.length === 1 ? '' : 's'}`
      : `all ${systems?.length || 0} affected systems`
    if (!confirm(
      `Promote ${scope} to Entities tagged "compromised"?\n\n` +
      `Existing entities for the same name will be marked compromised without duplicates.`
    )) return
    setPromoting(true); setPromoteResult(null)
    try {
      const res = await api.promoteAffectedSystemsToEntities(incidentId, {
        system_ids: ids.length > 0 ? ids : null,
      })
      setPromoteResult(res)
      setSelected(new Set())
    } catch (e) {
      alert(e.message || 'Promote failed.')
    } finally {
      setPromoting(false)
    }
  }

  return (
    <section className="panel" style={{ marginTop: 'var(--space-4)' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 'var(--space-3)', gap: 'var(--space-2)', flexWrap: 'wrap' }}>
        <h2 className="panel-h" style={{ margin: 0 }}>Affected systems</h2>
        {!readOnly && (
          <div style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'center', flexWrap: 'wrap' }}>
            {(systems?.length ?? 0) > 0 && (
              <button
                type="button"
                className="btn ghost"
                style={{ fontSize: 12 }}
                onClick={handlePromote}
                disabled={promoting}
                title={selected.size > 0
                  ? `Promote ${selected.size} selected to Entities (compromised)`
                  : 'Promote all to Entities (compromised)'}
              >
                {promoting
                  ? 'Promoting…'
                  : selected.size > 0
                    ? `⚠ Promote ${selected.size} → Entities`
                    : '⚠ Promote all → Entities'}
              </button>
            )}
            <button type="button" className="btn ghost" style={{ fontSize: 12 }} onClick={openAdd}>
              + Add system
            </button>
          </div>
        )}
      </div>

      {promoteResult && (
        <div className="alert info" role="status" style={{ marginBottom: 'var(--space-3)' }}>
          <span className="alert-icon">i</span>
          <span>
            Promoted {promoteResult.created} new entit{promoteResult.created === 1 ? 'y' : 'ies'}
            {promoteResult.skipped > 0 && `, ${promoteResult.skipped} already existed (marked compromised)`}
            . See Forensic → Entities.
          </span>
        </div>
      )}

      {loading && <div style={{ color: 'var(--muted)', fontSize: 13 }}>Loading…</div>}

      {!loading && systems?.length === 0 && (
        <div style={{ color: 'var(--dim)', fontStyle: 'italic', fontSize: 13 }}>No affected systems recorded.</div>
      )}

      {!loading && systems?.length > 0 && (
        <table className="data-table" style={{ width: '100%' }}>
          <thead>
            <tr>
              {!readOnly && (
                <th style={{ width: 28 }}>
                  <input
                    type="checkbox"
                    checked={allSelected}
                    onChange={toggleSelectAll}
                    aria-label="Select all affected systems"
                  />
                </th>
              )}
              <th>Name</th>
              <th>Type</th>
              <th>Notes</th>
              {!readOnly && <th style={{ width: 80 }} />}
            </tr>
          </thead>
          <tbody>
            {systems.map(s => (
              <tr key={s.id}>
                {!readOnly && (
                  <td style={{ width: 28 }}>
                    <input
                      type="checkbox"
                      checked={selected.has(s.id)}
                      onChange={() => toggleSelected(s.id)}
                      aria-label={`Select ${s.name}`}
                    />
                  </td>
                )}
                <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>{s.name}</td>
                <td>{s.system_type ? byValue.system_type?.[s.system_type]?.label ?? s.system_type : <span style={{ color: 'var(--muted)' }}>—</span>}</td>
                <td style={{ color: s.notes ? 'inherit' : 'var(--muted)', fontSize: 12 }}>{s.notes || '—'}</td>
                {!readOnly && (
                  <td style={{ textAlign: 'right', whiteSpace: 'nowrap' }}>
                    <button type="button" className="btn ghost" style={{ fontSize: 11, padding: '1px 6px' }}
                      onClick={() => openEdit(s)}>Edit</button>
                    {' '}
                    <button type="button" className="btn ghost" style={{ fontSize: 11, padding: '1px 6px', color: 'var(--crit)' }}
                      onClick={() => handleDelete(s)}>Remove</button>
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {modal && (
        <div className="modal-backdrop" onClick={() => setModal(null)}>
          <div className="modal" style={{ maxWidth: 420 }} onClick={e => e.stopPropagation()}>
            <div className="modal-head">
              <span>{modal === 'add' ? 'Add affected system' : 'Edit affected system'}</span>
              <button type="button" className="modal-close" onClick={() => setModal(null)}>×</button>
            </div>
            <div className="modal-body" style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
              <div className="field">
                <label className="field-label" htmlFor="as-name">Name <span style={{ color: 'var(--crit)' }}>*</span></label>
                <input id="as-name" className="input" value={form.name}
                  onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
                  placeholder="hostname, IP, service name…" maxLength={255} autoFocus />
              </div>
              <div className="field">
                <label className="field-label" htmlFor="as-type">System type</label>
                <select id="as-type" className="select" value={form.system_type}
                  onChange={e => setForm(f => ({ ...f, system_type: e.target.value }))}>
                  <option value="">— unclassified —</option>
                  {SYSTEM_TYPE.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
                </select>
              </div>
              <div className="field">
                <label className="field-label" htmlFor="as-notes">Notes</label>
                <textarea id="as-notes" className="input" value={form.notes}
                  onChange={e => setForm(f => ({ ...f, notes: e.target.value }))}
                  rows={3} placeholder="Optional context…" />
              </div>
              {error && (
                <div className="alert error" role="alert">
                  <span className="alert-icon">!</span><span>{error}</span>
                </div>
              )}
            </div>
            <div className="modal-foot">
              <button type="button" className="btn ghost" onClick={() => setModal(null)} disabled={busy}>Cancel</button>
              <button type="button" className="btn primary" onClick={handleSave} disabled={busy}>
                {busy ? 'Saving…' : modal === 'add' ? 'Add system' : 'Save changes'}
              </button>
            </div>
          </div>
        </div>
      )}
    </section>
  )
}

// ─── Snapshot chip strip (at-a-glance counts) ────────────────────────────────

function SnapshotChip({ to, label, value, accent = 'var(--accent)' }) {
  const inner = (
    <>
      <span style={{ fontFamily: 'var(--font-mono)', fontSize: 16, fontWeight: 600, color: accent, lineHeight: 1 }}>
        {value}
      </span>
      <span style={{ fontSize: 11, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: 0.4 }}>
        {label}
      </span>
    </>
  )
  const style = {
    display: 'inline-flex', flexDirection: 'column', alignItems: 'flex-start', gap: 4,
    padding: '8px 14px', borderRadius: 'var(--radius-sm)',
    background: 'var(--surface-2)', border: '1px solid var(--border)',
    textDecoration: 'none', minWidth: 78,
  }
  if (to) return <Link to={to} style={style}>{inner}</Link>
  return <div style={style}>{inner}</div>
}

function SnapshotStrip({ incidentId }) {
  const [snap, setSnap] = useState(null)
  useEffect(() => {
    let cancelled = false
    api.getIncidentSnapshot(incidentId)
      .then(r => { if (!cancelled) setSnap(r) })
      .catch(() => { if (!cancelled) setSnap(null) })
    return () => { cancelled = true }
  }, [incidentId])
  if (!snap) return null
  const pbLabel = snap.playbook_total > 0
    ? `${snap.playbook_done} / ${snap.playbook_total}`
    : '—'
  return (
    <div style={{
      display: 'flex', flexWrap: 'wrap', gap: 'var(--space-2)',
      marginBottom: 'var(--space-4)',
    }}>
      <SnapshotChip to="../forensic/iocs" label="IOCs"     value={snap.iocs} />
      <SnapshotChip to="../entities"      label="Entities" value={snap.entities} />
      <SnapshotChip to="../evidence"      label="Evidence" value={snap.evidence} />
      <SnapshotChip to="../timeline"      label="Timeline" value={snap.timeline} />
      <SnapshotChip to="../playbook"      label="Playbook" value={pbLabel}
        accent={snap.playbook_total > 0 && snap.playbook_done === snap.playbook_total ? 'var(--ok)' : 'var(--accent)'} />
      <SnapshotChip to="../assignments"   label="Responders" value={snap.assignments} />
    </div>
  )
}


export default function Details() {
  const { inc, draft, setField, readOnly, occurredAt, setOccurredAt, containedAt, setContainedAt, refresh } = useOutletContext()
  const { user } = useAuth()
  const [preview, setPreview] = useState(false)
  const isAdmin = user?.role === 'admin'

  const [assignments, setAssignments] = useState(null)
  const [tasks,       setTasks]       = useState(null)
  const [deadlines,   setDeadlines]   = useState(null)

  useEffect(() => {
    Promise.allSettled([
      api.listAssignments(inc.id),
      api.listPlaybookTasks(inc.id),
      api.listDeadlines(inc.id),
    ]).then(([a, p, d]) => {
      setAssignments(a.status === 'fulfilled' ? (a.value.items ?? a.value) : [])
      setTasks(p.status === 'fulfilled' ? p.value : [])
      setDeadlines(d.status === 'fulfilled' ? d.value : [])
    })
  }, [inc.id])

  return (
    <>
    <StakeholderMatrixBanner severity={inc.severity} />
    <SnapshotStrip incidentId={inc.id} />
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
          <h2 className="panel-h">Classification</h2>
          <dl className="kv" style={{ overflow: 'hidden' }}>
            <dt>Type</dt>
            <dd style={{ minWidth: 0 }}>
              <select className="select" disabled={readOnly} style={{ width: '100%' }}
                      value={draft.incident_type ?? ''} onChange={setField('incident_type')}>
                <option value="">— unclassified —</option>
                {INCIDENT_TYPE.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
              </select>
            </dd>
            <dt>Severity</dt>
            <dd style={{ minWidth: 0 }}>
              <select className="select" disabled={readOnly} style={{ width: '100%' }}
                      value={draft.severity} onChange={setField('severity')}>
                {SEVERITY.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
              </select>
            </dd>
            <dt>TLP</dt>
            <dd style={{ minWidth: 0 }}>
              <select className="select" disabled={readOnly} style={{ width: '100%' }}
                      value={draft.tlp} onChange={setField('tlp')}>
                {TLP.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
              </select>
            </dd>
            <dt>Triage state</dt>
            <dd style={{ minWidth: 0 }}>
              <select className="select" disabled={readOnly} style={{ width: '100%' }}
                      value={draft.triage_state ?? 'suspected'} onChange={setField('triage_state')}>
                {TRIAGE_STATE.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
              </select>
            </dd>
            <dt>Detection method</dt>
            <dd style={{ minWidth: 0 }}>
              <select className="select" disabled={readOnly} style={{ width: '100%' }}
                      value={draft.detection_method ?? ''} onChange={setField('detection_method')}>
                <option value="">— unknown —</option>
                {DETECTION_METHOD.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
              </select>
            </dd>
            <dt>Reporter</dt>
            <dd style={{ minWidth: 0 }}>
              <input className="input" value={draft.reporter} onChange={setField('reporter')}
                     readOnly={readOnly} maxLength={128} placeholder="—" style={{ width: '100%', boxSizing: 'border-box' }} />
            </dd>
            <dt>Occurred (UTC)</dt>
            <dd style={{ minWidth: 0, overflow: 'hidden' }}>
              <UtcDateTimeInput
                value={occurredAt}
                onChange={setOccurredAt}
                disabled={readOnly}
                hint={!readOnly}
                style={{ width: '100%', boxSizing: 'border-box', fontSize: 12 }}
              />
            </dd>
            {containedAt !== undefined && (
              <>
                <dt>Contained (UTC)</dt>
                <dd style={{ minWidth: 0, overflow: 'hidden' }}>
                  <UtcDateTimeInput
                    value={containedAt}
                    onChange={setContainedAt}
                    disabled={readOnly}
                    hint={!readOnly}
                    style={{ width: '100%', boxSizing: 'border-box', fontSize: 12 }}
                  />
                </dd>
              </>
            )}
          </dl>
        </section>

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
            <TagsSection inc={inc} readOnly={readOnly} onUpdated={refresh} />
            {isAdmin ? (
              <TeamsSection inc={inc} onUpdated={refresh} />
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

            <AssignmentsWidget assignments={assignments} />
            <PlaybookWidget tasks={tasks} />
            <LegalWidget deadlines={deadlines} />
          </dl>
        </section>
      </aside>
    </div>
    <AffectedSystemsSection incidentId={inc.id} readOnly={readOnly} />
    </>
  )
}
