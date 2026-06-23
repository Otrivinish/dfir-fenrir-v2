import { useCallback, useEffect, useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../hooks/useAuth.jsx'
import { api } from '../api/client.js'
import { PHASE } from '../lib/incidentVocab.js'
import { formatLocal } from '../lib/datetime.js'

const ALL_CATS = 'All'

function timeAgo(isoStr) {
  if (!isoStr) return null
  const diff = Math.floor((Date.now() - new Date(isoStr).getTime()) / 1000)
  if (diff < 60)         return `${diff}s ago`
  if (diff < 3600)       return `${Math.floor(diff / 60)}m ago`
  if (diff < 86400)      return `${Math.floor(diff / 3600)}h ago`
  if (diff < 86400 * 7)  return `${Math.floor(diff / 86400)}d ago`
  return formatLocal(isoStr)
}

export default function Playbooks() {
  const { user } = useAuth()
  const isAdmin = user?.role === 'admin'

  const [templates, setTemplates]  = useState([])
  const [loading, setLoading]      = useState(true)
  const [error, setError]          = useState(null)
  const [catFilter, setCatFilter]  = useState(ALL_CATS)
  const [search, setSearch]        = useState('')
  const [modal, setModal]          = useState(null) // null | 'execute' | 'new'
  const [selected, setSelected]    = useState(null) // template for execute
  const [previewTpl, setPreviewTpl] = useState(null) // template for read-only step preview

  const load = useCallback(async () => {
    setError(null)
    try {
      const data = await api.listPlaybookTemplates()
      setTemplates(data)
    } catch (e) {
      setError(e.message || 'Could not load playbooks')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  const categories = useMemo(() => {
    const cats = new Set(templates.map(t => t.category).filter(Boolean))
    return [ALL_CATS, ...Array.from(cats).sort()]
  }, [templates])

  const visible = useMemo(() => {
    const q = search.trim().toLowerCase()
    return templates
      .filter(t => catFilter === ALL_CATS || t.category === catFilter)
      .filter(t => !q || t.name.toLowerCase().includes(q) || (t.description || '').toLowerCase().includes(q))
  }, [templates, catFilter, search])

  const onExecute = (tpl) => { setSelected(tpl); setModal('execute') }

  const onCreated = (tpl) => {
    setTemplates(prev => [tpl, ...prev])
    setModal(null)
  }

  const onDeleted = async (tpl) => {
    if (!window.confirm(`Delete "${tpl.name}"? This cannot be undone.`)) return
    try {
      await api.deletePlaybookTemplate(tpl.id)
      setTemplates(prev => prev.filter(t => t.id !== tpl.id))
    } catch (e) {
      alert(e.message || 'Could not delete template')
    }
  }

  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="page-title">Playbooks</h1>
          <div className="page-sub">Response template library · execute into any active incident</div>
        </div>
        <button className="btn primary" type="button" onClick={() => setModal('new')}>
          + New template
        </button>
      </div>

      {error && (
        <div className="alert error" role="alert" style={{ marginBottom: 'var(--space-4)' }}>
          <span className="alert-icon">!</span><span>{error}</span>
        </div>
      )}

      <div style={{ display: 'flex', gap: 'var(--space-2)', marginBottom: 'var(--space-3)', alignItems: 'center' }}>
        <input
          className="input"
          type="search"
          placeholder="Search playbooks…"
          value={search}
          onChange={e => setSearch(e.target.value)}
          style={{ maxWidth: 280 }}
          aria-label="Search playbooks"
        />
      </div>

      <div className="pb-filter-bar" role="toolbar" aria-label="Filter by category">
        {categories.map(cat => (
          <button
            key={cat}
            type="button"
            className={`chip ${catFilter === cat ? 'on' : ''}`}
            onClick={() => setCatFilter(cat)}
          >{cat}</button>
        ))}
      </div>

      {loading ? (
        <div className="panel-empty"><div>Loading playbooks…</div></div>
      ) : (
        <div className="pb-grid">
          {visible.length === 0 && (
            <div className="pb-empty">
              <div className="panel-empty-mark" aria-hidden="true">▤</div>
              <div>No playbooks match this filter.</div>
            </div>
          )}
          {visible.map(tpl => (
            <PlaybookCard
              key={tpl.id}
              tpl={tpl}
              isAdmin={isAdmin}
              onOpen={setPreviewTpl}
              onExecute={onExecute}
              onDelete={onDeleted}
            />
          ))}
        </div>
      )}

      {previewTpl && (
        <PreviewModal
          tpl={previewTpl}
          onClose={() => setPreviewTpl(null)}
          onExecute={(t) => { setPreviewTpl(null); onExecute(t) }}
        />
      )}

      {modal === 'execute' && selected && (
        <ExecuteModal
          tpl={selected}
          onClose={() => { setModal(null); setSelected(null) }}
        />
      )}

      {modal === 'new' && (
        <NewTemplateModal
          onClose={() => setModal(null)}
          onCreated={onCreated}
        />
      )}
    </>
  )
}

// ── Playbook card ─────────────────────────────────────────────────────────────

function PlaybookCard({ tpl, isAdmin, onOpen, onExecute, onDelete }) {
  const shortId = tpl.key.toUpperCase().replace(/_/g, '-').slice(0, 16)
  // Click anywhere on the card (except the action buttons) opens the step preview.
  const open = (e) => { if (e.target.closest('button')) return; onOpen(tpl) }
  return (
    <article
      className="pb-card"
      role="button"
      tabIndex={0}
      onClick={open}
      onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onOpen(tpl) } }}
      style={{ cursor: 'pointer' }}
      title="Open to view steps"
    >
      <div className="pb-card-head">
        <div>
          <div className="pb-card-id">{shortId}</div>
          <div className="pb-card-name">{tpl.name}</div>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 4 }}>
          {tpl.category && <span className="pb-cat">{tpl.category}</span>}
          {tpl.is_system && <span className="pb-system-badge">system</span>}
        </div>
      </div>

      {tpl.description && (
        <p className="pb-card-desc">{tpl.description}</p>
      )}

      <div className="pb-card-foot">
        <span className="pb-step-count">
          <span className="pb-step-icon" aria-hidden="true">▤</span>
          {tpl.task_count} {tpl.task_count === 1 ? 'step' : 'steps'}
        </span>
        <span className="pb-run-meta">
          {tpl.run_count > 0
            ? `${tpl.run_count} run${tpl.run_count !== 1 ? 's' : ''} · last ${timeAgo(tpl.last_run_at)}`
            : 'Not yet executed'}
        </span>
      </div>

      <div className="pb-card-actions">
        <button
          type="button"
          className="btn ghost"
          onClick={() => onOpen(tpl)}
          title="View steps"
        >
          View steps
        </button>
        <button
          type="button"
          className="btn primary"
          style={{ flex: 1 }}
          onClick={() => onExecute(tpl)}
        >
          ▶ Execute
        </button>
        {!tpl.is_system && isAdmin && (
          <button
            type="button"
            className="btn ghost"
            onClick={() => onDelete(tpl)}
            style={{ padding: '0 12px' }}
            title="Delete template"
          >
            ×
          </button>
        )}
      </div>
    </article>
  )
}

// ── Preview modal — read-only view of a playbook's steps ──────────────────────

function PreviewModal({ tpl, onClose, onExecute }) {
  const [full, setFull]       = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError]     = useState(null)

  useEffect(() => {
    let cancelled = false
    api.getPlaybookTemplate(tpl.id)
      .then(d => { if (!cancelled) setFull(d) })
      .catch(e => { if (!cancelled) setError(e.message || 'Could not load playbook steps') })
      .finally(() => { if (!cancelled) setLoading(false) })
    return () => { cancelled = true }
  }, [tpl.id])

  useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  const steps = [...(full?.tasks || [])].sort((a, b) => a.order - b.order)
  const phaseLabel = (v) => PHASE.find(p => p.value === v)?.label || v

  return (
    <div className="modal-backdrop">
      <div className="modal" style={{ maxWidth: 640 }} role="dialog" aria-labelledby="pb-preview-title">
        <div className="modal-head">
          <h2 id="pb-preview-title">{tpl.name}</h2>
          <button type="button" className="modal-close" onClick={onClose} aria-label="Close">×</button>
        </div>
        <div className="modal-body">
          <div style={{
            padding: 'var(--space-3)',
            background: 'var(--surface-2)',
            border: '1px solid var(--border)',
            borderRadius: 'var(--radius)',
            marginBottom: 'var(--space-3)',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', flexWrap: 'wrap' }}>
              <span className="pb-card-id">{tpl.key.toUpperCase().replace(/_/g, '-').slice(0, 16)}</span>
              {tpl.category && <span className="pb-cat">{tpl.category}</span>}
              {tpl.is_system && <span className="pb-system-badge">system</span>}
            </div>
            {tpl.description && (
              <p style={{ fontSize: 13, color: 'var(--muted)', marginTop: 'var(--space-2)', lineHeight: 1.5 }}>
                {tpl.description}
              </p>
            )}
          </div>

          <div className="field-label" style={{ marginBottom: 'var(--space-2)' }}>
            Steps{!loading && !error ? ` (${steps.length})` : ''}
          </div>

          {loading ? (
            <div style={{ color: 'var(--muted)', fontSize: 13 }}>Loading steps…</div>
          ) : error ? (
            <div className="alert error" role="alert">
              <span className="alert-icon">!</span><span>{error}</span>
            </div>
          ) : steps.length === 0 ? (
            <div style={{ color: 'var(--muted)', fontSize: 13 }}>This playbook has no steps.</div>
          ) : (
            <ol style={{ listStyle: 'none', margin: 0, padding: 0, display: 'flex', flexDirection: 'column', gap: 'var(--space-2)' }}>
              {steps.map((s, i) => (
                <li key={i} style={{
                  background: 'var(--surface-2)',
                  border: '1px solid var(--border)',
                  borderRadius: 'var(--radius)',
                  padding: 'var(--space-2) var(--space-3)',
                }}>
                  <div style={{ display: 'flex', alignItems: 'baseline', gap: 'var(--space-2)' }}>
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--dim)', flexShrink: 0 }}>
                      {i + 1}.
                    </span>
                    <span style={{ fontWeight: 600, fontSize: 13, color: 'var(--text)', flex: 1, wordBreak: 'break-word' }}>
                      {s.title}
                    </span>
                    <span className="pill" style={{ fontSize: 10, flexShrink: 0 }}>{phaseLabel(s.phase)}</span>
                  </div>
                  {s.description && (
                    <div style={{ fontSize: 12, color: 'var(--muted)', marginTop: 4, marginLeft: 22, lineHeight: 1.5, whiteSpace: 'pre-wrap' }}>
                      {s.description}
                    </div>
                  )}
                </li>
              ))}
            </ol>
          )}
        </div>
        <div className="modal-foot">
          <button type="button" className="btn ghost" onClick={onClose}>Close</button>
          <button type="button" className="btn primary" onClick={() => onExecute(tpl)}>▶ Execute</button>
        </div>
      </div>
    </div>
  )
}

// ── Execute modal — pick an active incident ───────────────────────────────────

function ExecuteModal({ tpl, onClose }) {
  const navigate = useNavigate()
  const [incidents,   setIncidents]   = useState([])
  const [incidentId,  setIncidentId]  = useState('')
  const [existingCount, setExistingCount] = useState(0)
  const [confirmed,   setConfirmed]   = useState(false)
  const [loading,     setLoading]     = useState(true)
  const [taskLoading, setTaskLoading] = useState(false)
  const [busy, setBusy]               = useState(false)
  const [error, setError]             = useState(null)

  // Load active (non-closed) incidents only
  useEffect(() => {
    let cancelled = false
    api.listIncidents({ status: 'open', limit: 100 })
      .then(r => {
        if (!cancelled) {
          setIncidents(r.items)
          setIncidentId(r.items[0]?.id || '')
        }
      })
      .catch(e => { if (!cancelled) setError(e.message) })
      .finally(() => { if (!cancelled) setLoading(false) })
    return () => { cancelled = true }
  }, [])

  // When incident selection changes, check if it already has tasks
  useEffect(() => {
    if (!incidentId) { setExistingCount(0); return }
    let cancelled = false
    setTaskLoading(true)
    setConfirmed(false)
    api.listPlaybookTasks(incidentId)
      .then(tasks => { if (!cancelled) setExistingCount(tasks.length) })
      .catch(() => { if (!cancelled) setExistingCount(0) })
      .finally(() => { if (!cancelled) setTaskLoading(false) })
    return () => { cancelled = true }
  }, [incidentId])

  useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape' && !busy) onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [busy, onClose])

  const hasExisting = existingCount > 0

  const onSubmit = async (e) => {
    e.preventDefault()
    if (!incidentId) { setError('Select an incident.'); return }
    if (hasExisting && !confirmed) { setError('Confirm that the existing playbook will be replaced.'); return }
    setBusy(true); setError(null)
    try {
      await api.instantiatePlaybook(incidentId, { template_id: tpl.id, replace: true })
      onClose()
      navigate(`/incidents/${incidentId}/playbook`)
    } catch (e2) {
      setError(e2.message || 'Could not apply playbook')
      setBusy(false)
    }
  }

  return (
    <div className="modal-backdrop">
      <div className="modal" role="dialog" aria-labelledby="exec-modal-title">
        <div className="modal-head">
          <h2 id="exec-modal-title">Execute playbook</h2>
          <button type="button" className="modal-close" onClick={onClose} disabled={busy}>×</button>
        </div>
        <form onSubmit={onSubmit}>
          <div className="modal-body">
            <div className="form">
              <div style={{
                padding: 'var(--space-3)',
                background: 'var(--surface-2)',
                border: '1px solid var(--border)',
                borderRadius: 'var(--radius)',
                marginBottom: 'var(--space-3)',
              }}>
                <div className="pb-card-id">{tpl.key.toUpperCase().replace(/_/g, '-').slice(0, 16)}</div>
                <div style={{ fontWeight: 600, marginTop: 2 }}>{tpl.name}</div>
                {tpl.category && (
                  <div style={{ marginTop: 4 }}>
                    <span className="pb-cat">{tpl.category}</span>
                  </div>
                )}
              </div>

              <div className="field">
                <label className="field-label" htmlFor="exec-incident">Apply to incident</label>
                {loading ? (
                  <div style={{ color: 'var(--muted)', fontSize: 13 }}>Loading incidents…</div>
                ) : incidents.length === 0 ? (
                  <div style={{ color: 'var(--muted)', fontSize: 13 }}>No active incidents found.</div>
                ) : (
                  <select
                    id="exec-incident"
                    className="select"
                    value={incidentId}
                    onChange={(e) => setIncidentId(e.target.value)}
                    autoFocus
                  >
                    {incidents.map(inc => (
                      <option key={inc.id} value={inc.id}>{inc.title}</option>
                    ))}
                  </select>
                )}
                <div className="field-hint">Only active (non-closed) incidents are shown.</div>
              </div>

              {!taskLoading && hasExisting && (
                <div style={{
                  padding: 'var(--space-3)',
                  background: 'color-mix(in srgb, var(--high) 12%, transparent)',
                  border: '1px solid var(--high)',
                  borderRadius: 'var(--radius)',
                }}>
                  <div style={{ fontWeight: 600, fontSize: 13, color: 'var(--high)', marginBottom: 'var(--space-1)' }}>
                    This incident already has a playbook
                  </div>
                  <div style={{ fontSize: 12, color: 'var(--text)', marginBottom: 'var(--space-2)', lineHeight: 1.5 }}>
                    The {existingCount} existing task{existingCount !== 1 ? 's' : ''} — including any completed or in-progress work — will be permanently deleted and replaced.
                  </div>
                  <label style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', cursor: 'pointer', fontSize: 13 }}>
                    <input
                      type="checkbox"
                      checked={confirmed}
                      onChange={(e) => setConfirmed(e.target.checked)}
                    />
                    I understand all saved progress will be lost
                  </label>
                </div>
              )}

              {error && (
                <div className="alert error" role="alert">
                  <span className="alert-icon">!</span><span>{error}</span>
                </div>
              )}
            </div>
          </div>
          <div className="modal-foot">
            <button type="button" className="btn ghost" onClick={onClose} disabled={busy}>Cancel</button>
            <button
              type="submit"
              className="btn primary"
              disabled={busy || loading || taskLoading || incidents.length === 0 || (hasExisting && !confirmed)}
            >
              {busy ? 'Applying…' : 'Apply & open'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ── New template modal ────────────────────────────────────────────────────────

const CATEGORIES = [
  'Malware', 'Identity', 'Email', 'Data Loss', 'Insider',
  'Network', 'Vulnerability', 'IR Framework', 'Federal IR', 'Cloud', 'Other',
]

function NewTemplateModal({ onClose, onCreated }) {
  const [name, setName]         = useState('')
  const [category, setCategory] = useState('')
  const [description, setDesc]  = useState('')
  const [steps, setSteps]       = useState([
    { title: '', description: '', phase: 'detection_and_analysis', order: 10 },
  ])
  const [busy, setBusy]         = useState(false)
  const [error, setError]       = useState(null)

  useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape' && !busy) onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [busy, onClose])

  const addStep = () => {
    setSteps(prev => [
      ...prev,
      { title: '', description: '', phase: 'detection_and_analysis', order: (prev.length + 1) * 10 },
    ])
  }

  const updateStep = (idx, field, val) => {
    setSteps(prev => prev.map((s, i) => i === idx ? { ...s, [field]: val } : s))
  }

  const removeStep = (idx) => {
    setSteps(prev => prev.filter((_, i) => i !== idx))
  }

  const onSubmit = async (e) => {
    e.preventDefault()
    setError(null)
    if (!name.trim()) { setError('Name is required.'); return }
    const validSteps = steps.filter(s => s.title.trim())
    if (validSteps.length === 0) { setError('Add at least one step with a title.'); return }
    setBusy(true)
    try {
      const tpl = await api.createPlaybookTemplate({
        name: name.trim(),
        description: description.trim() || null,
        category: category || null,
        tasks: validSteps.map((s, i) => ({
          title: s.title.trim(),
          description: s.description.trim() || null,
          phase: s.phase,
          order: (i + 1) * 10,
        })),
      })
      onCreated(tpl)
    } catch (e2) {
      setError(e2.message || 'Could not create template')
      setBusy(false)
    }
  }

  return (
    <div className="modal-backdrop">
      <div className="modal" style={{ maxWidth: 640 }} role="dialog" aria-labelledby="new-tpl-title">
        <div className="modal-head">
          <h2 id="new-tpl-title">New playbook template</h2>
          <button type="button" className="modal-close" onClick={onClose} disabled={busy}>×</button>
        </div>
        <form onSubmit={onSubmit}>
          <div className="modal-body">
            <div className="form">
              <div style={{ display: 'grid', gridTemplateColumns: '1fr auto', gap: 'var(--space-2)' }}>
                <div className="field">
                  <label className="field-label" htmlFor="tpl-name">Name</label>
                  <input id="tpl-name" className="input" value={name}
                         onChange={(e) => setName(e.target.value)}
                         placeholder="Ransomware Containment" autoFocus required maxLength={256} />
                </div>
                <div className="field">
                  <label className="field-label" htmlFor="tpl-cat">Category</label>
                  <select id="tpl-cat" className="select" value={category}
                          onChange={(e) => setCategory(e.target.value)}
                          style={{ minWidth: 140 }}>
                    <option value="">— none —</option>
                    {CATEGORIES.map(c => <option key={c} value={c}>{c}</option>)}
                  </select>
                </div>
              </div>

              <div className="field">
                <label className="field-label" htmlFor="tpl-desc">Description (optional)</label>
                <textarea id="tpl-desc" className="input" value={description}
                          onChange={(e) => setDesc(e.target.value)}
                          rows={2} maxLength={4096} placeholder="One-line summary of when to use this playbook." />
              </div>

              <div className="field">
                <label className="field-label">Steps</label>
                <div className="pb-step-list">
                  {steps.map((step, idx) => (
                    <StepRow
                      key={idx}
                      step={step}
                      idx={idx}
                      total={steps.length}
                      onChange={(field, val) => updateStep(idx, field, val)}
                      onRemove={() => removeStep(idx)}
                      disabled={busy}
                    />
                  ))}
                </div>
                <div className="pb-add-step">
                  <button type="button" className="btn" onClick={addStep} disabled={busy}>
                    + Add step
                  </button>
                </div>
              </div>

              {error && (
                <div className="alert error" role="alert">
                  <span className="alert-icon">!</span><span>{error}</span>
                </div>
              )}
            </div>
          </div>
          <div className="modal-foot">
            <button type="button" className="btn ghost" onClick={onClose} disabled={busy}>Cancel</button>
            <button type="submit" className="btn primary" disabled={busy}>
              {busy ? 'Creating…' : 'Create template'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

function StepRow({ step, idx, total, onChange, onRemove, disabled }) {
  return (
    <div style={{
      background: 'var(--surface-2)',
      border: '1px solid var(--border)',
      borderRadius: 'var(--radius)',
      padding: 'var(--space-2) var(--space-3)',
      display: 'flex',
      flexDirection: 'column',
      gap: 'var(--space-2)',
    }}>
      <div style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'center' }}>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--dim)', flexShrink: 0, width: 20 }}>
          {idx + 1}.
        </span>
        <input
          className="input"
          style={{ flex: 1, padding: '5px 8px', fontSize: 13 }}
          placeholder="Step title"
          value={step.title}
          onChange={(e) => onChange('title', e.target.value)}
          disabled={disabled}
          maxLength={512}
        />
        <select
          className="select"
          style={{ padding: '5px 8px', fontSize: 11, minWidth: 160 }}
          value={step.phase}
          onChange={(e) => onChange('phase', e.target.value)}
          disabled={disabled}
        >
          {PHASE.map(p => <option key={p.value} value={p.value}>{p.label}</option>)}
        </select>
        <button
          type="button"
          className="pb-step-del"
          onClick={onRemove}
          disabled={disabled || total <= 1}
          title="Remove step"
        >×</button>
      </div>
      <textarea
        className="input"
        style={{ fontSize: 12, padding: '4px 8px', marginLeft: 28, resize: 'none', rows: 1 }}
        rows={1}
        placeholder="Optional description"
        value={step.description}
        onChange={(e) => onChange('description', e.target.value)}
        disabled={disabled}
        maxLength={4096}
      />
    </div>
  )
}
