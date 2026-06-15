import { useCallback, useEffect, useState } from 'react'
import { useOutletContext } from 'react-router-dom'
import { api } from '../../api/client.js'
import { formatLocal } from '../../lib/datetime.js'
import EntityDetailDrawer from './entities/EntityDetailDrawer.jsx'
import EntityGraph from './entities/EntityGraph.jsx'
import ConnectModal from './entities/ConnectModal.jsx'
import BulkImportModal from './entities/BulkImportModal.jsx'

const ENTITY_TYPES = [
  { value: 'host',          label: 'Host'          },
  { value: 'user',          label: 'User'          },
  { value: 'ip',            label: 'IP'            },
  { value: 'domain',        label: 'Domain'        },
  { value: 'email',         label: 'Email'         },
  { value: 'service',       label: 'Service'       },
  { value: 'network_range', label: 'Network range' },
  { value: 'group',         label: 'Group'         },
  { value: 'other',         label: 'Other'         },
]

const CRITICALITY = [
  { value: 'low',      label: 'Low'      },
  { value: 'medium',   label: 'Medium'   },
  { value: 'high',     label: 'High'     },
  { value: 'critical', label: 'Critical' },
]

const TYPE_COLOR = {
  host:          '--entity-host',
  user:          '--entity-user',
  ip:            '--entity-ip',
  domain:        '--entity-domain',
  email:         '--entity-email',
  service:       '--entity-service',
  network_range: '--entity-network',
  group:         '--entity-group',
  other:         '--entity-other',
}

const labelOfType = (v) => ENTITY_TYPES.find(t => t.value === v)?.label || v
const typeColor   = (v) => `var(${TYPE_COLOR[v] || '--muted'})`
const critOf      = (v) => CRITICALITY.find(c => c.value === v) || CRITICALITY[1]

export default function Entities() {
  const { inc } = useOutletContext()
  const isClosed = inc?.status === 'closed'

  const [items, setItems]           = useState([])
  const [relations, setRelations]   = useState([])
  const [loading, setLoading]       = useState(true)
  const [error, setError]           = useState(null)
  const [typeFilter, setTypeFilter] = useState('')
  const [critFilter, setCritFilter] = useState('')
  const [view, setView]             = useState('table')   // 'table' | 'graph'

  // Entity add/edit modal
  const [modal, setModal]           = useState(null)       // null | { mode, entity? }

  // Detail drawer
  const [selectedEntity, setSelectedEntity] = useState(null)

  // Connect modal
  const [connectSource, setConnectSource] = useState(null) // entity to connect from

  // Bulk import modal
  const [showBulkImport, setShowBulkImport] = useState(false)

  const [busy, setBusy]                   = useState(false)
  const [editingNameId, setEditingNameId] = useState(null)
  const [nameDraft, setNameDraft]         = useState('')

  const load = useCallback(async () => {
    setError(null)
    try {
      const params = { limit: 200 }
      if (typeFilter) params.type        = typeFilter
      if (critFilter) params.criticality = critFilter
      const [entRes, relRes] = await Promise.all([
        api.listEntities(inc.id, params),
        api.listEntityRelations(inc.id),
      ])
      setItems(entRes.items)
      setRelations(relRes.items)
      // Sync the detail drawer entity if one is open
      if (selectedEntity) {
        const fresh = entRes.items.find(e => e.id === selectedEntity.id)
        setSelectedEntity(fresh ?? null)
      }
    } catch (e) {
      setError(e.message || 'Could not load entities')
    } finally {
      setLoading(false)
    }
  }, [inc.id, typeFilter, critFilter]) // intentionally excludes selectedEntity to avoid loop

  useEffect(() => { load() }, [load])

  const onDelete = async (ent) => {
    const label = `${labelOfType(ent.type)}: ${ent.value}`
    if (!window.confirm(`Delete entity?\n\n${label}`)) return
    if (!window.confirm(`Confirm permanent deletion of:\n\n${label}\n\nThis cannot be undone.`)) return
    setBusy(true)
    try {
      await api.deleteEntity(inc.id, ent.id)
      if (selectedEntity?.id === ent.id) setSelectedEntity(null)
      await load()
    } catch (e) {
      setError(e.message || 'Could not delete entity')
    } finally {
      setBusy(false)
    }
  }

  const setCriticality = async (ent, value) => {
    if (value === ent.criticality) return
    setBusy(true)
    try {
      await api.updateEntity(inc.id, ent.id, { criticality: value })
      await load()
    } catch (e) {
      setError(e.message || 'Could not update criticality')
    } finally {
      setBusy(false)
    }
  }

  const toggleCompromised = async (ent) => {
    setBusy(true)
    try {
      await api.updateEntity(inc.id, ent.id, { compromised: !ent.compromised })
      await load()
    } catch (e) {
      setError(e.message || 'Could not update compromised status')
    } finally {
      setBusy(false)
    }
  }

  const startNameEdit  = (ent) => { setEditingNameId(ent.id); setNameDraft(ent.name || '') }
  const cancelNameEdit = ()    => { setEditingNameId(null); setNameDraft('') }
  const saveNameEdit   = async (ent) => {
    const next = nameDraft.trim()
    if (next === (ent.name || '')) { cancelNameEdit(); return }
    setBusy(true)
    try {
      await api.updateEntity(inc.id, ent.id, { name: next || null })
      await load()
    } catch (e) {
      setError(e.message || 'Could not update name')
    } finally {
      setBusy(false)
      cancelNameEdit()
    }
  }

  // Drawer callbacks
  const onEntityUpdated = useCallback(async () => {
    await load()
  }, [load])

  const onEntityDeleted = useCallback(async () => {
    setSelectedEntity(null)
    await load()
  }, [load])

  const openConnectModal = useCallback((entity) => {
    setConnectSource(entity)
  }, [])

  return (
    <section className="panel">
      <div className="panel-toolbar" style={{ flexWrap: 'wrap' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)', flexWrap: 'wrap' }}>
          <h2 className="panel-h">Entities</h2>

          {/* View toggle */}
          <div style={{
            display: 'inline-flex', border: '1px solid var(--border)',
            borderRadius: 'var(--radius)', overflow: 'hidden', flexShrink: 0,
          }}>
            <button
              type="button"
              className={`btn ${view === 'table' ? 'primary' : 'ghost'}`}
              style={{ borderRadius: 0, borderRight: '1px solid var(--border)', padding: '4px 12px', fontSize: 12 }}
              onClick={() => setView('table')}
            >
              ≡ Table
            </button>
            <button
              type="button"
              className={`btn ${view === 'graph' ? 'primary' : 'ghost'}`}
              style={{ borderRadius: 0, padding: '4px 12px', fontSize: 12 }}
              onClick={() => setView('graph')}
            >
              ◎ Graph
            </button>
          </div>

          {view === 'table' && (
            <>
              <select className="select" value={typeFilter} onChange={(e) => setTypeFilter(e.target.value)} aria-label="Filter by type">
                <option value="">All types</option>
                {ENTITY_TYPES.map(t => <option key={t.value} value={t.value}>{t.label}</option>)}
              </select>
              <select className="select" value={critFilter} onChange={(e) => setCritFilter(e.target.value)} aria-label="Filter by criticality">
                <option value="">All criticalities</option>
                {CRITICALITY.map(c => <option key={c.value} value={c.value}>{c.label}</option>)}
              </select>
            </>
          )}
        </div>

        <div style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'center' }}>
          {!isClosed && (
            <button
              type="button"
              className="btn ghost"
              onClick={() => setShowBulkImport(true)}
              title="Bulk import from CSV"
            >
              ↑ Import CSV
            </button>
          )}
          <button
            type="button"
            className="btn primary"
            onClick={() => setModal({ mode: 'create' })}
            disabled={isClosed}
            title={isClosed ? 'Closed incidents are read-only' : 'Add entity'}
          >
            + Add entity
          </button>
        </div>
      </div>

      {error && (
        <div className="alert error" role="alert">
          <span className="alert-icon">!</span><span>{error}</span>
        </div>
      )}

      {loading ? (
        <div className="panel-empty"><div>Loading…</div></div>
      ) : view === 'graph' ? (
        <EntityGraph
          entities={items}
          relations={relations}
          selectedEntityId={selectedEntity?.id ?? null}
          onSelectEntity={(ent) => setSelectedEntity(ent)}
        />
      ) : items.length === 0 ? (
        <div className="panel-empty">
          <div className="panel-empty-mark" aria-hidden="true">◇</div>
          <div>No entities yet.</div>
          {!isClosed && <div style={{ color: 'var(--dim)', fontSize: 12 }}>Click "Add entity" to record a host, user, service, …</div>}
        </div>
      ) : (
        <table className="settings-table">
          <thead>
            <tr>
              <th style={{ width: 110 }}>Type</th>
              <th>Value</th>
              <th>Name</th>
              <th style={{ width: 130 }}>Criticality</th>
              <th style={{ width: 120 }}>Compromised</th>
              <th style={{ width: 140 }}>Added</th>
              <th className="actions">Actions</th>
            </tr>
          </thead>
          <tbody>
            {items.map(ent => {
              const isSelected = selectedEntity?.id === ent.id
              return (
                <tr
                  key={ent.id}
                  onClick={() => setSelectedEntity(isSelected ? null : ent)}
                  style={{
                    cursor: 'pointer',
                    background: isSelected ? 'var(--accent-soft)' : undefined,
                  }}
                >
                  <td>
                    <span style={{
                      display: 'inline-flex', alignItems: 'center', gap: 5,
                      fontFamily: 'var(--font-mono)', fontSize: 10, fontWeight: 700,
                      letterSpacing: '0.08em', textTransform: 'uppercase',
                      color: typeColor(ent.type),
                    }}>
                      <span style={{ width: 7, height: 7, borderRadius: '50%', background: typeColor(ent.type), flexShrink: 0 }} />
                      {labelOfType(ent.type)}
                    </span>
                  </td>
                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12, wordBreak: 'break-all' }}>
                    {ent.value}
                  </td>
                  <td>
                    {editingNameId === ent.id ? (
                      <input
                        className="input"
                        autoFocus
                        value={nameDraft}
                        onChange={(e) => setNameDraft(e.target.value)}
                        onBlur={() => saveNameEdit(ent)}
                        onKeyDown={(e) => {
                          if (e.key === 'Enter')  { e.preventDefault(); saveNameEdit(ent) }
                          if (e.key === 'Escape') { e.preventDefault(); cancelNameEdit() }
                        }}
                        maxLength={256}
                        onClick={(e) => e.stopPropagation()}
                      />
                    ) : (
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                        <button
                          type="button"
                          className="btn ghost"
                          onClick={(e) => { e.stopPropagation(); if (!isClosed) startNameEdit(ent) }}
                          disabled={isClosed}
                          title={isClosed ? 'Closed incidents are read-only' : 'Click to edit display name'}
                          style={{
                            padding: '4px 8px', textAlign: 'left',
                            fontFamily: 'var(--font-body)', fontWeight: 400,
                            minHeight: 28, justifyContent: 'flex-start',
                          }}
                        >
                          {ent.name || <span style={{ color: 'var(--dim)' }}>—</span>}
                        </button>
                        {ent.file_count > 0 && (
                          <span style={{
                            fontSize: 9, fontFamily: 'var(--font-mono)', fontWeight: 700,
                            letterSpacing: '0.06em', textTransform: 'uppercase',
                            padding: '1px 5px', borderRadius: 'var(--radius-sm)',
                            background: 'var(--accent-soft)', color: 'var(--accent)',
                            border: '1px solid color-mix(in srgb, var(--accent) 30%, transparent)',
                            whiteSpace: 'nowrap', flexShrink: 0,
                          }}>
                            {ent.file_count} {ent.file_count === 1 ? 'file' : 'files'}
                          </span>
                        )}
                      </div>
                    )}
                  </td>
                  <td onClick={(e) => e.stopPropagation()}>
                    <select
                      className="select"
                      value={ent.criticality}
                      onChange={(e) => setCriticality(ent, e.target.value)}
                      disabled={isClosed || busy}
                      aria-label="Criticality"
                      style={{ padding: '2px 6px', fontSize: 11 }}
                    >
                      {CRITICALITY.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
                    </select>
                  </td>
                  <td onClick={(e) => e.stopPropagation()}>
                    <button
                      type="button"
                      className={`compromised-toggle ${ent.compromised ? 'is-compromised' : 'not-compromised'}`}
                      style={{ padding: '2px 8px', fontSize: 10 }}
                      onClick={() => !isClosed && toggleCompromised(ent)}
                      disabled={isClosed || busy}
                      title={ent.compromised ? 'Clear compromised flag' : 'Mark as compromised'}
                    >
                      {ent.compromised ? '⚠ Compromised' : '○ Clean'}
                    </button>
                  </td>
                  <td title={formatLocal(ent.added_at)} style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--muted)' }}>
                    {formatLocal(ent.added_at).slice(0, 16)}
                  </td>
                  <td className="actions" onClick={(e) => e.stopPropagation()}>
                    <span className="row-actions">
                      <button
                        type="button"
                        className="btn ghost"
                        onClick={() => setModal({ mode: 'edit', entity: ent })}
                        disabled={isClosed || busy}
                      >Edit</button>
                      <button
                        type="button"
                        className="btn ghost"
                        onClick={() => onDelete(ent)}
                        disabled={isClosed || busy}
                      >Delete</button>
                    </span>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      )}

      {/* Entity add/edit modal */}
      {modal && (
        <EntityModal
          mode={modal.mode}
          entity={modal.entity}
          incidentId={inc.id}
          allEntities={items}
          onClose={() => setModal(null)}
          onSaved={() => { setModal(null); load() }}
        />
      )}

      {/* Entity detail drawer */}
      {selectedEntity && (
        <EntityDetailDrawer
          entity={selectedEntity}
          relations={relations}
          allEntities={items}
          incidentId={inc.id}
          isClosed={isClosed}
          onClose={() => setSelectedEntity(null)}
          onEntityUpdated={onEntityUpdated}
          onEntityDeleted={onEntityDeleted}
          onAddConnection={openConnectModal}
        />
      )}

      {/* Connect / add relationship modal */}
      {connectSource && (
        <ConnectModal
          sourceEntity={connectSource}
          allEntities={items}
          incidentId={inc.id}
          onClose={() => setConnectSource(null)}
          onSaved={() => { setConnectSource(null); load() }}
        />
      )}

      {/* Bulk import modal */}
      {showBulkImport && (
        <BulkImportModal
          incidentId={inc.id}
          onClose={() => setShowBulkImport(false)}
          onImported={() => { setShowBulkImport(false); load() }}
        />
      )}
    </section>
  )
}

const STANDARD_REL_TYPES = [
  'communicates with', 'executed on', 'wrote to', 'read from',
  'connected to', 'authenticates as', 'spawned', 'downloaded',
  'uploaded to', 'lateral movement to', 'owns', 'member of',
  'impersonated', 'dropped', 'deleted',
]

function EntityModal({ mode, entity, incidentId, allEntities, onClose, onSaved }) {
  const isEdit  = mode === 'edit'
  const others  = (allEntities || []).filter(e => !isEdit || e.id !== entity?.id)

  const [type,        setType]        = useState(entity?.type        || 'host')
  const [value,       setValue]       = useState(entity?.value       || '')
  const [name,        setName]        = useState(entity?.name        || '')
  const [description, setDescription] = useState(entity?.description || '')
  const [criticality, setCriticality] = useState(entity?.criticality || 'medium')
  const [compromised, setCompromised] = useState(entity?.compromised ?? false)

  // Relationship (create mode only)
  const [addRel,      setAddRel]      = useState(false)
  const [relTarget,   setRelTarget]   = useState(others[0]?.id || '')
  const [relType,     setRelType]     = useState(STANDARD_REL_TYPES[0])
  const [relCustom,   setRelCustom]   = useState('')
  const [relIsCustom, setRelIsCustom] = useState(false)
  const [relReversed, setRelReversed] = useState(false)

  const [busy,  setBusy]  = useState(false)
  const [error, setError] = useState(null)

  useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape' && !busy) onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [busy, onClose])

  const onSubmit = async (e) => {
    e.preventDefault()
    setError(null)
    if (!isEdit && !value.trim()) { setError('Value is required.'); return }
    setBusy(true)
    try {
      if (isEdit) {
        await api.updateEntity(incidentId, entity.id, {
          name:        name.trim()        || null,
          description: description.trim() || null,
          criticality,
          compromised,
        })
      } else {
        const created = await api.createEntity(incidentId, {
          type,
          value:       value.trim(),
          name:        name.trim()        || null,
          description: description.trim() || null,
          criticality,
          compromised,
        })
        if (addRel && relTarget) {
          const finalRelType = relIsCustom ? relCustom.trim() : relType
          if (finalRelType) {
            const fromId = relReversed ? relTarget  : created.id
            const toId   = relReversed ? created.id : relTarget
            await api.createEntityRelation(incidentId, {
              from_entity_id:    fromId,
              to_entity_id:      toId,
              relationship_type: finalRelType,
            })
          }
        }
      }
      onSaved()
    } catch (err) {
      setError(err.message || 'Could not save entity.')
    } finally {
      setBusy(false)
    }
  }

  const newEntityLabel = (name || value || 'new entity').trim() || 'new entity'
  const targetEntity   = others.find(e => e.id === relTarget)
  const targetLabel    = targetEntity ? (targetEntity.name || targetEntity.value) : '?'

  return (
    <div
      className="modal-backdrop"
     
    >
      <div className="modal" role="dialog" aria-labelledby="entity-modal-title" style={{ maxWidth: 540 }}>
        <div className="modal-head">
          <h2 id="entity-modal-title">{isEdit ? 'Edit entity' : 'Add entity'}</h2>
          <button type="button" className="modal-close" onClick={onClose} disabled={busy} aria-label="Close">×</button>
        </div>
        <form onSubmit={onSubmit}>
          <div className="modal-body">
            <div className="form">
              <div className="form-row">
                <div className="field">
                  <label className="field-label" htmlFor="ent-type">Type</label>
                  <select id="ent-type" className="select" value={type}
                          onChange={(e) => setType(e.target.value)} disabled={isEdit}>
                    {ENTITY_TYPES.map(t => <option key={t.value} value={t.value}>{t.label}</option>)}
                  </select>
                </div>
                <div className="field">
                  <label className="field-label" htmlFor="ent-crit">Criticality</label>
                  <select id="ent-crit" className="select" value={criticality}
                          onChange={(e) => setCriticality(e.target.value)}>
                    {CRITICALITY.map(c => <option key={c.value} value={c.value}>{c.label}</option>)}
                  </select>
                </div>
              </div>

              <div className="field">
                <label className="field-label" htmlFor="ent-value">Value (identifier)</label>
                <input
                  id="ent-value" className="input"
                  value={value} onChange={(e) => setValue(e.target.value)}
                  autoFocus={!isEdit} required={!isEdit}
                  disabled={isEdit}
                  maxLength={2048}
                  placeholder="e.g. WIN-FS01, jdoe, 10.0.0.5, evil.example.com"
                  style={{ fontFamily: 'var(--font-mono)' }}
                />
                {isEdit && (
                  <div className="field-hint">Type and value can't be changed. Delete and re-create to alter them.</div>
                )}
              </div>

              <div className="field">
                <label className="field-label" htmlFor="ent-name">Display name (optional)</label>
                <input
                  id="ent-name" className="input"
                  value={name} onChange={(e) => setName(e.target.value)}
                  maxLength={256}
                  placeholder="e.g. Finance file server"
                />
              </div>

              <div className="field">
                <label className="field-label" htmlFor="ent-desc">Description (optional)</label>
                <textarea
                  id="ent-desc" className="input"
                  value={description} onChange={(e) => setDescription(e.target.value)}
                  rows={3} maxLength={4096}
                />
              </div>

              {/* Compromised toggle */}
              <div className="field">
                <button
                  type="button"
                  className={`compromised-toggle ${compromised ? 'is-compromised' : 'not-compromised'}`}
                  onClick={() => setCompromised(c => !c)}
                >
                  {compromised ? '⚠ Mark as compromised — ON' : '○ Mark as compromised — OFF'}
                </button>
              </div>

              {/* Relationship (create mode only, requires at least one other entity) */}
              {!isEdit && others.length > 0 && (
                <div className="field" style={{
                  borderTop: '1px solid var(--border)',
                  paddingTop: 'var(--space-3)',
                  marginTop: 'var(--space-1)',
                }}>
                  <label style={{
                    fontSize: 11, color: 'var(--muted)',
                    cursor: 'pointer',
                    display: 'flex', alignItems: 'center', gap: 8,
                    userSelect: 'none',
                  }}>
                    <input
                      type="checkbox"
                      checked={addRel}
                      onChange={e => setAddRel(e.target.checked)}
                      style={{ cursor: 'pointer' }}
                    />
                    <span className="field-label" style={{ margin: 0 }}>Connect to an existing entity</span>
                  </label>

                  {addRel && (
                    <div className="form" style={{ marginTop: 'var(--space-3)', gap: 'var(--space-3)' }}>
                      <div className="field">
                        <label className="field-label" htmlFor="rel-target">Other entity</label>
                        <select
                          id="rel-target"
                          className="select"
                          value={relTarget}
                          onChange={e => setRelTarget(e.target.value)}
                        >
                          {others.map(e => (
                            <option key={e.id} value={e.id}>
                              {e.type}: {e.name || e.value}
                            </option>
                          ))}
                        </select>
                      </div>

                      <div className="field">
                        <label className="field-label">Direction</label>
                        <div style={{ display: 'flex', gap: 'var(--space-2)' }}>
                          <button type="button"
                            className={`btn ${!relReversed ? 'primary' : 'ghost'}`}
                            style={{ fontSize: 11, padding: '3px 10px' }}
                            onClick={() => setRelReversed(false)}
                          >
                            {newEntityLabel} →
                          </button>
                          <button type="button"
                            className={`btn ${relReversed ? 'primary' : 'ghost'}`}
                            style={{ fontSize: 11, padding: '3px 10px' }}
                            onClick={() => setRelReversed(true)}
                          >
                            ← {newEntityLabel}
                          </button>
                        </div>
                      </div>

                      <div className="field">
                        <label className="field-label" htmlFor="rel-type">Relationship type</label>
                        {!relIsCustom ? (
                          <select id="rel-type" className="select" value={relType}
                                  onChange={e => setRelType(e.target.value)}>
                            {STANDARD_REL_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
                          </select>
                        ) : (
                          <input id="rel-type" className="input" autoFocus
                                 value={relCustom} onChange={e => setRelCustom(e.target.value)}
                                 maxLength={64} placeholder="e.g. pivot host for" />
                        )}
                        <label style={{ fontSize: 11, color: 'var(--muted)', cursor: 'pointer',
                                        display: 'flex', alignItems: 'center', gap: 6, marginTop: 6 }}>
                          <input type="checkbox" checked={relIsCustom}
                                 onChange={e => setRelIsCustom(e.target.checked)}
                                 style={{ cursor: 'pointer' }} />
                          Custom type
                        </label>
                      </div>

                      {/* Preview line */}
                      <div style={{
                        background: 'var(--surface-2)', border: '1px solid var(--border)',
                        borderRadius: 'var(--radius)', padding: '6px 10px',
                        fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--muted)',
                      }}>
                        {relReversed
                          ? <><span style={{ color: 'var(--text)' }}>{targetLabel}</span>{' '}
                              <span style={{ color: 'var(--accent)' }}>[{relIsCustom ? (relCustom || '…') : relType}]</span>
                              {' → '}<span style={{ color: 'var(--text)' }}>{newEntityLabel}</span></>
                          : <><span style={{ color: 'var(--text)' }}>{newEntityLabel}</span>{' '}
                              <span style={{ color: 'var(--accent)' }}>[{relIsCustom ? (relCustom || '…') : relType}]</span>
                              {' → '}<span style={{ color: 'var(--text)' }}>{targetLabel}</span></>
                        }
                      </div>
                    </div>
                  )}
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
            <button type="submit" className="btn primary" disabled={busy}>
              {busy ? 'Saving…' : (isEdit ? 'Save changes' : 'Add entity')}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
