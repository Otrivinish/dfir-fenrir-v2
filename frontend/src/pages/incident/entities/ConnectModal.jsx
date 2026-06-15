import { useEffect, useState } from 'react'
import { api } from '../../../api/client.js'

const ENTITY_TYPES = [
  { value: 'host',          label: 'Host'          },
  { value: 'user',          label: 'User'          },
  { value: 'ip',            label: 'IP'            },
  { value: 'domain',        label: 'Domain'        },
  { value: 'email',         label: 'Email'         },
  { value: 'service',       label: 'Service'       },
  { value: 'network_range', label: 'Network Range' },
  { value: 'group',         label: 'Group'         },
  { value: 'other',         label: 'Other'         },
]

const STANDARD_RELATION_TYPES = [
  'communicates with',
  'executed on',
  'wrote to',
  'read from',
  'connected to',
  'authenticates as',
  'spawned',
  'downloaded',
  'uploaded to',
  'lateral movement to',
  'owns',
  'member of',
  'impersonated',
  'dropped',
  'deleted',
]

const labelOfType = (v) => ENTITY_TYPES.find(t => t.value === v)?.label || v
const entityLabel = (e) => {
  const name = e.name ? ` — ${e.name}` : ''
  return `${labelOfType(e.type)}: ${e.value}${name}`
}

export default function ConnectModal({
  sourceEntity,   // EntityOut — opened from this entity
  allEntities,    // EntityOut[] — all entities for this incident
  incidentId,
  onClose,
  onSaved,
}) {
  const others = allEntities.filter((e) => e.id !== sourceEntity.id)

  const [otherId, setOtherId]       = useState(others[0]?.id || '')
  const [reversed, setReversed]     = useState(false)  // false = source→other, true = other→source
  const [relType, setRelType]       = useState(STANDARD_RELATION_TYPES[0])
  const [customType, setCustomType] = useState('')
  const [isCustom, setIsCustom]     = useState(false)
  const [notes, setNotes]           = useState('')
  const [busy, setBusy]             = useState(false)
  const [error, setError]           = useState(null)

  useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape' && !busy) onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [busy, onClose])

  const fromId = reversed ? otherId  : sourceEntity.id
  const toId   = reversed ? sourceEntity.id : otherId

  const fromEntity = allEntities.find((e) => e.id === fromId)
  const toEntity   = allEntities.find((e) => e.id === toId)
  const displayType = isCustom ? (customType || '…') : relType
  const sourceName  = sourceEntity.name || sourceEntity.value

  const onSubmit = async (evt) => {
    evt.preventDefault()
    setError(null)
    const finalType = isCustom ? customType.trim() : relType
    if (!finalType) { setError('Relationship type is required.'); return }
    if (!otherId)   { setError('Select a target entity.'); return }

    setBusy(true)
    try {
      await api.createEntityRelation(incidentId, {
        from_entity_id:    fromId,
        to_entity_id:      toId,
        relationship_type: finalType,
        notes:             notes.trim() || null,
      })
      onSaved()
    } catch (e) {
      setError(e.message || 'Could not create relationship.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div
      className="modal-backdrop"
     
    >
      <div className="modal" role="dialog" aria-labelledby="connect-modal-title">
        <div className="modal-head">
          <h2 id="connect-modal-title">Add connection</h2>
          <button type="button" className="modal-close" onClick={onClose} disabled={busy} aria-label="Close">×</button>
        </div>
        <form onSubmit={onSubmit}>
          <div className="modal-body">
            <div className="form">
              {/* Other entity */}
              <div className="field">
                <label className="field-label" htmlFor="conn-target">Other entity</label>
                {others.length === 0 ? (
                  <div style={{ color: 'var(--muted)', fontSize: 12 }}>
                    No other entities on this incident yet.
                  </div>
                ) : (
                  <select
                    id="conn-target"
                    className="select"
                    value={otherId}
                    onChange={(e) => setOtherId(e.target.value)}
                    required
                  >
                    {others.map(e => (
                      <option key={e.id} value={e.id}>{entityLabel(e)}</option>
                    ))}
                  </select>
                )}
              </div>

              {/* Direction */}
              <div className="field">
                <label className="field-label">Direction</label>
                <div style={{ display: 'flex', gap: 'var(--space-2)' }}>
                  <button
                    type="button"
                    className={`btn ${!reversed ? 'primary' : 'ghost'}`}
                    style={{ fontSize: 12, padding: '4px 10px' }}
                    onClick={() => setReversed(false)}
                  >
                    {sourceName} → other
                  </button>
                  <button
                    type="button"
                    className={`btn ${reversed ? 'primary' : 'ghost'}`}
                    style={{ fontSize: 12, padding: '4px 10px' }}
                    onClick={() => setReversed(true)}
                  >
                    other → {sourceName}
                  </button>
                </div>
              </div>

              {/* Relationship type */}
              <div className="field">
                <label className="field-label" htmlFor="conn-rel-type">Relationship type</label>
                <div style={{ display: 'flex', gap: 'var(--space-2)', flexDirection: 'column' }}>
                  {!isCustom ? (
                    <select
                      id="conn-rel-type"
                      className="select"
                      value={relType}
                      onChange={(e) => setRelType(e.target.value)}
                    >
                      {STANDARD_RELATION_TYPES.map(t => (
                        <option key={t} value={t}>{t}</option>
                      ))}
                    </select>
                  ) : (
                    <input
                      id="conn-rel-type"
                      className="input"
                      autoFocus
                      value={customType}
                      onChange={(e) => setCustomType(e.target.value)}
                      maxLength={64}
                      placeholder="e.g. pivot host for"
                    />
                  )}
                  <label style={{ fontSize: 11, color: 'var(--muted)', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 6 }}>
                    <input
                      type="checkbox"
                      checked={isCustom}
                      onChange={(e) => setIsCustom(e.target.checked)}
                      style={{ cursor: 'pointer' }}
                    />
                    Custom relationship type
                  </label>
                </div>
              </div>

              {/* Notes */}
              <div className="field">
                <label className="field-label" htmlFor="conn-notes">Notes (optional)</label>
                <textarea
                  id="conn-notes"
                  className="input"
                  value={notes}
                  onChange={(e) => setNotes(e.target.value)}
                  rows={2}
                  maxLength={1024}
                  placeholder="Additional context…"
                />
              </div>

              {/* Preview */}
              {fromEntity && toEntity && (
                <div style={{
                  background: 'var(--surface-2)',
                  border: '1px solid var(--border)',
                  borderRadius: 'var(--radius)',
                  padding: '8px 12px',
                  fontFamily: 'var(--font-mono)',
                  fontSize: 11,
                  color: 'var(--muted)',
                  lineHeight: 1.6,
                }}>
                  <span style={{ color: 'var(--text)' }}>{fromEntity.name || fromEntity.value}</span>
                  {' '}
                  <span style={{ color: 'var(--accent)' }}>[{displayType}]</span>
                  {' → '}
                  <span style={{ color: 'var(--text)' }}>{toEntity.name || toEntity.value}</span>
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
            <button type="submit" className="btn primary" disabled={busy || others.length === 0}>
              {busy ? 'Saving…' : 'Add connection'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
