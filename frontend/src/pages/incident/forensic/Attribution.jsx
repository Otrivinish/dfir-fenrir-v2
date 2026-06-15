import { useState, useEffect, useCallback } from 'react'
import { useOutletContext } from 'react-router-dom'
import { api } from '../../../api/client.js'

// ─── Helpers ──────────────────────────────────────────────────────────────────

const CONFIDENCE_META = {
  possible:  { label: 'Possible',  color: 'var(--med)',  order: 0 },
  probable:  { label: 'Probable',  color: 'var(--high)', order: 1 },
  confirmed: { label: 'Confirmed', color: 'var(--crit)', order: 2 },
}

const MOTIVATION_META = {
  espionage:   { label: 'Espionage',   color: 'var(--accent)' },
  financial:   { label: 'Financial',   color: 'var(--high)'   },
  ransomware:  { label: 'Ransomware',  color: 'var(--crit)'   },
  destructive: { label: 'Destructive', color: 'var(--crit)'   },
  hacktivist:  { label: 'Hacktivist',  color: 'var(--med)'    },
  unknown:     { label: 'Unknown',     color: 'var(--muted)'  },
}

function confidencePill(confidence) {
  const m = CONFIDENCE_META[confidence] || CONFIDENCE_META.possible
  return (
    <span style={{
      fontSize: 10, fontWeight: 700, letterSpacing: '0.06em', textTransform: 'uppercase',
      padding: '2px 7px', borderRadius: 'var(--radius-sm)',
      color: m.color,
      background: `color-mix(in srgb, ${m.color} 14%, transparent)`,
      border: `1px solid color-mix(in srgb, ${m.color} 30%, transparent)`,
    }}>{m.label}</span>
  )
}

function motivationPill(motivation) {
  const m = MOTIVATION_META[motivation] || MOTIVATION_META.unknown
  return (
    <span style={{
      fontSize: 10, padding: '1px 6px', borderRadius: 'var(--radius-sm)',
      color: m.color,
      background: `color-mix(in srgb, ${m.color} 10%, transparent)`,
      border: `1px solid color-mix(in srgb, ${m.color} 20%, transparent)`,
    }}>{m.label}</span>
  )
}

function OverlapBar({ pct, count, total }) {
  const color = pct >= 60 ? 'var(--crit)' : pct >= 30 ? 'var(--high)' : 'var(--med)'
  return (
    <div style={{ marginTop: 6 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 3 }}>
        <span style={{ fontSize: 10, color: 'var(--muted)' }}>
          TTP overlap — {count} of {total} incident technique{total !== 1 ? 's' : ''} matched
        </span>
        <span style={{ fontSize: 10, fontWeight: 700, color }}>{pct}%</span>
      </div>
      <div style={{ height: 4, borderRadius: 2, background: 'var(--surface-2)' }}>
        <div style={{
          height: '100%', borderRadius: 2,
          width: `${Math.min(pct, 100)}%`,
          background: color,
          transition: 'width 0.3s ease',
        }} />
      </div>
    </div>
  )
}

// ─── Attribution card ─────────────────────────────────────────────────────────

function AttributionCard({ attr, actor, onEdit, onDelete, isClosed }) {
  const [expanded, setExpanded] = useState(false)

  return (
    <div style={{
      border: '1px solid var(--border)',
      borderLeft: `3px solid ${CONFIDENCE_META[attr.confidence]?.color || 'var(--muted)'}`,
      borderRadius: 'var(--radius)',
      background: 'var(--surface)',
      padding: 'var(--space-3)',
      marginBottom: 'var(--space-2)',
    }}>
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 'var(--space-2)', flexWrap: 'wrap' }}>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', flexWrap: 'wrap', marginBottom: 4 }}>
            <span style={{ fontWeight: 600, fontSize: 14 }}>{attr.actor_label}</span>
            {actor?.mitre_id && (
              <span style={{
                fontSize: 10, fontFamily: 'var(--font-mono)',
                padding: '1px 5px', borderRadius: 'var(--radius-sm)',
                color: 'var(--accent)',
                background: 'color-mix(in srgb, var(--accent) 12%, transparent)',
                border: '1px solid color-mix(in srgb, var(--accent) 28%, transparent)',
              }}>{actor.mitre_id}</span>
            )}
            {confidencePill(attr.confidence)}
            {typeof attr.score === 'number' && (
              <span style={{
                fontSize: 10, fontFamily: 'var(--font-mono)', fontWeight: 700,
                padding: '1px 6px', borderRadius: 'var(--radius-sm)',
                color: CONFIDENCE_META[attr.confidence]?.color || 'var(--muted)',
                background: `color-mix(in srgb, ${CONFIDENCE_META[attr.confidence]?.color || 'var(--muted)'} 12%, transparent)`,
                border: `1px solid color-mix(in srgb, ${CONFIDENCE_META[attr.confidence]?.color || 'var(--muted)'} 30%, transparent)`,
              }} title="Score from the Suggest engine at attribution time">
                {attr.score}/100
              </span>
            )}
            {actor && motivationPill(actor.motivation)}
            {actor?.country_of_origin && (
              <span style={{ fontSize: 10, color: 'var(--dim)', fontFamily: 'var(--font-mono)' }}>
                {actor.country_of_origin}
              </span>
            )}
          </div>
          {actor?.aliases?.length > 0 && (
            <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', marginBottom: 4 }}>
              {actor.aliases.slice(0, 4).map(a => (
                <span key={a} style={{
                  fontSize: 10, color: 'var(--muted)', padding: '1px 5px',
                  background: 'var(--surface-2)', borderRadius: 'var(--radius-sm)',
                  border: '1px solid var(--border)',
                }}>{a}</span>
              ))}
              {actor.aliases.length > 4 && (
                <span style={{ fontSize: 10, color: 'var(--dim)' }}>+{actor.aliases.length - 4}</span>
              )}
            </div>
          )}
          {attr.analyst_notes && (
            <p style={{ fontSize: 12, color: 'var(--muted)', margin: '4px 0 0', lineHeight: 1.5 }}>
              {attr.analyst_notes}
            </p>
          )}
          <div style={{ marginTop: 6, display: 'flex', gap: 'var(--space-3)' }}>
            {attr.supporting_ioc_ids?.length > 0 && (
              <span style={{ fontSize: 10, color: 'var(--dim)' }}>
                {attr.supporting_ioc_ids.length} IOC{attr.supporting_ioc_ids.length !== 1 ? 's' : ''}
              </span>
            )}
            {attr.supporting_timeline_ids?.length > 0 && (
              <span style={{ fontSize: 10, color: 'var(--dim)' }}>
                {attr.supporting_timeline_ids.length} timeline event{attr.supporting_timeline_ids.length !== 1 ? 's' : ''}
              </span>
            )}
            <span style={{ fontSize: 10, color: 'var(--dim)' }}>by {attr.created_by_username}</span>
          </div>
        </div>
        {!isClosed && (
          <div style={{ display: 'flex', gap: 'var(--space-1)', flexShrink: 0 }}>
            <button
              className="btn btn-ghost btn-sm"
              onClick={() => onEdit(attr)}
              style={{ fontSize: 11 }}
            >Edit</button>
            <button
              className="btn btn-ghost btn-sm"
              onClick={() => onDelete(attr)}
              style={{ fontSize: 11, color: 'var(--crit)' }}
            >Remove</button>
          </div>
        )}
      </div>

      {actor && (
        <button
          onClick={() => setExpanded(e => !e)}
          style={{
            all: 'unset', cursor: 'pointer', fontSize: 11, color: 'var(--accent)',
            marginTop: 8, display: 'block',
          }}
        >
          {expanded ? '▾ Hide actor profile' : '▸ Show actor profile'}
        </button>
      )}

      {expanded && actor && (
        <div style={{
          marginTop: 8, padding: 'var(--space-2) var(--space-3)',
          background: 'var(--surface-2)', borderRadius: 'var(--radius-sm)',
          borderTop: '1px solid var(--border)',
        }}>
          {attr.evidence?.length > 0 && (
            <div style={{ marginBottom: 8 }}>
              <span style={{ fontSize: 10, color: 'var(--dim)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                Scoring evidence
              </span>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 3, marginTop: 3 }}>
                {attr.evidence.map((ev, i) => (
                  <div key={i} style={{ display: 'flex', alignItems: 'baseline', gap: 6, fontSize: 11 }}>
                    <span style={{ color: 'var(--high)', fontFamily: 'var(--font-mono)' }}>•</span>
                    <span style={{ color: 'var(--muted)', flex: 1 }}>{ev.description}</span>
                    <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--high)', fontSize: 10 }}>+{ev.points}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
          {actor.description && (
            <p style={{ fontSize: 12, color: 'var(--muted)', margin: '0 0 8px', lineHeight: 1.6 }}>
              {actor.description}
            </p>
          )}
          {actor.typical_targets?.length > 0 && (
            <div style={{ marginBottom: 6 }}>
              <span style={{ fontSize: 10, color: 'var(--dim)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                Typical targets
              </span>
              <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', marginTop: 3 }}>
                {actor.typical_targets.map(t => (
                  <span key={t} style={{
                    fontSize: 10, padding: '1px 5px', borderRadius: 'var(--radius-sm)',
                    background: 'var(--surface)', color: 'var(--muted)', border: '1px solid var(--border)',
                  }}>{t}</span>
                ))}
              </div>
            </div>
          )}
          {actor.associated_techniques?.length > 0 && (
            <div>
              <span style={{ fontSize: 10, color: 'var(--dim)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                Known techniques ({actor.associated_techniques.length})
              </span>
              <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', marginTop: 3 }}>
                {actor.associated_techniques.map(t => (
                  <span key={t} style={{
                    fontSize: 10, fontFamily: 'var(--font-mono)', padding: '1px 5px',
                    borderRadius: 'var(--radius-sm)',
                    color: 'var(--accent)',
                    background: 'color-mix(in srgb, var(--accent) 10%, transparent)',
                    border: '1px solid color-mix(in srgb, var(--accent) 20%, transparent)',
                  }}>{t}</span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// ─── Suggestion card ──────────────────────────────────────────────────────────

// Per-signal indicator colour. Driven by signal_type so the analyst can see at
// a glance which kind of evidence is doing the work.
const SIGNAL_COLOR = {
  ttp_match:     'var(--high)',
  malware_match: 'var(--crit)',
  victimology:   'var(--med)',
  ioc_hit:       'var(--accent)',
}
const SIGNAL_ICON = {
  ttp_match:     '⧉',
  malware_match: '◉',
  victimology:   '◎',
  ioc_hit:       '⚑',
}

function ScoreBar({ score, confidence }) {
  // Bar fill colour follows the confidence band.
  const color = confidence === 'confirmed' ? 'var(--crit)'
              : confidence === 'probable'  ? 'var(--high)'
              : 'var(--med)'
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
      <div style={{
        flex: 1, height: 8, background: 'var(--surface-2)',
        borderRadius: 4, overflow: 'hidden',
      }}>
        <div style={{ width: `${score}%`, height: '100%', background: color }} />
      </div>
      <span style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color, fontWeight: 700, width: 28, textAlign: 'right' }}>
        {score}
      </span>
    </div>
  )
}

function SuggestionCard({ suggestion, onAttribute }) {
  const { actor, score, confidence, evidence } = suggestion
  return (
    <div style={{
      border: '1px solid var(--border)', borderRadius: 'var(--radius)',
      background: 'var(--surface)', padding: 'var(--space-3)',
      marginBottom: 'var(--space-2)',
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', flexWrap: 'wrap', marginBottom: 6 }}>
        <span style={{ fontWeight: 600, fontSize: 13 }}>{actor.name}</span>
        {actor.mitre_id && (
          <span style={{
            fontSize: 10, fontFamily: 'var(--font-mono)',
            padding: '1px 5px', borderRadius: 'var(--radius-sm)',
            color: 'var(--accent)',
            background: 'color-mix(in srgb, var(--accent) 12%, transparent)',
            border: '1px solid color-mix(in srgb, var(--accent) 28%, transparent)',
          }}>{actor.mitre_id}</span>
        )}
        {motivationPill(actor.motivation)}
        {confidencePill(confidence)}
        {actor.country_of_origin && (
          <span style={{ fontSize: 10, color: 'var(--dim)', fontFamily: 'var(--font-mono)' }}>
            {actor.country_of_origin}
          </span>
        )}
        <button
          className="btn btn-sm btn-ghost"
          onClick={() => onAttribute(suggestion)}
          style={{ marginLeft: 'auto', fontSize: 11, color: 'var(--accent)' }}
        >+ Attribute</button>
      </div>

      <ScoreBar score={score} confidence={confidence} />

      {/* Evidence breakdown — one row per signal contributing to the score. */}
      <div style={{ marginTop: 8, display: 'flex', flexDirection: 'column', gap: 3 }}>
        {evidence.map((ev, i) => {
          const color = SIGNAL_COLOR[ev.signal_type] || 'var(--muted)'
          return (
            <div key={i} style={{
              display: 'flex', alignItems: 'baseline', gap: 6,
              fontSize: 11, lineHeight: 1.4,
            }}>
              <span style={{ color, fontFamily: 'var(--font-mono)', flexShrink: 0 }}>
                {SIGNAL_ICON[ev.signal_type] || '•'}
              </span>
              <span style={{ color: 'var(--muted)', flex: 1 }}>{ev.description}</span>
              <span style={{
                fontFamily: 'var(--font-mono)', color, fontSize: 10,
                flexShrink: 0,
              }}>+{ev.points}</span>
            </div>
          )
        })}
      </div>
    </div>
  )
}

// ─── Attribution modal ────────────────────────────────────────────────────────

function AttributionModal({ incidentId, existing, prefillActor, prefillSuggestion, onClose, onSaved }) {
  const [actors, setActors]         = useState([])
  const [search, setSearch]         = useState('')
  const [actorId, setActorId]       = useState(existing?.threat_actor_id || prefillActor?.id || null)
  const [actorLabel, setActorLabel] = useState(existing?.actor_label || prefillActor?.name || '')
  const [useCustom, setUseCustom]   = useState(!existing?.threat_actor_id && !prefillActor && !!existing)
  const [confidence, setConfidence] = useState(
    existing?.confidence || prefillSuggestion?.confidence || 'possible'
  )
  const [notes, setNotes]           = useState(existing?.analyst_notes || '')
  const [saving, setSaving]         = useState(false)
  const [error, setError]           = useState(null)

  useEffect(() => {
    api.listThreatActors(search || null).then(d => setActors(d.items || [])).catch(() => {})
  }, [search])

  const selectedActor = actors.find(a => a.id === actorId) || (prefillActor && prefillActor.id === actorId ? prefillActor : null)

  async function handleSave() {
    setSaving(true); setError(null)
    try {
      const payload = {
        threat_actor_id:         useCustom ? null : (actorId || null),
        actor_label:             useCustom ? actorLabel : null,
        confidence,
        // Carry the Suggest-engine output into the saved attribution so the
        // audit trail explains *why* this actor was chosen.
        score:                   prefillSuggestion?.score    ?? null,
        evidence:                prefillSuggestion?.evidence ?? [],
        analyst_notes:           notes || null,
        supporting_ioc_ids:      existing?.supporting_ioc_ids || [],
        supporting_timeline_ids: existing?.supporting_timeline_ids || [],
      }
      if (existing?.id) {
        await api.updateAttribution(incidentId, existing.id, {
          confidence, analyst_notes: notes || null,
        })
      } else {
        await api.createAttribution(incidentId, payload)
      }
      onSaved()
    } catch (e) {
      setError(e.data?.detail || e.message || 'Save failed')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="modal-backdrop">
      <div className="modal" style={{ width: 520, maxHeight: '90vh', overflowY: 'auto' }}
           onClick={e => e.stopPropagation()}>
        <div className="modal-header">
          <h3 style={{ margin: 0, fontSize: 15 }}>
            {existing ? 'Edit Attribution' : 'Attribute Incident'}
          </h3>
          <button className="btn btn-ghost btn-sm" onClick={onClose}>✕</button>
        </div>
        <div className="modal-body" style={{ padding: 'var(--space-4)' }}>
          {error && (
            <div style={{ color: 'var(--crit)', fontSize: 12, marginBottom: 'var(--space-3)',
              padding: 'var(--space-2)', background: 'color-mix(in srgb, var(--crit) 10%, transparent)',
              borderRadius: 'var(--radius-sm)' }}>{error}</div>
          )}

          {!existing && (
            <div style={{ marginBottom: 'var(--space-3)' }}>
              <label style={{ fontSize: 12, color: 'var(--muted)', display: 'block', marginBottom: 6 }}>
                Actor type
              </label>
              <div style={{ display: 'flex', gap: 'var(--space-2)' }}>
                <button
                  className={`btn btn-sm ${!useCustom ? 'btn-primary' : 'btn-ghost'}`}
                  onClick={() => setUseCustom(false)}
                  style={{ fontSize: 12 }}
                >Known actor</button>
                <button
                  className={`btn btn-sm ${useCustom ? 'btn-primary' : 'btn-ghost'}`}
                  onClick={() => setUseCustom(true)}
                  style={{ fontSize: 12 }}
                >Unnamed cluster</button>
              </div>
            </div>
          )}

          {!useCustom && !existing && (
            <div style={{ marginBottom: 'var(--space-3)' }}>
              <label style={{ fontSize: 12, color: 'var(--muted)', display: 'block', marginBottom: 6 }}>
                Threat actor
              </label>
              <input
                className="input"
                placeholder="Search by name or alias…"
                value={search}
                onChange={e => setSearch(e.target.value)}
                style={{ marginBottom: 6 }}
              />
              <div style={{
                maxHeight: 200, overflowY: 'auto', border: '1px solid var(--border)',
                borderRadius: 'var(--radius-sm)', background: 'var(--surface-2)',
              }}>
                {actors.length === 0 && (
                  <div style={{ padding: 'var(--space-2)', fontSize: 12, color: 'var(--dim)' }}>
                    No actors found
                  </div>
                )}
                {actors.map(a => (
                  <div
                    key={a.id}
                    onClick={() => { setActorId(a.id); setActorLabel(a.name) }}
                    style={{
                      padding: 'var(--space-2) var(--space-3)',
                      cursor: 'pointer',
                      background: actorId === a.id ? 'color-mix(in srgb, var(--accent) 12%, transparent)' : 'transparent',
                      borderBottom: '1px solid var(--border)',
                      display: 'flex', alignItems: 'center', gap: 'var(--space-2)',
                    }}
                  >
                    <span style={{ fontSize: 13, fontWeight: actorId === a.id ? 600 : 400 }}>{a.name}</span>
                    {motivationPill(a.motivation)}
                    {a.country_of_origin && (
                      <span style={{ fontSize: 10, color: 'var(--dim)', marginLeft: 'auto' }}>{a.country_of_origin}</span>
                    )}
                  </div>
                ))}
              </div>
              {selectedActor && (
                <div style={{
                  marginTop: 6, padding: 'var(--space-2) var(--space-3)',
                  background: 'color-mix(in srgb, var(--accent) 6%, transparent)',
                  borderRadius: 'var(--radius-sm)', fontSize: 12, color: 'var(--muted)',
                }}>
                  Selected: <strong style={{ color: 'var(--text)' }}>{selectedActor.name}</strong>
                  {selectedActor.aliases?.length > 0 && ` (${selectedActor.aliases.slice(0, 2).join(', ')}${selectedActor.aliases.length > 2 ? '…' : ''})`}
                </div>
              )}
            </div>
          )}

          {useCustom && (
            <div style={{ marginBottom: 'var(--space-3)' }}>
              <label style={{ fontSize: 12, color: 'var(--muted)', display: 'block', marginBottom: 6 }}>
                Cluster name / label
              </label>
              <input
                className="input"
                placeholder="e.g. UNC1234, Unattributed cluster"
                value={actorLabel}
                onChange={e => setActorLabel(e.target.value)}
              />
            </div>
          )}

          <div style={{ marginBottom: 'var(--space-3)' }}>
            <label style={{ fontSize: 12, color: 'var(--muted)', display: 'block', marginBottom: 6 }}>
              Confidence
            </label>
            <div style={{ display: 'flex', gap: 'var(--space-2)' }}>
              {Object.entries(CONFIDENCE_META).map(([key, m]) => (
                <button
                  key={key}
                  onClick={() => setConfidence(key)}
                  style={{
                    all: 'unset', cursor: 'pointer',
                    padding: '4px 12px', borderRadius: 'var(--radius-sm)', fontSize: 12,
                    fontWeight: confidence === key ? 700 : 400,
                    color: confidence === key ? m.color : 'var(--muted)',
                    background: confidence === key
                      ? `color-mix(in srgb, ${m.color} 14%, transparent)`
                      : 'var(--surface-2)',
                    border: `1px solid ${confidence === key
                      ? `color-mix(in srgb, ${m.color} 30%, transparent)`
                      : 'var(--border)'}`,
                  }}
                >{m.label}</button>
              ))}
            </div>
          </div>

          <div style={{ marginBottom: 'var(--space-3)' }}>
            <label style={{ fontSize: 12, color: 'var(--muted)', display: 'block', marginBottom: 6 }}>
              Analyst notes
            </label>
            <textarea
              className="input"
              rows={4}
              placeholder="Evidence basis, caveats, intelligence source…"
              value={notes}
              onChange={e => setNotes(e.target.value)}
              style={{ resize: 'vertical' }}
            />
          </div>
        </div>
        <div className="modal-footer" style={{ display: 'flex', justifyContent: 'flex-end', gap: 'var(--space-2)' }}>
          <button className="btn btn-ghost" onClick={onClose}>Cancel</button>
          <button
            className="btn btn-primary"
            onClick={handleSave}
            disabled={saving || (!useCustom && !actorId && !existing) || (useCustom && !actorLabel.trim())}
          >{saving ? 'Saving…' : existing ? 'Save changes' : 'Attribute'}</button>
        </div>
      </div>
    </div>
  )
}

// ─── Main component ───────────────────────────────────────────────────────────

export default function Attribution() {
  const ctx = useOutletContext()
  // Outlet context key is `inc` (matches every other Forensic sub-page).
  // The `ctx.incident` typo below previously made `incidentId` undefined and
  // the early-return blanked the whole tab.
  const incidentId = ctx?.inc?.id
  const isClosed   = ctx?.inc?.status === 'closed'

  const [attributions, setAttributions] = useState([])
  const [actorMap, setActorMap]         = useState({})   // actor_id → actor obj
  const [loading, setLoading]           = useState(true)
  const [error, setError]               = useState(null)

  // Suggest panel
  const [showSuggest, setShowSuggest]   = useState(false)
  const [suggestions, setSuggestions]   = useState(null)
  const [suggestLoading, setSuggestLoading] = useState(false)
  const [suggestError, setSuggestError] = useState(null)

  // Modal state
  const [modal, setModal]               = useState(null)  // null | {mode:'create'} | {mode:'edit', attr} | {mode:'create', prefillActor}

  const load = useCallback(async () => {
    if (!incidentId) return
    try {
      const data = await api.listAttributions(incidentId)
      const items = data.items || []
      setAttributions(items)

      // Fetch actor details for each attribution that has a threat_actor_id
      const ids = [...new Set(items.map(a => a.threat_actor_id).filter(Boolean))]
      const map = {}
      await Promise.all(ids.map(async id => {
        try {
          const actor = await api.getThreatActor(id)
          map[id] = actor
        } catch { /* actor may have been deleted */ }
      }))
      setActorMap(map)
    } catch (e) {
      setError(e.message || 'Failed to load attributions')
    } finally {
      setLoading(false)
    }
  }, [incidentId])

  useEffect(() => { load() }, [load])

  async function handleDelete(attr) {
    if (!confirm(`Remove attribution to "${attr.actor_label}"?`)) return
    try {
      await api.deleteAttribution(incidentId, attr.id)
      load()
    } catch (e) {
      alert(e.data?.detail || e.message || 'Delete failed')
    }
  }

  async function handleSuggest() {
    if (showSuggest) { setShowSuggest(false); return }
    setShowSuggest(true)
    if (suggestions !== null) return   // already loaded
    setSuggestLoading(true); setSuggestError(null)
    try {
      const data = await api.suggestAttributions(incidentId)
      setSuggestions(data)
    } catch (e) {
      setSuggestError(e.message || 'Failed to generate suggestions')
    } finally {
      setSuggestLoading(false)
    }
  }

  function handlePrefillAttribute(suggestion) {
    setShowSuggest(false)
    setModal({
      mode: 'create',
      prefillActor: suggestion.actor,
      prefillSuggestion: {
        score:      suggestion.score,
        confidence: suggestion.confidence,
        evidence:   suggestion.evidence,
      },
    })
  }

  function onModalSaved() {
    setModal(null)
    setSuggestions(null)  // reset so next suggest re-fetches with updated TTP count
    load()
  }

  if (!incidentId) return null

  return (
    <div style={{ padding: 'var(--space-4) var(--space-5)' }}>
      {/* Header */}
      <div style={{
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        marginBottom: 'var(--space-4)', flexWrap: 'wrap', gap: 'var(--space-2)',
      }}>
        <div>
          <h3 style={{ margin: 0, fontSize: 15, fontWeight: 600 }}>Threat Actor Attribution</h3>
          <p style={{ margin: '2px 0 0', fontSize: 12, color: 'var(--muted)' }}>
            Link this incident to known threat actors or named clusters
          </p>
        </div>
        <div style={{ display: 'flex', gap: 'var(--space-2)' }}>
          <button
            className="btn btn-ghost btn-sm"
            onClick={handleSuggest}
          >
            {showSuggest ? '▾ Hide suggestions' : '◈ Suggest actors'}
          </button>
          {!isClosed && (
            <button
              className="btn btn-primary btn-sm"
              onClick={() => setModal({ mode: 'create' })}
            >+ Attribute</button>
          )}
        </div>
      </div>

      {/* TTP suggestion panel */}
      {showSuggest && (
        <div style={{
          marginBottom: 'var(--space-4)', padding: 'var(--space-3)',
          border: '1px solid color-mix(in srgb, var(--accent) 25%, transparent)',
          borderRadius: 'var(--radius)',
          background: 'color-mix(in srgb, var(--accent) 4%, transparent)',
        }}>
          <div style={{
            fontSize: 12, fontWeight: 600, color: 'var(--accent)',
            marginBottom: 'var(--space-2)', textTransform: 'uppercase', letterSpacing: '0.06em',
          }}>
            ◈ Threat actor suggestions
          </div>
          {suggestLoading && (
            <div style={{ fontSize: 12, color: 'var(--muted)' }}>Scoring threat actors…</div>
          )}
          {suggestError && (
            <div style={{ fontSize: 12, color: 'var(--crit)' }}>{suggestError}</div>
          )}
          {suggestions && !suggestLoading && (
            <>
              {suggestions.cache_warming && (
                <div style={{
                  fontSize: 11, color: 'var(--accent)',
                  padding: '6px 10px', marginBottom: 'var(--space-2)',
                  background: 'color-mix(in srgb, var(--accent) 8%, transparent)',
                  border: '1px solid color-mix(in srgb, var(--accent) 25%, transparent)',
                  borderRadius: 'var(--radius-sm)',
                }}>
                  ⟳ Syncing MITRE ATT&CK catalogue in the background — refresh in a minute for a richer result.
                </div>
              )}
              {suggestions.incident_technique_count === 0 && suggestions.incident_ioc_count === 0 ? (
                <div style={{ fontSize: 12, color: 'var(--muted)' }}>
                  No MITRE techniques on timeline events and no IOCs yet — there's nothing for the scorer to match.
                  Tag timeline events with tactics/techniques or add IOCs to enable suggestions.
                </div>
              ) : suggestions.suggestions.length === 0 ? (
                <div style={{ fontSize: 12, color: 'var(--muted)' }}>
                  No actors matched. Signals checked: {suggestions.incident_technique_count} technique{suggestions.incident_technique_count !== 1 ? 's' : ''},
                  {' '}{suggestions.incident_ioc_count} IOC{suggestions.incident_ioc_count !== 1 ? 's' : ''}.
                </div>
              ) : (
                <>
                  <div style={{ fontSize: 11, color: 'var(--dim)', marginBottom: 'var(--space-2)' }}>
                    Ranked by 3-signal score (TTP overlap · Malware/tool family · Victimology) against{' '}
                    {suggestions.incident_technique_count} technique{suggestions.incident_technique_count !== 1 ? 's' : ''} +{' '}
                    {suggestions.incident_ioc_count} IOC{suggestions.incident_ioc_count !== 1 ? 's' : ''}.
                  </div>
                  {suggestions.suggestions.map(s => (
                    <SuggestionCard
                      key={s.actor.id}
                      suggestion={s}
                      onAttribute={handlePrefillAttribute}
                    />
                  ))}
                </>
              )}
            </>
          )}
        </div>
      )}

      {/* Attributions list */}
      {loading && <div style={{ fontSize: 13, color: 'var(--muted)' }}>Loading…</div>}
      {error && <div style={{ fontSize: 13, color: 'var(--crit)' }}>{error}</div>}

      {!loading && !error && attributions.length === 0 && (
        <div style={{
          textAlign: 'center', padding: 'var(--space-6)',
          border: '1px dashed var(--border)', borderRadius: 'var(--radius)',
          color: 'var(--dim)', fontSize: 13,
        }}>
          No attributions yet.{!isClosed && ' Use "Suggest by TTPs" or "+ Attribute" to link a threat actor.'}
        </div>
      )}

      {attributions.map(attr => (
        <AttributionCard
          key={attr.id}
          attr={attr}
          actor={attr.threat_actor_id ? actorMap[attr.threat_actor_id] : null}
          onEdit={a => setModal({ mode: 'edit', attr: a })}
          onDelete={handleDelete}
          isClosed={isClosed}
        />
      ))}

      {/* Modal */}
      {modal && (
        <AttributionModal
          incidentId={incidentId}
          existing={modal.mode === 'edit' ? modal.attr : null}
          prefillActor={modal.prefillActor || null}
          prefillSuggestion={modal.prefillSuggestion || null}
          onClose={() => setModal(null)}
          onSaved={onModalSaved}
        />
      )}
    </div>
  )
}
