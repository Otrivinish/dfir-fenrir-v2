import { useCallback, useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api/client.js'
import { useAuth } from '../hooks/useAuth.jsx'
import SevBadge from '../components/SevBadge.jsx'

// ─── Vocabulary ──────────────────────────────────────────────────────────────

const MOTIVATIONS = [
  { value: 'financial',   label: 'Financial',   color: 'var(--high)' },
  { value: 'espionage',   label: 'Espionage',   color: 'var(--accent)' },
  { value: 'hacktivist',  label: 'Hacktivist',  color: 'var(--med)' },
  { value: 'destructive', label: 'Destructive', color: 'var(--crit)' },
  { value: 'ransomware',  label: 'Ransomware',  color: 'var(--crit)' },
  { value: 'unknown',     label: 'Unknown',     color: 'var(--muted)' },
]
const MOTIVATION_META = Object.fromEntries(MOTIVATIONS.map(m => [m.value, m]))

const STATUS_PILL = {
  open:   { color: 'var(--high)', label: 'Open' },
  closed: { color: 'var(--ok)',   label: 'Closed' },
}

// ─── Page root ───────────────────────────────────────────────────────────────

export default function ThreatActors() {
  const { user } = useAuth()
  const isAdmin = user?.role === 'admin'

  const [actors,     setActors]     = useState([])
  const [loading,    setLoading]    = useState(true)
  const [error,      setError]      = useState(null)
  const [search,     setSearch]     = useState('')
  const [motivation, setMotivation] = useState('')
  const [source,     setSource]     = useState('all')   // all | mitre | custom
  const [selectedId, setSelectedId] = useState(null)
  const [editTarget, setEditTarget] = useState(null)    // 'new' | actor row | null
  const [syncStatus, setSyncStatus] = useState(null)
  const [syncing,    setSyncing]    = useState(false)

  const load = useCallback(async () => {
    setLoading(true); setError(null)
    try {
      const data = await api.listThreatActors(search || null, motivation || null)
      setActors(data.items || [])
    } catch (e) {
      setError(e.message || 'Failed to load actors')
    } finally {
      setLoading(false)
    }
  }, [search, motivation])

  useEffect(() => { load() }, [load])

  useEffect(() => {
    api.actorSyncStatus().then(setSyncStatus).catch(() => {})
  }, [])

  const filtered = useMemo(() => {
    if (source === 'all') return actors
    return actors.filter(a => source === 'mitre' ? a.is_system : !a.is_system)
  }, [actors, source])

  const selectedActor = useMemo(
    () => filtered.find(a => a.id === selectedId) || actors.find(a => a.id === selectedId) || null,
    [filtered, actors, selectedId],
  )

  // Roll-up counts for the filter chips so the analyst sees how big each
  // bucket is before drilling in.
  const counts = useMemo(() => ({
    all:    actors.length,
    mitre:  actors.filter(a => a.is_system).length,
    custom: actors.filter(a => !a.is_system).length,
  }), [actors])

  async function triggerSync(force = false) {
    if (!isAdmin) return
    setSyncing(true)
    try {
      await api.triggerActorSync(force)
      // Poll status until the in-process flag clears — sync runs as a
      // background task so we don't block on it. 1s × max 60 attempts.
      let attempts = 0
      const tick = async () => {
        attempts += 1
        const s = await api.actorSyncStatus().catch(() => null)
        setSyncStatus(s)
        // The sync function flips `last_sync` time when it finishes; if it's
        // newer than 30 s ago we treat the run as done.
        const fresh = s?.last_sync && (Date.now() / 1000 - s.last_sync) < 30
        if (fresh || attempts >= 60) {
          setSyncing(false)
          load()
        } else {
          setTimeout(tick, 1000)
        }
      }
      setTimeout(tick, 1500)
    } catch (e) {
      alert(e.message || 'Sync failed')
      setSyncing(false)
    }
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
      {/* Header */}
      <div className="page-head" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 'var(--space-3)' }}>
        <div>
          <h1 className="page-title">Threat Actors</h1>
          <div className="page-sub">
            MITRE ATT&CK intrusion sets + custom analyst-defined clusters
            {syncStatus?.last_sync ? ` · synced ${relTimeFromUnix(syncStatus.last_sync)}` : ''}
          </div>
        </div>
        <div style={{ display: 'flex', gap: 'var(--space-2)' }}>
          {isAdmin && (
            <button
              type="button"
              className="btn ghost"
              onClick={() => triggerSync(true)}
              disabled={syncing}
              title="Re-sync MITRE ATT&CK groups — backgrounds in ~30 s"
            >
              {syncing ? '⟳ Syncing…' : '⟳ Sync MITRE'}
            </button>
          )}
          {isAdmin && (
            <button
              type="button"
              className="btn primary"
              onClick={() => setEditTarget('new')}
            >+ Custom actor</button>
          )}
        </div>
      </div>

      {/* Filter row */}
      <div style={{
        display: 'flex', flexWrap: 'wrap', gap: 'var(--space-2)', alignItems: 'center',
        padding: 'var(--space-2) var(--space-3)',
        background: 'var(--surface-2)', border: '1px solid var(--border)',
        borderRadius: 'var(--radius)',
      }}>
        <input
          className="input"
          type="search"
          placeholder="Search name or alias…"
          value={search}
          onChange={e => setSearch(e.target.value)}
          style={{ flex: '1 1 200px', maxWidth: 340, fontSize: 13 }}
        />
        <select
          className="select"
          value={motivation}
          onChange={e => setMotivation(e.target.value)}
          style={{ fontSize: 12 }}
        >
          <option value="">All motivations</option>
          {MOTIVATIONS.map(m => <option key={m.value} value={m.value}>{m.label}</option>)}
        </select>
        <div style={{ display: 'flex', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', overflow: 'hidden' }}>
          {[
            ['all',    `All (${counts.all})`],
            ['mitre',  `MITRE (${counts.mitre})`],
            ['custom', `Custom (${counts.custom})`],
          ].map(([val, label]) => (
            <button
              key={val}
              type="button"
              onClick={() => setSource(val)}
              style={{
                fontSize: 12, padding: '4px 10px',
                background: source === val ? 'var(--accent-soft)' : 'transparent',
                color: source === val ? 'var(--accent)' : 'var(--muted)',
                border: 'none', cursor: 'pointer',
              }}
            >{label}</button>
          ))}
        </div>
        <span style={{ marginLeft: 'auto', fontSize: 11, color: 'var(--dim)' }}>
          {filtered.length} shown
        </span>
      </div>

      {/* Two-pane: card grid + detail drawer */}
      <div style={{ display: 'grid', gridTemplateColumns: selectedActor ? '1fr 420px' : '1fr', gap: 'var(--space-3)', alignItems: 'start' }}>
        <div>
          {error && <div className="alert error" role="alert"><span className="alert-icon">!</span><span>{error}</span></div>}
          {loading ? (
            <div style={{ color: 'var(--muted)', padding: 'var(--space-3)' }}>Loading…</div>
          ) : filtered.length === 0 ? (
            <div className="panel-empty">
              <div className="panel-empty-mark" aria-hidden="true">◇</div>
              <div>No threat actors match the current filter.</div>
              {isAdmin && counts.all === 0 && (
                <div style={{ color: 'var(--dim)', fontSize: 12 }}>
                  Click "⟳ Sync MITRE" to pull the ATT&CK groups catalogue.
                </div>
              )}
            </div>
          ) : (
            <div style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))',
              gap: 'var(--space-2)',
            }}>
              {filtered.map(a => (
                <ActorCard
                  key={a.id}
                  actor={a}
                  selected={a.id === selectedId}
                  onSelect={() => setSelectedId(a.id)}
                />
              ))}
            </div>
          )}
        </div>

        {selectedActor && (
          <ActorDetailDrawer
            actor={selectedActor}
            isAdmin={isAdmin}
            onClose={() => setSelectedId(null)}
            onEdit={() => setEditTarget(selectedActor)}
            onDeleted={() => { setSelectedId(null); load() }}
          />
        )}
      </div>

      {editTarget && (
        <ActorEditModal
          actor={editTarget === 'new' ? null : editTarget}
          onClose={() => setEditTarget(null)}
          onSaved={(saved) => {
            setEditTarget(null)
            load()
            if (saved?.id) setSelectedId(saved.id)
          }}
        />
      )}
    </div>
  )
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function relTimeFromUnix(sec) {
  if (!sec) return 'never'
  const diff = Date.now() / 1000 - sec
  if (diff < 60)   return 'just now'
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`
  return `${Math.floor(diff / 86400)}d ago`
}

function MotivationPill({ value }) {
  const m = MOTIVATION_META[value] || MOTIVATION_META.unknown
  return (
    <span style={{
      fontSize: 10, fontFamily: 'var(--font-mono)', fontWeight: 700,
      padding: '1px 6px', borderRadius: 'var(--radius-sm)',
      color: m.color,
      background: `color-mix(in srgb, ${m.color} 12%, transparent)`,
      border: `1px solid color-mix(in srgb, ${m.color} 28%, transparent)`,
    }}>{m.label}</span>
  )
}

// ─── Actor card ──────────────────────────────────────────────────────────────

function ActorCard({ actor, selected, onSelect }) {
  return (
    <button
      type="button"
      onClick={onSelect}
      style={{
        textAlign: 'left',
        background: selected ? 'var(--surface-2)' : 'var(--surface)',
        border: `1px solid ${selected ? 'var(--accent)' : 'var(--border)'}`,
        borderRadius: 'var(--radius)',
        padding: 'var(--space-3)',
        cursor: 'pointer',
        transition: 'border-color 120ms ease',
        display: 'flex', flexDirection: 'column', gap: 6,
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
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
        <MotivationPill value={actor.motivation} />
        {!actor.is_system && (
          <span style={{ fontSize: 10, color: 'var(--med)', fontFamily: 'var(--font-mono)' }}>custom</span>
        )}
      </div>

      {actor.aliases?.length > 0 && (
        <div style={{ fontSize: 11, color: 'var(--muted)', wordBreak: 'break-word', lineHeight: 1.3 }}>
          aka {actor.aliases.slice(0, 4).join(', ')}
          {actor.aliases.length > 4 && ` +${actor.aliases.length - 4}`}
        </div>
      )}

      {actor.description && (
        <div style={{
          fontSize: 11, color: 'var(--dim)',
          overflow: 'hidden', display: '-webkit-box',
          WebkitLineClamp: 2, WebkitBoxOrient: 'vertical',
        }}>
          {actor.description}
        </div>
      )}

      <div style={{ display: 'flex', gap: 'var(--space-3)', marginTop: 'auto', fontSize: 10, color: 'var(--dim)', fontFamily: 'var(--font-mono)' }}>
        {actor.country_of_origin && <span>{actor.country_of_origin}</span>}
        <span>{actor.associated_techniques?.length || 0} TTPs</span>
        <span>{actor.software?.length || 0} tools</span>
      </div>
    </button>
  )
}

// ─── Detail drawer ───────────────────────────────────────────────────────────

function ActorDetailDrawer({ actor, isAdmin, onClose, onEdit, onDeleted }) {
  const [linked, setLinked] = useState(null)
  const [linkedLoading, setLinkedLoading] = useState(true)

  useEffect(() => {
    setLinkedLoading(true)
    api.listActorAttributions(actor.id)
      .then(d => setLinked(d.items || []))
      .catch(() => setLinked([]))
      .finally(() => setLinkedLoading(false))
  }, [actor.id])

  async function handleDelete() {
    if (!confirm(`Delete custom actor "${actor.name}"? This cannot be undone.`)) return
    try {
      await api.deleteThreatActor(actor.id)
      onDeleted()
    } catch (e) {
      alert(e.data?.detail || e.message || 'Delete failed')
    }
  }

  return (
    <div style={{
      background: 'var(--surface)',
      border: '1px solid var(--border)',
      borderRadius: 'var(--radius)',
      padding: 'var(--space-3) var(--space-4)',
      position: 'sticky', top: 'var(--space-3)',
      maxHeight: 'calc(100vh - var(--space-5))',
      overflowY: 'auto',
      display: 'flex', flexDirection: 'column', gap: 'var(--space-3)',
    }}>
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 'var(--space-2)' }}>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap', marginBottom: 4 }}>
            <h2 style={{ margin: 0, fontSize: 16, fontWeight: 700 }}>{actor.name}</h2>
            {actor.mitre_id && (
              <a
                href={actor.mitre_url || `https://attack.mitre.org/groups/${actor.mitre_id}/`}
                target="_blank"
                rel="noreferrer"
                style={{
                  fontSize: 11, fontFamily: 'var(--font-mono)',
                  color: 'var(--accent)', textDecoration: 'none',
                  padding: '1px 6px', borderRadius: 'var(--radius-sm)',
                  border: '1px solid color-mix(in srgb, var(--accent) 28%, transparent)',
                }}
              >{actor.mitre_id} ↗</a>
            )}
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
            <MotivationPill value={actor.motivation} />
            {actor.country_of_origin && (
              <span style={{ fontSize: 11, color: 'var(--muted)', fontFamily: 'var(--font-mono)' }}>
                {actor.country_of_origin}
              </span>
            )}
            {actor.is_system ? (
              <span style={{ fontSize: 10, color: 'var(--dim)', fontFamily: 'var(--font-mono)' }}>
                MITRE-synced · read-only
              </span>
            ) : (
              <span style={{ fontSize: 10, color: 'var(--med)', fontFamily: 'var(--font-mono)' }}>
                custom
              </span>
            )}
          </div>
        </div>
        <button
          type="button"
          onClick={onClose}
          aria-label="Close"
          style={{
            background: 'transparent', border: 'none',
            color: 'var(--muted)', fontSize: 18, cursor: 'pointer',
            padding: '0 4px', lineHeight: 1,
          }}
        >×</button>
      </div>

      {isAdmin && !actor.is_system && (
        <div style={{ display: 'flex', gap: 'var(--space-2)' }}>
          <button type="button" className="btn ghost" onClick={onEdit} style={{ fontSize: 12 }}>Edit</button>
          <button type="button" className="btn ghost" onClick={handleDelete} style={{ fontSize: 12, color: 'var(--crit)' }}>Delete</button>
        </div>
      )}

      {actor.aliases?.length > 0 && (
        <DetailRow label="Aliases">
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
            {actor.aliases.map(a => (
              <span key={a} style={{
                fontSize: 11, padding: '1px 6px',
                background: 'var(--surface-2)', border: '1px solid var(--border)',
                borderRadius: 'var(--radius-sm)', color: 'var(--muted)',
              }}>{a}</span>
            ))}
          </div>
        </DetailRow>
      )}

      {actor.description && (
        <DetailRow label="Description">
          <p style={{ margin: 0, fontSize: 12, color: 'var(--text)', lineHeight: 1.6 }}>{actor.description}</p>
        </DetailRow>
      )}

      {actor.associated_techniques?.length > 0 && (
        <DetailRow label={`Techniques (${actor.associated_techniques.length})`}>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 3 }}>
            {actor.associated_techniques.map(t => (
              <a
                key={t}
                href={`https://attack.mitre.org/techniques/${t.replace('.', '/')}/`}
                target="_blank"
                rel="noreferrer"
                style={{
                  fontSize: 10, fontFamily: 'var(--font-mono)',
                  padding: '1px 5px', borderRadius: 'var(--radius-sm)',
                  color: 'var(--accent)',
                  background: 'color-mix(in srgb, var(--accent) 10%, transparent)',
                  border: '1px solid color-mix(in srgb, var(--accent) 22%, transparent)',
                  textDecoration: 'none',
                }}
              >{t}</a>
            ))}
          </div>
        </DetailRow>
      )}

      {actor.software?.length > 0 && (
        <DetailRow label={`Software / Tools (${actor.software.length})`}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
            {actor.software.slice(0, 30).map((sw, i) => (
              <div key={i} style={{ display: 'flex', alignItems: 'baseline', gap: 6, fontSize: 11 }}>
                <span style={{
                  fontSize: 9, fontFamily: 'var(--font-mono)', fontWeight: 700, textTransform: 'uppercase',
                  padding: '1px 4px', borderRadius: 2,
                  color: sw.type === 'malware' ? 'var(--crit)' : 'var(--accent)',
                  background: `color-mix(in srgb, ${sw.type === 'malware' ? 'var(--crit)' : 'var(--accent)'} 10%, transparent)`,
                }}>{sw.type || 'tool'}</span>
                <span style={{ color: 'var(--text)', fontFamily: 'var(--font-mono)' }}>{sw.name}</span>
                {sw.mitre_id && (
                  <a
                    href={`https://attack.mitre.org/software/${sw.mitre_id}/`}
                    target="_blank" rel="noreferrer"
                    style={{ marginLeft: 'auto', fontSize: 10, color: 'var(--dim)', textDecoration: 'none' }}
                  >{sw.mitre_id} ↗</a>
                )}
              </div>
            ))}
            {actor.software.length > 30 && (
              <div style={{ fontSize: 11, color: 'var(--dim)' }}>
                +{actor.software.length - 30} more
              </div>
            )}
          </div>
        </DetailRow>
      )}

      {actor.typical_targets?.length > 0 && (
        <DetailRow label="Typical targets">
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
            {actor.typical_targets.map(t => (
              <span key={t} style={{
                fontSize: 11, padding: '1px 6px',
                background: 'var(--surface-2)', border: '1px solid var(--border)',
                borderRadius: 'var(--radius-sm)', color: 'var(--muted)',
              }}>{t}</span>
            ))}
          </div>
        </DetailRow>
      )}

      <DetailRow label="Linked incidents">
        {linkedLoading ? (
          <div style={{ fontSize: 12, color: 'var(--muted)' }}>Loading…</div>
        ) : linked?.length === 0 ? (
          <div style={{ fontSize: 12, color: 'var(--dim)' }}>None yet</div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            {linked.map(l => {
              const sp = STATUS_PILL[l.incident_status] || { color: 'var(--muted)', label: l.incident_status }
              return (
                <Link
                  key={l.attribution_id}
                  to={`/incidents/${l.incident_id}/forensic/attribution`}
                  style={{
                    display: 'flex', alignItems: 'center', gap: 8,
                    padding: '6px 8px', textDecoration: 'none',
                    background: 'var(--surface-2)', border: '1px solid var(--border)',
                    borderRadius: 'var(--radius-sm)', fontSize: 12,
                    color: 'var(--text)',
                  }}
                >
                  {l.incident_ref && (
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--accent)', flexShrink: 0 }}>
                      {l.incident_ref}
                    </span>
                  )}
                  <span style={{ flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {l.incident_title}
                  </span>
                  <SevBadge value={l.severity} />
                  <span style={{
                    fontSize: 10, fontFamily: 'var(--font-mono)',
                    color: sp.color,
                    padding: '1px 5px', borderRadius: 'var(--radius-sm)',
                    background: `color-mix(in srgb, ${sp.color} 14%, transparent)`,
                    border: `1px solid color-mix(in srgb, ${sp.color} 28%, transparent)`,
                  }}>{sp.label}</span>
                  {typeof l.score === 'number' && (
                    <span style={{ fontSize: 10, fontFamily: 'var(--font-mono)', color: 'var(--muted)' }}>
                      {l.score}/100
                    </span>
                  )}
                </Link>
              )
            })}
          </div>
        )}
      </DetailRow>

      {actor.last_synced_at && (
        <div style={{ fontSize: 10, color: 'var(--dim)', fontFamily: 'var(--font-mono)', marginTop: 'auto' }}>
          Synced {new Date(actor.last_synced_at).toISOString().slice(0, 19).replace('T', ' ')}Z
        </div>
      )}
    </div>
  )
}

function DetailRow({ label, children }) {
  return (
    <div>
      <div style={{
        fontSize: 10, color: 'var(--dim)',
        textTransform: 'uppercase', letterSpacing: '0.08em',
        marginBottom: 4, fontWeight: 700,
      }}>{label}</div>
      {children}
    </div>
  )
}

// ─── Create / edit modal (admin) ─────────────────────────────────────────────

function ActorEditModal({ actor, onClose, onSaved }) {
  const editing = !!actor
  const [form, setForm] = useState({
    name:              actor?.name || '',
    aliases:           (actor?.aliases || []).join(', '),
    description:       actor?.description || '',
    country_of_origin: actor?.country_of_origin || '',
    motivation:        actor?.motivation || 'unknown',
    associated_techniques: (actor?.associated_techniques || []).join(', '),
    typical_targets:   (actor?.typical_targets || []).join(', '),
  })
  const [saving, setSaving] = useState(false)
  const [error,  setError]  = useState(null)

  function set(k, v) { setForm(f => ({ ...f, [k]: v })) }

  async function submit(e) {
    e.preventDefault()
    if (!form.name.trim()) { setError('Name is required.'); return }
    setSaving(true); setError(null)
    try {
      const payload = {
        name:                  form.name.trim(),
        aliases:               splitList(form.aliases),
        description:           form.description.trim() || null,
        country_of_origin:     form.country_of_origin.trim() || null,
        motivation:            form.motivation,
        associated_techniques: splitList(form.associated_techniques),
        typical_targets:       splitList(form.typical_targets),
      }
      const saved = editing
        ? await api.updateThreatActor(actor.id, payload)
        : await api.createThreatActor(payload)
      onSaved(saved)
    } catch (e) {
      setError(e.data?.detail || e.message || 'Save failed')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="modal-backdrop" onClick={() => !saving && onClose()}>
      <div className="modal" style={{ maxWidth: 560 }} onClick={e => e.stopPropagation()}>
        <div className="modal-head">
          <h2>{editing ? 'Edit custom actor' : 'New custom actor'}</h2>
          <button type="button" className="modal-close" onClick={onClose} aria-label="Close" disabled={saving}>×</button>
        </div>
        <form onSubmit={submit}>
          <div className="modal-body" style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
            <div className="field">
              <label className="field-label">Name *</label>
              <input className="input" value={form.name} onChange={e => set('name', e.target.value)} maxLength={128} autoFocus />
            </div>
            <div className="field">
              <label className="field-label">Aliases <span style={{ color: 'var(--dim)' }}>(comma-separated)</span></label>
              <input className="input" value={form.aliases} onChange={e => set('aliases', e.target.value)} placeholder="e.g. Fancy Bear, Sofacy" />
            </div>
            <div className="field">
              <label className="field-label">Description</label>
              <textarea className="input" value={form.description} onChange={e => set('description', e.target.value)} rows={3} maxLength={4096} />
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--space-3)' }}>
              <div className="field">
                <label className="field-label">Motivation</label>
                <select className="select" value={form.motivation} onChange={e => set('motivation', e.target.value)}>
                  {MOTIVATIONS.map(m => <option key={m.value} value={m.value}>{m.label}</option>)}
                </select>
              </div>
              <div className="field">
                <label className="field-label">Country of origin</label>
                <input className="input" value={form.country_of_origin} onChange={e => set('country_of_origin', e.target.value)} maxLength={64} />
              </div>
            </div>
            <div className="field">
              <label className="field-label">Associated techniques <span style={{ color: 'var(--dim)' }}>(MITRE IDs, comma-separated)</span></label>
              <input className="input" value={form.associated_techniques} onChange={e => set('associated_techniques', e.target.value)} placeholder="T1566, T1059.001, T1083" style={{ fontFamily: 'var(--font-mono)' }} />
            </div>
            <div className="field">
              <label className="field-label">Typical targets <span style={{ color: 'var(--dim)' }}>(comma-separated)</span></label>
              <input className="input" value={form.typical_targets} onChange={e => set('typical_targets', e.target.value)} placeholder="Government, Defense, Energy" />
            </div>
            {error && (
              <div className="alert error" role="alert"><span className="alert-icon">!</span><span>{error}</span></div>
            )}
          </div>
          <div className="modal-foot">
            <button type="button" className="btn ghost" onClick={onClose} disabled={saving}>Cancel</button>
            <button type="submit" className="btn primary" disabled={saving}>
              {saving ? 'Saving…' : (editing ? 'Save changes' : 'Create actor')}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

function splitList(s) {
  return (s || '').split(',').map(x => x.trim()).filter(Boolean)
}
