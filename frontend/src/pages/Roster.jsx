import { useState, useEffect, useCallback } from 'react'
import { api } from '../api/client.js'
import { useAuth } from '../hooks/useAuth.jsx'

const AVAILABILITY_OPTIONS = [
  { value: 'available',      label: 'Available',      color: 'var(--ok)'     },
  { value: 'on_call',        label: 'On-Call',        color: 'var(--med)'    },
  { value: 'unavailable',    label: 'Unavailable',    color: 'var(--crit)'   },
  { value: 'out_of_office',  label: 'Out of Office',  color: 'var(--muted)'  },
]

const COMMON_SKILLS = [
  'Malware Analysis', 'Network Forensics', 'Cloud IR', 'Threat Intelligence',
  'Digital Forensics', 'Log Analysis', 'Memory Forensics', 'Reverse Engineering',
  'Vulnerability Assessment', 'Incident Coordination', 'Legal / Compliance', 'Communications',
]

function availLabel(v) {
  return AVAILABILITY_OPTIONS.find(o => o.value === v)?.label ?? v
}
function availColor(v) {
  return AVAILABILITY_OPTIONS.find(o => o.value === v)?.color ?? 'var(--muted)'
}

function initials(name) {
  const parts = (name || '').trim().split(/[\s._-]+/).filter(Boolean)
  if (parts.length >= 2) return (parts[0][0] + parts[1][0]).toUpperCase()
  return (name || '?').slice(0, 2).toUpperCase()
}

// ─── Edit profile modal ───────────────────────────────────────────────────────

function EditProfileModal({ entry, onClose, onSaved }) {
  const [skills, setSkills]               = useState(entry.skills ?? [])
  const [skillInput, setSkillInput]       = useState('')
  const [availability, setAvailability]   = useState(entry.availability ?? 'available')
  const [notes, setNotes]                 = useState(entry.notes ?? '')
  const [saving, setSaving]               = useState(false)
  const [error, setError]                 = useState(null)

  const addSkill = (s) => {
    const trimmed = s.trim()
    if (!trimmed || skills.includes(trimmed)) return
    setSkills(prev => [...prev, trimmed])
    setSkillInput('')
  }

  const removeSkill = (s) => setSkills(prev => prev.filter(x => x !== s))

  const handleSubmit = async (e) => {
    e.preventDefault()
    setSaving(true)
    setError(null)
    try {
      const updated = await api.updateRosterProfile(entry.user_id, {
        skills,
        availability,
        notes: notes.trim() || null,
      })
      onSaved(updated)
    } catch (err) {
      setError(err.message ?? 'Save failed')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="modal-backdrop">
      <div className="modal" style={{ maxWidth: 500 }}>
        <div className="modal-header">
          <span className="modal-title">Edit profile — {entry.username}</span>
          <button className="btn-icon" onClick={onClose}>✕</button>
        </div>
        <form onSubmit={handleSubmit}>
          <div className="modal-body" style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
            {error && <div className="banner banner-err">{error}</div>}

            <label className="field-label">
              Availability
              <select
                className="input"
                value={availability}
                onChange={e => setAvailability(e.target.value)}
              >
                {AVAILABILITY_OPTIONS.map(o => (
                  <option key={o.value} value={o.value}>{o.label}</option>
                ))}
              </select>
            </label>

            <div className="field-label">
              Skills
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, margin: '6px 0' }}>
                {skills.map(s => (
                  <span key={s} style={{
                    display: 'inline-flex', alignItems: 'center', gap: 4,
                    background: 'var(--accent-soft)', color: 'var(--accent)',
                    borderRadius: 'var(--radius-sm)', padding: '2px 8px',
                    fontSize: 12, fontWeight: 600,
                  }}>
                    {s}
                    <button
                      type="button"
                      onClick={() => removeSkill(s)}
                      style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--accent)', padding: 0, lineHeight: 1 }}
                    >×</button>
                  </span>
                ))}
              </div>
              <div style={{ display: 'flex', gap: 'var(--space-2)' }}>
                <input
                  className="input"
                  style={{ flex: 1, fontSize: 12 }}
                  placeholder="Type a skill and press Enter or Add"
                  value={skillInput}
                  onChange={e => setSkillInput(e.target.value)}
                  onKeyDown={e => { if (e.key === 'Enter') { e.preventDefault(); addSkill(skillInput) } }}
                />
                <button
                  type="button"
                  className="btn"
                  style={{ fontSize: 12 }}
                  onClick={() => addSkill(skillInput)}
                >Add</button>
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginTop: 6 }}>
                {COMMON_SKILLS.filter(s => !skills.includes(s)).map(s => (
                  <button
                    key={s}
                    type="button"
                    onClick={() => addSkill(s)}
                    style={{
                      background: 'var(--surface-2)', border: '1px solid var(--border)',
                      borderRadius: 'var(--radius-sm)', padding: '2px 8px',
                      fontSize: 11, cursor: 'pointer', color: 'var(--muted)',
                    }}
                  >+ {s}</button>
                ))}
              </div>
            </div>

            <label className="field-label">
              Notes <span className="muted">(optional)</span>
              <textarea
                className="input"
                rows={2}
                value={notes}
                onChange={e => setNotes(e.target.value)}
                maxLength={512}
                style={{ fontSize: 12 }}
              />
            </label>
          </div>
          <div className="modal-footer">
            <button type="button" className="btn btn-ghost" onClick={onClose}>Cancel</button>
            <button type="submit" className="btn btn-primary" disabled={saving}>
              {saving ? 'Saving…' : 'Save'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ─── Responder card ───────────────────────────────────────────────────────────

function ResponderCard({ entry, canEdit, onEdit }) {
  return (
    <div style={{
      background: 'var(--surface)',
      border: '1px solid var(--border)',
      borderTop: `3px solid ${availColor(entry.availability)}`,
      borderRadius: 'var(--radius)',
      padding: 'var(--space-3)',
    }}>
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 'var(--space-2)', marginBottom: 'var(--space-2)' }}>
        <div style={{
          width: 36, height: 36, borderRadius: '50%', flexShrink: 0,
          background: 'var(--accent-soft)', color: 'var(--accent)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          fontFamily: 'var(--font-mono)', fontSize: 13, fontWeight: 700,
        }}>
          {initials(entry.username)}
        </div>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontWeight: 700, fontSize: 14, color: 'var(--text)' }}>{entry.username}</div>
          {entry.full_name && (
            <div style={{ fontSize: 11, color: 'var(--muted)' }}>{entry.full_name}</div>
          )}
        </div>
        {canEdit && (
          <button
            className="btn btn-ghost"
            style={{ fontSize: 11, padding: '2px 8px', flexShrink: 0 }}
            onClick={() => onEdit(entry)}
          >Edit</button>
        )}
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', marginBottom: 'var(--space-2)' }}>
        <span style={{
          fontSize: 11, fontWeight: 600, padding: '2px 8px',
          borderRadius: 'var(--radius-sm)',
          background: `color-mix(in srgb, ${availColor(entry.availability)} 12%, transparent)`,
          color: availColor(entry.availability),
          border: `1px solid color-mix(in srgb, ${availColor(entry.availability)} 25%, transparent)`,
        }}>
          {availLabel(entry.availability)}
        </span>
        {entry.active_incident_count > 0 && (
          <span style={{
            fontSize: 11, padding: '2px 8px',
            borderRadius: 'var(--radius-sm)',
            background: 'var(--surface-2)', color: 'var(--muted)',
            border: '1px solid var(--border)',
          }}>
            {entry.active_incident_count} active incident{entry.active_incident_count !== 1 ? 's' : ''}
          </span>
        )}
      </div>

      {entry.skills.length > 0 ? (
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
          {entry.skills.map(s => (
            <span key={s} style={{
              background: 'var(--accent-soft)', color: 'var(--accent)',
              borderRadius: 'var(--radius-sm)', padding: '2px 6px',
              fontSize: 11, fontWeight: 600,
            }}>{s}</span>
          ))}
        </div>
      ) : (
        <div style={{ fontSize: 11, color: 'var(--dim)' }}>No skills listed.</div>
      )}

      {entry.notes && (
        <div style={{ marginTop: 'var(--space-2)', fontSize: 11, color: 'var(--muted)', fontStyle: 'italic' }}>
          {entry.notes}
        </div>
      )}
    </div>
  )
}

// ─── Main page ────────────────────────────────────────────────────────────────

export default function Roster() {
  const { user }                        = useAuth()
  const [items, setItems]               = useState([])
  const [loading, setLoading]           = useState(true)
  const [error, setError]               = useState(null)
  const [avFilter, setAvFilter]         = useState('')
  const [textFilter, setTextFilter]     = useState('')
  const [editEntry, setEditEntry]       = useState(null)

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const data = await api.listRoster({
        availability: avFilter || undefined,
        q: textFilter.trim() || undefined,
      })
      setItems(data.items ?? [])
    } catch (e) {
      setError(e.message ?? 'Failed to load roster')
    } finally {
      setLoading(false)
    }
  }, [avFilter, textFilter])

  useEffect(() => { load() }, [load])

  const handleSaved = useCallback((updated) => {
    setItems(prev => prev.map(e => e.user_id === updated.user_id ? updated : e))
    setEditEntry(null)
  }, [])

  const canEdit = (entry) =>
    user?.id === entry.user_id || user?.role === 'admin'

  return (
    <div className="panel">
      <div className="panel-toolbar" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 'var(--space-3)' }}>
        <div>
          <h2 className="panel-h" style={{ margin: 0 }}>IR Roster</h2>
          <div style={{ fontSize: 11, color: 'var(--dim)', marginTop: 2 }}>
            {items.length} responder{items.length !== 1 ? 's' : ''}
          </div>
        </div>
        <div style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'center' }}>
          <select
            className="input"
            style={{ fontSize: 12, padding: '4px 8px' }}
            value={avFilter}
            onChange={e => setAvFilter(e.target.value)}
          >
            <option value="">All availability</option>
            {AVAILABILITY_OPTIONS.map(o => (
              <option key={o.value} value={o.value}>{o.label}</option>
            ))}
          </select>
          <input
            className="input"
            style={{ fontSize: 12, padding: '4px 8px', width: 160 }}
            placeholder="Search name…"
            value={textFilter}
            onChange={e => setTextFilter(e.target.value)}
          />
        </div>
      </div>

      {error && (
        <div className="alert error" role="alert" style={{ margin: 'var(--space-3) var(--space-4)' }}>
          <span className="alert-icon">!</span><span>{error}</span>
        </div>
      )}

      {loading && (
        <div className="panel-empty"><div style={{ color: 'var(--muted)', fontSize: 13 }}>Loading…</div></div>
      )}

      {!loading && items.length === 0 && (
        <div className="panel-empty">
          <div className="panel-empty-mark" aria-hidden="true">?</div>
          <div style={{ fontSize: 13 }}>No responders found.</div>
        </div>
      )}

      {!loading && items.length > 0 && (
        <div style={{
          padding: 'var(--space-4)',
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fill, minmax(260px, 1fr))',
          gap: 'var(--space-3)',
        }}>
          {items.map(entry => (
            <ResponderCard
              key={entry.user_id}
              entry={entry}
              canEdit={canEdit(entry)}
              onEdit={setEditEntry}
            />
          ))}
        </div>
      )}

      {editEntry && (
        <EditProfileModal
          entry={editEntry}
          onClose={() => setEditEntry(null)}
          onSaved={handleSaved}
        />
      )}
    </div>
  )
}
