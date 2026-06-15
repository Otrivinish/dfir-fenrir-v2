import { useCallback, useEffect, useState } from 'react'
import { useOutletContext } from 'react-router-dom'
import { api } from '../../api/client.js'
import { useAuth } from '../../hooks/useAuth.jsx'
import { formatLocalShort, relative } from '../../lib/datetime.js'

// ── Vocabulary ────────────────────────────────────────────────────────────

const THREAD_STATUSES = ['active', 'pending', 'confirmed', 'ruled_out']
const PRIORITIES      = ['high', 'medium', 'low']

const THREAD_PILL = {
  active:    'pill-med',
  pending:   'pill-gray',
  confirmed: 'pill-ok',
  ruled_out: 'pill-gray',
}

const PRIORITY_PILL = {
  high:   'pill-crit',
  medium: 'pill-med',
  low:    'pill-gray',
}

function confColor(n) {
  if (n >= 70) return 'var(--ok)'
  if (n >= 40) return 'var(--high)'
  return 'var(--crit)'
}

// ── Generic list-item builder ─────────────────────────────────────────────
// fields: [{ key, label, type:'text'|'select'|'range', options?, default?, flex? }]

function ListBuilder({ items, onChange, fields, addLabel }) {
  const blank = () => Object.fromEntries(fields.map(f => [f.key, f.default ?? '']))
  const [draft, setDraft] = useState(blank)

  const add = () => {
    if (!String(draft[fields[0].key] ?? '').trim()) return
    onChange([...items, { ...draft }])
    setDraft(blank())
  }

  const remove  = (i) => onChange(items.filter((_, idx) => idx !== i))
  const updateAt = (i, key, val) =>
    onChange(items.map((item, idx) => idx === i ? { ...item, [key]: val } : item))

  const textFields   = fields.filter(f => !f.type || f.type === 'text')
  const selectFields = fields.filter(f => f.type === 'select')
  const rangeFields  = fields.filter(f => f.type === 'range')

  const renderFields = (values, onChange) => (
    <>
      {textFields.map(f => (
        <input
          key={f.key}
          className="input"
          value={values[f.key] ?? ''}
          onChange={e => onChange(f.key, e.target.value)}
          onKeyDown={e => { if (e.key === 'Enter') add() }}
          placeholder={f.label}
          style={{ flex: f.flex ?? 1, minWidth: 80, fontSize: 13, padding: '5px 8px' }}
        />
      ))}
      {selectFields.map(f => (
        <select
          key={f.key}
          className="select"
          value={values[f.key] ?? f.default}
          onChange={e => onChange(f.key, e.target.value)}
          style={{ width: 'auto', flex: '0 0 auto', minWidth: 110, fontSize: 11, padding: '3px 6px' }}
        >
          {(f.options ?? []).map(o => (
            <option key={o} value={o}>{o.replace('_', ' ')}</option>
          ))}
        </select>
      ))}
      {rangeFields.map(f => (
        <div key={f.key} style={{ display: 'flex', alignItems: 'center', gap: 4, flexShrink: 0 }}>
          <span style={{ fontSize: 10, fontFamily: 'var(--font-mono)', color: 'var(--muted)', minWidth: 46 }}>
            {f.label}: {values[f.key] ?? 50}%
          </span>
          <input
            type="range" min={0} max={100}
            value={values[f.key] ?? 50}
            onChange={e => onChange(f.key, +e.target.value)}
            style={{ width: 70 }}
          />
        </div>
      ))}
    </>
  )

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
      {items.map((item, i) => (
        <div key={i} style={{
          display: 'flex', gap: 6, alignItems: 'center',
          background: 'var(--surface-2)', border: '1px solid var(--border)',
          borderRadius: 'var(--radius-sm)', padding: '4px 8px',
        }}>
          {renderFields(item, (key, val) => updateAt(i, key, val))}
          <button
            type="button"
            onClick={() => remove(i)}
            style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--crit)', fontSize: 13, padding: '0 2px', flexShrink: 0 }}
          >✕</button>
        </div>
      ))}
      <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
        {renderFields(draft, (key, val) => setDraft(p => ({ ...p, [key]: val })))}
        <button
          type="button"
          className="btn ghost"
          onClick={add}
          style={{ fontSize: 11, flexShrink: 0, padding: '3px 10px' }}
        >
          {addLabel ?? '+ Add'}
        </button>
      </div>
    </div>
  )
}

// ── Questions builder (simple string list) ────────────────────────────────

function QuestionsBuilder({ questions, onChange }) {
  const [draft, setDraft] = useState('')
  const add = () => {
    if (!draft.trim()) return
    onChange([...questions, draft.trim()])
    setDraft('')
  }
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
      {questions.map((q, i) => (
        <div key={i} style={{
          display: 'flex', gap: 6, alignItems: 'center',
          background: 'var(--surface-2)', border: '1px solid var(--border)',
          borderRadius: 'var(--radius-sm)', padding: '4px 8px',
        }}>
          <span style={{ fontSize: 12, color: 'var(--accent)', flexShrink: 0 }}>?</span>
          <span style={{ flex: 1, fontSize: 12 }}>{q}</span>
          <button type="button"
            onClick={() => onChange(questions.filter((_, j) => j !== i))}
            style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--crit)', fontSize: 13, padding: '0 2px' }}>
            ✕
          </button>
        </div>
      ))}
      <div style={{ display: 'flex', gap: 6 }}>
        <input
          className="input"
          value={draft}
          onChange={e => setDraft(e.target.value)}
          onKeyDown={e => { if (e.key === 'Enter') add() }}
          placeholder="What is still unanswered?"
          style={{ flex: 1, fontSize: 12, padding: '3px 7px' }}
        />
        <button type="button" className="btn ghost"
                onClick={add}
                style={{ fontSize: 11, padding: '3px 10px', flexShrink: 0 }}>
          + Add
        </button>
      </div>
    </div>
  )
}

// ── Snapshot stat bar ─────────────────────────────────────────────────────

function SnapStats({ snap }) {
  if (!snap || !Object.keys(snap).length) return null
  const stats = [
    { label: 'Phase',     value: snap.phase?.replace(/_/g, ' ') },
    { label: 'Severity',  value: snap.severity },
    { label: 'IOCs',      value: snap.ioc_count },
    { label: 'Timeline',  value: snap.timeline_count },
    { label: 'Entities',  value: snap.entity_count },
    snap.compromised_count > 0 && { label: 'Compromised', value: snap.compromised_count },
    snap.playbook_total > 0 && { label: 'Playbook', value: `${snap.playbook_done}/${snap.playbook_total}` },
    snap.respond_total > 0 && { label: 'Actions', value: `${snap.respond_done}/${snap.respond_total}` },
  ].filter(Boolean)

  return (
    <div style={{
      display: 'flex', gap: 0, flexWrap: 'wrap',
      background: 'var(--surface-2)', border: '1px solid var(--border)',
      borderRadius: 'var(--radius)', marginBottom: 'var(--space-3)',
      overflow: 'hidden',
    }}>
      {stats.map((s, i) => (
        <div key={i} style={{
          padding: '6px 12px',
          borderRight: '1px solid var(--border)',
          textAlign: 'center',
          minWidth: 64,
        }}>
          <div style={{ fontSize: 14, fontWeight: 700, fontFamily: 'var(--font-mono)', color: 'var(--text)' }}>
            {s.value ?? '—'}
          </div>
          <div style={{ fontSize: 9, color: 'var(--dim)', fontFamily: 'var(--font-mono)', textTransform: 'uppercase', letterSpacing: 1 }}>
            {s.label}
          </div>
        </div>
      ))}
    </div>
  )
}

// ── Rich handoff card (read view) ─────────────────────────────────────────

function HandoffCard({ h, currentUserId, onAck }) {
  const isPending  = h.status === 'pending'
  const isIncoming = h.incoming_user_id === currentUserId
  const conf       = h.hypothesis_confidence ?? 50

  return (
    <div className="panel" style={{
      padding: 'var(--space-4)',
      borderLeft: `3px solid ${isPending ? 'var(--high)' : 'var(--ok)'}`,
    }}>
      {/* Header row */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 'var(--space-3)' }}>
        <div>
          <span style={{ fontWeight: 600 }}>{h.outgoing_username}</span>
          <span style={{ color: 'var(--muted)', margin: '0 6px' }}>→</span>
          <span style={{ fontWeight: 600 }}>{h.incoming_username}</span>
          <span style={{ marginLeft: 8, color: 'var(--dim)', fontSize: 12 }}
                title={h.created_at}>{relative(h.created_at)}</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
          <span className={`pill ${isPending ? 'pill-high' : 'pill-ok'}`} style={{ fontSize: 11 }}>
            {h.status}
          </span>
          {isIncoming && isPending && (
            <button className="btn" style={{ fontSize: 12, padding: '2px 10px' }} onClick={onAck}>
              Acknowledge
            </button>
          )}
        </div>
      </div>

      {/* Snapshot */}
      <SnapStats snap={h.snapshot_data} />

      {/* Status note */}
      {h.note && (
        <NoteBlock text={h.note} label="Status summary" borderColor="var(--border)" />
      )}

      {/* Warnings — amber highlight */}
      {h.warnings && (
        <div style={{
          background: 'color-mix(in srgb, var(--high) 8%, transparent)',
          border: '1px solid color-mix(in srgb, var(--high) 30%, transparent)',
          borderRadius: 'var(--radius)', padding: 'var(--space-2) var(--space-3)',
          marginBottom: 'var(--space-3)',
        }}>
          <div style={{ fontSize: 10, fontFamily: 'var(--font-mono)', fontWeight: 700, color: 'var(--high)', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 4 }}>
            ⚠ Warnings for incoming analyst
          </div>
          <div style={{ fontSize: 13, lineHeight: 1.6, whiteSpace: 'pre-wrap' }}>{h.warnings}</div>
        </div>
      )}

      {/* Hypothesis */}
      {h.current_hypothesis && (
        <Section label="Current working hypothesis">
          <div style={{ display: 'flex', gap: 'var(--space-3)', alignItems: 'flex-start' }}>
            <div style={{ flex: 1, fontSize: 13, fontStyle: 'italic', lineHeight: 1.6, color: 'var(--text)' }}>
              "{h.current_hypothesis}"
            </div>
            <div style={{ textAlign: 'center', flexShrink: 0 }}>
              <div style={{ fontSize: 20, fontWeight: 700, fontFamily: 'var(--font-mono)', color: confColor(conf) }}>
                {conf}%
              </div>
              <div style={{ fontSize: 9, color: 'var(--dim)', fontFamily: 'var(--font-mono)', textTransform: 'uppercase' }}>confidence</div>
            </div>
          </div>
        </Section>
      )}

      {/* Key findings */}
      {h.key_findings && (
        <Section label="Key findings">
          <div style={{ fontSize: 13, color: 'var(--muted)', lineHeight: 1.6, whiteSpace: 'pre-wrap' }}>{h.key_findings}</div>
        </Section>
      )}

      {/* Investigation threads */}
      {h.threads?.length > 0 && (
        <Section label={`Investigation threads (${h.threads.length})`}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            {h.threads.map((t, i) => (
              <div key={i} style={{
                background: 'var(--surface-2)', border: '1px solid var(--border)',
                borderRadius: 'var(--radius-sm)', padding: '6px 10px',
                display: 'flex', alignItems: 'center', gap: 8,
              }}>
                <span className={`pill ${THREAD_PILL[t.status] ?? 'pill-gray'}`} style={{ fontSize: 10, flexShrink: 0 }}>
                  {t.status?.replace('_', ' ')}
                </span>
                <span style={{ flex: 1, fontSize: 13, fontWeight: 500 }}>{t.label}</span>
                <div style={{ display: 'flex', alignItems: 'center', gap: 4, flexShrink: 0 }}>
                  <div style={{ width: 48, height: 3, background: 'var(--surface)', borderRadius: 2, overflow: 'hidden' }}>
                    <div style={{ width: `${t.confidence ?? 50}%`, height: '100%', background: confColor(t.confidence ?? 50) }} />
                  </div>
                  <span style={{ fontSize: 10, fontFamily: 'var(--font-mono)', color: 'var(--dim)', minWidth: 28 }}>
                    {t.confidence ?? 50}%
                  </span>
                </div>
                {t.notes && <span style={{ fontSize: 11, color: 'var(--muted)', fontStyle: 'italic', flexShrink: 0 }}>{t.notes}</span>}
              </div>
            ))}
          </div>
        </Section>
      )}

      {/* Next steps */}
      {h.next_steps?.length > 0 && (
        <Section label="Next steps for incoming analyst">
          <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
            {h.next_steps.map((s, i) => (
              <div key={i} style={{ display: 'flex', alignItems: 'baseline', gap: 8 }}>
                <span className={`pill ${PRIORITY_PILL[s.priority] ?? 'pill-gray'}`} style={{ fontSize: 9 }}>{s.priority}</span>
                <span style={{ fontSize: 13 }}>{s.action}</span>
              </div>
            ))}
          </div>
        </Section>
      )}

      {/* Pending */}
      {h.pending?.length > 0 && (
        <Section label="Pending investigation">
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            {h.pending.map((p, i) => (
              <div key={i} style={{
                borderLeft: `2px solid var(--${p.priority === 'high' ? 'crit' : p.priority === 'medium' ? 'high' : 'border'})`,
                paddingLeft: 8,
              }}>
                <div style={{ display: 'flex', gap: 8, alignItems: 'baseline' }}>
                  <span className={`pill ${PRIORITY_PILL[p.priority] ?? 'pill-gray'}`} style={{ fontSize: 9 }}>{p.priority}</span>
                  <span style={{ fontSize: 13 }}>{p.item}</span>
                </div>
                {p.notes && <div style={{ fontSize: 11, color: 'var(--dim)', marginTop: 2 }}>{p.notes}</div>}
              </div>
            ))}
          </div>
        </Section>
      )}

      {/* Ruled out */}
      {h.ruled_out?.length > 0 && (
        <Section label="Ruled out">
          <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
            {h.ruled_out.map((r, i) => (
              <div key={i} style={{ display: 'flex', gap: 8, alignItems: 'baseline' }}>
                <span style={{ fontSize: 13, color: 'var(--dim)', textDecoration: 'line-through', flex: 1 }}>{r.item}</span>
                <span style={{ fontSize: 12, color: 'var(--muted)', fontStyle: 'italic' }}>{r.reason}</span>
              </div>
            ))}
          </div>
        </Section>
      )}

      {/* Open questions */}
      {h.open_questions?.length > 0 && (
        <Section label="Open questions">
          <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
            {h.open_questions.map((q, i) => (
              <div key={i} style={{ fontSize: 13 }}>
                <span style={{ color: 'var(--accent)', marginRight: 6 }}>?</span>{q}
              </div>
            ))}
          </div>
        </Section>
      )}

      {/* ACK note */}
      {h.acknowledged_note && (
        <NoteBlock
          text={h.acknowledged_note}
          label={`ACK · ${formatLocalShort(h.acknowledged_at)}`}
          borderColor="var(--ok)"
          style={{ marginTop: 'var(--space-2)' }}
        />
      )}
    </div>
  )
}

function Section({ label, children }) {
  return (
    <div style={{ marginBottom: 'var(--space-3)' }}>
      <div style={{ fontSize: 10, color: 'var(--dim)', fontFamily: 'var(--font-mono)', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 6 }}>
        {label}
      </div>
      {children}
    </div>
  )
}

function NoteBlock({ text, label, borderColor, style: extraStyle }) {
  return (
    <div style={{
      background: 'var(--surface-2)', borderRadius: 'var(--radius)',
      padding: 'var(--space-3)', fontSize: 13,
      whiteSpace: 'pre-wrap', borderLeft: `3px solid ${borderColor}`,
      marginBottom: 'var(--space-3)',
      ...extraStyle,
    }}>
      {label && (
        <span style={{ color: 'var(--muted)', fontSize: 11, display: 'block', marginBottom: 4 }}>{label}</span>
      )}
      {text}
    </div>
  )
}

// ── Acknowledge modal ─────────────────────────────────────────────────────

function AckModal({ incidentId, handoff, onClose, onAcked }) {
  const [note,   setNote]   = useState('')
  const [saving, setSaving] = useState(false)
  const [err,    setErr]    = useState('')

  async function submit(e) {
    e.preventDefault()
    setSaving(true); setErr('')
    try {
      const updated = await api.acknowledgeHandoff(incidentId, handoff.id, {
        acknowledged_note: note.trim() || null,
      })
      onAcked(updated)
      onClose()
    } catch (e) {
      setErr(e.message || 'Acknowledge failed')
      setSaving(false)
    }
  }

  return (
    <div className="modal-backdrop">
      <div className="modal" style={{ maxWidth: 480 }}>
        <div className="modal-head">
          <span className="modal-title">Acknowledge handoff</span>
          <button className="modal-close" onClick={onClose} type="button">✕</button>
        </div>
        <form className="modal-body" onSubmit={submit}>
          {handoff.note && (
            <NoteBlock text={handoff.note} label="Status summary" borderColor="var(--border)" />
          )}
          {err && <div className="form-error">{err}</div>}
          <label className="form-label">Acknowledgment note (optional)</label>
          <textarea className="input" rows={3} value={note}
            onChange={e => setNote(e.target.value)}
            placeholder="Anything to pass back to the outgoing analyst…" />
          <div className="modal-actions" style={{ marginTop: 'var(--space-4)' }}>
            <button type="button" className="btn" onClick={onClose} disabled={saving}>Cancel</button>
            <button type="submit" className="btn primary" disabled={saving}>
              {saving ? 'Saving…' : 'Acknowledge'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ── Create handoff modal ──────────────────────────────────────────────────

const EMPTY_FORM = {
  incoming_user_id:      '',
  note:                  '',
  current_hypothesis:    '',
  hypothesis_confidence: 70,
  key_findings:          '',
  warnings:              '',
  threads:               [],
  ruled_out:             [],
  pending:               [],
  next_steps:            [],
  open_questions:        [],
}

function HandoffModal({ incidentId, currentUser, onClose, onCreated }) {
  const [users,   setUsers]   = useState([])
  const [form,    setForm]    = useState({ ...EMPTY_FORM })
  const [saving,  setSaving]  = useState(false)
  const [err,     setErr]     = useState('')

  useEffect(() => {
    api.listAssignableUsers()
      .then(u => setUsers(u.filter(x => x.id !== currentUser?.id)))
      .catch(() => {})
  }, [currentUser])

  const fv = key => e => setForm(p => ({ ...p, [key]: e.target.value }))
  const fn = key => e => setForm(p => ({ ...p, [key]: +e.target.value }))
  const fl = key => val => setForm(p => ({ ...p, [key]: val }))

  async function submit(e) {
    e.preventDefault()
    if (!form.incoming_user_id) { setErr('Select an incoming analyst'); return }
    setSaving(true); setErr('')
    try {
      const payload = {
        incoming_user_id:      form.incoming_user_id,
        note:                  form.note.trim() || null,
        current_hypothesis:    form.current_hypothesis.trim() || null,
        hypothesis_confidence: form.hypothesis_confidence,
        key_findings:          form.key_findings.trim() || null,
        warnings:              form.warnings.trim() || null,
        threads:               form.threads,
        ruled_out:             form.ruled_out,
        pending:               form.pending,
        next_steps:            form.next_steps,
        open_questions:        form.open_questions,
      }
      const created = await api.createHandoff(incidentId, payload)
      onCreated(created)
      onClose()
    } catch (e) {
      setErr(e.message || 'Handoff failed')
      setSaving(false)
    }
  }

  const SectionHead = ({ label }) => (
    <div style={{ fontSize: 10, fontFamily: 'var(--font-mono)', color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 4, marginTop: 'var(--space-3)' }}>
      {label}
    </div>
  )

  return (
    <div className="modal-backdrop">
      <div className="modal" role="dialog" style={{ maxWidth: 640 }}>
        <div className="modal-head">
          <span className="modal-title">Create handoff</span>
          <button className="modal-close" onClick={onClose} type="button" disabled={saving}>✕</button>
        </div>
        <form onSubmit={submit}>
          <div className="modal-body" style={{ maxHeight: '72vh', overflowY: 'auto' }}>
            <p style={{ color: 'var(--muted)', fontSize: 13, marginTop: 0, marginBottom: 'var(--space-3)' }}>
              Records a shift-change snapshot and notifies the incoming analyst.
            </p>
            {err && <div className="form-error" style={{ marginBottom: 'var(--space-2)' }}>{err}</div>}

            {/* ── Incoming analyst ── */}
            <div className="field">
              <label className="field-label" htmlFor="hm-incoming">Incoming analyst *</label>
              <select id="hm-incoming" className="select" value={form.incoming_user_id}
                      onChange={fv('incoming_user_id')} required>
                <option value="">— select —</option>
                {users.map(u => (
                  <option key={u.id} value={u.id}>
                    {u.username}{u.full_name ? ` (${u.full_name})` : ''}
                  </option>
                ))}
              </select>
            </div>

            {/* ── Status summary ── */}
            <div className="field">
              <label className="field-label" htmlFor="hm-note">Status summary</label>
              <textarea id="hm-note" className="input" rows={3} value={form.note}
                        onChange={fv('note')}
                        placeholder="Current status, open tasks, next steps, watch-outs…" />
            </div>

            {/* ── Warnings ── */}
            <div className="field">
              <label className="field-label" htmlFor="hm-warn" style={{ color: 'var(--high)' }}>
                ⚠ Warnings / gotchas for incoming analyst
              </label>
              <textarea id="hm-warn" className="input" rows={2} value={form.warnings}
                        onChange={fv('warnings')}
                        placeholder="Traps, dead ends, tools that don't work, things that look interesting but aren't…"
                        style={{ borderColor: 'color-mix(in srgb, var(--high) 40%, var(--border))' }} />
            </div>

            {/* ── Hypothesis ── */}
            <SectionHead label="Current working hypothesis" />
            <div className="field">
              <textarea className="input" rows={2} value={form.current_hypothesis}
                        onChange={fv('current_hypothesis')}
                        placeholder="What do you currently believe is happening?" />
            </div>
            <div className="field">
              <label className="field-label">
                Hypothesis confidence: <span style={{ fontFamily: 'var(--font-mono)', color: confColor(form.hypothesis_confidence) }}>
                  {form.hypothesis_confidence}%
                </span>
              </label>
              <input type="range" min={0} max={100} value={form.hypothesis_confidence}
                     onChange={fn('hypothesis_confidence')} style={{ width: '100%' }} />
            </div>

            {/* ── Key findings ── */}
            <div className="field">
              <label className="field-label" htmlFor="hm-findings">Key findings (established facts)</label>
              <textarea id="hm-findings" className="input" rows={2} value={form.key_findings}
                        onChange={fv('key_findings')}
                        placeholder="What has been confirmed as fact?" />
            </div>

            {/* ── Investigation threads ── */}
            <SectionHead label="Investigation threads" />
            <ListBuilder
              items={form.threads}
              onChange={fl('threads')}
              addLabel="+ Thread"
              fields={[
                { key: 'label',      label: 'Thread label', flex: 2 },
                { key: 'status',     type: 'select', default: 'active', options: THREAD_STATUSES },
                { key: 'confidence', type: 'range',  label: 'Conf',     default: 50 },
                { key: 'notes',      label: 'Notes…', flex: 2 },
              ]}
            />

            {/* ── Next steps ── */}
            <SectionHead label="Next steps for incoming analyst" />
            <ListBuilder
              items={form.next_steps}
              onChange={fl('next_steps')}
              addLabel="+ Step"
              fields={[
                { key: 'action',   label: 'Action', flex: 3 },
                { key: 'priority', type: 'select', default: 'high', options: PRIORITIES },
              ]}
            />

            {/* ── Pending ── */}
            <SectionHead label="Pending / not yet investigated" />
            <ListBuilder
              items={form.pending}
              onChange={fl('pending')}
              addLabel="+ Pending"
              fields={[
                { key: 'item',     label: 'What to investigate', flex: 2 },
                { key: 'priority', type: 'select', default: 'medium', options: PRIORITIES },
                { key: 'notes',    label: 'Context…', flex: 2 },
              ]}
            />

            {/* ── Ruled out ── */}
            <SectionHead label="Ruled out" />
            <ListBuilder
              items={form.ruled_out}
              onChange={fl('ruled_out')}
              addLabel="+ Ruled Out"
              fields={[
                { key: 'item',   label: 'What was ruled out', flex: 1 },
                { key: 'reason', label: 'Why / evidence',     flex: 2 },
              ]}
            />

            {/* ── Open questions ── */}
            <SectionHead label="Open questions" />
            <QuestionsBuilder
              questions={form.open_questions}
              onChange={fl('open_questions')}
            />
          </div>

          <div className="modal-foot">
            <button type="button" className="btn ghost" onClick={onClose} disabled={saving}>Cancel</button>
            <button type="submit" className="btn primary" disabled={saving}>
              {saving ? 'Sending…' : 'Send handoff'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ── Main component ────────────────────────────────────────────────────────

export default function IncidentHandoffs() {
  const { inc: incident } = useOutletContext()
  const { user } = useAuth()
  const incidentId = incident?.id
  const isClosed   = incident?.status === 'closed'

  const [items,   setItems]   = useState([])
  const [loading, setLoading] = useState(true)
  const [err,     setErr]     = useState('')
  const [modal,   setModal]   = useState(null)   // null | 'create' | handoff-for-ack

  const load = useCallback(async () => {
    if (!incidentId) return
    setErr('')
    try {
      const res = await api.listHandoffs(incidentId)
      setItems(res.items)
    } catch (e) {
      setErr(e.message || 'Could not load handoffs')
    } finally {
      setLoading(false)
    }
  }, [incidentId])

  useEffect(() => { load() }, [load])

  const canCreate = !isClosed && user?.role !== 'viewer'

  return (
    <section className="panel">
      <div className="panel-toolbar">
        <div>
          <h2 className="panel-h" style={{ marginBottom: 0 }}>Handoff log</h2>
        </div>
        {canCreate && (
          <button className="btn primary" onClick={() => setModal('create')}>+ Handoff</button>
        )}
      </div>

      {err && <div className="alert error" role="alert"><span className="alert-icon">!</span><span>{err}</span></div>}

      {loading ? (
        <div className="panel-empty"><div>Loading…</div></div>
      ) : items.length === 0 ? (
        <div className="panel-empty">
          <div className="panel-empty-mark">↔</div>
          <div>No handoffs recorded yet.</div>
          {canCreate && (
            <div><button className="btn primary" onClick={() => setModal('create')}>Create first handoff</button></div>
          )}
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
          {items.map(h => (
            <HandoffCard
              key={h.id}
              h={h}
              currentUserId={user?.id}
              onAck={() => setModal(h)}
            />
          ))}
        </div>
      )}

      {modal === 'create' && (
        <HandoffModal
          incidentId={incidentId}
          currentUser={user}
          onClose={() => setModal(null)}
          onCreated={(h) => setItems(prev => [h, ...prev])}
        />
      )}
      {modal && modal !== 'create' && (
        <AckModal
          incidentId={incidentId}
          handoff={modal}
          onClose={() => setModal(null)}
          onAcked={(updated) => setItems(prev => prev.map(h => h.id === updated.id ? updated : h))}
        />
      )}
    </section>
  )
}
