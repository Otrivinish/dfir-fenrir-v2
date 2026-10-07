import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useOutletContext } from 'react-router-dom'
import { api } from '../../../api/client.js'
import { useAuth } from '../../../hooks/useAuth.jsx'
import { useDialogFocus } from '../../../hooks/useDialogFocus.js'
import { formatLocal } from '../../../lib/datetime.js'

// ─── Vocabulary ──────────────────────────────────────────────────────────────

export const TYPE_LABELS = {
  internal:        'Internal',
  legal:           'Legal',
  regulatory:      'Regulatory',
  law_enforcement: 'Law Enforcement',
  media_pr:        'Media / PR',
  vendor:          'Vendor',
  ir_firm:         'IR Firm',
  customer:        'Customer',
  insurer:         'Insurer',
  board:           'Board',
  supervisory_authority: 'Supervisory Authority',
  csirt:           'CSIRT',
  other:           'Other',
}

export const TYPE_COLORS = {
  internal:        'var(--accent)',
  legal:           'var(--med)',
  regulatory:      'var(--high)',
  law_enforcement: 'var(--crit)',
  media_pr:        'var(--ok)',
  vendor:          'var(--muted)',
  ir_firm:         'var(--accent)',
  customer:        'var(--ok)',
  insurer:         'var(--med)',
  board:           'var(--high)',
  // E2 types: tokens with >= 4.5:1 text contrast on --surface in all three themes (--high is 3.6:1 in nordic-calm)
  supervisory_authority: 'var(--crit)',
  csirt:           'var(--low)',
  other:           'var(--dim)',
}

export const CHANNEL_LABELS = {
  email:       'Email',
  phone:       'Phone',
  mobile:      'Mobile',
  signal:      'Signal',
  whatsapp:    'WhatsApp',
  telegram:    'Telegram',
  teams:       'Teams',
  slack:       'Slack',
  secure_fax:  'Secure Fax',
  in_person:   'In Person',
}

export const CHANNEL_OPTS = Object.entries(CHANNEL_LABELS).map(([value, label]) => ({ value, label }))
const TYPE_OPTS    = Object.entries(TYPE_LABELS).map(([value, label]) => ({ value, label }))

// CSV column → channel mapping for bulk import
const CSV_CHANNEL_COLS = ['email', 'phone', 'mobile', 'signal', 'whatsapp', 'telegram', 'teams', 'slack']

// ─── CSV parser ──────────────────────────────────────────────────────────────

function parseCsvRow(line) {
  const result = []
  let cur = '', inQuote = false
  for (let i = 0; i < line.length; i++) {
    const ch = line[i]
    if (ch === '"') {
      if (inQuote && line[i + 1] === '"') { cur += '"'; i++ }
      else inQuote = !inQuote
    } else if (ch === ',' && !inQuote) {
      result.push(cur.trim()); cur = ''
    } else {
      cur += ch
    }
  }
  result.push(cur.trim())
  return result
}

function parseCsv(text) {
  const lines = text.split(/\r?\n/).filter(l => l.trim())
  if (lines.length < 2) return { headers: [], rows: [] }
  const headers = parseCsvRow(lines[0]).map(h => h.toLowerCase().replace(/\s+/g, '_'))
  const rows = lines.slice(1).map(line => {
    const vals = parseCsvRow(line)
    const obj = {}
    headers.forEach((h, i) => { obj[h] = vals[i] || '' })
    return obj
  }).filter(r => r.name)
  return { headers, rows }
}

function csvRowToStakeholder(row) {
  const contact_methods = []
  for (const ch of CSV_CHANNEL_COLS) {
    if (row[ch]) {
      contact_methods.push({ channel: ch, value: row[ch], preferred: false, notes: '' })
    }
  }
  return {
    name:            row.name || '',
    title:           row.title || '',
    organization:    row.organization || row.org || '',
    type:            TYPE_OPTS.find(o => o.value === (row.type || '').toLowerCase()) ? row.type.toLowerCase() : 'other',
    available_hours: row.available_hours || '',
    notes:           row.notes || '',
    contact_methods,
  }
}

// ─── Empty form ───────────────────────────────────────────────────────────────

const EMPTY_FORM = {
  name: '', title: '', organization: '', type: 'other',
  available_hours: '', notes: '',
  contact_methods: [],
}

const EMPTY_METHOD = { channel: 'email', value: '', preferred: false, notes: '' }

// ─── Incident tab: the board over this incident's stakeholders ──────────────

export default function Stakeholders() {
  const { inc, isClosed } = useOutletContext()
  const { user } = useAuth()
  const [pickerOpen, setPickerOpen] = useState(false)
  const [reloadToken, setReloadToken] = useState(0)

  const source = useMemo(() => ({
    list:   ()            => api.listStakeholders(inc.id).then(d => d.items || []),
    create: (payload)     => api.createStakeholder(inc.id, payload),
    update: (id, payload) => api.updateStakeholder(inc.id, id, payload),
    remove: (id)          => api.deleteStakeholder(inc.id, id),
    bulk:   (payload)     => api.bulkCreateStakeholders(inc.id, payload),
  }), [inc.id])

  // The Contacts directory is readable by analysts and admins (GET /api/contacts).
  const canUseDirectory = !isClosed && (user?.role === 'admin' || user?.role === 'analyst')

  return (
    <>
      <StakeholderBoard
        source={source}
        readOnly={isClosed || user?.role === 'viewer'}
        reloadToken={reloadToken}
        toolbarExtra={canUseDirectory && (
          <button className="btn" type="button" onClick={() => setPickerOpen(true)}>Add from directory</button>
        )}
      />
      {pickerOpen && (
        <DirectoryPicker
          incidentId={inc.id}
          onAdded={() => setReloadToken(n => n + 1)}
          onClose={() => setPickerOpen(false)}
        />
      )}
    </>
  )
}

// ─── The board (incident Stakeholders tab + Prepare → Contacts) ──────────────
// `source` is the data API: { list() → items, create(p), update(id, p), remove(id), bulk?(p) }.
// The board holds no rules of its own; the API enforces who may write.

export function StakeholderBoard({
  source, readOnly, title = 'Stakeholders', toolbarExtra = null, cardExtra = null, reloadToken = 0,
  emptyText = 'No stakeholders yet.', emptyHint = 'Add individual contacts or bulk-import from CSV.',
  deleteConfirm = 'Remove this stakeholder?', noun = 'stakeholder',
}) {
  const [items,        setItems]        = useState([])
  const [loading,      setLoading]      = useState(true)
  const [error,        setError]        = useState('')
  const [typeFilter,   setTypeFilter]   = useState('')
  const [search,       setSearch]       = useState('')

  const [editTarget,   setEditTarget]   = useState(null)  // null | {} | existing row
  const [saving,       setSaving]       = useState(false)

  const [importOpen,   setImportOpen]   = useState(false)
  const [csvText,      setCsvText]      = useState('')
  const [csvPreview,   setCsvPreview]   = useState(null)   // parsed rows
  const [importing,    setImporting]    = useState(false)
  const [importResult, setImportResult] = useState(null)

  const load = useCallback(async () => {
    setError('')
    try {
      setItems(await source.list())
    } catch (e) {
      setError(e.message || 'Failed to load stakeholders')
    } finally {
      setLoading(false)
    }
  }, [source])

  useEffect(() => { load() }, [load, reloadToken])

  const replaceItem = useCallback((updated) => {
    setItems(prev => prev.map(s => s.id === updated.id ? updated : s))
  }, [])

  const filtered = useMemo(() => {
    let list = items
    if (typeFilter) list = list.filter(s => s.type === typeFilter)
    if (search) {
      const q = search.toLowerCase()
      list = list.filter(s =>
        s.name.toLowerCase().includes(q) ||
        (s.organization || '').toLowerCase().includes(q) ||
        (s.title || '').toLowerCase().includes(q)
      )
    }
    return list
  }, [items, typeFilter, search])

  const openAdd  = () => setEditTarget({ ...EMPTY_FORM, contact_methods: [] })
  const openEdit = (s) => setEditTarget({
    _id: s.id,
    name: s.name, title: s.title || '', organization: s.organization || '',
    type: s.type, available_hours: s.available_hours || '', notes: s.notes || '',
    contact_methods: s.contact_methods.map(m => ({ ...m })),
  })

  const onSave = async (form) => {
    setSaving(true); setError('')
    try {
      const payload = {
        name:            form.name,
        title:           form.title || null,
        organization:    form.organization || null,
        type:            form.type,
        available_hours: form.available_hours || null,
        notes:           form.notes || null,
        contact_methods: form.contact_methods.filter(m => m.value.trim()),
      }
      if (form._id) {
        replaceItem(await source.update(form._id, payload))
      } else {
        const created = await source.create(payload)
        setItems(prev => [...prev, created])
      }
      setEditTarget(null)
    } catch (e) {
      setError(e.message || 'Save failed')
    } finally {
      setSaving(false)
    }
  }

  const onDelete = async (id) => {
    if (!confirm(deleteConfirm)) return
    try {
      await source.remove(id)
      setItems(prev => prev.filter(s => s.id !== id))
    } catch (e) {
      setError(e.message || 'Delete failed')
    }
  }

  const parseCsvPreview = () => {
    const { rows } = parseCsv(csvText)
    setCsvPreview(rows.map(csvRowToStakeholder))
  }

  const runImport = async () => {
    if (!csvPreview?.length) return
    setImporting(true); setImportResult(null)
    try {
      const result = await source.bulk({ rows: csvPreview })
      setImportResult(result)
      if (result.created > 0) await load()
    } catch (e) {
      setImportResult({ created: 0, errors: [e.message || 'Import failed'] })
    } finally {
      setImporting(false)
    }
  }

  const closeImport = () => {
    setImportOpen(false); setCsvText(''); setCsvPreview(null); setImportResult(null)
  }

  return (
    <section className="panel">
      <div className="panel-toolbar">
        <h2 className="panel-h">{title}</h2>
        <div style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'center' }}>
          <input
            className="input"
            placeholder="Search…"
            value={search}
            onChange={e => setSearch(e.target.value)}
            style={{ width: 160 }}
          />
          <select className="select" value={typeFilter} onChange={e => setTypeFilter(e.target.value)}>
            <option value="">All types</option>
            {TYPE_OPTS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
          </select>
          {toolbarExtra}
          {!readOnly && (
            <>
              {source.bulk && <button className="btn" type="button" onClick={() => setImportOpen(true)}>Import CSV</button>}
              <button className="btn primary" type="button" onClick={openAdd}>+ Add</button>
            </>
          )}
        </div>
      </div>

      {error && (
        <div className="alert error" role="alert">
          <span className="alert-icon">!</span><span>{error}</span>
        </div>
      )}

      {loading ? (
        <div className="panel-empty"><div>Loading…</div></div>
      ) : filtered.length === 0 ? (
        <div className="panel-empty">
          <div className="panel-empty-mark" aria-hidden="true">◎</div>
          <div>{items.length === 0 ? emptyText : 'No matches.'}</div>
          {items.length === 0 && !readOnly && emptyHint && (
            <div style={{ color: 'var(--dim)', fontSize: 12 }}>
              {emptyHint}
            </div>
          )}
        </div>
      ) : (
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fill, minmax(min(300px, 100%), 1fr))',   // one column on a narrow screen, never wider than it
          gap: 'var(--space-3)',
          marginTop: 'var(--space-2)',
        }}>
          {filtered.map(s => (
            <StakeholderCard
              key={s.id}
              stakeholder={s}
              readOnly={readOnly}
              extra={cardExtra && cardExtra(s, replaceItem)}
              onEdit={() => openEdit(s)}
              onDelete={() => onDelete(s.id)}
            />
          ))}
        </div>
      )}

      {editTarget && (
        <StakeholderModal
          form={editTarget}
          noun={noun}
          saving={saving}
          onSave={onSave}
          onClose={() => setEditTarget(null)}
        />
      )}

      {importOpen && (
        <ImportModal
          csvText={csvText}
          setCsvText={setCsvText}
          preview={csvPreview}
          result={importResult}
          importing={importing}
          onParse={parseCsvPreview}
          onImport={runImport}
          onClose={closeImport}
        />
      )}
    </section>
  )
}

// ─── Stakeholder card ────────────────────────────────────────────────────────

function StakeholderCard({ stakeholder: s, readOnly, extra, onEdit, onDelete }) {
  const typeColor = TYPE_COLORS[s.type] || 'var(--dim)'
  const preferred = s.contact_methods.find(m => m.preferred) || s.contact_methods[0]

  return (
    <div style={{
      background: 'var(--surface)',
      border: '1px solid var(--border)',
      borderTop: `3px solid ${typeColor}`,
      borderRadius: 'var(--radius)',
      padding: 'var(--space-3)',
      display: 'flex',
      flexDirection: 'column',
      gap: 'var(--space-2)',
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div style={{ minWidth: 0, overflowWrap: 'anywhere' }}>
          <div style={{ fontWeight: 600, fontSize: 14 }}>{s.name}</div>
          {(s.title || s.organization) && (
            <div style={{ fontSize: 12, color: 'var(--muted)', marginTop: 2 }}>
              {[s.title, s.organization].filter(Boolean).join(' · ')}
            </div>
          )}
        </div>
        <span style={{
          fontFamily: 'var(--font-mono)',
          fontSize: 9,
          color: typeColor,
          border: `1px solid ${typeColor}`,
          borderRadius: 'var(--radius-sm)',
          padding: '2px 6px',
          textTransform: 'uppercase',
          whiteSpace: 'nowrap',
          marginLeft: 'var(--space-2)',
        }}>
          {TYPE_LABELS[s.type] || s.type}
        </span>
      </div>

      {s.contact_methods.length > 0 && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
          {s.contact_methods.map((m, i) => (
            <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', fontSize: 12 }}>
              <span style={{
                fontFamily: 'var(--font-mono)',
                fontSize: 10,
                color: m.preferred ? 'var(--accent)' : 'var(--muted)',
                minWidth: 64,
              }}>
                {m.preferred && '★ '}{CHANNEL_LABELS[m.channel] || m.channel}
              </span>
              <span style={{ color: 'var(--text)', fontFamily: 'var(--font-mono)', fontSize: 11 }}>
                {m.value}
              </span>
              {m.notes && (
                <span style={{ color: 'var(--dim)', fontSize: 10 }}>({m.notes})</span>
              )}
            </div>
          ))}
        </div>
      )}

      {s.available_hours && (
        <div style={{ fontSize: 11, color: 'var(--muted)' }}>
          <span style={{ color: 'var(--dim)' }}>Available: </span>{s.available_hours}
        </div>
      )}

      {s.notes && (
        <div style={{
          fontSize: 12, color: 'var(--muted)',
          borderTop: '1px solid var(--border)', paddingTop: 'var(--space-2)',
          overflow: 'hidden',
          display: '-webkit-box', WebkitLineClamp: 2, WebkitBoxOrient: 'vertical',
        }}>
          {s.notes}
        </div>
      )}

      {extra}

      {!readOnly && (
        <div style={{
          display: 'flex', gap: 'var(--space-2)', justifyContent: 'flex-end',
          borderTop: '1px solid var(--border)', paddingTop: 'var(--space-2)', marginTop: 'auto',
        }}>
          <button className="btn" type="button" onClick={onEdit}>Edit</button>
          <button className="btn" type="button" style={{ color: 'var(--crit)' }} onClick={onDelete}>Remove</button>
        </div>
      )}
    </div>
  )
}

// ─── Add / edit modal ────────────────────────────────────────────────────────

function StakeholderModal({ form: initialForm, noun, saving, onSave, onClose }) {
  const [form, setForm] = useState(initialForm)

  const set = (k) => (e) => setForm(f => ({ ...f, [k]: e.target.value }))

  const addMethod = () =>
    setForm(f => ({ ...f, contact_methods: [...f.contact_methods, { ...EMPTY_METHOD }] }))

  const removeMethod = (i) =>
    setForm(f => ({ ...f, contact_methods: f.contact_methods.filter((_, j) => j !== i) }))

  const updateMethod = (i, k, v) =>
    setForm(f => ({
      ...f,
      contact_methods: f.contact_methods.map((m, j) =>
        j === i ? (k === 'preferred'
          ? { ...m, preferred: v }   // toggle preferred — only one can be preferred
          : { ...m, [k]: v })
        : (k === 'preferred' && v ? { ...m, preferred: false } : m)
      ),
    }))

  const submit = (e) => {
    e.preventDefault()
    if (!form.name.trim()) return
    onSave(form)
  }

  return (
    <div className="modal-backdrop">
      <div className="modal" style={{ maxWidth: 560, width: '100%' }} onClick={e => e.stopPropagation()}>
        <div className="modal-head">
          <h3 className="modal-title">{form._id ? `Edit ${noun}` : `Add ${noun}`}</h3>
          <button className="modal-close" type="button" onClick={onClose}>✕</button>
        </div>

        <form onSubmit={submit} style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--space-3)' }}>
            <div>
              <label className="label">Name *</label>
              <input className="input" value={form.name} onChange={set('name')} required maxLength={255} />
            </div>
            <div>
              <label className="label">Type</label>
              <select className="select" value={form.type} onChange={set('type')}>
                {TYPE_OPTS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
              </select>
            </div>
            <div>
              <label className="label">Title / Role</label>
              <input className="input" value={form.title} onChange={set('title')} maxLength={128} placeholder="e.g. CISO" />
            </div>
            <div>
              <label className="label">Organization</label>
              <input className="input" value={form.organization} onChange={set('organization')} maxLength={256} />
            </div>
          </div>

          <div>
            <label className="label">Available hours</label>
            <input className="input" value={form.available_hours} onChange={set('available_hours')} maxLength={64} placeholder="e.g. 24/7 or 09:00–17:00 CET" />
          </div>

          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 'var(--space-2)' }}>
              <label className="label" style={{ margin: 0 }}>Contact methods</label>
              <button className="btn" type="button" onClick={addMethod}>+ Add</button>
            </div>
            {form.contact_methods.length === 0 && (
              <div style={{ fontSize: 12, color: 'var(--dim)', padding: 'var(--space-2) 0' }}>
                No contact methods yet.
              </div>
            )}
            {form.contact_methods.map((m, i) => (
              <div key={i} style={{ display: 'grid', gridTemplateColumns: '120px 1fr 80px auto', gap: 'var(--space-2)', marginBottom: 'var(--space-2)', alignItems: 'center' }}>
                <select className="select" value={m.channel} onChange={e => updateMethod(i, 'channel', e.target.value)}>
                  {CHANNEL_OPTS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
                </select>
                <input
                  className="input"
                  value={m.value}
                  onChange={e => updateMethod(i, 'value', e.target.value)}
                  placeholder="Address / number / handle"
                  maxLength={512}
                />
                <label style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 12, color: 'var(--muted)', cursor: 'pointer', whiteSpace: 'nowrap' }}>
                  <input
                    type="checkbox"
                    checked={m.preferred}
                    onChange={e => updateMethod(i, 'preferred', e.target.checked)}
                    style={{ accentColor: 'var(--accent)' }}
                  />
                  Preferred
                </label>
                <button
                  className="btn"
                  type="button"
                  style={{ color: 'var(--crit)' }}
                  onClick={() => removeMethod(i)}
                >✕</button>
              </div>
            ))}
          </div>

          <div>
            <label className="label">Notes</label>
            <textarea className="input" value={form.notes} onChange={set('notes')} rows={3} maxLength={4096} style={{ resize: 'vertical' }} />
          </div>

          <div style={{ display: 'flex', gap: 'var(--space-2)', justifyContent: 'flex-end' }}>
            <button className="btn" type="button" onClick={onClose} disabled={saving}>Cancel</button>
            <button className="btn primary" type="submit" disabled={saving || !form.name.trim()}>
              {saving ? 'Saving…' : (form._id ? 'Save changes' : `Add ${noun}`)}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ─── Bulk import modal ────────────────────────────────────────────────────────

function ImportModal({ csvText, setCsvText, preview, result, importing, onParse, onImport, onClose }) {
  return (
    <div className="modal-backdrop">
      <div className="modal" style={{ maxWidth: 700, width: '100%' }} onClick={e => e.stopPropagation()}>
        <div className="modal-head">
          <h3 className="modal-title">Import stakeholders from CSV</h3>
          <button className="modal-close" type="button" onClick={onClose}>✕</button>
        </div>

        {/* .modal-body: the content scrolls inside the 90vh modal instead of spilling out of it */}
        <div className="modal-body">
        {!result ? (
          <>
            <p style={{ fontSize: 12, color: 'var(--muted)', margin: '0 0 var(--space-2)' }}>
              Paste CSV with header row. Supported columns:
            </p>
            <pre style={{
              fontSize: 10, background: 'var(--bg)', color: 'var(--muted)',
              padding: 'var(--space-2)', borderRadius: 'var(--radius-sm)',
              marginBottom: 'var(--space-3)', overflowX: 'auto',
            }}>
              name,title,organization,type,email,phone,mobile,signal,whatsapp,telegram,teams,slack,available_hours,notes
            </pre>
            <p style={{ fontSize: 11, color: 'var(--dim)', margin: '0 0 var(--space-3)' }}>
              <b>type</b> values: {Object.keys(TYPE_LABELS).join(', ')} &nbsp;·&nbsp;
              Contact columns (email, phone, signal, etc.) each become a contact method entry.
            </p>

            <textarea
              className="input compact"
              value={csvText}
              onChange={e => setCsvText(e.target.value)}
              rows={8}
              placeholder="name,title,organization,type,email,phone,signal,whatsapp,notes&#10;Alice Smith,CISO,Acme Corp,internal,alice@acme.com,+1-555-0100,+1-555-0100,,On call 24/7"
              style={{ resize: 'vertical', fontFamily: 'var(--font-mono)', marginBottom: 'var(--space-3)' }}
            />

            {preview === null ? (
              <div style={{ display: 'flex', gap: 'var(--space-2)', justifyContent: 'flex-end' }}>
                <button className="btn" type="button" onClick={onClose}>Cancel</button>
                <button className="btn primary" type="button" disabled={!csvText.trim()} onClick={onParse}>
                  Preview
                </button>
              </div>
            ) : (
              <>
                <div style={{ fontSize: 12, color: 'var(--muted)', marginBottom: 'var(--space-2)' }}>
                  {preview.length} row{preview.length !== 1 ? 's' : ''} parsed
                </div>
                <div style={{ maxHeight: 240, overflowY: 'auto', border: '1px solid var(--border)', borderRadius: 'var(--radius)', marginBottom: 'var(--space-3)' }}>
                  <table className="tbl">
                    <thead>
                      <tr>
                        <th>Name</th><th>Type</th><th>Title / Org</th><th>Contacts</th>
                      </tr>
                    </thead>
                    <tbody>
                      {preview.map((r, i) => (
                        <tr key={i}>
                          <td style={{ fontWeight: 600, fontSize: 13 }}>{r.name}</td>
                          <td>
                            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: TYPE_COLORS[r.type] || 'var(--muted)' }}>
                              {TYPE_LABELS[r.type] || r.type}
                            </span>
                          </td>
                          <td style={{ fontSize: 12, color: 'var(--muted)' }}>
                            {[r.title, r.organization].filter(Boolean).join(' · ') || '—'}
                          </td>
                          <td style={{ fontSize: 11, color: 'var(--muted)', fontFamily: 'var(--font-mono)' }}>
                            {r.contact_methods.map(m => `${m.channel}:${m.value}`).join(', ') || '—'}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                <div style={{ display: 'flex', gap: 'var(--space-2)', justifyContent: 'flex-end' }}>
                  <button className="btn" type="button" onClick={onClose}>Cancel</button>
                  <button className="btn primary" type="button" disabled={importing || !preview.length} onClick={onImport}>
                    {importing ? 'Importing…' : `Import ${preview.length} contact${preview.length !== 1 ? 's' : ''}`}
                  </button>
                </div>
              </>
            )}
          </>
        ) : (
          <>
            {result.created > 0 && (
              <div className="alert ok" role="status" style={{ marginBottom: 'var(--space-3)' }}>
                <span className="alert-icon">✓</span>
                <span>{result.created} contact{result.created !== 1 ? 's' : ''} imported successfully.</span>
              </div>
            )}
            {result.errors?.length > 0 && (
              <div style={{ marginBottom: 'var(--space-3)' }}>
                <div style={{ fontSize: 12, color: 'var(--crit)', marginBottom: 'var(--space-1)' }}>
                  {result.errors.length} error{result.errors.length !== 1 ? 's' : ''}:
                </div>
                <ul style={{ listStyle: 'none', margin: 0, padding: 0, display: 'flex', flexDirection: 'column', gap: 4 }}>
                  {result.errors.map((e, i) => (
                    <li key={i} style={{ fontSize: 11, color: 'var(--crit)', fontFamily: 'var(--font-mono)' }}>{e}</li>
                  ))}
                </ul>
              </div>
            )}
            <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
              <button className="btn primary" type="button" onClick={onClose}>Close</button>
            </div>
          </>
        )}
        </div>
      </div>
    </div>
  )
}

// ─── Contacts directory helpers (E2) ─────────────────────────────────────────

// "Verified <local time with offset> by <user>" from the server's stamp, or "Never verified".
export function verifiedLabel(c) {
  if (!c.last_verified_at) return 'Never verified'
  return `Verified ${formatLocal(c.last_verified_at)}${c.verified_by_username ? ` by ${c.verified_by_username}` : ''}`
}

// "Add from directory": lists GET /api/contacts and POSTs { contact_id } so the server copies the
// entry into this incident. The copy is the incident's own: later directory edits don't change it.
function DirectoryPicker({ incidentId, onAdded, onClose }) {
  const [q,       setQ]       = useState('')
  const [type,    setType]    = useState('')
  const [items,   setItems]   = useState([])
  const [cursor,  setCursor]  = useState(null)
  const [loading, setLoading] = useState(true)
  const [error,   setError]   = useState('')
  const [added,   setAdded]   = useState({})     // contact id → true once copied in this session
  const [busy,    setBusy]    = useState(null)
  const seq = useRef(0)

  const fetchPage = useCallback(async (cur) => {
    const mine = ++seq.current
    setLoading(true); setError('')
    try {
      const d = await api.listContacts({ q: q.trim(), type, limit: 50, cursor: cur })
      if (mine !== seq.current) return
      setItems(prev => cur ? [...prev, ...d.items] : d.items)
      setCursor(d.next_cursor || null)
    } catch (e) {
      if (mine === seq.current) setError(e.message || 'Could not load the directory')
    } finally {
      if (mine === seq.current) setLoading(false)
    }
  }, [q, type])

  useEffect(() => {
    const t = setTimeout(() => fetchPage(null), 200)
    return () => clearTimeout(t)
  }, [fetchPage])

  // Focus moves in (search field), Tab stays inside, Esc closes, focus returns to the opener on close.
  const dialogRef = useRef(null)
  useDialogFocus(dialogRef, onClose)

  const add = async (c) => {
    setBusy(c.id); setError('')
    try {
      await api.createStakeholder(incidentId, { contact_id: c.id })
      setAdded(a => ({ ...a, [c.id]: true }))
      onAdded()
    } catch (e) {
      setError(e.message || 'Could not add the contact')
    } finally {
      setBusy(null)
    }
  }

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal dir-picker" ref={dialogRef} role="dialog" aria-modal="true" aria-labelledby="dir-picker-title"
           style={{ maxWidth: 640 }} onClick={e => e.stopPropagation()}>
        <div className="modal-head">
          <h2 id="dir-picker-title">Add from directory</h2>
          <button className="modal-close" type="button" aria-label="Close" onClick={onClose}>✕</button>
        </div>
        <div className="modal-body" style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
          <p style={{ margin: 0, fontSize: 12, color: 'var(--muted)' }}>
            Adds a copy of the contact to this incident. Later changes in the directory don't change the copy.
          </p>
          <div className="panel-toolbar" style={{ gap: 'var(--space-2)' }}>
            <input className="input" placeholder="Search name or organization…" aria-label="Search the directory"
                   value={q} onChange={e => setQ(e.target.value)} />
            <select className="select" aria-label="Type" value={type} onChange={e => setType(e.target.value)}>
              <option value="">All types</option>
              {TYPE_OPTS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
            </select>
          </div>
          {error && (
            <div className="alert error" role="alert"><span className="alert-icon">!</span><span>{error}</span></div>
          )}
          {!loading && items.length === 0 && !error && (
            <div className="panel-empty" style={{ padding: 'var(--space-4)' }}>
              <div>{q || type ? 'No matches.' : 'The Contacts directory is empty.'}</div>
              <div style={{ color: 'var(--muted)', fontSize: 12 }}>Admins fill it in under Prepare → Contacts.</div>
            </div>
          )}
          {items.length > 0 && (
            <ul className="dir-picker-list" aria-label="Directory contacts"
                style={{ listStyle: 'none', margin: 0, padding: 0, display: 'flex', flexDirection: 'column', gap: 'var(--space-2)' }}>
              {items.map(c => (
                <li key={c.id} data-contact-id={c.id} style={{
                  display: 'flex', alignItems: 'center', gap: 'var(--space-3)',
                  border: '1px solid var(--border)', borderLeft: `3px solid ${TYPE_COLORS[c.type] || 'var(--dim)'}`,
                  borderRadius: 'var(--radius)', padding: 'var(--space-2) var(--space-3)',
                }}>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontWeight: 600, fontSize: 13, overflowWrap: 'anywhere' }}>{c.name}</div>
                    <div style={{ fontSize: 12, color: 'var(--muted)', overflowWrap: 'anywhere' }}>
                      {[TYPE_LABELS[c.type] || c.type, c.organization, c.title].filter(Boolean).join(' · ')}
                    </div>
                    <div style={{ fontSize: 11, color: 'var(--muted)' }}>{verifiedLabel(c)}</div>
                  </div>
                  {added[c.id]
                    ? <span className="dir-picker-added" style={{ fontSize: 12, color: 'var(--text)', whiteSpace: 'nowrap' }}>
                        <span aria-hidden="true" style={{ color: 'var(--ok)' }}>✓ </span>Added
                      </span>
                    : <button className="btn" type="button" disabled={busy === c.id} onClick={() => add(c)}
                              aria-label={`Add ${c.name} to this incident`}>
                        {busy === c.id ? 'Adding…' : 'Add'}
                      </button>}
                </li>
              ))}
            </ul>
          )}
          {loading && <div style={{ fontSize: 12, color: 'var(--muted)' }}>Loading…</div>}
          {cursor && !loading && (
            <button className="btn ghost" type="button" onClick={() => fetchPage(cursor)}>Load more</button>
          )}
        </div>
        <div className="modal-foot">
          <button className="btn primary" type="button" onClick={onClose}>Done</button>
        </div>
      </div>
    </div>
  )
}
