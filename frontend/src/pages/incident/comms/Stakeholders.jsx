import { useCallback, useEffect, useMemo, useState } from 'react'
import { useOutletContext } from 'react-router-dom'
import { api } from '../../../api/client.js'
import { formatLocal } from '../../../lib/datetime.js'

// ─── Vocabulary ──────────────────────────────────────────────────────────────

const TYPE_LABELS = {
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
  other:           'Other',
}

const TYPE_COLORS = {
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
  other:           'var(--dim)',
}

const CHANNEL_LABELS = {
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

const CHANNEL_OPTS = Object.entries(CHANNEL_LABELS).map(([value, label]) => ({ value, label }))
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

// ─── Main component ──────────────────────────────────────────────────────────

export default function Stakeholders() {
  const { inc, isClosed } = useOutletContext()

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
      const data = await api.listStakeholders(inc.id)
      setItems(data.items || [])
    } catch (e) {
      setError(e.message || 'Failed to load stakeholders')
    } finally {
      setLoading(false)
    }
  }, [inc.id])

  useEffect(() => { load() }, [load])

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
        const updated = await api.updateStakeholder(inc.id, form._id, payload)
        setItems(prev => prev.map(s => s.id === updated.id ? updated : s))
      } else {
        const created = await api.createStakeholder(inc.id, payload)
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
    if (!confirm('Remove this stakeholder?')) return
    try {
      await api.deleteStakeholder(inc.id, id)
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
      const result = await api.bulkCreateStakeholders(inc.id, { rows: csvPreview })
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
        <h2 className="panel-h">Stakeholders</h2>
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
          {!isClosed && (
            <>
              <button className="btn" type="button" onClick={() => setImportOpen(true)}>Import CSV</button>
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
          <div>{items.length === 0 ? 'No stakeholders yet.' : 'No matches.'}</div>
          {items.length === 0 && !isClosed && (
            <div style={{ color: 'var(--dim)', fontSize: 12 }}>
              Add individual contacts or bulk-import from CSV.
            </div>
          )}
        </div>
      ) : (
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fill, minmax(300px, 1fr))',
          gap: 'var(--space-3)',
          marginTop: 'var(--space-2)',
        }}>
          {filtered.map(s => (
            <StakeholderCard
              key={s.id}
              stakeholder={s}
              readOnly={isClosed}
              onEdit={() => openEdit(s)}
              onDelete={() => onDelete(s.id)}
            />
          ))}
        </div>
      )}

      {editTarget && (
        <StakeholderModal
          form={editTarget}
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

function StakeholderCard({ stakeholder: s, readOnly, onEdit, onDelete }) {
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
        <div>
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

      {!readOnly && (
        <div style={{
          display: 'flex', gap: 'var(--space-2)', justifyContent: 'flex-end',
          borderTop: '1px solid var(--border)', paddingTop: 'var(--space-2)', marginTop: 'auto',
        }}>
          <button className="btn" type="button" style={{ fontSize: 12 }} onClick={onEdit}>Edit</button>
          <button className="btn" type="button" style={{ fontSize: 12, color: 'var(--crit)' }} onClick={onDelete}>Remove</button>
        </div>
      )}
    </div>
  )
}

// ─── Add / edit modal ────────────────────────────────────────────────────────

function StakeholderModal({ form: initialForm, saving, onSave, onClose }) {
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
    <div className="modal-overlay">
      <div className="modal" style={{ maxWidth: 560, width: '100%' }} onClick={e => e.stopPropagation()}>
        <div className="modal-head">
          <h3 className="modal-title">{form._id ? 'Edit stakeholder' : 'Add stakeholder'}</h3>
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
              <button className="btn" type="button" style={{ fontSize: 12 }} onClick={addMethod}>+ Add</button>
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
                  style={{ color: 'var(--crit)', fontSize: 12, padding: '2px 8px' }}
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
              {saving ? 'Saving…' : (form._id ? 'Save changes' : 'Add stakeholder')}
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
    <div className="modal-overlay">
      <div className="modal" style={{ maxWidth: 700, width: '100%' }} onClick={e => e.stopPropagation()}>
        <div className="modal-head">
          <h3 className="modal-title">Import stakeholders from CSV</h3>
          <button className="modal-close" type="button" onClick={onClose}>✕</button>
        </div>

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
              className="input"
              value={csvText}
              onChange={e => setCsvText(e.target.value)}
              rows={8}
              placeholder="name,title,organization,type,email,phone,signal,whatsapp,notes&#10;Alice Smith,CISO,Acme Corp,internal,alice@acme.com,+1-555-0100,+1-555-0100,,On call 24/7"
              style={{ resize: 'vertical', fontFamily: 'var(--font-mono)', fontSize: 11, marginBottom: 'var(--space-3)' }}
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
  )
}
