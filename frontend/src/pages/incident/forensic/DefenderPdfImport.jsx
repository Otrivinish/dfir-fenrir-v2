import { useCallback, useEffect, useState } from 'react'
import { useOutletContext } from 'react-router-dom'
import { api } from '../../../api/client.js'
import { formatLocal, formatLocalShort } from '../../../lib/datetime.js'

// Defender Import — upload a Microsoft Defender XDR incident PDF ("Evidence
// and response" export) and get back candidate IOCs/Entities/Timeline
// events, each with a suggested destination the analyst can accept or
// override before committing. Nothing is committed as an IOC/Entity/Timeline
// event until "Commit selected" is clicked, but the upload itself IS
// persisted (raw PDF quarantined as an Artifact, parsed candidates saved) so
// the page survives a refresh — same pattern as Timeline Import's saved
// imports.
//
// Some fields (long free-text table cells with no ruling lines in
// Microsoft's PDF layout) can't always be extracted reliably — those are
// never used as a candidate's value, only kept as best-effort context in
// its raw_log, and candidates missing a parseable timestamp are flagged
// "low confidence" rather than silently guessed at.

const DESTINATIONS = [
  { value: 'ioc', label: 'IOC' },
  { value: 'entity', label: 'Entity' },
  { value: 'timeline_event', label: 'Timeline event' },
]

const OVERVIEW_FIELDS = [
  'Severity', 'Status', 'Classification', 'Categories', 'Assigned to',
  'Time created', 'First activity', 'Last activity', 'Time closed', 'Description',
]

export default function DefenderPdfImport() {
  const { inc } = useOutletContext()
  const incidentId = inc.id
  const isClosed = inc?.status === 'closed'

  const [file, setFile] = useState(null)
  const [parsing, setParsing] = useState(false)
  const [parseErr, setParseErr] = useState(null)
  const [incidentMeta, setIncidentMeta] = useState(null)
  const [candidates, setCandidates] = useState([])
  const [activeImportId, setActiveImportId] = useState(null)

  const [committing, setCommitting] = useState(false)
  const [commitResult, setCommitResult] = useState(null)

  // Saved imports — listed on mount; refreshed after each upload/dispose.
  const [imports, setImports] = useState([])
  const [importsErr, setImportsErr] = useState(null)

  const loadImports = useCallback(async () => {
    try {
      const r = await api.listDefenderPdfImports(incidentId)
      setImports(r.items || [])
    } catch (e) {
      setImportsErr(e.message || 'Could not load saved imports.')
    }
  }, [incidentId])

  useEffect(() => { loadImports() }, [loadImports])

  const applyDetail = (detail) => {
    setIncidentMeta(detail.incident)
    setCandidates(detail.candidates.map((c, i) => ({
      ...c, _id: i, selected: true, destination: c.suggested_destination,
    })))
    setActiveImportId(detail.id)
    setCommitResult(null)
  }

  const onParse = async () => {
    if (!file) return
    setParsing(true); setParseErr(null); setCommitResult(null)
    try {
      const detail = await api.createDefenderPdfImport(incidentId, file)
      applyDetail(detail)
      setFile(null)
      await loadImports()
    } catch (e) {
      setParseErr(e.message || 'Parse failed.')
      setIncidentMeta(null); setCandidates([]); setActiveImportId(null)
    } finally {
      setParsing(false)
    }
  }

  const loadImport = async (importId) => {
    setParsing(true); setParseErr(null)
    try {
      const detail = await api.getDefenderPdfImport(incidentId, importId)
      applyDetail(detail)
    } catch (e) {
      setParseErr(e.message || 'Load failed.')
    } finally {
      setParsing(false)
    }
  }

  const onDeleteImport = async (imp) => {
    if (!confirm(`Dispose "${imp.filename}"?\n\n${imp.candidate_count} candidate(s) will be removed from this incident. Items already committed as IOCs/Entities/Timeline events are not affected. Audit-logged.`)) return
    try {
      await api.deleteDefenderPdfImport(incidentId, imp.id)
      if (activeImportId === imp.id) {
        setIncidentMeta(null); setCandidates([]); setActiveImportId(null)
      }
      await loadImports()
    } catch (e) {
      setImportsErr(e.message || 'Dispose failed.')
    }
  }

  const toggleSelect = (id) => setCandidates(prev =>
    prev.map(c => c._id === id ? { ...c, selected: !c.selected } : c))
  const setDestination = (id, destination) => setCandidates(prev =>
    prev.map(c => c._id === id ? { ...c, destination } : c))
  const toggleAll = () => {
    const allSelected = candidates.every(c => c.selected)
    setCandidates(prev => prev.map(c => ({ ...c, selected: !allSelected })))
  }

  const onCommit = async () => {
    const selected = candidates.filter(c => c.selected)
    if (selected.length === 0) return
    setCommitting(true); setCommitResult(null)
    const errors = []
    let created = 0, skipped = 0

    const iocItems = []
    const entityItems = []
    const timelineItems = []
    for (const c of selected) {
      if (c.destination === 'ioc') {
        iocItems.push({
          type: c.ioc_type || 'other',
          value: c.value || c.description,
          notes: c.raw_log || undefined,
          source: c.source || 'Microsoft Defender PDF import',
        })
      } else if (c.destination === 'entity') {
        entityItems.push(c)
      } else if (c.destination === 'timeline_event') {
        if (!c.event_time) {
          skipped++
          errors.push(`Skipped "${(c.value || c.description).slice(0, 60)}" — no parseable timestamp for a Timeline event`)
          continue
        }
        timelineItems.push({
          event_time: c.event_time,
          hostname: c.hostname || undefined,
          source: c.source || 'Microsoft Defender PDF import',
          event_type: c.event_type || undefined,
          description: c.description,
          raw_log: c.raw_log || undefined,
        })
      }
    }

    try {
      if (iocItems.length) {
        const r = await api.batchCreateIocs(incidentId, { items: iocItems })
        created += r.created; skipped += r.skipped; errors.push(...(r.errors || []))
      }
      if (timelineItems.length) {
        const r = await api.batchCreateTimelineEvents(incidentId, { events: timelineItems })
        created += r.created; errors.push(...(r.errors || []))
      }
      for (const c of entityItems) {
        try {
          await api.createEntity(incidentId, {
            type: c.entity_type_hint || 'other',
            value: c.value || c.description,
            name: c.value || undefined,
            description: c.description,
            criticality: c.criticality || 'medium',
          })
          created++
        } catch (e) {
          if (e.status === 409) skipped++
          else errors.push(`Entity "${c.value}": ${e.message}`)
        }
      }
    } catch (e) {
      errors.push(e.message || 'Commit failed.')
    } finally {
      setCommitResult({ created, skipped, errors })
      setCommitting(false)
    }
  }

  const selectedCount = candidates.filter(c => c.selected).length

  return (
    <section className="panel">
      <div className="panel-toolbar">
        <h2 className="panel-h">Defender Import</h2>
        <span style={{ color: 'var(--muted)', fontSize: 13 }}>
          Upload a Microsoft Defender incident PDF → review suggested IOCs, Entities, and Timeline events before committing
        </span>
      </div>

      <div style={{
        display: 'flex', gap: 'var(--space-2)', alignItems: 'center', flexWrap: 'wrap',
        padding: 'var(--space-3)', background: 'var(--surface-2)', borderRadius: 'var(--radius)',
        marginBottom: 'var(--space-3)',
      }}>
        <input type="file" accept="application/pdf" disabled={parsing || isClosed}
               onChange={e => setFile(e.target.files?.[0] || null)} />
        <button type="button" className="btn primary" onClick={onParse} disabled={!file || parsing || isClosed}>
          {parsing ? 'Parsing…' : 'Parse PDF'}
        </button>
        <span style={{ color: 'var(--dim)', fontSize: 11 }}>
          The incident PDF exported from Defender's "Evidence and response" tab — up to 25 MB. The upload is saved (quarantined + candidates persisted); nothing is committed as an IOC/Entity/Timeline event until you click "Commit selected" below.
        </span>
      </div>

      {parseErr && (
        <div className="alert error" role="alert" style={{ marginBottom: 'var(--space-3)' }}>
          <span className="alert-icon">!</span><span>{parseErr}</span>
        </div>
      )}
      {importsErr && (
        <div className="alert error" role="alert" style={{ marginBottom: 'var(--space-3)' }}>
          <span className="alert-icon">!</span><span>{importsErr}</span>
        </div>
      )}

      {imports.length > 0 && (
        <div style={{ border: '1px solid var(--border)', borderRadius: 'var(--radius)', marginBottom: 'var(--space-3)' }}>
          <div style={{
            padding: 'var(--space-2) var(--space-3)', borderBottom: '1px solid var(--border)',
            fontSize: 11, fontWeight: 700, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '0.08em',
            display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          }}>
            <span>Saved imports ({imports.length})</span>
            <span style={{ fontWeight: 400, textTransform: 'none', letterSpacing: 0, color: 'var(--dim)' }}>
              Click a row to re-load · × to dispose (audit-logged)
            </span>
          </div>
          {imports.map(imp => {
            const isActive = activeImportId === imp.id
            return (
              <div
                key={imp.id}
                onClick={() => !isActive && loadImport(imp.id)}
                style={{
                  display: 'flex', alignItems: 'center', gap: 'var(--space-2)',
                  padding: 'var(--space-2) var(--space-3)', borderBottom: '1px solid var(--border)',
                  background: isActive ? 'var(--accent-soft)' : 'transparent',
                  cursor: isActive ? 'default' : 'pointer', fontSize: 12,
                }}
              >
                <span style={{
                  fontFamily: 'var(--font-mono)', color: isActive ? 'var(--accent)' : 'var(--text)',
                  flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                }} title={imp.filename}>{imp.filename}</span>
                <span style={{ color: 'var(--muted)' }}>{imp.candidate_count} candidates</span>
                {imp.low_confidence_count > 0 && (
                  <span style={{ color: 'var(--high)' }} title={`${imp.low_confidence_count} low confidence`}>
                    ⚠ {imp.low_confidence_count}
                  </span>
                )}
                <span style={{ color: 'var(--dim)', fontSize: 11, fontFamily: 'var(--font-mono)', whiteSpace: 'nowrap' }}
                      title={formatLocal(imp.uploaded_at)}>
                  {formatLocalShort(imp.uploaded_at)}
                </span>
                {imp.uploaded_by && <span style={{ color: 'var(--dim)', fontSize: 11 }}>{imp.uploaded_by}</span>}
                <button
                  type="button"
                  onClick={(e) => { e.stopPropagation(); onDeleteImport(imp) }}
                  disabled={isClosed}
                  title={isClosed ? 'Closed incidents are read-only' : 'Dispose this import (audit-logged)'}
                  style={{
                    background: 'transparent', border: '1px solid var(--border)', color: 'var(--crit)',
                    borderRadius: 'var(--radius-sm)', padding: '2px 8px', fontSize: 11,
                    cursor: isClosed ? 'not-allowed' : 'pointer',
                  }}
                >× dispose</button>
              </div>
            )
          })}
        </div>
      )}

      {incidentMeta && (
        <div style={{
          padding: 'var(--space-3)', background: 'var(--surface-2)', borderRadius: 'var(--radius)',
          marginBottom: 'var(--space-3)', fontSize: 13,
        }}>
          <div style={{ fontWeight: 600, marginBottom: 'var(--space-2)' }}>
            {incidentMeta.title || 'Defender incident'} {incidentMeta['Incident ID'] && `(ID ${incidentMeta['Incident ID']})`}
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))', gap: 'var(--space-2)' }}>
            {OVERVIEW_FIELDS.filter(f => incidentMeta[f]).map(f => (
              <div key={f}>
                <div style={{ color: 'var(--dim)', fontSize: 11 }}>{f}</div>
                <div style={{ wordBreak: 'break-word' }}>{incidentMeta[f]}</div>
              </div>
            ))}
          </div>
        </div>
      )}

      {candidates.length > 0 && (
        <>
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', marginBottom: 'var(--space-2)' }}>
            <button type="button" className="btn primary" onClick={onCommit} disabled={committing || selectedCount === 0 || isClosed}>
              {committing ? 'Committing…' : `Commit ${selectedCount} selected`}
            </button>
            <span style={{ color: 'var(--muted)', fontSize: 12 }}>{candidates.length} candidates found</span>
          </div>

          {commitResult && (
            <div className={`alert ${commitResult.errors.length ? 'error' : 'info'}`} role="alert" style={{ marginBottom: 'var(--space-2)' }}>
              <span className="alert-icon">{commitResult.errors.length ? '!' : '✓'}</span>
              <span>
                Created {commitResult.created}, skipped {commitResult.skipped}.
                {commitResult.errors.length > 0 && (
                  <ul style={{ margin: '4px 0 0', paddingLeft: 18 }}>
                    {commitResult.errors.map((e, i) => <li key={i}>{e}</li>)}
                  </ul>
                )}
              </span>
            </div>
          )}

          <div style={{ overflowX: 'auto' }}>
            <table className="settings-table">
              <thead>
                <tr>
                  <th style={{ width: 32 }}><input type="checkbox" checked={candidates.every(c => c.selected)} onChange={toggleAll} /></th>
                  <th style={{ width: 150 }}>Time (UTC)</th>
                  <th>Item</th>
                  <th style={{ width: 130 }}>Destination</th>
                </tr>
              </thead>
              <tbody>
                {candidates.map(c => (
                  <tr key={c._id}>
                    <td><input type="checkbox" checked={c.selected} onChange={() => toggleSelect(c._id)} /></td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }} title={c.event_time ? formatLocal(c.event_time) : ''}>
                      {c.event_time ? c.event_time.replace('T', ' ').slice(0, 19) : '—'}
                    </td>
                    <td style={{ fontSize: 13, maxWidth: 480 }}>
                      <div style={{ fontWeight: 600 }}>{c.description}</div>
                      {c.low_confidence && (
                        <div style={{ color: 'var(--high)', fontSize: 11 }}>⚠ low confidence — verify against Defender directly</div>
                      )}
                      {c.raw_log && (
                        <details style={{ marginTop: 2 }}>
                          <summary style={{ cursor: 'pointer', fontSize: 11, color: 'var(--muted)' }}>context</summary>
                          <div style={{ fontSize: 11, color: 'var(--muted)', wordBreak: 'break-word' }}>{c.raw_log}</div>
                        </details>
                      )}
                    </td>
                    <td>
                      <select className="select" style={{ fontSize: 12 }} value={c.destination}
                              onChange={e => setDestination(c._id, e.target.value)}>
                        {DESTINATIONS.map(d => <option key={d.value} value={d.value}>{d.label}</option>)}
                      </select>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </section>
  )
}
