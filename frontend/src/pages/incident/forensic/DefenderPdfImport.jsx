import { useCallback, useEffect, useState } from 'react'
import { useOutletContext } from 'react-router-dom'
import { api } from '../../../api/client.js'
import { formatLocal, formatLocalShort } from '../../../lib/datetime.js'
import { ClockOffsetNotice, OffsetMark, fmtOffset } from '../../../components/ClockOffset.jsx'
import { exhibitBlock } from '../../../components/ExhibitPicker.jsx'

// Defender Import — upload a Microsoft Defender XDR incident PDF ("Evidence
// and response" export), or parse one already registered as an exhibit (G4),
// and get back candidate IOCs/Entities/Timeline events, each with a suggested
// destination the analyst can accept or override before committing. Nothing is
// committed as an IOC/Entity/Timeline event until "Commit selected" is clicked;
// the server then copies the chosen candidates (the browser sends only idx +
// destination), so each fact carries the run's exhibit and, for timeline events,
// the import and the candidate index. The import itself is persisted with its
// run record (input SHA-256, exhibit, parser version, clock offset applied) so
// the page survives a refresh — same pattern as Logs & triage.
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

const MAX_PDF_BYTES = 25 * 1024 * 1024

// Why an exhibit can't be parsed as a Defender PDF right now (the shared rule, FE-L8), or null.
const pdfBlock = (ev) => exhibitBlock(ev, MAX_PDF_BYTES, '25 MiB')

export default function DefenderPdfImport() {
  const { inc, viewer } = useOutletContext()
  const incidentId = inc.id
  const isClosed = inc?.status === 'closed'
  // G-fix FE-L12: viewers get the closed-incident view of the write controls (the API refuses them).
  const ro = isClosed || !!viewer
  const RO_TITLE = isClosed ? 'Closed incidents are read-only' : 'Read-only: viewers can’t change the incident'

  const [mode, setMode] = useState('upload')          // 'upload' | 'exhibit'
  const [exhibits, setExhibits] = useState(null)      // digital evidence items (exhibit mode)
  const [exhibitId, setExhibitId] = useState('')
  const [file, setFile] = useState(null)
  const [parsing, setParsing] = useState(false)
  const [parseErr, setParseErr] = useState(null)
  const [detail, setDetail] = useState(null)           // the active import (run record + meta)
  const [candidates, setCandidates] = useState([])

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

  // Exhibit mode: every digital evidence item of the incident (all pages).
  useEffect(() => {
    if (mode !== 'exhibit' || exhibits !== null) return
    let live = true
    ;(async () => {
      const all = []
      let cursor = null
      do {
        const res = await api.listEvidence(incidentId, { kind: 'digital_file', limit: 200, ...(cursor ? { cursor } : {}) })
        all.push(...res.items)
        cursor = res.next_cursor
      } while (cursor)
      if (live) setExhibits(all)
    })().catch(e => { if (live) { setExhibits([]); setParseErr(e.message || 'Could not list exhibits.') } })
    return () => { live = false }
  }, [mode, exhibits, incidentId])

  const exhibit = (exhibits || []).find(x => x.id === exhibitId) || null
  const activeImportId = detail?.id || null
  const legacy = !!detail && !detail.parser_version

  const applyDetail = (d) => {
    setDetail(d)
    setCandidates(d.candidates.map((c, i) => ({
      ...c, idx: c.idx ?? i, selected: true, destination: c.suggested_destination,
    })))
    setCommitResult(null)
  }

  const clearDetail = () => { setDetail(null); setCandidates([]) }

  const onParse = async () => {
    if (!file) return
    setParsing(true); setParseErr(null); setCommitResult(null)
    try {
      applyDetail(await api.createDefenderPdfImport(incidentId, file))
      setFile(null)
      await loadImports()
    } catch (e) {
      setParseErr(e.message || 'Parse failed.')
      clearDetail()
    } finally {
      setParsing(false)
    }
  }

  const onParseExhibit = async () => {
    if (!exhibit) return
    setParsing(true); setParseErr(null); setCommitResult(null)
    try {
      applyDetail(await api.importDefenderPdfFromEvidence(incidentId, exhibit.id))
      await loadImports()
    } catch (e) {
      setParseErr(e.message || 'Could not parse the exhibit.')
      clearDetail()
      if (e.status === 409) setExhibits(null)   // e.g. frozen after a hash mismatch: refresh the list
    } finally {
      setParsing(false)
    }
  }

  const loadImport = async (importId) => {
    setParsing(true); setParseErr(null)
    try {
      applyDetail(await api.getDefenderPdfImport(incidentId, importId))
    } catch (e) {
      setParseErr(e.message || 'Load failed.')
    } finally {
      setParsing(false)
    }
  }

  const onDeleteImport = async (imp) => {
    if (!confirm(`Dispose "${imp.filename}"?\n\n${imp.candidate_count} candidate(s) will be removed from this incident. Items already committed as IOCs/Entities are not affected; an import with committed timeline events can't be disposed. Audit-logged.`)) return
    try {
      await api.deleteDefenderPdfImport(incidentId, imp.id)
      if (activeImportId === imp.id) clearDetail()
      await loadImports()
    } catch (e) {
      setImportsErr(e.message || 'Dispose failed.')
    }
  }

  const toggleSelect = (idx) => setCandidates(prev =>
    prev.map(c => c.idx === idx ? { ...c, selected: !c.selected } : c))
  const setDestination = (idx, destination) => setCandidates(prev =>
    prev.map(c => c.idx === idx ? { ...c, destination } : c))
  const toggleAll = () => {
    const allSelected = candidates.every(c => c.selected)
    setCandidates(prev => prev.map(c => ({ ...c, selected: !allSelected })))
  }

  // The server copies the chosen candidates from the stored import (G4): only idx + destination go.
  const onCommit = async () => {
    const selected = candidates.filter(c => c.selected)
    if (selected.length === 0 || !activeImportId) return
    setCommitting(true); setCommitResult(null)
    try {
      const r = await api.promoteDefenderPdfImport(incidentId, activeImportId, {
        items: selected.map(c => ({ idx: c.idx, destination: c.destination })),
      })
      setCommitResult({ ok: true, ...r })
    } catch (e) {
      setCommitResult({ ok: false, error: e.message || 'Commit failed.' })
    } finally {
      setCommitting(false)
    }
  }

  const selectedCount = candidates.filter(c => c.selected).length
  const incidentMeta = detail?.incident

  return (
    <section className="panel">
      <div className="panel-toolbar">
        <h2 className="panel-h">Defender Import</h2>
        <span style={{ color: 'var(--muted)', fontSize: 13 }}>
          Parse a Microsoft Defender incident PDF → review suggested IOCs, Entities, and Timeline events before committing
        </span>
      </div>

      {/* Source (G4): upload a PDF, or parse a registered exhibit without re-uploading it */}
      <div className="form" style={{ marginBottom: 'var(--space-3)' }}>
        <div role="radiogroup" aria-label="Import source" style={{ display: 'flex', gap: 'var(--space-4)', flexWrap: 'wrap', fontSize: 13 }}>
          {[['upload', 'Upload a PDF'], ['exhibit', 'From a registered exhibit']].map(([v, label]) => (
            <label key={v} style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-1)', cursor: 'pointer' }}>
              <input type="radio" name="dfimp-mode" value={v} checked={mode === v}
                     onChange={() => { setMode(v); setParseErr(null) }} />
              {label}
            </label>
          ))}
        </div>

        {mode === 'upload' && (
          <div style={{
            display: 'flex', gap: 'var(--space-2)', alignItems: 'center', flexWrap: 'wrap',
            padding: 'var(--space-3)', background: 'var(--surface-2)', borderRadius: 'var(--radius)',
          }}>
            <input type="file" accept="application/pdf" disabled={parsing || ro}
                   onChange={e => setFile(e.target.files?.[0] || null)} />
            <button type="button" className="btn primary" onClick={onParse} disabled={!file || parsing || ro}>
              {parsing ? 'Parsing…' : 'Parse PDF'}
            </button>
            <span style={{ color: 'var(--dim)', fontSize: 11 }}>
              The incident PDF exported from Defender's "Evidence and response" tab — up to 25 MiB. The upload is saved (quarantined + candidates persisted); a PDF whose SHA-256 matches exactly one registered exhibit is linked to it. Nothing is committed as an IOC/Entity/Timeline event until you click "Commit selected" below.
            </span>
          </div>
        )}

        {mode === 'exhibit' && (
          <>
            <div className="form-row">
              <div className="field">
                <label className="field-label" htmlFor="dfimp-exhibit">Exhibit *</label>
                <select id="dfimp-exhibit" className="select" value={exhibitId}
                        onChange={(e) => setExhibitId(e.target.value)} disabled={exhibits === null}>
                  <option value="">{exhibits === null ? 'Loading exhibits…' : exhibits.length ? '— choose an exhibit —' : 'No digital exhibits registered'}</option>
                  {(exhibits || []).map(x => {
                    const block = pdfBlock(x)
                    return (
                      <option key={x.id} value={x.id} disabled={!!block}>
                        {x.identifier} · {x.name}{x.original_filename ? ` (${x.original_filename})` : ''}{block ? ` — ${block}` : ''}
                      </option>
                    )
                  })}
                </select>
              </div>
              <div className="field" style={{ justifyContent: 'flex-end' }}>
                <button type="button" className="btn primary" onClick={onParseExhibit}
                        disabled={ro || parsing || !exhibit || !!pdfBlock(exhibit)}
                        title={ro ? (isClosed ? 'Closed incidents are read-only — re-open the incident to import' : RO_TITLE)
                          : 'Verify the exhibit’s hash, parse it and save the candidates (recorded in its custody log)'}>
                  {parsing ? 'Parsing…' : 'Parse exhibit'}
                </button>
              </div>
            </div>
            {exhibit && (
              <div className="field-hint" role="status" data-testid="dfimp-exhibit-hint">
                Device clock offset: <strong>not applied</strong> — a Defender incident PDF holds Microsoft cloud times,
                {' '}not the device&rsquo;s clock{exhibit.system_time_offset_seconds !== null && exhibit.system_time_offset_seconds !== undefined
                  ? <> (the exhibit records {fmtOffset(exhibit.system_time_offset_seconds)})</> : null}.
                {' · '}The exhibit is re-hashed before parsing; a mismatch freezes it and nothing is parsed.
              </div>
            )}
          </>
        )}
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
                data-testid="dfimp-saved"
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
                {imp.evidence_identifier && (
                  <span className="pill" style={{ fontSize: 10, fontFamily: 'var(--font-mono)' }}
                        title="Parsed from this registered exhibit">⛁ {imp.evidence_identifier}</span>
                )}
                {(imp.clock_offset_status === 'text_only' || imp.clock_offset_status === 'changed') && (
                  <span style={{ color: 'var(--high)', fontSize: 11 }}
                        title={imp.clock_offset_status === 'changed' ? 'The exhibit’s clock offset changed after this import'
                          : 'Clock offset recorded only as text: not applied'}>⚠ clock</span>
                )}
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
                  disabled={ro}
                  title={ro ? RO_TITLE : 'Dispose this import (audit-logged)'}
                  style={{
                    background: 'transparent', border: '1px solid var(--border)', color: 'var(--crit)',
                    borderRadius: 'var(--radius-sm)', padding: '2px 8px', fontSize: 11,
                    cursor: ro ? 'not-allowed' : 'pointer',
                  }}
                >× dispose</button>
              </div>
            )
          })}
        </div>
      )}

      {/* Run record of the active import (G4, R03) */}
      {detail && (
        <dl className="kv" data-testid="dfimp-run-record" style={{
          padding: 'var(--space-3)', background: 'var(--surface-2)', borderRadius: 'var(--radius)',
          marginBottom: 'var(--space-3)', fontSize: 13,
        }}>
          <dt>Input</dt>
          <dd>
            <span style={{ fontFamily: 'var(--font-mono)' }}>{detail.filename}</span>
            {detail.evidence_identifier && (
              <> <span className="pill" data-testid="dfimp-exhibit-pill" style={{ fontSize: 11, fontFamily: 'var(--font-mono)' }}
                       title="Parsed from this registered exhibit">⛁ {detail.evidence_identifier}</span></>
            )}
          </dd>
          <dt>Input SHA-256</dt>
          <dd data-testid="dfimp-sha256" style={{ fontFamily: 'var(--font-mono)', fontSize: 11, wordBreak: 'break-all' }}>{detail.sha256_hash}</dd>
          <dt>Parser</dt>
          <dd data-testid="dfimp-parser">
            {detail.parser_version
              ? <>{detail.parser_name || 'FENRIR Defender PDF parser'} {detail.parser_version}</>
              : <span style={{ color: 'var(--dim)' }}>not recorded (imported before run records)</span>}
          </dd>
          <dt>Run</dt>
          <dd>{formatLocal(detail.uploaded_at)}{detail.uploaded_by ? ` by ${detail.uploaded_by}` : ''}</dd>
          {detail.clock_offset_status === 'not_applicable' ? (
            <><dt>Clock offset</dt>
              <dd data-testid="dfimp-offset-na">Not applicable — Defender incident times are Microsoft cloud times, not the device clock, so no exhibit offset is applied.</dd></>
          ) : detail.clock_offset_seconds !== null && detail.clock_offset_seconds !== undefined && (
            <><dt>Clock offset</dt><dd>{fmtOffset(detail.clock_offset_seconds)} applied</dd></>
          )}
        </dl>
      )}

      {detail && <ClockOffsetNotice imp={detail} />}

      {legacy && (
        <div className="alert warn" role="status" data-testid="dfimp-legacy" style={{ marginBottom: 'var(--space-3)' }}>
          <span className="alert-icon">!</span>
          <span>This import was made before run records: its candidates carry no time basis, so they can&rsquo;t be committed. Import the PDF or exhibit again.</span>
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
            <button type="button" className="btn primary" onClick={onCommit}
                    disabled={committing || selectedCount === 0 || ro || legacy}
                    title={legacy ? 'Imported before run records — import it again to commit' : undefined}>
              {committing ? 'Committing…' : `Commit ${selectedCount} selected`}
            </button>
            <span style={{ color: 'var(--muted)', fontSize: 12 }}>{candidates.length} candidates found</span>
          </div>

          {commitResult && (
            <div className={`alert ${commitResult.ok ? 'info' : 'error'}`} role="alert" data-testid="dfimp-commit-result"
                 style={{ marginBottom: 'var(--space-2)' }}>
              <span className="alert-icon">{commitResult.ok ? '✓' : '!'}</span>
              {commitResult.ok ? (
                <span>
                  Created {commitResult.created} ({commitResult.created_iocs} IOC{commitResult.created_iocs === 1 ? '' : 's'},
                  {' '}{commitResult.created_entities} entit{commitResult.created_entities === 1 ? 'y' : 'ies'},
                  {' '}{commitResult.created_events} timeline event{commitResult.created_events === 1 ? '' : 's'}).
                  {commitResult.skipped_untimestamped.length > 0 && ` ${commitResult.skipped_untimestamped.length} without a timestamp not placed on the timeline.`}
                  {commitResult.already_promoted.length > 0 && ` ${commitResult.already_promoted.length} already on the timeline from this import.`}
                  {commitResult.already_exists.length > 0 && ` ${commitResult.already_exists.length} already on the incident (left as they are).`}
                </span>
              ) : <span>{commitResult.error}</span>}
            </div>
          )}

          <div className="table-scroll">
            <table className="settings-table">
              <thead>
                <tr>
                  <th style={{ width: 32 }}><input type="checkbox" aria-label="Select all candidates"
                                                    checked={candidates.every(c => c.selected)} onChange={toggleAll} /></th>
                  <th style={{ width: 170 }}>Time</th>
                  <th>Item</th>
                  <th style={{ width: 130 }}>Destination</th>
                </tr>
              </thead>
              <tbody>
                {candidates.map(c => (
                  <tr key={c.idx} data-testid="dfimp-row">
                    <td><input type="checkbox" aria-label="Select candidate" checked={c.selected} onChange={() => toggleSelect(c.idx)} /></td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }} title={c.event_time ? `${c.event_time} (UTC)` : 'No timestamp'}>
                      {c.event_time ? formatLocal(c.event_time) : '—'}
                      {c.time_basis === 'assumed_tz' && (
                        <> <span className="pill" data-basis="assumed_tz"
                                 style={{ fontSize: 9, padding: '0 4px', color: 'var(--med)', borderColor: 'var(--med)' }}
                                 title="The PDF does not state its UTC offset: read as UTC">TZ assumed</span></>
                      )}
                      {c.recorded_time && <> <OffsetMark seconds={detail?.clock_offset_seconds} recorded={c.recorded_time} size={9} /></>}
                    </td>
                    <td style={{ fontSize: 13, maxWidth: 480 }}>
                      <div style={{ fontWeight: 600 }}>{c.description}</div>
                      {c.low_confidence && (
                        <div style={{ color: 'var(--high)', fontSize: 11 }}>⚠ low confidence — verify against Defender directly</div>
                      )}
                      {c.destination === 'timeline_event' && !c.event_time && (
                        <div style={{ color: 'var(--muted)', fontSize: 11 }}>No timestamp — won&rsquo;t be placed on the timeline</div>
                      )}
                      {c.raw_log && (
                        <details style={{ marginTop: 2 }}>
                          <summary style={{ cursor: 'pointer', fontSize: 11, color: 'var(--muted)' }}>context</summary>
                          <div style={{ fontSize: 11, color: 'var(--muted)', wordBreak: 'break-word' }}>{c.raw_log}</div>
                        </details>
                      )}
                    </td>
                    <td>
                      <select className="select compact" value={c.destination} aria-label="Destination"
                              onChange={e => setDestination(c.idx, e.target.value)}>
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
