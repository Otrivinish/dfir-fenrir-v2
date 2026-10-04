import { useEffect, useState } from 'react'
import { api } from '../../../api/client.js'

// Wizard B — Examination session (ISO/IEC 27042; integrity bracket per ISO/IEC 27037 §5.4.5).
//
// G5 (R08): a digital exhibit is examined on a verified working copy (or, explicitly, in place with a
// reason). The server records, under one examination_session UUID:
//   1. before  — optional: your hash of the copy, compared with the copy's recorded hash
//   2. examine — tool/version/params/notes + the 27042 records + which copy
//   3. after   — your hash of the copy after the examination (required with a copy)
// A mismatch before aborts (nothing recorded); after, the examination is recorded and the copy is
// flagged altered. The master is not re-hashed here — that is the separate Verify integrity action.

// The working copy an examination ran on, or "examined in place" with a reason. Shared with the quick
// Examine modal. `copies` = GET …/working-copies items; only those the API marks usable are offered.
export function ExamTarget({ copies, value, onChange, idPrefix = 'ext' }) {
  const usable = (copies || []).filter(c => c.usable_for_examination)
  const set = (patch) => onChange({ ...value, ...patch })
  return (
    <div className="field" data-testid={`${idPrefix}-target`}>
      <label className="field-label" htmlFor={`${idPrefix}-wc`}>Working copy examined (required)</label>
      <select id={`${idPrefix}-wc`} className="select" value={value.workingCopyId} disabled={value.inPlace}
              onChange={e => set({ workingCopyId: e.target.value })}>
        <option value="">{usable.length ? '— choose a verified working copy —' : '— no verified working copy yet —'}</option>
        {usable.map(c => (
          <option key={c.id} value={c.id}>
            {c.copy_identifier || c.id.slice(0, 8)} · {c.kind === 'lab_copy' ? 'lab copy' : c.kind}{c.purpose ? ` · ${c.purpose.slice(0, 40)}` : ''}
          </option>
        ))}
      </select>
      <div className="field-hint">Analysis runs on a verified working copy, never the master (ISO 27037 §7.1.3.1.1). Download one or record your lab copy with its hash in the item detail.</div>
      <label style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'center', marginTop: 'var(--space-2)', fontSize: 13 }}>
        <input type="checkbox" checked={value.inPlace} data-testid={`${idPrefix}-inplace`}
               onChange={e => set({ inPlace: e.target.checked, workingCopyId: e.target.checked ? '' : value.workingCopyId })} />
        Examined in place (no working copy)
      </label>
      {value.inPlace && (
        <textarea id={`${idPrefix}-inplace-reason`} className="input" rows={2} maxLength={2048} value={value.inPlaceReason}
                  aria-label="Why it was examined in place" style={{ marginTop: 'var(--space-1)' }}
                  onChange={e => set({ inPlaceReason: e.target.value })}
                  placeholder="Why (required, audited) — e.g. live triage on the running server, no copy possible" />
      )}
    </div>
  )
}

// Client-side completeness only (the API enforces the rule): what is missing, or null.
export function examTargetMissing(value) {
  if (value.inPlace) return value.inPlaceReason.trim() ? null : 'Give the reason it was examined in place.'
  return value.workingCopyId ? null : 'Choose the verified working copy you examined, or mark it examined in place.'
}

export default function ExaminationWizard({ incidentId, item, onClose, onSaved }) {
  const [tool, setTool]       = useState('')
  const [version, setVersion] = useState('')
  const [params, setParams]   = useState('')
  const [notes, setNotes]     = useState('')
  // ISO/IEC 27041 — analysis tool/method validation (Slice B)
  const [toolValidated, setToolValidated]       = useState('')   // '' | true | false
  const [toolValidationRef, setToolValidationRef] = useState('')
  // ISO/IEC 27042 — analysis & interpretation records (Slice E)
  const [findings, setFindings]                 = useState('')
  const [interpretation, setInterpretation]     = useState('')
  const [confidence, setConfidence]             = useState('')   // '' | low | moderate | high
  const [scopeLimitations, setScopeLimitations] = useState('')
  // GS-1 — validated-tools registry (ISO/IEC 27041)
  const [validatedTools, setValidatedTools]     = useState([])
  // GS-2 / G5 — which working copy the analysis was performed on (ISO/IEC 27037 §7.1.3.1.1)
  const [workingCopies, setWorkingCopies]       = useState([])
  const [target, setTarget] = useState({ workingCopyId: '', inPlace: false, inPlaceReason: '' })
  const [preHash, setPreHash]   = useState('')
  const [postHash, setPostHash] = useState('')
  const [busy, setBusy]       = useState(false)
  const [result, setResult]   = useState(null)
  const [error, setError]     = useState(null)

  useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape' && !busy) onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [busy, onClose])

  useEffect(() => {
    api.listValidatedTools().then(r => setValidatedTools(r.items || [])).catch(() => {})
    api.listWorkingCopies(incidentId, item.id).then(r => setWorkingCopies(r.items || [])).catch(() => {})
  }, [incidentId, item.id])

  function pickRegistryTool(id) {
    const t = validatedTools.find(x => x.id === id)
    if (!t) return
    setTool(t.name)
    setVersion(t.version)
    setToolValidated('true')
    setToolValidationRef(t.validation_ref || '')
  }

  async function run() {
    if (!tool.trim()) { setError('Tool is required.'); return }
    const missing = examTargetMissing(target)
    if (missing) { setError(missing); return }
    if (!target.inPlace && !postHash.trim()) { setError('Enter your hash of the working copy after the examination.'); return }
    setBusy(true); setError(null); setResult(null)
    try {
      const r = await api.examinationSession(incidentId, item.id, {
        tool:    tool.trim(),
        version: version.trim() || null,
        params:  params.trim() || null,
        notes:   notes.trim() || null,
        tool_validated:      toolValidated === '' ? null : toolValidated === 'true',
        tool_validation_ref: toolValidationRef.trim() || null,
        findings:          findings.trim() || null,
        interpretation:    interpretation.trim() || null,
        confidence:        confidence || null,
        scope_limitations: scopeLimitations.trim() || null,
        working_copy_id:   target.inPlace ? null : target.workingCopyId,
        examined_in_place: target.inPlace,
        in_place_reason:   target.inPlace ? target.inPlaceReason.trim() : null,
        pre_exam_copy_hash:  !target.inPlace && preHash.trim() ? preHash.trim() : null,
        post_exam_copy_hash: !target.inPlace ? postHash.trim() : null,
      })
      setResult(r)
      if (r.ok) {
        // Caller refreshes the custody log after Done.
      }
    } catch (e) {
      setError(e.message || 'Examination session failed.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="modal-backdrop">
      <div className="modal" role="dialog" aria-labelledby="exw-title" style={{ width: 'min(540px, 96vw)' }}>
        <div className="modal-head">
          <h2 id="exw-title">Examination wizard</h2>
          <button type="button" className="modal-close" onClick={onClose} disabled={busy} aria-label="Close">×</button>
        </div>

        <div className="modal-body">
          <div style={{
            padding: 'var(--space-2) var(--space-3)', marginBottom: 'var(--space-3)',
            background: 'var(--surface-2)', border: '1px solid var(--border)',
            borderRadius: 'var(--radius)', fontSize: 12, color: 'var(--muted)',
          }}>
            <strong style={{ color: 'var(--text)' }}>Sequence:</strong>{' '}
            copy hash before (optional) → record analysis → copy hash after.
            Your hashes of the working copy are compared with the hash recorded for it (ISO 27037 §5.4.5; ISO/IEC 27042).
            The master is not re-hashed here — use <b>Verify integrity</b> for that.
          </div>

          {!result && (
            <div className="form">
              {validatedTools.length > 0 && (
                <div className="field">
                  <label className="field-label" htmlFor="exw-vtool">Validated tool (ISO 27041 registry)</label>
                  <select id="exw-vtool" className="select" defaultValue=""
                          onChange={e => { if (e.target.value) pickRegistryTool(e.target.value) }}>
                    <option value="">— pick a validated tool, or enter manually below —</option>
                    {validatedTools.map(t => (
                      <option key={t.id} value={t.id}>{t.name} {t.version}{t.validation_ref ? ` — ${t.validation_ref}` : ''}</option>
                    ))}
                  </select>
                </div>
              )}
              <div className="form-row">
                <div className="field">
                  <label className="field-label" htmlFor="exw-tool">Tool *</label>
                  <input id="exw-tool" className="input" value={tool}
                         onChange={e => setTool(e.target.value)} autoFocus maxLength={256}
                         placeholder="e.g. Volatility 3 · Autopsy · X-Ways" />
                </div>
                <div className="field">
                  <label className="field-label" htmlFor="exw-ver">Version</label>
                  <input id="exw-ver" className="input" value={version}
                         onChange={e => setVersion(e.target.value)} maxLength={64}
                         placeholder="e.g. 2.5.2" style={{ fontFamily: 'var(--font-mono)' }} />
                </div>
              </div>
              <div className="field">
                <label className="field-label" htmlFor="exw-params">Command line / parameters</label>
                <textarea id="exw-params" className="input" value={params}
                          onChange={e => setParams(e.target.value)} rows={2} maxLength={4096}
                          placeholder="e.g. vol.py -f mem.raw windows.pslist.PsList" />
              </div>
              <div className="form-row">
                <div className="field">
                  <label className="field-label" htmlFor="exw-val">Tool/method validated? (ISO 27041)</label>
                  <select id="exw-val" className="select" value={toolValidated}
                          onChange={e => setToolValidated(e.target.value)}>
                    <option value="">— select —</option>
                    <option value="true">Yes — validated as suitable</option>
                    <option value="false">No / not yet</option>
                  </select>
                </div>
                <div className="field">
                  <label className="field-label" htmlFor="exw-valref">Validation reference</label>
                  <input id="exw-valref" className="input" value={toolValidationRef}
                         onChange={e => setToolValidationRef(e.target.value)} maxLength={256}
                         disabled={toolValidated !== 'true'}
                         placeholder="e.g. VR-2026-014 / NIST CFTT" />
                </div>
              </div>
              <div className="field">
                <label className="field-label" htmlFor="exw-notes">Notes</label>
                <textarea id="exw-notes" className="input" value={notes}
                          onChange={e => setNotes(e.target.value)} rows={2} maxLength={4096}
                          placeholder="Working notes — commands run, hashes verified manually, hypotheses checked, …" />
              </div>

              {/* ISO/IEC 27042 — analysis & interpretation (Slice E) */}
              <div className="field">
                <label className="field-label" htmlFor="exw-findings">
                  Findings <span style={{ fontWeight: 400, color: 'var(--muted)', fontSize: 12 }}>· ISO 27042 — what was found</span>
                </label>
                <textarea id="exw-findings" className="input" value={findings}
                          onChange={e => setFindings(e.target.value)} rows={3} maxLength={8192}
                          placeholder="Artefacts / indicators / timeline facts recovered" />
              </div>
              <div className="field">
                <label className="field-label" htmlFor="exw-interp">Interpretation <span style={{ fontWeight: 400, color: 'var(--muted)', fontSize: 12 }}>· what it means</span></label>
                <textarea id="exw-interp" className="input" value={interpretation}
                          onChange={e => setInterpretation(e.target.value)} rows={2} maxLength={8192}
                          placeholder="What the findings mean for the investigation (kept separate from raw findings)" />
              </div>
              <div className="form-row">
                <div className="field">
                  <label className="field-label" htmlFor="exw-conf">Confidence</label>
                  <select id="exw-conf" className="select" value={confidence} onChange={e => setConfidence(e.target.value)}>
                    <option value="">— select —</option>
                    <option value="low">Low</option>
                    <option value="moderate">Moderate</option>
                    <option value="high">High</option>
                  </select>
                </div>
                <div className="field">
                  <label className="field-label" htmlFor="exw-scope">Scope limitations <span style={{ fontWeight: 400, color: 'var(--muted)', fontSize: 12 }}>· item 12</span></label>
                  <input id="exw-scope" className="input" value={scopeLimitations}
                         onChange={e => setScopeLimitations(e.target.value)} maxLength={4096}
                         placeholder="What was NOT examined / caveats (e.g. encrypted container not opened)" />
                </div>
              </div>

              {/* GS-2 / G5 — what the analysis ran on (ISO/IEC 27037 §7.1.3.1.1) + the copy hash bracket */}
              <ExamTarget copies={workingCopies} value={target} onChange={setTarget} idPrefix="exw" />
              {!target.inPlace && (
                <div className="form-row">
                  <div className="field">
                    <label className="field-label" htmlFor="exw-pre">Copy hash before (optional)</label>
                    <input id="exw-pre" className="input" value={preHash} onChange={e => setPreHash(e.target.value)}
                           maxLength={64} spellCheck={false} style={{ fontFamily: 'var(--font-mono)' }} placeholder="MD5 / SHA-1 / SHA-256" />
                  </div>
                  <div className="field">
                    <label className="field-label" htmlFor="exw-post">Copy hash after (required)</label>
                    <input id="exw-post" className="input" value={postHash} onChange={e => setPostHash(e.target.value)}
                           maxLength={64} spellCheck={false} style={{ fontFamily: 'var(--font-mono)' }} placeholder="MD5 / SHA-1 / SHA-256" />
                  </div>
                </div>
              )}
            </div>
          )}

          {result && (
            <div className="form">
              <div className={`alert ${result.ok ? 'info' : 'error'}`} role="status">
                <span className="alert-icon">{result.ok ? '✓' : '!'}</span>
                <span>{result.message}</span>
              </div>
              <div style={{
                padding: 'var(--space-2) var(--space-3)', background: 'var(--surface-2)',
                border: '1px solid var(--border)', borderRadius: 'var(--radius)',
                fontFamily: 'var(--font-mono)', fontSize: 11,
              }}>
                <div><strong>session_id:</strong> {result.session_id}</div>
                {result.examined_in_place && <div><strong>examined in place</strong> (no working copy)</div>}
                {result.copy_identifier && <div><strong>working copy:</strong> {result.copy_identifier}</div>}
                {result.copy_hash_recorded && (
                  <div><strong>recorded ({result.hash_algorithm}):</strong> {result.copy_hash_recorded.slice(0, 24)}…</div>
                )}
                {result.pre_exam_copy_hash && (
                  <div><strong>before:</strong> {result.pre_exam_copy_hash.slice(0, 24)}… {result.pre_exam_match ? '✓ match' : '✗ MISMATCH'}</div>
                )}
                {result.post_exam_copy_hash && (
                  <div><strong>after:</strong> {result.post_exam_copy_hash.slice(0, 24)}… {result.post_exam_match ? '✓ match' : '✗ MISMATCH'}</div>
                )}
              </div>
            </div>
          )}

          {error && (
            <div className="alert error" role="alert" style={{ marginTop: 'var(--space-3)' }}>
              <span className="alert-icon">!</span><span>{error}</span>
            </div>
          )}
        </div>

        <div className="modal-foot">
          <button type="button" className="btn ghost" onClick={onClose} disabled={busy}>
            {result ? 'Close' : 'Cancel'}
          </button>
          {!result && (
            <button type="button" className="btn primary" onClick={run} disabled={busy}>
              {busy ? 'Running examination session…' : 'Run session'}
            </button>
          )}
          {result && (
            <button type="button" className="btn primary" onClick={() => onSaved?.(result)}>
              Done
            </button>
          )}
        </div>
      </div>
    </div>
  )
}
