// Mirror of backend/evidence/provenance.py for instant per-row scoring.
// Kept intentionally simple — the backend is the source of truth for handoff
// gating; this helper is for live UX (pill + chain-integrity card).

const SEV_WEIGHT = { mandatory: 2, advisory: 1 }

function check(code, label, status, severity, note) {
  return { code, label, status, severity, note: note || null }
}

export function scoreEvidence(ev) {
  const checks = []
  const isDigital  = ev.kind === 'digital_file'
  const isPhysical = ev.kind === 'physical_item'

  if (isPhysical) {
    const ok = Array.isArray(ev.photos) && ev.photos.length > 0
    checks.push(check('iso_27037_9_1_4', 'In-situ photograph captured',
      ok ? 'pass' : 'fail', 'mandatory',
      ok ? null : 'Physical evidence requires at least one photo'))
  }

  checks.push(check('iso_27037_collector', 'Collector identified',
    ev.collected_by_id ? 'pass' : 'fail', 'mandatory'))
  checks.push(check('iso_27037_collection_location', 'Collection location recorded',
    (ev.collected_location || '').trim() ? 'pass' : 'fail', 'advisory'))
  checks.push(check('gdpr_5_1_c_lawful_basis', 'Lawful basis recorded',
    ev.lawful_basis ? 'pass' : 'fail', 'mandatory',
    ev.lawful_basis ? null : 'GDPR Art. 5.1(c)'))

  if (isDigital) {
    checks.push(check('iso_27037_9_2_3_sha256', 'SHA-256 captured at acquisition',
      ev.sha256 ? 'pass' : 'fail', 'mandatory'))
    const wb = ev.write_blocker_used
    const ss = (ev.system_state || '').toLowerCase()
    if (wb == null && !ss) {
      checks.push(check('iso_27037_9_2_1_writeblocker',
        'Write-blocker / live-acquisition status',
        'fail', 'advisory', 'Run the acquisition wizard'))
    } else {
      let ok = true, note = null
      if (ss === 'live' && !(ev.live_justification || '').trim()) {
        ok = false; note = 'Live acquisition needs justification'
      }
      checks.push(check('iso_27037_9_2_1_writeblocker',
        'Write-blocker / live-acquisition status',
        ok ? 'pass' : 'fail', 'advisory', note))
    }
    const toolOk = !!(ev.acquisition_tool && ev.acquisition_tool_version)
    checks.push(check('iso_27037_9_2_4_tool',
      'Acquisition tool + version documented',
      toolOk ? 'pass' : 'fail',
      ev.coc_sealed ? 'mandatory' : 'advisory'))
    if (ev.acquisition_hash_source || ev.acquisition_hash_target) {
      const m = (ev.acquisition_hash_source || '').toLowerCase()
             === (ev.acquisition_hash_target || '').toLowerCase()
      checks.push(check('iso_27037_9_2_5_hash_match',
        'Acquisition source/target hash match',
        m ? 'pass' : 'fail', 'mandatory',
        m ? null : 'Source ≠ target — re-acquire'))
    }
  }

  const chainOk = ev.status !== 'verify_failed'
  checks.push(check('custody_chain_unbroken', 'Chain unbroken',
    chainOk ? 'pass' : 'fail', 'mandatory',
    chainOk ? null : 'Integrity verify failed'))

  // External-custody flag — ISO 27037 §9.3 still holds (chain is intact) but
  // examine/verify/seal are paused while the row is externally held.
  const isExternalNow = !ev.current_custodian_id && !!ev.current_custodian_external_name
  if (isExternalNow) {
    const holder = ev.current_custodian_external_name
                 + (ev.current_custodian_external_org ? ` (${ev.current_custodian_external_org})` : '')
    checks.push(check('custody_internal_holder',
      'Currently held by an internal accountable user',
      'fail', 'advisory',
      `In external custody: ${holder}. Take it back to re-enable examine/verify/seal.`))
  } else {
    checks.push(check('custody_internal_holder',
      'Currently held by an internal accountable user',
      'pass', 'advisory'))
  }

  checks.push(check('wizard_a_sealed', 'Acquisition wizard sealed',
    ev.coc_sealed ? 'pass' : 'manual', 'advisory'))

  // GS-4 — trusted timestamp on the seal (RFC 3161; advisory)
  if (ev.coc_sealed) {
    const tsOk = !!(ev.seal_tst_time || '').trim()
    checks.push(check('rfc3161_seal_timestamp',
      'Seal carries an independent trusted timestamp',
      tsOk ? 'pass' : 'manual', 'advisory',
      tsOk ? null : 'Server-clock only — configure a TSA for an RFC-3161 timestamp at seal'))
  }

  // ISO/IEC 27041 — method/tool validation (Slice B; advisory/soft)
  if (isDigital) {
    const valOk = ev.acquisition_tool_validated === true
    checks.push(check('iso_27041_method_validated',
      'Acquisition tool/method validated (ISO/IEC 27041)',
      valOk ? 'pass' : 'fail', 'advisory',
      valOk ? null : 'Record that the acquisition tool/method was validated (27041, item 7)'))
  }
  // Expert qualifications (ISO 27037 Annex A / 27041; advisory)
  const qualOk = !!(ev.collected_by_qualifications || '').trim()
  checks.push(check('iso_27037_annex_a_qualifications', 'Collector qualifications recorded',
    qualOk ? 'pass' : 'fail', 'advisory',
    qualOk ? null : "Set the collector's qualifications on their user profile (item 10)"))

  // Collector role DEFR/DES (ISO/IEC 27037 §3.7/§3.8; GS-12; advisory)
  const roleOk = ev.collected_as_role === 'defr' || ev.collected_as_role === 'des'
  checks.push(check('iso_27037_3_7_collector_role', 'Collector role recorded (DEFR/DES)',
    roleOk ? 'pass' : 'fail', 'advisory',
    roleOk ? null : 'Record DEFR (first responder) or DES (specialist) — ISO 27037 §3.7/§3.8'))

  // ISO/IEC 27037 §7.1.3.1.1 — working copy verified vs master (Slice D; advisory)
  if (isDigital) {
    const wc = ev.has_verified_working_copy === true
    checks.push(check('iso_27037_7_1_3_1_1_working_copy',
      'Analysis used a master-verified working copy',
      wc ? 'pass' : 'manual', 'advisory',
      wc ? null : 'No verified working copy yet — an export auto-creates one'))
  }

  // ISO/IEC 27042 — examination documentation (GS-3; advisory; only once examined)
  if (isDigital && ev.has_examination === true) {
    const fOk = ev.has_examination_findings === true
    checks.push(check('iso_27042_findings', 'Examination findings/interpretation recorded',
      fOk ? 'pass' : 'fail', 'advisory',
      fOk ? null : 'Record findings + interpretation in the examination wizard (ISO 27042 item 8)'))
    const sOk = ev.has_examination_scope === true
    checks.push(check('iso_27042_scope_limitations', 'Examination scope limitations recorded',
      sOk ? 'pass' : 'fail', 'advisory',
      sOk ? null : 'Record what was NOT examined / caveats (ISO 27042 item 12)'))
  }

  // Roll up
  const failMand = checks.filter(c => c.status === 'fail' && c.severity === 'mandatory').length
  const failAdv  = checks.filter(c => c.status === 'fail' && c.severity === 'advisory').length
  const hasManual = checks.some(c => c.status === 'manual')

  let score = 'green'
  let summary = 'All applicable checks pass'
  if (failMand)        { score = 'red';   summary = `${failMand} mandatory check(s) failing` }
  else if (failAdv)    { score = 'amber'; summary = `${failAdv} advisory check(s) failing` }
  else if (hasManual)  { score = 'amber'; summary = 'Manual confirmation pending' }

  // Completeness ratio (ISO/IEC 27041 paper rubric): % of determinable checks passing.
  const determinable = checks.filter(c => c.status === 'pass' || c.status === 'fail')
  const passes = determinable.filter(c => c.status === 'pass').length
  const completeness = determinable.length ? Math.round(100 * passes / determinable.length) : 100

  return { score, summary, checks, completeness }
}

export function severityColor(score) {
  if (score === 'green') return 'var(--ok)'
  if (score === 'amber') return 'var(--med)'
  if (score === 'red')   return 'var(--crit)'
  return 'var(--muted)'
}

// Aggregate for the chain-integrity card.
export function aggregateIntegrity(items) {
  const total = items.length
  let sealed = 0, verifyFailed = 0, onHold = 0
  const dist = { green: 0, amber: 0, red: 0 }
  for (const it of items) {
    if (it.coc_sealed) sealed++
    if (it.status === 'verify_failed') verifyFailed++
    if (it.legal_hold) onHold++
    const s = scoreEvidence(it)
    dist[s.score] = (dist[s.score] || 0) + 1
  }
  return { total, sealed, verifyFailed, onHold, dist }
}
