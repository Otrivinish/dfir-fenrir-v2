// Mirror of backend/evidence/provenance.py for instant per-row scoring.
// Kept intentionally simple — the backend is the source of truth for handoff
// gating; this helper is for live UX (pill + chain-integrity card).

const SEV_WEIGHT = { mandatory: 2, advisory: 1 }

// C3 — an imaging tool reports MD5, SHA-1 or SHA-256; the algorithm follows from the
// hex length (same rule as backend/evidence/hashing.py). null = not a valid hash.
const HASH_ALGORITHM = { 32: 'MD5', 40: 'SHA-1', 64: 'SHA-256' }
export function hashAlgorithm(value) {
  return value && /^[0-9a-fA-F]+$/.test(value) ? (HASH_ALGORITHM[value.length] || null) : null
}

function check(code, label, status, severity, note) {
  return { code, label, status, severity, note: note || null }
}

const blank = (v) => !(v || '').trim()
const EXPORT_TYPES = ['email_export', 'vendor_report', 'network_capture']

// S3 — the seal gate's source rule (HLD §3.3, owner Q1). Same rule as backend/evidence/source.py
// seal_source_missing: what a digital exhibit lacks of its source record ([] = met), not counting
// source_unknown_reason (which meets all of it). The device = an entity, the source system or the serial (make and
// model alone do not identify a device); the path: a full image needs a device path (style device); live data and
// exports need none; anything else needs the path and its style.
export function sourceMissing(ev) {
  const missing = (ev.entity_id || !blank(ev.source_system) || !blank(ev.serial)) ? [] : ['source_device']
  const hasPath = ev.source_path != null && !!ev.source_path_style
  if (ev.acquisition_scope === 'full_image') {
    if (!hasPath) missing.push('source_path')
    else if (ev.source_path_style !== 'device') missing.push('source_path_style')
  } else if (!(['live', 'live_critical'].includes(ev.system_state || '')
               || (ev.device_types || []).some(t => EXPORT_TYPES.includes(t))) && !hasPath) {
    missing.push('source_path')
  }
  return missing
}
export const SOURCE_MISSING_LABEL = {
  source_device: 'the source device (an entity, the source system or the serial)',
  source_path: 'the source path and its style',
  source_path_style: 'a device path (style device) for the full image',
}

// S2/S3 — HLD §3.3 (ISO/IEC 27037 §5.4.2, §6.6, §7.1.3.4). Mandatory once a seal bound it (record_v1:
// seal_record_sha256 set), advisory otherwise. Same rule as provenance.py _source_location.
function sourceLocation(ev) {
  const missing = sourceMissing(ev)
  let status = 'pass', note = null
  if (missing.length && !blank(ev.source_unknown_reason)) {
    status = 'manual'; note = `Source stated as unknown: ${ev.source_unknown_reason.slice(0, 200)}`
  } else if (missing.length) {
    status = 'fail'; note = `Record ${missing.map(m => SOURCE_MISSING_LABEL[m]).join(' and ')}, or say why the source is unknown`
  }
  return check('iso_27037_source_location', 'Source location recorded (device + path)', status,
    ev.coc_sealed && ev.seal_record_sha256 ? 'mandatory' : 'advisory', note)
}

// S4 — each photo says who took it, when and with what camera (ISO/IEC 27037 §6.6; advisory). The API's taken_at is
// already a valid UTC time or null (a legacy value is in taken_at_unparsed). Same rule as provenance.py _photo_record.
function photoRecord(ev) {
  const photos = (ev.photos || []).filter(p => p && typeof p === 'object')
  if (!photos.length) return null
  const gaps = { 'taken by': 0, 'taken at': 0, camera: 0 }
  let incomplete = 0
  for (const p of photos) {
    const lacks = [['taken by', !!p.taken_by_id || !blank(p.taken_by_name)], ['taken at', !!p.taken_at],
      ['camera', !blank(p.camera)]].filter(([, ok]) => !ok).map(([k]) => k)
    if (lacks.length) incomplete++
    for (const k of lacks) gaps[k]++
  }
  return check('iso_27037_photo_record', 'Photo record complete (taken by, taken at, camera)',
    incomplete ? 'fail' : 'pass', 'advisory',
    incomplete ? `${incomplete} of ${photos.length} photo(s) lack: ${Object.keys(gaps).filter(k => gaps[k]).join(', ')}` : null)
}

// EG-5 — the provider's own hash vs the stored file (advisory). Same rule as source.py provider_hash_check: only
// MD5 / SHA-1 / SHA-256, given as hex or base64 (Azure Content-MD5, S3 checksums).
const DIGEST_SIZE = { md5: 16, sha1: 20, sha256: 32 }
const ALGO_LABEL = { md5: 'MD5', sha1: 'SHA-1', sha256: 'SHA-256' }
function digestHex(value, size) {
  const v = (value || '').trim()
  if (v.length === 2 * size && /^[0-9a-fA-F]+$/.test(v)) return v.toLowerCase()
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(v) || v.length % 4) return null
  let bin
  try { bin = atob(v) } catch { return null }
  if (bin.length !== size) return null
  return Array.from(bin, c => c.charCodeAt(0).toString(16).padStart(2, '0')).join('')
}
function providerHash(ev) {
  const ph = ev.source_details?.provider?.provider_hash
  if (!ph) return null
  const label = "Provider's hash matches the stored file"
  const algo = String(ph.algorithm || '').toLowerCase().replace(/[-_]/g, '')
  if (!DIGEST_SIZE[algo])
    return check('source_provider_hash_match', label, 'n_a', 'advisory',
      `${ph.algorithm} is recorded as given; FENRIR compares only MD5, SHA-1 and SHA-256`)
  const hex = digestHex(String(ph.value || ''), DIGEST_SIZE[algo])
  if (!hex) return check('source_provider_hash_match', label, 'n_a', 'advisory', 'the value is not hex or base64 of that algorithm')
  const stored = ev[algo]
  if (!stored) return check('source_provider_hash_match', label, 'n_a', 'advisory', 'no stored file to compare')
  const ok = hex === stored.toLowerCase()
  return check('source_provider_hash_match', label, ok ? 'pass' : 'fail', 'advisory',
    ok ? null : `The provider's ${ALGO_LABEL[algo]} differs from the stored file's: the copy may not be the provider's object`)
}

// S6 — a container exhibit's per-file manifest (advisory). Same rule as provenance.py _container_manifest.
function containerManifest(ev) {
  const label = 'Container contents listed (per-file manifest)'
  if (!ev.container_format) return check('container_manifest', label, 'n_a', 'advisory', 'Not a container exhibit')
  if (ev.manifest_status === 'built') {
    const bad = (ev.manifest_listing || []).reduce((n, s) => n + (Number(s?.tool_hash_mismatches) || 0), 0)
    return check('container_manifest', label, bad ? 'fail' : 'pass', 'advisory',
      bad ? `${bad} member(s) differ from the tool listing's hash` : null)
  }
  const note = {
    pending: 'The manifest is still being built',
    not_indexed: `FENRIR does not index ${ev.container_format} containers: list the contents from the tool's own report`,
    failed: `The manifest could not be built: ${(ev.manifest_error || '').slice(0, 200)}`,
  }[ev.manifest_status] || 'No manifest'
  return check('container_manifest', label, 'manual', 'advisory', note)
}

export function scoreEvidence(ev) {
  const checks = []
  const isDigital  = ev.kind === 'digital_file'
  const isPhysical = ev.kind === 'physical_item'

  if (isPhysical) {
    const ok = Array.isArray(ev.photos) && ev.photos.length > 0
    checks.push(check('iso_27037_9_1_4', 'In-situ photograph captured (ISO/IEC 27037 §6.2.1)',
      ok ? 'pass' : 'fail', 'mandatory',
      ok ? null : 'Physical evidence requires at least one photo'))
    // S2 — make, model and serial "when possible" (ISO/IEC 27037 §7.1.1.1; advisory)
    const missing = ['make', 'model', 'serial'].filter(f => blank(ev[f]))
    checks.push(check('iso_27037_device_identifiers', 'Device identifiers recorded (make, model, serial)',
      missing.length ? 'fail' : 'pass', 'advisory',
      missing.length ? `Record the item's ${missing.join(', ')} where possible` : null))
  }
  const photoRec = photoRecord(ev)
  if (photoRec) checks.push(photoRec)

  checks.push(check('iso_27037_collector', 'Collector identified',
    ev.collected_by_id ? 'pass' : 'fail', 'mandatory'))
  checks.push(check('iso_27037_collection_location', 'Collection location recorded',
    (ev.collected_location || '').trim() ? 'pass' : 'fail', 'advisory'))
  if (isDigital) checks.push(sourceLocation(ev))
  checks.push(check('gdpr_5_1_c_lawful_basis', 'Lawful basis recorded',
    ev.lawful_basis ? 'pass' : 'fail', 'mandatory',
    ev.lawful_basis ? null : 'GDPR Art. 5.1(c)'))

  if (isDigital) {
    checks.push(check('iso_27037_9_2_3_sha256', 'SHA-256 captured at acquisition (ISO/IEC 27037 §5.4.4)',
      ev.sha256 ? 'pass' : 'fail', 'mandatory'))
    const wb = ev.write_blocker_used
    const ss = (ev.system_state || '').toLowerCase()
    if (wb == null && !ss) {
      checks.push(check('iso_27037_9_2_1_writeblocker',
        'Write-blocker / live-acquisition status (ISO/IEC 27037 §5.4.4, §7.1.3)',
        'fail', 'advisory', 'Run the acquisition wizard'))
    } else {
      let ok = true, note = null
      // FP-4: live and live_critical both need a justification, as at the seal.
      if ((ss === 'live' || ss === 'live_critical') && !(ev.live_justification || '').trim()) {
        ok = false; note = 'Live acquisition needs justification'
      }
      checks.push(check('iso_27037_9_2_1_writeblocker',
        'Write-blocker / live-acquisition status (ISO/IEC 27037 §5.4.4, §7.1.3)',
        ok ? 'pass' : 'fail', 'advisory', note))
    }
    const toolOk = !!(ev.acquisition_tool && ev.acquisition_tool_version)
    checks.push(check('iso_27037_9_2_4_tool',
      'Acquisition tool + version documented (ISO/IEC 27037 §5.4.4)',
      toolOk ? 'pass' : 'fail',
      ev.coc_sealed ? 'mandatory' : 'advisory'))
    const srcAlgo = hashAlgorithm(ev.acquisition_hash_source)
    const tgtAlgo = hashAlgorithm(ev.acquisition_hash_target)
    if (srcAlgo && tgtAlgo && srcAlgo !== tgtAlgo) {
      // Different algorithms can't be compared here: advisory, never a mandatory fail.
      checks.push(check('iso_27037_9_2_5_hash_match',
        'Acquisition source/target hash match (ISO/IEC 27037 §5.4.4)',
        'manual', 'advisory',
        `Source (${srcAlgo}) and target (${tgtAlgo}) use different algorithms — confirm the match in the imaging tool's report`))
    } else if (!ev.acquisition_hash_source !== !ev.acquisition_hash_target) {
      // One hash alone has nothing to compare with: advisory, not a mismatch (mirrors provenance.py _ONE_HASH_NOTE).
      checks.push(check('iso_27037_9_2_5_hash_match',
        'Acquisition source/target hash match (ISO/IEC 27037 §5.4.4)',
        'manual', 'advisory',
        ev.acquisition_hash_target
          ? "Only the target hash is recorded, so there is nothing to compare it with: confirm the source hash in the tool's report (a screenshot or other capture has none)"
          : "Only the source hash is recorded, so there is nothing to compare it with: record the target hash from the tool's report"))
    } else if (ev.acquisition_hash_source || ev.acquisition_hash_target) {
      const m = (ev.acquisition_hash_source || '').toLowerCase()
             === (ev.acquisition_hash_target || '').toLowerCase()
      checks.push(check('iso_27037_9_2_5_hash_match',
        'Acquisition source/target hash match (ISO/IEC 27037 §5.4.4)',
        m ? 'pass' : 'fail', 'mandatory',
        m ? null : 'Source ≠ target — re-acquire'))
    }
    const provider = providerHash(ev)
    if (provider) checks.push(provider)
    checks.push(containerManifest(ev))
  }

  const chainOk = ev.status !== 'verify_failed'
  checks.push(check('custody_chain_unbroken', 'Chain unbroken',
    chainOk ? 'pass' : 'fail', 'mandatory',
    chainOk ? null : 'Integrity verify failed'))

  // External-custody flag — ISO 27037 §6.1 still holds (chain is intact) but
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

  // C4 — internal custody transfers accepted by the recipient. Legacy transfers (recorded
  // before acceptance existed) are advisory ("manual"), never a fail; none → no check.
  const legacyTransfers = ev.internal_transfers_legacy || 0
  if (legacyTransfers) {
    checks.push(check('custody_transfers_acknowledged',
      'Custody transfers acknowledged by the recipient',
      'manual', 'advisory',
      `${legacyTransfers} transfer(s) recorded before recipient acceptance existed — confirm receipt and condition from the paper record`))
  } else if (ev.internal_transfers_acknowledged) {
    checks.push(check('custody_transfers_acknowledged',
      'Custody transfers acknowledged by the recipient',
      'pass', 'mandatory'))
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
      wc ? null : 'No verified working copy yet — download one, or record a lab copy with its hash, in the item detail'))
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
