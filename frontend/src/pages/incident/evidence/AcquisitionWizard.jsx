import { useEffect, useState } from 'react'
import { api } from '../../../api/client.js'
import { TLP } from '../../../lib/incidentVocab.js'
import { formatLocal } from '../../../lib/datetime.js'
import { hashAlgorithm } from '../../../lib/evidenceProvenance.js'
import LocalDateTimePicker from '../../../components/LocalDateTimePicker.jsx'
import { fmtOffset, parseOffsetSeconds } from '../../../components/ClockOffset.jsx'
import UploadProgress, { useChunkedUpload, useRetainedUpload } from '../../../components/UploadProgress.jsx'

// Collection wizard — ISO/IEC 27037 §7 (branch-aware).
//
// Spine = 27037 Figure 1 (collect vs acquire × device state). Device type is a
// non-exclusive context tag that injects the §7 sub-procedure's extras. Steps:
//   type     — device type tag(s) + digital/physical kind
//   identify — lawful basis, source description, in-situ photo (physical only)
//   decide   — system state, collect/acquire, §7.1.1.3 decision factors
//   branch   — per-type extras (computer/storage/mobile/network/cctv)
//   acquire  — file + acquisition time + tool/version/params, source/target hashes
//              (MD5 / SHA-1 / SHA-256) and what the target hash covers (digital)
//   witness  — second user co-signs (optional)
//   confirm  — seal-readiness preview + Collect & seal
//
// Steps are shown only when relevant: `branch` when a type is tagged, `acquire`
// only for digital_file. After collecting we call POST /seal which enforces the
// minimum ISO 27037 + GDPR fields server-side; if seal 422s the row is still
// created and can be sealed later.
//
// Implements docs/coc-collection-wizard-slice.md (Slice A). The file name stays
// AcquisitionWizard.jsx by design; only the user-facing labels say "Collection".
//
// G3 — `existing` = "Complete & seal" an unsealed item already registered (e.g. a draft exhibit an
// Email / PCAP / Browser history upload created, or a Quick add): the same steps, prefilled from the
// item; the stored file is kept (no upload); Save calls PATCH …/acquisition-record, then /seal.
// G-fix FE-H1: photos already stored on the item are never re-sent (a PATCH of the photo list can't
// remove them and must name each by id); a caption is added only when the item has no stored photo.
// G-fix FE-M2: a refused complete (identifier taken, 507, a 422 input error) keeps the uploaded file on
// the server: fix the field and Collect again — nothing is re-sent.

const LAWFUL_BASIS = [
  { value: 'ir',           label: 'Incident response (LIA — legitimate interest)' },
  { value: 'consent',      label: 'Subject consent (data subject authorised)' },
  { value: 'warrant',      label: 'Warrant (judicial authorisation)' },
  { value: 'court_order',  label: 'Court order' },
  { value: 'eio',          label: 'European Investigation Order (Dir. 2014/41/EU)' },
  { value: 'mla',          label: 'Mutual Legal Assistance (Budapest Conv. Art. 31)' },
  { value: 'lia',          label: 'Legitimate Interest Assessment (other)' },
  { value: 'other',        label: 'Other (justify in note)' },
]

const SYSTEM_STATE = [
  { value: 'powered_off',  label: 'Powered off (forensic image)' },
  { value: 'live',         label: 'Live system (justify below)' },
  { value: 'live_critical', label: 'Live — cannot power off / mission-critical (justify)' },
  { value: 'unknown',      label: 'Unknown' },
]

const DEVICE_TYPES = [
  { value: 'computer',   label: 'Computer' },
  { value: 'peripheral', label: 'Peripheral' },
  { value: 'storage',    label: 'Storage media' },
  { value: 'mobile',     label: 'Mobile' },
  { value: 'network',    label: 'Network device' },
  { value: 'cctv',       label: 'CCTV / VSS' },
  // K1 (R37): data handed over as an export, with no device to tag (no §7 branch checklist).
  { value: 'email_export',    label: 'Email export' },
  { value: 'vendor_report',   label: 'Vendor report' },
  { value: 'network_capture', label: 'Network capture export' },
]
// The types whose §7 checklist is on the Branch step.
const BRANCH_TYPES = ['computer', 'peripheral', 'storage', 'mobile', 'network', 'cctv']

const HANDLING_MODE = [
  { value: 'acquire', label: 'Acquire — image / copy here' },
  { value: 'collect', label: 'Collect — seize the device' },
]

// §7.1.1.3 factors that drive the collect-vs-acquire decision (advisory/soft).
const DECISION_FACTORS = [
  { key: 'volatile',             label: 'Volatile evidence present (RAM, connections, processes)' },
  { key: 'encryption_key_in_ram', label: 'Disk/volume encryption — key may live in RAM (power-off may lose access)' },
  { key: 'criticality',          label: 'System is mission/safety-critical (downtime not tolerated)' },
  { key: 'legal',                label: 'Jurisdiction imposes special handling (e.g. seal in owner presence)' },
  { key: 'resources',            label: 'Resource constraints (storage / personnel / time)' },
]

const ISOLATION_METHODS = [
  { value: '',                 label: '— select —' },
  { value: 'none',             label: 'None' },
  { value: 'wired_disconnect', label: 'Wired link disconnected' },
  { value: 'wifi_disable',     label: 'Wi-Fi / access point disabled' },
  { value: 'faraday',          label: 'Faraday / EM-shielded enclosure' },
  { value: 'jammer',           label: 'Signal jammer (⚠ legality varies)' },
  { value: 'usim_substitute',  label: 'Substitute (U)SIM' },
  { value: 'provider_disable', label: 'Services disabled via provider' },
]

const CCTV_OPTIONS = [
  { value: '', label: '— select —' },
  { value: '1', label: '1 · Burn to CD/DVD/Blu-ray' },
  { value: '2', label: '2 · Copy to external storage medium' },
  { value: '3', label: '3 · Pull over network port' },
  { value: '4', label: '4 · Export to MPEG/AVI (last resort — recompresses)' },
  { value: '5', label: '5 · Analog copy from analog output' },
]

function StepHeader({ n, total, title, subtitle }) {
  return (
    <div style={{
      display: 'flex', alignItems: 'baseline', gap: 'var(--space-2)',
      marginBottom: 'var(--space-3)',
    }}>
      <span style={{
        fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--accent)',
        padding: '2px 8px', borderRadius: 'var(--radius-sm)',
        background: 'var(--accent-soft)',
      }}>STEP {n}/{total}</span>
      <h3 style={{ margin: 0, fontSize: 15 }}>{title}</h3>
      {subtitle && (
        <span style={{ color: 'var(--muted)', fontSize: 12 }}>{subtitle}</span>
      )}
    </div>
  )
}

// C3 — an imaging tool reports MD5, SHA-1 or SHA-256: accept 32 / 40 / 64 hex and show
// which algorithm the length means. `sha256Only` keeps the tool-fingerprint field strict.
function HashInput({ id, value, onChange, placeholder, disabled, sha256Only = false }) {
  const algo = hashAlgorithm(value)
  const ok = !!value && (sha256Only ? algo === 'SHA-256' : !!algo)
  const bad = !!value && !ok
  const hintId = id ? `${id}-algo` : undefined
  return (
    <>
      <input
        id={id}
        className="input compact"
        value={value || ''}
        onChange={(e) => onChange(e.target.value.trim())}
        placeholder={placeholder}
        maxLength={64}
        disabled={disabled}
        aria-invalid={bad || undefined}
        aria-describedby={sha256Only ? undefined : hintId}
        style={{ fontFamily: 'var(--font-mono)',
          borderColor: bad ? 'var(--crit)' : (ok ? 'var(--ok)' : undefined) }}
      />
      {!sha256Only && (
        <div id={hintId} className="field-hint" data-hash-algo={algo || ''}
             style={bad ? { color: 'var(--crit)' } : undefined}>
          {!value ? 'MD5, SHA-1 or SHA-256 (32 / 40 / 64 hex)'
            : algo ? `${algo} · ${value.length} hex`
            : 'Not a hash — use 32 (MD5), 40 (SHA-1) or 64 (SHA-256) hex characters'}
        </div>
      )}
    </>
  )
}

function TypeChip({ active, label, onClick }) {
  return (
    <button type="button" onClick={onClick} style={{
      cursor: 'pointer', fontSize: 12.5, padding: '5px 12px',
      borderRadius: 'var(--radius-lg)',
      border: `1px solid ${active ? 'var(--accent)' : 'var(--border)'}`,
      background: active ? 'var(--accent)' : 'var(--surface)',
      color: active ? 'var(--bg)' : 'var(--text)',
      fontWeight: active ? 600 : 400,
    }}>{label}</button>
  )
}

function SealCheck({ ok, label }) {
  return (
    <li style={{ display: 'flex', gap: 8, alignItems: 'baseline', listStyle: 'none' }}>
      <span style={{ color: ok ? 'var(--ok)' : 'var(--crit)', fontWeight: 700 }}>{ok ? '✓' : '✗'}</span>
      <span style={{ color: ok ? 'var(--muted)' : 'var(--crit)' }}>{label}</span>
    </li>
  )
}

// G-fix (R101): the photo-list merge refusals (nothing was changed), in words.
function photoErrorText(e) {
  if (e?.data?.code === 'unknown_photo_id' || e?.code === 'unknown_photo_id')
    return 'a photo on the item changed meanwhile (unknown photo id), so nothing was changed. Close this, reopen the item and try again.'
  if (e?.data?.code === 'photo_remove_not_supported' || e?.code === 'photo_remove_not_supported')
    return 'an uploaded photo can’t be removed, so nothing was changed. Reopen the item and try again.'
  return e?.message || 'the photo list could not be saved.'
}

export default function AcquisitionWizard({
  incidentId, entities = [], users = [], onClose, onSaved, existing = null,
}) {
  // G3 — completing an existing unsealed item: every field starts from what it already records.
  const completing = !!existing
  const ex = existing || {}
  const tri = (v) => (v === true ? 'true' : v === false ? 'false' : '')
  const exPhotos = ex.photos || []
  const storedPhotos = exPhotos.filter(p => p && p.id)     // uploaded (encrypted) photos: never re-sent
  const { note: exDecisionNote, ...exDecisionFactors } = ex.decision_factors || {}
  // ── Shared identity ───────────────────────────────────────────────────
  const [kind, setKind]             = useState(ex.kind || 'digital_file')
  const [name, setName]             = useState(ex.name || '')
  const [identifier, setIdentifier] = useState(ex.identifier || '')
  const [tlp, setTlp]               = useState(ex.tlp || 'amber')
  const [description, setDescription] = useState(ex.description || '')
  const [entityId, setEntityId]     = useState(ex.entity_id || '')
  const [collectedLocation, setCollectedLocation] = useState(ex.collected_location || '')
  const [collectedAsRole, setCollectedAsRole]     = useState(ex.collected_as_role || '')   // GS-12 — '' | defr | des

  // ── Type step ─────────────────────────────────────────────────────────
  const [deviceTypes, setDeviceTypes] = useState(ex.device_types || [])

  // ── Identify step ─────────────────────────────────────────────────────
  const [lawfulBasis, setLawfulBasis]         = useState(ex.lawful_basis || '')
  const [lawfulBasisNote, setLawfulBasisNote] = useState(ex.lawful_basis_note || '')
  const [photoCaption, setPhotoCaption]       = useState('')
  const [photoTakenAt, setPhotoTakenAt]       = useState('')   // FE-L9: else the seizure time, else unknown

  // ── Decide step ───────────────────────────────────────────────────────
  const [systemState, setSystemState]             = useState(ex.system_state || '')
  const [liveJustification, setLiveJustification]  = useState(ex.live_justification || '')
  const [handlingMode, setHandlingMode]            = useState(ex.handling_mode || 'acquire')
  const [decisionFactors, setDecisionFactors]      = useState(exDecisionFactors)
  const [decisionNote, setDecisionNote]            = useState(exDecisionNote || '')

  // ── Branch step (device_details) ──────────────────────────────────────
  const [dd, setDd] = useState(ex.device_details || {})
  const setDetail = (k, v) => setDd(prev => ({ ...prev, [k]: v }))

  // ── Acquire step (digital) ────────────────────────────────────────────
  const [writeBlockerUsed, setWriteBlockerUsed]   = useState(tri(ex.write_blocker_used))
  const [writeBlockerSerial, setWriteBlockerSerial] = useState(ex.write_blocker_serial || '')
  const [networkIsolated, setNetworkIsolated]     = useState(tri(ex.network_isolated))
  const [acquisitionTool, setAcquisitionTool]               = useState(ex.acquisition_tool || '')
  const [acquisitionToolVersion, setAcquisitionToolVersion] = useState(ex.acquisition_tool_version || '')
  const [acquisitionToolSha256, setAcquisitionToolSha256]   = useState(ex.acquisition_tool_sha256 || '')
  const [acquisitionParams, setAcquisitionParams]           = useState(ex.acquisition_params || '')
  const [acquisitionHashSource, setAcquisitionHashSource]   = useState(ex.acquisition_hash_source || '')
  const [acquisitionHashTarget, setAcquisitionHashTarget]   = useState(ex.acquisition_hash_target || '')
  // C3 — what the target hash covers: the uploaded file (compared, mismatch refused) or
  // an E01/AFF4 container's media (recorded as advisory, not compared).
  const [targetHashScope, setTargetHashScope]     = useState(ex.upload_hash_check === 'container_media' ? 'container_media' : 'uploaded_file')
  const [acquiredAt, setAcquiredAt]               = useState(ex.acquired_at || '')   // UTC ISO …Z or ''
  const [acquisitionScope, setAcquisitionScope]   = useState(ex.acquisition_scope || '')   // '' | full_image | logical
  const [logicalRationale, setLogicalRationale]   = useState(ex.logical_acquisition_rationale || '')
  const [systemTimeOffset, setSystemTimeOffset]   = useState(ex.system_time_offset || '')
  // G4 (R35) — the same offset as a signed number of seconds (device clock minus true UTC); '' = not recorded.
  const [timeOffsetSeconds, setTimeOffsetSeconds] = useState(
    ex.system_time_offset_seconds === null || ex.system_time_offset_seconds === undefined ? '' : String(ex.system_time_offset_seconds))
  const [screenState, setScreenState]             = useState(ex.screen_state || '')
  const [changesMade, setChangesMade]             = useState(ex.changes_made || '')
  // ISO/IEC 27041 — tool/method validation (Slice B)
  const [toolValidated, setToolValidated]         = useState(tri(ex.acquisition_tool_validated))   // '' | true | false
  const [toolValidationRef, setToolValidationRef] = useState(ex.acquisition_tool_validation_ref || '')
  const [toolValidationDate, setToolValidationDate] = useState(ex.acquisition_tool_validation_date || '')
  // GS-1 — validated-tools registry (ISO/IEC 27041)
  const [validatedTools, setValidatedTools]       = useState([])
  const [file, setFile]   = useState(null)

  // ── Witness step ──────────────────────────────────────────────────────
  const [witnessUserId, setWitnessUserId] = useState(ex.witness_user_id || '')
  const [witnessName, setWitnessName]     = useState(ex.witness_name || '')

  // ── Step machinery ────────────────────────────────────────────────────
  const [step, setStep] = useState('type')
  const [busy, setBusy] = useState(false)
  const up = useChunkedUpload()   // G1 stage 3b: progress + cancel of the chunked upload
  const kept = useRetainedUpload() // FE-M2: an upload the server kept after a refused complete
  const [error, setError] = useState(null)
  const [sealResult, setSealResult] = useState(null)

  const isLive = systemState === 'live' || systemState === 'live_critical'
  // An in-situ photo caption is required for a physical item with no photo yet (ISO 27037 §6.2.1).
  const captionRequired = kind === 'physical_item' && !(completing && exPhotos.length)
  // FE-L9: a caption-only photo is dated by its own time, else the seizure time; never "now".
  const photoTime = photoTakenAt || acquiredAt || null
  const has = (t) => deviceTypes.includes(t)

  // C3 — source and target are compared only when both use the same algorithm.
  const srcAlgo = hashAlgorithm(acquisitionHashSource)
  const tgtAlgo = hashAlgorithm(acquisitionHashTarget)
  const hashesComparable = !!srcAlgo && srcAlgo === tgtAlgo
  const hashesMatch = hashesComparable &&
    acquisitionHashSource.toLowerCase() === acquisitionHashTarget.toLowerCase()

  // Step list per kind + tags. `branch` only when a type is tagged; `acquire`
  // only for digital files.
  const stepList = [
    'type', 'identify', 'decide',
    ...(deviceTypes.some(t => BRANCH_TYPES.includes(t)) ? ['branch'] : []),
    ...(kind === 'digital_file' ? ['acquire'] : []),
    'witness', 'confirm',
  ]
  const totalSteps = stepList.length
  const stepIdx = stepList.indexOf(step) + 1
  const isLastStep = step === 'confirm'

  useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape' && !busy) onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [busy, onClose])

  // GS-1 — load the validated-tools registry for the acquire step picker.
  useEffect(() => {
    api.listValidatedTools().then(r => setValidatedTools(r.items || [])).catch(() => {})
  }, [])

  // Picking a registry tool auto-fills tool/version + marks it validated with its ref.
  function pickRegistryTool(id) {
    const t = validatedTools.find(x => x.id === id)
    if (!t) return
    setAcquisitionTool(t.name)
    setAcquisitionToolVersion(t.version)
    setToolValidated('true')
    setToolValidationRef(t.validation_ref || '')
    setToolValidationDate(t.validated_at || '')
  }

  function toggleType(t) {
    setDeviceTypes(prev => prev.includes(t) ? prev.filter(x => x !== t) : [...prev, t])
  }

  // ── Per-step validation ────────────────────────────────────────────────
  function validateStep(s) {
    setError(null)
    if (s === 'type') {
      if (deviceTypes.length === 0) {
        setError('Tag at least one device type (ISO 27037 §7 — required to seal).'); return false
      }
    }
    if (s === 'identify') {
      if (!name.trim())       { setError('Name is required.'); return false }
      if (!identifier.trim()) { setError('Identifier is required.'); return false }
      if (!lawfulBasis)       { setError('Lawful basis is required (GDPR Art. 5.1(c)).'); return false }
      if ((lawfulBasis === 'other' || lawfulBasis === 'lia') && !lawfulBasisNote.trim()) {
        setError('This lawful basis requires a justification note.'); return false
      }
      if (captionRequired && !photoCaption.trim()) {
        setError('Physical evidence requires at least one in-situ photo caption (ISO 27037 §6.2.1).'); return false
      }
    }
    if (s === 'decide') {
      if (isLive && !liveJustification.trim()) {
        setError('Live / mission-critical acquisition requires justification (ISO 27037 §5.4.4 / §7.1.3.1.1).'); return false
      }
    }
    if (s === 'acquire') {
      if (kind === 'digital_file' && !file && !completing) { setError('Please choose a file to acquire.'); return false }
      if (!acquisitionTool.trim() || !acquisitionToolVersion.trim()) {
        setError('Acquisition tool name + version are required for reproducibility (ISO 27037 §5.4.4).'); return false
      }
      if (acquisitionScope === 'logical' && !logicalRationale.trim()) {
        setError('Logical acquisition requires a rationale of what was taken and why (§7.1.3.1.1).'); return false
      }
      if ((acquisitionHashSource && !srcAlgo) || (acquisitionHashTarget && !tgtAlgo)) {
        setError('Hashes must be 32 (MD5), 40 (SHA-1) or 64 (SHA-256) hex characters.'); return false
      }
      if (hashesComparable && !hashesMatch) {
        setError('Source and target hashes do not match — acquisition integrity broken. Re-acquire before continuing.'); return false
      }
      if (parseOffsetSeconds(timeOffsetSeconds) === undefined) {
        setError('Clock offset must be a whole number of seconds, e.g. +120 or -30 (at most 100 years either way).'); return false
      }
    }
    return true
  }

  function next() {
    if (!validateStep(step)) return
    const idx = stepList.indexOf(step)
    if (idx < stepList.length - 1) setStep(stepList[idx + 1])
  }
  function prev() {
    const idx = stepList.indexOf(step)
    if (idx > 0) setStep(stepList[idx - 1])
  }

  // Seal-readiness mirror of the server gate (so the operator sees gaps first).
  const sealChecks = [
    { ok: !!lawfulBasis,           label: 'Lawful basis recorded' },
    { ok: deviceTypes.length > 0,  label: 'Device type tagged' },
    ...(kind === 'digital_file' ? [
      { ok: completing ? !!ex.sha256 : !!file,                   label: completing ? 'File stored (SHA-256 recorded)' : 'File acquired (SHA-256 computed)' },
      { ok: !!(acquisitionTool.trim() && acquisitionToolVersion.trim()), label: 'Acquisition tool + version' },
      ...(isLive ? [{ ok: !!liveJustification.trim(), label: 'Live justification' }] : []),
      ...(acquisitionScope === 'logical' ? [{ ok: !!logicalRationale.trim(), label: 'Logical-acquisition rationale' }] : []),
    ] : [
      { ok: !!photoCaption.trim() || (completing && exPhotos.length > 0), label: 'In-situ photo caption' },
    ]),
  ]
  const sealReady = sealChecks.every(c => c.ok)

  // ── Final action: collect + seal ────────────────────────────────────────
  async function commit() {
    setBusy(true); setError(null); setSealResult(null)
    try {
      const decision_factors = (Object.values(decisionFactors).some(Boolean) || decisionNote.trim())
        ? { ...decisionFactors, note: decisionNote.trim() || undefined }
        : null
      const device_details = Object.keys(dd).length ? dd : null

      const wizardCommon = {
        lawful_basis: lawfulBasis || null,
        lawful_basis_note: lawfulBasisNote.trim() || null,
        acquisition_tool: acquisitionTool.trim() || null,
        acquisition_tool_version: acquisitionToolVersion.trim() || null,
        acquisition_tool_sha256: acquisitionToolSha256.trim() || null,
        acquisition_params: acquisitionParams.trim() || null,
        witness_user_id: witnessUserId || null,
        witness_name: witnessName.trim() || null,
        collected_as_role: collectedAsRole || null,   // GS-12 — DEFR/DES (§3.7/§3.8)
        // Collection wizard (ISO/IEC 27037 §7)
        device_types: deviceTypes.length ? deviceTypes : null,
        handling_mode: handlingMode || null,
        decision_factors,
        acquisition_scope: acquisitionScope || null,
        logical_acquisition_rationale: logicalRationale.trim() || null,
        system_time_offset: systemTimeOffset.trim() || null,
        system_time_offset_seconds: parseOffsetSeconds(timeOffsetSeconds) ?? null,
        screen_state: screenState.trim() || null,
        changes_made: changesMade.trim() || null,
        device_details,
        // ISO/IEC 27041 — method/tool validation (Slice B)
        acquisition_tool_validated: toolValidated === '' ? null : toolValidated === 'true',
        acquisition_tool_validation_ref: toolValidationRef.trim() || null,
        acquisition_tool_validation_date: toolValidationDate || null,
        acquired_at: acquiredAt || null,   // C3 — when the image was taken / item seized
      }

      let created
      if (completing) {
        // G3 — record the acquisition on the existing item (only the stored file is never sent).
        const digital = kind === 'digital_file' ? {
          acquisition_hash_source: acquisitionHashSource.trim() || null,
          acquisition_hash_target: acquisitionHashTarget.trim() || null,
          ...(acquisitionHashTarget.trim() ? { target_hash_scope: targetHashScope } : {}),
          write_blocker_used: writeBlockerUsed === '' ? null : writeBlockerUsed === 'true',
          write_blocker_serial: writeBlockerSerial.trim() || null,
          system_state: systemState || null,
          live_justification: liveJustification.trim() || null,
          network_isolated: networkIsolated === '' ? null : networkIsolated === 'true',
        } : {}
        created = await api.updateAcquisitionRecord(incidentId, ex.id, {
          ...wizardCommon, ...digital, collected_location: collectedLocation.trim() || null,
        })
        // FE-H1: only when the item has no stored photo (then its list holds reference-only entries,
        // which a PATCH replaces as sent). Stored photos stay as they are; add more from the item's detail.
        if (kind === 'physical_item' && photoCaption.trim() && !storedPhotos.length) {
          try {
            created = await api.updateEvidence(incidentId, ex.id, {
              photos: [...exPhotos, { url: '', caption: photoCaption.trim(), taken_at: photoTime }],
            })
          } catch (pe) {
            throw new Error(`The acquisition record was saved, but the photo caption was not: ${photoErrorText(pe)}`)
          }
        }
      } else if (kind === 'digital_file') {
        const fields = {
          name: name.trim(),
          identifier: identifier.trim(),
          description: description.trim() || null,
          tlp,
          collected_location: collectedLocation.trim() || null,
          entity_id: entityId || null,
          file,
          wizard: {
            ...wizardCommon,
            acquisition_hash_source: acquisitionHashSource.trim() || null,
            acquisition_hash_target: acquisitionHashTarget.trim() || null,
            target_hash_scope: acquisitionHashTarget.trim() ? targetHashScope : null,
            write_blocker_used: writeBlockerUsed === '' ? null : writeBlockerUsed === 'true',
            write_blocker_serial: writeBlockerSerial.trim() || null,
            system_state: systemState || null,
            live_justification: liveJustification.trim() || null,
            network_isolated: networkIsolated === '' ? null : networkIsolated === 'true',
          },
        }
        const opts = up.start(file.size)
        created = kept.held
          ? (await kept.held.retry(api.digitalCompleteBody(fields), opts)).evidence    // FE-M2: no re-upload
          : await api.collectDigital(incidentId, fields, { ...opts, retainOnError: true })
        kept.drop({ cancel: false })
        up.done()
      } else {
        created = await api.collectPhysical(incidentId, {
          name: name.trim(),
          identifier: identifier.trim(),
          description: description.trim() || null,
          tlp,
          entity_id: entityId || null,
          physical_location: dd.physical_location || null,
          collected_location: collectedLocation.trim() || null,
          photos: photoCaption.trim() ? [{
            url: '',
            caption: photoCaption.trim(),
            taken_at: photoTime,
          }] : [],
          ...wizardCommon,
        })
      }

      try {
        const sealed = await api.sealEvidence(incidentId, created.id)
        setSealResult({ kind: 'sealed', evidence: sealed })
      } catch (sealErr) {
        setSealResult({ kind: 'unsealed', evidence: created, message: sealErr.message })
      }
      setStep('confirm')
    } catch (e) {
      // FE-M2: the server kept the upload (a refused field or no room): fix it and Collect again.
      if (e.retained) kept.keep(e, file)
      else if (kept.held) kept.drop({ cancel: false })
      const still = e.retained ? ' The file stays uploaded on the server: Collect again to finish without re-sending it.' : ''
      // C3 — a refused hash stores nothing; the fix is on the Acquisition step.
      const code = e.data?.code
      setError(((code === 'hash_mismatch' || code === 'invalid_hash_format')
        ? `${e.message} Go Back to the Acquisition step to correct it.`
        : code === 'acquired_in_future'
          ? (kind === 'digital_file'
            ? 'The acquisition time is in the future. Go Back to the Acquisition step and correct it, or clear it if unknown.'
            : 'The seizure time is in the future. Go Back to the Identification step and correct it, or clear it if unknown.')
          : code === 'identifier_exists'
            ? `The identifier “${identifier.trim()}” is already used on this incident. Go Back to the Identification step and change it.`
            : (e.message || 'Could not collect evidence.')) + still)
    } finally {
      up.done()
      setBusy(false)
    }
  }

  const acquiredAtField = (
    <div className="field">
      <label className="field-label" htmlFor="aw-acquired">
        {kind === 'digital_file' ? 'Acquisition time (when the image was taken)' : 'Seizure time (when the item was taken)'}
      </label>
      <LocalDateTimePicker id="aw-acquired" value={acquiredAt} onChange={setAcquiredAt} clearable />
      <div className="field-hint">From the imaging tool's log or your notes — not when you upload it here. Leave blank if unknown.</div>
    </div>
  )

  return (
    <div className="modal-backdrop">
      <div className="modal" role="dialog" aria-labelledby="aw-title" style={{ width: 'min(640px, 96vw)' }}>
        <div className="modal-head">
          <h2 id="aw-title">{completing ? `Complete & seal — ${ex.identifier}` : 'Collection wizard — ISO/IEC 27037 §7'}</h2>
          <button type="button" className="modal-close" onClick={onClose} disabled={busy} aria-label="Close">×</button>
        </div>

        <div className="modal-body">
          {/* Progress strip */}
          <div style={{ display: 'flex', gap: 4, marginBottom: 'var(--space-3)' }}>
            {stepList.map((s, i) => (
              <div key={s} style={{
                flex: 1, height: 4, borderRadius: 2,
                background: i < stepIdx ? 'var(--accent)' : 'var(--border)',
              }} />
            ))}
          </div>

          {/* ── Step: TYPE ──────────────────────────────────────────────── */}
          {step === 'type' && (
            <div className="form">
              <StepHeader n={stepIdx} total={totalSteps} title="Device type & kind"
                          subtitle="ISO 27037 §7 — selects the sub-procedure" />

              <div className="field">
                <label className="field-label">Device type(s) * <span style={{ color: 'var(--muted)', fontWeight: 400 }}>— tag all that apply</span></label>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, marginTop: 4 }}>
                  {DEVICE_TYPES.map(t => (
                    <TypeChip key={t.value} active={has(t.value)} label={t.label} onClick={() => toggleType(t.value)} />
                  ))}
                </div>
                <div className="field-hint">A device can be several types (e.g. a seized phone is both Mobile and Storage). Each device tag adds its §7 checklist on the Branch step; the export types (email, vendor report, network capture) have none.</div>
              </div>

              <div className="field">
                <label className="field-label" htmlFor="aw-kind">Record as</label>
                <select id="aw-kind" className="select" value={kind} onChange={e => setKind(e.target.value)} disabled={completing}>
                  <option value="digital_file">Digital file (acquired image/copy, AES-256 at rest)</option>
                  <option value="physical_item">Physical item (seized device, referenced)</option>
                </select>
              </div>
            </div>
          )}

          {/* ── Step: IDENTIFY ──────────────────────────────────────────── */}
          {step === 'identify' && (
            <div className="form">
              <StepHeader n={stepIdx} total={totalSteps} title="Identification & lawful basis"
                          subtitle="ISO 27037 §5.4.2 · GDPR Art. 5.1(c)" />

              <div className="form-row">
                <div className="field">
                  <label className="field-label" htmlFor="aw-name">Name</label>
                  <input id="aw-name" className="input" value={name} onChange={e => setName(e.target.value)}
                         autoFocus maxLength={256} placeholder="e.g. WIN-FS01 memory dump" disabled={completing} />
                </div>
                <div className="field">
                  <label className="field-label" htmlFor="aw-tlp">TLP</label>
                  <select id="aw-tlp" className="select" value={tlp} onChange={e => setTlp(e.target.value)} disabled={completing}>
                    {TLP.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
                  </select>
                </div>
              </div>

              <div className="field">
                <label className="field-label" htmlFor="aw-id">Identifier (case tag / item #)</label>
                <input id="aw-id" className="input" value={identifier} onChange={e => setIdentifier(e.target.value)}
                       maxLength={128} placeholder="e.g. EV-2026-042-01" style={{ fontFamily: 'var(--font-mono)' }} disabled={completing} />
                {completing && <div className="field-hint">The identifier is fixed; name, TLP and description are edited from the item&rsquo;s detail.</div>}
              </div>

              <div className="field">
                <label className="field-label" htmlFor="aw-lb">Lawful basis *</label>
                <select id="aw-lb" className="select" value={lawfulBasis} onChange={e => setLawfulBasis(e.target.value)}>
                  <option value="">— pick a basis —</option>
                  {LAWFUL_BASIS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
                </select>
                <div className="field-hint">GDPR Art. 5.1(c) — data minimisation requires a documented purpose for collection.</div>
              </div>

              {(lawfulBasis === 'other' || lawfulBasis === 'lia') && (
                <div className="field">
                  <label className="field-label" htmlFor="aw-lbn">Justification note *</label>
                  <textarea id="aw-lbn" className="input" value={lawfulBasisNote}
                            onChange={e => setLawfulBasisNote(e.target.value)} rows={2} maxLength={4096}
                            placeholder="e.g. LIA balancing test — internal counsel approval ref. LCA-2026-014" />
                </div>
              )}

              <div className="field">
                <label className="field-label" htmlFor="aw-desc">Description (source, scope)</label>
                <textarea id="aw-desc" className="input" value={description}
                          onChange={e => setDescription(e.target.value)} rows={2} maxLength={4096} disabled={completing} />
              </div>

              <div className="field">
                <label className="field-label" htmlFor="aw-loc">Collection location</label>
                <input id="aw-loc" className="input" value={collectedLocation}
                       onChange={e => setCollectedLocation(e.target.value)} maxLength={256}
                       placeholder="e.g. Finance dept, 4F server room — desk 4F-12" />
              </div>

              <div className="field">
                <label className="field-label" htmlFor="aw-role">Collected as role <span style={{ fontWeight: 400, color: 'var(--muted)', fontSize: 12 }}>· ISO 27037 §3.7/§3.8</span></label>
                <select id="aw-role" className="select" value={collectedAsRole}
                        onChange={e => setCollectedAsRole(e.target.value)}>
                  <option value="">— select —</option>
                  <option value="defr">DEFR — Digital Evidence First Responder</option>
                  <option value="des">DES — Digital Evidence Specialist</option>
                </select>
                <div className="field-hint">DEFR collects/acquires on scene; DES applies specialist techniques. Records the responder's authorised capacity.</div>
              </div>

              {entities.length > 0 && !completing && (
                <div className="field">
                  <label className="field-label" htmlFor="aw-entity">Asset / entity (optional)</label>
                  <select id="aw-entity" className="select" value={entityId} onChange={e => setEntityId(e.target.value)}>
                    <option value="">— No entity linked —</option>
                    {entities.map(e => (
                      <option key={e.id} value={e.id}>
                        {e.type}: {e.name || e.value}{e.compromised ? ' ⚠ compromised' : ''}
                      </option>
                    ))}
                  </select>
                </div>
              )}

              {kind === 'physical_item' && completing && storedPhotos.length > 0 && (
                <div className="field" data-testid="aw-photos-kept">
                  <span className="field-label">In-situ photos (ISO 27037 §6.2.1)</span>
                  <div className="field-hint">
                    The item already has {exPhotos.length} photo{exPhotos.length === 1 ? '' : 's'}
                    {exPhotos.some(p => p.caption) ? ` (${exPhotos.filter(p => p.caption).map(p => p.caption).join('; ')})` : ''}.
                    {' '}They are kept as stored. Add more under <b>Photographs</b> in the item&rsquo;s detail.
                  </div>
                </div>
              )}
              {kind === 'physical_item' && !(completing && storedPhotos.length > 0) && (
                <div className="field">
                  <label className="field-label" htmlFor="aw-photo">In-situ photo caption{captionRequired ? ' *' : ' (optional)'} (ISO 27037 §6.2.1)</label>
                  <input id="aw-photo" className="input" value={photoCaption}
                         onChange={e => setPhotoCaption(e.target.value)} maxLength={256}
                         placeholder="e.g. Laptop in situ on desk, lid open, screen photographed (IMG_3421)" />
                  <div className="field-hint">
                    {completing && exPhotos.length > 0
                      ? `The item already has ${exPhotos.length} photo caption${exPhotos.length === 1 ? '' : 's'}; a new caption is added to them.`
                      : 'Caption alone documents that a photo was taken; attach the image under Photographs in the item’s detail.'}
                  </div>
                </div>
              )}
              {kind === 'physical_item' && photoCaption.trim() && !(completing && storedPhotos.length > 0) && (
                <div className="field">
                  <label className="field-label" htmlFor="aw-photo-at">Photo taken at (optional)</label>
                  <LocalDateTimePicker id="aw-photo-at" value={photoTakenAt} onChange={setPhotoTakenAt} clearable />
                  <div className="field-hint">Blank: the seizure time below, or unknown if that is blank too. Never the time you save this.</div>
                </div>
              )}

              {kind === 'physical_item' && acquiredAtField}
            </div>
          )}

          {/* ── Step: DECIDE ────────────────────────────────────────────── */}
          {step === 'decide' && (
            <div className="form">
              <StepHeader n={stepIdx} total={totalSteps} title="Collect or acquire?"
                          subtitle="ISO 27037 Fig. 1 / §7.1.1.3 / §7.1.3.1.1" />

              <div className="form-row">
                <div className="field">
                  <label className="field-label" htmlFor="aw-ss">Device state</label>
                  <select id="aw-ss" className="select" value={systemState} onChange={e => setSystemState(e.target.value)}>
                    <option value="">— select —</option>
                    {SYSTEM_STATE.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
                  </select>
                  <div className="field-hint">Never change the state: if on, don't power off; if off, don't power on.</div>
                </div>
                <div className="field">
                  <label className="field-label" htmlFor="aw-hm">Handling</label>
                  <select id="aw-hm" className="select" value={handlingMode} onChange={e => setHandlingMode(e.target.value)}>
                    {HANDLING_MODE.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
                  </select>
                </div>
              </div>

              {isLive && (
                <div className="field">
                  <label className="field-label" htmlFor="aw-lj">
                    {systemState === 'live_critical' ? 'Mission-critical justification (cannot power off) *' : 'Live acquisition justification *'}
                  </label>
                  <textarea id="aw-lj" className="input" value={liveJustification}
                            onChange={e => setLiveJustification(e.target.value)} rows={2} maxLength={4096}
                            placeholder="e.g. RAM capture required to preserve volatile encryption keys — system cannot be powered off without losing the artefact" />
                </div>
              )}

              <div className="field">
                <label className="field-label">Decision factors (§7.1.1.3) <span style={{ color: 'var(--muted)', fontWeight: 400 }}>— tick what drove the choice</span></label>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4, marginTop: 4 }}>
                  {DECISION_FACTORS.map(f => (
                    <label key={f.key} style={{ display: 'flex', gap: 8, alignItems: 'baseline', fontSize: 13, color: 'var(--muted)' }}>
                      <input type="checkbox" checked={!!decisionFactors[f.key]}
                             onChange={e => setDecisionFactors(prev => ({ ...prev, [f.key]: e.target.checked }))} />
                      {f.label}
                    </label>
                  ))}
                </div>
              </div>

              <div className="field">
                <label className="field-label" htmlFor="aw-dnote">Decision note (optional)</label>
                <input id="aw-dnote" className="input" value={decisionNote}
                       onChange={e => setDecisionNote(e.target.value)} maxLength={1024} />
              </div>
            </div>
          )}

          {/* ── Step: BRANCH (device-specific extras) ───────────────────── */}
          {step === 'branch' && (
            <div className="form">
              <StepHeader n={stepIdx} total={totalSteps} title="Device-specific handling"
                          subtitle="ISO 27037 §7 extras for the tagged types" />

              {(has('computer') || has('peripheral') || has('storage')) && (
                <>
                  <div className="form-row">
                    <div className="field">
                      <label className="field-label" htmlFor="aw-wb">Write-blocker used?</label>
                      <select id="aw-wb" className="select" value={writeBlockerUsed} onChange={e => setWriteBlockerUsed(e.target.value)}>
                        <option value="">— select —</option>
                        <option value="true">Yes</option>
                        <option value="false">No</option>
                      </select>
                    </div>
                    <div className="field">
                      <label className="field-label" htmlFor="aw-wbs">Write-blocker serial</label>
                      <input id="aw-wbs" className="input" value={writeBlockerSerial}
                             onChange={e => setWriteBlockerSerial(e.target.value)} maxLength={128}
                             disabled={writeBlockerUsed !== 'true'} style={{ fontFamily: 'var(--font-mono)' }} />
                    </div>
                  </div>
                  <div className="field">
                    <label className="field-label" htmlFor="aw-ports">Cabling / ports labelled & sketched?</label>
                    <input id="aw-ports" className="input" value={dd.cabling_note || ''}
                           onChange={e => setDetail('cabling_note', e.target.value)} maxLength={256}
                           placeholder="e.g. all ports tagged P1–P6, sketch attached" />
                  </div>
                </>
              )}

              {has('mobile') && (
                <>
                  <div className="form-row">
                    <div className="field">
                      <label className="field-label" htmlFor="aw-imei">IMEI / ESN</label>
                      <input id="aw-imei" className="input" value={dd.imei_esn || ''}
                             onChange={e => setDetail('imei_esn', e.target.value)} maxLength={64}
                             style={{ fontFamily: 'var(--font-mono)' }} />
                    </div>
                    <div className="field">
                      <label className="field-label" htmlFor="aw-faraday">Radio isolated (Faraday)?</label>
                      <select id="aw-faraday" className="select" value={dd.faraday_used == null ? '' : String(dd.faraday_used)}
                              onChange={e => setDetail('faraday_used', e.target.value === '' ? null : e.target.value === 'true')}>
                        <option value="">— select —</option>
                        <option value="true">Yes</option>
                        <option value="false">No</option>
                      </select>
                    </div>
                  </div>
                  <div className="field">
                    <label className="field-label" htmlFor="aw-pinpuk">PIN/PUK captured?</label>
                    <input id="aw-pinpuk" className="input" value={dd.pin_puk_note || ''}
                           onChange={e => setDetail('pin_puk_note', e.target.value)} maxLength={256}
                           placeholder="e.g. PIN noted from sticky note, PUK from carrier" />
                  </div>
                </>
              )}

              {has('network') && (
                <>
                  <div className="field">
                    <label className="field-label" htmlFor="aw-comms">Communication paths</label>
                    <input id="aw-comms" className="input" value={dd.comms_paths || ''}
                           onChange={e => setDetail('comms_paths', e.target.value)} maxLength={512}
                           placeholder="e.g. wired LAN (eth0), Wi-Fi, LTE modem — all ports labelled" />
                    <div className="field-hint">Identify and label ALL comms paths for later reconstruction (§7.2.2.2).</div>
                  </div>
                  <div className="field">
                    <label className="field-label" htmlFor="aw-iso">Isolation method</label>
                    <select id="aw-iso" className="select" value={dd.isolation_method || ''}
                            onChange={e => setDetail('isolation_method', e.target.value || null)}>
                      {ISOLATION_METHODS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
                    </select>
                  </div>
                </>
              )}

              {has('cctv') && (
                <>
                  <div className="form-row">
                    <div className="field">
                      <label className="field-label" htmlFor="aw-ow">Overwrite window</label>
                      <input id="aw-ow" className="input" value={dd.cctv_overwrite_window || ''}
                             onChange={e => setDetail('cctv_overwrite_window', e.target.value)} maxLength={64}
                             placeholder="e.g. ≈14 days" />
                    </div>
                    <div className="field">
                      <label className="field-label" htmlFor="aw-mm">System make / model</label>
                      <input id="aw-mm" className="input" value={dd.cctv_system_make_model || ''}
                             onChange={e => setDetail('cctv_system_make_model', e.target.value)} maxLength={128}
                             placeholder="e.g. Hikvision DS-7608" />
                    </div>
                  </div>
                  <div className="field">
                    <label className="field-label" htmlFor="aw-opt">Acquisition option</label>
                    <select id="aw-opt" className="select" value={dd.cctv_acquisition_option || ''}
                            onChange={e => setDetail('cctv_acquisition_option', e.target.value || null)}>
                      {CCTV_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
                    </select>
                    <div className="field-hint">Record the time offset (device clock vs true time) on the Acquire step.</div>
                  </div>
                </>
              )}
            </div>
          )}

          {/* ── Step: ACQUIRE (digital) ─────────────────────────────────── */}
          {step === 'acquire' && (
            <div className="form">
              <StepHeader n={stepIdx} total={totalSteps} title="Acquisition"
                          subtitle="ISO 27037 §5.4.4 / §7.1.3.1.1 · NIST SP 800-86 §3.1.2" />

              {completing ? (
                <div className="field" data-testid="aw-stored-file">
                  <span className="field-label">Stored file</span>
                  <div style={{ fontSize: 13 }}>
                    <span style={{ fontFamily: 'var(--font-mono)' }}>{ex.original_filename || '—'}</span>
                    <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--muted)', wordBreak: 'break-all' }}>SHA-256 {ex.sha256}</div>
                  </div>
                  <div className="field-hint">Registered and hashed when it was uploaded; it is never replaced. A target hash below is compared with it.</div>
                </div>
              ) : (
              <div className="field">
                <label className="field-label" htmlFor="aw-file">File *</label>
                <input id="aw-file" className="input" type="file"
                       onChange={e => { if (kept.held) kept.drop(); setFile(e.target.files?.[0] || null) }} />
                <div className="field-hint">Hashed (SHA-256 + SHA-1 + MD5) and AES-256-GCM encrypted at rest on upload.</div>
                {kept.held && (
                  <div className="field-hint" data-testid="aw-upload-held-file">
                    {kept.held.filename} is already uploaded (held by the server): choosing another file discards it.
                  </div>
                )}
              </div>
              )}

              {acquiredAtField}

              <div className="field">
                <label className="field-label" htmlFor="aw-scope">Acquisition scope</label>
                <select id="aw-scope" className="select" value={acquisitionScope} onChange={e => setAcquisitionScope(e.target.value)}>
                  <option value="">— select —</option>
                  <option value="full_image">Full forensic image</option>
                  <option value="logical">Logical / selected files (image not possible)</option>
                </select>
              </div>

              {acquisitionScope === 'logical' && (
                <div className="field">
                  <label className="field-label" htmlFor="aw-lr">Logical-acquisition rationale *</label>
                  <textarea id="aw-lr" className="input" value={logicalRationale}
                            onChange={e => setLogicalRationale(e.target.value)} rows={2} maxLength={4096}
                            placeholder="e.g. volume too large for full image — acquired user profile + mailbox export only; deleted/unallocated space not captured" />
                </div>
              )}

              {validatedTools.length > 0 && (
                <div className="field">
                  <label className="field-label" htmlFor="aw-vtool">Validated tool (ISO 27041 registry)</label>
                  <select id="aw-vtool" className="select" defaultValue=""
                          onChange={e => { if (e.target.value) pickRegistryTool(e.target.value) }}>
                    <option value="">— pick a validated tool, or enter manually below —</option>
                    {validatedTools.map(t => (
                      <option key={t.id} value={t.id}>{t.name} {t.version}{t.validation_ref ? ` — ${t.validation_ref}` : ''}</option>
                    ))}
                  </select>
                  <div className="field-hint">Picking one fills the tool below + marks it validated with its reference. Not listed? Enter it manually (recorded as unvalidated).</div>
                </div>
              )}

              <div className="form-row">
                <div className="field">
                  <label className="field-label" htmlFor="aw-tool">Tool name *</label>
                  <input id="aw-tool" className="input" value={acquisitionTool}
                         onChange={e => setAcquisitionTool(e.target.value)} maxLength={128}
                         placeholder="e.g. FTK Imager · dd · WinHex · X-Ways" />
                </div>
                <div className="field">
                  <label className="field-label" htmlFor="aw-tv">Tool version *</label>
                  <input id="aw-tv" className="input" value={acquisitionToolVersion}
                         onChange={e => setAcquisitionToolVersion(e.target.value)} maxLength={64}
                         placeholder="e.g. 4.7.1" style={{ fontFamily: 'var(--font-mono)' }} />
                </div>
              </div>

              <div className="field">
                <label className="field-label" htmlFor="aw-tsha">Tool SHA-256 (optional)</label>
                <HashInput id="aw-tsha" value={acquisitionToolSha256} onChange={setAcquisitionToolSha256}
                           placeholder="64-hex tool binary fingerprint" sha256Only />
              </div>

              {/* ISO/IEC 27041 — method/tool validation (soft-scored) */}
              <div className="form-row">
                <div className="field">
                  <label className="field-label" htmlFor="aw-val">Tool/method validated? (ISO 27041)</label>
                  <select id="aw-val" className="select" value={toolValidated} onChange={e => setToolValidated(e.target.value)}>
                    <option value="">— select —</option>
                    <option value="true">Yes — validated as suitable</option>
                    <option value="false">No / not yet</option>
                  </select>
                </div>
                <div className="field">
                  <label className="field-label" htmlFor="aw-valdate">Validation date</label>
                  <input id="aw-valdate" className="input" type="date" value={toolValidationDate}
                         onChange={e => setToolValidationDate(e.target.value)} disabled={toolValidated !== 'true'} />
                </div>
              </div>
              {toolValidated === 'true' && (
                <div className="field">
                  <label className="field-label" htmlFor="aw-valref">Validation reference</label>
                  <input id="aw-valref" className="input" value={toolValidationRef}
                         onChange={e => setToolValidationRef(e.target.value)} maxLength={256}
                         placeholder="e.g. lab validation report VR-2026-014 / NIST CFTT entry / internal test ref" />
                  <div className="field-hint">Soft — improves the provenance score; never blocks sealing.</div>
                </div>
              )}

              <div className="field">
                <label className="field-label" htmlFor="aw-params">Command line / parameters</label>
                <textarea id="aw-params" className="input" value={acquisitionParams}
                          onChange={e => setAcquisitionParams(e.target.value)} rows={2} maxLength={4096}
                          placeholder="e.g. dd if=/dev/sda of=evidence.dd bs=4M conv=noerror,sync status=progress" />
              </div>

              <div className="form-row">
                <div className="field">
                  <label className="field-label" htmlFor="aw-hs">Source hash (pre-image)</label>
                  <HashInput id="aw-hs" value={acquisitionHashSource} onChange={setAcquisitionHashSource} placeholder="Hash of the source media" />
                </div>
                <div className="field">
                  <label className="field-label" htmlFor="aw-ht">Target hash (post-image)</label>
                  <HashInput id="aw-ht" value={acquisitionHashTarget} onChange={setAcquisitionHashTarget} placeholder="Hash of the acquired image" />
                </div>
              </div>
              {srcAlgo && tgtAlgo && (
                <div data-hash-compare={hashesComparable ? (hashesMatch ? 'match' : 'differ') : 'different_algorithms'} style={{
                  padding: '6px 10px', fontSize: 11,
                  background: !hashesComparable
                    ? 'color-mix(in srgb, var(--med) 12%, transparent)'
                    : hashesMatch
                      ? 'color-mix(in srgb, var(--ok) 12%, transparent)'
                      : 'color-mix(in srgb, var(--crit) 12%, transparent)',
                  color: !hashesComparable ? 'var(--med)' : hashesMatch ? 'var(--ok)' : 'var(--crit)',
                  borderRadius: 'var(--radius-sm)',
                }}>
                  {!hashesComparable
                    ? `Different algorithms (${srcAlgo} source, ${tgtAlgo} target) — they can't be compared here. Confirm the match in the imaging tool's report.`
                    : hashesMatch
                      ? '✓ Source and target hashes match — acquisition integrity proven'
                      : '✗ Hashes differ — re-acquire before sealing'}
                </div>
              )}

              <fieldset className="field" style={{ border: 0, padding: 0, margin: 0, minWidth: 0 }}
                        disabled={!acquisitionHashTarget}>
                <legend className="field-label">Target hash covers</legend>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4, marginTop: 4 }}>
                  {[
                    { value: 'uploaded_file',   label: 'The file you upload here',
                      desc: 'FENRIR hashes the upload with the same algorithm and refuses a mismatch.' },
                    { value: 'container_media', label: "The container's media (E01 / AFF4 content hash)",
                      desc: 'The hash covers the imaged disk inside the container, not the container file. Recorded as advisory, not compared.' },
                  ].map(o => (
                    <label key={o.value} style={{ display: 'flex', gap: 8, alignItems: 'baseline', fontSize: 13 }}>
                      <input type="radio" name="aw-target-scope" value={o.value}
                             checked={targetHashScope === o.value}
                             onChange={() => setTargetHashScope(o.value)} />
                      <span>
                        {o.label}
                        <span style={{ display: 'block', fontSize: 11, color: 'var(--muted)' }}>{o.desc}</span>
                      </span>
                    </label>
                  ))}
                </div>
              </fieldset>

              {(systemState === 'live' || systemState === 'live_critical') && (
                <div className="field">
                  <label className="field-label" htmlFor="aw-screen">On-screen state (§6.6)</label>
                  <input id="aw-screen" className="input" value={screenState}
                         onChange={e => setScreenState(e.target.value)} maxLength={1024}
                         placeholder="e.g. visible apps: Outlook, TrueCrypt mounted volume X:, browser at …" />
                </div>
              )}

              <div className="form-row">
                {/* K1 (R37): asked here only when the Branch step (computer / peripheral / storage) did not ask it. */}
                {!(has('computer') || has('peripheral') || has('storage')) && (
                  <div className="field">
                    <label className="field-label" htmlFor="aw-wb2">Write-blocker used?</label>
                    <select id="aw-wb2" className="select" value={writeBlockerUsed} onChange={e => setWriteBlockerUsed(e.target.value)}>
                      <option value="">— select —</option>
                      <option value="true">Yes</option>
                      <option value="false">No</option>
                    </select>
                  </div>
                )}
                <div className="field">
                  <label className="field-label" htmlFor="aw-ni">Network isolated?</label>
                  <select id="aw-ni" className="select" value={networkIsolated} onChange={e => setNetworkIsolated(e.target.value)}>
                    <option value="">— select —</option>
                    <option value="true">Yes</option>
                    <option value="false">No</option>
                  </select>
                </div>
              </div>

              <div className="form-row">
                <div className="field">
                  <label className="field-label" htmlFor="aw-tof">System time offset (§6.6)</label>
                  <input id="aw-tof" className="input" value={systemTimeOffset}
                         onChange={e => setSystemTimeOffset(e.target.value)} maxLength={128}
                         placeholder="e.g. device 12:00:03, NTP 12:00:00 → +3s" />
                </div>
                <div className="field">
                  <label className="field-label" htmlFor="aw-chg">Changes made by acquisition</label>
                  <input id="aw-chg" className="input" value={changesMade}
                         onChange={e => setChangesMade(e.target.value)} maxLength={1024}
                         placeholder="e.g. agent written to %TEMP%; documented (§6.1)" />
                </div>
              </div>

              <div className="form-row">
                <div className="field">
                  <label className="field-label" htmlFor="aw-tofs">Clock offset in seconds (optional)</label>
                  <input id="aw-tofs" className="input" inputMode="numeric" value={timeOffsetSeconds}
                         onChange={e => setTimeOffsetSeconds(e.target.value)} maxLength={12}
                         placeholder="e.g. +3 or -120"
                         aria-invalid={parseOffsetSeconds(timeOffsetSeconds) === undefined || undefined}
                         aria-describedby="aw-tofs-hint"
                         style={parseOffsetSeconds(timeOffsetSeconds) === undefined ? { borderColor: 'var(--crit)' } : undefined} />
                  <div id="aw-tofs-hint" className="field-hint" data-testid="aw-tofs-hint">
                    {parseOffsetSeconds(timeOffsetSeconds) === undefined
                      ? <span style={{ color: 'var(--crit)' }}>A whole number of seconds, e.g. +120 or -30.</span>
                      : <>Device clock minus true time, after its timezone: <strong>+120</strong> = the device was 2 minutes ahead.
                          {' '}Imports from this exhibit subtract it from the device&rsquo;s times and keep the recorded time. The note above is kept as written and never interpreted.</>}
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* ── Step: WITNESS ───────────────────────────────────────────── */}
          {step === 'witness' && (
            <div className="form">
              <StepHeader n={stepIdx} total={totalSteps} title="Witness / second analyst"
                          subtitle="ISO 27037 role doctrine — DES co-signature (optional)" />

              <div className="field">
                <label className="field-label" htmlFor="aw-wu">Witness (platform user)</label>
                <select id="aw-wu" className="select" value={witnessUserId} onChange={e => setWitnessUserId(e.target.value)}>
                  <option value="">— no witness —</option>
                  {users.map(u => (
                    <option key={u.id} value={u.id}>{u.username}{u.full_name ? ` (${u.full_name})` : ''}</option>
                  ))}
                </select>
              </div>

              <div className="field">
                <label className="field-label" htmlFor="aw-wn">Or witness name (free text)</label>
                <input id="aw-wn" className="input" value={witnessName}
                       onChange={e => setWitnessName(e.target.value)} maxLength={128}
                       placeholder="e.g. Insp. P. Hansen, Cybercrime Unit" />
                <div className="field-hint">Use when the witness isn't a platform user (external counsel, LE officer on scene, etc.).</div>
              </div>
            </div>
          )}

          {/* ── Step: CONFIRM ───────────────────────────────────────────── */}
          {step === 'confirm' && (
            <div className="form">
              <StepHeader n={stepIdx} total={totalSteps} title="Confirm & seal"
                          subtitle="Locks the wizard fields after server validation" />

              {!sealResult && (
                <>
                  <div style={{
                    padding: 'var(--space-3)', background: 'var(--surface-2)',
                    border: '1px solid var(--border)', borderRadius: 'var(--radius)', fontSize: 12,
                  }}>
                    <strong>Seal readiness</strong>
                    <ul style={{ margin: 'var(--space-2) 0 0', padding: 0, display: 'flex', flexDirection: 'column', gap: 4 }}>
                      {sealChecks.map((c, i) => <SealCheck key={i} ok={c.ok} label={c.label} />)}
                    </ul>
                    {!sealReady && (
                      <div className="field-hint" style={{ marginTop: 'var(--space-2)' }}>
                        Missing items won't block collection — the row is created and can be sealed later — but it can't be sealed until they're present.
                      </div>
                    )}
                  </div>
                  <div style={{
                    marginTop: 'var(--space-3)', padding: 'var(--space-3)', background: 'var(--surface-2)',
                    border: '1px solid var(--border)', borderRadius: 'var(--radius)', fontSize: 12,
                  }}>
                    <strong>Summary</strong>
                    <ul style={{ margin: 'var(--space-1) 0 0 var(--space-3)', padding: 0 }}>
                      <li><strong>{kind === 'digital_file' ? 'Digital file' : 'Physical item'}:</strong> {name} ({identifier})</li>
                      <li><strong>Type(s):</strong> {deviceTypes.map(t => DEVICE_TYPES.find(d => d.value === t)?.label).join(', ') || '—'}</li>
                      <li><strong>State / handling:</strong> {SYSTEM_STATE.find(s => s.value === systemState)?.label || '—'} · {HANDLING_MODE.find(h => h.value === handlingMode)?.label}</li>
                      <li><strong>Lawful basis:</strong> {LAWFUL_BASIS.find(l => l.value === lawfulBasis)?.label || '—'}</li>
                      {kind === 'digital_file' && <li><strong>Tool:</strong> {acquisitionTool} v{acquisitionToolVersion} ({acquisitionScope || 'scope n/s'})</li>}
                      <li><strong>{kind === 'digital_file' ? 'Acquired' : 'Seized'}:</strong> {acquiredAt ? formatLocal(acquiredAt) : 'not recorded'}</li>
                      {parseOffsetSeconds(timeOffsetSeconds) != null && (
                        <li><strong>Clock offset:</strong> {fmtOffset(parseOffsetSeconds(timeOffsetSeconds))} (applied to imports from this exhibit)</li>
                      )}
                      {kind === 'digital_file' && tgtAlgo && (
                        <li><strong>Target hash:</strong> {tgtAlgo} · {targetHashScope === 'container_media' ? "container's media (advisory)" : 'compared with the upload'}</li>
                      )}
                      {(witnessUserId || witnessName) && (
                        <li><strong>Witness:</strong> {witnessName || users.find(u => u.id === witnessUserId)?.username}</li>
                      )}
                    </ul>
                  </div>
                  <button type="button" className="btn primary" onClick={commit} disabled={busy} style={{ marginTop: 'var(--space-3)' }}>
                    {completing
                      ? (busy ? 'Saving & sealing…' : (sealReady ? 'Save & seal' : 'Save (seal later)'))
                      : (busy ? 'Collecting & sealing…' : (sealReady ? 'Collect & seal' : 'Collect (seal later)'))}
                  </button>
                  <UploadProgress progress={up.progress} onCancel={up.cancel} testid="aw-upload-progress"
                                  limit={up.limit} incidentId={incidentId} />
                  {kept.held && !busy && (
                    <div className="alert info" role="status" data-testid="aw-upload-held" style={{ marginTop: 'var(--space-3)' }}>
                      <span className="alert-icon">i</span>
                      <span>
                        <b>{kept.held.filename}</b> is uploaded and held by the server, not yet stored as evidence. Correct the
                        {' '}field above, then <b>Collect</b> again: the file is not sent again. It is discarded if you close this
                        {' '}wizard, or after 30 minutes without activity.{' '}
                        <button type="button" className="btn ghost" onClick={() => kept.drop()} data-testid="aw-upload-discard">
                          Discard upload
                        </button>
                      </span>
                    </div>
                  )}
                </>
              )}

              {sealResult?.kind === 'sealed' && (
                <div className="alert info" role="status">
                  <span className="alert-icon">✓</span>
                  <span>{completing ? 'Acquisition record saved and sealed.' : 'Evidence row created and sealed.'} ISO 27037 + GDPR fields locked; further changes write amend-after-seal audit entries.</span>
                </div>
              )}
              {sealResult?.kind === 'unsealed' && (
                <div className="alert error" role="alert">
                  <span className="alert-icon">!</span>
                  <span>{completing ? 'Acquisition record saved' : 'Evidence row created'} but seal failed: {sealResult.message}. You can return later to seal the row.</span>
                </div>
              )}
              {sealResult && (
                <button type="button" className="btn primary" onClick={() => onSaved(sealResult.evidence)} style={{ marginTop: 'var(--space-3)' }}>
                  Done
                </button>
              )}
            </div>
          )}

          {error && (
            <div className="alert error" role="alert" style={{ marginTop: 'var(--space-3)' }}>
              <span className="alert-icon">!</span><span>{error}</span>
            </div>
          )}
        </div>

        <div className="modal-foot" style={{ justifyContent: 'space-between' }}>
          <button type="button" className="btn ghost" onClick={onClose} disabled={busy}>Cancel</button>
          <div style={{ display: 'flex', gap: 'var(--space-2)' }}>
            {stepIdx > 1 && !sealResult && (
              <button type="button" className="btn ghost" onClick={prev} disabled={busy}>Back</button>
            )}
            {!isLastStep && (
              <button type="button" className="btn primary" onClick={next} disabled={busy}>Next</button>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
