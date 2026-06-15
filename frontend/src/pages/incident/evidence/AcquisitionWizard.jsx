import { useEffect, useState } from 'react'
import { api } from '../../../api/client.js'
import { TLP } from '../../../lib/incidentVocab.js'

// Collection wizard — ISO/IEC 27037 §7 (branch-aware).
//
// Spine = 27037 Figure 1 (collect vs acquire × device state). Device type is a
// non-exclusive context tag that injects the §7 sub-procedure's extras. Steps:
//   type     — device type tag(s) + digital/physical kind
//   identify — lawful basis, source description, in-situ photo (physical only)
//   decide   — system state, collect/acquire, §7.1.1.3 decision factors
//   branch   — per-type extras (computer/storage/mobile/network/cctv)
//   acquire  — file + tool/version/SHA-256/params, source/target hashes, scope (digital)
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
]

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

function HashInput({ value, onChange, placeholder, disabled }) {
  const ok = value && /^[0-9a-fA-F]{64}$/.test(value)
  const bad = value && !ok
  return (
    <input
      className="input"
      value={value || ''}
      onChange={(e) => onChange(e.target.value.trim())}
      placeholder={placeholder}
      maxLength={64}
      disabled={disabled}
      style={{
        fontFamily: 'var(--font-mono)', fontSize: 11,
        borderColor: bad ? 'var(--crit)' : (ok ? 'var(--ok)' : undefined),
      }}
    />
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

export default function AcquisitionWizard({
  incidentId, entities = [], users = [], onClose, onSaved,
}) {
  // ── Shared identity ───────────────────────────────────────────────────
  const [kind, setKind]             = useState('digital_file')
  const [name, setName]             = useState('')
  const [identifier, setIdentifier] = useState('')
  const [tlp, setTlp]               = useState('amber')
  const [description, setDescription] = useState('')
  const [entityId, setEntityId]     = useState('')
  const [collectedLocation, setCollectedLocation] = useState('')
  const [collectedAsRole, setCollectedAsRole]     = useState('')   // GS-12 — '' | defr | des

  // ── Type step ─────────────────────────────────────────────────────────
  const [deviceTypes, setDeviceTypes] = useState([])

  // ── Identify step ─────────────────────────────────────────────────────
  const [lawfulBasis, setLawfulBasis]         = useState('')
  const [lawfulBasisNote, setLawfulBasisNote] = useState('')
  const [photoCaption, setPhotoCaption]       = useState('')

  // ── Decide step ───────────────────────────────────────────────────────
  const [systemState, setSystemState]             = useState('')
  const [liveJustification, setLiveJustification]  = useState('')
  const [handlingMode, setHandlingMode]            = useState('acquire')
  const [decisionFactors, setDecisionFactors]      = useState({})
  const [decisionNote, setDecisionNote]            = useState('')

  // ── Branch step (device_details) ──────────────────────────────────────
  const [dd, setDd] = useState({})
  const setDetail = (k, v) => setDd(prev => ({ ...prev, [k]: v }))

  // ── Acquire step (digital) ────────────────────────────────────────────
  const [writeBlockerUsed, setWriteBlockerUsed]   = useState('')
  const [writeBlockerSerial, setWriteBlockerSerial] = useState('')
  const [networkIsolated, setNetworkIsolated]     = useState('')
  const [acquisitionTool, setAcquisitionTool]               = useState('')
  const [acquisitionToolVersion, setAcquisitionToolVersion] = useState('')
  const [acquisitionToolSha256, setAcquisitionToolSha256]   = useState('')
  const [acquisitionParams, setAcquisitionParams]           = useState('')
  const [acquisitionHashSource, setAcquisitionHashSource]   = useState('')
  const [acquisitionHashTarget, setAcquisitionHashTarget]   = useState('')
  const [acquisitionScope, setAcquisitionScope]   = useState('')   // '' | full_image | logical
  const [logicalRationale, setLogicalRationale]   = useState('')
  const [systemTimeOffset, setSystemTimeOffset]   = useState('')
  const [screenState, setScreenState]             = useState('')
  const [changesMade, setChangesMade]             = useState('')
  // ISO/IEC 27041 — tool/method validation (Slice B)
  const [toolValidated, setToolValidated]         = useState('')   // '' | true | false
  const [toolValidationRef, setToolValidationRef] = useState('')
  const [toolValidationDate, setToolValidationDate] = useState('')
  // GS-1 — validated-tools registry (ISO/IEC 27041)
  const [validatedTools, setValidatedTools]       = useState([])
  const [file, setFile]   = useState(null)

  // ── Witness step ──────────────────────────────────────────────────────
  const [witnessUserId, setWitnessUserId] = useState('')
  const [witnessName, setWitnessName]     = useState('')

  // ── Step machinery ────────────────────────────────────────────────────
  const [step, setStep] = useState('type')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)
  const [sealResult, setSealResult] = useState(null)

  const isLive = systemState === 'live' || systemState === 'live_critical'
  const has = (t) => deviceTypes.includes(t)

  // Step list per kind + tags. `branch` only when a type is tagged; `acquire`
  // only for digital files.
  const stepList = [
    'type', 'identify', 'decide',
    ...(deviceTypes.length ? ['branch'] : []),
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
      if (kind === 'physical_item' && !photoCaption.trim()) {
        setError('Physical evidence requires at least one in-situ photo caption (ISO 27037 §9.1.4).'); return false
      }
    }
    if (s === 'decide') {
      if (isLive && !liveJustification.trim()) {
        setError('Live / mission-critical acquisition requires justification (ISO 27037 §9.2.1 / §7.1.3.1.1).'); return false
      }
    }
    if (s === 'acquire') {
      if (kind === 'digital_file' && !file) { setError('Please choose a file to acquire.'); return false }
      if (!acquisitionTool.trim() || !acquisitionToolVersion.trim()) {
        setError('Acquisition tool name + version are required for reproducibility (ISO 27037 §9.2.4).'); return false
      }
      if (acquisitionScope === 'logical' && !logicalRationale.trim()) {
        setError('Logical acquisition requires a rationale of what was taken and why (§7.1.3.1.1).'); return false
      }
      if (acquisitionHashSource && acquisitionHashTarget &&
          acquisitionHashSource.toLowerCase() !== acquisitionHashTarget.toLowerCase()) {
        setError('Source and target hashes do not match — acquisition integrity broken. Re-acquire before continuing.'); return false
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
      { ok: !!file,                                              label: 'File acquired (SHA-256 computed)' },
      { ok: !!(acquisitionTool.trim() && acquisitionToolVersion.trim()), label: 'Acquisition tool + version' },
      ...(isLive ? [{ ok: !!liveJustification.trim(), label: 'Live justification' }] : []),
      ...(acquisitionScope === 'logical' ? [{ ok: !!logicalRationale.trim(), label: 'Logical-acquisition rationale' }] : []),
    ] : [
      { ok: !!photoCaption.trim(),  label: 'In-situ photo caption' },
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
        screen_state: screenState.trim() || null,
        changes_made: changesMade.trim() || null,
        device_details,
        // ISO/IEC 27041 — method/tool validation (Slice B)
        acquisition_tool_validated: toolValidated === '' ? null : toolValidated === 'true',
        acquisition_tool_validation_ref: toolValidationRef.trim() || null,
        acquisition_tool_validation_date: toolValidationDate || null,
      }

      let created
      if (kind === 'digital_file') {
        created = await api.collectDigital(incidentId, {
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
            write_blocker_used: writeBlockerUsed === '' ? null : writeBlockerUsed === 'true',
            write_blocker_serial: writeBlockerSerial.trim() || null,
            system_state: systemState || null,
            live_justification: liveJustification.trim() || null,
            network_isolated: networkIsolated === '' ? null : networkIsolated === 'true',
          },
        })
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
            taken_at: new Date().toISOString(),
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
      setError(e.message || 'Could not collect evidence.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="modal-backdrop">
      <div className="modal" role="dialog" aria-labelledby="aw-title" style={{ width: 'min(640px, 96vw)' }}>
        <div className="modal-head">
          <h2 id="aw-title">Collection wizard — ISO/IEC 27037 §7</h2>
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
                <div className="field-hint">A device can be several types (e.g. a seized phone is both Mobile and Storage). Each tag adds its §7 checklist on the Branch step.</div>
              </div>

              <div className="field">
                <label className="field-label" htmlFor="aw-kind">Record as</label>
                <select id="aw-kind" className="select" value={kind} onChange={e => setKind(e.target.value)}>
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
                          subtitle="ISO 27037 §9.1 · GDPR Art. 5.1(c)" />

              <div className="form-row">
                <div className="field">
                  <label className="field-label" htmlFor="aw-name">Name</label>
                  <input id="aw-name" className="input" value={name} onChange={e => setName(e.target.value)}
                         autoFocus maxLength={256} placeholder="e.g. WIN-FS01 memory dump" />
                </div>
                <div className="field">
                  <label className="field-label" htmlFor="aw-tlp">TLP</label>
                  <select id="aw-tlp" className="select" value={tlp} onChange={e => setTlp(e.target.value)}>
                    {TLP.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
                  </select>
                </div>
              </div>

              <div className="field">
                <label className="field-label" htmlFor="aw-id">Identifier (case tag / item #)</label>
                <input id="aw-id" className="input" value={identifier} onChange={e => setIdentifier(e.target.value)}
                       maxLength={128} placeholder="e.g. EV-2026-042-01" style={{ fontFamily: 'var(--font-mono)' }} />
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
                          onChange={e => setDescription(e.target.value)} rows={2} maxLength={4096} />
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

              {entities.length > 0 && (
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

              {kind === 'physical_item' && (
                <div className="field">
                  <label className="field-label" htmlFor="aw-photo">In-situ photo caption * (ISO 27037 §9.1.4)</label>
                  <input id="aw-photo" className="input" value={photoCaption}
                         onChange={e => setPhotoCaption(e.target.value)} maxLength={256}
                         placeholder="e.g. Laptop in situ on desk, lid open, screen photographed (IMG_3421)" />
                  <div className="field-hint">Caption alone documents that a photo was taken — file attachment UI in a later slice.</div>
                </div>
              )}
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
                          subtitle="ISO 27037 §9.2.4 / §7.1.3.1.1 · NIST SP 800-86 §3.2.4" />

              <div className="field">
                <label className="field-label" htmlFor="aw-file">File *</label>
                <input id="aw-file" className="input" type="file" onChange={e => setFile(e.target.files?.[0] || null)} />
                <div className="field-hint">Hashed (SHA-256 + SHA-1 + MD5) and AES-256-GCM encrypted at rest on upload.</div>
              </div>

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
                <HashInput value={acquisitionToolSha256} onChange={setAcquisitionToolSha256}
                           placeholder="64-hex tool binary fingerprint" />
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
                  <HashInput value={acquisitionHashSource} onChange={setAcquisitionHashSource} placeholder="SHA-256 of source media" />
                </div>
                <div className="field">
                  <label className="field-label" htmlFor="aw-ht">Target hash (post-image)</label>
                  <HashInput value={acquisitionHashTarget} onChange={setAcquisitionHashTarget} placeholder="SHA-256 of acquired image" />
                </div>
              </div>
              {acquisitionHashSource && acquisitionHashTarget && (
                <div style={{
                  padding: '6px 10px', fontSize: 11,
                  background: acquisitionHashSource.toLowerCase() === acquisitionHashTarget.toLowerCase()
                    ? 'color-mix(in srgb, var(--ok) 12%, transparent)'
                    : 'color-mix(in srgb, var(--crit) 12%, transparent)',
                  color: acquisitionHashSource.toLowerCase() === acquisitionHashTarget.toLowerCase() ? 'var(--ok)' : 'var(--crit)',
                  borderRadius: 'var(--radius-sm)',
                }}>
                  {acquisitionHashSource.toLowerCase() === acquisitionHashTarget.toLowerCase()
                    ? '✓ Source and target hashes match — acquisition integrity proven'
                    : '✗ Hashes differ — re-acquire before sealing'}
                </div>
              )}

              {(systemState === 'live' || systemState === 'live_critical') && (
                <div className="field">
                  <label className="field-label" htmlFor="aw-screen">On-screen state (§6.6)</label>
                  <input id="aw-screen" className="input" value={screenState}
                         onChange={e => setScreenState(e.target.value)} maxLength={1024}
                         placeholder="e.g. visible apps: Outlook, TrueCrypt mounted volume X:, browser at …" />
                </div>
              )}

              <div className="form-row">
                <div className="field">
                  <label className="field-label" htmlFor="aw-wb2">Write-blocker used?</label>
                  <select id="aw-wb2" className="select" value={writeBlockerUsed} onChange={e => setWriteBlockerUsed(e.target.value)}>
                    <option value="">— select —</option>
                    <option value="true">Yes</option>
                    <option value="false">No</option>
                  </select>
                </div>
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
                  {users.filter(u => u.is_active).map(u => (
                    <option key={u.id} value={u.id}>{u.username} ({u.role})</option>
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
                      {(witnessUserId || witnessName) && (
                        <li><strong>Witness:</strong> {witnessName || users.find(u => u.id === witnessUserId)?.username}</li>
                      )}
                    </ul>
                  </div>
                  <button type="button" className="btn primary" onClick={commit} disabled={busy} style={{ marginTop: 'var(--space-3)' }}>
                    {busy ? 'Collecting & sealing…' : (sealReady ? 'Collect & seal' : 'Collect (seal later)')}
                  </button>
                </>
              )}

              {sealResult?.kind === 'sealed' && (
                <div className="alert info" role="status">
                  <span className="alert-icon">✓</span>
                  <span>Evidence row created and sealed. ISO 27037 + GDPR fields locked; further changes write amend-after-seal audit entries.</span>
                </div>
              )}
              {sealResult?.kind === 'unsealed' && (
                <div className="alert error" role="alert">
                  <span className="alert-icon">!</span>
                  <span>Evidence row created but seal failed: {sealResult.message}. You can return later to seal the row.</span>
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
