// Tiny fetch wrapper for the v2 API.
// - cookies always sent (same-origin)
// - JSON in / JSON out
// - 401 → null user / caller decides
// - normalises FastAPI {detail, code} into Error.message + Error.status + Error.code

async function request(method, path, body) {
  const headers = { Accept: 'application/json' }
  const init = { method, credentials: 'same-origin', headers }
  if (body !== undefined) {
    headers['Content-Type'] = 'application/json'
    init.body = JSON.stringify(body)
  }
  const res = await fetch(path, init)
  const text = await res.text()
  const data = text ? safeJson(text) : null
  if (!res.ok) {
    const err = new Error(extractMessage(data, res.status))
    err.status = res.status
    err.code = data && typeof data === 'object' ? data.code : undefined
    err.data = data
    throw err
  }
  return data
}

function safeJson(s) {
  try { return JSON.parse(s) } catch { return s }
}

function extractMessage(data, status) {
  if (data && typeof data === 'object') {
    if (typeof data.detail === 'string') return data.detail
    if (Array.isArray(data.detail) && data.detail[0]?.msg) return data.detail[0].msg
  }
  if (status === 429) return 'Too many attempts. Try again later.'
  if (status === 401) return 'Authentication failed.'
  if (status === 403) return 'Forbidden.'
  return `Request failed (${status})`
}

export const api = {
  // health
  health:        ()        => request('GET',  '/api/health'),

  // first-run gate + policy
  setupCheck:    ()        => request('GET',  '/api/auth/setup-check'),
  authPolicy:    ()        => request('GET',  '/api/auth/policy'),
  setup:         (payload) => request('POST', '/api/auth/setup', payload),

  // login
  login:         (payload) => request('POST', '/api/auth/login', payload),
  totpVerify:    (code)    => request('POST', '/api/auth/totp/verify', { code }),
  logout:        ()        => request('POST', '/api/auth/logout'),

  // current user
  me:            ()        => request('GET',  '/api/users/me'),

  // totp enrol
  totpSetup:     ()        => request('POST', '/api/auth/totp/setup'),
  totpEnable:    (code)    => request('POST', '/api/auth/totp/enable', { code }),
  totpDisable:   (payload) => request('POST', '/api/auth/totp/disable', payload),

  // account self-service
  changePassword: (payload) => request('POST', '/api/auth/change-password', payload),

  // sessions (own)
  listSessions:        ()              => request('GET',    '/api/sessions'),
  revokeSession:       (id)            => request('DELETE', `/api/sessions/${id}`),
  revokeOtherSessions: ()              => request('POST',   '/api/sessions/revoke-others'),
  labelSession:        (id, label)     => request('PATCH',  `/api/sessions/${id}/label`, { label }),

  // sessions (admin — all users)
  listAdminSessions:  ()   => request('GET',    '/api/admin/sessions'),
  adminRevokeSession: (id) => request('DELETE', `/api/admin/sessions/${id}`),

  // teams (admin)
  listTeams:        ()              => request('GET',    '/api/teams'),
  createTeam:       (payload)       => request('POST',   '/api/teams', payload),
  updateTeam:       (id, payload)   => request('PATCH',  `/api/teams/${id}`, payload),
  deleteTeam:       (id)            => request('DELETE', `/api/teams/${id}`),
  listTeamMembers:  (teamId)         => request('GET',    `/api/teams/${teamId}/members`),
  addTeamMember:    (teamId, userId) => request('POST',   `/api/teams/${teamId}/members/${userId}`),
  removeTeamMember: (teamId, userId) => request('DELETE', `/api/teams/${teamId}/members/${userId}`),

  // operational roles (admin)
  listOperationalRoles:  ({ includeInactive = false } = {}) =>
    request('GET', `/api/operational-roles${includeInactive ? '?include_inactive=true' : ''}`),
  createOperationalRole: (payload)      => request('POST',   '/api/operational-roles', payload),
  updateOperationalRole: (id, payload)  => request('PATCH',  `/api/operational-roles/${id}`, payload),
  deleteOperationalRole: (id)           => request('DELETE', `/api/operational-roles/${id}`),

  // users (admin)
  listUsers:             ()              => request('GET',    '/api/users'),
  createUser:            (payload)       => request('POST',   '/api/users', payload),
  getUser:               (id)            => request('GET',    `/api/users/${id}`),
  updateUser:            (id, payload)   => request('PATCH',  `/api/users/${id}`, payload),
  deleteUser:            (id)            => request('DELETE', `/api/users/${id}`),

  // Validated-tools registry (ISO/IEC 27041, GS-1)
  listValidatedTools:    (params = {}) => {
    const qs = new URLSearchParams()
    for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== null && v !== '') qs.set(k, v)
    const s = qs.toString()
    return request('GET', `/api/validated-tools${s ? '?' + s : ''}`)
  },
  createValidatedTool:   (payload)     => request('POST',   '/api/validated-tools', payload),
  updateValidatedTool:   (id, payload) => request('PATCH',  `/api/validated-tools/${id}`, payload),
  deleteValidatedTool:   (id)          => request('DELETE', `/api/validated-tools/${id}`),
  resetPassword:         (id, payload)   => request('POST',   `/api/users/${id}/reset-password`, payload),
  getUserSessions:       (id)            => request('GET',    `/api/users/${id}/sessions`),
  revokeUserSession:     (id, sessionId) => request('DELETE', `/api/users/${id}/sessions/${sessionId}`),
  revokeUserAllSessions: (id)            => request('POST',   `/api/users/${id}/sessions/revoke-all`),
  unlockUser:            (id)            => request('POST',   `/api/users/${id}/unlock`),
  getUserActivity:       (id)            => request('GET',    `/api/users/${id}/activity`),
  getUserTeams:          (id)            => request('GET',    `/api/users/${id}/teams`),

  // incidents
  listIncidents: (params = {}) => {
    const qs = new URLSearchParams()
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== null && v !== '') qs.set(k, v)
    }
    const s = qs.toString()
    return request('GET', `/api/incidents${s ? '?' + s : ''}`)
  },
  getIncident:         (id)       => request('GET',   `/api/incidents/${id}`),
  getIncidentSnapshot: (id)       => request('GET',   `/api/incidents/${id}/snapshot`),
  createIncident:      (payload)  => request('POST',  '/api/incidents', payload),
  updateIncident:      (id, body) => request('PATCH', `/api/incidents/${id}`, body),
  closeIncident:       (id)       => request('POST',  `/api/incidents/${id}/close`),
  reopenIncident:      (id)       => request('POST',  `/api/incidents/${id}/reopen`),

  // IOC export — triggers a browser file download
  exportIocs: async (incidentId, fmt, params = {}) => {
    const qs = new URLSearchParams()
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== null && v !== '') qs.set(k, v)
    }
    const s = qs.toString()
    const url = `/api/incidents/${incidentId}/iocs/export/${fmt}${s ? '?' + s : ''}`
    const res = await fetch(url, { method: 'GET', credentials: 'same-origin' })
    if (!res.ok) {
      const text = await res.text()
      const data = text ? (() => { try { return JSON.parse(text) } catch { return text } })() : null
      const err = new Error(
        (data && typeof data === 'object' && (data.detail || data.message)) ||
        `Export failed (${res.status})`
      )
      err.status = res.status
      throw err
    }
    const blob = await res.blob()
    const cd = res.headers.get('Content-Disposition') || ''
    const match = cd.match(/filename="([^"]+)"/)
    const filename = match ? match[1] : `iocs-${fmt}.bin`
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = filename
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(a.href)
  },

  // Correlations — per-incident IOC cross-match + global shared views
  listIocCorrelations:      (incidentId)             => request('GET', `/api/incidents/${incidentId}/iocs/correlations`),
  listCorrelatedIocs:       (params = {}) => {
    const qs = new URLSearchParams()
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== null && v !== '') qs.set(k, v)
    }
    const s = qs.toString()
    return request('GET', `/api/correlations/iocs${s ? '?' + s : ''}`)
  },
  listCorrelatedEntities:   (params = {}) => {
    const qs = new URLSearchParams()
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== null && v !== '') qs.set(k, v)
    }
    const s = qs.toString()
    return request('GET', `/api/correlations/entities${s ? '?' + s : ''}`)
  },

  // IOCs (per-incident)
  listIocs:    (incidentId, params = {}) => {
    const qs = new URLSearchParams()
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== null && v !== '') qs.set(k, v)
    }
    const s = qs.toString()
    return request('GET', `/api/incidents/${incidentId}/iocs${s ? '?' + s : ''}`)
  },
  createIoc:   (incidentId, payload)         => request('POST',   `/api/incidents/${incidentId}/iocs`, payload),
  updateIoc:   (incidentId, iocId, payload)  => request('PATCH',  `/api/incidents/${incidentId}/iocs/${iocId}`, payload),
  deleteIoc:   (incidentId, iocId)           => request('DELETE', `/api/incidents/${incidentId}/iocs/${iocId}`),
  scanIocsTi:  (incidentId)                  => request('POST',   `/api/incidents/${incidentId}/iocs/scan-ti`),

  // Threat intel feeds (admin CRUD + pull; analyst read)
  listTiFeeds:    ()               => request('GET',    '/api/threat-intel/feeds'),
  initTiFeeds:    ()               => request('POST',   '/api/threat-intel/feeds/init'),
  createTiFeed:   (payload)        => request('POST',   '/api/threat-intel/feeds', payload),
  updateTiFeed:   (id, payload)    => request('PATCH',  `/api/threat-intel/feeds/${id}`, payload),
  deleteTiFeed:   (id)             => request('DELETE', `/api/threat-intel/feeds/${id}`),
  pullTiFeed:     (id)             => request('POST',   `/api/threat-intel/feeds/${id}/pull`),
  pullAllTiFeeds: ()               => request('POST',   '/api/threat-intel/feeds/pull-all'),
  listTiIocs:     (params = {}) => {
    const qs = new URLSearchParams()
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== null && v !== '') qs.set(k, v)
    }
    const s = qs.toString()
    return request('GET', `/api/threat-intel/iocs${s ? '?' + s : ''}`)
  },
  getTiSummary:          ()             => request('GET', '/api/threat-intel/summary'),
  getTiIncidentMatches:  (params = {}) => {
    const qs = new URLSearchParams()
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== null && v !== '') qs.set(k, v)
    }
    const s = qs.toString()
    return request('GET', `/api/threat-intel/incident-matches${s ? '?' + s : ''}`)
  },

  // Entities (per-incident)
  listEntities: (incidentId, params = {}) => {
    const qs = new URLSearchParams()
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== null && v !== '') qs.set(k, v)
    }
    const s = qs.toString()
    return request('GET', `/api/incidents/${incidentId}/entities${s ? '?' + s : ''}`)
  },
  createEntity: (incidentId, payload)             => request('POST',   `/api/incidents/${incidentId}/entities`, payload),
  updateEntity: (incidentId, entityId, payload)   => request('PATCH',  `/api/incidents/${incidentId}/entities/${entityId}`, payload),
  deleteEntity: (incidentId, entityId)            => request('DELETE', `/api/incidents/${incidentId}/entities/${entityId}`),

  listEntityRelations:  (incidentId)              => request('GET',    `/api/incidents/${incidentId}/entity-relations`),
  createEntityRelation: (incidentId, payload)     => request('POST',   `/api/incidents/${incidentId}/entity-relations`, payload),
  deleteEntityRelation: (incidentId, relationId)  => request('DELETE', `/api/incidents/${incidentId}/entity-relations/${relationId}`),

  // Entity asset log
  listEntityEvents:   (incidentId, entityId)             => request('GET',    `/api/incidents/${incidentId}/entities/${entityId}/asset-log`),
  createEntityEvent:  (incidentId, entityId, payload)    => request('POST',   `/api/incidents/${incidentId}/entities/${entityId}/asset-log`, payload),
  deleteEntityEvent:  (incidentId, entityId, eventId)    => request('DELETE', `/api/incidents/${incidentId}/entities/${entityId}/asset-log/${eventId}`),

  // Entity files
  listEntityFiles:   (incidentId, entityId)            => request('GET',    `/api/incidents/${incidentId}/entities/${entityId}/files`),
  deleteEntityFile:  (incidentId, entityId, fileId)    => request('DELETE', `/api/incidents/${incidentId}/entities/${entityId}/files/${fileId}`),
  entityFileDownloadUrl: (incidentId, entityId, fileId) =>
    `/api/incidents/${incidentId}/entities/${entityId}/files/${fileId}/download`,

  uploadEntityFile: async (incidentId, entityId, file) => {
    const form = new FormData()
    form.append('file', file)
    const res = await fetch(`/api/incidents/${incidentId}/entities/${entityId}/files`, {
      method: 'POST',
      credentials: 'same-origin',
      body: form,
    })
    const text = await res.text()
    const data = text ? (() => { try { return JSON.parse(text) } catch { return text } })() : null
    if (!res.ok) {
      const err = new Error(
        (data && typeof data === 'object' && (data.detail || data.message)) ||
        (res.status === 413 ? 'File exceeds 50 MB limit.' : `Upload failed (${res.status})`)
      )
      err.status = res.status
      throw err
    }
    return data
  },

  // Evidence (chain of custody)
  listEvidence: (incidentId, params = {}) => {
    const qs = new URLSearchParams()
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== null && v !== '') qs.set(k, v)
    }
    const s = qs.toString()
    return request('GET', `/api/incidents/${incidentId}/evidence${s ? '?' + s : ''}`)
  },
  getEvidence:        (incidentId, evidenceId) => request('GET', `/api/incidents/${incidentId}/evidence/${evidenceId}`),
  updateEvidence:     (incidentId, evidenceId, payload) =>
    request('PATCH', `/api/incidents/${incidentId}/evidence/${evidenceId}`, payload),

  // Collect — digital_file uses multipart/form-data (no JSON wrapper).
  // `wizard` is the optional Wizard-A AcquisitionMetadata payload; passed as
  // additional Form fields so the back-end endpoint stays one route.
  collectDigital: async (incidentId, { name, identifier, description, tlp, collected_location, entity_id, file, wizard }) => {
    const form = new FormData()
    form.append('name', name)
    form.append('identifier', identifier)
    if (description)        form.append('description', description)
    if (tlp)                form.append('tlp', tlp)
    if (collected_location) form.append('collected_location', collected_location)
    if (entity_id)          form.append('entity_id', entity_id)
    if (wizard) {
      for (const [k, v] of Object.entries(wizard)) {
        if (v === null || v === undefined || v === '') continue
        if (Array.isArray(v)) {
          // Lists ride as a JSON string (multipart list binding varies by
          // framework version) — backend parses via _json_list (e.g. device_types).
          if (v.length === 0) continue
          form.append(k, JSON.stringify(v))
        } else if (typeof v === 'object') {
          // Nested objects can't ride multipart natively → JSON string the
          // backend parses (e.g. decision_factors, device_details).
          form.append(k, JSON.stringify(v))
        } else {
          // Booleans need explicit "true"/"false" so FastAPI parses them.
          form.append(k, typeof v === 'boolean' ? String(v) : v)
        }
      }
    }
    form.append('file', file)
    const res = await fetch(`/api/incidents/${incidentId}/evidence/digital`, {
      method: 'POST',
      credentials: 'same-origin',
      body: form,
    })
    const text = await res.text()
    const data = text ? (() => { try { return JSON.parse(text) } catch { return text } })() : null
    if (!res.ok) {
      const err = new Error(
        (data && typeof data === 'object' && (data.detail || data.message)) ||
        (res.status === 413 ? 'File exceeds upload limit.' : `Upload failed (${res.status})`)
      )
      err.status = res.status
      err.data = data
      throw err
    }
    return data
  },

  collectPhysical: (incidentId, payload) =>
    request('POST', `/api/incidents/${incidentId}/evidence/physical`, payload),

  transferEvidence: (incidentId, evidenceId, payload) =>
    request('POST', `/api/incidents/${incidentId}/evidence/${evidenceId}/transfer`, payload),

  examineEvidence:  (incidentId, evidenceId, payload) =>
    request('POST', `/api/incidents/${incidentId}/evidence/${evidenceId}/examine`, payload),

  verifyEvidence:   (incidentId, evidenceId) =>
    request('POST', `/api/incidents/${incidentId}/evidence/${evidenceId}/verify`),

  disposeEvidence:  (incidentId, evidenceId, payload) =>
    request('POST', `/api/incidents/${incidentId}/evidence/${evidenceId}/dispose`, payload),

  // U8.1 — Email analyzer (Forensic → Email)
  analyzeEmail: async (incidentId, { raw, file }) => {
    const form = new FormData()
    if (file) form.append('file', file)
    if (raw != null && raw !== '') form.append('raw', raw)
    const res = await fetch(`/api/incidents/${incidentId}/email/analyze`, {
      method: 'POST', credentials: 'same-origin', body: form,
    })
    const text = await res.text()
    const data = text ? (() => { try { return JSON.parse(text) } catch { return text } })() : null
    if (!res.ok) {
      const err = new Error((data && typeof data === 'object' && (data.detail || data.message)) || `Analyze failed (${res.status})`)
      err.status = res.status; err.data = data
      throw err
    }
    return data
  },
  listEmailAnalyses:   (incidentId)        => request('GET',  `/api/incidents/${incidentId}/email`),
  getEmailAnalysis:    (incidentId, aid)   => request('GET',  `/api/incidents/${incidentId}/email/${aid}`),
  promoteEmailIocs:    (incidentId, aid, iocs) => request('POST', `/api/incidents/${incidentId}/email/${aid}/promote-iocs`, { iocs }),
  extractEmailAttachment: (incidentId, aid, idx) => request('POST', `/api/incidents/${incidentId}/email/${aid}/attachments/${idx}/extract`),
  importEmailHops:     (incidentId, aid)   => request('POST', `/api/incidents/${incidentId}/email/${aid}/import-hops`),
  mintEmailEvidence:   (incidentId, aid)   => request('POST', `/api/incidents/${incidentId}/email/${aid}/mint-evidence`),

  // GS-11 — attach an image/* photo (encrypted at rest). Returns the updated evidence.
  addEvidencePhoto: async (incidentId, evidenceId, { file, caption, taken_at }) => {
    const form = new FormData()
    form.append('file', file)
    if (caption)  form.append('caption', caption)
    if (taken_at) form.append('taken_at', taken_at)
    const res = await fetch(`/api/incidents/${incidentId}/evidence/${evidenceId}/photos`, {
      method: 'POST', credentials: 'same-origin', body: form,
    })
    const text = await res.text()
    const data = text ? (() => { try { return JSON.parse(text) } catch { return text } })() : null
    if (!res.ok) {
      const err = new Error(
        (data && typeof data === 'object' && (data.detail || data.message)) ||
        (res.status === 415 ? 'File must be an image.' : `Upload failed (${res.status})`)
      )
      err.status = res.status; err.data = data
      throw err
    }
    return data
  },

  // Wizard A — Seal: validates ISO 27037 + GDPR Art. 5.1(c) minimum fields and locks the row.
  sealEvidence:     (incidentId, evidenceId) =>
    request('POST', `/api/incidents/${incidentId}/evidence/${evidenceId}/seal`, { confirm: true }),

  // Wizard B — Examination session (pre-verify → record → post-verify, transactional).
  examinationSession: (incidentId, evidenceId, payload) =>
    request('POST', `/api/incidents/${incidentId}/evidence/${evidenceId}/examination-session`, payload),

  // Server-side provenance score (mirrors SOP autoCheck logic).
  evidenceProvenance: (incidentId, evidenceId) =>
    request('GET',  `/api/incidents/${incidentId}/evidence/${evidenceId}/provenance`),

  custodyLog:       (incidentId, evidenceId) =>
    request('GET',  `/api/incidents/${incidentId}/evidence/${evidenceId}/custody`),

  // Working-copy ledger (ISO/IEC 27037 §7.1.3.1.1, Slice C)
  listWorkingCopies: (incidentId, evidenceId) =>
    request('GET',  `/api/incidents/${incidentId}/evidence/${evidenceId}/working-copies`),
  mintWorkingCopy:   (incidentId, evidenceId, payload) =>
    request('POST', `/api/incidents/${incidentId}/evidence/${evidenceId}/working-copy`, payload),
  incidentCustodyLog: (incidentId) =>
    request('GET',  `/api/incidents/${incidentId}/evidence/custody-log`),
  verifyCustodyChain: (incidentId) =>
    request('POST', `/api/incidents/${incidentId}/evidence/custody-log/verify`),

  // Incident audit log (admin-only)
  incidentAuditLog: (incidentId, params = {}) => {
    const qs = new URLSearchParams(params).toString()
    return request('GET', `/api/incidents/${incidentId}/audit-log${qs ? '?' + qs : ''}`)
  },

  // Global audit log (admin-only)
  globalAuditLog: (params = {}) => {
    const qs = new URLSearchParams()
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== null && v !== '') qs.set(k, v)
    }
    const s = qs.toString()
    return request('GET', `/api/admin/audit-log${s ? '?' + s : ''}`)
  },

  // Signed audit-log exports — admin only.
  // Each create returns the bundle key ONCE in the response body, alongside
  // the single-use 24h download URL at /api/audit-exports/{token}.
  createGlobalAuditExport: (payload) =>
    request('POST', '/api/admin/audit-log/exports', payload),
  listGlobalAuditExports: (params = {}) => {
    const qs = new URLSearchParams()
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== null && v !== '') qs.set(k, v)
    }
    const s = qs.toString()
    return request('GET', `/api/admin/audit-log/exports${s ? '?' + s : ''}`)
  },
  createIncidentAuditExport: (incidentId, payload) =>
    request('POST', `/api/incidents/${incidentId}/audit-log/exports`, payload),
  listIncidentAuditExports: (incidentId) =>
    request('GET', `/api/incidents/${incidentId}/audit-log/exports`),

  // Ed25519 public key + fingerprint (used by the offline verifier).
  getVersion: () => request('GET', '/api/version'),

  // Admin: backups
  listBackups: () => request('GET',  '/api/admin/backups'),
  runBackup:   () => request('POST', '/api/admin/backups/run'),

  // Playbook templates
  listPlaybookTemplates:   ()              => request('GET',    '/api/playbook-templates'),
  getPlaybookTemplate:     (id)            => request('GET',    `/api/playbook-templates/${id}`),
  createPlaybookTemplate:  (payload)       => request('POST',   '/api/playbook-templates', payload),
  updatePlaybookTemplate:  (id, payload)   => request('PATCH',  `/api/playbook-templates/${id}`, payload),
  deletePlaybookTemplate:  (id)            => request('DELETE', `/api/playbook-templates/${id}`),

  // Playbook tasks (per incident)
  listPlaybookTasks: (incidentId) =>
    request('GET',    `/api/incidents/${incidentId}/playbook/tasks`),
  createPlaybookTask: (incidentId, payload) =>
    request('POST',   `/api/incidents/${incidentId}/playbook/tasks`, payload),
  updatePlaybookTask: (incidentId, taskId, payload) =>
    request('PATCH',  `/api/incidents/${incidentId}/playbook/tasks/${taskId}`, payload),
  deletePlaybookTask: (incidentId, taskId) =>
    request('DELETE', `/api/incidents/${incidentId}/playbook/tasks/${taskId}`),
  instantiatePlaybook: (incidentId, payload) =>
    request('POST',   `/api/incidents/${incidentId}/playbook/instantiate`, payload),

  // Respond — actions (per-incident)
  listRespondActions: (incidentId, params = {}) => {
    const qs = new URLSearchParams()
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== null && v !== '') qs.set(k, v)
    }
    const s = qs.toString()
    return request('GET', `/api/incidents/${incidentId}/respond/actions${s ? '?' + s : ''}`)
  },
  createRespondAction: (incidentId, payload)             => request('POST',   `/api/incidents/${incidentId}/respond/actions`, payload),
  updateRespondAction: (incidentId, actionId, payload)   => request('PATCH',  `/api/incidents/${incidentId}/respond/actions/${actionId}`, payload),
  revertRespondAction: (incidentId, actionId, payload)   => request('POST',   `/api/incidents/${incidentId}/respond/actions/${actionId}/revert`, payload),
  deleteRespondAction: (incidentId, actionId)            => request('DELETE', `/api/incidents/${incidentId}/respond/actions/${actionId}`),

  // Respond — decisions (per-incident)
  listDecisions: (incidentId, params = {}) => {
    const qs = new URLSearchParams()
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== null && v !== '') qs.set(k, v)
    }
    const s = qs.toString()
    return request('GET', `/api/incidents/${incidentId}/respond/decisions${s ? '?' + s : ''}`)
  },
  createDecision: (incidentId, payload)               => request('POST',   `/api/incidents/${incidentId}/respond/decisions`, payload),
  updateDecision: (incidentId, decisionId, payload)   => request('PATCH',  `/api/incidents/${incidentId}/respond/decisions/${decisionId}`, payload),
  deleteDecision: (incidentId, decisionId)            => request('DELETE', `/api/incidents/${incidentId}/respond/decisions/${decisionId}`),

  // Comms — comments (per-incident)
  listComments: (incidentId, params = {}) => {
    const qs = new URLSearchParams()
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== null && v !== '') qs.set(k, v)
    }
    const s = qs.toString()
    return request('GET', `/api/incidents/${incidentId}/comments${s ? '?' + s : ''}`)
  },
  createComment:   (incidentId, payload)              => request('POST',   `/api/incidents/${incidentId}/comments`, payload),
  updateComment:   (incidentId, commentId, payload)   => request('PATCH',  `/api/incidents/${incidentId}/comments/${commentId}`, payload),
  deleteComment:   (incidentId, commentId)            => request('DELETE', `/api/incidents/${incidentId}/comments/${commentId}`),

  // Comms — OOB passphrase + dark operation
  getPassphrase:        (incidentId)          => request('GET',   `/api/incidents/${incidentId}/oob/passphrase`),
  regeneratePassphrase: (incidentId)          => request('POST',  `/api/incidents/${incidentId}/oob/passphrase/regenerate`),
  toggleDarkOperation:  (incidentId, enabled) => request('PATCH', `/api/incidents/${incidentId}/oob/dark-operation`, { enabled }),

  // Comms — OOB communications log
  listOOBLog:   (incidentId)          => request('GET',    `/api/incidents/${incidentId}/oob/log`),
  createOOBLog: (incidentId, payload) => request('POST',   `/api/incidents/${incidentId}/oob/log`, payload),
  deleteOOBLog: (incidentId, logId)   => request('DELETE', `/api/incidents/${incidentId}/oob/log/${logId}`),

  // Stakeholder contacts (per-incident)
  listStakeholders:        (incidentId, params = {}) => {
    const qs = new URLSearchParams(params).toString()
    return request('GET', `/api/incidents/${incidentId}/stakeholders${qs ? '?' + qs : ''}`)
  },
  createStakeholder:       (incidentId, payload)               => request('POST',   `/api/incidents/${incidentId}/stakeholders`, payload),
  updateStakeholder:       (incidentId, stakeholderId, payload) => request('PATCH',  `/api/incidents/${incidentId}/stakeholders/${stakeholderId}`, payload),
  deleteStakeholder:       (incidentId, stakeholderId)          => request('DELETE', `/api/incidents/${incidentId}/stakeholders/${stakeholderId}`),
  bulkCreateStakeholders:  (incidentId, payload)               => request('POST',   `/api/incidents/${incidentId}/stakeholders/bulk`, payload),

  // Incident assignments (IR role roster)
  listAssignments:   (incidentId)                              => request('GET',    `/api/incidents/${incidentId}/assignments`),
  createAssignment:  (incidentId, payload)                     => request('POST',   `/api/incidents/${incidentId}/assignments`, payload),
  deleteAssignment:  (incidentId, assignmentId)                => request('DELETE', `/api/incidents/${incidentId}/assignments/${assignmentId}`),

  // Timeline (per-incident)
  listTimelineEvents: (incidentId, params = {}) => {
    const qs = new URLSearchParams()
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== null && v !== '') qs.set(k, v)
    }
    const s = qs.toString()
    return request('GET', `/api/incidents/${incidentId}/timeline${s ? '?' + s : ''}`)
  },
  createTimelineEvent: (incidentId, payload)          => request('POST',   `/api/incidents/${incidentId}/timeline`, payload),
  updateTimelineEvent: (incidentId, eventId, payload) => request('PATCH',  `/api/incidents/${incidentId}/timeline/${eventId}`, payload),
  deleteTimelineEvent: (incidentId, eventId)          => request('DELETE', `/api/incidents/${incidentId}/timeline/${eventId}`),

  batchCreateTimelineEvents: (incidentId, payload) =>
    request('POST', `/api/incidents/${incidentId}/timeline/batch`, payload),

  // Forensic artifact parse (multipart — returns candidate events, nothing persisted)
  parseForensicTimeline: async (incidentId, file) => {
    const form = new FormData()
    form.append('file', file)
    const res = await fetch(`/api/incidents/${incidentId}/forensic/timeline-import/parse`, {
      method: 'POST',
      credentials: 'same-origin',
      body: form,
    })
    const text = await res.text()
    const data = text ? (() => { try { return JSON.parse(text) } catch { return text } })() : null
    if (!res.ok) {
      const err = new Error(
        (data && typeof data === 'object' && (data.detail || data.message)) ||
        (res.status === 413 ? 'File exceeds 100 MB limit.' : `Parse failed (${res.status})`)
      )
      err.status = res.status
      err.data = data
      throw err
    }
    return data
  },

  // Forensic timeline imports — persisted on the server with a "dispose" option.
  // POST takes a file (multipart), GETs return the parsed events for re-load,
  // DELETE removes the record (audit-logged).
  createForensicImport: async (incidentId, file) => {
    const form = new FormData()
    form.append('file', file)
    const res = await fetch(`/api/incidents/${incidentId}/forensic/timeline-import/imports`, {
      method: 'POST',
      credentials: 'same-origin',
      body: form,
    })
    const text = await res.text()
    const data = text ? (() => { try { return JSON.parse(text) } catch { return text } })() : null
    if (!res.ok) {
      const err = new Error(
        (data && typeof data === 'object' && (data.detail || data.message)) ||
        (res.status === 413 ? 'File exceeds 100 MB limit.' : `Upload failed (${res.status})`)
      )
      err.status = res.status
      err.data   = data
      throw err
    }
    return data
  },
  listForensicImports: (incidentId) =>
    request('GET',    `/api/incidents/${incidentId}/forensic/timeline-import/imports`),
  getForensicImport:  (incidentId, importId) =>
    request('GET',    `/api/incidents/${incidentId}/forensic/timeline-import/imports/${importId}`),
  deleteForensicImport: (incidentId, importId) =>
    request('DELETE', `/api/incidents/${incidentId}/forensic/timeline-import/imports/${importId}`),

  // MITRE ATT&CK coverage (per-incident)
  getMitreCoverage: (incidentId) => request('GET', `/api/incidents/${incidentId}/mitre/coverage`),
  // MITRE ATT&CK global coverage matrix
  getGlobalMitreCoverage: () => request('GET', '/api/mitre/coverage'),

  // Quarantine artifacts (per-incident)
  listArtifacts:    (incidentId) => request('GET', `/api/incidents/${incidentId}/artifacts`),
  getArtifact:      (incidentId, artifactId) => request('GET', `/api/incidents/${incidentId}/artifacts/${artifactId}`),
  deleteArtifact:   (incidentId, artifactId) => request('DELETE', `/api/incidents/${incidentId}/artifacts/${artifactId}`),
  uploadArtifact:   async (incidentId, file, description) => {
    const form = new FormData()
    form.append('file', file)
    if (description) form.append('description', description)
    const res = await fetch(`/api/incidents/${incidentId}/artifacts`, {
      method: 'POST',
      credentials: 'same-origin',
      body: form,
    })
    const text = await res.text()
    const data = text ? (() => { try { return JSON.parse(text) } catch { return text } })() : null
    if (!res.ok) {
      const err = new Error(
        (data && typeof data === 'object' && (data.detail || data.message)) ||
        (res.status === 413 ? 'File exceeds 500 MB limit.' : `Upload failed (${res.status})`)
      )
      err.status = res.status
      throw err
    }
    return data
  },
  analyzeArtifact:  (incidentId, artifactId, tool, params = {}) => {
    const qs = new URLSearchParams(params).toString()
    return request('POST', `/api/incidents/${incidentId}/artifacts/${artifactId}/analyze/${tool}${qs ? '?' + qs : ''}`)
  },

  // Forensic timeline-import from an ingested collection artifact (U1.3)
  importForensicFromArtifact: (incidentId, artifactId) =>
    request('POST', `/api/incidents/${incidentId}/forensic/timeline-import/from-artifact/${artifactId}`),

  // Collection packages (U1 — signed offline collectors)
  listCollectionProfiles: (incidentId) => request('GET',  `/api/incidents/${incidentId}/collections/profiles`),
  listCollections:        (incidentId) => request('GET',  `/api/incidents/${incidentId}/collections`),
  generateCollection:     (incidentId, payload) => request('POST', `/api/incidents/${incidentId}/collections`, payload),
  deleteCollection:       (incidentId, cid) => request('DELETE', `/api/incidents/${incidentId}/collections/${cid}`),
  cleanupCollections:     () => request('POST', '/api/admin/collections/cleanup'),
  ingestCollection:       async (incidentId, cid, file) => {
    const form = new FormData()
    form.append('file', file)
    const res = await fetch(`/api/incidents/${incidentId}/collections/${cid}/ingest`, {
      method: 'POST', credentials: 'same-origin', body: form,
    })
    const text = await res.text()
    const data = text ? (() => { try { return JSON.parse(text) } catch { return text } })() : null
    if (!res.ok) {
      const err = new Error(
        (data && typeof data === 'object' && (data.detail || data.message)) ||
        (res.status === 413 ? 'Collection output exceeds the size limit.' : `Ingest failed (${res.status})`)
      )
      err.status = res.status
      throw err
    }
    return data
  },

  // LOLBins timeline correlation
  lolbinsTimelineScan: (incidentId) => request('GET', `/api/incidents/${incidentId}/timeline/lolbin-scan`),

  // IOC enrichment — batch (all IOCs) and per-IOC
  enrichAllIocs: (incidentId, payload) => request('POST', `/api/incidents/${incidentId}/iocs/enrich-all`, payload),
  enrichIoc:     (incidentId, iocId)   => request('POST', `/api/incidents/${incidentId}/iocs/${iocId}/enrich`),

  // Platform settings — API keys (admin)
  listApiKeyServices: ()               => request('GET',    '/api/settings/api-keys'),
  setApiKey:          (service, value) => request('PUT',    `/api/settings/api-keys/${service}`, { value }),
  deleteApiKey:       (service)        => request('DELETE', `/api/settings/api-keys/${service}`),

  // OSINT enrichment
  osintSources: () => request('GET', '/api/osint/sources'),
  osintEnrich:  (payload) => request('POST', '/api/osint/enrich', payload),

  // OSINT sessions (per-incident persistence)
  listOsintSessions:   (incidentId) =>
    request('GET',    `/api/incidents/${incidentId}/osint/sessions`),
  createOsintSession:  (incidentId, payload) =>
    request('POST',   `/api/incidents/${incidentId}/osint/sessions`, payload),
  updateOsintSession:  (incidentId, sessionId, payload) =>
    request('PATCH',  `/api/incidents/${incidentId}/osint/sessions/${sessionId}`, payload),
  deleteOsintSession:  (incidentId, sessionId) =>
    request('DELETE', `/api/incidents/${incidentId}/osint/sessions/${sessionId}`),

  // LOLBins / GTFOBins reference
  lolbinsStatus:    ()                   => request('GET',  '/api/lolbins/status'),
  lolbinsSync:      ()                   => request('POST', '/api/lolbins/sync'),
  lolbinsSearch:    (q = '', platform = '') => {
    const qs = new URLSearchParams()
    if (q)        qs.set('q', q)
    if (platform) qs.set('platform', platform)
    const s = qs.toString()
    return request('GET', `/api/lolbins/search${s ? '?' + s : ''}`)
  },
  lolbinsCheckText: (text)               => request('GET',  `/api/lolbins/check-text?text=${encodeURIComponent(text)}`),

  // Custody exports (Phase 2 legal handoff)
  listExports:  (incidentId, params = {}) => {
    const qs = new URLSearchParams()
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== null && v !== '') qs.set(k, v)
    }
    const s = qs.toString()
    return request('GET', `/api/incidents/${incidentId}/evidence/exports${s ? '?' + s : ''}`)
  },
  createExport: (incidentId, payload) =>
    request('POST', `/api/incidents/${incidentId}/evidence/exports`, payload),
  getExport:    (incidentId, exportId) =>
    request('GET',  `/api/incidents/${incidentId}/evidence/exports/${exportId}`),

  // LE package (P1 #4) — admin only.
  // `payload` now carries the full Wizard-C set including EIO/MLA references,
  // recipient details, sender_declaration, and enable_acknowledgment.
  prepareLePackage: (incidentId, payload) =>
    request('POST', `/api/incidents/${incidentId}/le-package`, payload),
  listLePackages: (incidentId) =>
    request('GET',  `/api/incidents/${incidentId}/le-packages`),
  getLePackage:   (incidentId, lpId) =>
    request('GET',  `/api/incidents/${incidentId}/le-packages/${lpId}`),
  // Admin-attested ack for external recipients who can't reach the URL.
  manualAckLePackage: (incidentId, lpId, payload) =>
    request('POST', `/api/incidents/${incidentId}/le-packages/${lpId}/manual-ack`, payload),

  // Public recipient-ack page — no auth, single-use token.
  getLePackageByAck: (token) =>
    request('GET',  `/api/le-package-ack/${token}`),
  acknowledgeLePackage: (token, payload) =>
    request('POST', `/api/le-package-ack/${token}`, payload),

  // PCAP analysis (per-incident)
  listPcap:   (incidentId) => request('GET',    `/api/incidents/${incidentId}/pcap`),
  getPcap:    (incidentId, resultId) => request('GET',    `/api/incidents/${incidentId}/pcap/${resultId}`),
  deletePcap: (incidentId, resultId) => request('DELETE', `/api/incidents/${incidentId}/pcap/${resultId}`),
  importPcapIocs: (incidentId, resultId, payload) =>
    request('POST', `/api/incidents/${incidentId}/pcap/${resultId}/import-iocs`, payload),
  getPcapDnsRecon: (incidentId, resultId) =>
    request('GET',  `/api/incidents/${incidentId}/pcap/${resultId}/dns-recon`),

  uploadPcap: async (incidentId, file) => {
    const form = new FormData()
    form.append('file', file)
    const res = await fetch(`/api/incidents/${incidentId}/pcap`, {
      method: 'POST',
      credentials: 'same-origin',
      body: form,
    })
    const text = await res.text()
    const data = text ? (() => { try { return JSON.parse(text) } catch { return text } })() : null
    if (!res.ok) {
      const err = new Error(
        (data && typeof data === 'object' && (data.detail || data.message)) ||
        `Upload failed (${res.status})`
      )
      err.status = res.status
      err.data = data
      throw err
    }
    return data
  },

  // Stakeholder Matrix (global notification rules)
  listStakeholderMatrix:    () =>
    request('GET',    '/api/stakeholder-matrix'),
  createStakeholderRule:    (payload) =>
    request('POST',   '/api/stakeholder-matrix', payload),
  updateStakeholderRule:    (ruleId, payload) =>
    request('PATCH',  `/api/stakeholder-matrix/${ruleId}`, payload),
  deleteStakeholderRule:    (ruleId) =>
    request('DELETE', `/api/stakeholder-matrix/${ruleId}`),

  // Post-incident
  listClosureChecklist:   (incidentId) => request('GET',   `/api/incidents/${incidentId}/post-incident/checklist`),
  createClosureItem:      (incidentId, label) =>
    request('POST',   `/api/incidents/${incidentId}/post-incident/checklist`, { label }),
  deleteClosureItem:      (incidentId, itemId) =>
    request('DELETE', `/api/incidents/${incidentId}/post-incident/checklist/${itemId}`),
  toggleClosureItem:      (incidentId, itemId, checked) =>
    request('PATCH', `/api/incidents/${incidentId}/post-incident/checklist/${itemId}`, { checked }),
  patchChecklistMeta:     (incidentId, itemId, payload) =>
    request('PATCH', `/api/incidents/${incidentId}/post-incident/checklist/${itemId}/meta`, payload),
  getLessonsLearned:      (incidentId) => request('GET',   `/api/incidents/${incidentId}/post-incident/lessons`),
  saveLessonsLearned:     (incidentId, payload) =>
    request('PATCH', `/api/incidents/${incidentId}/post-incident/lessons`, payload),
  exportLessonsLearned:   (incidentId) => `/api/incidents/${incidentId}/post-incident/lessons/export`,
  getMitreSummary:        (incidentId) => request('GET',   `/api/incidents/${incidentId}/post-incident/mitre-summary`),
  listAssignableUsers:    () => request('GET', '/api/users/assignable'),

  // YARA rule library (global)
  listYaraRules:   ()                => request('GET',    '/api/yara'),
  createYaraRule:  (payload)         => request('POST',   '/api/yara', payload),
  updateYaraRule:  (id, payload)     => request('PATCH',  `/api/yara/${id}`, payload),
  deleteYaraRule:  (id)              => request('DELETE', `/api/yara/${id}`),

  uploadYaraRule: async (file) => {
    const form = new FormData()
    form.append('file', file)
    const res = await fetch('/api/yara/upload', {
      method: 'POST', credentials: 'same-origin', body: form,
    })
    const text = await res.text()
    const data = text ? (() => { try { return JSON.parse(text) } catch { return text } })() : null
    if (!res.ok) {
      const err = new Error((data && typeof data === 'object' && (data.detail || data.message)) || `Upload failed (${res.status})`)
      err.status = res.status; err.data = data; throw err
    }
    return data
  },

  // YARA per-incident scan + matches
  yaraRunScan:       (incidentId)            => request('POST',   `/api/incidents/${incidentId}/yara/scan`),
  listYaraMatches:   (incidentId)            => request('GET',    `/api/incidents/${incidentId}/yara/matches`),
  clearYaraMatches:  (incidentId)            => request('DELETE', `/api/incidents/${incidentId}/yara/matches`),
  yaraMatchTimeline: (incidentId, matchId)   => request('POST',   `/api/incidents/${incidentId}/yara/matches/${matchId}/to-timeline`),
  yaraMatchIoc:      (incidentId, matchId)   => request('POST',   `/api/incidents/${incidentId}/yara/matches/${matchId}/to-ioc`),

  // Detection queries
  getDetections:    (incidentId) => request('GET', `/api/incidents/${incidentId}/detections`),
  detectionsDownloadUrl: (incidentId) => `/api/incidents/${incidentId}/detections/download`,

  // Reports
  getReportData: (incidentId) => request('GET', `/api/incidents/${incidentId}/reports/data`),
  saveReport:    (incidentId, payload) =>
    request('POST', `/api/incidents/${incidentId}/reports`, payload),
  listReportHistory: (incidentId) =>
    request('GET', `/api/incidents/${incidentId}/reports/history`),
  // Re-download returns a Response/blob so we handle it inline rather than via request().
  downloadSavedReportUrl: (incidentId, reportId) =>
    `/api/incidents/${incidentId}/reports/${reportId}/download`,

  // Dashboard
  getDashboardSummary:  (mine = false) => request('GET', `/api/dashboard/summary?mine=${mine}`),
  getDashboardActivity: (mine = false, limit = 50) => request('GET', `/api/dashboard/activity?mine=${mine}&limit=${limit}`),
  getDashboardLegalSummary: (mine = false) => request('GET', `/api/dashboard/legal-summary?mine=${mine}`),
  getDashboardTrend:    (days = 30, mine = false) => request('GET', `/api/dashboard/trend?days=${days}&mine=${mine}`),
  getDashboardWorkload: () => request('GET', '/api/dashboard/workload'),
  getDashboardTopTactics: (limit = 8) => request('GET', `/api/dashboard/top-tactics?limit=${limit}`),
  getDashboardTopTags:    (scope = 'incident', limit = 8) =>
    request('GET', `/api/dashboard/top-tags?scope=${scope}&limit=${limit}`),

  // Portfolio metrics
  getMetrics: (window_days = 90) => request('GET', `/api/metrics?window_days=${window_days}`),

  // Legal — regulatory deadline tracking
  legalTemplates:      (incidentId)                    => request('GET',    `/api/incidents/${incidentId}/legal/templates`),
  listDeadlines:       (incidentId)                    => request('GET',    `/api/incidents/${incidentId}/legal/deadlines`),
  initializeDeadlines: (incidentId, payload)           => request('POST',   `/api/incidents/${incidentId}/legal/deadlines/initialize`, payload),
  createDeadline:      (incidentId, payload)           => request('POST',   `/api/incidents/${incidentId}/legal/deadlines`, payload),
  updateDeadline:      (incidentId, deadlineId, payload) => request('PATCH', `/api/incidents/${incidentId}/legal/deadlines/${deadlineId}`, payload),
  deleteDeadline:      (incidentId, deadlineId)        => request('DELETE', `/api/incidents/${incidentId}/legal/deadlines/${deadlineId}`),

  // Costs + Business Impact Assessment
  getBusinessImpact:    (incidentId)              => request('GET',   `/api/incidents/${incidentId}/business-impact`),
  updateBusinessImpact: (incidentId, payload)     => request('PATCH', `/api/incidents/${incidentId}/business-impact`, payload),
  listCosts:            (incidentId)              => request('GET',   `/api/incidents/${incidentId}/costs`),
  costSummary:          (incidentId)              => request('GET',   `/api/incidents/${incidentId}/costs/summary`),
  createCost:           (incidentId, payload)     => request('POST',  `/api/incidents/${incidentId}/costs`, payload),
  updateCost:           (incidentId, costId, payload) => request('PATCH', `/api/incidents/${incidentId}/costs/${costId}`, payload),
  deleteCost:           (incidentId, costId)      => request('DELETE', `/api/incidents/${incidentId}/costs/${costId}`),

  // War Room chat (per-incident)
  listWarRoomMessages: (incidentId) => request('GET',  `/api/incidents/${incidentId}/warroom/messages`),
  sendWarRoomMessage:  (incidentId, body) => request('POST', `/api/incidents/${incidentId}/warroom/messages`, { body }),
  warRoomOnline:       (incidentId) => request('GET',  `/api/incidents/${incidentId}/warroom/online`),

  // Notifications
  listNotifications: (unreadOnly = false) =>
    request('GET', `/api/notifications${unreadOnly ? '?unread_only=true' : ''}`),
  markNotificationRead:    (id) => request('PATCH', `/api/notifications/${id}/read`),
  markAllNotificationsRead: () => request('POST',  '/api/notifications/read-all'),

  // Analytics
  getIncidentAnalytics: (incidentId) => request('GET', `/api/incidents/${incidentId}/analytics`),

  // Storage admin
  getStorageStatus: () => request('GET', '/api/admin/storage'),

  // Presence (who is viewing an incident)
  listViewers:  (incidentId) => request('GET', `/api/incidents/${incidentId}/presence/viewers`),

  // On-call schedule (org-wide rota)
  listOnCall:       (includePast = false) =>
    request('GET', `/api/on-call${includePast ? '?include_past=true' : ''}`),
  getCurrentOnCall: () => request('GET', '/api/on-call/current'),
  createOnCall:    (payload)     => request('POST',   '/api/on-call', payload),
  updateOnCall:    (id, payload) => request('PATCH',  `/api/on-call/${id}`, payload),
  deleteOnCall:    (id)          => request('DELETE', `/api/on-call/${id}`),

  // Handoffs (per-incident + global pending queue)
  listHandoffs:        (incidentId)                        => request('GET',   `/api/incidents/${incidentId}/handoffs`),
  createHandoff:       (incidentId, payload)               => request('POST',  `/api/incidents/${incidentId}/handoffs`, payload),
  acknowledgeHandoff:  (incidentId, handoffId, payload)    =>
    request('PATCH', `/api/incidents/${incidentId}/handoffs/${handoffId}/acknowledge`, payload),
  listPendingHandoffs: () => request('GET', '/api/handoffs/pending'),

  // Affected systems
  listAffectedSystems:   (incidentId)           => request('GET',    `/api/incidents/${incidentId}/affected-systems`),
  createAffectedSystem:  (incidentId, payload)  => request('POST',   `/api/incidents/${incidentId}/affected-systems`, payload),
  updateAffectedSystem:  (incidentId, sysId, payload) => request('PATCH', `/api/incidents/${incidentId}/affected-systems/${sysId}`, payload),
  deleteAffectedSystem:  (incidentId, sysId)    => request('DELETE', `/api/incidents/${incidentId}/affected-systems/${sysId}`),
  promoteAffectedSystemsToEntities: (incidentId, payload = {}) =>
    request('POST', `/api/incidents/${incidentId}/affected-systems/promote-to-entities`, payload),

  // Integrations (admin)
  getSmtpConfig:      ()        => request('GET',    '/api/integrations/smtp'),
  saveSmtpConfig:     (payload) => request('PUT',    '/api/integrations/smtp', payload),
  testEmail:          ()        => request('POST',   '/api/integrations/smtp/test'),
  getWebhookConfig:   ()        => request('GET',    '/api/integrations/webhooks'),
  saveWebhookConfig:  (payload) => request('PUT',    '/api/integrations/webhooks', payload),
  getSiemKey:         ()        => request('GET',    '/api/integrations/siem-key'),
  generateSiemKey:    ()        => request('POST',   '/api/integrations/siem-key/generate'),
  deleteSiemKey:      ()        => request('DELETE', '/api/integrations/siem-key'),
  getSyslogConfig:    ()        => request('GET',    '/api/integrations/syslog'),
  saveSyslogConfig:   (payload) => request('PUT',    '/api/integrations/syslog', payload),
  testSyslog:         ()        => request('POST',   '/api/integrations/syslog/test'),

  // Threat actors (global library)
  listThreatActors:   (q, motivation) => {
    const p = new URLSearchParams()
    if (q)          p.set('q', q)
    if (motivation) p.set('motivation', motivation)
    const s = p.toString()
    return request('GET', `/api/threat-actors${s ? '?' + s : ''}`)
  },
  getThreatActor:     (actorId)         => request('GET',    `/api/threat-actors/${actorId}`),
  createThreatActor:  (payload)         => request('POST',   '/api/threat-actors', payload),
  updateThreatActor:  (actorId, payload) => request('PATCH', `/api/threat-actors/${actorId}`, payload),
  deleteThreatActor:  (actorId)         => request('DELETE', `/api/threat-actors/${actorId}`),
  listActorAttributions: (actorId)      => request('GET',    `/api/threat-actors/${actorId}/attributions`),
  triggerActorSync:   (force = false)   => request('POST',   `/api/threat-actors/sync?force=${force}`),
  actorSyncStatus:    ()                => request('GET',    `/api/threat-actors/sync-status`),

  // Incident attributions
  listAttributions:   (incidentId)               => request('GET',    `/api/incidents/${incidentId}/attributions`),
  createAttribution:  (incidentId, payload)      => request('POST',   `/api/incidents/${incidentId}/attributions`, payload),
  updateAttribution:  (incidentId, id, payload)  => request('PATCH',  `/api/incidents/${incidentId}/attributions/${id}`, payload),
  deleteAttribution:  (incidentId, id)           => request('DELETE', `/api/incidents/${incidentId}/attributions/${id}`),
  suggestAttributions:(incidentId)               => request('GET',    `/api/incidents/${incidentId}/attributions/suggest`),

  // Global search
  globalSearch: (q) => request('GET', `/api/search?q=${encodeURIComponent(q)}`),

  // IR Roster
  listRoster:          (params = {}) => {
    const qs = new URLSearchParams()
    if (params.availability) qs.set('availability', params.availability)
    if (params.q) qs.set('q', params.q)
    const s = qs.toString()
    return request('GET', `/api/roster${s ? '?' + s : ''}`)
  },
  updateRosterProfile: (userId, payload) => request('PATCH', `/api/roster/${userId}`, payload),
  getRosterCoverage:   (incidentId)      => request('GET', `/api/incidents/${incidentId}/roster/coverage`),
}
