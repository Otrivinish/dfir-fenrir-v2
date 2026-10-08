// Tiny fetch wrapper for the v2 API.
// - cookies always sent (same-origin)
// - JSON in / JSON out
// - 401 → null user / caller decides
// - normalises FastAPI {detail, code} into Error.message + Error.status + Error.code

// Registered by the auth layer; invoked when a request 401s mid-session so the
// app can bounce the user to the login page instead of silently failing.
let onUnauthorized = null
export function setUnauthorizedHandler(fn) { onUnauthorized = fn }
// Called by non-fetch transports (WebSockets) that detect an auth drop — e.g. a
// socket closed with code 4001 (unauthenticated) — to trigger the same redirect.
export function notifyUnauthorized() { onUnauthorized?.() }

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
    // Session expired/revoked mid-use → let the auth layer redirect to login.
    // Skip /api/auth/* so login failures and bootstrap probes (which 401
    // normally) don't trigger a redirect.
    if (res.status === 401 && !path.startsWith('/api/auth/')) {
      onUnauthorized?.()
    }
    throw err
  }
  return data
}

function safeJson(s) {
  try { return JSON.parse(s) } catch { return s }
}

// Every API error is flat {detail, code}; a 422 validation_error also has errors [{loc, msg, type}] (L4).
// The list-shaped detail is still read for a server from before L4.
function extractMessage(data, status) {
  if (data && typeof data === 'object') {
    if (typeof data.detail === 'string') return data.detail
    if (Array.isArray(data.detail) && data.detail[0]?.msg) return data.detail[0].msg
  }
  // The edge proxy's 413 has no JSON body (L4, R50).
  if (status === 413) return 'The request is too large for the server (size limit reached). Nothing was saved.'
  if (status === 429) return 'Too many attempts. Try again later.'
  if (status === 401) return 'Authentication failed.'
  if (status === 403) return 'Forbidden.'
  return `Request failed (${status})`
}

// ── G1 stage 3b — chunked, resumable upload (R80) ─────────────────────────────────────────────
// A multipart upload is spooled by the server before the route sees it. An upload session instead
// sends the file as raw 8 MiB chunks that the server hashes and encrypts as they arrive; nothing is
// stored until `complete` succeeds (the server checks the hash then).
//   onProgress(sentBytes, totalBytes, phase) while each chunk is sent and after it is accepted; phase
//     'completing' while the server checks and stores the file (no Cancel then: the result would be unknown)
//   signal: an AbortSignal — aborting cancels the session (DELETE: its staged file is deleted). A cancel
//     that lands while the server completes it throws err.code 'upload_result_unknown'.
//   a failed chunk is retried with backoff after re-reading the session (resume from next_index),
//   a 429 waits for Retry-After; a lost session (expired, or the server restarted) throws
//   err.code === 'upload_interrupted'; 503 upload_storage_error is final (the server ended the upload).
//   onLimit(openUploads | null): 409 upload_limit_reached at create — the caller's open sessions when the
//     server lists them (the 409's open_uploads, or GET …/uploads), else null. Also on err.openUploads.
//   retainOnError (G-fix FE-M2): a complete error the server keeps the session open for (identifier_exists,
//     507 insufficient_storage, a 422 input error) leaves the upload on the server. The error then has
//     err.retained = true, err.retryComplete(completeBody, { signal, onProgress }) → the complete result
//     (no re-upload) and err.discard() → DELETE. Without it, every failed session is cancelled.
//   Leaving the page (pagehide) cancels every session still open, with a keepalive DELETE (FE-M5).
// Returns the complete result {exhibit_link, evidence_id, evidence}.
const UPLOAD_RETRIES = 5

function apiError(res, data, fallback) {
  const err = new Error(extractMessage(data, res.status) || fallback)
  err.status = res.status
  err.code = data && typeof data === 'object' ? data.code : undefined
  err.data = data
  if (res.status === 401) onUnauthorized?.()
  return err
}

function interrupted() {
  const err = new Error('Upload interrupted — the server no longer has this upload (it expired after 30 minutes '
    + 'without progress, or the server restarted). Nothing was stored. Start the upload again.')
  err.code = 'upload_interrupted'
  return err
}

function cancelled() {
  const err = new Error('Upload cancelled. Nothing was stored.')
  err.code = 'upload_cancelled'
  err.name = 'AbortError'
  return err
}

// FE-L16 — cancelled or cut off while the server was completing the upload: it may have stored it.
function resultUnknown() {
  const err = new Error('Result unknown — the connection was cancelled or lost while the server was storing the '
    + 'upload, and it may have finished. Check Evidence › Exhibits (and this page’s list) before uploading again.')
  err.code = 'upload_result_unknown'
  return err
}

const sleep = (ms, signal) => new Promise((resolve, reject) => {
  const onAbort = () => { clearTimeout(t); reject(cancelled()) }
  const t = setTimeout(() => { signal?.removeEventListener('abort', onAbort); resolve() }, ms)
  signal?.addEventListener('abort', onAbort, { once: true })
})

// One chunk PUT over XHR, because fetch can't report upload progress: onSent(bytes of this chunk sent so
// far). Resolves to { res: { ok, status, headers.get }, text }; rejects like fetch would (AbortError when
// the signal aborts, TypeError on a network failure).
function putChunk(url, blob, signal, onSent) {
  return new Promise((resolve, reject) => {
    const aborted = () => Object.assign(new Error('Aborted'), { name: 'AbortError' })
    if (signal?.aborted) { reject(aborted()); return }
    const xhr = new XMLHttpRequest()
    const onAbort = () => xhr.abort()
    const done = () => signal?.removeEventListener('abort', onAbort)
    xhr.open('PUT', url)
    xhr.setRequestHeader('Content-Type', 'application/octet-stream')
    xhr.setRequestHeader('Accept', 'application/json')
    xhr.upload.onprogress = (e) => onSent(e.loaded)
    xhr.onload = () => {
      done()
      resolve({ res: { ok: xhr.status >= 200 && xhr.status < 300, status: xhr.status,
                       headers: { get: (name) => xhr.getResponseHeader(name) } },
                text: xhr.responseText })
    }
    xhr.onerror = () => { done(); reject(new TypeError('Network request failed')) }
    xhr.onabort = () => { done(); reject(aborted()) }
    signal?.addEventListener('abort', onAbort, { once: true })
    xhr.send(blob)
  })
}

async function sendJson(method, path, body, signal) {
  const init = { method, credentials: 'same-origin', signal, headers: { Accept: 'application/json' } }
  if (body !== undefined) { init.headers['Content-Type'] = 'application/json'; init.body = JSON.stringify(body) }
  const res = await fetch(path, init)
  const text = await res.text()
  return { res, data: text ? safeJson(text) : null }
}

// FE-M5 — sessions this page has open. Leaving the page (reload, tab close, navigation away) sends
// each a keepalive DELETE, so a reload doesn't hold a session (and one of the 3 slots) for 30 minutes.
const openSessions = new Set()
let pagehideBound = false
function trackSession(url) {
  if (!pagehideBound && typeof window !== 'undefined') {
    pagehideBound = true
    window.addEventListener('pagehide', () => {
      for (const u of openSessions) {
        try { fetch(u, { method: 'DELETE', credentials: 'same-origin', keepalive: true }).catch(() => {}) } catch { /* leaving */ }
      }
      openSessions.clear()
    })
  }
  openSessions.add(url)
}

// M7 / FE-M5 — the caller's open upload sessions, when the server lists them: the 409's open_uploads,
// else GET …/uploads (items or a bare list). null when neither exists.
async function openUploadsFor(incidentId, data) {
  if (data && typeof data === 'object' && Array.isArray(data.open_uploads)) return data.open_uploads
  try {
    const r = await fetch(`/api/incidents/${incidentId}/uploads`, { credentials: 'same-origin', headers: { Accept: 'application/json' } })
    if (!r.ok) return null
    const j = safeJson(await r.text())
    return Array.isArray(j) ? j : Array.isArray(j?.items) ? j.items : null
  } catch { return null }
}

// The complete errors after which the server keeps the session open (it refused the metadata, or the
// volume is below its reserve); content refusals and storage errors end it (uploads.py).
const COMPLETE_ENDS_SESSION = new Set(['upload_hash_mismatch', 'hash_mismatch', 'not_a_capture', 'not_sqlite'])
function keptOpen(status, code) {
  if (status === 507) return true
  if (status === 409) return code === 'identifier_exists' || code === 'upload_busy'
  if (status === 422) return !COMPLETE_ENDS_SESSION.has(code)
  if (status === 404) return !!code && code !== 'upload_not_found' && code !== 'incident_not_found'
  return false
}

export async function uploadInChunks(incidentId, file, {
  purpose, completeBody = {}, mimeType, onProgress, signal, onLimit, retainOnError = false,
} = {}) {
  const base = `/api/incidents/${incidentId}/uploads`
  if (signal?.aborted) throw cancelled()
  const opening = {
    purpose, filename: file.name || 'upload.bin', size: file.size,
    ...(purpose === 'evidence' && mimeType ? { mime_type: mimeType.slice(0, 128) } : {}),
  }
  const open = (body) => sendJson('POST', base, body, signal).catch(e => { throw e.name === 'AbortError' ? cancelled() : e })
  // G-fix L12: the complete body goes along as `metadata`, so the server checks its fields (enums, types)
  // before a byte is sent. A server without that field refuses it (422 extra_forbidden): open without.
  let created = await open({ ...opening, metadata: completeBody })
  const fieldErrors = created.data?.errors ?? created.data?.detail     // L4: errors[]; list detail before L4
  if (created.res.status === 422 && Array.isArray(fieldErrors)
      && fieldErrors.some(d => d?.loc?.[1] === 'metadata' && d?.type === 'extra_forbidden')) {
    created = await open(opening)
  }
  if (!created.res.ok) {
    const err = apiError(created.res, created.data, `Upload failed (${created.res.status})`)
    if (err.code === 'upload_limit_reached') {
      err.openUploads = await openUploadsFor(incidentId, created.data)
      onLimit?.(err.openUploads)
    }
    throw err
  }
  const session = created.data
  const url = `${base}/${session.upload_id}`
  trackSession(url)
  // DELETE; resolves to the HTTP status (204 = cancelled, nothing stored), 0 when it didn't get through.
  const cancel = async () => {
    openSessions.delete(url)
    try { return (await fetch(url, { method: 'DELETE', credentials: 'same-origin' })).status } catch { return 0 }
  }
  let next = session.next_index
  onProgress?.(0, file.size)
  try {
    let failures = 0
    while (next < session.chunk_count) {
      const sentBefore = next * session.chunk_size
      const blob = file.slice(sentBefore, Math.min(file.size, sentBefore + session.chunk_size))
      let res = null, data = null
      try {
        // Progress within the chunk; its completion is reported from the server's answer below, so the
        // bar never reaches 100% (the 'completing' look, no Cancel) before the last chunk is accepted.
        const sent = await putChunk(`${url}/chunks/${next}`, blob, signal,
                                    (n) => { if (n < blob.size) onProgress?.(sentBefore + n, file.size) })
        res = sent.res
        data = sent.text ? safeJson(sent.text) : null
      } catch (e) {
        if (signal?.aborted || e.name === 'AbortError') throw cancelled()
        res = null                               // network failure: retry below
      }
      if (res?.ok) {
        next = data.next_index
        failures = 0
        onProgress?.(data.received_bytes, file.size)
        continue
      }
      const code = data && typeof data === 'object' ? data.code : undefined
      if (res?.status === 404 && code === 'upload_not_found') throw interrupted()
      if (res?.status === 409 && code === 'upload_out_of_order') { next = data.next_index; continue }
      // FE-L17: the server ended the upload (its staging write failed): final, with its own detail.
      if (code === 'upload_storage_error') throw apiError(res, data, `Upload failed (${res.status})`)
      const retryable = !res || res.status >= 500 || res.status === 429 || code === 'upload_busy'
      if (!retryable) throw apiError(res, data, `Upload failed (${res.status})`)
      if (++failures > UPLOAD_RETRIES) {
        throw res ? apiError(res, data, `Upload failed (${res.status})`)
          : Object.assign(new Error('Upload failed: the connection to the server keeps failing.'), { code: 'upload_network' })
      }
      const after = Number(res?.headers.get('Retry-After'))
      await sleep(after > 0 ? after * 1000 : Math.min(16000, 1000 * 2 ** (failures - 1)), signal)
      // Resume from what the server has (a chunk whose answer was lost may have landed).
      const st = await sendJson('GET', url, undefined, signal).catch(e => {
        if (e.name === 'AbortError') throw cancelled()
        return null
      })
      if (st?.res.status === 404) throw interrupted()
      if (st?.res.ok) next = st.data.next_index
    }
  } catch (e) {
    cancel()                                     // a session that failed is never left open
    throw e
  }

  const retained = (err) => Object.assign(err, {
    retained: true,
    retryComplete: (body = completeBody, opts = {}) => complete(body, opts.signal ?? signal, opts.onProgress ?? onProgress),
    discard: () => cancel(),
  })

  // Cancelled (or the connection lost) during complete: did the server finish? (FE-L16)
  const completeLost = async (e, sig) => {
    const aborted = e.name === 'AbortError' || !!sig?.aborted
    if (!aborted && retainOnError) {
      const st = await sendJson('GET', url).catch(() => null)
      if (st?.res.ok) {
        return retained(Object.assign(new Error('The server did not answer while completing the upload. It still '
          + 'has the file: try again (nothing is re-sent).'), { code: 'upload_complete_no_answer' }))
      }
      return resultUnknown()                     // 404: the session ended (stored, or refused); no answer
    }
    const st = await cancel()
    if (st === 204) {
      return aborted ? cancelled()
        : Object.assign(new Error('The connection failed while completing the upload; it was cancelled and nothing '
          + 'was stored. Start the upload again.'), { code: 'upload_network' })
    }
    return resultUnknown()                       // 404: the session ended (stored, or refused); 409: still completing
  }

  async function complete(body, sig, progress) {
    progress?.(file.size, file.size, 'completing')
    let done
    try {
      done = await sendJson('POST', `${url}/complete`, { purpose, ...body }, sig)
    } catch (e) {
      throw await completeLost(e, sig)
    }
    if (done.res.ok) { openSessions.delete(url); return done.data }
    if (done.res.status === 404 && done.data?.code === 'upload_not_found') { openSessions.delete(url); throw interrupted() }
    const err = apiError(done.res, done.data, `Upload failed (${done.res.status})`)
    if (retainOnError && keptOpen(done.res.status, err.code)) throw retained(err)
    cancel()                                     // FE-M2: only when the caller can't complete it again
    throw err
  }

  return complete(completeBody, signal, onProgress)
}

// FE-M1 — the first file of a two-file upload is already registered (or linked) when the second fails:
// say so, and name the exhibit, so it can be parsed from "From a registered exhibit".
function mainStoredButFailed(e, done, filename, what) {
  const ident = done.evidence?.identifier || 'an exhibit'
  const stored = done.exhibit_link === 'sha256_match' ? `matched the existing exhibit ${ident}` : `was registered as ${ident}`
  const why = e.code === 'upload_cancelled' ? 'was cancelled'
    : e.code === 'upload_result_unknown' ? 'has an unknown result (check Evidence › Exhibits)'
    : `failed: ${e.message || 'unknown error'}`
  const err = new Error(`${filename} ${stored}; the ${what} upload ${why}. Nothing was parsed. Parse ${ident} under `
    + '“From a registered exhibit” (with the form history once it is registered).')
  err.code = e.code
  err.status = e.status
  err.openUploads = e.openUploads
  err.data = { ...(e.data && typeof e.data === 'object' ? e.data : {}), evidence_id: done.evidence_id,
               evidence_identifier: done.evidence?.identifier, exhibit_link: done.exhibit_link }
  return err
}

// The `complete` body of a digital collection: the multipart route's fields as JSON (empty ones left out).
function digitalCompleteBody({ name, identifier, description, tlp, collected_location, entity_id, wizard }) {
  const meta = { name, identifier }
  if (description)        meta.description = description
  if (tlp)                meta.tlp = tlp
  if (collected_location) meta.collected_location = collected_location
  if (entity_id)          meta.entity_id = entity_id
  for (const [k, v] of Object.entries(wizard || {})) {
    if (v === null || v === undefined || v === '') continue
    if (Array.isArray(v) && v.length === 0) continue
    meta[k] = v
  }
  return meta
}

// After a chunked G3 upload: the analysis runs on the registered exhibit. If it fails, the error
// still names the exhibit (as the multipart route's did), so the page can offer it under "From a
// registered exhibit". G-fix R93: the run names its upload (?upload_id=…), so its record keeps the
// upload's exhibit link (registered / sha256_match); a server that can't match it (422
// upload_link_not_found) is asked again without, and records from_evidence.
async function analyseUploaded(done, fn) {
  try {
    const qs = done.upload_id ? `?upload_id=${encodeURIComponent(done.upload_id)}` : ''
    try {
      return await fn(done.evidence_id, qs)
    } catch (e) {
      if (qs && e.code === 'upload_link_not_found') return await fn(done.evidence_id, '')
      throw e
    }
  } catch (e) {
    e.data = { ...(e.data && typeof e.data === 'object' ? e.data : {}), evidence_id: done.evidence_id,
               evidence_identifier: done.evidence?.identifier, exhibit_link: done.exhibit_link }
    throw e
  }
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

  // API tokens (R144) — own, and admin (all users)
  listApiTokens:       ()        => request('GET',    '/api/tokens'),
  createApiToken:      (payload) => request('POST',   '/api/tokens', payload),
  revokeApiToken:      (id)      => request('DELETE', `/api/tokens/${id}`),
  listAllApiTokens:    ()        => request('GET',    '/api/admin/tokens'),
  adminRevokeApiToken: (id)      => request('DELETE', `/api/admin/tokens/${id}`),

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
  getIncidentPhaseHistory: (id)   => request('GET',   `/api/incidents/${id}/phase-history`),
  createIncident:      (payload)  => request('POST',  '/api/incidents', payload),
  updateIncident:      (id, body) => request('PATCH', `/api/incidents/${id}`, body),
  getIncidentGates:    (id)       => request('GET',   `/api/incidents/${id}/gates`),
  // I5: { role: 'ic'|'dpo', statement } — the API decides who may sign and whether the gate needs it.
  signOffGate:         (id, gate, payload) => request('POST', `/api/incidents/${id}/gates/${gate}/sign-off`, payload),
  getIncidentStartChecks: (id)    => request('GET',   `/api/incidents/${id}/start-checks`),
  // My rights on this incident (E3): {is_lead, capabilities[]}; the API decides.
  getIncidentAccess:   (id)       => request('GET',   `/api/incidents/${id}/access`),
  closeIncident:       (id, reason, overrideGate = false) => request('POST', `/api/incidents/${id}/close`,
                         overrideGate ? { reason, override_gate: true } : { reason }),
  reopenIncident:      (id, reason, phase, overrideGate = false) => request('POST', `/api/incidents/${id}/reopen`,
                         overrideGate ? { reason, phase, override_gate: true } : { reason, phase }),

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
  correlateLookup:          (payload)     => request('POST', '/api/correlations/lookup', payload),

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
  batchCreateIocs: (incidentId, payload)     => request('POST',   `/api/incidents/${incidentId}/iocs/batch`, payload),
  updateIoc:   (incidentId, iocId, payload)  => request('PATCH',  `/api/incidents/${incidentId}/iocs/${iocId}`, payload),
  deleteIoc:   (incidentId, iocId)           => request('DELETE', `/api/incidents/${incidentId}/iocs/${iocId}`),
  scanIocsTi:  (incidentId)                  => request('POST',   `/api/incidents/${incidentId}/iocs/scan-ti`),
  // IOC ↔ timeline-event links (many-to-many)
  listIocTimelineLinks:   (incidentId, iocId)          => request('GET',    `/api/incidents/${incidentId}/iocs/${iocId}/timeline-links`),
  linkIocTimelineEvent:   (incidentId, iocId, eventId) => request('POST',   `/api/incidents/${incidentId}/iocs/${iocId}/timeline-links`, { event_id: eventId }),
  unlinkIocTimelineEvent: (incidentId, iocId, eventId) => request('DELETE', `/api/incidents/${incidentId}/iocs/${iocId}/timeline-links/${eventId}`),

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
  // Every page (limit 200 each) — for pickers that must offer all of an incident's entities.
  listAllEntities: async (incidentId, params = {}) => {
    const byId = new Map()
    let cursor = null
    do {
      const res = await api.listEntities(incidentId, { ...params, limit: 200, ...(cursor ? { cursor } : {}) })
      for (const e of res.items) byId.set(e.id, e)
      cursor = res.next_cursor
    } while (cursor)
    return [...byId.values()]
  },
  // Every page of any cursor-paged per-incident list (listFn = api.listIocs, api.listEvidence, …),
  // keyed by id: a row shifted onto the next page by a concurrent insert is kept once.
  // `limit` = that endpoint's maximum page size.
  // `signal` (AbortSignal): once aborted, no further page is requested and the call rejects with
  // an AbortError (a page already in flight still completes). `maxPages` (default 50, i.e. 10 000
  // rows at 200 a page) bounds a runaway list: the result then carries `truncated = true`.
  listAllPages: async (listFn, incidentId, params = {}, limit = 200, { signal, maxPages = 50 } = {}) => {
    const byId = new Map()
    let cursor = null
    let pages = 0
    do {
      signal?.throwIfAborted()
      const res = await listFn(incidentId, { ...params, limit, ...(cursor ? { cursor } : {}) })
      signal?.throwIfAborted()
      for (const it of res.items) byId.set(it.id, it)
      cursor = res.next_cursor
    } while (cursor && ++pages < maxPages)
    const all = [...byId.values()]
    if (cursor) all.truncated = true
    return all
  },
  createEntity:(incidentId, payload)             => request('POST',   `/api/incidents/${incidentId}/entities`, payload),
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
  // H4: a reason is required (JSON body, never the query string); 409 file_referenced lists what relies on it.
  deleteEntityFile:  (incidentId, entityId, fileId, reason) => request('DELETE', `/api/incidents/${incidentId}/entities/${entityId}/files/${fileId}`, { reason }),
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
        (res.status === 413 ? 'File exceeds the 50 MiB limit.' : `Upload failed (${res.status})`)
      )
      err.status = res.status
      throw err
    }
    return data
  },

  // Incident file store ("Files") — unified with entity files
  listIncidentFiles:   (incidentId)             => request('GET',    `/api/incidents/${incidentId}/files`),
  updateIncidentFile:  (incidentId, fileId, payload) => request('PATCH', `/api/incidents/${incidentId}/files/${fileId}`, payload),
  deleteIncidentFile:  (incidentId, fileId, reason) => request('DELETE', `/api/incidents/${incidentId}/files/${fileId}`, { reason }),
  registerFileExhibit: (incidentId, fileId)     => request('POST',   `/api/incidents/${incidentId}/files/${fileId}/register-exhibit`),
  incidentFileDownloadUrl: (incidentId, fileId) => `/api/incidents/${incidentId}/files/${fileId}/download`,

  uploadIncidentFile: async (incidentId, file, entityId = null) => {
    const form = new FormData()
    form.append('file', file)
    if (entityId) form.append('entity_id', entityId)
    const res = await fetch(`/api/incidents/${incidentId}/files`, {
      method: 'POST',
      credentials: 'same-origin',
      body: form,
    })
    const text = await res.text()
    const data = text ? (() => { try { return JSON.parse(text) } catch { return text } })() : null
    if (!res.ok) {
      const err = new Error(
        (data && typeof data === 'object' && (data.detail || data.message)) ||
        (res.status === 413 ? 'File exceeds the 50 MiB limit.' : `Upload failed (${res.status})`)
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

  // Collect — digital_file. G1 stage 3b: a chunked upload session (encrypted on arrival), completed
  // with the same fields the (deprecated) multipart route took, as JSON. `wizard` = the optional
  // Wizard-A acquisition metadata. opts: { onProgress, signal, onLimit, retainOnError } (see
  // uploadInChunks). With retainOnError, a refused complete (identifier_exists, 507, a 422 input
  // error) keeps the upload: err.retryComplete(api.digitalCompleteBody(fields)) finishes it without
  // re-sending the file.
  collectDigital: async (incidentId, fields, opts = {}) => {
    const done = await uploadInChunks(incidentId, fields.file, {
      purpose: 'evidence', completeBody: digitalCompleteBody(fields), mimeType: fields.file.type, ...opts })
    return done.evidence
  },
  digitalCompleteBody: (fields) => digitalCompleteBody(fields),
  // FE-M5 / M7 — cancel one of your open upload sessions (e.g. one left by a closed tab).
  cancelUpload: (incidentId, uploadId) => request('DELETE', `/api/incidents/${incidentId}/uploads/${uploadId}`),

  collectPhysical: (incidentId, payload) =>
    request('POST', `/api/incidents/${incidentId}/evidence/physical`, payload),

  transferEvidence: (incidentId, evidenceId, payload) =>
    request('POST', `/api/incidents/${incidentId}/evidence/${evidenceId}/transfer`, payload),
  // C4 — the recipient accepts {condition_on_receipt, seals_intact}; decline/cancel {reason}.
  acceptEvidenceTransfer:  (incidentId, evidenceId, payload) =>
    request('POST', `/api/incidents/${incidentId}/evidence/${evidenceId}/transfer/accept`, payload),
  declineEvidenceTransfer: (incidentId, evidenceId, payload) =>
    request('POST', `/api/incidents/${incidentId}/evidence/${evidenceId}/transfer/decline`, payload),

  examineEvidence:  (incidentId, evidenceId, payload) =>
    request('POST', `/api/incidents/${incidentId}/evidence/${evidenceId}/examine`, payload),

  verifyEvidence:   (incidentId, evidenceId) =>
    request('POST', `/api/incidents/${incidentId}/evidence/${evidenceId}/verify`),

  disposeEvidence:  (incidentId, evidenceId, payload) =>
    request('POST', `/api/incidents/${incidentId}/evidence/${evidenceId}/dispose`, payload),

  // U8.1 — Email analyzer (Forensic → Email)
  // G3 — register-first: the upload (or pasted source) becomes a draft exhibit, then it is analysed.
  // A file goes through a chunked upload session (G1 stage 3b: registered as the exhibit, encrypted
  // on arrival), then the exhibit is analysed; pasted source stays a form post. opts: { onProgress, signal }.
  analyzeEmail: async (incidentId, { raw, file, acquiredAt }, opts = {}) => {
    if (file) {
      const done = await uploadInChunks(incidentId, file, {
        purpose: 'email', completeBody: acquiredAt ? { acquired_at: acquiredAt } : {}, ...opts })
      return analyseUploaded(done, (id, qs) => request('POST', `/api/incidents/${incidentId}/email/from-evidence/${id}${qs}`))
    }
    const form = new FormData()
    if (file) form.append('file', file)
    if (raw != null && raw !== '') form.append('raw', raw)
    if (acquiredAt) form.append('acquired_at', acquiredAt)
    const res = await fetch(`/api/incidents/${incidentId}/email/analyze`, {
      method: 'POST', credentials: 'same-origin', body: form,
    })
    const text = await res.text()
    const data = text ? (() => { try { return JSON.parse(text) } catch { return text } })() : null
    if (!res.ok) {
      const err = new Error((data && typeof data === 'object' && (data.detail || data.message)) || `Analyze failed (${res.status})`)
      err.status = res.status; err.data = data; err.code = data && typeof data === 'object' ? data.code : undefined
      throw err
    }
    return data
  },
  // G3 — analyse a registered exhibit (hash re-verified server-side, no upload)
  analyzeEmailFromEvidence: (incidentId, evidenceId) =>
    request('POST', `/api/incidents/${incidentId}/email/from-evidence/${evidenceId}`),
  analyzeEmailBulk: async (incidentId, files, { acquiredAt } = {}) => {
    const form = new FormData()
    for (const f of files) form.append('files', f)
    if (acquiredAt) form.append('acquired_at', acquiredAt)
    const res = await fetch(`/api/incidents/${incidentId}/email/analyze-bulk`, {
      method: 'POST', credentials: 'same-origin', body: form,
    })
    const text = await res.text()
    const data = text ? (() => { try { return JSON.parse(text) } catch { return text } })() : null
    if (!res.ok) {
      const err = new Error((data && typeof data === 'object' && (data.detail || data.message)) || `Bulk analyze failed (${res.status})`)
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
  checkEmailDomain:    (incidentId, domain, selector, confirmOutbound = false) => {
    const qs = new URLSearchParams({ domain })
    if (selector) qs.set('selector', selector)
    if (confirmOutbound) qs.set('confirm_outbound', 'true')
    return request('GET', `/api/incidents/${incidentId}/email/domain-check?${qs.toString()}`)
  },

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

  // G3 — complete the acquisition record of an unsealed item (only the fields sent change), then seal.
  updateAcquisitionRecord: (incidentId, evidenceId, payload) =>
    request('PATCH', `/api/incidents/${incidentId}/evidence/${evidenceId}/acquisition-record`, payload),

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
  // G5 — record a lab copy made outside FENRIR with the hash(es) its tool reported:
  // {purpose, copy_sha256 | copy_sha1 | copy_md5, copy_tool?, destination_note?} → the copy (verified | mismatch)
  mintWorkingCopy:   (incidentId, evidenceId, payload) =>
    request('POST', `/api/incidents/${incidentId}/evidence/${evidenceId}/working-copy`, payload),
  // G5 — issue a working copy to download: {purpose, destination_note?} → {copy, download_url, token_expires_at}.
  // download_url is one-time and works only for you; the server records the hash of the bytes it sends.
  issueWorkingCopy:  (incidentId, evidenceId, payload) =>
    request('POST', `/api/incidents/${incidentId}/evidence/${evidenceId}/working-copies`, payload),
  // G5 — set / release a legal hold: {legal_hold: bool, reason} (release: incident lead or admin)
  setLegalHold:      (incidentId, evidenceId, payload) =>
    request('PUT',  `/api/incidents/${incidentId}/evidence/${evidenceId}/legal-hold`, payload),
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
  // I3: { incident_type } lists only the templates suggested for that type.
  listPlaybookTemplates:   (params = {})   => request('GET',    '/api/playbook-templates' +
    (params.incident_type ? `?incident_type=${encodeURIComponent(params.incident_type)}` : '')),
  getPlaybookTemplate:     (id)            => request('GET',    `/api/playbook-templates/${id}`),
  createPlaybookTemplate:  (payload)       => request('POST',   '/api/playbook-templates', payload),
  updatePlaybookTemplate:  (id, payload)   => request('PATCH',  `/api/playbook-templates/${id}`, payload),
  deletePlaybookTemplate:  (id)            => request('DELETE', `/api/playbook-templates/${id}`),
  reviewPlaybookTemplate:  (id)            => request('POST',   `/api/playbook-templates/${id}/review`),

  // Playbook tasks (per incident)
  listPlaybookTasks: (incidentId, { includeArchived = false } = {}) =>
    request('GET',    `/api/incidents/${incidentId}/playbook/tasks${includeArchived ? '?include_archived=true' : ''}`),
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

  // Legacy scratchpads (read-only since H2: one per analyst, markdown, optionally private)
  listNotes:        (incidentId)          => request('GET',    `/api/incidents/${incidentId}/notes`),
  listNoteVersions:  (incidentId, noteId)  => request('GET',    `/api/incidents/${incidentId}/notes/${noteId}/versions`),

  // Case notes (H2): shared, append-only; filters author_id / evidence_id / entity_id / ioc_id / timeline_event_id
  listCaseNotes: (incidentId, params = {}) => {
    const qs = new URLSearchParams()
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== null && v !== '') qs.set(k, v)
    }
    const s = qs.toString()
    return request('GET', `/api/incidents/${incidentId}/case-notes${s ? '?' + s : ''}`)
  },
  createCaseNote: (incidentId, payload) => request('POST', `/api/incidents/${incidentId}/case-notes`, payload),

  // Recovery tracker (I1): in-scope systems + roll-up; filters state; PATCH one system (fields / one state step)
  listRecovery: (incidentId, params = {}) => {
    const qs = new URLSearchParams()
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== null && v !== '') qs.set(k, v)
    }
    const s = qs.toString()
    return request('GET', `/api/incidents/${incidentId}/recovery${s ? '?' + s : ''}`)
  },
  updateRecovery: (incidentId, entityId, payload) => request('PATCH', `/api/incidents/${incidentId}/recovery/${entityId}`, payload),

  // Stakeholder notification tracker (I2): obligations from the matrix + roll-up + severity levels;
  // filters status / active; PATCH one obligation (record notified / not required, undo, correct)
  listStakeholderNotifications: (incidentId, params = {}) => {
    const qs = new URLSearchParams()
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== null && v !== '') qs.set(k, v)
    }
    const s = qs.toString()
    return request('GET', `/api/incidents/${incidentId}/stakeholder-notifications${s ? '?' + s : ''}`)
  },
  updateStakeholderNotification: (incidentId, notificationId, payload) =>
    request('PATCH', `/api/incidents/${incidentId}/stakeholder-notifications/${notificationId}`, payload),

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
        (res.status === 413 ? 'File exceeds the 500 MiB limit.' : `Parse failed (${res.status})`)
      )
      err.status = res.status
      err.data = data
      throw err
    }
    return data
  },

  // Forensic timeline imports — persisted on the server with a "dispose" option.
  // POST takes a file (multipart) + the source timezone (IANA) for zone-less times,
  // GETs return the parsed events for re-load, DELETE removes the record (audit-logged;
  // 409 while events promoted from it are on the timeline).
  createForensicImport: async (incidentId, file, sourceTz) => {
    const form = new FormData()
    form.append('file', file)
    if (sourceTz) form.append('source_tz', sourceTz)
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
        (res.status === 413 ? 'File exceeds the 500 MiB limit.' : `Upload failed (${res.status})`)
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
  // C5 — parse a registered exhibit (hash re-verified server-side): { source_tz, parser? }
  importForensicFromEvidence: (incidentId, evidenceId, payload) =>
    request('POST', `/api/incidents/${incidentId}/forensic/timeline-import/from-evidence/${evidenceId}`, payload),
  // C5 — the server copies the chosen events (by idx) from the stored parse: { indices, ir_phase? }
  promoteForensicImport: (incidentId, importId, payload) =>
    request('POST', `/api/incidents/${incidentId}/forensic/timeline-import/imports/${importId}/promote`, payload),

  // MITRE ATT&CK coverage (per-incident)
  getMitreCoverage: (incidentId) => request('GET', `/api/incidents/${incidentId}/mitre/coverage`),
  // MITRE ATT&CK global coverage matrix
  getGlobalMitreCoverage: () => request('GET', '/api/mitre/coverage'),

  // Quarantine artifacts (per-incident)
  listArtifacts:    (incidentId) => request('GET', `/api/incidents/${incidentId}/artifacts`),
  getArtifact:      (incidentId, artifactId) => request('GET', `/api/incidents/${incidentId}/artifacts/${artifactId}`),
  // H1: a reason (10–2000 chars) in the JSON body; 409 artifact_referenced carries err.data.references
  deleteArtifact:   (incidentId, artifactId, reason) => request('DELETE', `/api/incidents/${incidentId}/artifacts/${artifactId}`, { reason }),
  promoteArtifactHashIocs: (incidentId, artifactId) =>
    request('POST', `/api/incidents/${incidentId}/artifacts/${artifactId}/hash-iocs`),
  uploadArtifact:   async (incidentId, file, description, createHashIocs = false) => {
    const form = new FormData()
    form.append('file', file)
    if (description) form.append('description', description)
    if (createHashIocs) form.append('create_hash_iocs', 'true')
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
        (res.status === 413 ? 'File exceeds the 500 MiB limit.' : `Upload failed (${res.status})`)
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
        (res.status === 413 ? 'Collection output exceeds the 512 MiB limit.' : `Ingest failed (${res.status})`)
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
  enrichIoc:     (incidentId, iocId, confirmOutbound = false) =>
    request('POST', `/api/incidents/${incidentId}/iocs/${iocId}/enrich${confirmOutbound ? '?confirm_outbound=true' : ''}`),

  // Platform settings — API keys (admin)
  listApiKeyServices: ()               => request('GET',    '/api/settings/api-keys'),
  setApiKey:          (service, value) => request('PUT',    `/api/settings/api-keys/${service}`, { value }),
  deleteApiKey:       (service)        => request('DELETE', `/api/settings/api-keys/${service}`),
  getIncidentRefSettings:    ()       => request('GET',   '/api/settings/incident-ref'),
  updateIncidentRefSettings: (prefix) => request('PATCH', '/api/settings/incident-ref', { prefix }),

  // Browser history (per-incident)
  // G3 — register-first: the file(s) become draft exhibits, then they are parsed.
  // G1 stage 3b: each file goes through a chunked upload session (registered as an exhibit, encrypted on
  // arrival; Firefox formhistory.sqlite as the companion of places.sqlite), then the exhibit(s) are parsed.
  // opts: { onProgress(sent, total) over both files, signal }.
  uploadWebHistory: async (incidentId, { file, browser, formHistoryFile, acquiredAt }, { onProgress, signal, onLimit } = {}) => {
    const total = file.size + (formHistoryFile?.size || 0)
    const at = acquiredAt ? { acquired_at: acquiredAt } : {}
    const main = await uploadInChunks(incidentId, file, {
      purpose: 'webhistory', completeBody: { browser, ...at }, signal, onLimit,
      onProgress: (sent, _t, phase) => onProgress?.(sent, total, phase) })
    let form = null
    if (formHistoryFile) {
      try {
        form = await uploadInChunks(incidentId, formHistoryFile, {
          purpose: 'webhistory', completeBody: { browser, companion_of: main.evidence_id, ...at }, signal, onLimit,
          onProgress: (sent, _t, phase) => onProgress?.(file.size + sent, total, phase) })
      } catch (e) {
        throw mainStoredButFailed(e, main, file.name || 'places.sqlite', 'form history (formhistory.sqlite)')
      }
    }
    return analyseUploaded(main, (id, qs) => request('POST', `/api/incidents/${incidentId}/webhistory/from-evidence/${id}${qs}`,
      { browser, ...(form ? { form_history_evidence_id: form.evidence_id } : {}) }))
  },
  // G3 — parse a registered exhibit as browser history: { browser, form_history_evidence_id? }
  webHistoryFromEvidence: (incidentId, evidenceId, payload) =>
    request('POST', `/api/incidents/${incidentId}/webhistory/from-evidence/${evidenceId}`, payload),
  // G3 — server-side copy onto the Timeline: { visit_ids, download_ids, ir_phase? }
  promoteWebHistory: (incidentId, payload) =>
    request('POST', `/api/incidents/${incidentId}/webhistory/promote`, payload),
  parseDefenderPdf: async (incidentId, file) => {
    const form = new FormData()
    form.append('file', file)
    const res = await fetch(`/api/incidents/${incidentId}/forensic/defender-pdf/parse`, {
      method: 'POST', credentials: 'same-origin', body: form,
    })
    const text = await res.text()
    const data = text ? (() => { try { return JSON.parse(text) } catch { return text } })() : null
    if (!res.ok) {
      const err = new Error((data && typeof data === 'object' && (data.detail || data.message)) || `Parse failed (${res.status})`)
      err.status = res.status; err.data = data
      throw err
    }
    return data
  },
  createDefenderPdfImport: async (incidentId, file) => {
    const form = new FormData()
    form.append('file', file)
    const res = await fetch(`/api/incidents/${incidentId}/forensic/defender-pdf/imports`, {
      method: 'POST', credentials: 'same-origin', body: form,
    })
    const text = await res.text()
    const data = text ? (() => { try { return JSON.parse(text) } catch { return text } })() : null
    if (!res.ok) {
      const err = new Error((data && typeof data === 'object' && (data.detail || data.message)) ||
        (res.status === 413 ? 'File exceeds the 25 MiB limit.' : `Upload failed (${res.status})`))
      err.status = res.status; err.data = data
      throw err
    }
    return data
  },
  listDefenderPdfImports: (incidentId) =>
    request('GET',    `/api/incidents/${incidentId}/forensic/defender-pdf/imports`),
  getDefenderPdfImport:  (incidentId, importId) =>
    request('GET',    `/api/incidents/${incidentId}/forensic/defender-pdf/imports/${importId}`),
  deleteDefenderPdfImport: (incidentId, importId) =>
    request('DELETE', `/api/incidents/${incidentId}/forensic/defender-pdf/imports/${importId}`),
  // G4 — parse a registered exhibit as a Defender PDF (hash re-verified server-side, no upload)
  importDefenderPdfFromEvidence: (incidentId, evidenceId) =>
    request('POST', `/api/incidents/${incidentId}/forensic/defender-pdf/from-evidence/${evidenceId}`),
  // G4 — the server copies the chosen candidates: { items: [{ idx, destination }], ir_phase? }
  promoteDefenderPdfImport: (incidentId, importId, payload) =>
    request('POST', `/api/incidents/${incidentId}/forensic/defender-pdf/imports/${importId}/promote`, payload),
  listWebHistoryUploads:  (incidentId) => request('GET', `/api/incidents/${incidentId}/webhistory`),
  deleteWebHistoryUpload: (incidentId, uploadId) => request('DELETE', `/api/incidents/${incidentId}/webhistory/${uploadId}`),
  mintWebHistoryEvidence: (incidentId, uploadId) => request('POST', `/api/incidents/${incidentId}/webhistory/${uploadId}/mint-evidence`),
  listWebHistoryVisits:      (incidentId, params = {}) => {
    const qs = new URLSearchParams()
    for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== null && v !== '') qs.set(k, v)
    const s = qs.toString()
    return request('GET', `/api/incidents/${incidentId}/webhistory/visits${s ? '?' + s : ''}`)
  },
  listWebHistorySearchTerms: (incidentId, params = {}) => {
    const qs = new URLSearchParams()
    for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== null && v !== '') qs.set(k, v)
    const s = qs.toString()
    return request('GET', `/api/incidents/${incidentId}/webhistory/search-terms${s ? '?' + s : ''}`)
  },
  listWebHistoryDownloads: (incidentId, params = {}) => {
    const qs = new URLSearchParams()
    for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== null && v !== '') qs.set(k, v)
    const s = qs.toString()
    return request('GET', `/api/incidents/${incidentId}/webhistory/downloads${s ? '?' + s : ''}`)
  },

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

  // Custody exports (Phase 2 legal handoff) — deprecated (K1); read-only history on the Disclosure page.
  listExports:  (incidentId, params = {}) => {
    const qs = new URLSearchParams()
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== null && v !== '') qs.set(k, v)
    }
    const s = qs.toString()
    return request('GET', `/api/incidents/${incidentId}/evidence/exports${s ? '?' + s : ''}`)
  },
  // K1 (R36): Disclosure packages (internal | law_enforcement | regulator) replace Evidence › Export and the
  // LE package (their routes are deprecated). Incident lead or admin.
  createDisclosure: (incidentId, payload) =>
    request('POST', `/api/incidents/${incidentId}/disclosures`, payload),
  listDisclosures: (incidentId, params = {}) => {
    const qs = new URLSearchParams()
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== null && v !== '') qs.set(k, v)
    }
    const s = qs.toString()
    return request('GET', `/api/incidents/${incidentId}/disclosures${s ? '?' + s : ''}`)
  },
  getDisclosure: (incidentId, id) =>
    request('GET',  `/api/incidents/${incidentId}/disclosures/${id}`),
  // Lead-attested ack for external recipients who can't reach the URL (any disclosure id).
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
  // G3 — analyse a registered exhibit (hash re-verified server-side) / promote timeline candidates
  analyzePcapFromEvidence: (incidentId, evidenceId) =>
    request('POST', `/api/incidents/${incidentId}/pcap/from-evidence/${evidenceId}`),
  promotePcap: (incidentId, resultId, payload) =>
    request('POST', `/api/incidents/${incidentId}/pcap/${resultId}/promote`, payload),

  // G3 — register-first: the capture is kept as a draft exhibit, then analysed. G1 stage 3b: through a
  // chunked upload session (encrypted on arrival). opts: { acquiredAt, onProgress, signal }.
  uploadPcap: async (incidentId, file, { acquiredAt, ...opts } = {}) => {
    const done = await uploadInChunks(incidentId, file, {
      purpose: 'pcap', completeBody: acquiredAt ? { acquired_at: acquiredAt } : {}, ...opts })
    return analyseUploaded(done, (id, qs) => request('POST', `/api/incidents/${incidentId}/pcap/from-evidence/${id}${qs}`))
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
  // I5: { not_applicable, na_reason? } marks / unmarks the item N/A.
  setClosureItemNa:       (incidentId, itemId, payload) =>
    request('PATCH', `/api/incidents/${incidentId}/post-incident/checklist/${itemId}`, payload),
  patchChecklistMeta:     (incidentId, itemId, payload) =>
    request('PATCH', `/api/incidents/${incidentId}/post-incident/checklist/${itemId}/meta`, payload),
  getLessonsLearned:      (incidentId) => request('GET',   `/api/incidents/${incidentId}/post-incident/lessons`),
  saveLessonsLearned:     (incidentId, payload) =>
    request('PATCH', `/api/incidents/${incidentId}/post-incident/lessons`, payload),
  exportLessonsLearned:   (incidentId) => `/api/incidents/${incidentId}/post-incident/lessons/export`,
  getMitreSummary:        (incidentId) => request('GET',   `/api/incidents/${incidentId}/post-incident/mitre-summary`),
  // incidentId (optional): only the users who can see that incident (what its person fields accept).
  // writersOnly: analysts and admins only (J4 handoff recipients; a viewer can't act on a handoff).
  listAssignableUsers:    (incidentId, { writersOnly = false } = {}) => {
    const q = new URLSearchParams()
    if (incidentId) q.set('incident_id', incidentId)
    if (writersOnly) q.set('writers_only', 'true')
    const qs = q.toString()
    return request('GET', `/api/users/assignable${qs ? `?${qs}` : ''}`)
  },

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

  // Organisation readiness (E1) — admins + analysts; viewers get 403
  getReadiness: () => request('GET', '/api/readiness'),

  // Contacts directory (E2) — read: admins + analysts (viewers 403); write: admins only.
  // { verified: true } on update stamps the server time + you as verifier.
  listContacts:  (params = {}) => {
    const qs = new URLSearchParams()
    for (const k of ['q', 'type', 'limit', 'cursor']) if (params[k]) qs.set(k, params[k])
    const s = qs.toString()
    return request('GET', `/api/contacts${s ? '?' + s : ''}`)
  },
  createContact: (payload)     => request('POST',   '/api/contacts', payload),
  updateContact: (id, payload) => request('PATCH',  `/api/contacts/${id}`, payload),
  deleteContact: (id)          => request('DELETE', `/api/contacts/${id}`),

  // Legal — regulatory deadline tracking
  legalTemplates:      (incidentId)                    => request('GET',    `/api/incidents/${incidentId}/legal/templates`),
  listDeadlines:       (incidentId)                    => request('GET',    `/api/incidents/${incidentId}/legal/deadlines`),
  initializeDeadlines: (incidentId, payload)           => request('POST',   `/api/incidents/${incidentId}/legal/deadlines/initialize`, payload),
  createDeadline:      (incidentId, payload)           => request('POST',   `/api/incidents/${incidentId}/legal/deadlines`, payload),
  updateDeadline:      (incidentId, deadlineId, payload) => request('PATCH', `/api/incidents/${incidentId}/legal/deadlines/${deadlineId}`, payload),
  // The reason goes in the JSON body, not the query string (which lands in access logs).
  deleteDeadline:      (incidentId, deadlineId, reason) => request('DELETE', `/api/incidents/${incidentId}/legal/deadlines/${deadlineId}`, { reason }),

  // Costs + Business Impact Assessment
  getBusinessImpact:    (incidentId)              => request('GET',   `/api/incidents/${incidentId}/business-impact`),
  updateBusinessImpact: (incidentId, payload)     => request('PATCH', `/api/incidents/${incidentId}/business-impact`, payload),
  listCosts:            (incidentId)              => request('GET',   `/api/incidents/${incidentId}/costs`),
  costSummary:          (incidentId)              => request('GET',   `/api/incidents/${incidentId}/costs/summary`),
  createCost:           (incidentId, payload)     => request('POST',  `/api/incidents/${incidentId}/costs`, payload),
  updateCost:           (incidentId, costId, payload) => request('PATCH', `/api/incidents/${incidentId}/costs/${costId}`, payload),
  deleteCost:           (incidentId, costId)      => request('DELETE', `/api/incidents/${incidentId}/costs/${costId}`),

  // War Room chat (per-incident)
  // Newest page first; pass { cursor: next_cursor } for the next OLDER page (items in chat order).
  listWarRoomMessages: (incidentId, { cursor } = {}) =>
    request('GET', `/api/incidents/${incidentId}/warroom/messages${cursor ? `?cursor=${encodeURIComponent(cursor)}` : ''}`),
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
  getHandoffPrefill:   (incidentId)                        => request('GET',   `/api/incidents/${incidentId}/handoffs/prefill`),
  // J4 (R33): promote a War Room message / comment to a timeline event or a decision.
  promoteMessage:      (incidentId, payload)               => request('POST',  `/api/incidents/${incidentId}/promote`, payload),
  acknowledgeHandoff:  (incidentId, handoffId, payload)    =>
    request('PATCH', `/api/incidents/${incidentId}/handoffs/${handoffId}/acknowledge`, payload),
  listPendingHandoffs: () => request('GET', '/api/handoffs/pending'),

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
