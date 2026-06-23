// Time formatting at the UI edge.
// Inputs are ISO 8601 strings from the API (UTC, `…Z`).
// Outputs render in the user's stored timezone with the offset visible,
// per the global timestamp rule (`~/.claude/CLAUDE.md`).

import { getStoredTz } from './timezone.js'

function pad(n) { return String(n).padStart(2, '0') }

function getOffsetString(d, tz) {
  const parts = new Intl.DateTimeFormat('en-CA', {
    timeZone: tz,
    timeZoneName: 'shortOffset',
  }).formatToParts(d)
  const tzName = parts.find(p => p.type === 'timeZoneName')?.value || 'GMT'
  // tzName is like "GMT+5:30", "GMT-8", "GMT"
  const raw = tzName.replace('GMT', '')
  if (!raw) return '+00:00'
  const sign = raw[0] === '-' ? '-' : '+'
  const [h, m = '0'] = raw.slice(1).split(':')
  return `${sign}${pad(h)}:${pad(m)}`
}

function dtParts(d, tz, includeSeconds) {
  const opts = {
    timeZone: tz,
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit',
    hourCycle: 'h23',
  }
  if (includeSeconds) opts.second = '2-digit'
  return new Intl.DateTimeFormat('en-CA', opts).formatToParts(d)
}

function get(parts, type) { return parts.find(p => p.type === type)?.value || '' }

/** "YYYY-MM-DD HH:MM:SS +ZZ:ZZ" — full timestamp with offset. */
export function formatLocal(iso) {
  if (!iso) return ''
  const d = new Date(iso)
  if (isNaN(d)) return iso
  const tz = getStoredTz()
  const p = dtParts(d, tz, true)
  return `${get(p, 'year')}-${get(p, 'month')}-${get(p, 'day')} ${get(p, 'hour')}:${get(p, 'minute')}:${get(p, 'second')} ${getOffsetString(d, tz)}`
}

/** "YYYY-MM-DD HH:MM" — compact for table rows. Offset not shown (hover for full). */
export function formatLocalShort(iso) {
  if (!iso) return ''
  const d = new Date(iso)
  if (isNaN(d)) return iso
  const tz = getStoredTz()
  const p = dtParts(d, tz, false)
  return `${get(p, 'year')}-${get(p, 'month')}-${get(p, 'day')} ${get(p, 'hour')}:${get(p, 'minute')}`
}

// ─── Manual UTC entry (input edge) ──────────────────────────────────────────
// The global rule mandates UTC + 24h + `YYYY-MM-DD HH:mm:ss` for entry. Browser
// <input type="datetime-local"> renders in locale (MM/DD/YYYY AM/PM) and can't be
// forced, so manual datetime entry uses a validated text field via these helpers.

const UTC_INPUT_RE = /^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2})(?::(\d{2}))?$/

/** ISO-8601 (`…Z`) → "YYYY-MM-DD HH:MM:SS" in **UTC** for a text input. '' if empty/invalid. */
export function formatUtcInput(iso) {
  if (!iso) return ''
  const d = new Date(iso)
  if (isNaN(d)) return ''
  return d.toISOString().slice(0, 19).replace('T', ' ')
}

/** "YYYY-MM-DD HH:MM[:SS]" interpreted as **UTC** → canonical ISO-8601 (`…Z`), or null if invalid. */
export function parseUtcInput(str) {
  if (!str) return null
  const m = UTC_INPUT_RE.exec(String(str).trim())
  if (!m) return null
  const [, y, mo, d, h, mi, s] = m
  const ms = Date.UTC(+y, +mo - 1, +d, +h, +mi, s ? +s : 0)
  const dt = new Date(ms)
  if (isNaN(dt)) return null
  // Reject silent rollover (e.g. month 13, day 32, hour 25).
  if (dt.getUTCFullYear() !== +y || dt.getUTCMonth() !== +mo - 1 || dt.getUTCDate() !== +d ||
      dt.getUTCHours() !== +h || dt.getUTCMinutes() !== +mi || dt.getUTCSeconds() !== (s ? +s : 0)) {
    return null
  }
  return dt.toISOString()
}

/** Current time as "YYYY-MM-DD HH:MM:SS" in UTC (for "now" seeds). */
export function nowUtcInput() {
  return new Date().toISOString().slice(0, 19).replace('T', ' ')
}

// ─── Zoned wall-clock entry (input edge, local Fenrir TZ) ───────────────────
// For datetime entry in the user's stored timezone (offset visible) rather than
// raw UTC. Rendering already does this; these let entry match it. Storage stays
// UTC — conversion happens here at the boundary.

/** Offset (ms) of `tz` at a given UTC instant: (wall-clock-as-if-UTC) − instant. */
function tzOffsetMs(instantMs, tz) {
  const p = dtParts(new Date(instantMs), tz, true)
  const asIfUtc = Date.UTC(
    +get(p, 'year'), +get(p, 'month') - 1, +get(p, 'day'),
    +get(p, 'hour'), +get(p, 'minute'), +get(p, 'second'),
  )
  return asIfUtc - instantMs
}

/** ISO-8601 (`…Z`) → wall-clock parts {y,mo,d,h,mi,s} in the stored TZ. null if empty/invalid. */
export function isoToZonedParts(iso) {
  if (!iso) return null
  const d = new Date(iso)
  if (isNaN(d)) return null
  const p = dtParts(d, getStoredTz(), true)
  return {
    y:  +get(p, 'year'),  mo: +get(p, 'month'), d: +get(p, 'day'),
    h:  +get(p, 'hour'),  mi: +get(p, 'minute'), s: +get(p, 'second'),
  }
}

/**
 * Wall-clock parts {y,mo,d,h,mi,s} interpreted in the stored TZ → canonical UTC ISO.
 * DST-safe: the zone offset is computed at the target instant with one correction
 * pass (handles the offset changing across a transition). Returns null if invalid.
 */
export function zonedPartsToIso({ y, mo, d, h, mi, s = 0 }) {
  if ([y, mo, d, h, mi, s].some(v => !Number.isFinite(v))) return null
  const tz = getStoredTz()
  // Provisional: treat the wall components as if they were UTC.
  const asUtc = Date.UTC(y, mo - 1, d, h, mi, s)
  if (isNaN(asUtc)) return null
  // Subtract the zone's offset to land on the real instant; re-check once in case
  // the offset differs at that corrected instant (DST boundary).
  let utc = asUtc - tzOffsetMs(asUtc, tz)
  const off2 = tzOffsetMs(utc, tz)
  const utc2 = asUtc - off2
  if (utc2 !== utc) utc = utc2
  const dt = new Date(utc)
  if (isNaN(dt)) return null
  // Reject silent rollover (e.g. month 13, day 32) by round-tripping the parts.
  const back = isoToZonedParts(dt.toISOString())
  if (!back || back.y !== y || back.mo !== mo || back.d !== d ||
      back.h !== h || back.mi !== mi || back.s !== s) {
    return null
  }
  return dt.toISOString()
}

/** Relative descriptor — "3m ago", "2h ago", "in 5h", "yesterday". For sub-day deltas. */
export function relative(iso) {
  if (!iso) return ''
  const d = new Date(iso)
  if (isNaN(d)) return ''
  const s = Math.floor((Date.now() - d.getTime()) / 1000)
  if (s < 0) {
    const f = -s
    if (f < 3600)      return `in ${Math.floor(f / 60)}m`
    if (f < 86400)     return `in ${Math.floor(f / 3600)}h`
    if (f < 86400 * 2) return 'tomorrow'
    if (f < 86400 * 7) return `in ${Math.floor(f / 86400)}d`
    return formatLocalShort(iso)
  }
  if (s < 60)        return `${s}s ago`
  if (s < 3600)      return `${Math.floor(s / 60)}m ago`
  if (s < 86400)     return `${Math.floor(s / 3600)}h ago`
  if (s < 86400 * 2) return 'yesterday'
  if (s < 86400 * 7) return `${Math.floor(s / 86400)}d ago`
  return formatLocalShort(iso)
}
