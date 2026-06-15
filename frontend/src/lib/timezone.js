// Timezone preference — persisted to localStorage.
// datetime.js reads getStoredTz() at call time, so any render after setStoredTz()
// will use the new value. Components can trigger a full re-render by reloading.

const KEY = 'fenrir.tz'

export function getStoredTz() {
  try {
    const saved = localStorage.getItem(KEY)
    if (saved) return saved
  } catch {}
  return Intl.DateTimeFormat().resolvedOptions().timeZone
}

export function setStoredTz(tz) {
  try { localStorage.setItem(KEY, tz) } catch {}
}

export function getBrowserTz() {
  return Intl.DateTimeFormat().resolvedOptions().timeZone
}

// Curated IANA timezone list grouped by region.
// Each entry: { id: IANA name, label: display string }
export const TIMEZONE_GROUPS = [
  {
    group: 'UTC',
    zones: [
      { id: 'UTC', label: 'UTC — UTC+00:00' },
    ],
  },
  {
    group: 'Africa',
    zones: [
      { id: 'Africa/Abidjan',      label: 'Abidjan (GMT/UTC+00:00)' },
      { id: 'Africa/Cairo',        label: 'Cairo (UTC+02:00)' },
      { id: 'Africa/Johannesburg', label: 'Johannesburg (UTC+02:00)' },
      { id: 'Africa/Lagos',        label: 'Lagos (UTC+01:00)' },
      { id: 'Africa/Nairobi',      label: 'Nairobi (UTC+03:00)' },
    ],
  },
  {
    group: 'Americas',
    zones: [
      { id: 'America/Anchorage',      label: 'Anchorage (UTC−09:00)' },
      { id: 'America/Bogota',         label: 'Bogotá (UTC−05:00)' },
      { id: 'America/Buenos_Aires',   label: 'Buenos Aires (UTC−03:00)' },
      { id: 'America/Chicago',        label: 'Chicago / CDT (UTC−06:00)' },
      { id: 'America/Denver',         label: 'Denver / MDT (UTC−07:00)' },
      { id: 'America/Halifax',        label: 'Halifax / ADT (UTC−04:00)' },
      { id: 'America/Los_Angeles',    label: 'Los Angeles / PDT (UTC−08:00)' },
      { id: 'America/Mexico_City',    label: 'Mexico City (UTC−06:00)' },
      { id: 'America/New_York',       label: 'New York / EDT (UTC−05:00)' },
      { id: 'America/Sao_Paulo',      label: 'São Paulo (UTC−03:00)' },
      { id: 'America/St_Johns',       label: 'St. John\'s (UTC−03:30)' },
      { id: 'America/Toronto',        label: 'Toronto / EDT (UTC−05:00)' },
      { id: 'America/Vancouver',      label: 'Vancouver / PDT (UTC−08:00)' },
    ],
  },
  {
    group: 'Asia & Middle East',
    zones: [
      { id: 'Asia/Baghdad',    label: 'Baghdad (UTC+03:00)' },
      { id: 'Asia/Bangkok',    label: 'Bangkok (UTC+07:00)' },
      { id: 'Asia/Dhaka',      label: 'Dhaka (UTC+06:00)' },
      { id: 'Asia/Dubai',      label: 'Dubai (UTC+04:00)' },
      { id: 'Asia/Hong_Kong',  label: 'Hong Kong (UTC+08:00)' },
      { id: 'Asia/Jakarta',    label: 'Jakarta (UTC+07:00)' },
      { id: 'Asia/Karachi',    label: 'Karachi (UTC+05:00)' },
      { id: 'Asia/Kolkata',    label: 'Kolkata / Mumbai (UTC+05:30)' },
      { id: 'Asia/Riyadh',     label: 'Riyadh (UTC+03:00)' },
      { id: 'Asia/Seoul',      label: 'Seoul (UTC+09:00)' },
      { id: 'Asia/Shanghai',   label: 'Shanghai (UTC+08:00)' },
      { id: 'Asia/Singapore',  label: 'Singapore (UTC+08:00)' },
      { id: 'Asia/Taipei',     label: 'Taipei (UTC+08:00)' },
      { id: 'Asia/Tashkent',   label: 'Tashkent (UTC+05:00)' },
      { id: 'Asia/Tehran',     label: 'Tehran (UTC+03:30)' },
      { id: 'Asia/Tokyo',      label: 'Tokyo (UTC+09:00)' },
    ],
  },
  {
    group: 'Australia & Pacific',
    zones: [
      { id: 'Australia/Adelaide',  label: 'Adelaide (UTC+09:30)' },
      { id: 'Australia/Brisbane',  label: 'Brisbane (UTC+10:00)' },
      { id: 'Australia/Perth',     label: 'Perth (UTC+08:00)' },
      { id: 'Australia/Sydney',    label: 'Sydney / Melbourne (UTC+10:00)' },
      { id: 'Pacific/Auckland',    label: 'Auckland (UTC+12:00)' },
      { id: 'Pacific/Fiji',        label: 'Fiji (UTC+12:00)' },
      { id: 'Pacific/Honolulu',    label: 'Honolulu / Hawaii (UTC−10:00)' },
    ],
  },
  {
    group: 'Europe',
    zones: [
      { id: 'Europe/Amsterdam',  label: 'Amsterdam (UTC+01:00)' },
      { id: 'Europe/Athens',     label: 'Athens (UTC+02:00)' },
      { id: 'Europe/Berlin',     label: 'Berlin (UTC+01:00)' },
      { id: 'Europe/Helsinki',   label: 'Helsinki (UTC+02:00)' },
      { id: 'Europe/Istanbul',   label: 'Istanbul (UTC+03:00)' },
      { id: 'Europe/Lisbon',     label: 'Lisbon (UTC+00:00)' },
      { id: 'Europe/London',     label: 'London / GMT (UTC+00:00)' },
      { id: 'Europe/Madrid',     label: 'Madrid (UTC+01:00)' },
      { id: 'Europe/Moscow',     label: 'Moscow (UTC+03:00)' },
      { id: 'Europe/Oslo',       label: 'Oslo (UTC+01:00)' },
      { id: 'Europe/Paris',      label: 'Paris (UTC+01:00)' },
      { id: 'Europe/Rome',       label: 'Rome (UTC+01:00)' },
      { id: 'Europe/Stockholm',  label: 'Stockholm (UTC+01:00)' },
      { id: 'Europe/Warsaw',     label: 'Warsaw (UTC+01:00)' },
      { id: 'Europe/Zurich',     label: 'Zurich (UTC+01:00)' },
    ],
  },
]
