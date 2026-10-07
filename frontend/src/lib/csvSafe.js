// R129: CSV formula-injection guard (OWASP "CSV Injection"), same rule as backend core/csv_safe.py.
// A cell starting with = + - @ TAB or CR gets a leading ' so a spreadsheet shows it as text;
// plain numbers ("-12.5", "+3") stay as they are. Returns a string ('' for null/undefined).
const FORMULA_START = /^[=+\-@\t\r]/
const PLAIN_NUMBER = /^[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?$/

export function csvSafe(v) {
  if (v == null) return ''
  const s = String(v)
  return FORMULA_START.test(s) && !PLAIN_NUMBER.test(s) ? `'${s}` : s
}
