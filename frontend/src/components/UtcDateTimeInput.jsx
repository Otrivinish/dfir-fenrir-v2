import { useEffect, useState } from 'react'
import { formatUtcInput, parseUtcInput } from '../lib/datetime.js'

// Manual datetime entry in canonical UTC, 24h: "YYYY-MM-DD HH:mm:ss".
//
// Browser <input type="datetime-local"> renders in the OS/browser locale
// (e.g. MM/DD/YYYY hh:mm AM/PM) and HTML offers no way to force a fixed format,
// so manual entry uses a validated text field instead. Per the global timestamp
// rule, the value entered here is UTC.
//
// Controlled by `value` (canonical ISO-8601 `…Z` string, or '').
// `onChange` receives a canonical ISO string when the text is a valid datetime,
// or '' when the field is cleared. Invalid/partial text is held locally (the last
// valid value is kept) and is normalised/discarded on blur.
export default function UtcDateTimeInput({
  id,
  value,
  onChange,
  required = false,
  disabled = false,
  className = 'input',
  placeholder = 'YYYY-MM-DD HH:mm:ss',
  hint = true,
  ...rest
}) {
  const [text, setText] = useState(() => formatUtcInput(value))
  const [focused, setFocused] = useState(false)

  // While not editing, mirror the canonical value (also normalises on blur).
  useEffect(() => {
    if (!focused) setText(formatUtcInput(value))
  }, [value, focused])

  const invalid = text.trim() !== '' && parseUtcInput(text) === null

  function handleChange(e) {
    const t = e.target.value
    setText(t)
    if (t.trim() === '') { onChange(''); return }
    const iso = parseUtcInput(t)
    if (iso) onChange(iso)   // emit canonical only when valid; otherwise hold last valid
  }

  return (
    <>
      <input
        id={id}
        className={className}
        type="text"
        inputMode="numeric"
        autoComplete="off"
        value={text}
        placeholder={placeholder}
        disabled={disabled}
        required={required}
        aria-invalid={invalid || undefined}
        onFocus={() => setFocused(true)}
        onBlur={() => setFocused(false)}
        onChange={handleChange}
        style={{ fontFamily: 'var(--font-mono)', ...(invalid ? { borderColor: 'var(--crit)' } : null) }}
        {...rest}
      />
      {hint && (
        <div className="field-hint" style={invalid ? { color: 'var(--crit)' } : undefined}>
          {invalid ? 'Invalid — use UTC YYYY-MM-DD HH:mm:ss (24h)' : 'UTC · 24-hour · YYYY-MM-DD HH:mm:ss'}
        </div>
      )}
    </>
  )
}
