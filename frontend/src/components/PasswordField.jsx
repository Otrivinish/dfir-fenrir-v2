import { useState } from 'react'

// Input with show/hide toggle. autoComplete defaults to current-password.
export default function PasswordField({
  id, value, onChange, label, placeholder,
  autoComplete = 'current-password', required = true,
  autoFocus = false, minLength,
}) {
  const [show, setShow] = useState(false)
  return (
    <div className="field">
      <label className="field-label" htmlFor={id}>{label}</label>
      <div className="input-wrap">
        <input
          id={id}
          className="input"
          type={show ? 'text' : 'password'}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          placeholder={placeholder}
          autoComplete={autoComplete}
          required={required}
          autoFocus={autoFocus}
          minLength={minLength}
          spellCheck={false}
        />
        <button
          type="button"
          className="input-toggle"
          aria-label={show ? 'Hide password' : 'Show password'}
          aria-pressed={show}
          onClick={() => setShow(s => !s)}
          tabIndex={0}
        >
          {show ? 'HIDE' : 'SHOW'}
        </button>
      </div>
    </div>
  )
}
