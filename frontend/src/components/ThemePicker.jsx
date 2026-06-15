import { useTheme } from '../hooks/useTheme.jsx'

const SHORT = {
  'mission-control': 'Mission',
  'nordic-calm':     'Nordic',
  'aurora-night':    'Aurora',
}

export default function ThemePicker({ variant = 'floating' }) {
  const { theme, themes, setTheme } = useTheme()
  return (
    <div className={`theme-picker ${variant === 'inline' ? 'inline' : ''}`} role="radiogroup" aria-label="Theme">
      {themes.map(t => (
        <button
          key={t.id}
          className={`theme-pick ${t.id === theme ? 'active' : ''}`}
          role="radio"
          aria-checked={t.id === theme}
          onClick={() => setTheme(t.id)}
          title={t.label}
          type="button"
        >
          {SHORT[t.id]}
        </button>
      ))}
    </div>
  )
}
