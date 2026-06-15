import { createContext, useCallback, useContext, useEffect, useState } from 'react'

export const THEMES = [
  { id: 'mission-control', label: 'Mission Control' },
  { id: 'nordic-calm',     label: 'Nordic Calm' },
  { id: 'aurora-night',    label: 'Aurora Night' },
]
const DEFAULT = 'mission-control'
const KEY = 'fenrir.theme'

const ThemeCtx = createContext(null)

export function ThemeProvider({ children }) {
  const [theme, setThemeState] = useState(() => {
    try {
      const saved = localStorage.getItem(KEY)
      if (saved && THEMES.some(t => t.id === saved)) return saved
    } catch {}
    return DEFAULT
  })

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme)
    try { localStorage.setItem(KEY, theme) } catch {}
  }, [theme])

  const setTheme = useCallback((id) => {
    if (THEMES.some(t => t.id === id)) setThemeState(id)
  }, [])

  return <ThemeCtx.Provider value={{ theme, setTheme, themes: THEMES }}>{children}</ThemeCtx.Provider>
}

export function useTheme() {
  const ctx = useContext(ThemeCtx)
  if (!ctx) throw new Error('useTheme must be used inside <ThemeProvider>')
  return ctx
}
