// TagInput — multi-tag input with platform-wide typeahead.
//
// Value contract: array of canonical lowercase-dashed strings. Adds happen on
// Enter, comma, or clicking a suggestion; removes happen on chip ×, or
// Backspace when the input is empty. We normalise client-side so the UI shows
// what the backend will store; the backend also normalises defensively.

import { useEffect, useMemo, useRef, useState } from 'react'
import { api } from '../api/client.js'
import TagChip, { MAX_TAG_LENGTH } from './TagChip.jsx'

const MAX_TAGS_PER_ROW = 20
const _DASH_RUN  = /[\s_-]+/g
// Same forbidden set as backend/core/tags.py — keep these in sync.
const _FORBIDDEN = /[^a-z0-9\-./:]/g

export function normalizeTag(raw) {
  if (raw == null) return null
  let s = String(raw).trim().toLowerCase()
  s = s.replace(_DASH_RUN, '-').replace(_FORBIDDEN, '')
  s = s.replace(/^[-./:]+|[-./:]+$/g, '')
  if (!s) return null
  return s.slice(0, MAX_TAG_LENGTH)
}

export function normalizeTags(arr) {
  const seen = new Set(), out = []
  for (const t of (arr || [])) {
    const n = normalizeTag(t)
    if (!n || seen.has(n)) continue
    seen.add(n); out.push(n)
    if (out.length >= MAX_TAGS_PER_ROW) break
  }
  return out
}

export default function TagInput({ value, onChange, scope = 'all', placeholder = 'Add tag…', disabled = false }) {
  const [text, setText]         = useState('')
  const [suggestions, setSugg]  = useState([])
  const [open, setOpen]         = useState(false)
  const [focusIdx, setFocusIdx] = useState(-1)
  const inputRef = useRef(null)
  const wrapRef  = useRef(null)

  const tags = useMemo(() => Array.isArray(value) ? value : [], [value])

  // Debounced typeahead. The platform-wide /api/tags endpoint is access-
  // controlled so suggestions only include tags the analyst can already see.
  useEffect(() => {
    if (!open) return
    let cancelled = false
    const handle = setTimeout(() => {
      const params = new URLSearchParams({ scope, limit: '12' })
      if (text.trim()) params.set('q', text.trim().toLowerCase())
      fetch(`/api/tags?${params}`, { credentials: 'same-origin' })
        .then(r => r.ok ? r.json() : { items: [] })
        .then(d => {
          if (cancelled) return
          // Hide tags already on this row.
          const inUse = new Set(tags)
          setSugg((d.items || []).filter(s => !inUse.has(s.tag)).slice(0, 8))
        })
        .catch(() => !cancelled && setSugg([]))
    }, 150)
    return () => { cancelled = true; clearTimeout(handle) }
  }, [text, open, scope, tags])

  // Close on outside click.
  useEffect(() => {
    if (!open) return
    function onDown(e) {
      if (wrapRef.current && !wrapRef.current.contains(e.target)) setOpen(false)
    }
    document.addEventListener('mousedown', onDown)
    return () => document.removeEventListener('mousedown', onDown)
  }, [open])

  function addTag(raw) {
    const n = normalizeTag(raw)
    if (!n) return
    if (tags.includes(n)) return
    if (tags.length >= MAX_TAGS_PER_ROW) return
    onChange([...tags, n])
    setText(''); setFocusIdx(-1)
  }

  function removeTag(t) {
    onChange(tags.filter(x => x !== t))
  }

  function onKeyDown(e) {
    if (e.key === 'Enter' || e.key === ',') {
      e.preventDefault()
      if (focusIdx >= 0 && suggestions[focusIdx]) addTag(suggestions[focusIdx].tag)
      else addTag(text)
    } else if (e.key === 'Backspace' && text === '' && tags.length > 0) {
      removeTag(tags[tags.length - 1])
    } else if (e.key === 'ArrowDown') {
      e.preventDefault()
      setFocusIdx(i => Math.min(suggestions.length - 1, i + 1))
    } else if (e.key === 'ArrowUp') {
      e.preventDefault()
      setFocusIdx(i => Math.max(-1, i - 1))
    } else if (e.key === 'Escape') {
      setOpen(false); setFocusIdx(-1)
    }
  }

  const reachedCap = tags.length >= MAX_TAGS_PER_ROW

  return (
    <div ref={wrapRef} style={{ position: 'relative' }}>
      <div
        onClick={() => !disabled && inputRef.current?.focus()}
        style={{
          display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 4,
          padding: '4px 6px',
          background: disabled ? 'var(--surface-2)' : 'var(--surface)',
          border: '1px solid var(--border)',
          borderRadius: 'var(--radius-sm)',
          minHeight: 30,
          cursor: disabled ? 'not-allowed' : 'text',
        }}
      >
        {tags.map(t => (
          <TagChip
            key={t}
            tag={t}
            onRemove={disabled ? undefined : removeTag}
          />
        ))}
        {!disabled && !reachedCap && (
          <input
            ref={inputRef}
            type="text"
            value={text}
            onChange={(e) => { setText(e.target.value); setOpen(true); setFocusIdx(-1) }}
            onFocus={() => setOpen(true)}
            onKeyDown={onKeyDown}
            placeholder={tags.length === 0 ? placeholder : ''}
            style={{
              flex: '1 1 60px', minWidth: 60,
              border: 'none', outline: 'none',
              background: 'transparent',
              color: 'var(--text)', fontSize: 12,
              padding: '2px 4px',
            }}
          />
        )}
        {reachedCap && (
          <span style={{ fontSize: 10, color: 'var(--dim)' }}>max {MAX_TAGS_PER_ROW}</span>
        )}
      </div>

      {open && suggestions.length > 0 && !disabled && (
        <div style={{
          position: 'absolute', top: '100%', left: 0, right: 0,
          marginTop: 2, zIndex: 50,
          background: 'var(--surface)', border: '1px solid var(--border-strong)',
          borderRadius: 'var(--radius-sm)', boxShadow: 'var(--shadow)',
          maxHeight: 240, overflowY: 'auto',
        }}>
          {suggestions.map((s, i) => (
            <button
              key={s.tag}
              type="button"
              onMouseDown={(e) => { e.preventDefault(); addTag(s.tag) }}
              onMouseEnter={() => setFocusIdx(i)}
              style={{
                width: '100%', textAlign: 'left',
                padding: '6px 10px',
                background: i === focusIdx ? 'var(--surface-2)' : 'transparent',
                border: 'none', cursor: 'pointer',
                display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                fontSize: 12, color: 'var(--text)',
              }}
            >
              <TagChip tag={s.tag} dense />
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--dim)' }}>
                {s.count}× · {s.scopes.join(', ')}
              </span>
            </button>
          ))}
        </div>
      )}
    </div>
  )
}
