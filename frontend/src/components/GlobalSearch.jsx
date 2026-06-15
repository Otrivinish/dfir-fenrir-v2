import { useState, useEffect, useRef, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../api/client.js'
import TagChip from './TagChip.jsx'

const SEV_COLOR = { critical: 'var(--crit)', high: 'var(--high)', medium: 'var(--med)', low: 'var(--low)', baseline: 'var(--muted)' }

function highlight(text, q) {
  if (!text || !q) return text
  const idx = text.toLowerCase().indexOf(q.toLowerCase())
  if (idx === -1) return text
  return (
    <>
      {text.slice(0, idx)}
      <mark className="sr-highlight">{text.slice(idx, idx + q.length)}</mark>
      {text.slice(idx + q.length)}
    </>
  )
}

// Returns the subset of an item's tags that helped this match — used to render
// a chip badge next to the title when the hit came via tag rather than text.
function tagHits(tags, q) {
  if (!Array.isArray(tags) || !q) return []
  const needle = String(q).toLowerCase().trim()
  if (!needle) return []
  return tags.filter(t => typeof t === 'string' && t.toLowerCase().includes(needle))
}

export default function GlobalSearch() {
  const [query, setQuery]       = useState('')
  const [results, setResults]   = useState(null)
  const [loading, setLoading]   = useState(false)
  const [open, setOpen]         = useState(false)
  const inputRef                = useRef(null)
  const dropdownRef             = useRef(null)
  const timerRef                = useRef(null)
  const navigate                = useNavigate()

  // Ctrl/Cmd+K → focus
  useEffect(() => {
    const handler = (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault()
        inputRef.current?.focus()
        inputRef.current?.select()
      }
    }
    document.addEventListener('keydown', handler)
    return () => document.removeEventListener('keydown', handler)
  }, [])

  // Click outside → close
  useEffect(() => {
    const handler = (e) => {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target) &&
          inputRef.current && !inputRef.current.contains(e.target)) {
        setOpen(false)
      }
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [])

  const doSearch = useCallback(async (q) => {
    if (q.length < 2) { setResults(null); setOpen(false); return }
    setLoading(true)
    try {
      const data = await api.globalSearch(q)
      setResults(data)
      setOpen(true)
    } catch {
      setResults(null)
    } finally {
      setLoading(false)
    }
  }, [])

  const handleChange = (e) => {
    const q = e.target.value
    setQuery(q)
    clearTimeout(timerRef.current)
    if (q.length < 2) { setResults(null); setOpen(false); return }
    timerRef.current = setTimeout(() => doSearch(q), 300)
  }

  const handleKeyDown = (e) => {
    if (e.key === 'Escape') { setOpen(false); inputRef.current?.blur() }
  }

  const go = (path) => {
    setOpen(false)
    setQuery('')
    setResults(null)
    navigate(path)
  }

  const hasResults = results && (
    results.incidents.length + results.iocs.length +
    results.entities.length + results.timeline_events.length > 0
  )

  return (
    <div className="search sr-wrap">
      <input
        ref={inputRef}
        type="search"
        value={query}
        onChange={handleChange}
        onKeyDown={handleKeyDown}
        onFocus={() => { if (results) setOpen(true) }}
        placeholder=":: search incidents, IOCs, evidence… (⌘K)"
        aria-label="Global search"
        aria-expanded={open}
        aria-autocomplete="list"
        autoComplete="off"
        spellCheck={false}
      />
      {loading && <span className="sr-spinner" aria-hidden="true" />}

      {open && (
        <div className="sr-dropdown" ref={dropdownRef} role="listbox">
          {!hasResults ? (
            <div className="sr-empty">No results for "{query}"</div>
          ) : (
            <>
              {results.incidents.length > 0 && (
                <section className="sr-group">
                  <div className="sr-group-label">Incidents</div>
                  {results.incidents.map(r => (
                    <button key={r.id} className="sr-item" role="option" onClick={() => go(`/incidents/${r.id}`)}>
                      <span className="sr-item-ref" style={{ color: SEV_COLOR[r.severity] }}>{r.ref}</span>
                      <span className="sr-item-title">
                        {highlight(r.title, query)}
                        {tagHits(r.tags, query).length > 0 && (
                          <span style={{ display: 'inline-flex', gap: 3, marginLeft: 6, verticalAlign: 'middle' }}>
                            {tagHits(r.tags, query).map(t => <TagChip key={t} tag={t} dense />)}
                          </span>
                        )}
                      </span>
                      <span className="sr-item-meta">{r.status}</span>
                    </button>
                  ))}
                </section>
              )}

              {results.iocs.length > 0 && (
                <section className="sr-group">
                  <div className="sr-group-label">IOCs</div>
                  {results.iocs.map(r => (
                    <button key={r.id} className="sr-item" role="option" onClick={() => go(`/incidents/${r.incident_id}/forensic/iocs`)}>
                      <span className="sr-item-ref">{r.type}</span>
                      <span className="sr-item-title">
                        {highlight(r.value, query)}
                        {tagHits(r.tags, query).length > 0 && (
                          <span style={{ display: 'inline-flex', gap: 3, marginLeft: 6, verticalAlign: 'middle' }}>
                            {tagHits(r.tags, query).map(t => <TagChip key={t} tag={t} dense />)}
                          </span>
                        )}
                      </span>
                      <span className="sr-item-meta">{r.incident_ref}</span>
                    </button>
                  ))}
                </section>
              )}

              {results.entities.length > 0 && (
                <section className="sr-group">
                  <div className="sr-group-label">Entities</div>
                  {results.entities.map(r => (
                    <button key={r.id} className="sr-item" role="option" onClick={() => go(`/incidents/${r.incident_id}/entities`)}>
                      <span className="sr-item-ref">{r.type}</span>
                      <span className="sr-item-title">{highlight(r.name || r.value, query)}</span>
                      <span className="sr-item-meta">{r.incident_ref}</span>
                    </button>
                  ))}
                </section>
              )}

              {results.timeline_events.length > 0 && (
                <section className="sr-group">
                  <div className="sr-group-label">Timeline</div>
                  {results.timeline_events.map(r => (
                    <button key={r.id} className="sr-item" role="option" onClick={() => go(`/incidents/${r.incident_id}/timeline`)}>
                      <span className="sr-item-ref">{r.hostname || r.source || '—'}</span>
                      <span className="sr-item-title">{highlight(r.description, query)}</span>
                      <span className="sr-item-meta">{r.incident_ref}</span>
                    </button>
                  ))}
                </section>
              )}
            </>
          )}
        </div>
      )}
    </div>
  )
}
