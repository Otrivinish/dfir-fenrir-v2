import { memo, useEffect, useRef, useState } from 'react'
import { NavLink, useLocation } from 'react-router-dom'
import { api } from '../api/client.js'
import { PHASE } from '../lib/incidentVocab.js'

const PHASE_BY_VALUE = Object.fromEntries(PHASE.map(p => [p.value, p]))

// The incident's left rail. `groups` come from IncidentDetail (NAV_GROUPS):
// a group with a `phase` shows that phase's glyph and --phase-* colour on its
// label; an item with `count(snapshot)` shows a .sub-count badge (null = none).
//
// Counts come from GET /incidents/{id}/snapshot, re-read when the route changes,
// when `rev` changes (a tab's write: bumpRail in the Outlet context) and when the
// window regains focus (no polling). They are state of this component only, so a
// refresh re-renders the rail, never the page in the Outlet.
function IncidentRail({ incidentId, groups, rev }) {
  const { pathname } = useLocation()
  const [snap, setSnap] = useState(null)
  const navRef = useRef(null)

  useEffect(() => {
    let cancelled = false
    let seq = 0                       // only the newest response wins
    const load = () => {
      const n = ++seq
      api.getIncidentSnapshot(incidentId)
        .then(s => { if (!cancelled && n === seq) setSnap(s) })
        .catch(() => {})              // keep the last counts; the page reports its own errors
    }
    load()
    window.addEventListener('focus', load)
    return () => { cancelled = true; window.removeEventListener('focus', load) }
  }, [incidentId, pathname, rev])

  // Narrow screens: the rail is one scrolling row; bring the active item into view.
  useEffect(() => {
    const nav = navRef.current
    const a = nav?.querySelector('.sub-item.active')
    if (!a || nav.scrollWidth <= nav.clientWidth) return
    const n = nav.getBoundingClientRect(), r = a.getBoundingClientRect()
    if (r.left < n.left || r.right > n.right) nav.scrollLeft += r.left - n.left - (n.width - r.width) / 2
  }, [pathname])

  return (
    <nav className="sub-nav" aria-label="Incident sections" ref={navRef}>
      {groups.map((group, gi) => {
        const phase = PHASE_BY_VALUE[group.phase]
        return (
          <div
            key={group.label || `g${gi}`}
            className="sub-group"
            role={group.label ? 'group' : undefined}
            aria-label={group.label || undefined}
          >
            {group.label && (
              <div
                className="sub-group-label"
                aria-hidden="true"
                data-phase={group.phase}
                style={phase ? { color: phase.color } : undefined}
              >
                {phase && <span className="phase-glyph" aria-hidden="true">{phase.glyph}</span>}
                {group.label}
              </div>
            )}
            {group.items.map(item => {
              const badge = snap && item.count ? item.count(snap) : null
              return (
                <NavLink
                  key={item.to}
                  to={item.to}
                  className={({ isActive }) => `sub-item ${isActive ? 'active' : ''}`}
                >
                  {item.label}
                  {badge && <span className="sub-count" title={badge.title}>{badge.text}</span>}
                </NavLink>
              )
            })}
          </div>
        )
      })}
    </nav>
  )
}

export default memo(IncidentRail)
