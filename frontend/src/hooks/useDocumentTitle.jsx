import { useEffect } from 'react'
import { useLocation, matchPath } from 'react-router-dom'

const BRAND = 'FENRIR'

// Compose a tab title from a section segment. Falls back to the bare brand
// on the dashboard / unmatched routes.
export function formatTitle(segment) {
  return segment ? `${segment} · ${BRAND}` : BRAND
}

// Route pattern -> title segment. First match wins; `/*` patterns match
// sub-routes so Settings/Admin tabs share their parent title.
const ROUTES = [
  ['/setup',                  'Setup'],
  ['/login/totp',             'Verify'],
  ['/login',                  'Sign in'],
  ['/totp/enrol',             'Enrol authenticator'],
  ['/le-package-ack/:token',  'Acknowledge handoff'],
  ['/incidents',              'Incidents'],
  ['/playbooks',              'Playbooks'],
  ['/correlations',           'Correlations'],
  ['/threat-intel',           'Threat Intel'],
  ['/threat-actors',          'Threat Actors'],
  ['/mitre',                  'ATT&CK Matrix'],
  ['/on-call',                'On-Call'],
  ['/handoffs',               'Handoffs'],
  ['/roster',                 'IR Roster'],
  ['/help',                   'Help'],
  ['/settings/*',             'Settings'],
  ['/admin/*',                'Admin'],
  ['/',                       ''],          // Dashboard -> bare brand
]

// Sets document.title from the current route. Mounted once inside the router.
// Incident-detail routes are skipped here — IncidentDetail owns its own title
// so it can include the live case ref + active section.
export function TitleManager() {
  const { pathname } = useLocation()
  useEffect(() => {
    if (matchPath('/incidents/:id/*', pathname)) return
    const hit = ROUTES.find(([p]) => matchPath(p, pathname))
    document.title = formatTitle(hit ? hit[1] : '')
  }, [pathname])
  return null
}
