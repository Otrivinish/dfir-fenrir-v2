import { NavLink, Outlet, useOutletContext } from 'react-router-dom'

// Examine (route segment `forensic`) — the analysis tooling, in three labelled groups in
// workflow order: acquire first (ISO/IEC 27037), then analyse each kind of artefact,
// then enrich and hunt. Attribution lives under ATT&CK & attribution (AttackLayout);
// the Sandbox route still exists (a stub) but has no tab until it is built.
// Labels only: the route segments never change, so links and bookmarks still work.
const GROUPS = [
  {
    label: 'Acquire & ingest',
    tabs: [
      { to: 'collections', label: 'Collector packages' },
      { to: 'artifacts',   label: 'Malware quarantine' },
    ],
  },
  {
    label: 'Analyse by artefact',
    tabs: [
      { to: 'email',           label: 'Email' },
      { to: 'pcap',            label: 'Network capture' },
      { to: 'web-browser',     label: 'Browser history' },
      { to: 'timeline-import', label: 'Logs & triage' },
      { to: 'defender-pdf',    label: 'Vendor reports' },
      { to: 'ransomware',      label: 'Ransom note' },
    ],
  },
  {
    label: 'Enrich & hunt',
    tabs: [
      { to: 'osint',      label: 'OSINT' },
      { to: 'detections', label: 'YARA & hunt queries' },
      { to: 'lolbins',    label: 'LOLBins reference' },
    ],
  },
]

const tabClass = ({ isActive }) => `tab-h ${isActive ? 'active' : ''}`

export default function Forensic() {
  // Pass the parent IncidentDetail's Outlet context through so inner tabs
  // can reach `inc`, `editing`, etc. without prop drilling.
  const ctx = useOutletContext()
  return (
    <>
      <nav className="tabs-h tabs-grouped" aria-label="Examine sections">
        {GROUPS.map(g => (
          <div key={g.label} className="tab-group" role="group" aria-label={g.label}>
            <div className="tab-group-label" aria-hidden="true">{g.label}</div>
            <div className="tab-group-items">
              {g.tabs.map(t => <NavLink key={t.to} to={t.to} className={tabClass}>{t.label}</NavLink>)}
            </div>
          </div>
        ))}
      </nav>
      <Outlet context={ctx} />
    </>
  )
}
