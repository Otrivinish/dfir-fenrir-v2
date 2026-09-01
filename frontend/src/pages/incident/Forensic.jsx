import { NavLink, Outlet, useOutletContext } from 'react-router-dom'

// Forensic sub-section — investigation tooling. Inner-tab layout:
// Detections (default) · Attribution · LOLBins · PCAP · Sandbox · Timeline Import · Artifacts.
// IOCs moved to a top-level incident tab (between Timeline and Entities) —
// it's created from most of these sub-features but was buried here.
const TABS = [
  { to: 'detections',       label: 'Detections' },
  { to: 'attribution',      label: 'Attribution' },
  { to: 'lolbins',          label: 'LOLBins' },
  { to: 'pcap',             label: 'PCAP' },
  { to: 'email',            label: 'Email' },
  { to: 'web-browser',      label: 'Web Browser' },
  { to: 'sandbox',          label: 'Sandbox' },
  { to: 'timeline-import',  label: 'Timeline Import' },
  { to: 'defender-pdf',     label: 'Defender Import' },
  { to: 'artifacts',        label: 'Artifacts' },
  { to: 'collections',      label: 'Collections' },
  { to: 'osint',            label: 'OSINT' },
  { to: 'ransomware',       label: 'Ransomware' },
]

export default function Forensic() {
  // Pass the parent IncidentDetail's Outlet context through so inner tabs
  // (IOCs etc.) can reach `inc`, `editing`, etc. without prop drilling.
  const ctx = useOutletContext()
  return (
    <>
      <nav className="tabs-h" aria-label="Forensic inner sections">
        {TABS.map(t => (
          <NavLink
            key={t.to}
            to={t.to}
            className={({ isActive }) => `tab-h ${isActive ? 'active' : ''}`}
          >
            {t.label}
          </NavLink>
        ))}
      </nav>
      <Outlet context={ctx} />
    </>
  )
}
