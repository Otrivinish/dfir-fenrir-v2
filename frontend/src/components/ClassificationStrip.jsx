import SevBadge from './SevBadge.jsx'
import TagChip from './TagChip.jsx'
import { labelOf, pillOf } from '../lib/incidentVocab.js'

// A team chip in the team's own colour (set by an admin on the team). The tint and border are
// mixed from it in CSS (.team-chip); a missing or invalid colour falls back to the --muted token.
export function TeamChip({ team }) {
  const color = typeof team.color === 'string' && CSS.supports('color', team.color) ? team.color : null
  return (
    <span className="team-chip" style={color ? { '--team': color } : undefined}>
      <span className="team-chip-dot" aria-hidden="true" />
      {team.name}
    </span>
  )
}

// The incident's classification as one read-only line that wraps when narrow: Type · Severity ·
// TLP · Triage · How detected · Reporter · Teams · Tags. Used on the Situation board and on
// Details outside edit mode (edit mode keeps the form).
export default function ClassificationStrip({ inc }) {
  const teams = inc.teams ?? []
  const tags  = inc.tags ?? []
  const none  = (text) => <span className="cls-none">{text}</span>
  return (
    <div className="cls-strip">
      <dl className="cls-strip-items">
        <div><dt>Type</dt><dd>{inc.incident_type ? labelOf('incident_type', inc.incident_type) : none('Unclassified')}</dd></div>
        <div><dt>Severity</dt><dd><SevBadge value={inc.severity} /></dd></div>
        <div><dt>TLP</dt><dd><span className={`pill ${pillOf('tlp', inc.tlp)}`}>{labelOf('tlp', inc.tlp)}</span></dd></div>
        <div><dt>Triage</dt><dd><span className={`pill ${pillOf('triage_state', inc.triage_state)}`}>{labelOf('triage_state', inc.triage_state)}</span></dd></div>
        <div><dt>How detected</dt><dd>{inc.detection_method ? labelOf('detection_method', inc.detection_method) : none('Unknown')}</dd></div>
        <div><dt>Reporter</dt><dd>{inc.reporter || none('—')}</dd></div>
        <div><dt>Teams</dt><dd>{teams.length ? teams.map(t => <TeamChip key={t.id} team={t} />) : none('Unrestricted')}</dd></div>
        <div><dt>Tags</dt><dd>{tags.length ? tags.map(t => <TagChip key={t} tag={t} />) : none('None')}</dd></div>
      </dl>
    </div>
  )
}
