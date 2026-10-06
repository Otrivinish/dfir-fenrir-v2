import { useEffect, useMemo, useRef, useState } from 'react'
import { PHASE } from '../lib/incidentVocab.js'

// ── Content database ────────────────────────────────────────────────────────
// Categories → articles → block-typed body. The search index is built once
// from this structure at module load.

const CATEGORIES = [
  {
    id: 'getting-started',
    icon: '⊞',
    label: 'Getting Started',
    color: '#3b82f6',
    desc: 'First steps, roles, and system overview',
    articles: [
      {
        id: 'gs-overview',
        title: 'DFIR-FENRIR v2 — Overview',
        tags: ['overview', 'architecture', 'intro', 'csf', '800-61'],
        body: [
          { type: 'p', text: 'DFIR-FENRIR is an incident response coordination platform aligned with NIST CSF 2.0, NIST SP 800-61 R3, and CISA playbooks. Every incident phase, IOC, evidence record, and post-incident artefact flows through one auditable system.' },
          { type: 'section', title: 'Core concepts', items: [
            '**Incidents** are the top-level container. Timeline events, IOCs, entities, evidence, and communications all belong to an incident.',
            '**Phases** follow 800-61 R3: Preparation → Detection & Analysis → Containment, Eradication & Recovery → Post-Incident.',
            '**Severity** is internal Low / Medium / High / Critical (CVSS-style bands). Federal handoff reports derive NCISS from this.',
            '**TLP** (Traffic Light Protocol) controls information sharing. RED = named recipients, AMBER = org-internal, GREEN = community, WHITE = public.',
            '**Roles** (Admin / Analyst / Responder / Observer) gate what each user can see and do.',
          ] },
          { type: 'section', title: 'Top-level sections', items: [
            'The sidebar groups them; you see only the sections your role can use.',
            '**Operate** — **Dashboard** (your live operational view of all incidents) · **Incidents** (the list; open one to enter the per-incident workspace) · **Shift handoffs** · **On-call**.',
            '**Investigate** — **Correlations** · **ATT&CK coverage**.',
            '**Intel** — **Threat intel** · **Threat actors**: reference databases.',
            '**Prepare** — **Readiness** (admins and analysts) · **Playbooks** (playbook templates and tasks) · **IR roster** · **Contacts** (admins and analysts), plus **Stakeholder matrix** · **Validated tools** for admins.',
            '**Report** — **Metrics**: cross-incident analytics (admins and analysts).',
            '**Admin** — **Admin** (admins only) · **Settings**: your account, plus admin sections (Users / Teams / Roles / Stakeholder Matrix / Feeds / Integrations / API Keys).',
            'At the bottom: **Help** and **Account**.',
          ] },
          { type: 'section', title: 'Inside an incident', items: [
            'Open any incident to enter the workspace. It opens on the **Situation** board. The left rail follows NIST SP 800-61 R3 and shows live counts: **Situation** · **Details** · **Command**: Team · Playbook · Shift handoffs · **Notify**: Comms & stakeholders · Legal & regulatory · **Detection & Analysis**: Evidence · Supporting documents · Examine · Timeline · Entities · IOCs · ATT&CK & attribution · Case notes · **Containment, Eradication & Recovery**: Respond · **Post-Incident Activity**: Post-Incident · **Record**: Audit log (admins and the incident lead only).',
            'For a tab-by-tab walk-through (including the 11 Examine sub-tabs, the 5 Evidence sub-tabs, and the 5 Post-Incident sub-tabs), see the **Incident Workspace** category.',
            'For the full evidence lifecycle — collection, acquisition, examination, custody, and law-enforcement handoff — see the **Evidence & Chain of Custody** category.',
          ] },
        ],
      },
      {
        id: 'gs-roles',
        title: 'User Roles & Permissions',
        tags: ['roles', 'permissions', 'admin', 'analyst', 'responder', 'observer', 'lead', 'incident commander', 'deputy'],
        body: [
          { type: 'p', text: 'Role-based access control. Most write actions require Analyst or above; admin-only sections (Users, Audit Log, Stakeholder Matrix, API Keys, Operational Roles) are hidden from non-admins even when the URL is opened directly.' },
          { type: 'table', headers: ['Role', 'Can do'], rows: [
            ['**Admin**', 'Full access. Manage users, teams, audit log, regulatory tabs, system settings.'],
            ['**Analyst**', 'Create + update incidents, timeline, IOCs, evidence. Run YARA scans. Full investigation access.'],
            ['**Responder**', 'View all incident data. Post War Room messages and comments. Cannot create incidents.'],
            ['**Observer**', 'Read-only access to incidents the operator has assigned them to.'],
          ] },
          { type: 'note', text: 'Two auth mechanisms map to the same RBAC: browser **cookies** (login) and **API tokens** (`Authorization: Bearer …`) for MCP clients, scripts, and integrations. Both resolve to the same User.' },
          { type: 'section', title: 'Incident lead (Incident Commander / Deputy)', items: [
            'An **analyst** assigned as **Incident Commander** or **Deputy Incident Commander** on an incident is its **incident lead**, on that incident only. An admin always counts as a lead.',
            "The lead can read the incident's **Audit Log** (a lead's read is itself audited), build **LE packages** (the admins get a notification), set the incident's **teams** (only an admin can make a restricted incident visible to everyone), **override** a phase gate, and remove anyone's assignment.",
            'The rights end as soon as the assignment is removed. A viewer gains nothing from an assignment, and an API token capped at viewer is never a lead.',
            'An assignment does not let anyone see an incident: the teams decide who can see it.',
          ] },
        ],
      },
      {
        id: 'gs-first-incident',
        title: 'Creating Your First Incident',
        tags: ['create', 'incident', 'new', 'start', 'detected', 'detection', 'intake'],
        body: [
          { type: 'p', text: 'Open an incident the moment something is detected, so its first-hour facts are on record from the start.' },
          { type: 'steps', items: [
            'Sidebar → **Incidents** → **+ New Incident**.',
            'Enter a title and set **Severity** (Low / Medium / High / Critical) and **TLP**.',
            'Pick the starting **Phase** — **Detection & Analysis**, or **Containment, Eradication & Recovery** if containment is already under way. An incident cannot start in Preparation or Post-Incident.',
            'Set **How detected** and **Triage state** (default **Suspected**).',
            'Check **Detected** — it is pre-filled with now. Change it to when the alert fired or the report came in. It cannot be earlier than **When did it occur?** or in the future.',
            'The incident opens on its **Situation** board ([[iw-details]]): classification, clocks, the next gate, open response actions, team gaps and the newest events on one screen.',
            'Fill the gaps it shows: **Team** to assign the Incident Commander and the other roles, **Edit details** for anything missing from the classification, then move through phases using the phase stepper at the top.',
            'Start collecting data in **Examine**, **Timeline**, **Entities** and **IOCs**.',
          ] },
          { type: 'note', text: 'Severity and TLP are editable at any time. When in doubt, start higher and revise downward.' },
          { type: 'note', text: 'Incidents raised by a SIEM webhook (Splunk, Microsoft Sentinel, Elastic) arrive with **How detected** = **SIEM Alert** and **Detected** = the alert\'s own time, never later than when FENRIR received it.' },
        ],
      },
      {
        id: 'gs-dashboard',
        title: 'Dashboard',
        tags: ['dashboard', 'overview', 'metrics', 'home'],
        body: [
          { type: 'p', text: 'Your live operational view across all incidents — open the **Dashboard** from the sidebar.' },
          { type: 'section', title: 'What it shows', items: [
            'Active incidents by phase and severity, with quick entry to each workspace.',
            'At-a-glance counts and recent activity so you can triage where to look first.',
          ] },
        ],
      },
      {
        id: 'gs-search',
        title: 'Global Search',
        tags: ['search', 'find', 'navigation', 'shortcut'],
        body: [
          { type: 'p', text: 'Jump to any incident, entity, or IOC from one box — open **Global Search** from the top bar.' },
          { type: 'section', title: 'Tips', items: [
            'Search by incident ref (`INC-2026-00001`, or `INC-0001` for incidents created before October 2026), title, hostname, username, or IOC value.',
            'Results are scoped to what your role can see.',
          ] },
        ],
      },
      {
        id: 'gs-staffing',
        title: 'Staffing — Shift Handoffs, On-Call & IR Roster',
        tags: ['on-call', 'handoff', 'roster', 'shift', 'staffing'],
        body: [
          { type: 'p', text: 'Coordinate who is responding and hand work over cleanly between shifts.' },
          { type: 'section', title: 'Where', items: [
            '**Operate → Shift handoffs** — create a shift handover; also reachable from the **Shift handoff** button in any incident header.',
            '**Operate → On-call** — the current on-call schedule and who to escalate to.',
            '**Prepare → IR roster** — the responder roster and contact list.',
          ] },
          { type: 'section', title: 'Out-of-band contact', items: [
            'How to reach a responder when email or chat may be compromised — a mobile number, Signal, and so on.',
            'Record yours in **Prepare → IR roster** → **Edit** on your card. An admin can edit anyone\'s.',
            'Admins and analysts see it on **On-call** and in the Dashboard on-call strip. Viewers don\'t.',
          ] },
          { type: 'note', text: 'It is personal data: it never goes into reports or the LE package. Readiness blocks while anyone on call in the next 14 days has none.' },
        ],
      },
      {
        id: 'gs-readiness',
        title: 'Readiness',
        tags: ['readiness', 'preparation', 'prepare', 'blocker', 'csf', 'on-call', 'backup', 'totp'],
        body: [
          { type: 'p', text: 'Readiness checks whether the organisation is prepared for the next incident. Open it from **Prepare → Readiness** (admins and analysts).' },
          { type: 'section', title: 'What it shows', items: [
            'Each check as **Pass**, **Fail** or **Unknown**, its level (**Blocker** or **Warning**), its NIST CSF 2.0 ID, and a **Fix** link to the page where it is fixed. Most fixes need an admin.',
            '**Blockers:** at least 2 active admins · TOTP enforced and every admin enrolled · Incident Commander, Communications Lead and Legal Liaison roles active · someone on call every UTC day of the next 14 · required Stakeholder matrix rules for High and Critical · a backup under 26 h old and not failing · an audit-chain anchor that verified · a Data Protection Officer role · an out-of-band contact for everyone on call in the next 14 days.',
            '**Warnings:** Ransomware and Data-breach playbooks updated within 12 months · a threat-intel API key and every enabled feed pulled within 24 h · email configured · at least one validated tool · an audit-chain anchor that is missing or over 26 h old · the six key contacts in the Contacts directory, each verified within 90 days ([[co-contacts]]).',
            '**Unknown** means Fenrir could not check it (for example, the backup directory is not mounted). It never counts as a pass.',
          ] },
          { type: 'section', title: 'Where else it appears', items: [
            'The **Dashboard** shows a banner while any blocker fails.',
            '**+ New incident** lists the failing blockers. It never stops you creating the incident.',
            'MCP: `fenrir_dashboard(view="readiness")` · API: `GET /api/readiness`.',
          ] },
          { type: 'note', text: 'A pass means the record exists, not that it works. Readiness does not check restore tests, tabletop exercises or whether a test email arrives.' },
        ],
      },
    ],
  },
  {
    id: 'incidents',
    icon: '☢',
    label: 'Incidents',
    color: '#dc2626',
    desc: 'Lifecycle, phases, severity, TLP, triage',
    articles: [
      {
        id: 'inc-phases',
        title: 'Incident Phases',
        tags: ['phases', 'lifecycle', 'detection', 'containment', 'eradication', 'recovery', 'post-incident', 'milestones', 'declare', 'gate', 'override', 'stepper', 'colour', 'color', 'symbol', 'glyph', 'legend'],
        body: [
          { type: 'p', text: 'The phase stepper at the top of every incident tracks where you are in the IR lifecycle, aligned to NIST SP 800-61 R3. Moving into Post-Incident passes **Gate 1**.' },
          { type: 'table', headers: ['Phase', 'What happens'], rows: [
            ['**Preparation**', 'Readiness before any incident: rosters, playbooks, drills. An incident can\'t be moved to it.'],
            ['**Detection & Analysis**', 'Triage, IOC collection, timeline reconstruction, threat actor identification.'],
            ['**Containment, Eradication & Recovery**', 'Isolate affected systems. Log responder actions in **Respond**. Eradicate and recover. Avoid destroying evidence.'],
            ['**Post-Incident**', 'Closure checklist, lessons learned, report. Cost tracking.'],
          ] },
          { type: 'p', text: 'Each phase has a **symbol** and a **colour** on the stepper, the **Incidents** list and the **Dashboard**. The colour follows the phase\'s NIST CSF 2.0 function and is softer than the severity badges, so the two never read alike.' },
          { type: 'phase-legend', items: ['Violet · CSF 2.0 Protect', 'Yellow · CSF 2.0 Detect', 'Red · CSF 2.0 Respond', 'Green · CSF 2.0 Recover'] },
          { type: 'section', title: 'Changing phase', items: [
            'Click a phase on the stepper; a confirmation opens. Analysts and Admins only — for Observers the stepper is static.',
            '**Preparation** can\'t be selected.',
            'Moving **back** to an earlier phase needs a reason of at least 10 characters. It goes into the audit log.',
            'Moving **into Post-Incident** — from the stepper or with **Resolve** — checks **Gate 1** first.',
          ] },
          { type: 'section', title: 'Gate 1: C/E/R → Post-Incident', items: [
            '**Contained**, **Eradicated** and **Recovered** times are declared.',
            'No containment, eradication or recovery action on **Respond** is Open or In progress. Done or Deferred both count.',
            'Every mandatory legal deadline that is due, or has a window of 72 h or less, is Completed or Waived on **Legal**. Longer ones, such as the NIS2 final report, are carried forward and listed.',
            'Maps to NIST SP 800-61 R3 / CSF 2.0 `RS.MI-01`, `RS.MI-02` (contained, eradicated) and, **partially**, `RC.RP-01`–`RC.RP-06` (recovery done, verified and declared): v1 checks the declared times and that no action is open, not that restores were verified.',
          ] },
          { type: 'steps', items: [
            'When Gate 1 is unmet, the confirmation lists each missing item with a link to where you fix it.',
            'Fix them and try again — or, as the incident lead (Incident Commander / Deputy, [[gs-roles]]) or an admin, tick **Override** and write a justification of at least 10 characters.',
            'An override goes into the audit log (`incident_gate_override`, with the missing items) and onto the **Timeline** as **Gate overridden**.',
          ] },
          { type: 'section', title: 'Response milestones', items: [
            'Changing phase sets no time. Declare each milestone in the incident header: **Declare contained** → **Declare eradicated** → **Declare recovered** (only the next one not yet set shows; Observers and closed incidents see none).',
            'Each is pre-filled with now and editable. It can\'t be in the future, nor before the incident\'s **Detected** time (or **Occurred**, when Detected is empty); Eradicated and Recovered can\'t be before Contained, nor Recovered before Eradicated.',
            'Setting a milestone the first time adds a **Containment declared** / **Eradication declared** / **Recovery declared** event to the **Timeline**, at that time.',
            'Correct or clear a milestone on **Details → Classification** in edit mode. That is audited but adds no Timeline event.',
            'Milestones drive **MTTC** and **MTTR** — see [[pi-analytics]].',
          ] },
          { type: 'note', text: 'Incidents that entered C/E/R before 2026-10-02 may carry a **Contained** time that was stamped automatically on phase entry. FENRIR can\'t tell those from times entered by hand, so none were changed — check them on **Details**.' },
          { type: 'note', text: 'Post-Incident keeps the incident open for the lessons-learned review, the checklist and reports. Closing is a separate step with its own gate — see [[inc-closing]].' },
          { type: 'note', text: 'The same checks come from the API: `GET /api/incidents/{id}/gates` returns both gates and what each is missing.' },
        ],
      },
      {
        id: 'inc-severity-tlp',
        title: 'Severity, TLP & Triage State',
        tags: ['severity', 'tlp', 'triage', 'critical', 'high', 'medium', 'low', 'false positive', 'benign positive', 'tlp:red', 'outbound'],
        body: [
          { type: 'p', text: 'Three classification fields you set when you open an incident and revise on **Details** as the investigation firms up.' },
          { type: 'section', title: 'Severity (impact)', items: [
            '**Critical** — direct business impact, active data loss / control loss.',
            '**High** — confirmed compromise on production systems.',
            '**Medium** — confirmed compromise on non-production systems.',
            '**Low** — minor or contained anomalies.',
          ] },
          { type: 'section', title: 'Triage state (analyst confidence)', items: [
            '**Suspected** — initial signal, not yet confirmed. The default for a new incident.',
            '**Confirmed** — verified malicious activity.',
            '**False Positive** — the signal was wrong; nothing malicious happened.',
            '**Benign Positive** — the activity was real but authorised or harmless (e.g. a pen test or an admin task).',
          ] },
          { type: 'section', title: 'TLP (sharing)', items: [
            '**TLP:RED** blocks every automatic outbound channel, the same as Dark Operation: Teams and Slack webhooks and the alert email (SMTP or Microsoft Graph) for new incident, phase change, severity change and closed, and the automatic DNS checks (SPF, DKIM, DMARC) of an analyzed email\'s sender domain. Each blocked send or check is listed in the incident audit log (`outbound_notification_suppressed` / `outbound_lookup_suppressed`, reason `tlp_red`) and is not sent later.',
            'On a TLP:RED incident, OSINT lookups, IOC enrichment and the email **Domain auth check** still run, but only after you confirm a warning. Each one is listed in the audit log as `outbound_manual_lookup`.',
            'The header shows **Automatic outbound suppressed (TLP:RED)**. In-app notifications and syslog audit forwarding (actions and IDs only) stay on.',
            '**AMBER+STRICT**, **AMBER**, **GREEN** and **CLEAR** change nothing about outbound sends.',
          ] },
          { type: 'note', text: 'Severity is *impact*; triage is *confidence*. They are distinct dimensions — a Suspected/Critical incident is a real thing.' },
        ],
      },
      {
        id: 'inc-closing',
        title: 'Resolving, Closing & Reopening',
        tags: ['resolve', 'close', 'closed', 'sign-off', 'reopen', 're-open', 'false positive', 'benign positive', 'lock', 'gate', 'override'],
        body: [
          { type: 'p', text: '**Resolve** and **Close** are two steps, each with a gate. Resolve moves the incident to Post-Incident and keeps it open; Close signs it off and makes it read-only.' },
          { type: 'steps', items: [
            'Click **Resolve** in the incident header. The confirmation checks **Gate 1** — see [[inc-phases]]. The incident stays open for the lessons-learned meeting, the checklist and reports.',
            'Work through what **Gate 2** asks for (below) and generate the final **Report**. The **Close** dialog shows what is still missing at any time.',
            'Click **Close**, write a sign-off statement (at least 10 characters) and confirm.',
          ] },
          { type: 'section', title: 'Gate 2: Post-Incident → Closed', items: [
            '**Resolution summary** on **Details** — what happened, root cause, recommendations.',
            '**Lessons Learned** (Post-Incident tab) set to **Final**, with **Date conducted**, **Participants**, and an **Owner** and **Due date** on every action item.',
            '**Closure Checklist** opened, with every item checked except **Incident formally closed** — Close ticks that one.',
            'No **Playbook** task Open or In progress. Done, or Skipped with a reason.',
            'Every legal deadline already due is Completed or Waived on **Legal**. Deadlines still ahead, such as the NIS2 final report, are carried forward and listed; they don\'t block.',
            'At least one cost entry, or a filled-in business impact, on **Post-Incident → Reports**.',
            'Maps to NIST SP 800-61 R3 / CSF 2.0 `ID.IM-03`, `ID.IM-04` (improvements from lessons learned) and `RC.RP-06` (incident documentation completed) and the CISA IR playbook\'s post-incident activity.',
          ] },
          { type: 'section', title: 'When Gate 2 is unmet', items: [
            'The **Close** dialog lists each missing item with a link to where you fix it.',
            'To close anyway, the incident lead (Incident Commander / Deputy) or an admin ticks **Override**. The sign-off statement is the justification.',
            'The override goes into the audit log (`incident_gate_override`, with the missing items) and onto the **Timeline** as **Gate overridden**.',
          ] },
          { type: 'section', title: 'What Close does', items: [
            'Records you as the closer, with the close time.',
            'Ticks **Incident formally closed** on the Closure Checklist, if the checklist has been opened.',
            'Writes your statement to the audit log and as an **Incident closed** event on the **Timeline**.',
            'Makes the incident read-only, except **Lessons Learned → Action items**, which stay editable to track follow-up work, and the costs and business impact on **Post-Incident → Reports**.',
          ] },
          { type: 'section', title: 'Re-opening', items: [
            'Click **Re-open**, choose the phase to return to (Detection & Analysis, C/E/R or Post-Incident) and give a reason.',
            'The closer and close time are cleared and **Incident formally closed** is unticked.',
            'The reason goes to the audit log and as an **Incident re-opened** event on the **Timeline**.',
            'Re-opening into **Post-Incident** an incident that was closed in another phase (a false or benign positive) runs **Gate 1**. When it is unmet the dialog lists the items; the incident lead or an admin can tick **Override**, and your reason is the justification.',
          ] },
          { type: 'note', text: 'A **False Positive** or **Benign Positive** can be closed from any phase, without Gate 2 — set the **Triage state** on **Details**, then **Close** appears in the header. Outside Detection & Analysis, that triage change needs a reason of at least 10 characters; it goes to the audit log and onto the **Timeline** as **Triage changed**. The phase stays as it is; the audit log records that the gate was skipped, and a close from C/E/R or Post-Incident also adds a **Gate 2 skipped** event with your sign-off statement.' },
          { type: 'note', text: 'Costs and business impact stay editable after closure: realised costs (invoices, legal fees, fines) often arrive weeks later. Changes are audited.' },
          { type: 'note', text: 'Observers see no Resolve, Close, Re-open or Edit buttons and can\'t change the phase.' },
        ],
      },
    ],
  },
  {
    id: 'timeline',
    icon: '◷',
    label: 'Timeline & Investigation',
    color: '#10b981',
    desc: 'Events, MITRE tagging, attribution, system events, export',
    articles: [
      {
        id: 'tl-events',
        title: 'Timeline Events',
        tags: ['timeline', 'events', 'add', 'edit', 'system'],
        body: [
          { type: 'p', text: 'The timeline is the canonical narrative of an incident. Add an event for every analyst observation, decision, or system action.' },
          { type: 'section', title: 'Event fields', items: [
            '**Time** — when the event occurred (UTC stored, rendered in your TZ).',
            '**Description** — short, factual.',
            '**Type** — Malware / Network / Authentication / Process / Registry / etc.',
            '**IR phase** — optional: the 800-61 R3 phase this event belongs to, by your judgement.',
            '**MITRE tactic + technique** — ATT&CK mapping (optional but recommended for the Suggest engine).',
            '**Host / entity** — type or pick the host (or account, service…). When it matches an entity in **Entities** (case doesn\'t matter), click **Link** to link the event to it; a typed name never links on its own. **Unlink** removes the link and keeps the hostname. A host not in scope yet: tick **Add … to Entities as a host**; it is added once the event is saved. The hostname text is saved as well.',
            '**Source · Raw log** — supporting evidence.',
          ] },
          { type: 'section', title: 'Imported events', items: [
            'Events promoted from **Examine → Logs & triage** or committed from **Examine → Vendor reports** carry an **import** badge and, when parsed from an exhibit, a **⛁ exhibit** badge with its identifier.',
            '**TZ assumed** — the source gave no zone; the time was read in the source timezone chosen at import. **year inferred** — the source gave no year (BSD syslog).',
            '**offset-corrected (+120 s)** — the exhibit records the device clock as 120 s ahead, so the time shown is the recorded time minus 120 s. Hover the badge, or expand the event, for the time the device recorded.',
            'Their facts — time, host, source, type, description, raw log — are locked as imported. **Edit** opens **Annotate imported event**: set the **IR phase**, **ATT&CK** and the **Entity link**.',
            'The same lock applies to events added from **Network capture**, **Browser history** and an email\u2019s **Import hops**, and to any event recorded from an exhibit or with a time basis (for example a YARA match). The expanded event says where it came from.',
          ] },
          { type: 'note', text: 'Every edit is audit-logged with the value before and after.' },
        ],
      },
      {
        id: 'tl-mitre',
        title: 'MITRE ATT&CK Tagging',
        tags: ['mitre', 'attack', 'tactic', 'technique', 'tagging'],
        body: [
          { type: 'p', text: 'Tag timeline events with MITRE tactic + technique to enable cross-incident TTP analysis, threat actor attribution scoring, and detection-query generation.' },
          { type: 'section', title: 'Where ATT&CK tags drive value', items: [
            '**MITRE summary** (Post-Incident) — coverage map of tactics + techniques per incident.',
            '**Threat actor attribution** — the Suggest engine scores actors using TTP overlap.',
            '**Detection queries** (Examine → YARA & hunt queries) — KQL / Splunk / EQL / Cortex / CrowdStrike queries auto-generated from your tagged events.',
          ] },
        ],
      },
      {
        id: 'fo-attribution',
        title: 'Attribution',
        tags: ['attribution', 'actor', 'apt', 'suggest', 'ttp', 'mitre', 'cluster'],
        body: [
          { type: 'p', text: 'Link an incident to one or more known threat actors or unnamed clusters.' },
          { type: 'section', title: 'Actor cards', items: [
            'Actor name · MITRE ID · confidence pill (Possible / Probable / Confirmed) · score /100 · motivation · country · analyst notes.',
            'Supporting IOC count and timeline-event count for each actor.',
            'Expand a card for aliases, description, typical targets, associated techniques, TTP overlap %.',
          ] },
          { type: 'section', title: 'Suggest engine', items: [
            'Collapsible panel — scores every known actor against this incident\'s TTPs, malware, and victimology.',
            'Each suggestion explains *why* — per-signal breakdown (TTP overlap %, malware family hits, victimology matches).',
            '**+ Attribute** on a suggestion or use the manual **+ Attribute** button.',
          ] },
          { type: 'steps', items: [
            'Tag timeline events with MITRE tactics + techniques (the scorer needs signal).',
            'Open **ATT&CK & attribution → Attribution → ◈ Suggest actors**.',
            'Pick a suggestion (or attribute manually).',
            'Set confidence and notes; save.',
          ] },
          { type: 'note', text: 'Attribution records carry the Suggest score + evidence array at attribution time, so the audit trail explains *why* this actor was chosen.' },
        ],
      },
      {
        id: 'tl-export',
        title: 'Export Timeline',
        tags: ['export', 'csv', 'html', 'report', 'zig-zag'],
        body: [
          { type: 'p', text: 'Two export options in the timeline toolbar:' },
          { type: 'section', title: 'CSV', items: [
            'Flat row-per-event. Use for spreadsheet analysis, BI tools, or pipeline ingestion.',
            'The last six columns are provenance: exhibit, parser name and version, time basis, the time the device recorded and the clock offset applied. They are empty for events entered by hand.',
          ] },
          { type: 'section', title: 'HTML', items: [
            'Standalone, JS-free, dark-themed page with a vertical spine and alternating left/right event cards.',
            'Severity / TLP / count badges in the header.',
            'Raw logs collapse with native `<details>` (no JS).',
            'Print stylesheet included — light theme, raw logs auto-expanded.',
          ] },
        ],
      },
    ],
  },
  {
    id: 'iocs',
    icon: '◎',
    label: 'IOCs',
    color: '#f59e0b',
    desc: 'Indicators, status, enrichment, intel feeds',
    articles: [
      {
        id: 'ioc-types',
        title: 'IOC Types & Status',
        tags: ['ioc', 'types', 'status', 'malicious', 'clean', 'unknown'],
        body: [
          { type: 'section', title: 'Supported types', items: [
            '`ip` · `domain` · `url` · `email`',
            '`hash_md5` · `hash_sha1` · `hash_sha256`',
            '`registry_key` · `file_path` · `other`',
          ] },
          { type: 'section', title: 'Tri-state status', items: [
            '**Malicious** — analyst-confirmed bad.',
            '**Clean** — analyst-confirmed benign.',
            '**Unknown** — not yet reviewed (default for auto-extracted IOCs).',
          ] },
          { type: 'note', text: 'Click any IOC row to expand. The detail panel shows the full value, notes editor, the three **Mark** buttons, and (when fetched) enrichment results.' },
        ],
      },
      {
        id: 'ioc-enrichment',
        title: 'Enrichment Sources',
        tags: ['enrich', 'virustotal', 'vt', 'abuseipdb', 'shodan', 'greynoise', 'urlscan', 'osint'],
        body: [
          { type: 'p', text: 'Configure API keys in Settings → API Keys. Enrichment results are cached server-side so repeated queries don\'t hit external APIs.' },
          { type: 'table', headers: ['Source', 'Applies to'], rows: [
            ['VirusTotal',  'hash, ip, domain, url'],
            ['AbuseIPDB',   'ip'],
            ['Shodan',      'ip'],
            ['GreyNoise',   'ip'],
            ['URLScan',     'url, domain'],
          ] },
          { type: 'note', text: 'Click **Enrich** on a row for single-IOC enrichment, or **Run all sources** at the top to batch the whole incident.' },
        ],
      },
      {
        id: 'ioc-intel',
        title: 'Threat Intel Feeds & Correlations',
        tags: ['ti', 'feed', 'threat intel', 'correlation', 'cross-incident'],
        body: [
          { type: 'section', title: 'Threat Intel feeds', items: [
            'Admin configures feeds in Settings → Feeds (URLhaus, abuse.ch, MISP, custom).',
            'When an IOC matches a known TI feed, a **⚠ TI** badge appears next to its value.',
          ] },
          { type: 'section', title: 'Cross-incident correlations', items: [
            'The **⋈** badge in the IOC list shows how many *other* incidents share this exact (type, value).',
            'Click the badge to see the cross-incident list.',
          ] },
        ],
      },
    ],
  },
  {
    id: 'entities-evidence',
    icon: '▦',
    label: 'Entities & Artifacts',
    color: '#a78bfa',
    desc: 'Asset registry and quarantine analysis',
    articles: [
      {
        id: 'ee-entities',
        title: 'Entity Registry',
        tags: ['entity', 'asset', 'host', 'user', 'compromised', 'criticality'],
        body: [
          { type: 'p', text: 'Entities are assets relevant to the incident — hosts, users, services, network ranges. Distinct from IOCs (an IOC is "evidence of badness"; an Entity is "a thing in our environment").' },
          { type: 'section', title: 'Per-entity attributes', items: [
            '**Type** — host / user / service / network / etc.',
            '**Criticality** — Low / Medium / High / Critical.',
            '**Compromised** flag — separately tracked from criticality. Compromised entities are the incident\'s **Affected systems** (Details tab and reports).',
            '**Attributes** — arbitrary key-value JSON.',
          ] },
        ],
      },
      {
        id: 'ee-artifacts',
        title: 'Quarantine Artifacts',
        tags: ['artifact', 'quarantine', 'sandbox', 'analysis', 'hash', 'zip', 'infected', 'encrypted', 'ioc', 'delete'],
        body: [
          { type: 'p', text: 'Upload binary samples for analysis. Files are stored **encrypted at rest** (AES-256-GCM, the same format as evidence) on the quarantine volume. For analysis, FENRIR decrypts a copy in memory and sends it over TLS to the isolated analysis worker, which has no internet access.' },
          { type: 'section', title: 'On upload', items: [
            'MD5 / SHA-256 / SHA-512 computed in the same streaming pass that encrypts the file.',
            'MIME type detected via libmagic.',
            'No IOCs are created unless you tick **Also create SHA-256 + MD5 IOCs** — only for a malicious sample. A ransom note or a screenshot is context, not an indicator.',
            'Later, **Promote hashes to IOCs** on the artifact row creates them (ones the incident already has are skipped).',
          ] },
          { type: 'section', title: 'On download', items: [
            'Files download as AES-256 password-protected ZIP. Password: `infected`.',
            'Standard malware-analyst convention — prevents AV auto-execution.',
            'A stored file that fails its integrity check is not downloaded (**integrity failed**).',
          ] },
          { type: 'section', title: 'Deleting an artifact', items: [
            'You must give a reason (at least 10 characters). The audit log keeps it with the file\'s hashes.',
            'Its YARA matches are deleted with it.',
            'An artifact another record still uses can\'t be deleted: the source of an email analysis or an extracted attachment, a browser-history upload, a collection\'s output, a Defender import or a timeline import.',
          ] },
          { type: 'note', text: 'Analysis tools available: file-type · hashes · entropy · strings · IOC extract · PE · Office · PDF · EXIF · hexdump · YARA. Run from the artifact row. Artifacts uploaded before encryption at rest show **plaintext (awaiting migration)** until an admin runs the one-off migration.' },
        ],
      },
    ],
  },
  {
    id: 'evidence-coc',
    icon: '⛓',
    label: 'Evidence & Chain of Custody',
    color: '#a78bfa',
    desc: 'ISO 27037/41/42/43 collection, custody, examination, and handoff',
    articles: [
      {
        id: 'coc-overview',
        title: 'Chain of Custody — ISO Framework',
        tags: ['evidence', 'custody', 'iso', '27037', '27041', '27042', '27043', 'overview'],
        body: [
          { type: 'p', text: 'Evidence handling is built on the ISO/IEC 27037 family. Every item carries a hash-chained, tamper-evident custody log from collection through to disposal.' },
          { type: 'section', title: 'The standards in play', items: [
            '`ISO/IEC 27037` — identification, collection, acquisition, preservation.',
            '`ISO/IEC 27041` — assurance: was the tool/method validated and the examiner competent?',
            '`ISO/IEC 27042` — analysis and interpretation of the evidence.',
            '`ISO/IEC 27043` — the overall investigation process.',
            '`GDPR Art. 5.1(c)` lawful basis at collection; `RFC 3161` trusted timestamps; AES-256-GCM at rest.',
          ] },
          { type: 'section', title: 'Lifecycle', items: [
            'Collect / acquire → **Seal** (Wizard A) → **Examine** (Wizard B) → working copies → custody transfers → provenance gate → send to law enforcement → dispose.',
          ] },
          { type: 'note', text: 'Every step writes to the hash-chained audit log. The **Audit chain** verifier and the tamper monitor (see **Tamper Monitoring & Audit Anchors**) prove it was not altered.' },
        ],
      },
      {
        id: 'coc-collection',
        title: 'Collection Wizard',
        tags: ['collection', 'device type', 'collect', 'acquire', 'lawful basis', '27037'],
        body: [
          { type: 'p', text: 'Starts an evidence record the right way — device type, the collect-vs-acquire decision, and lawful basis — per `ISO/IEC 27037 §7`.' },
          { type: 'section', title: 'What you record', items: [
            '**Device type(s)** — §7 tags: computer / peripheral / storage / mobile / network / CCTV.',
            '**Collect vs acquire** plus the `§7.1.1.3` factors that drove the choice; live or mission-critical handling needs a justification.',
            '**Lawful basis** (`GDPR Art. 5.1(c)`) — IR / consent / warrant / court order / EIO / MLA / LIA.',
            'Device-specific handling: write-blocker · Faraday + IMEI + PIN · comms paths + isolation · CCTV overwrite window + time offset.',
            '**Acquisition time** (digital) or **Seizure time** (physical) — when the image was taken or the item seized, from the tool log or your notes. **Collected at** stays the time you registered the item in FENRIR.',
          ] },
          { type: 'note', text: 'Physical items require an in-situ photograph (`§6.2.1`) — see **Evidence Photos**.' },
          { type: 'note', text: 'Uploads to **Email**, **Network capture** and **Browser history** are registered as **draft exhibits** before they are analysed — see [[coc-draft-exhibits]]. Older analyses can still use **Register as exhibit**: the quarantine copy is re-hashed against the hash taken at upload, the upload time becomes the acquisition time, and the item appears in the **Custody log** as **Collected**.' },
        ],
      },
      {
        id: 'coc-acquisition',
        title: 'Acquisition & Sealing (Wizard A)',
        tags: ['acquisition', 'seal', 'hash', 'md5', 'sha-1', 'sha-256', 'e01', 'aff4', 'hash mismatch', 'acquisition time', 'write-blocker', '27037', '27041'],
        body: [
          { type: 'p', text: 'Captures the reproducibility evidence for a digital acquisition, then **Seal** locks the minimum `ISO/IEC 27037 §6.1` fields.' },
          { type: 'steps', items: [
            'Choose the file. FENRIR hashes it (MD5 + SHA-1 + **SHA-256**) as it uploads (`§5.4.4`) and encrypts each piece as it arrives — see [[coc-resumable-upload]].',
            'Set the **Acquisition time** — when the image was taken, not when you upload it.',
            'Record **tool + version** (pick from the validated-tools registry where possible) and the command / parameters.',
            'Enter the **Source hash** and **Target hash** your imaging tool reported — MD5, SHA-1 or SHA-256. The field shows which algorithm the length means.',
            'Confirm the **source ↔ target hash match** — a mismatch means re-acquire (`§5.4.4`). Hashes of different algorithms can\'t be compared; confirm those in the tool\'s report.',
            'Pick what the **Target hash covers**: **The file you upload here** (default) or **The container\'s media** (an E01 / AFF4 content hash).',
            'Record write-blocker use, **system state** (powered-off / live / mission-critical), full-image vs **logical + rationale**, screen state, and changes made.',
            'Record the device clock (`§6.6`): the **System time offset** note as you observed it, and optionally the **Clock offset in seconds** — device clock minus true time, after its timezone (`+120` = the device was 2 minutes ahead).',
            'Confirm **27041** tool/method validation and the collector competence.',
            'Click **Seal** — locks the acquisition record. A later change to a descriptive field (name, description, TLP, storage location, condition, clock offset) is logged **Amended after seal** with the value before and after. The photos already attached and the collector\u2019s role can\u2019t change; a new photo can still be added, logged **Photo added** ([[coc-photos]]).',
          ] },
          { type: 'note', text: 'The item\u2019s detail shows the whole record under **Acquisition record**: lawful basis, tool + version, source / target hashes, write-blocker, witness, device details, and who sealed it when. A viewer sees it read-only.' },
          { type: 'section', title: 'The upload check', items: [
            '**The file you upload here** — FENRIR compares the target hash with its own hash of the upload (same algorithm) once the last piece is in, **before** storing anything.',
            'A mismatch is refused: nothing is stored and the attempt is logged as **Collection REFUSED** in the **Custody log**.',
            '**The container\'s media** — E01 and AFF4 hashes cover the imaged disk inside the container, not the container file, so FENRIR records the hash as advisory and does not compare it.',
            'The item\'s **Hash check** shows the result: matches · advisory (container media) · not checked (no target hash).',
          ] },
          { type: 'section', title: 'Device clock offset', items: [
            'Imports from the exhibit (**Logs & triage**, **Vendor reports**, a matching upload or collection) subtract the **Clock offset in seconds** from the device\u2019s times and keep each recorded time.',
            'The note is kept as written and never interpreted: an offset recorded only as text is **not applied**, and the import says so.',
            'Set or correct it later in the item\u2019s **Device clock** row (**Set offset** / **Change offset**). Every change is audit-logged with the value before and after; on a sealed item it is also logged **Amended after seal**.',
            'Who: the item\u2019s collector, its current custodian, the incident lead or an **Admin**, with the item held by an internal custodian and no transfer pending — the same rule as **Complete & seal**. Others don\u2019t see **Set offset**.',
            'Imports already made keep the offset they were parsed with — they show **⚠ clock** — and nothing is rewritten. Import the exhibit again to apply the new value.',
          ] },
          { type: 'note', text: 'Items registered before this check show **does not match** when their target hash differs from the uploaded file — often a container-media hash. Review them; the stored hashes themselves are unchanged.' },
          { type: 'note', text: 'At seal an optional **RFC 3161** trusted timestamp is taken (see **Trusted Timestamping**). Evidence is encrypted **AES-256-GCM at rest**, with the key-encrypting key held separately from the data.' },
        ],
      },
      {
        id: 'coc-resumable-upload',
        title: 'Resumable Upload',
        tags: ['upload', 'resumable', 'chunked', 'progress', 'cancel', 'interrupted', 'encrypted', 'plaintext', 'r80', 'hash check'],
        body: [
          { type: 'p', text: 'Evidence files go up in 8 MiB pieces that FENRIR hashes and encrypts as they arrive, so the file is never written to the server\u2019s disk unencrypted. A brief network drop is retried; a reload, a long outage or a server restart means starting again.' },
          { type: 'section', title: 'Where it is used', items: [
            '**Evidence › Items**: the **Collection wizard** and **Quick add**.',
            '**Email** (one `.eml` / `.msg` file), **Network capture** and **Browser history** uploads ([[fo-email]], [[fo-pcap]], [[fo-browser-history]]).',
            'The MCP tools that upload these files.',
          ] },
          { type: 'steps', items: [
            'Start the upload as usual. A progress bar shows the bytes received.',
            'Click **Cancel upload** to stop. What arrived is deleted; nothing is stored.',
            'When the last piece is in, FENRIR checks it — your target hash, or that a capture is a capture and a history file is SQLite — and only then stores the file and registers the exhibit. The bar shows **Checking the hash and storing…**; there is no **Cancel** then, because the result would be unknown.',
            'Email, network capture and browser history files are then analysed from that exhibit.',
          ] },
          { type: 'section', title: 'Size limits', items: [
            '**Evidence**: up to **10 GiB** per file by default. An admin sets the limit with `EVIDENCE_MAX_UPLOAD_BYTES` on the backend.',
            '**Email**: 25 MiB. **Network capture** and **Browser history**: 500 MiB.',
            'The evidence disk must have room for the whole file plus a 1 GiB reserve, counting the other uploads in progress. If not, the upload is refused (**insufficient storage**) before anything is sent. Ask an admin to free space.',
            'The analysers keep their own limits when you analyse a registered exhibit: Logs & triage 500 MiB, Defender PDF 25 MiB, Email 25 MiB, Network capture 500 MiB, Browser history 500 MiB. A larger exhibit is refused (**exhibit too large for analyser**) before anything is decrypted.',
            'At most **3 uploads** open at a time per user. A fourth is refused (**upload limit reached**) with a list of your open uploads, each with **Cancel**.',
          ] },
          { type: 'section', title: 'If the upload is interrupted', items: [
            'A piece that fails is sent again automatically — up to 5 times, waiting longer each time — and the upload continues where the server stopped. If it keeps failing, the upload stops: start it again.',
            'An upload with no progress for **30 minutes** is cancelled and what arrived is deleted.',
            'A server restart also ends every upload in progress. You see **Upload interrupted — start again**. Nothing was stored: choose the file again.',
            'A failed write on the server (**upload storage error**) ends the upload at once: nothing was stored. Try again later, or ask an admin to check the evidence storage.',
            'Closing the dialog, reloading or closing the tab cancels the upload: the page tells the server as it closes. If that message is lost, the upload ends after 30 minutes.',
            'Cancelled, or cut off, while FENRIR was storing the file: the result is unknown (**Result unknown**). Check **Evidence › Items** before uploading again.',
          ] },
          { type: 'section', title: 'When the last step is refused', items: [
            '**Collection wizard** and **Quick add**: if FENRIR refuses the details at the end — the identifier is already used, a field it rejects, or the evidence disk is below its 1 GiB reserve (**insufficient storage**) — the uploaded file is kept on the server.',
            'Correct the field (or free space) and click **Collect** / **Add evidence** again: the file is not sent again. **Discard upload**, choosing another file or closing the dialog drops it; it also ends after 30 minutes without activity.',
            'A refused target hash, or a file that is not what the analyser takes, ends the upload: nothing is stored.',
            'If another upload takes the same identifier at the same moment, the upload ends too: send it again.',
            '**Email**, **Network capture** and **Browser history** uploads end on any refusal: upload the file again.',
          ] },
          { type: 'note', text: 'Nothing is stored until the whole file is in and checked. A refused file leaves no exhibit and no stored copy; a refused target hash is logged as **Collection REFUSED** in the **Custody log**.' },
          { type: 'note', text: 'A batch of emails (several files or a `.zip`), photos, Supporting documents, **Malware quarantine**, **Logs & triage** and **Vendor reports** uploads and collector output still go up in one request, at most 512 MiB each. The server holds it only in memory (a 1 GiB scratch area, never its disk) until it is processed. When that area is full the upload is refused (**insufficient storage**): try again shortly.' },
        ],
      },
      {
        id: 'coc-examination',
        title: 'Examination (Wizard B)',
        tags: ['examination', 'analysis', 'verify', 'findings', '27042', 'working copy', 'in place'],
        body: [
          { type: 'p', text: 'Records an analysis of a digital exhibit, done on a verified working copy, with the copy\u2019s integrity checked before and after — `ISO/IEC 27037 §5.4.5` + `ISO/IEC 27042`.' },
          { type: 'steps', items: [
            '**Working copy** — choose the verified copy you examined (`§7.1.3.1.1`): a complete download or a lab copy whose hash matched the master. See [[coc-working-copies]].',
            '**Copy hash before** (optional) — your hash of the copy before you start. A mismatch aborts: no examination is recorded, the copy is flagged **Altered**, and the custody log records **Working copy changed**.',
            '**Record** — tool + version (validated-tools registry), 27041 validation, examiner qualifications, and the 27042 records: **findings**, **interpretation**, **confidence**, **scope limitations**.',
            '**Copy hash after** (required) — your hash of the copy afterwards. If it differs, the examination is still recorded, the copy is flagged **Altered** and can\u2019t be examined again.',
          ] },
          { type: 'section', title: 'Rules', items: [
            'A digital exhibit needs a working copy, or **Examined in place** with a reason (audited) — for example live triage where no copy was possible. **Examine (quick)** follows the same rule.',
            'Your hashes are compared with the hash recorded for the copy, in the same algorithm (MD5, SHA-1 or SHA-256).',
            'On a working copy the master is not re-hashed. **Examined in place**: FENRIR verifies the stored master before and after the examination; a mismatch freezes it and nothing is recorded. **Verify integrity** checks the master at any time.',
            'Physical items are exempt: they have no working copies.',
          ] },
          { type: 'note', text: 'Findings and interpretation are kept separate on purpose (27042 item 8); scope limitations record what was **not** examined (item 12).' },
          { type: 'note', text: '**Examine → Logs & triage → From a registered exhibit** is also an examination: it re-hashes the exhibit first (a mismatch freezes it, nothing is parsed) and records `evidence_examine` with the parser version and source timezone in the item\u2019s custody log. See [[fo-timeline-import]]. **Vendor reports → From a registered exhibit** does the same for a Defender PDF ([[fo-vendor-reports]]), and so do **Email**, **Network capture** and **Browser history** ([[fo-email]], [[fo-pcap]], [[fo-browser-history]]).' },
        ],
      },
      {
        id: 'coc-working-copies',
        title: 'Working Copies',
        tags: ['working copy', 'download', 'lab copy', 'master', 'verified', 'hash', '27037', '7.1.3.1.1'],
        body: [
          { type: 'p', text: 'Analysis runs on a working copy whose own hash matched the master — never the master itself (`ISO/IEC 27037 §7.1.3.1.1`). The master can\u2019t be downloaded; every download is a registered working copy.' },
          { type: 'steps', items: [
            'Open the item\u2019s **Detail** and click **Download a working copy**. Give the purpose and, optionally, where the copy will go.',
            'FENRIR registers the copy as `<identifier>-WC-n` and your browser downloads it. The link works once, for you, for 10 minutes.',
            'FENRIR hashes exactly the bytes it sends (SHA-256, SHA-1, MD5) and records them on the copy with the byte count.',
            'The page follows the copy: **Download started** once FENRIR begins sending, then the recorded hash when the transfer ends — or why it stopped. If nothing has started after 15 seconds, FENRIR refused the link (for example, the item is frozen or in a transfer) or your browser blocked it: the page says so.',
            'Hash the file you received and compare it with the recorded SHA-256.',
          ] },
          { type: 'section', title: 'What a copy shows', items: [
            '**Complete** — every byte was sent; **✓ Copy hash matches the master**. It is **Usable for examination**.',
            '**Aborted** — the transfer stopped early (your connection, or the stored file could not be read). No hash is recorded; download again.',
            '**Failed integrity** — the stored master failed its check while it was read. The item is frozen, as **Verify integrity** does.',
            '**Link expired** — the link was never used.',
            '**Lab copy** — a copy you made outside FENRIR, recorded with **Record a lab copy** and the hash(es) your tool reported for it. **Verified** when each matches the master\u2019s hash of the same algorithm; **Hash mismatch** otherwise (flagged, never counted as verified).',
            '**Export** — made by an export bundle. **Legacy record** — recorded before copies kept their own hash: it holds the master\u2019s hash, not the copy\u2019s, so it is not a verified copy.',
          ] },
          { type: 'note', text: 'Any **Analyst** who can see the incident can download or record a copy, also after the incident is closed. Every copy is in the item\u2019s custody log; a **Viewer** sees the list only.' },
          { type: 'note', text: 'The item must be active (not frozen), held by an internal custodian, with no transfer pending. The provenance score flags a digital item with no verified working copy.' },
        ],
      },
      {
        id: 'coc-provenance',
        title: 'Provenance Score',
        tags: ['provenance', 'score', 'green', 'amber', 'red', 'completeness', 'court-ready'],
        body: [
          { type: 'p', text: 'A per-item readiness score — **green / amber / red** plus a completeness percentage — that tells you whether an item is court-ready before handoff.' },
          { type: 'section', title: 'How it scores', items: [
            '**Mandatory** check failing → **red** (no collector, no lawful basis, no SHA-256, hash mismatch, broken chain).',
            '**Advisory** check failing or pending → **amber** (tool validation, qualifications, working copy, 27042 findings/scope, DEFR/DES role, trusted timestamp).',
            'Source and target hashes are compared only when they use the same algorithm. An MD5 source and a SHA-256 target is **amber** (confirm in the tool\'s report), never red, and never blocks **Seal**.',
            'All applicable checks pass → **green**.',
          ] },
          { type: 'note', text: 'The server computes the same score the UI shows (API-first), so MCP clients and scripts get an identical verdict. Advisory checks never block sealing.' },
        ],
      },
      {
        id: 'coc-validated-tools',
        title: 'Validated-Tools Registry',
        tags: ['validated tools', '27041', 'validation', 'settings'],
        body: [
          { type: 'p', text: 'A governed catalog of validated forensic tools and methods (`ISO/IEC 27041`), so "the tool was validated" is a record rather than a free-text claim.' },
          { type: 'section', title: 'Using it', items: [
            'Admins manage it under **Settings → Validated Tools** (tool, version, validation ref / scope / date, validator).',
            'The acquisition and examination wizards **pick from it** and auto-fill the validation fields.',
            'Using an unlisted tool is allowed but flagged unvalidated in the provenance score.',
          ] },
        ],
      },
      {
        id: 'coc-timestamping',
        title: 'Trusted Timestamping',
        tags: ['rfc 3161', 'timestamp', 'tsa', 'eidas', 'seal'],
        body: [
          { type: 'p', text: 'An optional **RFC 3161** time-stamp token binds an evidence hash to an independent trusted time, provable without trusting the platform clock.' },
          { type: 'section', title: 'Where it applies', items: [
            'Best-effort at **seal**, on the **LE manifest**, and on the **signed audit export**.',
            'Only the hash is sent to the timestamp authority — never the evidence.',
            'Configure the authority with the `TSA_URL` env var; unset = server clock only (provenance shows a manual check).',
          ] },
          { type: 'note', text: 'An eIDAS-*qualified* timestamp (point `TSA_URL` at a qualified TSA) carries the most court weight. No HSM is required for this.' },
        ],
      },
      {
        id: 'coc-transfers',
        title: 'Custody Transfers & External Custodians',
        tags: ['transfer', 'custodian', 'external', 'handoff', 'accept', 'decline', 'acceptance', '27037', '6.1'],
        body: [
          { type: 'p', text: 'Every change of hands is recorded — to another FENRIR user (internal) or to a real-world party without an account (external) — `ISO/IEC 27037 §6.1`. An internal transfer completes only when the recipient accepts it.' },
          { type: 'steps', items: [
            'The current custodian clicks **Request transfer** and picks the recipient. An **Admin** can do it too, recorded as an override. Custody does not change yet.',
            'The item shows **Awaiting acceptance by …** and the recipient gets a notification.',
            'The recipient inspects the item, records the **Condition on receipt** and whether the **Seals** are intact, and clicks **Accept custody**. Custody passes to them.',
            'Or the recipient clicks **Decline…**, or the requester or an **Admin** clicks **Cancel request…** — both need a reason.',
          ] },
          { type: 'section', title: 'Rules', items: [
            'Only the recipient can accept — an **Admin** cannot accept for them.',
            'The recipient must be an active **Analyst** or **Admin** with access to the incident.',
            'While a transfer is pending, another transfer, **Seal** and **Dispose** are blocked.',
            '**External** custodian (courier, counsel, LE officer, vendor): one step, by the custodian or an **Admin**. Examine, verify and seal pause until the item comes back.',
            '**Take back** from external custody: you record that you received it, with its condition and seals.',
            'Structured transport details (method, seal ID, courier ref) are captured for every handoff.',
          ] },
          { type: 'note', text: 'Transfers recorded before recipient acceptance existed show as a manual provenance check — confirm them from the paper record.' },
        ],
      },
      {
        id: 'coc-disposal',
        title: 'Disposal & the Two-Person Rule',
        tags: ['dispose', 'destroy', 'archive', 'return', 'legal hold', 'two-person'],
        body: [
          { type: 'p', text: 'Disposal — **archive**, **return**, or **destroy** — is admin-only and always audited. Destroying a digital item permanently deletes the encrypted file while keeping the hash and chain.' },
          { type: 'section', title: 'Rules', items: [
            'A **legal-hold** item can\u2019t be destroyed. The incident lead or an **Admin** releases the hold first — see [[coc-legal-hold]].',
            'Archiving or returning a **legal-hold** item requires a **second approver** — another active user, not you (the **Admin** disposing it) — two-person integrity (SWGDE / ACPO).',
            'The final SHA-256 is recorded at disposition; the custody chain is retained for the legal record.',
          ] },
          { type: 'note', text: 'Destruction cannot be undone — the file is gone; only the hash and the chain remain.' },
        ],
      },
      {
        id: 'coc-legal-hold',
        title: 'Legal Hold',
        tags: ['legal hold', 'litigation hold', 'preserve', 'release', 'dispose', 'le package'],
        body: [
          { type: 'p', text: 'A legal hold marks an item that must be preserved — for litigation, a regulator or law enforcement. While held it can\u2019t be destroyed.' },
          { type: 'steps', items: [
            'Open the item\u2019s **Detail** and click **Place on legal hold…**. Give the reason (audited).',
            'The item shows **Legal hold** in the list, and since when, by whom and why in its detail.',
            'To end it, the incident lead (Incident Commander or Deputy) or an **Admin** clicks **Release hold…** with a reason.',
          ] },
          { type: 'section', title: 'Rules', items: [
            'Any **Analyst** who can see the incident can set a hold; only the lead or an **Admin** can release it.',
            'Both work after the incident is closed: preservation outlives closure.',
            'While held: **Destroy** is refused; **Archive** and **Return** need a second approver ([[coc-disposal]]).',
            'The **LE package** can include only held items (**Only include evidence flagged legal_hold**).',
            'Every set and release is in the custody log with its reason; the item detail lists the history.',
          ] },
        ],
      },
      {
        id: 'coc-draft-exhibits',
        title: 'Draft Exhibits',
        tags: ['draft', 'unsealed', 'complete & seal', 'acquisition record', 'register first', 'email', 'pcap', 'browser history', 'quick add', '27037'],
        body: [
          { type: 'p', text: 'A draft exhibit is an evidence item that is registered, hashed and in custody but not yet sealed: its acquisition record is incomplete.' },
          { type: 'section', title: 'Where drafts come from', items: [
            'An upload to **Email**, **Network capture** or **Browser history** — the file is registered first, then analysed (`ISO/IEC 27037 §5.4.4`: identify and preserve before you examine).',
            'A **Quick add** in **Evidence › Items**.',
            'A draft gets an automatic identifier (`EMAIL-…`, `PCAP-…`, `WEBHIST-…`), you as collector and custodian, and its SHA-256 / SHA-1 / MD5. The file is encrypted at rest.',
            '**Acquired at** is unknown unless you entered it at upload. The lawful basis is pending.',
            'Its collection appears in the incident **Custody log** as **Collected**, and every analysis of it as **Examined**.',
          ] },
          { type: 'steps', items: [
            'Open **Evidence › Items**. Drafts show **Draft · unsealed**.',
            'Click **Complete & seal** (in the row or the item\u2019s detail).',
            'Work through the wizard: device type, lawful basis, how it was acquired, tool + version, the hashes your tool reported, acquisition time, witness. The stored file is kept; nothing is uploaded again.',
            'A target hash you enter is compared with the stored file: a mismatch is refused and nothing changes.',
            'Click **Save & seal**. If something required is missing, the record is saved and you can seal later.',
          ] },
          { type: 'note', text: 'Only the item\u2019s collector, its current custodian, the incident lead or an **Admin** can complete the record, with the item held by an internal custodian and no transfer pending. The record is logged as **Acquisition record** in the custody log with each changed value before and after; device types, decision factors and device details record the new value only.' },
          { type: 'note', text: 'An upload whose SHA-256 equals an active exhibit with a stored file is analysed as that exhibit (the oldest, if there are several) — no second copy is made, and the uploaded copy is deleted.' },
          { type: 'note', text: 'Exports and LE packages leave unsealed drafts out unless you tick **Include unsealed drafts** (audited): the manifest lists each as `excluded: unsealed draft`. See [[pi-le-package]].' },
        ],
      },
      {
        id: 'coc-photos',
        title: 'Evidence Photos',
        tags: ['photo', 'image', '27037', '6.2.1', 'encrypted'],
        body: [
          { type: 'p', text: 'Attach photographs to an item (`ISO/IEC 27037 §6.2.1`); images are stored **AES-256-GCM encrypted at rest** and served only through an auth-gated route.' },
          { type: 'section', title: 'Behaviour', items: [
            'Add a photo from the evidence detail, with an optional caption and **Taken at** — it starts at the acquisition time; clear it if unknown. Thumbnails render inline. At most 512 MiB per image.',
            'Until the seal, **Edit caption** changes a photo\u2019s caption. An attached photo can\u2019t be removed; only destroying the item removes its photos.',
            'After the seal the photos and their captions can\u2019t change. A new photo can still be added; the custody log records it as **Photo added** (not **Amended after seal**).',
            '**Complete & seal** keeps the photos already stored. It adds a caption-only photo only to an item with no stored photo, dated by **Photo taken at**, else the seizure time, else unknown — never the time you save.',
            'Physical items require at least one in-situ photo — the provenance score enforces it.',
            'On **destroy**, photo files are deleted alongside the evidence file; their hashes stay on the record.',
          ] },
        ],
      },
      {
        id: 'coc-roles',
        title: 'Collector Roles (DEFR / DES)',
        tags: ['defr', 'des', 'role', '27037', '3.7', '3.8'],
        body: [
          { type: 'p', text: 'Record the capacity in which evidence was collected — **DEFR** (Digital Evidence First Responder) or **DES** (Digital Evidence Specialist) — `ISO/IEC 27037 §3.7/§3.8`.' },
          { type: 'section', title: 'Usage', items: [
            'Set on the collection / acquisition wizard; shown in the evidence detail.',
            'A DEFR collects and acquires on scene; a DES applies specialist techniques.',
          ] },
          { type: 'note', text: 'Advisory in the provenance score — recorded for accountability, never blocks sealing.' },
        ],
      },
      {
        id: 'coc-tamper',
        title: 'Tamper Monitoring & Audit Anchors',
        tags: ['tamper', 'audit', 'append-only', 'anchor', 'rfc 3161', 'integrity'],
        body: [
          { type: 'p', text: 'The custody audit log is hash-chained and **append-only at the database layer**, and a monitor periodically anchors it so tampering is provable, not merely detectable.' },
          { type: 'section', title: 'How it is protected', items: [
            '`audit_logs` rejects UPDATE and DELETE via a database trigger — the application cannot rewrite history.',
            'A sidecar verifies the chain segment and takes an **RFC 3161** timestamp over the chain head on an interval; each result is stored as an anchor.',
            'View anchor status at `/api/admin/audit/anchors` (admin); a detected break is logged and flagged.',
          ] },
          { type: 'note', text: 'The per-incident **Evidence → Audit chain** sub-tab verifies on demand; the signed **Audit Export** lets anyone re-verify offline.' },
        ],
      },
      {
        id: 'coc-handoff',
        title: 'Send to Law Enforcement',
        tags: ['le', 'law enforcement', 'package', 'manifest', 'eio', 'mla', 'export'],
        body: [
          { type: 'p', text: 'The law-enforcement package is a single signed handoff bundle: report + per-item custody chains + manifest, AES-256-encrypted with a one-time download.' },
          { type: 'section', title: 'What it contains', items: [
            'Manifest with **SHA-256** file hashes and an **HMAC-SHA-256** integrity check (not a public-key signature); embeds the SOP, Annex B documents, and EIO / MLA references.',
            'A one-time, time-limited download URL plus a recipient acknowledgment (HMAC) that closes the chain.',
            '`retention_until` recorded for lawful retention.',
            'Unsealed draft exhibits are left out unless you tick **Include unsealed drafts** — see [[pi-le-package]].',
          ] },
          { type: 'note', text: 'See **Backup & Restore** for evidence-volume continuity (`ISO 22301`).' },
        ],
      },
      {
        id: 'coc-backup',
        title: 'Backup & Restore',
        tags: ['backup', 'restore', 'continuity', 'iso 22301', 'admin'],
        body: [
          { type: 'p', text: 'A daily job mirrors the encrypted evidence volume and dumps the database; `scripts/restore.sh` restores either, with guards. Admin / operations topic.' },
          { type: 'section', title: 'Behaviour', items: [
            'The evidence mirror stays ciphertext (`ISO/IEC 27037 §6.9.2`); restore is dry-run by default and needs an explicit `--apply` plus a typed confirmation.',
            'Runs offline from the host — no internet dependency.',
            'The scheduled backup refuses to run without an age recipient (`BACKUP_AGE_RECIPIENT`), and skips a run while a key rotation is in progress.',
          ] },
          { type: 'section', title: 'Destroyed items and the mirror', items: [
            'Destroying an item deletes its file at once; its copy in the backup mirror is kept for a grace period (`MIRROR_PURGE_GRACE_DAYS`, default 30 days) so a mistaken destroy can still be recovered.',
            'After the grace period the backup run purges the mirror copy (`GDPR Art. 17`) and the item\u2019s custody log records **Backup mirror copy purged** (by `backup:mirror-purge`).',
            'Restoring a database from before the destroy brings the record back, but not a file already purged from the mirror.',
          ] },
        ],
      },
    ],
  },
  {
    id: 'incident-workspace',
    icon: '☰',
    label: 'Incident Workspace',
    color: '#fb923c',
    desc: 'Walk-through of every tab inside an incident',
    articles: [
      {
        id: 'iw-header',
        title: 'Incident Header & Status Band',
        tags: ['header', 'phase', 'stepper', 'edit', 'resolve', 'reopen', 'dark op', 'presence'],
        body: [
          { type: 'p', text: 'The fixed area at the top of every incident page. Available everywhere you are inside an incident.' },
          { type: 'section', title: 'Top bar', items: [
            '**← Incidents** link · ref code (e.g. `INC-2026-00001`) · incident title.',
            '**Shift handoff** — jump straight to the **Shift handoffs** tab to create a shift handover.',
            '**Edit** — opens **Details** in edit mode (title, severity, TLP, triage state, type, detection method, reporter, dates).',
            '**Resolve** — moves the incident to Post-Incident through the phase confirmation; it stays open. Shown until the incident is in Post-Incident.',
            '**Close** — signs the incident off with a statement; it becomes read-only. Shown in Post-Incident, and in any phase for a False or Benign Positive — see [[inc-closing]].',
            '**Re-open** — appears once the incident is closed; asks for a reason and the phase to return to.',
            'Observers see none of Edit, Resolve, Close or Re-open.',
            '**Save changes / Discard** — appear only in edit mode. A grey dot ● = unsaved changes; "SAVED" tag = recently persisted.',
          ] },
          { type: 'section', title: 'Status band', items: [
            '**Phase stepper** — the 4 phases (Preparation · Detection & Analysis · Containment/Eradication/Recovery · Post-Incident). Click one to move there; Preparation can\'t be selected. Opens a confirmation that asks a reason for moving back and checks Gate 1 before Post-Incident — see [[inc-phases]]. Static for Observers and closed incidents.',
            '**Pills** — current severity, status, TLP, and a red **DARK OP** pill when Dark Operation is on.',
            '**Presence avatars** — coloured initials of every other user currently viewing the incident, via WebSocket. Yours has a thicker ring.',
          ] },
          { type: 'note', text: 'When Dark Operation is active, a red banner sits below the status band and the page is forced to the Mission Control theme.' },
        ],
      },
      {
        id: 'iw-details',
        title: 'Situation & Details',
        tags: ['situation', 'board', 'landing', 'details', 'description', 'tags', 'systems', 'classification', 'clocks', 'gate', 'markdown', 'matrix'],
        body: [
          { type: 'p', text: '**Situation** is the landing tab, a read-only one-screen summary of the incident; **Details** is the full record and where you edit it.' },
          { type: 'section', title: 'Situation board', items: [
            '**Stakeholder Matrix banner** — required notifications for this severity ([[co-matrix]]).',
            '**Classification strip** — Type · Severity · TLP · Triage · How detected · Reporter · Teams · Tags on one line. **Edit details** opens Details in edit mode (analysts and admins, while the incident is open).',
            '**Clocks** — Occurred · Detected · Declared (opened in FENRIR) · Contained · Eradicated · Recovered, the time elapsed since detection, and the nearest open legal deadline. **NOT CONTAINED** shows in red when Contained is not declared in Containment, Eradication & Recovery or later.',
            '**Next gate** — Gate 1 (into Post-Incident) or Gate 2 (close), as the server evaluates it now: met, or how many items are missing with links to where each is fixed ([[inc-phases]]).',
            '**Open response actions** — open and in-progress actions from Respond, with their target, its containment state, owner and age ([[iw-respond]]).',
            '**Scope** — compromised entities with their containment state, plus entity and IOC counts.',
            '**Team** — every operational role and who holds it; vacant roles are outlined.',
            '**Latest shift handoff** — who handed over to whom, whether it is acknowledged, and the working hypothesis.',
            '**Next tasks** — the first 3 open playbook tasks of the current phase, with owner and due time.',
            '**Latest events** — the newest 5 timeline events. **Description** — the first lines; **Show all** opens Details.',
            'Each panel loads on its own: if one can\'t be read, only that panel says so.',
          ] },
          { type: 'section', title: 'Details', items: [
            '**Classification** — the strip above; in edit mode the form: Severity · TLP · Triage state · Incident type · Detection method · Reporter · Occurred · Detected · Contained · Eradicated · Recovered.',
            '**Description** — markdown, with a Write / Preview toggle in edit mode.',
            '**Snapshot** — Created / Updated / Closed and the incident times; **Tags** and **Teams** with their own Manage buttons.',
            '**Affected systems** — the incident\'s compromised entities: one scope list with **Entities** ([[iw-entities]]). **+ Add system** marks an entity compromised, or adds a new one; **Clear** removes the flag and keeps the entity; **Manage in Entities →** opens the full list.',
            '**Resolution summary** — what happened, root cause and recommendations; required to close ([[inc-closing]]).',
          ] },
          { type: 'note', text: 'The counts that used to sit on top of Details (IOCs, entities, evidence, timeline, playbook, responders) are on the left rail.' },
          { type: 'note', text: 'Links and bookmarks to an incident open Situation; links to its Details still open Details.' },
        ],
      },
      {
        id: 'iw-assignments',
        title: 'Team',
        tags: ['assign', 'role', 'commander', 'coverage', 'cisa', 'operational role'],
        body: [
          { type: 'p', text: 'Who is on the response team and what role they hold. Distinct from RBAC ([[gs-roles]]) — these are CISA operational roles per incident.' },
          { type: 'section', title: 'Sections', items: [
            '**Role Coverage** — at-a-glance grid showing which CISA roles are filled (Incident Commander, Communications Lead, Forensic Lead, Containment Lead, Recovery Lead, Scribe) and which are vacant.',
            '**Team grid** — one card per assignee: username, operational role, assignment notes, assigned-at timestamp.',
            '**+ Assign** — modal picks a user, role, and optional notes. The user must already be able to see the incident. The assignee gets a notification.',
            "**Incident Commander / Deputy** — these make an analyst the incident lead ([[gs-roles]]). Only the lead or an admin can assign or remove them; while the incident has no lead, its creator or today's on-call analyst can.",
            "**Remove** — your own assignment, or anyone's if you are the lead.",
          ] },
        ],
      },
      {
        id: 'iw-playbook',
        title: 'Playbook',
        tags: ['playbook', 'task', 'template', 'progress', 'phase'],
        body: [
          { type: 'p', text: 'Response tasks grouped by 800-61 R3 phase. Apply a template (CISA Federal IR Playbook, Vulnerability Response Playbook, etc.) or build tasks ad-hoc.' },
          { type: 'section', title: 'Per phase', items: [
            'A progress bar with % complete and counts (done · in-progress · open · skipped).',
            'Each task row: title, description, status dropdown, assignee, completion timestamp.',
          ] },
          { type: 'section', title: 'Toolbar', items: [
            '**Apply template** — opens a modal listing playbook templates; applying seeds tasks across all 4 phases.',
            '**+ Add task** — custom task for this incident only.',
            '**Reassign / Status** — inline edits per row.',
          ] },
        ],
      },
      {
        id: 'iw-handoffs',
        title: 'Shift Handoffs',
        tags: ['handoff', 'shift', 'transition', 'acknowledge', 'hypothesis', 'threads'],
        body: [
          { type: 'p', text: 'Structured shift handovers between analysts. Each handoff is a snapshot of state + the departing analyst\'s thinking.' },
          { type: 'section', title: 'Per handoff card', items: [
            '**From → To** — outgoing → incoming analyst.',
            '**Status badge** — pending · acknowledged · completed.',
            '**Snapshot counts** — IOCs, entities, evidence, timeline entries at handoff time.',
            '**Hypothesis** — one-line summary + confidence (%).',
            '**Key findings + investigation threads** — each with its own status/confidence.',
            '**Pending steps · ruled-out items · open questions · follow-up tasks.**',
          ] },
          { type: 'section', title: 'Actions', items: [
            '**Create handoff** — opens the structured form (the same shortcut sits in the incident header).',
            '**Acknowledge** — incoming analyst confirms receipt and takes over.',
          ] },
        ],
      },
      {
        id: 'iw-comms',
        title: 'Comms & Stakeholders',
        tags: ['comms', 'comments', 'oob', 'stakeholders', 'banner'],
        body: [
          { type: 'p', text: 'Everything communications-related for the incident.' },
          { type: 'table', headers: ['Sub-tab', 'What it does'], rows: [
            ['**Comments**', 'Threaded @-mention discussion. Mentions deliver notifications.'],
            ['**OOB**',      'Out-of-band log + passphrase generator. Use when the platform may be compromised — see [[co-comments]].'],
            ['**Stakeholders**', 'Per-incident contact list — see [[co-stakeholders]]. CSV bulk import supported.'],
          ] },
          { type: 'note', text: 'The Stakeholder Matrix banner (required notifications for this severity) appears above the sub-tabs and on the Situation board.' },
        ],
      },
      {
        id: 'iw-case-notes',
        title: 'Case notes',
        tags: ['case notes', 'notes', 'scratchpad', 'append-only', 'correction', 'contemporaneous', 'exhibit', 'sha-256'],
        body: [
          { type: 'p', text: 'Shared notes made at the time: what you did, saw or decided, and why. Everyone who can see the incident reads them; analysts and admins add them. Open **Detection & Analysis → Case notes**.' },
          { type: 'steps', items: [
            'Write the note under **New case note** (markdown).',
            'Optionally link it with **+ Link an item…** to exhibits, entities, IOCs or timeline events of this incident.',
            'Click **Post note**. The server sets the time; you can’t type one in.',
          ] },
          { type: 'section', title: 'Append-only', items: [
            'A posted note can’t be edited or deleted by anyone, admins included. The database refuses it.',
            'To fix a mistake, click **Correct** on the entry and post the correction. The original stays as written, struck through, with a link to the correction.',
            'Only the entry’s author or an admin can correct it. An entry is corrected once; to change a correction, correct the correction.',
          ] },
          { type: 'section', title: 'Where else they show', items: [
            '**Evidence** item detail, an expanded **Timeline** event or **IOC**, and the **Entities** drawer list the notes linked to that item. **+ Add note** there posts a note already linked to it.',
            'The **LE package** has them in `10_Case_Notes/Case_Notes.csv`; the **Full Technical Report** has a **Case Notes** appendix. Both include each entry’s SHA-256.',
          ] },
          { type: 'note', text: 'Each entry shows `#` and the start of its SHA-256. The hash is written to the hash-chained audit log when the entry is posted, so a changed note would no longer match.' },
          { type: 'note', text: 'On a closed incident case notes are read-only, like comments. Re-open the incident to add one.' },
          { type: 'section', title: 'Your old scratchpad', items: [
            'Case notes replace the private scratchpad. Existing scratchpads are kept read-only under **Legacy scratchpads** and are never published for you.',
            'Click **Post as case note** to share yours: its current text becomes a new case note, dated now and marked **from scratchpad**.',
            'Scratchpads can no longer be edited or deleted.',
          ] },
          { type: 'note', text: 'MCP: `fenrir_comms_list(view="case_notes")`, `fenrir_comms_write(action="case_note_add", data={body, evidence_ids?, entity_ids?, ioc_ids?, timeline_event_ids?, corrects_id?})` · API: `/api/incidents/{id}/case-notes`.' },
        ],
      },
      {
        id: 'iw-legal',
        title: 'Legal & Regulatory',
        tags: ['legal', 'gdpr', 'nis2', 'dora', 'pci', 'hipaa', 'ccpa', 'deadline', 'countdown', 'waive', 'breach', 'anchor', 're-anchor', 'reminder', 'clock'],
        body: [
          { type: 'p', text: 'Regulatory notification deadlines, each counted from an anchor: the moment the organisation became aware of the breach.' },
          { type: 'section', title: 'Initialise', items: [
            'Pick the applicable regulations. The **Anchor** defaults to the incident\'s **Detected** time.',
            'Give a regulation its **own anchor** when its awareness moment differs (GDPR Art. 33, NIS2 Art. 23 and DORA each define it differently).',
            'Initialising again adds only what is missing — it never duplicates a deadline.',
            'No Detected time and no anchor entered: initialise is refused until you enter one.',
          ] },
          { type: 'section', title: 'Built-in regulations', items: [
            '**GDPR** — Art. 33 DPA notification, 72 h. Art. 34 notice to individuals is an **internal target**: the law says “without undue delay” and sets no fixed window.',
            '**NIS2** — early warning 24 h, incident notification 72 h, final report one calendar month after the incident notification (`NIS2 Art. 23(4)(d)`).',
            '**DORA** · **PCI-DSS** · **HIPAA** · **CCPA**.',
          ] },
          { type: 'section', title: 'Per deadline card', items: [
            'Regulation badge · article / reference · obligation text · recipient (DPA, CSIRT, card brand, etc.).',
            'Countdown, the **Deadline** (or **Internal target**) and the **Anchor**, in your timezone.',
            'Status: **Pending** · **In Progress** · **Completed** · **Waived**.',
          ] },
          { type: 'section', title: 'Actions', items: [
            '**Mark In Progress** · **Mark Completed** · **Reopen**.',
            '**Waive** — needs a justification (at least 10 characters), saved as the completion notes.',
            '**Re-anchor** — a new anchor and a reason; the deadline is recalculated and the old and new times are audited.',
            '**Delete** — needs a reason; the audit log keeps the reason and a full copy of the deadline.',
            '**+ Add custom** — for obligations outside the standard list; the anchor defaults to Detected.',
          ] },
          { type: 'section', title: 'Clocks and reminders', items: [
            'The incident header shows one chip per regulation: its nearest open deadline, as a countdown. Red = overdue or under 2 h, orange = under 12 h, green = later. Click a chip to open Legal.',
            'In-app reminders arrive at 12 h before, 2 h before and when overdue. They go to the incident\'s assignees, or to everyone with access when nobody is assigned. They keep coming under Dark Operation and after the incident is closed. Nothing is emailed.',
          ] },
          { type: 'note', text: 'Completing the NIS2 72 h incident notification moves the NIS2 final report to one calendar month after that completion time. A month-end date clamps to the last day of the next month (31 Jan → 28/29 Feb).' },
          { type: 'note', text: 'On a closed incident you can still complete, waive or annotate deadlines; adding, deleting and re-anchoring need the incident re-opened.' },
        ],
      },
      {
        id: 'iw-evidence',
        title: 'Evidence Tab',
        tags: ['evidence', 'items', 'custody', 'audit chain', 'export', 'sop', 'aes-256', 'transfer', 'dispose'],
        body: [
          { type: 'p', text: 'The incident workspace for evidence — five sub-tabs. For the full ISO 27037/41/42/43 lifecycle and wizards, see the **Evidence & Chain of Custody** category.' },
          { type: 'table', headers: ['Sub-tab', 'What it does'], rows: [
            ['**Items**', 'Add / view evidence items, filter by kind (digital file or physical item). Unsealed items show **Draft · unsealed** with **Complete & seal** ([[coc-draft-exhibits]]). Actions: collection + acquisition wizards, evidence detail (acquisition record, legal hold, working copies, examinations, photos, provenance score), transfer custody, examination wizard, dispose (admin only).'],
            ['**Custody log**', 'Per-incident timeline of every collect / acquire / transfer / examine / return / dispose event across all items.'],
            ['**Audit chain**', 'Cryptographic chain verifier — recomputes the hash chain over evidence events and reports any mismatch.'],
            ['**Export**', 'Bundles selected items into an AES-256-encrypted ZIP with a one-time key and a single-use 24-hour download URL; auto-mints master-verified working copies for the items whose file is in the bundle. Up to 60 GiB of stored files per bundle; a multi-GiB bundle takes minutes to build. Unsealed drafts are left out (listed `excluded: unsealed draft`) unless you tick **Include unsealed drafts** (audited). Each file is hashed as it is bundled: a SHA-256 mismatch or a failed integrity check discards the bundle (nothing is exported) and freezes the item.'],
            ['**CoC SOP**', 'Reference card: phase-by-phase chain-of-custody procedure; flags missing photos on physical items and missing SHA-256 on digital files.'],
          ] },
          { type: 'note', text: 'A **legal hold** item can\u2019t be destroyed; archiving or returning it needs a second approver (two-person rule) — see [[coc-legal-hold]] and [[coc-disposal]].' },
        ],
      },
      {
        id: 'iw-files',
        title: 'Supporting Documents',
        tags: ['files', 'supporting documents', 'screenshot', 'upload', 'attachment', 'link entity', 'include in report', 'report figure', 'caption', 'sha-256', 'hash', 'rename', 'delete', 'reason', 'register as exhibit', 'exhibit'],
        body: [
          { type: 'p', text: 'A working store for non-malicious supporting material: screenshots, exported logs, notes. Encrypted at rest. Files attached to an entity (**Entities → Collected Files**) live in the same store.' },
          { type: 'section', title: 'On the page', items: [
            '**+ Upload files** — add one or more files.',
            'Per file: name · type · size · **SHA-256** (hover for SHA-1 and MD5) · added · added by · linked entity · report · exhibit.',
            '**Download** · **Link** / **Re-link** to an entity · **Rename** · **Delete**.',
            '**Report → Include** (PNG, JPEG, GIF or WebP only) — makes the screenshot a numbered figure in generated reports, with an optional caption (**Caption** to change it) and its SHA-256. See [[pi-reports]].',
            '**Register as exhibit** — makes the file an exhibit with chain of custody (below). Once registered, the column shows the exhibit (**⛁ DOC-…**, **Draft · unsealed** until it is sealed).',
          ] },
          { type: 'section', title: 'What is hashed', items: [
            'The server computes the SHA-256, SHA-1 and MD5 of every file as it encrypts the upload, and records them with the file and in the audit log. Files uploaded before this were hashed once afterwards by an admin tool, and the audit log says so.',
            'Renaming never changes the stored bytes or their hashes.',
          ] },
          { type: 'section', title: 'Rename and delete', items: [
            'Both ask for a **reason** (at least 10 characters). The audit log keeps the old and new name, or the deleted file\'s hashes, with your reason.',
            'Delete is refused while something relies on the file, and the message says what: it is a report figure (untick **Include**), a saved report shows it, a case note cites it, it is registered as an exhibit, or it is attached to an entity (unlink it first; from the entity\'s own **Collected Files** you remove the attachment itself). Exhibits and case notes are permanent records, so a file they rely on stays.',
          ] },
          { type: 'section', title: 'When to register as exhibit', items: [
            'When the file itself may be needed as evidence — shown to a court, a regulator or law enforcement, or relied on for a finding — rather than only illustrating the work.',
            'The file is decrypted, re-encrypted into the evidence store with a new key, and its SHA-256 checked against the one recorded at upload; if they differ nothing is registered and the attempt is audited.',
            'The result is an **unsealed draft exhibit** collected by you and in your custody (audited as a collection, with the file as its source). Complete its acquisition record and seal it in **Evidence → Items** ([[iw-evidence]]).',
            'If the incident already holds an exhibit with the same SHA-256, that exhibit is linked instead (no second copy). Registering again just shows the exhibit. The file stays here as a supporting document.',
          ] },
          { type: 'note', text: 'Screenshots can show personal data or TLP:RED material, and an included image goes into every report for the incident. Check it first; upload a cropped or redacted copy if needed.' },
          { type: 'note', text: 'Not for suspected-malicious samples: quarantine those in **Examine → Malware quarantine** ([[fo-artifacts]]). Material collected as evidence from the start goes straight to **Evidence** ([[iw-evidence]]).' },
        ],
      },
      {
        id: 'iw-forensic',
        title: 'Examine',
        tags: ['examine', 'forensic', 'collector packages', 'collections', 'malware quarantine', 'artifacts', 'email', 'network capture', 'pcap', 'browser history', 'logs & triage', 'timeline import', 'vendor reports', 'defender', 'ransom note', 'osint', 'yara', 'hunt queries', 'detections', 'lolbins'],
        body: [
          { type: 'p', text: 'The examination workbench (formerly **Forensic**): acquire the data, analyse each kind of artefact, then enrich and hunt. Eleven sub-tabs in three groups; it opens on **Collector packages**.' },
          { type: 'section', title: 'Acquire & ingest', items: [
            '**Collector packages** (was Collections) — signed Velociraptor collection packages; **Ingest results** brings the output back — see [[fo-collector-packages]].',
            '**Malware quarantine** (was Artifacts) — quarantine binaries + 11-tool analysis pipeline — see [[fo-artifacts]].',
          ] },
          { type: 'section', title: 'Analyse by artefact', items: [
            '**Email** — phishing triage of pasted headers or `.eml` / `.msg` / `.zip` files, or a registered exhibit — see [[fo-email]].',
            '**Network capture** — PCAP analysis — see [[fo-pcap]].',
            '**Browser history** — Chromium / Firefox history: visits, search terms, downloads — see [[fo-browser-history]].',
            '**Logs & triage** (was Timeline Import) — parse a log file or a registered exhibit, then promote events to the timeline — see [[fo-timeline-import]].',
            '**Vendor reports** (was Defender Import) — import a Microsoft Defender XDR incident PDF or a registered exhibit — see [[fo-vendor-reports]].',
            '**Ransom note** — pull wallets, deadlines and amounts out of a ransom note.',
          ] },
          { type: 'section', title: 'Enrich & hunt', items: [
            '**OSINT** — 11-source OSINT lookup for free-text IOCs — see [[fo-osint]].',
            '**YARA & hunt queries** (was Detections) — YARA rules, scan results, detection queries — see [[fo-detections]].',
            '**LOLBins reference** — LOLBAS + GTFOBins reference and correlations — see [[fo-lolbins]].',
          ] },
          { type: 'note', text: '**Email**, **Network capture** and **Browser history** register an upload as a draft exhibit before analysing it, or analyse an exhibit you pick — see [[coc-draft-exhibits]].' },
          { type: 'note', text: 'Attribution moved to **ATT&CK & attribution** ([[iw-mitre]]); old links redirect. IOCs has its own incident tab ([[iw-iocs]]).' },
        ],
      },
      {
        id: 'iw-timeline',
        title: 'Timeline',
        tags: ['timeline', 'event', 'spine', 'system', 'export', 'csv', 'html', 'mitre', 'lolbin'],
        body: [
          { type: 'p', text: 'The canonical narrative of the incident — analyst observations, system actions, decisions. See also [[tl-events]] and [[tl-mitre]].' },
          { type: 'section', title: 'On the page', items: [
            'Vertical spine with date separators and alternating event cards.',
            'Per-event: type, MITRE tactic + technique, IR phase, host (linked to its entity), source, raw log (collapsible).',
            'Inline **⚑ LOLBin panel** when an event references a known living-off-the-land binary.',
            '**Show / hide system events** toggle.',
          ] },
          { type: 'section', title: 'Toolbar', items: [
            '**+ Add event** — modal with a host picker over **Entities**, an IR-phase field, the MITRE selector and structured fields ([[tl-events]]).',
            '**Export CSV** — flat rows for spreadsheets / pipelines.',
            '**Export HTML** — standalone, JS-free, printable dark page ([[tl-export]]).',
          ] },
        ],
      },
      {
        id: 'iw-entities',
        title: 'Entities',
        tags: ['entity', 'asset', 'host', 'user', 'graph', 'compromised', 'connect', 'import'],
        body: [
          { type: 'p', text: 'Assets in your environment relevant to the incident — hosts, users, services, IP ranges. See also [[ee-entities]].' },
          { type: 'section', title: 'Views', items: [
            '**Table view** — Type, Value, Name, Criticality dropdown, Compromised toggle, added-at.',
            '**Compromised** entities are the incident\'s **Affected systems** on the Details tab and in reports — add a host once, here or there.',
            '**Isolated** / **Disabled** / **Blocked** / **Pending…** badge next to the Compromised toggle — containment state from **Respond**: the linked containment action is done (green) or still open or in progress (amber). See [[iw-respond]].',
            '**Graph view** — relationship visualisation of connected entities.',
          ] },
          { type: 'section', title: 'Toolbar', items: [
            '**Filter by Type / Criticality.**',
            '**+ Add entity** — single-entity modal (Type · Value · Name · Criticality · Compromised · Tags).',
            '**Bulk import** — CSV upload with preview.',
            '**Connect** — draw a relationship between two existing entities.',
          ] },
          { type: 'section', title: 'Entity detail drawer', items: [
            'Edit / Delete / Promote to IOC.',
            'Relationships to other entities, count of linked evidence files.',
          ] },
        ],
      },
      {
        id: 'iw-iocs',
        title: 'IOCs',
        tags: ['ioc', 'indicator', 'enrich', 'correlate', 'mark malicious', 'export', 'scan', 'bulk'],
        body: [
          { type: 'p', text: 'Indicators of compromise tied to this incident. See also [[ioc-types]] and [[ioc-enrichment]] for status and enrichment fundamentals.' },
          { type: 'section', title: 'Table columns', items: [
            'Type · Value (with badges) · linked Entity · Source · confidence bar · added-at · tags.',
            '**⚠ TI** badge — value matches an enabled Threat Intel feed.',
            '**LOL** badge — file-path matches a known LOLBin.',
            '**⋈** badge — IOC appears in N other incidents (click for cross-incident list).',
            '**Blocked** / **Pending…** badge — containment state from **Respond**: a block action linked to this IOC is done (green) or still open or in progress (amber). See [[iw-respond]].',
          ] },
          { type: 'section', title: 'Toolbar', items: [
            '**+ Add IOC** · **Bulk import (CSV)** · **Run all sources** (batch enrich whole incident).',
            '**Scan to platforms** — modal pushes IOCs to Microsoft Defender / CrowdStrike / SentinelOne / Cortex XDR / FortiGate / Palo Alto for blocking or hunting.',
          ] },
          { type: 'section', title: 'Row actions', items: [
            'Click a row to expand: full value, **Mark Malicious / Mark Clean / Mark Unknown** buttons, notes editor, enrichment cards.',
            'Per-row **Enrich** runs only the enrichment sources that apply to this IOC type.',
            '**Edit** · **Delete** · **Open correlations**.',
          ] },
        ],
      },
      {
        id: 'iw-mitre',
        title: 'ATT&CK & Attribution',
        tags: ['mitre', 'attack', 'tactic', 'technique', 'coverage', 'attribution', 'actor'],
        body: [
          { type: 'p', text: 'What the attacker did, and who it points to. Two sub-tabs: **Coverage** (opens first) and **Attribution** — see [[fo-attribution]].' },
          { type: 'section', title: 'Coverage', items: [
            'Per-incident MITRE coverage map. Driven entirely by timeline events you have tagged with a tactic + technique ([[tl-mitre]]).',
            'Header counts: tactics observed (of 12) · total techniques observed.',
            'One row per MITRE tactic, in ATT&CK order.',
            'Observed tactics show technique pills with the event count per technique.',
            'Unobserved tactics show a gap indicator — useful to spot blind spots.',
          ] },
        ],
      },
      {
        id: 'iw-respond',
        title: 'Respond',
        tags: ['respond', 'kanban', 'containment', 'eradication', 'recovery', 'decision', 'action', 'revert'],
        body: [
          { type: 'p', text: 'A Kanban board for tracking response actions during Containment / Eradication / Recovery.' },
          { type: 'section', title: 'Columns', items: [
            '**Containment** · **Eradication** · **Recovery** · **Decisions**.',
            'Drag cards between columns or change status via the per-card dropdown.',
          ] },
          { type: 'section', title: 'Action cards', items: [
            'Title, description, target, assignee, occurrence + completion timestamps. A target not linked to an entity or IOC shows **(unlinked target)**.',
            '**Done** — stamps the completion time and adds a system event to the **Timeline** (at the occurrence time if set, else the completion time). Logging an action straight as Done does the same.',
            '**Revert** — marks the action **Reverted** (rolled back), records the reason and adds a Timeline event.',
            'Edit / Delete inline.',
          ] },
          { type: 'section', title: 'Target and containment state', items: [
            'Pick the host, account or C2 IP in **Link target** — the entities and IOCs of this incident, filtered to the template\'s types. **Target** takes its value; you can still type free text instead. The list loads when the dialog opens; if it can\'t load, the dialog says so and free text still works.',
            'A containment template only links to its kind of target: isolate / quarantine / take offline → host entities; disable / reset / revoke → user or email-account entities; block IP → IP IOCs and IP or network-range entities; block domain, URL or hash → that IOC type (a domain entity also for block domain); block sender → email or domain IOCs and entities. Any other link is refused.',
            'A linked containment action sets a badge on the **Entities** or **IOCs** row: isolate host, quarantine endpoint or take offline → **Isolated**; disable account, reset credentials or revoke sessions / MFA / tokens → **Disabled**; block IP, domain, URL, hash or sender → **Blocked**.',
            'Open or in progress → **Pending…** (amber). **Done** → the effect (green). **Revert** clears it.',
            'The most recently created linked containment action decides the badge. Deferred actions and other templates don\'t count.',
          ] },
          { type: 'section', title: 'Decision cards', items: [
            'Summary, rationale, outcome, tags, decided-by / decided-at.',
          ] },
          { type: 'section', title: 'Toolbar', items: [
            '**Action templates** — pick from a built-in library (isolate host, reset credentials, block IOC, etc.) to pre-fill.',
          ] },
        ],
      },
      {
        id: 'iw-post-incident',
        title: 'Post-Incident Tab',
        tags: ['post-incident', 'analytics', 'closure', 'lessons', 'attack chain', 'reports'],
        body: [
          { type: 'p', text: 'Closure activities and reporting. Five inner tabs:' },
          { type: 'table', headers: ['Sub-tab', 'What it does'], rows: [
            ['**Analytics**',         'Quantitative incident view — see [[pi-analytics]].'],
            ['**Closure Checklist**', '12 seeded items plus custom rows — see [[pi-closure]].'],
            ['**Lessons Learned**',   'Structured 800-61 §4 review — see [[pi-lessons]].'],
            ['**Attack Chain**',      'Swimlane visualisation of MITRE-tagged events — see [[pi-attack-chain]].'],
            ['**Reports**',           'Executive / Full / LE Package generation — see [[pi-reports]].'],
          ] },
        ],
      },
      {
        id: 'iw-audit-log',
        title: 'Audit Log Tab',
        tags: ['audit', 'log', 'admin', 'filter', 'denied'],
        body: [
          { type: 'p', text: "Per-incident audit feed. Visible to admins and to the incident lead (its Incident Commander or Deputy, [[gs-roles]]); a lead's read is itself audited." },
          { type: 'section', title: 'Columns', items: [
            'Timestamp · HTTP method / IP · action name (colour-coded) · username + role · outcome (success / failure / denied) · resource label · request path.',
          ] },
          { type: 'section', title: 'Filters', items: [
            'By action type · by user · shows total + filtered counts.',
            'Click any row to expand the full event payload.',
          ] },
          { type: 'note', text: 'Cookie sessions and Bearer-token API calls both appear here. Global audit is at Admin → Global Audit Log ([[st-audit-export]]).' },
        ],
      },
      {
        id: 'iw-warroom',
        title: 'War Room Tab',
        tags: ['warroom', 'chat', 'mention', 'drawer'],
        body: [
          { type: 'p', text: 'Pinned to the right edge of every incident page. See [[co-warroom]] for full details.' },
        ],
      },
    ],
  },
  {
    id: 'forensic',
    icon: '⌖',
    label: 'Examine Tools',
    color: '#22d3ee',
    desc: 'YARA & hunt queries · LOLBins · Email · Network capture · Browser history · Malware quarantine · Logs & triage · OSINT',
    articles: [
      {
        id: 'fo-detections',
        title: 'YARA & Hunt Queries',
        tags: ['yara', 'rule', 'scan', 'detection', 'detections', 'hunt', 'query', 'kql', 'splunk', 'eql'],
        body: [
          { type: 'p', text: 'Inner tabs: **YARA Rules** · **Scan Results** · **Detection Queries**.' },
          { type: 'section', title: 'YARA Rules', items: [
            'Paste or upload `.yar` / `.yara` files. Rules are validated before save.',
            'Per-rule card: match count, hit indicators, disabled flag, author, description, tags.',
            'Toggle a rule active/inactive without deleting it.',
            'Expand a card to view the full rule body.',
          ] },
          { type: 'section', title: 'Scan Results', items: [
            'Runs all active rules against this incident\'s quarantine artifacts.',
            'Per-match: rule name, matched artifact, matched strings (expandable).',
            'Promote a match to a **Timeline event** or create an **IOC** from its SHA-256.',
            '**Clear all** results · shows last-scan timestamp.',
          ] },
          { type: 'section', title: 'Detection Queries', items: [
            'Auto-generated from your IOCs and MITRE-mapped events.',
            'Platform tabs: **KQL · EQL · Splunk · Cortex XDR · CrowdStrike**.',
            'Queries grouped by category, with confidence colour-coding.',
            '**Copy** individual queries or **Download ZIP** of all queries for the selected platform.',
          ] },
        ],
      },
      {
        id: 'fo-lolbins',
        title: 'LOLBins & GTFOBins',
        tags: ['lolbin', 'lolbas', 'gtfobins', 'living-off-the-land'],
        body: [
          { type: 'p', text: 'FENRIR includes a bundled LOLBAS (Windows) + GTFOBins (Linux/macOS) database.' },
          { type: 'section', title: 'On the page', items: [
            'Summary bar: total LOLBin count, Windows count, Linux count, last-sync time.',
            '**Force sync** button refreshes the database.',
            'Search by name · filter All / Windows / Linux.',
            'Entries grouped by platform; expand to view all file paths.',
            'Per technique: type (Execution, Defense Evasion, …), required privileges, MITRE ATT&CK tag, command example, detection hints.',
          ] },
          { type: 'section', title: 'Auto-correlations elsewhere', items: [
            '**Timeline** — events referencing a known LOLBin are flagged with an inline ⚑ panel.',
            '**IOCs** — file-path IOCs matching a LOLBin show a **LOL** badge.',
          ] },
        ],
      },
      {
        id: 'fo-pcap',
        title: 'PCAP Analysis',
        tags: ['pcap', 'pcapng', 'network', 'network capture', 'tshark', 'dns', 'tls', 'http', 'talkers', 'exhibit', 'run record', 'timeline'],
        body: [
          { type: 'p', text: 'Analyse a packet capture in the air-gapped analysis worker (tshark). The capture itself is kept as an exhibit, so every result traces back to the hashed file.' },
          { type: 'steps', items: [
            'Choose the source: **Upload a capture** (`.pcap` / `.pcapng`, up to 500 MiB), or **From a registered exhibit** — no re-upload; the exhibit must be **active**, in internal custody and not awaiting a transfer.',
            'An upload is registered first as a **draft exhibit** (`PCAP-…`), hashed and encrypted as it arrives ([[coc-resumable-upload]]) — or analysed as the exhibit with the same SHA-256. Optionally set **Acquired at**. A file that is not a capture is refused and nothing is stored.',
            'An exhibit is re-hashed before it is analysed: a mismatch freezes it (**verify_failed**) and nothing is analysed.',
            'Review the result tabs, then put what matters on the Timeline from the **Timeline** tab.',
          ] },
          { type: 'section', title: 'Run record', items: [
            'Shows the **⛁ exhibit** (and **Draft · unsealed** until it is sealed), the **Input SHA-256**, the **Analyser** name and version, how the exhibit was linked, and who ran it when.',
            'Every analysis is in the exhibit\u2019s custody log as **Examined**.',
            'If the worker is down the capture stays registered; analyse it later **From a registered exhibit**.',
          ] },
          { type: 'section', title: 'Result tabs', items: [
            '**Suspicious** — severity-ranked findings.',
            '**Conversations** — TCP / UDP, sorted by byte volume.',
            '**DNS** — queries (with the resolved address) and suspicious-domain heuristics (long names, low-vowel ratio, IP-in-DNS, suspicious TLDs).',
            '**DNS Recon** — top resolvers, per-domain stats, CNAME chains, entropy.',
            '**HTTP** — method, host, URI, response code, UA. Flags cmd / shell / base64 / sqlmap-style patterns.',
            '**TLS** — SNI, version, suspicious indicators.',
            '**Top Talkers** — by bytes.',
            '**Timeline** — candidates: capture start and end, each conversation\u2019s first and last packet, DNS queries, HTTP requests and TLS ClientHello SNI.',
          ] },
          { type: 'section', title: 'Timeline candidates', items: [
            'Times come from the capture (UTC) and are shown in your timezone.',
            'When the exhibit records a **Clock offset in seconds**, times are corrected by it: **offset-corrected (+N s)**, with the recorded time on hover.',
            'Select rows and click **Add N to Timeline**. FENRIR copies them from the stored run; the events carry the exhibit and are locked as imported. They are internal-only until you mark them external-safe.',
            'Adding the same candidate again does nothing; a candidate without a time is never added.',
          ] },
          { type: 'note', text: '**Import IOCs to Incident** — promote indicators into the IOC list; they record the exhibit.' },
          { type: 'note', text: 'The worker keeps the largest 50 TCP and 30 UDP conversations, the first query of up to 200 DNS names, 200 HTTP messages and 100 TLS handshakes; the timeline is built from those. Analyses made before captures were kept have no timeline: upload the capture again.' },
        ],
      },
      {
        id: 'fo-email',
        title: 'Email Analysis',
        tags: ['email', 'phishing', 'eml', 'msg', 'headers', 'spf', 'dkim', 'dmarc', 'exhibit', 'run record', 'attachments', 'hops'],
        body: [
          { type: 'p', text: 'Offline phishing triage of a message: headers, relay hops, SPF / DKIM / DMARC, URLs and attachments, with a verdict and score. The message analysed is always an exhibit.' },
          { type: 'steps', items: [
            'Choose the source: **Upload or paste** (one or more `.eml` / `.msg` files, a `.zip` of them, or pasted source), or **From a registered exhibit**.',
            'Each uploaded message — and pasted source — is registered first as a **draft exhibit** (`EMAIL-…`), hashed and encrypted, or analysed as the exhibit with the same SHA-256. A single file uploads in resumable pieces ([[coc-resumable-upload]]). A `.zip` is a container only: each message in it becomes its own exhibit.',
            'An exhibit is re-hashed before it is analysed: a mismatch freezes it and nothing is analysed.',
            'Click **Analyze** or **Analyze exhibit**.',
          ] },
          { type: 'section', title: 'Run record', items: [
            'Shows the **⛁ exhibit** (and **Draft · unsealed** until it is sealed), the **Input SHA-256**, the **Analyser** and version, and who ran it when. **Previous analyses** list the exhibit of each.',
            'Every analysis is in the exhibit\u2019s custody log as **Examined**. No plaintext quarantine copy of the message is kept.',
            'A message that can\u2019t be parsed stays registered; the error names the exhibit.',
          ] },
          { type: 'section', title: 'Actions', items: [
            '**Import hops → Timeline** — relay hops with a time. They record the exhibit and are locked as imported. No clock offset applies: the mail servers wrote those times.',
            '**Promote selected → IOC** — the IOCs record the exhibit.',
            '**Extract → Artifact** — the message is re-read from the exhibit (re-hashed first) and the attachment goes to **Malware quarantine**.',
            '**Register as exhibit** — only on analyses made before uploads were registered first.',
          ] },
          { type: 'note', text: 'Live SPF / DKIM / DMARC checks query the claimed sender domain; they are skipped under Dark Operation or TLP:RED. Nothing in the message is fetched or executed.' },
        ],
      },
      {
        id: 'fo-browser-history',
        title: 'Browser History',
        tags: ['browser history', 'web history', 'chrome', 'edge', 'brave', 'firefox', 'places.sqlite', 'formhistory', 'visits', 'downloads', 'exhibit', 'timeline'],
        body: [
          { type: 'p', text: 'Parse a browser\u2019s history database into visits, downloads and search terms, then put the ones that matter on the Timeline. The file parsed is always an exhibit.' },
          { type: 'steps', items: [
            'Choose the source: **Upload a history file** (Chrome / Edge / Brave `History`, Firefox `places.sqlite`, up to 500 MiB) or **From a registered exhibit**.',
            'An upload is registered first as a **draft exhibit** (`WEBHIST-…`), hashed and encrypted as it arrives ([[coc-resumable-upload]]) — or parsed as the exhibit with the same SHA-256. Firefox\u2019s `formhistory.sqlite` becomes its own exhibit; its search-bar terms join the upload.',
            'An exhibit is re-hashed before it is parsed: a mismatch freezes it and nothing is parsed.',
            'Search and filter **Visits**, **Search terms** and **Downloads**.',
            'Select visits or downloads and click **Add N to Timeline**.',
          ] },
          { type: 'section', title: 'Run record and times', items: [
            'Selecting an upload shows its **⛁ exhibit**, **Input SHA-256**, **Analyser** (parser) and version, and the clock offset.',
            'Visit and download times are UTC, as the browser recorded them.',
            'When the exhibit records a **Clock offset in seconds**, events added to the Timeline are corrected by it and keep the recorded time. **⚠ clock** marks an upload whose exhibit\u2019s offset changed afterwards: parse the exhibit again to apply it.',
          ] },
          { type: 'section', title: 'On the Timeline', items: [
            'FENRIR copies each record from the stored upload; the event records the exhibit and is locked as imported. **⏱✓** marks a record already on the Timeline.',
            'Events are internal-only (browsing history is personal data) until you mark them external-safe.',
            'A download without a start time is never added. An upload made before files were registered first can\u2019t add to the Timeline: upload the file again.',
          ] },
          { type: 'note', text: 'Firefox: `places.sqlite` is registered before `formhistory.sqlite` is sent. If the second file fails or you cancel it, the first stays registered and the message names it — parse it **From a registered exhibit**.' },
          { type: 'note', text: 'An upload with events on the Timeline can\u2019t be deleted: it is their provenance record. **Register as exhibit** is only for uploads made before files were registered first.' },
        ],
      },
      {
        id: 'fo-artifacts',
        title: 'Malware Quarantine',
        tags: ['artifact', 'artifacts', 'malware', 'quarantine', 'sandbox', 'hash', 'zip', 'infected', 'pe', 'office', 'pdf', 'yara', 'strings'],
        body: [
          { type: 'p', text: 'Upload binaries for analysis. Files land on the air-gapped quarantine volume (no internet, read-only from the worker).' },
          { type: 'section', title: 'Upload', items: [
            'Drag-and-drop or click upload zone, up to **500 MiB**.',
            'On ingest: SHA-256 / SHA-512 / MD5 hashed in one streaming pass, MIME detected via libmagic, IOCs auto-extracted, path-traversal guard applied.',
            'Files **download** as AES-256 password-protected ZIP. Password: `infected`.',
          ] },
          { type: 'section', title: 'Per-artifact card', items: [
            'Filename, MIME type, size, SHA-256 (truncated, full on hover), uploader, uploaded-at.',
            '**Download** · **Delete** · expand for analysis panel.',
          ] },
          { type: 'section', title: 'Analysis tools (11)', items: [
            '**Hashes · File Type · Strings · IOC Extract · Entropy · PE Analysis · Office/Macro · PDF · Metadata/EXIF · Hex Dump · YARA**.',
            'Click a tool tab to run it; results are cached on the artifact and surfaced inline.',
          ] },
        ],
      },
      {
        id: 'fo-timeline-import',
        title: 'Logs & Triage',
        tags: ['logs & triage', 'timeline import', 'parse', 'evtx', 'sqlite', 'csv', 'jsonl', 'syslog', 'promote', 'tree'],
        body: [
          { type: 'p', text: 'Parse a forensic artifact or a registered exhibit, triage the parsed events, then promote the ones you pick onto the incident timeline with their provenance.' },
          { type: 'section', title: 'Accepted formats', items: [
            '**EVTX · Windows XML · SQLite · CSV/TSV · JSON/JSONL · syslog / auth.log · journald JSON · macOS Unified Log.** Up to 500 MiB.',
          ] },
          { type: 'steps', items: [
            'Choose the source: **Upload a file**, or **From a registered exhibit** — no re-upload; the exhibit must be **active**, in internal custody and not awaiting a transfer.',
            'Choose the **Source timezone** — the zone the log was written in. It applies only to times without a zone; times with UTC or an offset stay as they are. For an exhibit, the recorded device clock note is shown as a hint, with whether a clock offset will be applied.',
            'Click **Parse & save** or **Parse exhibit**. An exhibit is re-hashed first: a mismatch freezes it (**verify_failed**) and nothing is parsed. The import is recorded in the exhibit\u2019s custody log.',
            'Triage, select, then **Add N to Timeline**.',
          ] },
          { type: 'section', title: 'On the page', items: [
            'Summary bar: format, counts, **⛁ exhibit**, source timezone, parser version, and how many times were assumed or inferred.',
            'Filters: free-text search · suspicious-only toggle · per-source dropdown.',
            '**Table / Tree** view toggle.',
            'Per row: timestamp, source, hostname, event type, description, MITRE technique (if inferred), suspicious flag.',
            '**TZ assumed** — the row had no zone and was read in the source timezone. **year inferred** — a BSD syslog line without a year, dated against the exhibit\u2019s acquisition time (else the import time).',
            'Rows with **no timestamp** can be selected and added as IOCs, but they are never placed on the timeline: **Add N to Timeline** counts only the selected rows that have a time.',
            '**offset-corrected (+N s)** — the exhibit records a **Clock offset in seconds**, so the time is the recorded time minus N. Hover for the recorded time. The summary bar shows **Clock offset**.',
            'A warning shows when the offset was **not applied** (recorded only as text) or **changed** after the import; a saved import in that state shows **⚠ clock**. See **Acquisition & Sealing**.',
          ] },
          { type: 'section', title: 'Actions', items: [
            '**Add N to Timeline** — FENRIR copies the events from the stored import, so times come from the parse, not the browser. Events already promoted from this import are skipped.',
            'Promoted events keep their facts as imported; you annotate them on the Timeline (see **Timeline Events**).',
            'Per row: **+ IOC** opens the quick-add modal. IOCs added from an exhibit\u2019s import record that exhibit.',
            '**× dispose** removes a saved import — refused while events promoted from it are on the timeline.',
          ] },
          { type: 'note', text: 'An upload whose SHA-256 equals exactly one active exhibit (with a stored file) of the incident is linked to that exhibit automatically, and that exhibit\u2019s clock offset is applied. With none or several, nothing is linked.' },
          { type: 'note', text: '**Review in Logs & triage** on a collector package links the import to the exhibit its container matched at ingest — see [[fo-collector-packages]].' },
        ],
      },
      {
        id: 'fo-vendor-reports',
        title: 'Vendor Reports',
        tags: ['vendor reports', 'defender', 'defender import', 'microsoft defender', 'xdr', 'pdf', 'run record', 'exhibit', 'clock offset'],
        body: [
          { type: 'p', text: 'Turn a Microsoft Defender XDR incident PDF into candidate IOCs, entities and timeline events, and commit the ones you pick with their provenance.' },
          { type: 'steps', items: [
            'Choose the source: **Upload a PDF** (up to 25 MiB), or **From a registered exhibit** — no re-upload; the exhibit must be **active**, in internal custody and not awaiting a transfer.',
            'Click **Parse PDF** or **Parse exhibit**. An exhibit is re-hashed first: a mismatch freezes it (**verify_failed**) and nothing is parsed. The parse is recorded in the exhibit\u2019s custody log.',
            'Review the candidates. Set each **Destination**: IOC, Entity or Timeline event.',
            'Click **Commit N selected**. FENRIR copies the candidates from the stored import, so the facts come from the parse, not the browser.',
          ] },
          { type: 'section', title: 'Run record', items: [
            'Every import shows its **Input SHA-256**, the **⛁ exhibit** it came from, the **Parser** name and version, and who ran it when.',
            'An uploaded PDF whose SHA-256 equals exactly one exhibit is linked to it automatically. The uploaded copy is also kept in **Malware quarantine**.',
            'Committed IOCs record the exhibit. Committed timeline events record the exhibit, the import and the candidate; their facts are locked as imported.',
          ] },
          { type: 'section', title: 'Times', items: [
            'Times are shown in your timezone, to the second, with the offset. **TZ assumed** — the PDF does not state its UTC offset, so its times were read as UTC.',
            'No clock offset is applied: a Defender incident PDF holds Microsoft cloud times, not the device\u2019s clock. The run record says **Clock offset: Not applicable**, whatever the exhibit records.',
            'A candidate without a time never becomes a timeline event; commit it as an IOC or entity instead.',
          ] },
          { type: 'note', text: 'Committing again skips what is already there: events already promoted from this import, and IOCs or entities already on the incident.' },
          { type: 'note', text: 'Imports made before run records can\u2019t be committed — import the PDF again. **× dispose** is refused while timeline events committed from the import exist.' },
        ],
      },
      {
        id: 'fo-collector-packages',
        title: 'Collector Packages',
        tags: ['collector packages', 'collections', 'velociraptor', 'ingest', 'container', 'sha-256', 'run record', 'exhibit'],
        body: [
          { type: 'p', text: 'Signed, offline Velociraptor collectors for the incident, and the ingest that brings their encrypted output back into FENRIR.' },
          { type: 'steps', items: [
            'Generate a package from a profile and download it once.',
            'Run it on the host. Register the encrypted output container in **Evidence** with the acquisition wizard first — evidence before analysis.',
            'Click **Ingest results** and upload the same container.',
            'Click **Review in Logs & triage** to parse the decrypted collection.',
          ] },
          { type: 'section', title: 'Run record of the ingest', items: [
            'FENRIR hashes the container **exactly as received**, before decrypting it, and shows it as **container …** (hover for the full SHA-256, the decrypted collection\u2019s SHA-256 and the collector version).',
            'When that SHA-256 equals exactly one active exhibit, the package shows its **⛁ exhibit** and the ingest is recorded in the exhibit\u2019s custody log.',
            'Logs & triage imports of the collection are then linked to that exhibit and apply its clock offset.',
          ] },
          { type: 'note', text: 'A container ingested before it was registered as an exhibit stays unlinked. Register first, then ingest. The output can be at most 512 MiB.' },
          { type: 'note', text: '**Review in Logs & triage** re-hashes the quarantined collection first. If it no longer matches the SHA-256 recorded at ingest, nothing is imported or linked (**collection hash mismatch**, audited `forensic_import_rejected`): ingest the output again.' },
        ],
      },
      {
        id: 'fo-osint',
        title: 'OSINT Lookup',
        tags: ['osint', 'whois', 'dns', 'dnsbl', 'asn', 'geoip', 'shodan', 'virustotal', 'abuseipdb', 'greynoise', 'crt.sh', 'passive dns', 'opsec', 'session'],
        body: [
          { type: 'p', text: 'Paste raw text → auto-extract IPv4 / IPv6 / domains / URLs / hashes → enrich selectively against multiple OSINT sources → optionally add results as IOCs.' },
          { type: 'section', title: 'Workflow', items: [
            'Paste log output, alert text, or any free-form text into the textarea.',
            'Click **Extract indicators** — up to 100 indicators are pulled out (private IPs are flagged).',
            'Pick which sources to query (the **SOURCES** bar at the top — toggleable checkboxes).',
            'Click **Enrich** per row, or **Enrich all visible** to batch (sequential, to avoid rate limits).',
            'Click any enriched row to expand and see the per-source result cards.',
            'Tick rows and use **Add N to IOCs** to push selections into the incident IOC list (de-duped server-side).',
          ] },
          { type: 'section', title: 'All 11 enrichment sources', items: [
            '**WHOIS** — registrant / registrar / nameservers / registration & expiry. *(domain)*',
            '**DNS** — A / AAAA / CNAME / MX / NS / TXT / SOA. *(domain)*',
            '**DNSBL** — checks ~20 RBL zones for spam / malware listings. *(ip)*',
            '**Passive DNS** — historical resolutions with first/last seen. *(ip, domain)*',
            '**ASN** — AS number, holder, prefix. *(ip)*',
            '**GeoIP** — city / region / country, ISP, org, rDNS, proxy/hosting/mobile flags. *(ip)*',
            '**crt.sh** — Certificate Transparency lookup: total certs, subdomains, recent certificates with SANs. *(domain)*',
            '**Shodan** — org, ISP, ASN, country, open ports, tags. *(ip)* — API key required.',
            '**GreyNoise** — internet-scanner classification (malicious / benign / unknown), noise / RIOT flags. *(ip)* — API key required.',
            '**AbuseIPDB** — abuse confidence score, report count, last seen, usage type, Tor exit flag. *(ip)* — API key required.',
            '**VirusTotal** — engine verdicts (X / Y malicious), file/IP/domain/URL details. *(hash, ip, domain, url)* — API key required.',
          ] },
          { type: 'section', title: 'OPSEC', items: [
            'Public sources (VirusTotal etc.) display a **⚠ PUBLIC** marker — your submitted indicator may be logged and visible to third parties.',
            'When any public source is enabled, a yellow warning banner sits above the input area.',
            'Default-on: all available non-public sources. Public ones are off until you opt in.',
          ] },
          { type: 'section', title: 'Sessions', items: [
            'Each Extract creates a saved session — raw text, extracted indicators, and any enrichment results persist across reloads.',
            '**SAVED SESSIONS** list at the bottom: timestamp · indicator count · enriched flag · creator. **Load** to switch, **×** to delete.',
          ] },
          { type: 'note', text: 'Sources without an API key show greyed out and labelled `(no key)`. Configure keys in Settings → API Keys.' },
        ],
      },
    ],
  },
  {
    id: 'comms',
    icon: '✉',
    label: 'Communications',
    color: '#f43f5e',
    desc: 'Comments, OOB, Stakeholders, War Room',
    articles: [
      {
        id: 'co-comments',
        title: 'Comments & OOB',
        tags: ['comment', 'oob', 'out-of-band', 'dark', 'passphrase'],
        body: [
          { type: 'section', title: 'Comments', items: [
            'Free-text @-mention thread per incident. Mentions deliver notifications.',
          ] },
          { type: 'section', title: 'OOB (Out-of-Band)', items: [
            'For incidents where the platform itself may be compromised. Switch the incident to **Dark Operation** mode — banner appears, communication blackout in effect. To start dark, tick **Open as Dark Operation** when you create the incident.',
            'Blocked while dark: every Teams, Slack and alert-mailbox message about the incident. Each one is listed in the incident audit log as `outbound_notification_suppressed` and is not sent later.',
            'Also blocked: the automatic DNS checks (SPF, DKIM, DMARC) of an analyzed email\'s sender domain. Each skipped check is listed in the incident audit log as `outbound_lookup_suppressed`, and the analysis shows **Live DNS checks skipped — Dark Operation**.',
            'TLP:RED blocks the same automatic channels, with reason `tlp_red`; the header then shows **Automatic outbound suppressed (TLP:RED)**.',
            'Manual lookups — OSINT, IOC enrichment, the email **Domain auth check** — still run under Dark Operation or TLP:RED, but only after you confirm a warning. Each one is listed in the audit log as `outbound_manual_lookup`.',
            'Still on: in-app notifications to people who can see the incident, syslog audit forwarding (actions and IDs only), and admin test messages.',
            'Each OOB passphrase generation is logged. Use it on the external channel agreed with stakeholders.',
            'OOB log records what was communicated and through which channel.',
          ] },
        ],
      },
      {
        id: 'co-stakeholders',
        title: 'Stakeholder Registry',
        tags: ['stakeholder', 'contact', 'csv', 'bulk import', 'communication method'],
        body: [
          { type: 'p', text: 'Per-incident contact list. Track who to notify and how, per incident.' },
          { type: 'section', title: 'Per-stakeholder', items: [
            '**Type** — internal / legal / regulatory / law enforcement / media / vendor / IR firm / customer / insurer / board / supervisory authority / CSIRT / other.',
            '**Contact methods** — multiple (phone, email, Signal, etc.).',
            '**Available hours** — free-text (e.g. "24/7 hotline").',
            '**Notes** — free-text.',
          ] },
          { type: 'note', text: 'Bulk import via CSV (header row required). Preview before commit.' },
          { type: 'note', text: '**Add from directory** copies a contact from the Contacts directory into the incident — see [[co-contacts]].' },
        ],
      },
      {
        id: 'co-contacts',
        title: 'Contacts Directory',
        tags: ['contacts', 'directory', 'supervisory authority', 'csirt', 'police', 'insurer', 'retainer', 'pr', 'verify', 'prepare'],
        body: [
          { type: 'p', text: 'The organisation\'s external contacts, prepared before an incident: open **Prepare → Contacts**. Admins and analysts can read it; only admins add, edit, verify or delete.' },
          { type: 'section', title: 'The six key contacts', items: [
            'Supervisory authority · national CSIRT · police cyber unit (type **Law Enforcement**) · insurer · IR retainer (type **IR Firm**) · PR (type **Media / PR**).',
            'Readiness warns while one is missing or any of them was not verified in the last 90 days (NIST CSF 2.0 `RS.CO-03`).',
          ] },
          { type: 'steps', items: [
            'Check that the entry is still right: call the number or confirm the address.',
            'Click **Mark verified** on its card. Fenrir records the server time and your name; neither can be typed in.',
          ] },
          { type: 'section', title: 'Using it on an incident', items: [
            'Incident → **Comms & stakeholders** → **Stakeholders** → **Add from directory**, then **Add** on a contact.',
            'The incident gets its own copy. Editing or deleting the directory entry later does not change the case record.',
          ] },
          { type: 'note', text: 'MCP: `fenrir_people_list(view="contacts")`, `fenrir_people_write(action="contact_add" / "contact_update" / "contact_verify")`, `fenrir_comms_write(action="stakeholder_add", data={contact_id})` · API: `/api/contacts`.' },
        ],
      },
      {
        id: 'co-matrix',
        title: 'Stakeholder Matrix',
        tags: ['matrix', 'banner', 'notification', 'required', 'severity', 'sla'],
        body: [
          { type: 'p', text: 'Org-wide rules: "for incidents of severity X, role Y must be notified within Z minutes." Distinct from the per-incident Stakeholder Registry — this is policy, applied to every incident.' },
          { type: 'section', title: 'Where to manage', items: [
            'Settings → **Stakeholder Matrix** (admin-only). Per-severity tables with role / notify-within / category / required-vs-advisory.',
          ] },
          { type: 'section', title: 'Where it shows up', items: [
            '**Incident Details** — banner at the top lists required notifications for that incident\'s severity.',
            '**Comms tab** — same banner, above the sub-tabs.',
          ] },
          { type: 'note', text: 'Only rules marked **Required** appear in the banner. Advisory rules are visible only in the Matrix page.' },
        ],
      },
      {
        id: 'co-warroom',
        title: 'War Room',
        tags: ['warroom', 'chat', 'ws', 'websocket', 'mention', 'drawer'],
        body: [
          { type: 'p', text: 'Persistent per-incident chat over WebSocket. Mentions (`@username`) deliver notifications.' },
          { type: 'section', title: 'The War Room tab', items: [
            'Pinned to the right edge on incident pages. Click to open/close the drawer.',
            'Press-and-hold (or drag past ~18 px) to reposition the tab vertically; the position persists per browser.',
          ] },
        ],
      },
    ],
  },
  {
    id: 'post-incident',
    icon: '⏲',
    label: 'Post-Incident',
    color: '#84cc16',
    desc: 'Analytics, closure, lessons, attack chain, reports',
    articles: [
      {
        id: 'pi-analytics',
        title: 'Analytics',
        tags: ['analytics', 'ttd', 'ttc', 'ttr', 'metrics', 'stats', 'bar chart'],
        body: [
          { type: 'p', text: 'Quantitative view of the incident. Computed on demand from the live data.' },
          { type: 'section', title: 'Top stat cards', items: [
            '**Time to Detect (TTD)** — occurred → detected.',
            '**Time to Contain (TTC)** — detected → contained.',
            '**Time to Recover (TTR)** — detected → recovered.',
            'Without a Detected time, TTC and TTR start at created; without a Recovered time, TTR ends at closed. The card shows which. A negative interval shows as — and the card says **excluded**. The Dashboard and Metrics MTTD / MTTC / MTTR average the same intervals and show **n excluded** for incidents left out (a time missing, or an interval that runs backwards).',
            '**IOCs · Entities (with compromised count) · Playbook %**.',
          ] },
          { type: 'section', title: 'Bar charts', items: [
            'IOCs by type · Entities by type · Timeline events by IR phase (with MITRE-mapped count) · Playbook tasks by status.',
            '**Respond actions** grid — Containment / Eradication / Recovery split by done · in-progress · open · deferred.',
            '**Evidence** breakdown by kind.',
          ] },
        ],
      },
      {
        id: 'pi-closure',
        title: 'Closure Checklist',
        tags: ['closure', 'checklist', 'add', 'delete', 'custom', 'assign'],
        body: [
          { type: 'p', text: 'Seeded with 12 standard items (containment verified, accounts remediated, evidence preserved, etc.). Each item is assignable to a user and supports a notes field.' },
          { type: 'section', title: 'Custom items', items: [
            '**+ Add item** at the top adds a custom checklist row.',
            'The trash button (✕) on any row deletes it. Defaults that you delete won\'t reappear — they\'re soft-deleted per-incident.',
          ] },
          { type: 'note', text: 'All add / delete / toggle / assign actions are audit-logged.' },
          { type: 'note', text: '**Close** ticks **Incident formally closed** and **Re-open** unticks it. A closed incident\'s checklist is read-only.' },
        ],
      },
      {
        id: 'pi-lessons',
        title: 'Lessons Learned',
        tags: ['lessons', 'rca', 'effectiveness', 'action items', 'control improvements'],
        body: [
          { type: 'p', text: 'Structured post-incident review aligned with 800-61 R3 §4 (Post-Incident Activity).' },
          { type: 'section', title: 'Sections', items: [
            '**Review metadata** — conducted-by, participants, date.',
            '**Incident narrative** — markdown.',
            '**Root cause** — categorised (unpatched system / misconfig / human error / etc.) + free text.',
            '**Effectiveness** — 6-dimension rating (Detection / Containment / Comms / Roles / Plan / Docs).',
            '**Observations** — what went well, friction points, near-misses.',
            '**Timeline metrics** — detection / escalation / containment / comms / remediation in minutes.',
            '**Action items** — owner, due date, priority, status.',
            '**Control improvements** — preventive / detective / corrective / process / training.',
          ] },
          { type: 'note', text: 'Export as a standalone HTML for distribution. Status flips from Draft → Final when finalised.' },
          { type: 'note', text: 'After the incident is closed, only **Action items** can be edited (**Save action items**); everything else is read-only until it is re-opened.' },
        ],
      },
      {
        id: 'pi-attack-chain',
        title: 'Attack Chain',
        tags: ['attack chain', 'swimlane', 'mitre', 'kill chain', 'sequence'],
        body: [
          { type: 'p', text: 'Visual reconstruction of the attack, driven by MITRE-tagged timeline events ([[tl-mitre]]).' },
          { type: 'section', title: 'On the page', items: [
            '**Swimlane diagram** — one lane per observed tactic, in canonical ATT&CK order; events plotted on a left-to-right time axis with dashed connectors.',
            'Each event is a coloured dot — hover for time, technique ID, description.',
            'Time axis with 5 evenly-spaced ticks across the incident span.',
            '**Chronological list** below — every MITRE-tagged event, ordered by time, with technique ID and hostname.',
          ] },
          { type: 'note', text: 'If no events are MITRE-tagged, the page tells you so — tag events from the Timeline tab to build the chain.' },
        ],
      },
      {
        id: 'pi-reports',
        title: 'Reports',
        tags: ['report', 'pdf', 'html', 'executive', 'full', 'post-incident', 'le package', 'sha-256', 'template', 'figures', 'screenshots', 'communications log', 'sign-off', 'csf', 'nciss'],
        body: [
          { type: 'p', text: 'Generate, preview, and download incident reports. All persist to history.' },
          { type: 'section', title: 'Template picker', items: [
            '**Executive Summary** — key facts, KPIs, MITRE tactics, lessons, recommendations. No raw IOC values, no full timeline.',
            '**Full Technical Report** — every section: complete IOC table, timeline, entities, respond actions, playbook, evidence.',
            '**Post-Incident Report** — formal closure report (lessons learned, remediation roadmap, what worked / could improve).',
          ] },
          { type: 'section', title: 'Customisation', items: [
            'Mode: HTML or PDF.',
            'Custom logo upload.',
            'Custom footer text.',
            '**Remediation roadmap** is split into Short-term (0–30 days) · Medium-term (30–90 days) · Long-term (90+ days).',
            '**Preview structure** button shows the report skeleton with autogen-field placeholders.',
          ] },
          { type: 'section', title: 'Figures, comms log, sign-off, standards', items: [
            '**Figures** — screenshots ticked **Include in report** in Supporting documents ([[iw-files]]), numbered, with caption and the SHA-256 of the original file. Images over 1.5 MiB are downscaled to 1920 px; embedded images are capped at 7 MiB, and you are warned before saving if figures go over it.',
            '**Communications & Notification Log** (full report only) — the out-of-band log. Never the passphrase or anyone\'s contact details.',
            '**Approval & Sign-off** — who closed the incident, when, the close statement, and a signature line for Incident Commander, Deputy, Legal Liaison and DPO.',
            'Every section shows its **NIST CSF 2.0** subcategory IDs. Severity also shows the **NCISS** level: Critical → Emergency, High → Severe, Medium → Medium, Low → Low.',
          ] },
          { type: 'section', title: 'Report History', items: [
            'Every generated report is persisted with template ID and SHA-256 footer for tamper-evidence.',
            'Re-download requires entering a reason — logged in the audit trail.',
          ] },
        ],
      },
      {
        id: 'pi-le-package',
        title: 'Law-Enforcement Package',
        tags: ['le package', 'law enforcement', 'aes-256', 'one-time', 'key', 'download url', 'forensic'],
        body: [
          { type: 'p', text: 'One-click bundle for handing the incident to law enforcement: full report + timeline + IOCs + artifact manifest + audit chain in a single AES-256-encrypted ZIP.' },
          { type: 'section', title: 'Generate flow', items: [
            'Click **Generate LE package**.',
            'The system produces the bundle and shows the AES-256 key + a single-use download URL **ONCE**.',
            'Copy both — they are not stored and cannot be retrieved later.',
          ] },
          { type: 'section', title: 'After generation', items: [
            'Download URL is single-use and expires after 24 hours.',
            'Decryption instructions are displayed (OpenSSL / 7-Zip commands).',
            'Lives in Post-Incident → Reports tab alongside other generated artefacts.',
          ] },
          { type: 'note', text: '`02_Timeline/Timeline.csv` ends with provenance columns: exhibit, its SHA-256, parser name and version, time basis, the import run, the time the device recorded and the clock offset applied. New columns are only ever appended.' },
          { type: 'section', title: 'Unsealed drafts', items: [
            'By default an exhibit whose chain of custody is not sealed is left out: `Evidence_Inventory.csv` lists it as `excluded: unsealed draft`, with no custody log or file.',
            'Tick **Include unsealed drafts** (incident lead or **Admin**, as for the package itself) to put them in; the choice is recorded on the package\u2019s audit anchor.',
            'The inventory has `coc_sealed`, `coc_sealed_at_utc`, `lawful_basis` and `package_inclusion` columns. After the build the page lists the drafts left out.',
          ] },
          { type: 'note', text: 'Exhibits of any size are streamed into the package. A multi-GiB package takes minutes: wait for the result, which is the only place the key appears.' },
          { type: 'note', text: 'An exhibit whose stored file fails its integrity check while the package is built is listed as `integrity_failed:<reason>` (or `HASH_MISMATCH_AT_EXPORT` for a different SHA-256), with no file, and is frozen (**verify failed**); the page names it. If a file changes while it is being written into the package, nothing is built.' },
          { type: 'note', text: 'Treat the AES-256 key like a one-time passphrase — share via OOB channels with the LE recipient, never in-band.' },
        ],
      },
    ],
  },
  {
    id: 'settings',
    icon: '⚙',
    label: 'Settings & Admin',
    color: '#94a3b8',
    desc: 'Account, themes, users, feeds, tokens, audit',
    articles: [
      {
        id: 'st-account',
        title: 'Account, Themes, Timezone',
        tags: ['account', 'theme', 'timezone', 'tz', 'password'],
        body: [
          { type: 'section', title: 'Themes', items: [
            '**Mission Control** (default) — dense dark, cyan/amber, JetBrains Mono. Operations posture.',
            '**Nordic Calm** — light, Linear-style. Calm investigation / report-writing posture.',
            '**Aurora Night** — vibrant glass dark. Demo / showcase.',
          ] },
          { type: 'section', title: 'Timezone', items: [
            'TZ picker is in the top bar. All persisted timestamps are UTC; the UI renders in your chosen TZ with the offset visible.',
          ] },
        ],
      },
      {
        id: 'st-users',
        title: 'Users, Teams, Operational Roles',
        tags: ['user', 'team', 'role', 'operational', 'admin'],
        body: [
          { type: 'p', text: 'Admin-only sections.' },
          { type: 'section', title: 'Users', items: [
            'Create / disable users. Set RBAC role (Admin / Analyst / Responder / Observer).',
            'Reset passwords. Force-rotate sessions.',
          ] },
          { type: 'section', title: 'Operational roles', items: [
            'Distinct from RBAC. These are *response* roles assignable per incident. Seeded on every install: Incident Commander, Deputy Incident Commander, Lead Investigator, Communications Lead, Legal Liaison, Recorder, Data Protection Officer.',
            '**Data Protection Officer** — assesses personal-data impact and advises on GDPR breach notification. Readiness blocks while the role is inactive.',
          ] },
        ],
      },
      {
        id: 'st-tokens',
        title: 'API Tokens',
        tags: ['api', 'token', 'bearer', 'mcp', 'integration', 'script'],
        body: [
          { type: 'p', text: 'For MCP clients, scripts, and integrations. Both browser cookies and Bearer tokens resolve to the same User and the same RBAC.' },
          { type: 'steps', items: [
            'Settings → **API Keys** (admin only).',
            '**+ Create token** — name it, set expiry, choose scopes (defaults to the creating user\'s role).',
            'Copy the token *immediately* — it\'s only shown once.',
            'Use as `Authorization: Bearer <token>` against any `/api/...` endpoint.',
          ] },
          { type: 'note', text: 'Revoke any token with one click. Token usage is audit-logged separately from cookie sessions.' },
        ],
      },
      {
        id: 'st-audit-export',
        title: 'Signed Audit Export',
        tags: ['audit', 'export', 'ed25519', 'signature', 'compliance'],
        body: [
          { type: 'p', text: 'The audit log is a tamper-evident hash chain. Exports are Ed25519-signed + ReportLab PDF + AES-256 ZIP; bundles expire after 30 days.' },
          { type: 'section', title: 'Verifying an export', items: [
            'Each bundle includes the public key fingerprint and the detached signature.',
            'The Public Key PEM is exposed unauthenticated at `/api/version` for downstream verifiers.',
          ] },
        ],
      },
      {
        id: 'set-time',
        title: 'Time Entry & Display',
        tags: ['time', 'utc', 'timezone', 'iso 8601', 'datetime', 'date'],
        body: [
          { type: 'p', text: 'FENRIR follows one timestamp rule: store in UTC, 24-hour, ISO-8601; enter and display in your zone with the offset shown.' },
          { type: 'section', title: 'How it works', items: [
            'Every date + time field opens the same picker: a month calendar and hour / minute / second drums, 24-hour — never a locale or AM/PM format.',
            'Enter the time in your FENRIR timezone (default) or switch the picker to UTC. It shows both: `YYYY-MM-DD HH:MM:SS ±HH:MM` and the stored UTC value (`…Z`).',
            'Nothing changes until you click **Apply** (or press Enter); **Cancel**, Esc or a click outside discards. **Clear** empties an optional field.',
            'A filter over data shown in UTC (e.g. **Browser history**) starts on the UTC side.',
            'Read-only timestamps render in your stored timezone with the offset visible (e.g. `2026-06-14 10:00:00 +02:00`).',
            'Set your timezone under **Settings → Account** (see **Account, Themes, Timezone**).',
          ] },
          { type: 'note', text: 'Persisted and transmitted values are always UTC (`…Z`); only the display edge is localised.' },
        ],
      },
      {
        id: 'set-integrations',
        title: 'Integrations & Feeds',
        tags: ['integrations', 'feeds', 'threat intel', 'webhook', 'syslog', 'admin'],
        body: [
          { type: 'p', text: 'Admin configuration for outside data and destinations — under **Settings** (admin only).' },
          { type: 'section', title: 'What you can configure', items: [
            '**Feeds** — threat-intel sources that enrich IOCs and drive cross-incident correlations.',
            '**Integrations** — outbound connections such as a syslog forwarder for audit rows (TLS 1.3, HMAC where applicable).',
          ] },
        ],
      },
      {
        id: 'set-storage',
        title: 'Storage',
        tags: ['storage', 'disk', 'volumes', 'evidence', 'admin'],
        body: [
          { type: 'p', text: 'Admin view of storage usage across the platform volumes (quarantine, evidence, reports, backups).' },
          { type: 'note', text: 'Evidence and backups are encrypted at rest. For continuity and recovery see **Backup & Restore** in **Evidence & Chain of Custody**.' },
        ],
      },
    ],
  },
]

// ── FAQs ────────────────────────────────────────────────────────────────────

const FAQS = [
  {
    q: 'I forgot the password for the AES-256 quarantine ZIP.',
    a: 'The password is always `infected` (lowercase). This is the malware-analyst convention — prevents AV from auto-executing the file when extracted.',
    tags: ['password', 'zip', 'quarantine', 'infected'],
  },
  {
    q: 'Why is my IOC showing as "Unknown" instead of Clean?',
    a: 'Auto-extracted IOCs (from artifact uploads, PCAP analysis, etc.) default to Unknown because no analyst has reviewed them yet. Use the Mark Clean / Mark Malicious buttons in the expanded row to set the status.',
    tags: ['ioc', 'unknown', 'clean', 'malicious', 'mark', 'status'],
  },
  {
    q: 'Where does the Stakeholder Matrix banner come from?',
    a: 'It pulls the global rules from Settings → Stakeholder Matrix and filters by the current incident\'s severity AND `required = true`. Add or edit rules in Settings (admin only). The banner shows on both Incident Details and the Comms tab.',
    tags: ['matrix', 'banner', 'stakeholder', 'notification', 'severity'],
  },
  {
    q: 'How do I delete a default checklist item without it coming back?',
    a: 'Click the ✕ next to the item. FENRIR soft-deletes the row (marks it inactive) instead of hard-deleting, so the seed loop won\'t resurrect dismissed defaults on next page load.',
    tags: ['checklist', 'delete', 'soft delete', 'default'],
  },
  {
    q: 'Can I move the War Room tab?',
    a: 'Yes — press-and-hold the tab for ~250 ms, or drag at least 18 px, to enter drag mode. Quick clicks still open/close the drawer. Position persists per browser.',
    tags: ['warroom', 'tab', 'drag', 'reposition'],
  },
  {
    q: 'Why are timestamps shown in my browser TZ but not the picker TZ?',
    a: 'Most surfaces use the persisted TZ from the picker. If you spot one that uses raw `toISOString()` (browser TZ or UTC), report it as a bug — every UI-rendered time should respect the picker.',
    tags: ['timezone', 'tz', 'utc', 'time'],
  },
  {
    q: 'Do I enter a time in UTC or in my local time?',
    a: 'Either. The date/time picker starts in your FENRIR timezone and has a switch for UTC; it shows the time with its offset and the UTC value that is stored, 24-hour, `YYYY-MM-DD HH:MM:SS`. Pick the date and time, then click **Apply**. Stored values are always UTC; read-only times are shown in your zone with the offset.',
    tags: ['utc', 'datetime', 'time', 'entry', 'iso 8601'],
  },
  {
    q: 'How do I integrate FENRIR with my MCP client?',
    a: 'Issue a Bearer token in Settings → API Keys, then point your MCP server at `https://<your-host>/api/openapi.json`. Every endpoint is API-first — no feature is browser-only.',
    tags: ['mcp', 'api', 'token', 'bearer', 'openapi'],
  },
  {
    q: 'What is "Dark Operation" mode?',
    a: 'A flag set on the incident header that signals "the platform may be compromised — switch to OOB". While it is on, nothing about the incident goes to Teams, Slack or the alert mailbox, and email analysis skips its automatic DNS checks (SPF, DKIM, DMARC) of the sender\'s domain; each blocked message or check is listed in the incident audit log and is not sent or run later. TLP:RED blocks the same channels. In-app notifications still reach people who can see the incident; OSINT lookups, IOC enrichment and the email **Domain auth check** run only after you confirm a warning, and are audited. The UI shows a red banner across every tab and the theme is locked to Mission Control. Turn it on in Comms → **OOB**, or tick **Open as Dark Operation** when you create the incident. Use OOB → Passphrase + Log to coordinate over external channels.',
    tags: ['dark operation', 'oob', 'compromise', 'teams', 'slack', 'email', 'dns', 'suppressed'],
  },
  {
    q: 'Where is the audit log?',
    a: 'On each incident: Audit Log tab (admin-only). Global audit: Admin → Global Audit Log. Audit exports (Ed25519-signed) are under Admin → Audit Exports.',
    tags: ['audit', 'log', 'compliance'],
  },
  {
    q: 'How do I verify a generated report wasn\'t tampered with?',
    a: 'Each report has a SHA-256 footer. Recompute the SHA-256 of the downloaded file (excluding the footer placeholder); it must match the value in the footer.',
    tags: ['report', 'sha-256', 'integrity', 'tamper'],
  },
  {
    q: 'Which OSINT sources can I query, and which need an API key?',
    a: 'Eleven sources are wired in. Key-free: WHOIS, DNS, DNSBL, Passive DNS, ASN, GeoIP, crt.sh. Key-required: Shodan, GreyNoise, AbuseIPDB, VirusTotal. Configure keys in Settings → API Keys. Sources without a key appear greyed out and labelled "(no key)" in the SOURCES bar at Examine → OSINT.',
    tags: ['osint', 'sources', 'api key', 'whois', 'shodan', 'virustotal'],
  },
  {
    q: 'Why is one of my OSINT sources marked "⚠ PUBLIC"?',
    a: 'Sources flagged PUBLIC (e.g. VirusTotal) log your queries and may make the submitted indicator visible to third parties. If the indicator is sensitive (an internal asset, an unburned C2), disable the source before enriching. Public sources are off by default; only non-public sources are enabled when the page loads.',
    tags: ['osint', 'opsec', 'public', 'virustotal', 'leak'],
  },
  {
    q: 'Where do I parse an EVTX or syslog file?',
    a: 'Examine → Logs & triage. Drop the file in (EVTX, Windows XML, SQLite, CSV/TSV, JSON/JSONL, syslog/auth.log, journald JSON, macOS Unified Log — up to 500 MiB), click Parse, tick the rows you want, then **Add N to Timeline**. Rows without a timestamp are never placed on the timeline; add them as IOCs instead.',
    tags: ['evtx', 'syslog', 'timeline import', 'parse', 'forensic'],
  },
  {
    q: 'Where is the Law-Enforcement package?',
    a: 'Post-Incident → Reports → LE Package. Clicking Generate shows the AES-256 key and a single-use 24-hour download URL ONCE — copy both before closing. Share the key out-of-band, never in-band with the URL.',
    tags: ['le package', 'law enforcement', 'aes-256', 'download'],
  },
  {
    q: 'Why is the right-edge War Room tab on every incident page?',
    a: 'War Room is pinned at the incident scope, so every page inside the incident can open it. Press-and-hold or drag at least 18 px to reposition vertically — position persists per browser.',
    tags: ['warroom', 'drawer', 'tab', 'pinned'],
  },
  {
    q: 'How do I revert a completed Respond action?',
    a: 'Open the action card on the Respond Kanban board → Revert button. A modal asks for the reason; the revert is audit-logged. The card moves back to in-progress.',
    tags: ['respond', 'revert', 'kanban', 'action'],
  },
  {
    q: 'How do I initialise the Legal regulatory deadlines?',
    a: 'Go to the Legal tab → Initialize deadlines. Pick the applicable regulations (GDPR, NIS2, DORA, PCI-DSS, HIPAA, CCPA) and check the Anchor — it defaults to the incident\'s Detected time; give a regulation its own anchor if its awareness moment differs. Deadlines count from the anchor, the header shows a countdown chip per regulation, and in-app reminders arrive 12 h and 2 h before and when overdue. Initialising again only adds what is missing. Add anything outside the standard list with + Add custom.',
    tags: ['legal', 'gdpr', 'nis2', 'dora', 'deadline', 'anchor', 'reminder'],
  },
  {
    q: 'What\'s the difference between an Operational Role and an RBAC role?',
    a: 'RBAC roles (Admin / Analyst / Responder / Observer) gate what you can do in the platform. Operational roles (Incident Commander, Forensic Lead, etc.) are per-incident response responsibilities assigned in the Assignments tab. The Role Coverage widget there shows which seats are empty.',
    tags: ['role', 'rbac', 'operational', 'assignments', 'cisa'],
  },
]

// ── Search index ────────────────────────────────────────────────────────────

function buildIndex() {
  const index = []
  CATEGORIES.forEach(cat => {
    cat.articles.forEach(art => {
      const text = [
        art.title,
        ...(art.tags || []),
        ...art.body.flatMap(b => {
          if (b.type === 'p')              return [b.text]
          if (b.items)                     return b.items
          if (b.rows)                      return b.rows.flat()
          if (b.text)                      return [b.text]
          return []
        }),
      ].join(' ').toLowerCase()
      index.push({
        type: 'article', catId: cat.id, catLabel: cat.label,
        catColor: cat.color, catIcon: cat.icon, id: art.id, title: art.title, text,
      })
    })
  })
  FAQS.forEach((faq, i) => {
    index.push({
      type: 'faq', id: `faq-${i}`, title: faq.q,
      text: [faq.q, faq.a, ...(faq.tags || [])].join(' ').toLowerCase(),
    })
  })
  return index
}

const SEARCH_INDEX = buildIndex()

function searchIndex(q) {
  if (!q || q.length < 2) return []
  const words = q.toLowerCase().split(/\s+/).filter(Boolean)
  return SEARCH_INDEX.filter(item => words.every(w => item.text.includes(w))).slice(0, 10)
}

// ── Inline markdown renderer (bold **text** only) ───────────────────────────

function renderInline(text) {
  const parts = String(text).split(/\*\*([^*]+)\*\*/g)
  return parts.map((p, i) => i % 2 === 1
    ? <strong key={i} style={{ color: 'var(--text)' }}>{p}</strong>
    : <span key={i}>{p}</span>)
}

function ArticleBody({ body }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      {body.map((block, i) => {
        if (block.type === 'p') return (
          <p key={i} style={{ fontSize: 13, color: 'var(--muted)', lineHeight: 1.7, margin: 0 }}>
            {renderInline(block.text)}
          </p>
        )
        if (block.type === 'section') return (
          <div key={i}>
            <div style={{
              fontSize: 11, fontWeight: 700, color: 'var(--dim)',
              letterSpacing: '0.1em', textTransform: 'uppercase',
              marginBottom: 6,
            }}>{block.title}</div>
            <ul style={{ margin: 0, paddingLeft: 18, display: 'flex', flexDirection: 'column', gap: 4 }}>
              {block.items.map((item, j) => (
                <li key={j} style={{ fontSize: 13, color: 'var(--muted)', lineHeight: 1.6 }}>
                  {renderInline(item)}
                </li>
              ))}
            </ul>
          </div>
        )
        if (block.type === 'steps') return (
          <div key={i} style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            {block.items.map((item, j) => (
              <div key={j} style={{ display: 'flex', gap: 10, alignItems: 'flex-start' }}>
                <div style={{
                  width: 20, height: 20, borderRadius: '50%',
                  background: 'var(--accent)', color: 'var(--accent-fg, #000)',
                  fontSize: 11, fontWeight: 700,
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  flexShrink: 0, marginTop: 2,
                }}>{j + 1}</div>
                <div style={{ fontSize: 13, color: 'var(--muted)', lineHeight: 1.6, flex: 1 }}>
                  {renderInline(item)}
                </div>
              </div>
            ))}
          </div>
        )
        if (block.type === 'table') return (
          <div key={i} style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
              <thead>
                <tr>
                  {block.headers.map(h => (
                    <th key={h} style={{
                      textAlign: 'left', padding: '6px 10px',
                      borderBottom: '2px solid var(--border)',
                      color: 'var(--dim)', fontWeight: 700,
                      letterSpacing: '0.06em', textTransform: 'uppercase',
                      fontSize: 10,
                    }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {block.rows.map((row, ri) => (
                  <tr key={ri}>
                    {row.map((cell, ci) => (
                      <td key={ci} style={{
                        padding: '6px 10px',
                        borderBottom: '1px solid var(--border)',
                        color: 'var(--muted)', lineHeight: 1.5,
                        verticalAlign: 'top',
                      }}>{renderInline(cell)}</td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )
        if (block.type === 'phase-legend') return (
          <div key={i} style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            {PHASE.map((p, j) => (
              <div key={p.value} style={{ display: 'flex', alignItems: 'baseline', gap: 10, fontSize: 13, color: 'var(--muted)' }}>
                <span className="phase-glyph" aria-hidden="true"
                      style={{ color: p.color, width: 16, textAlign: 'center', marginRight: 0, flexShrink: 0 }}>{p.glyph}</span>
                <strong style={{ color: 'var(--text)' }}>{p.label}</strong>
                <span>{block.items[j]}</span>
              </div>
            ))}
          </div>
        )
        if (block.type === 'note') return (
          <div key={i} style={{
            padding: '10px 14px',
            background: 'color-mix(in srgb, var(--accent) 8%, transparent)',
            border: '1px solid color-mix(in srgb, var(--accent) 25%, transparent)',
            borderLeft: '3px solid var(--accent)',
            borderRadius: 'var(--radius-sm)',
            fontSize: 12, color: 'var(--muted)', lineHeight: 1.6,
          }}>
            <strong style={{ color: 'var(--accent)' }}>Note:</strong> {renderInline(block.text)}
          </div>
        )
        return null
      })}
    </div>
  )
}

// ── Main page ───────────────────────────────────────────────────────────────

export default function Help() {
  const [query,         setQuery]         = useState('')
  const [suggestions,   setSuggestions]   = useState([])
  const [showSugg,      setShowSugg]      = useState(false)
  const [searchResults, setSearchResults] = useState(null)
  const [activeCat,     setActiveCat]     = useState(null)
  const [activeArt,     setActiveArt]     = useState(null)
  const [openFaq,       setOpenFaq]       = useState(null)
  const searchRef = useRef(null)

  const showCategoryGrid = searchResults === null && !activeCat

  useEffect(() => {
    if (query.length >= 2) {
      const res = searchIndex(query)
      setSuggestions(res)
      setShowSugg(res.length > 0)
    } else {
      setSuggestions([])
      setShowSugg(false)
    }
  }, [query])

  function onSubmit(e) {
    e.preventDefault()
    if (!query.trim()) { setSearchResults(null); return }
    setSearchResults(searchIndex(query))
    setShowSugg(false)
    setActiveCat(null)
    setActiveArt(null)
  }

  function openFromSuggestion(item) {
    setShowSugg(false)
    setSearchResults(null)
    if (item.type === 'article') {
      const cat = CATEGORIES.find(c => c.id === item.catId)
      const art = cat?.articles.find(a => a.id === item.id)
      setActiveCat(cat)
      setActiveArt(art)
    } else {
      const idx = FAQS.findIndex((_, i) => `faq-${i}` === item.id)
      setActiveCat(null)
      setActiveArt(null)
      setOpenFaq(idx)
      setTimeout(() =>
        document.getElementById(`faq-${idx}`)?.scrollIntoView({ behavior: 'smooth', block: 'center' }),
      100)
    }
    setQuery('')
  }

  return (
    <div style={{ maxWidth: 960, margin: '0 auto' }}>

      {/* ── Hero + search ─────────────────────────────────────────────── */}
      <div style={{ textAlign: 'center', marginBottom: 'var(--space-5)', paddingTop: 'var(--space-3)' }}>
        <div style={{
          fontFamily: 'var(--font-heading)',
          fontSize: 26, fontWeight: 700,
          letterSpacing: '0.06em', textTransform: 'uppercase',
          marginBottom: 6, color: 'var(--text)',
        }}>
          Help & Documentation
        </div>
        <div style={{ fontSize: 13, color: 'var(--muted)', marginBottom: 'var(--space-4)' }}>
          DFIR-FENRIR v2 — Incident Response Platform
        </div>

        <form onSubmit={onSubmit} style={{ position: 'relative', maxWidth: 560, margin: '0 auto' }}>
          <div style={{ display: 'flex', gap: 0 }}>
            <input
              ref={searchRef}
              className="input"
              value={query}
              onChange={e => setQuery(e.target.value)}
              onFocus={() => suggestions.length > 0 && setShowSugg(true)}
              onBlur={() => setTimeout(() => setShowSugg(false), 150)}
              placeholder="Search — e.g. 'mark malicious', 'YARA scan', 'stakeholder matrix'…"
              autoComplete="off"
              style={{ flex: 1, borderRadius: 'var(--radius) 0 0 var(--radius)' }}
            />
            <button type="submit" className="btn primary"
                    style={{ borderRadius: '0 var(--radius) var(--radius) 0', fontSize: 12 }}>
              Search
            </button>
          </div>

          {showSugg && (
            <div style={{
              position: 'absolute', top: '100%', left: 0, right: 0, zIndex: 50,
              background: 'var(--surface)',
              border: '1px solid var(--border)',
              borderRadius: '0 0 var(--radius) var(--radius)',
              boxShadow: 'var(--shadow)',
              overflow: 'hidden',
              marginTop: 4,
            }}>
              {suggestions.map(item => (
                <div
                  key={item.id}
                  onMouseDown={() => openFromSuggestion(item)}
                  style={{
                    display: 'flex', alignItems: 'center', gap: 10,
                    padding: '10px 14px', cursor: 'pointer',
                    borderBottom: '1px solid var(--border)',
                    textAlign: 'left',
                  }}
                  onMouseEnter={e => e.currentTarget.style.background = 'var(--surface-2)'}
                  onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                >
                  <span style={{
                    fontSize: 14,
                    color: item.type === 'faq' ? 'var(--accent)' : (item.catColor || 'var(--muted)'),
                  }}>
                    {item.type === 'faq' ? '?' : item.catIcon}
                  </span>
                  <div style={{ flex: 1 }}>
                    <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text)' }}>{item.title}</div>
                    <div style={{ fontSize: 11, color: 'var(--dim)' }}>
                      {item.type === 'faq' ? 'FAQ' : item.catLabel}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </form>
      </div>

      {/* ── Search results view ────────────────────────────────────────── */}
      {searchResults !== null && (
        <div style={{ marginBottom: 'var(--space-5)' }}>
          <div style={{
            fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--muted)',
            marginBottom: 'var(--space-3)',
          }}>
            {searchResults.length} result{searchResults.length !== 1 ? 's' : ''} for "{query}"
            <button
              type="button"
              onClick={() => { setSearchResults(null); setQuery('') }}
              style={{
                marginLeft: 12, background: 'none', border: 'none',
                color: 'var(--accent)', fontSize: 11, cursor: 'pointer',
              }}
            >Clear</button>
          </div>
          {searchResults.length === 0 ? (
            <div className="panel-empty">
              <div className="panel-empty-mark" aria-hidden="true">⊘</div>
              <div>No results found</div>
              <div style={{ fontSize: 12, color: 'var(--dim)' }}>
                Try different keywords, or browse the categories below.
              </div>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-2)' }}>
              {searchResults.map(item => (
                <div
                  key={item.id}
                  onClick={() => openFromSuggestion(item)}
                  style={{
                    padding: 'var(--space-2) var(--space-3)',
                    background: 'var(--surface)',
                    border: '1px solid var(--border)',
                    borderRadius: 'var(--radius)',
                    cursor: 'pointer',
                    display: 'flex', gap: 12, alignItems: 'center',
                  }}
                  onMouseEnter={e => e.currentTarget.style.borderColor = 'var(--accent)'}
                  onMouseLeave={e => e.currentTarget.style.borderColor = 'var(--border)'}
                >
                  <span style={{
                    fontSize: 16,
                    color: item.type === 'faq' ? 'var(--accent)' : item.catColor,
                  }}>{item.type === 'faq' ? '?' : item.catIcon}</span>
                  <div>
                    <div style={{ fontWeight: 600, fontSize: 13, color: 'var(--text)' }}>{item.title}</div>
                    <div style={{ fontSize: 11, color: 'var(--dim)' }}>
                      {item.type === 'faq' ? 'FAQ' : item.catLabel}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* ── Category grid ──────────────────────────────────────────────── */}
      {showCategoryGrid && (
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fill, minmax(260px, 1fr))',
          gap: 'var(--space-3)',
          marginBottom: 'var(--space-5)',
        }}>
          {CATEGORIES.map(c => (
            <div
              key={c.id}
              onClick={() => { setActiveCat(c); setActiveArt(c.articles[0]) }}
              style={{
                background: 'var(--surface)',
                border: '1px solid var(--border)',
                borderLeft: `4px solid ${c.color}`,
                borderRadius: 'var(--radius)',
                padding: 'var(--space-3) var(--space-4)',
                cursor: 'pointer',
                transition: 'border-color 120ms ease',
                height: 160,
                overflow: 'hidden',
                boxSizing: 'border-box',
              }}
              onMouseEnter={e => { e.currentTarget.style.borderTopColor = c.color; e.currentTarget.style.borderRightColor = c.color; e.currentTarget.style.borderBottomColor = c.color }}
              onMouseLeave={e => { e.currentTarget.style.borderTopColor = 'var(--border)'; e.currentTarget.style.borderRightColor = 'var(--border)'; e.currentTarget.style.borderBottomColor = 'var(--border)' }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
                <span style={{ fontSize: 18, color: c.color }}>{c.icon}</span>
                <span style={{ fontWeight: 700, fontSize: 14, color: 'var(--text)' }}>{c.label}</span>
              </div>
              <div style={{ fontSize: 12, color: 'var(--muted)', marginBottom: 8 }}>{c.desc}</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                {c.articles.slice(0, 3).map(a => (
                  <div key={a.id} style={{
                    fontSize: 12, color: 'var(--dim)',
                    display: 'flex', alignItems: 'center', gap: 6,
                  }}>
                    <span style={{ color: c.color, fontSize: 10 }}>›</span>{a.title}
                  </div>
                ))}
                {c.articles.length > 3 && (
                  <div style={{ fontSize: 11, color: 'var(--dim)', paddingLeft: 16, marginTop: 2 }}>
                    +{c.articles.length - 3} more
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* ── Category + article view ───────────────────────────────────── */}
      {searchResults === null && activeCat && (
        <div style={{ marginBottom: 'var(--space-5)' }}>
          <button
            type="button"
            onClick={() => { setActiveCat(null); setActiveArt(null) }}
            style={{
              background: 'none', border: 'none', cursor: 'pointer',
              color: 'var(--muted)', fontSize: 12,
              marginBottom: 'var(--space-3)',
              display: 'flex', alignItems: 'center', gap: 6,
            }}
          >← All categories</button>

          <div style={{ display: 'grid', gridTemplateColumns: '220px 1fr', gap: 'var(--space-4)' }}>
            {/* Article list */}
            <div>
              <div style={{
                fontSize: 11, fontWeight: 700, color: activeCat.color,
                letterSpacing: '0.1em', textTransform: 'uppercase',
                marginBottom: 'var(--space-2)',
                display: 'flex', alignItems: 'center', gap: 6,
              }}>
                <span>{activeCat.icon}</span>{activeCat.label}
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                {activeCat.articles.map(a => (
                  <div
                    key={a.id}
                    onClick={() => setActiveArt(a)}
                    style={{
                      padding: '8px 10px',
                      borderRadius: 'var(--radius-sm)',
                      cursor: 'pointer',
                      fontSize: 13,
                      fontWeight: activeArt?.id === a.id ? 700 : 400,
                      color: activeArt?.id === a.id ? 'var(--text)' : 'var(--muted)',
                      background: activeArt?.id === a.id ? 'var(--surface-2)' : 'transparent',
                      borderLeft: `2px solid ${activeArt?.id === a.id ? activeCat.color : 'transparent'}`,
                    }}
                  >{a.title}</div>
                ))}
              </div>
            </div>

            {/* Article body */}
            {activeArt && (
              <div className="panel">
                <h2 style={{
                  fontSize: 17, fontWeight: 700, color: 'var(--text)',
                  borderBottom: '1px solid var(--border)',
                  paddingBottom: 'var(--space-2)',
                  marginBottom: 'var(--space-3)',
                }}>{activeArt.title}</h2>
                <ArticleBody body={activeArt.body} />
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── FAQ ────────────────────────────────────────────────────────── */}
      <div style={{ marginTop: 'var(--space-5)', marginBottom: 'var(--space-5)' }}>
        <div style={{
          fontSize: 11, fontWeight: 700, color: 'var(--dim)',
          letterSpacing: '0.12em', textTransform: 'uppercase',
          marginBottom: 'var(--space-3)',
          display: 'flex', alignItems: 'center', gap: 10,
        }}>
          <span style={{ flex: 1, height: 1, background: 'var(--border)' }} />
          Frequently Asked Questions
          <span style={{ flex: 1, height: 1, background: 'var(--border)' }} />
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
          {FAQS.map((faq, i) => (
            <div
              key={i}
              id={`faq-${i}`}
              style={{
                background: 'var(--surface)',
                border: '1px solid var(--border)',
                borderRadius: 'var(--radius)',
                overflow: 'hidden',
              }}
            >
              <div
                onClick={() => setOpenFaq(openFaq === i ? null : i)}
                style={{
                  display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                  padding: '12px 14px', cursor: 'pointer',
                  fontWeight: 600, fontSize: 13, color: 'var(--text)',
                }}
                onMouseEnter={e => e.currentTarget.style.background = 'var(--surface-2)'}
                onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
              >
                <span>{faq.q}</span>
                <span style={{ color: 'var(--muted)', fontSize: 12, flexShrink: 0, marginLeft: 12 }}>
                  {openFaq === i ? '▲' : '▼'}
                </span>
              </div>
              {openFaq === i && (
                <div style={{
                  padding: '0 14px 12px',
                  fontSize: 13, color: 'var(--muted)',
                  lineHeight: 1.7,
                  borderTop: '1px solid var(--border)',
                }}>
                  <div style={{ paddingTop: 'var(--space-2)' }}>{renderInline(faq.a)}</div>
                </div>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* ── Support footer ─────────────────────────────────────────────── */}
      <div style={{
        background: 'var(--surface)',
        border: '1px solid var(--border)',
        borderRadius: 'var(--radius)',
        padding: 'var(--space-4)',
        marginBottom: 'var(--space-5)',
        display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
        gap: 'var(--space-4)',
      }}>
        <div>
          <div style={{
            fontSize: 11, fontWeight: 700, color: 'var(--dim)',
            letterSpacing: '0.1em', textTransform: 'uppercase',
            marginBottom: 6,
          }}>Still need help?</div>
          <div style={{ fontSize: 13, color: 'var(--muted)', lineHeight: 1.6 }}>
            If self-service didn't resolve your issue, reach out through one of the channels below.
          </div>
        </div>
        {[
          { icon: '✉', label: 'Email Support', value: 'Contact your FENRIR administrator', sub: 'For account and access issues' },
          { icon: '⊟', label: 'Audit & Incident Logs', value: 'Check the Audit Log',         sub: 'For unexplained changes or access events' },
          { icon: '⎋', label: 'Report a Bug',         value: 'github.com/dfir-fenrir',      sub: 'For platform defects and feature requests' },
        ].map(item => (
          <div key={item.label} style={{ borderLeft: '2px solid var(--border)', paddingLeft: 12 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
              <span style={{ fontSize: 14 }}>{item.icon}</span>
              <span style={{ fontWeight: 700, fontSize: 13, color: 'var(--text)' }}>{item.label}</span>
            </div>
            <div style={{ fontSize: 12, color: 'var(--muted)' }}>{item.value}</div>
            <div style={{ fontSize: 11, color: 'var(--dim)' }}>{item.sub}</div>
          </div>
        ))}
      </div>
    </div>
  )
}
