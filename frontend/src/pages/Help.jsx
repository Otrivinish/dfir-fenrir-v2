import { useEffect, useMemo, useRef, useState } from 'react'

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
            '**Dashboard** — your live operational view of all incidents.',
            '**Incidents** — the list. Open one to enter the per-incident workspace.',
            '**Playbooks** — playbook templates and tasks.',
            '**Threat Intel · Threat Actors · ATT&CK Matrix** — reference databases.',
            '**On-Call · Handoffs · IR Roster** — staffing and shift coordination.',
            '**Settings** — your account, plus admin sections (Users / Teams / Roles / Stakeholder Matrix / Feeds / Integrations / API Keys).',
          ] },
          { type: 'section', title: 'Inside an incident', items: [
            'Open any incident to enter the workspace. The left rail has 13 tabs (14 for admins): Details · Assignments · Handoffs · Playbook · Timeline · Entities · Evidence · Forensic · Respond · Comms · Legal · MITRE ATT&CK · Post-Incident · Audit Log.',
            'For a tab-by-tab walk-through (including all 9 Forensic sub-tabs, the 5 Evidence sub-tabs, and the 5 Post-Incident sub-tabs), see the **Incident Workspace** category.',
            'For the full evidence lifecycle — collection, acquisition, examination, custody, and law-enforcement handoff — see the **Evidence & Chain of Custody** category.',
          ] },
        ],
      },
      {
        id: 'gs-roles',
        title: 'User Roles & Permissions',
        tags: ['roles', 'permissions', 'admin', 'analyst', 'responder', 'observer'],
        body: [
          { type: 'p', text: 'Role-based access control. Most write actions require Analyst or above; admin-only sections (Users, Audit Log, Stakeholder Matrix, API Keys, Operational Roles) are hidden from non-admins even when the URL is opened directly.' },
          { type: 'table', headers: ['Role', 'Can do'], rows: [
            ['**Admin**', 'Full access. Manage users, teams, audit log, regulatory tabs, system settings.'],
            ['**Analyst**', 'Create + update incidents, timeline, IOCs, evidence. Run YARA scans. Full investigation access.'],
            ['**Responder**', 'View all incident data. Post War Room messages and comments. Cannot create incidents.'],
            ['**Observer**', 'Read-only access to incidents the operator has assigned them to.'],
          ] },
          { type: 'note', text: 'Two auth mechanisms map to the same RBAC: browser **cookies** (login) and **API tokens** (`Authorization: Bearer …`) for MCP clients, scripts, and integrations. Both resolve to the same User.' },
        ],
      },
      {
        id: 'gs-first-incident',
        title: 'Creating Your First Incident',
        tags: ['create', 'incident', 'new', 'start'],
        body: [
          { type: 'steps', items: [
            'Sidebar → **Incidents** → **+ New Incident**.',
            'Enter a title and set **Severity** (Low / Medium / High / Critical) and **TLP**.',
            'Pick the initial **Phase** — typically Detection & Analysis.',
            'After creation, click **Edit** on the incident to assign IC and primary analyst, then move through phases using the phase stepper at the top.',
            'Start collecting data in the Forensic tabs (Timeline, IOCs, Entities, Artifacts).',
          ] },
          { type: 'note', text: 'Severity and TLP are editable at any time. When in doubt, start higher and revise downward.' },
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
            'Search by incident ref (`INC-2026-0001`), title, hostname, username, or IOC value.',
            'Results are scoped to what your role can see.',
          ] },
        ],
      },
      {
        id: 'gs-staffing',
        title: 'Staffing — On-Call, Handoffs & IR Roster',
        tags: ['on-call', 'handoff', 'roster', 'shift', 'staffing'],
        body: [
          { type: 'p', text: 'Coordinate who is responding and hand work over cleanly between shifts.' },
          { type: 'section', title: 'Where', items: [
            '**On-Call** — the current on-call schedule and who to escalate to.',
            '**Handoffs** — create a shift handover; also reachable from the **Handoff** button in any incident header.',
            '**IR Roster** — the responder roster and contact list.',
          ] },
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
        tags: ['phases', 'lifecycle', 'detection', 'containment', 'eradication', 'recovery', 'post-incident'],
        body: [
          { type: 'p', text: 'The phase stepper at the top of every incident tracks where you are in the IR lifecycle. Click any phase to advance or rewind.' },
          { type: 'table', headers: ['Phase', 'What happens'], rows: [
            ['**Preparation**', 'Pre-incident: rosters, playbooks, drills. Usually not selected during an active incident.'],
            ['**Detection & Analysis**', 'Triage, IOC collection, timeline reconstruction, threat actor identification.'],
            ['**Containment, Eradication & Recovery**', 'Isolate affected systems. Log responder actions in **Respond**. Eradicate and recover. Avoid destroying evidence.'],
            ['**Post-Incident**', 'Closure checklist, lessons learned, report. Cost tracking.'],
          ] },
          { type: 'note', text: 'Transitioning *into* Containment auto-stamps `contained_at` (used for dashboard metrics). Transitioning *out of* Post-Incident closes the incident.' },
        ],
      },
      {
        id: 'inc-severity-tlp',
        title: 'Severity, TLP & Triage State',
        tags: ['severity', 'tlp', 'triage', 'critical', 'high', 'medium', 'low'],
        body: [
          { type: 'section', title: 'Severity (impact)', items: [
            '**Critical** — direct business impact, active data loss / control loss.',
            '**High** — confirmed compromise on production systems.',
            '**Medium** — confirmed compromise on non-production systems.',
            '**Low** — minor or contained anomalies.',
          ] },
          { type: 'section', title: 'Triage state (analyst confidence)', items: [
            '**Suspected** — initial signal, not yet confirmed.',
            '**Confirmed** — verified malicious activity.',
            '**Benign** — investigation determined no incident.',
            '**Closed** — work complete.',
          ] },
          { type: 'note', text: 'Severity is *impact*; triage is *confidence*. They are distinct dimensions — a Suspected/Critical incident is a real thing.' },
        ],
      },
      {
        id: 'inc-closing',
        title: 'Closing & Reopening',
        tags: ['close', 'closed', 'reopen', 'lock'],
        body: [
          { type: 'p', text: 'Closing an incident makes it read-only across every tab. The Resolve button is on the incident header.' },
          { type: 'section', title: 'Before closing', items: [
            'Walk the **Closure Checklist** (Post-Incident → Closure Checklist).',
            'Finalise **Lessons Learned** (Post-Incident → Lessons Learned).',
            'Generate the final **Report**.',
          ] },
          { type: 'note', text: 'Closed incidents can be re-opened from the header. Re-opening is itself audit-logged.' },
        ],
      },
    ],
  },
  {
    id: 'timeline',
    icon: '◷',
    label: 'Timeline & Investigation',
    color: '#10b981',
    desc: 'Events, MITRE tagging, system events, export',
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
            '**IR phase** — phase this event belongs to (auto-suggested from the incident\'s current phase).',
            '**MITRE tactic + technique** — ATT&CK mapping (optional but recommended for the Suggest engine).',
            '**Hostname · Source · Raw log** — supporting evidence.',
          ] },
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
            '**Detection queries** (Forensic → Detections) — KQL / Splunk / EQL / Cortex / CrowdStrike queries auto-generated from your tagged events.',
          ] },
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
            '**Compromised** flag — separately tracked from criticality.',
            '**Attributes** — arbitrary key-value JSON.',
          ] },
        ],
      },
      {
        id: 'ee-artifacts',
        title: 'Quarantine Artifacts',
        tags: ['artifact', 'quarantine', 'sandbox', 'analysis', 'hash', 'zip', 'infected'],
        body: [
          { type: 'p', text: 'Upload binary samples for analysis. Files land on an air-gapped quarantine volume (read-only from the analysis worker; no internet access).' },
          { type: 'section', title: 'On upload', items: [
            'MD5 / SHA-1 / SHA-256 / SHA-512 computed in one streaming pass.',
            'MIME type detected via libmagic.',
            'Two IOC records auto-created (SHA-256 + MD5) for immediate enrichment.',
            'Path-traversal guard applied to every file access.',
          ] },
          { type: 'section', title: 'On download', items: [
            'Files download as AES-256 password-protected ZIP. Password: `infected`.',
            'Standard malware-analyst convention — prevents AV auto-execution.',
          ] },
          { type: 'note', text: 'Analysis tools available: file-type · hashes · entropy · strings · IOC extract · PE · Office · PDF · EXIF · hexdump. Run from the artifact row.' },
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
          ] },
          { type: 'note', text: 'Physical items require an in-situ photograph (`§9.1.4`) — see **Evidence Photos**.' },
        ],
      },
      {
        id: 'coc-acquisition',
        title: 'Acquisition & Sealing (Wizard A)',
        tags: ['acquisition', 'seal', 'hash', 'sha-256', 'write-blocker', '27037', '27041'],
        body: [
          { type: 'p', text: 'Captures the reproducibility evidence for a digital acquisition, then **Seal** locks the minimum `ISO/IEC 27037 §6.1` fields.' },
          { type: 'steps', items: [
            'Hash the source: MD5 + SHA-1 + **SHA-256**, captured at acquisition (`§9.2.3`).',
            'Record **tool + version** (pick from the validated-tools registry where possible) and the command / parameters.',
            'Confirm the **source ↔ target hash match** — a mismatch means re-acquire (`§9.2.5`).',
            'Record write-blocker use, **system state** (powered-off / live / mission-critical), full-image vs **logical + rationale**, screen state, and changes made.',
            'Confirm **27041** tool/method validation and the collector competence.',
            'Click **Seal** — locks the row; later edits write an `evidence_amend_after_seal` audit row.',
          ] },
          { type: 'note', text: 'At seal an optional **RFC 3161** trusted timestamp is taken (see **Trusted Timestamping**). Evidence is encrypted **AES-256-GCM at rest**, with the key-encrypting key held separately from the data.' },
        ],
      },
      {
        id: 'coc-examination',
        title: 'Examination (Wizard B)',
        tags: ['examination', 'analysis', 'verify', 'findings', '27042', 'working copy'],
        body: [
          { type: 'p', text: 'Runs analysis as a transactional, audited sequence so the evidence is provably unchanged by the examination — `ISO/IEC 27037 §9.4.2` + `ISO/IEC 27042`.' },
          { type: 'steps', items: [
            '**Pre-verify** — re-hash the file and compare to the recorded SHA-256. A mismatch aborts the session and freezes the row.',
            '**Record** — tool + version (validated-tools registry), 27041 validation, examiner qualifications, and the 27042 records: **findings**, **interpretation**, **confidence**, **scope limitations**.',
            '**Working copy** — select which master-verified copy you analysed (`§7.1.3.1.1`).',
            '**Post-verify** — re-hash again; if it differs the examination is still recorded (auditable) and the row is frozen.',
          ] },
          { type: 'note', text: 'Findings and interpretation are kept separate on purpose (27042 item 8); scope limitations record what was **not** examined (item 12).' },
        ],
      },
      {
        id: 'coc-working-copies',
        title: 'Working Copies',
        tags: ['working copy', 'master', 'verified', '27037', '7.1.3.1.1'],
        body: [
          { type: 'p', text: 'Analysis runs on a **master-verified working copy**, never the master itself — `ISO/IEC 27037 §7.1.3.1.1`.' },
          { type: 'section', title: 'How it works', items: [
            'Exporting an item auto-mints a working copy, hash-verified against the master.',
            'The ledger tracks each copy: created, purpose, verified-against-master, discarded.',
            'Examinations bind to a specific copy (Wizard B), so it is provable the master was untouched.',
          ] },
          { type: 'note', text: 'The provenance score flags a digital item that has no verified working copy.' },
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
        tags: ['transfer', 'custodian', 'external', 'handoff', '27037', '9.3'],
        body: [
          { type: 'p', text: 'Every change of hands is recorded — to another FENRIR user (internal) or to a real-world party without an account (external) — `ISO/IEC 27037 §9.3`.' },
          { type: 'section', title: 'Two paths', items: [
            '**Internal** transfer hands custody to another user; the row stays fully actionable.',
            '**External** custodian (courier, counsel, LE officer, vendor) records name / org / contact; examine, verify and seal pause until you take it back.',
            'Structured transport details are captured for the handoff.',
          ] },
        ],
      },
      {
        id: 'coc-disposal',
        title: 'Disposal & the Two-Person Rule',
        tags: ['dispose', 'destroy', 'archive', 'return', 'legal hold', 'two-person'],
        body: [
          { type: 'p', text: 'Disposal — **archive**, **return**, or **destroy** — is admin-only and always audited. Destroying a digital item permanently deletes the encrypted file while keeping the hash and chain.' },
          { type: 'section', title: 'Rules', items: [
            'A **legal-hold** item requires a **second approver** (a distinct, active user) to dispose — two-person integrity (SWGDE / ACPO).',
            'The final SHA-256 is recorded at disposition; the custody chain is retained for the legal record.',
          ] },
          { type: 'note', text: 'Destruction cannot be undone — the file is gone; only the hash and the chain remain.' },
        ],
      },
      {
        id: 'coc-photos',
        title: 'Evidence Photos',
        tags: ['photo', 'image', '27037', '9.1.4', 'encrypted'],
        body: [
          { type: 'p', text: 'Attach photographs to an item (`ISO/IEC 27037 §9.1.4`); images are stored **AES-256-GCM encrypted at rest** and served only through an auth-gated route.' },
          { type: 'section', title: 'Behaviour', items: [
            'Add a photo with an optional caption from the evidence detail; thumbnails render inline.',
            'Physical items require at least one in-situ photo — the provenance score enforces it.',
            'On **destroy**, photo files are deleted alongside the evidence file.',
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
            'Manifest with **SHA-256 + HMAC-SHA-256 + Ed25519** signature; embeds the SOP, Annex B documents, and EIO / MLA references.',
            'A one-time, time-limited download URL plus a recipient acknowledgment (HMAC) that closes the chain.',
            '`retention_until` recorded for lawful retention.',
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
            'GDPR erasure / disposal should propagate to the mirror (`GDPR Art. 17`).',
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
            '**← Incidents** link · ref code (e.g. `INC-2026-0001`) · incident title.',
            '**Handoff** — jump straight to the Handoffs tab to create a shift handover.',
            '**Edit** — switch the Details form to edit mode (title, severity, TLP, triage state, type, detection method, reporter, dates).',
            '**Resolve** — closes the incident (phase → Post-Incident; everything becomes read-only).',
            '**Re-open** — appears once the incident is closed; restarts work in Containment / Eradication / Recovery.',
            '**Save changes / Discard** — appear only in edit mode. A grey dot ● = unsaved changes; "SAVED" tag = recently persisted.',
          ] },
          { type: 'section', title: 'Status band', items: [
            '**Phase stepper** — click any of the 4 phases (Preparation · Detection & Analysis · Containment/Eradication/Recovery · Post-Incident) to advance or rewind. Opens a confirmation modal.',
            '**Pills** — current severity, status, TLP, and a red **DARK OP** pill when Dark Operation is on.',
            '**Presence avatars** — coloured initials of every other user currently viewing the incident, via WebSocket. Yours has a thicker ring.',
          ] },
          { type: 'note', text: 'When Dark Operation is active, a red banner sits below the status band and the page is forced to the Mission Control theme.' },
        ],
      },
      {
        id: 'iw-details',
        title: 'Details',
        tags: ['details', 'description', 'tags', 'systems', 'snapshot', 'markdown', 'matrix'],
        body: [
          { type: 'p', text: 'The default landing tab. The full incident record plus everything you can change in edit mode.' },
          { type: 'section', title: 'On the page', items: [
            '**Snapshot stats** — counts of IOCs, entities, evidence, timeline events, playbook tasks, assigned responders.',
            '**Description** — markdown editor with a Preview toggle.',
            '**Classification fields** — Severity · TLP · Triage state · Incident type · Detection method · Reporter.',
            '**Timestamps** — Occurred at / Contained at (UTC, entered as `YYYY-MM-DD HH:mm:ss` in edit mode) · Created / Updated / Closed.',
            '**Assign Team** — modal to add or remove organisations and roles.',
            '**Tags** — chip editor for free-form labels (used in filters and search).',
            '**Affected systems** — table; rows can be edited, deleted, or promoted to full Entities.',
            '**Stakeholder Matrix banner** — top of page, shows required notifications for this severity ([[co-matrix]]).',
          ] },
        ],
      },
      {
        id: 'iw-assignments',
        title: 'Assignments',
        tags: ['assign', 'role', 'commander', 'coverage', 'cisa', 'operational role'],
        body: [
          { type: 'p', text: 'Who is on the response team and what role they hold. Distinct from RBAC ([[gs-roles]]) — these are CISA operational roles per incident.' },
          { type: 'section', title: 'Sections', items: [
            '**Role Coverage** — at-a-glance grid showing which CISA roles are filled (Incident Commander, Communications Lead, Forensic Lead, Containment Lead, Recovery Lead, Scribe) and which are vacant.',
            '**Team grid** — one card per assignee: username, operational role, assignment notes, assigned-at timestamp.',
            '**+ Assign** — modal picks a user, role, and optional notes.',
            '**Remove** — drop an assignee.',
          ] },
        ],
      },
      {
        id: 'iw-handoffs',
        title: 'Handoffs',
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
        id: 'iw-timeline',
        title: 'Timeline',
        tags: ['timeline', 'event', 'spine', 'system', 'export', 'csv', 'html', 'mitre', 'lolbin'],
        body: [
          { type: 'p', text: 'The canonical narrative of the incident — analyst observations, system actions, decisions. See also [[tl-events]] and [[tl-mitre]].' },
          { type: 'section', title: 'On the page', items: [
            'Vertical spine with date separators and alternating event cards.',
            'Per-event: type, MITRE tactic + technique, IR phase, hostname, source, raw log (collapsible).',
            'Inline **⚑ LOLBin panel** when an event references a known living-off-the-land binary.',
            '**Show / hide system events** toggle.',
          ] },
          { type: 'section', title: 'Toolbar', items: [
            '**+ Add event** — modal with MITRE selector and structured fields.',
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
        id: 'iw-evidence',
        title: 'Evidence Tab',
        tags: ['evidence', 'items', 'custody', 'audit chain', 'export', 'sop', 'aes-256', 'transfer', 'dispose'],
        body: [
          { type: 'p', text: 'The incident workspace for evidence — five sub-tabs. For the full ISO 27037/41/42/43 lifecycle and wizards, see the **Evidence & Chain of Custody** category.' },
          { type: 'table', headers: ['Sub-tab', 'What it does'], rows: [
            ['**Items**', 'Add / view evidence items, filter by kind (digital file or physical item). Actions: collection + acquisition wizards, evidence detail (with photos + provenance score), transfer custody, examination wizard, dispose (admin only).'],
            ['**Custody log**', 'Per-incident timeline of every collect / acquire / transfer / examine / return / dispose event across all items.'],
            ['**Audit chain**', 'Cryptographic chain verifier — recomputes the hash chain over evidence events and reports any mismatch.'],
            ['**Export**', 'Bundles selected items into an AES-256-encrypted ZIP with a one-time key and a single-use 24-hour download URL; auto-mints master-verified working copies.'],
            ['**CoC SOP**', 'Reference card: phase-by-phase chain-of-custody procedure; flags missing photos on physical items and missing SHA-256 on digital files.'],
          ] },
          { type: 'note', text: 'A **legal hold** item can still be disposed, but only with a second approver (two-person rule) — see **Disposal & the Two-Person Rule**.' },
        ],
      },
      {
        id: 'iw-forensic',
        title: 'Forensic Tab',
        tags: ['forensic', 'iocs', 'detections', 'attribution', 'lolbins', 'pcap', 'sandbox', 'timeline import', 'artifacts', 'osint'],
        body: [
          { type: 'p', text: 'The investigation workbench. Nine inner tabs:' },
          { type: 'table', headers: ['Sub-tab', 'Purpose'], rows: [
            ['**IOCs**',            'Indicators of compromise — see [[fo-iocs]].'],
            ['**Detections**',      'YARA rules, scan results, detection queries — see [[fo-detections]].'],
            ['**Attribution**',     'Link the incident to a threat actor / cluster — see [[fo-attribution]].'],
            ['**LOLBins**',         'LOLBAS + GTFOBins reference and correlations — see [[fo-lolbins]].'],
            ['**PCAP**',            'Network packet analysis — see [[fo-pcap]].'],
            ['**Sandbox**',         'Air-gapped sandbox detonation (in progress).'],
            ['**Timeline Import**', 'Parse a forensic artifact and bulk-promote events to the timeline — see [[fo-timeline-import]].'],
            ['**Artifacts**',       'Quarantine binaries + 11-tool analysis pipeline — see [[fo-artifacts]].'],
            ['**OSINT**',           '11-source OSINT lookup for free-text IOCs — see [[fo-osint]].'],
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
            'Title, description, target entity, assignee, occurrence + completion timestamps.',
            '**Revert** — moves a completed action back to in-progress; captures the reason for the audit trail.',
            'Edit / Delete inline.',
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
        id: 'iw-comms',
        title: 'Comms Tab',
        tags: ['comms', 'comments', 'oob', 'stakeholders', 'banner'],
        body: [
          { type: 'p', text: 'Everything communications-related for the incident.' },
          { type: 'table', headers: ['Sub-tab', 'What it does'], rows: [
            ['**Comments**', 'Threaded @-mention discussion. Mentions deliver notifications.'],
            ['**OOB**',      'Out-of-band log + passphrase generator. Use when the platform may be compromised — see [[co-comments]].'],
            ['**Stakeholders**', 'Per-incident contact list — see [[co-stakeholders]]. CSV bulk import supported.'],
          ] },
          { type: 'note', text: 'The Stakeholder Matrix banner (required notifications for this severity) appears above the sub-tabs and on Details.' },
        ],
      },
      {
        id: 'iw-legal',
        title: 'Legal',
        tags: ['legal', 'gdpr', 'nis2', 'dora', 'pci', 'hipaa', 'ccpa', 'deadline', 'countdown', 'waive', 'breach'],
        body: [
          { type: 'p', text: 'Regulatory notification deadlines. Initialise the panel by selecting applicable regulations and entering the breach detection time.' },
          { type: 'section', title: 'Built-in regulations', items: [
            '**GDPR** (72-hour DPA notification) · **NIS2** (24/72-hour) · **DORA** · **PCI-DSS** · **HIPAA** · **CCPA**.',
          ] },
          { type: 'section', title: 'Per deadline card', items: [
            'Regulation badge · article / reference · obligation text · recipient (DPA, CSIRT, card brand, etc.).',
            'Colour-coded countdown timer — red / orange / yellow / green by days remaining.',
            'Status: **Not Started** · **In Progress** · **Completed**.',
          ] },
          { type: 'section', title: 'Actions', items: [
            'Mark In Progress / Mark Completed · **Reopen** · **Waive** (requires reason) · **Delete**.',
            '**+ Add custom deadline** — for obligations outside the standard list.',
          ] },
        ],
      },
      {
        id: 'iw-mitre',
        title: 'MITRE ATT&CK',
        tags: ['mitre', 'attack', 'tactic', 'technique', 'coverage'],
        body: [
          { type: 'p', text: 'Per-incident MITRE coverage map. Driven entirely by timeline events you have tagged with a tactic + technique ([[tl-mitre]]).' },
          { type: 'section', title: 'What it shows', items: [
            'Header counts: tactics observed (of 12) · total techniques observed.',
            'One row per MITRE tactic, in ATT&CK order.',
            'Observed tactics show technique pills with the event count per technique.',
            'Unobserved tactics show a gap indicator — useful to spot blind spots.',
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
          { type: 'p', text: 'Per-incident audit feed. Only visible to admins.' },
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
    label: 'Forensic Tools',
    color: '#22d3ee',
    desc: 'IOCs · Detections · OSINT · PCAP · Attribution · Artifacts · LOLBins · Timeline Import',
    articles: [
      {
        id: 'fo-iocs',
        title: 'IOCs',
        tags: ['ioc', 'indicator', 'enrich', 'correlate', 'mark malicious', 'export', 'scan', 'bulk'],
        body: [
          { type: 'p', text: 'Indicators of compromise tied to this incident. See also [[ioc-types]] and [[ioc-enrichment]] for status and enrichment fundamentals.' },
          { type: 'section', title: 'Table columns', items: [
            'Type · Value (with badges) · linked Entity · Source · confidence bar · added-at · tags.',
            '**⚠ TI** badge — value matches an enabled Threat Intel feed.',
            '**LOL** badge — file-path matches a known LOLBin.',
            '**⋈** badge — IOC appears in N other incidents (click for cross-incident list).',
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
        id: 'fo-detections',
        title: 'Detections',
        tags: ['yara', 'rule', 'scan', 'detection', 'query', 'kql', 'splunk', 'eql'],
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
            'Open **Forensic → Attribution → ◈ Suggest actors**.',
            'Pick a suggestion (or attribute manually).',
            'Set confidence and notes; save.',
          ] },
          { type: 'note', text: 'Attribution records carry the Suggest score + evidence array at attribution time, so the audit trail explains *why* this actor was chosen.' },
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
        tags: ['pcap', 'pcapng', 'network', 'tshark', 'dns', 'tls', 'http', 'talkers'],
        body: [
          { type: 'p', text: 'Upload a PCAP / PCAPNG / CAP. The air-gapped analysis worker runs it through tshark.' },
          { type: 'section', title: 'On the page', items: [
            'Drag-and-drop upload zone.',
            '**Saved analyses** — previous uploads with filename, size, uploader, timestamp; Load or Delete.',
            'Stats grid: counts per category.',
          ] },
          { type: 'section', title: 'Result tabs', items: [
            '**Suspicious** — severity-ranked findings.',
            '**Conversations** — TCP / UDP, sorted by byte volume.',
            '**DNS** — queries with suspicious-domain heuristics (long names, low-vowel ratio, IP-in-DNS, suspicious TLDs).',
            '**DNS Recon** — top resolvers, per-domain stats, CNAME chains, entropy.',
            '**HTTP** — method, host, URI, response code, UA. Flags cmd / shell / base64 / sqlmap-style patterns.',
            '**TLS** — SNI, version, suspicious indicators.',
            '**Top Talkers** — by bytes.',
          ] },
          { type: 'note', text: '**Import to IOCs** — promote any suspicious finding directly into the incident IOC list.' },
        ],
      },
      {
        id: 'fo-artifacts',
        title: 'Artifacts',
        tags: ['artifact', 'quarantine', 'sandbox', 'hash', 'zip', 'infected', 'pe', 'office', 'pdf', 'yara', 'strings'],
        body: [
          { type: 'p', text: 'Upload binaries for analysis. Files land on the air-gapped quarantine volume (no internet, read-only from the worker).' },
          { type: 'section', title: 'Upload', items: [
            'Drag-and-drop or click upload zone, up to **500 MB**.',
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
        title: 'Timeline Import',
        tags: ['timeline import', 'parse', 'evtx', 'sqlite', 'csv', 'jsonl', 'syslog', 'promote', 'tree'],
        body: [
          { type: 'p', text: 'Parse a forensic artifact, triage the parsed events, then bulk-promote selected ones into the incident timeline.' },
          { type: 'section', title: 'Accepted formats', items: [
            '**EVTX · Windows XML · SQLite · CSV/TSV · JSON/JSONL · syslog / auth.log · journald JSON · macOS Unified Log.** Up to 100 MB.',
          ] },
          { type: 'section', title: 'On the page', items: [
            'Drop zone · **Parse artifact** button · summary bar with total + suspicious-event counts.',
            'Filters: free-text search · suspicious-only toggle · per-source dropdown.',
            '**Table / Tree** view toggle.',
            'Per row: timestamp, source, hostname, event type, description, MITRE technique (if inferred), suspicious flag.',
            'Multi-select with **Select all visible**.',
          ] },
          { type: 'section', title: 'Actions', items: [
            '**Promote selected to timeline** — bulk-creates timeline events. Events without timestamps are stamped at promotion time (confirmed in the prompt).',
            'Per row: **+ IOC** opens the quick-add modal.',
          ] },
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
            'For incidents where the platform itself may be compromised. Switch the incident to **Dark Operation** mode — banner appears, communication blackout in effect.',
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
            '**Type** — internal / legal / regulatory / law enforcement / media / vendor / IR firm / customer / insurer / board / other.',
            '**Contact methods** — multiple (phone, email, Signal, etc.).',
            '**Available hours** — free-text (e.g. "24/7 hotline").',
            '**Notes** — free-text.',
          ] },
          { type: 'note', text: 'Bulk import via CSV (header row required). Preview before commit.' },
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
            '**Time to Detect (TTD)** — occurred → created.',
            '**Time to Contain (TTC)** — created → contained.',
            '**Time to Resolve (TTR)** — created → closed.',
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
        tags: ['report', 'pdf', 'html', 'executive', 'full', 'post-incident', 'le package', 'sha-256', 'template'],
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
            'Distinct from RBAC. These are *response* roles assignable per incident — Incident Commander, Communications Lead, Forensic Lead, Containment Lead, Recovery Lead, Scribe.',
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
          { type: 'p', text: 'FENRIR follows one timestamp rule: store and enter in UTC, 24-hour, ISO-8601; display in your zone with the offset shown.' },
          { type: 'section', title: 'How it works', items: [
            'Manual datetime fields are entered in **UTC** as `YYYY-MM-DD HH:mm:ss` (the field validates the format) — never a locale / AM-PM picker.',
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
    q: 'Why does the date/time field want UTC instead of my local time?',
    a: 'All datetime entry is in UTC, 24-hour, as `YYYY-MM-DD HH:mm:ss` — one unambiguous format for evidence and incident records (no MM/DD vs DD/MM, no AM/PM). Type the UTC time; the field validates it. Read-only timestamps are still shown in your local zone with the offset visible.',
    tags: ['utc', 'datetime', 'time', 'entry', 'iso 8601'],
  },
  {
    q: 'How do I integrate FENRIR with my MCP client?',
    a: 'Issue a Bearer token in Settings → API Keys, then point your MCP server at `https://<your-host>/api/openapi.json`. Every endpoint is API-first — no feature is browser-only.',
    tags: ['mcp', 'api', 'token', 'bearer', 'openapi'],
  },
  {
    q: 'What is "Dark Operation" mode?',
    a: 'A flag set on the incident header that signals "the platform may be compromised — switch to OOB". The UI shows a red banner across every tab and the theme is locked to Mission Control. Use OOB → Passphrase + Log to coordinate over external channels.',
    tags: ['dark operation', 'oob', 'compromise'],
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
    a: 'Eleven sources are wired in. Key-free: WHOIS, DNS, DNSBL, Passive DNS, ASN, GeoIP, crt.sh. Key-required: Shodan, GreyNoise, AbuseIPDB, VirusTotal. Configure keys in Settings → API Keys. Sources without a key appear greyed out and labelled "(no key)" in the SOURCES bar at Forensic → OSINT.',
    tags: ['osint', 'sources', 'api key', 'whois', 'shodan', 'virustotal'],
  },
  {
    q: 'Why is one of my OSINT sources marked "⚠ PUBLIC"?',
    a: 'Sources flagged PUBLIC (e.g. VirusTotal) log your queries and may make the submitted indicator visible to third parties. If the indicator is sensitive (an internal asset, an unburned C2), disable the source before enriching. Public sources are off by default; only non-public sources are enabled when the page loads.',
    tags: ['osint', 'opsec', 'public', 'virustotal', 'leak'],
  },
  {
    q: 'Where do I parse an EVTX or syslog file?',
    a: 'Forensic → Timeline Import. Drop the file in (EVTX, Windows XML, SQLite, CSV/TSV, JSON/JSONL, syslog/auth.log, journald JSON, macOS Unified Log — up to 100 MB), click Parse, tick the rows you want, then Promote to timeline. Events without timestamps are stamped at promotion time after confirmation.',
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
    a: 'Go to the Legal tab → Initialise Deadlines. Pick the applicable regulations (GDPR, NIS2, DORA, PCI-DSS, HIPAA, CCPA) and enter the breach detection time. Countdown timers start from that moment. Add anything outside the standard list with + Add custom deadline.',
    tags: ['legal', 'gdpr', 'nis2', 'dora', 'deadline'],
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
