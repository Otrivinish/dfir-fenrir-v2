# DFIR-FENRIR v2 — Feature Inventory

---

## Authentication & user management

- Password login with lockout protection
- First-run bootstrap token (printed to logs / `setup.sh`)
- TOTP / 2FA — enrol, enable, disable, org-wide enforcement toggle
- Change password (argon2id hashing)
- Two-axis RBAC (admin / analyst / viewer)
- Teams CRUD + membership management
- Operational role catalogue (CISA roles seeded)
- User management UI (create, edit, enable/disable, delete with last-admin/self guards)
- API tokens — `Authorization: Bearer …`, role-capped to `min(user.role, token.role)`, issue/list/revoke, plaintext shown once
- Per-user activity log in the user detail modal
- Opaque sessions with idle-timeout revocation

## Incident core

- Cursor-paginated incident list with severity/status/team/tag filters
- Create incident with inline validation; detail page with edit-on-blur
- Unique incident numbers (`INC-NNNN`, Postgres sequence)
- 800-61 R3 phase stepper — interactive, audit-logged transitions
- Severity scale (internal Low/Med/High/Critical → NCISS at report time)
- TLP 2.0 marking · incident type · CSF 2.0 function tag · reporter field
- Markdown description (view + edit preview)
- Affected systems (with bulk promote to entities)
- Detection method classification
- Occurred / Contained datetimes (ISO 8601 UTC, rendered in user TZ)
- Operational dark-mode toggle (`dark_operation`)
- Tags (incident + IOC scoped, normalised, auto-sourced, 20-cap, usage-ranked typeahead)

## Investigation — forensics

### Timeline
- Timeline CRUD with vertical-spine UI, date grouping, expand/collapse
- MITRE ATT&CK cascading dropdowns (tactic → technique), tactic-coloured dots
- 800-61 R3 phase tag per event; raw-log expand
- Export to CSV and self-contained HTML
- Process-tree visualiser (Sysmon / Windows Security / syslog PID hierarchy)

### Forensic timeline import
- Multi-format upload (EVTX, XML, SQLite, CSV, JSON) with auto-detection
- Event classification engine (36 Windows/Sysmon EID → MITRE)
- Suspicious-event flagging; triage table with filters
- Bulk promote to timeline; per-row quick-add IOC
- Linux support (syslog RFC 3164 + ISO 8601, auth.log, journald JSON)
- macOS unified log support (`log show --style json` NDJSON)
- Velociraptor collector output auto-parse → timeline

### IOCs
- IOC CRUD per incident, dedup on `(incident, type, value)`
- Confidence scoring, tags, entity linking, malicious flag, inline notes
- Cross-incident correlation with "seen in" badge + modal
- Bulk import (text/CSV, auto-type-detect, 500 cap, dedup)
- Export to 7 formats: MDE CSV/JSON, CrowdStrike, SentinelOne, Cortex XDR, FortiGate CLI, Palo Alto PAN-OS/EDL
- Threat-feed matching (8 seeded feeds) with TI badge + detail
- Per-IOC enrichment (VT, AbuseIPDB, Shodan, URLScan, GreyNoise) with cache + cards

### Entities (assets)
- Entity CRUD, dedup, criticality levels, free-form attributes, compromised flag
- Relationships (15 standard + custom types) with detail drawer
- react-flow asset graph (zoom/pan/drag, click-to-detail)
- Bulk CSV import (3-stage wizard); per-entity asset logs
- Bulk promote from Affected Systems

### Evidence & chain of custody
- Digital + physical evidence models, per-incident dedup
- AES-256-GCM encryption at rest (fail-fast without `EVIDENCE_KEK`)
- Custody actions: Transfer / Examine / Verify / Dispose with per-item timeline
- One-time 24h encrypted download tokens (consumed/expired/revoked → 410)
- Export bundles: files + per-item CoC JSON + audit JSONL excerpt + SHA-256 manifest + decrypt README
- Per-incident custody log; on-demand audit-chain verification
- Evidence SOP (6 NIST/ISO/ACPO/SWGDE phases, auto-compliance engine)
- ISO 27037 collection wizard, 27041 validation, master/working-copy ledger
- Entity linking + legal-hold flag; RFC 3161 trusted timestamping

### Artifacts (quarantined files)
- Drag-and-drop upload; MD5/SHA256/SHA512 hashing; MIME detection; path-traversal guard
- Auto-extract hashes as IOCs; AES-256 password ZIP download (`infected`)
- Air-gapped analysis worker pipeline with 11 static tools: file-type, hashes, entropy, strings, IOC-extract, PE, Office, PDF, EXIF, hexdump, YARA

### Detections (YARA & hunting)
- Global YARA rule library (upload, enable/disable, match counts)
- Per-incident artifact scan (air-gapped worker); matches → timeline / IOC
- SIEM detection-query generation (10 techniques × 5 platforms: KQL/EQL/SPL/XQL/CrowdStrike; ZIP export)

### LOLBins
- Global LOLBAS + GTFOBins library
- Per-incident timeline correlation scan, LOL badge, inline correlation panel

### PCAP analysis
- Drag-and-drop upload, tshark analysis (conversations, DNS, HTTP, TLS, top talkers, suspicious patterns)
- 7-tab result view incl. DNS reconstruction (domain aggregation, DGA heuristics)
- IOC import / bulk promote from results

### OSINT lookup
- Client-side IOC extraction from pasted text
- 7 sources: GeoIP, GreyNoise, AbuseIPDB, VirusTotal, Shodan, ASN (RIPE), crt.sh
- Per-source TTL cache, OPSEC warnings, add-to-IOC

### Threat-actor attribution
- 25 seeded actors (APT28/29/32/41, Lazarus, Turla, …), MITRE-synced (intrusion-set + techniques + software, 7-day TTL)
- Per-incident attribution model (possible/probable/confirmed) with analyst notes
- TTP-overlap scoring suggestion engine (top-10 candidates with evidence breakdown)
- Global `/threat-actors` page (search, motivation filter, detail drawer, linked-incident table)

### MITRE ATT&CK coverage
- Per-incident coverage matrix (12 tactics, observed vs gaps, technique pills)

### Email analyzer
- Offline phishing triage (`.msg`/RFC-822 parsing → Artifact/IOC/Timeline/Evidence)

## Response & recovery

- **11 seeded playbook templates:** NIST 800-61 R3, CISA Federal IR, CISA Vulnerability Response, Ransomware Containment, Credential Stuffing, Phishing Takedown, Anomalous Data Egress, OAuth App Revocation, Insider Data Exfiltration, DDoS Mitigation, Business Email Compromise
- Per-incident phase-grouped task list; template instantiation; progress bar; custom template builder
- Global `/playbooks` page with category filters + Execute flow
- **Respond Kanban** — 4 columns (Containment / Eradication / Recovery / Decisions), 42 action templates, 2-step picker, custom actions
- Per-card status, entity/target picker, revert workflow (audit-logged), auto-timeline logging on done
- Decision log (outcome, rationale, tags)

## Post-incident

- Closure checklist (9 seeded items, assignees, notes, progress)
- Lessons learned (root cause, effectiveness ratings, observations, near-misses, timeline metrics, action items, control improvements; HTML export)
- Response analytics (TTD/TTC/TTR, IOC/entity/timeline/playbook/respond/evidence breakdowns)
- MITRE post-incident summary
- **6 report templates** (Mission Control, Executive, Nordic Calm, Forensic, Compact, Tactical) with exec/full modes, 12 section toggles, classification override, remediation roadmap, show-structure preview, audit-grade history + verified re-download
- Business-impact assessment (6 dimensions)
- Cost tracking (line items, category/phase summaries)
- **Legal & regulatory deadlines** — GDPR, NIS2, DORA, HIPAA, CCPA, PCI-DSS with live countdowns, status workflow, custom deadlines
- **Law-Enforcement package** — admin-only AES-256-GCM ZIP: legal cover README, CASE_INFO, MANIFEST (SHA-256/512), INTEGRITY (sha256sum + HMAC-SHA-256), sections 01–09 (incident, timeline, IOCs, evidence + decrypted files + custody CSV, artifacts, forensic, comms, full audit trail + chain verification, legal SOP + tool provenance + TLP); one-time download; bundle KEK shown once

## Communications

- Comments (threaded, edit/delete, read-only on closed incidents)
- Out-of-band comms (passphrase gen/regen, dark-op toggle, 8 channel types, direction + verification)
- War room — WebSocket live chat per incident + presence/online list
- Notifications — WebSocket push, bell + unread badge + dropdown, toasts (5 types), 30s keep-alive
- Stakeholder contacts (typed directory, contact methods, bulk CSV import, card grid)

## Cross-incident analytics

- **Dashboard** — 7 KPI cards (open, crit+high, opened/closed 30d, MTTD/MTTR/MTTC), context strip (on-call, stale, legal-overdue), distribution widgets, All/Mine scope, 30-day trend, analyst workload, top MITRE tactics, live indicator, open-incidents table, 14-day activity feed
- Global ⌘K / Ctrl+K search across incidents/IOCs/entities/timeline (access-controlled, deep-linking)
- Threat Intelligence Hub (KPI bar, matched-incidents tab, IOC database, feed management link)
- Threat Actors database (scoring, MITRE sync, custom actors)
- Correlations (shared IOCs / shared entities, pagination, per-incident drill-in)
- Portfolio metrics (volume trend, TTx trend, type/IOC breakdowns, analyst load, playbook %, 30/90/180d window)

## Administration

- Hash-chained tamper-evident audit log (global + per-incident viewers, filters, pagination, expandable rows)
- **Signed audit-log export** — Ed25519 signature, AES-256-GCM ZIP, one-time 24h download, 30-day retention; public key/fingerprint at `GET /api/version`
- Background **audit-chain anchoring** (`audit-monitor` service) with optional RFC 3161 timestamps
- Session management (list, revoke, revoke-all per user)
- Storage admin (6 volumes: usage, file counts, pressure colour-coding)
- Backup status + manual trigger
- Fernet-encrypted API-key vault (VirusTotal, AbuseIPDB, Shodan, GreyNoise, URLScan)
- Theme picker (3 themes) + timezone picker (~45 IANA zones, detect-from-browser)
- Settings shell (Account, Sessions, Teams, Operational Roles, + admin Feeds / API Keys / Integrations / Metrics)

## API & integration

- OpenAPI (`/api/openapi.json`); Swagger + ReDoc under Admin (`/admin/api-docs`)
- Cookie + Bearer auth resolving to the same RBAC
- CORS + TrustedHost middleware; hardened CSP/HSTS/COOP/CORP/Permissions-Policy at Caddy
- Redis token-bucket rate limiting (anon per-IP 60/min, auth per-credential 600/min; `X-RateLimit-*`; 429 + `Retry-After`)
- Authenticated WebSockets (war room, notifications, presence) with keep-alive
- One-time encrypted download flow; per-export ephemeral AES-256-GCM keys; SHA-256 manifests
- Per-incident access control (`IncidentAssignment` + CISA roles) and team-based visibility gating (404-not-403 for forbidden)

### Integrations
- Email alerting — SMTP (STARTTLS) + Microsoft Graph (client-credentials), encrypted settings, test-send
- Outbound webhooks — Teams MessageCard + Slack Block Kit (incident created / phase / severity / resolved)
- SIEM inbound webhooks — Splunk / Sentinel / Elastic, `X-Fenrir-Key` auth, severity normalisation → incident
- Syslog forwarding — RFC 5424, UDP / TCP / TCP+TLS 1.3, optional mTLS, audit-only or audit+logging scopes

### Signed offline collectors (U1)
- Incident-scoped signed collection packages (Velociraptor v0.76.6, hash-pinned)
- Windows Triage/Full + macOS ARM64 profiles; X.509 per-package encryption (key wrapped under `EVIDENCE_KEK`)
- Ingest responder output → quarantine → first-class Artifact, `output_sha256` anchored in audit chain
- Auto-parse collector output → forensic import → triage → timeline

## Infrastructure

- Docker Compose: Caddy TLS (BYO / generated / DuckDNS / internal), Postgres + daily backup, Redis, air-gapped analysis worker, audit-monitor
- Non-root containers (backend 1001, worker 1002), read-only rootfs + tmpfs, dropped caps, `no-new-privileges`
- Volume separation (evidence, quarantine, reports, logs, branding); network isolation (`fenrir-internal` bridge + `fenrir-analysis` internal-only)

---