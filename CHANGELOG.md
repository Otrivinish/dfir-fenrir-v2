# Changelog

All notable changes to DFIR-FENRIR v2. Dates are UTC (ISO 8601).

## [Released] — `feature/ux-002` (merged, #28) and branch `fix/ebm` (2026-10-01)

### Changed

- **New date/time picker** for every date+time field (16 fields on 10 pages): a month calendar next to HH / MM / SS wheels, a switch to enter the time in your timezone or in UTC, and a readout of both — including the UTC value that is stored.
- **Changes are saved only with Apply.** Cancel, Esc or clicking outside discards them; previously every click saved immediately.
- Keyboard: Enter applies; arrow keys move through the calendar; on a wheel, ↑/↓ step by 1, PgUp/PgDn by 10, Home/End jump to the ends. The mouse wheel steps a wheel too.
- Daylight saving: a time skipped when the clocks go forward can't be applied, and the picker says why; a time that occurs twice shows which offset is selected.

### Fixed

- **Required date fields never blocked a form submit** (the hidden validation field was read-only, which browsers skip). Affects "Breach Detected At" when adding a legal deadline.

### Verification

- 49 headless-Chrome checks on the component in isolation — Apply/Cancel/Esc/outside click, keyboard, mouse wheel, timezone switch, `utc` fields, Clear, `required`, daylight-saving gap and repeat (Europe/Stockholm), a half-hour zone (Asia/Kolkata), placement at 390–1920 px, all three themes — 0 failures, 0 console errors. `npm run build` clean.
- Not yet checked in the running app: the 10 pages that use it sit behind login.

### Fixed — post-incident report

- **Timestamps follow the ISO 8601 rule.** They used to follow the reader's browser language (`09/15/2026, 10:30 GMT+2`, or `15.09.2026, 10:30 MESZ` in German), so one report read differently on different machines.
  - Now: `YYYY-MM-DD HH:MM:SS ±HH:MM`, 24 h, in the operator's Fenrir timezone, using the same formatter as the rest of the app.
  - The Timeline appendix used the browser's timezone instead of Fenrir's, so events late in the day could land under the wrong date. Fixed too.
- **Cost Tracking "Phase" column** was always blank: it read `phase`, but the cost data calls it `ir_phase`.
- **Playbook tasks show their assignee.** The report data now includes `assignee_username` for each task; before, only the user ID was sent, and the report printed nothing.
- **"Include sections" checkboxes work.** The 13 old checkboxes had no effect and partly named sections that no longer exist (e.g. "Entity graph").
  - **New list:** one checkbox for each of the 19 report sections, plus "Key metrics strip (cover)". All of them come from one shared list (`REPORT_SECTIONS` in `reportTemplates.js`) that the report, "Show structure" and the Reports page all use.
  - **Behaviour:** unticked sections are left out and the rest are renumbered. "Show structure" shows them greyed out as "Not included".
  - **Executive mode** still leaves out its four full-report-only sections; their checkboxes are greyed out there.
  - **Always printed:** the classification marking, TLP banner and cover are never left out.
- **Verification:**
  - **Generator:** report checks on the real generator all pass, in two browser languages (en-US, de-DE) and two browser timezones, with the same Fenrir timezone. All 12 timestamps are identical across runs.
  - **Checkboxes:** every checkbox removes exactly its own section. "Show structure" matched the report's numbering in 64/64 random checkbox combinations.
  - **API:** `assignee_username` was checked through the real report-data endpoint (rolled back).
  - **GUI:** the Reports page was checked in a headless browser.

### Incidents — immutable incident reference

- **References are now stored once, at creation, and can never change.** Before, `INC-0002` was recomputed from a counter on every read, so any format change would have renamed incidents in reports, LE packages and audit exports that had already been issued.
  - **New column:** `incidents.ref` (NOT NULL, unique).
  - **Enforcement:** a database trigger rejects any change. This covers the application's restricted role and a database superuser alike.
- **New format for new incidents:** `PREFIX-YYYY-NNNNN`, e.g. `INC-2026-00011`.
  - `YYYY` is the UTC creation year.
  - `NNNNN` is the existing global counter, zero-padded to 5. It never resets, and grows past 99999 without truncation.
- **Existing incidents keep their reference** (`INC-0001` … `INC-0010`): the backfill was checked to be byte-identical.
- **Prefix:** the default is `INC`, and admins can change it under **Settings → Incident Reference**, or via `GET/PATCH /api/settings/incident-ref`.
  - The page shows a preview of the next reference.
  - Changes are audit-logged (`incident_ref_prefix_changed`) and apply only to incidents created afterwards.
  - A valid prefix is 2–10 characters: a letter, then letters or digits.
- **Lookup:**
  - `GET /api/incidents?ref=…` is an exact, case-insensitive match for both formats.
  - Global search now matches references; before, typing a reference into search found nothing.
- **Both creation paths** use the new scheme: UI/API, and SIEM inbound webhooks.
- **MCP server (`dfir-fenrir-mcp`, separate repository):** now accepts both reference formats, and resolves a new reference through `?ref=`. The old 200-incident scan remains as a fallback for older servers. Tests: 43 passed.

### Security

- **Defender PDF import never loads native PDFium.** `pdfplumber` also installs `pypdfium2` (native PDFium), but only uses it for page rendering, which FENRIR doesn't do.
  - `defender_pdf/parser.py` now blocks that import, so an untrusted PDF can never reach native code; any rendering attempt fails loudly.
  - The `requirements.txt` comment that claimed "no native PDF renderer" is corrected.

### Upgrading

- Rebuild and restart: `docker compose up -d --build backend audit-monitor frontend`. The `migrate` service adds and backfills `incidents.ref` and creates the trigger. It is safe to re-run.
- Update `dfir-fenrir-mcp` too, for the new reference format. Older MCP versions can't resolve `PREFIX-YYYY-NNNNN` references; UUIDs keep working.

### Verification — incident reference and PDF import

- **Database:** all 10 existing references are identical after the backfill. The trigger blocks renames by both `fenrir_app` and the superuser; normal updates work; re-running `migrate` is a no-op.
- **API:** 18/18 end-to-end checks through the real app pass: creation (UI/API and webhook), year, renaming blocked, `?ref=` and search for both formats, prefix validation, audit entry, prefix applies to new incidents only, report data and OpenAPI. They ran in a rolled-back transaction, with the counter restored.
- **GUI:** the Settings → Incident Reference page was checked in a headless browser. Input is uppercased, an invalid prefix is blocked, and saving updates the preview.
- **PDF:** the Defender PDF parser still works with PDFium blocked; `page.to_image()` raises.
- **Gates:** `make posture` 72/72. Logs of backend, migrate, audit-monitor, frontend and Caddy were clean.

### Known issues

- **`make scan` currently fails (3 images).** Fixes for High OpenSSL / PCRE2 CVEs were published on 2026-10-01: Debian `openssl 3.5.7-1~deb13u3` and `pcre2 10.46-1~deb13u3`, and Alpine `libssl3 3.3.7-r2`. The backend and analysis-worker need a rebuild without the Docker cache to pick them up. The pinned `redis:7.4-alpine` digest needs updating. This is not caused by the changes above.

## [0.3.1] — 2026-10-01 — container security hardening — **breaking for upgrades**

Zero-trust / least-privilege hardening of the Docker deployment. No change to the API, the data model or the UI — but upgrading an existing installation needs one manual step, and some clients may lose access (TLS 1.3 only). Decisions: [`docs/adr/`](docs/adr/README.md).

### ⚠ Upgrading

1. **Run `./setup.sh` once after pulling** (idempotent). `docker compose up -d --build` on its own fails. It moves your secrets out of `.env` into `./secrets/` (values preserved), creates the internal service certificates, applies the new database roles and prepares Caddy's volumes.
2. **Set `BACKUP_AGE_RECIPIENT`** in `.env` to an age public key generated **offline** (`age-keygen -o fenrir-backup.agekey`). Unset = unencrypted dumps (with a warning). Existing dumps: `scripts/encrypt-legacy-backups.sh --apply`.
3. **Back up the four keys that can never be regenerated — before storing any evidence** ([INSTALL.md §5.2](INSTALL.md#52-back-up-the-keys-offline--do-this-now) has the full procedure):

   | Key | Lose it and… |
   |---|---|
   | `./secrets/evidence_kek` | all evidence and the evidence-backup mirror are unreadable |
   | `./secrets/secret_key` | every user's TOTP and the stored integration API keys are lost |
   | `./secrets/audit_signing_key` | past signed audit exports can no longer be verified |
   | `fenrir-backup.agekey` (age identity) | every DB backup is unreadable |

   In short: record fingerprints (`tr -d '\r\n' < secrets/<key> | sha256sum`), store the four files as **attachments** in your password manager plus a second offline copy, prove the copy with `AGE_IDENTITY=<exported key> make verify-restore`, and keep the age identity **off** the server. On a new host, put the three `./secrets/` files back **before** running `./setup.sh`.
4. **The edge is TLS 1.3 only.** Browsers are fine; Windows 10 / Server 2019 PowerShell and `curl.exe`, Java < 11 and older HTTP clients are not. **Check that your SIEM webhook senders (Splunk / Sentinel / Elastic) support TLS 1.3** before upgrading.
5. **Only `DOMAIN` is served.** Opening FENRIR by IP or another hostname now returns an empty page — use the `DOMAIN` name. Set `TLS_MODE` explicitly (`selfsigned` · `acme` · `duckdns` · `byo` · `internal`).
6. Restores of age-encrypted dumps need the identity: `scripts/restore.sh --identity <key>`.

### Security

- **Edge (Caddy 2.11.4, pinned):** TLS 1.3 only in every TLS mode; new `TLS_MODE` incl. Let's Encrypt for public names; runs as uid 10001 with no capabilities and a read-only root filesystem; receives no application secrets; the local CA private key moved to `./ca/` (never mounted). Slow-header timeout (10 s), body limits (10 MiB JSON, 2.2 GiB multipart), `connect-src 'self'`, admin API off, one Caddyfile as the single source.
- **Networks:** new internal-only `fenrir-data` tier (Postgres, Redis, backup, audit-monitor, migrate) — no internet, unreachable from the edge. The backend trusts `X-Forwarded-For` only from Caddy's pinned address; audit IPs can no longer be spoofed.
- **Encryption in transit, internally:** a separate, name-constrained internal CA (`scripts/internal-pki.sh`, auto-renewal). Caddy → backend and backend → Redis use mutual TLS; Postgres is TLS 1.3 verify-full with plaintext refused; backend → analysis worker uses TLS plus a bearer token.
- **Secrets:** Compose secret files in `./secrets/` (dir 0700), mounted only into the services that need them — no secret in any environment variable, `docker inspect` or child process. `.env` is mode 0600.
- **Database least privilege:** per-service roles. The app role is DML-only: it cannot modify or delete audit-log rows, drop the append-only trigger, run DDL or `COPY … TO PROGRAM`. Schema changes run in a new one-shot `migrate` service. The bootstrap superuser can only connect over the container's local socket. Connections and DDL are logged.
- **Redis:** ACL with the default user disabled; the app user is limited to its commands and key prefixes. RDB snapshots instead of AOF.
- **Containers:** all non-root (the backup sidecar keeps only `CHOWN` + `FSETID`), every capability dropped, `no-new-privileges`, read-only root filesystems, memory/PID limits, rotated logs, healthchecks with health-gated startup.
- **Analysis worker:** authenticates every call (token), serves TLS, no docs/OpenAPI, strict `/quarantine` path containment, 500 MiB input cap, YARA timeouts, analyzers off the event loop; dependencies updated (python-multipart, starlette, pdfminer.six advisories).
- **Supply chain:** base images pinned by digest (`scripts/refresh-digests.sh`), node 20 → 24 LTS, nginx 1.27 → 1.30, Redis pinned to 7.4; Python dependencies hash-locked (`scripts/lock-python.sh`, 14-day cooldown); API-docs assets vendored and checksummed; `age` built from source; `make scan` (hadolint, Grype, Dockle) fails on fixable High/Critical without a dated exception (`.grype.yaml`); SBOMs (`make sbom`).
- **Backups:** age public-key encryption (sidecar and manual), fail closed; evidence-mirror copies are root-owned read-only.

### Fixed

- Scheduled DB backups **silently stopped** after every restart (the loop slept 24 h before its first run); retention would then have deleted every older dump. Now: hourly check of a success marker, newest 14 always kept, failures leave no partial dump.
- Manual backups made in the app could not be restored with `scripts/restore.sh` (`pg_dump` 17 vs a Postgres 16 server); the backend now ships `postgresql-client-16`.
- The evidence-backup mirror was writable by the backend it is meant to protect.
- The audit monitor ran a stale image (it was built separately from the backend).
- The frontend healthcheck always failed (`localhost` resolved to IPv6).
- The syslog forwarder left its client private key in `/tmp` on every reconnect.
- The KEK-rotation runbook's command could not work as written.

### Operations

- New scripts / make targets: `make posture` (security posture check of the running stack), `make smoke` (functional smoke test), `make scan` / `make sbom`, `make verify-restore`, `make pki`, `make db-roles`, `make lock`, `make digests`.
- Memory: the backend is capped at 6 GiB (a 1 GiB evidence upload peaks at ~4 GiB). Size hosts handling evidence near the cap at 12 GB+.
- Developer notes: the backend container is read-only (write only to `/tmp`, the data volumes or `/app/data`); new Redis commands or key prefixes must be added to the ACL in `scripts/secrets.sh`; after changing a secret file, `docker compose up -d --force-recreate <service>`.

### Known limits

- Host-level controls stay with the operator: full-disk encryption for the Docker volumes and `./secrets`, and filtering published ports on the `DOCKER-USER` chain (Docker bypasses `ufw`).
- The backend keeps direct internet egress (OSINT, webhooks, SMTP, syslog) — accepted risk, [ADR-0007](docs/adr/0007-backend-egress-accepted-risk.md).

## [0.3.0] — 2026-09-30

Post-incident report remap, incident detection time, two UX standards (control sizing, date/time entry), a dependency refresh under a 14-day cooldown, and layout fixes.

### Post-incident report

The report is `generateProReport` in `frontend/src/lib/reportTemplates.js`. Sections are numbered automatically in the order they appear.

- **Cover:** "Incident ID" shows the incident reference (`INC-0002`); "Opened" is the creation time; "Closed" is the resolve time, or "Not closed".
- **§ Executive Summary** now prints *What happened* (Details → Resolution summary, stored as `lessons_learned.incident_narrative`). The Description appears only under Incident Details.
- **Incident Details:** adds Reporter, Occurred At and **Detected At** (new field, see below). Closed At shows "Not closed" while open. The Description is rendered as **Markdown**, using the same renderer as the UI: raw HTML is shown as text and `javascript:` links are stripped.
- **Containment, Eradication & Recovery:** the three tables share fixed column widths, so Status and Notes line up. New Description and Occurred At columns. "By" stays the action's assignee.
- **Decisions Log** is its own section, with Decided By and Decided At.
- **Executive report** leaves out Detection & Identification; Containment, Eradication & Recovery; Evidence & Artifacts; and Playbook.
- **Detection Method** prints the friendly label (e.g. "SIEM Alert") instead of the code.
- **Lessons Learned & Recommendations** now sits directly before the Remediation Plan. Each sub-heading prints the Reports-tab text **and then** the structured Lessons Learned entries (previously it printed one or the other).
- **Remediation Plan:** action items are sorted into terms by due date measured from the incident's **close time** (report time while open), so regenerating a report never moves items. Undated items go under "Unscheduled".
- **Impact → Legal Obligations** is empty unless legal deadlines have been initialized; it then lists the obligations. The misleading "[ GDPR Art.33 / NIS2 ]" placeholder is gone.
- **New sections:**
  - **Stakeholders** — name, title, organization and type only; contact details are never printed.
  - **Legal & Regulatory Deadlines** — per deadline: met / violated (completed late or overdue) / pending / waived, computed server-side.
  - **Attack Chain** — a visual swimlane per MITRE tactic; shown only when timeline events carry a tactic.
  - **Threat Actor Attribution.**
- **Appendices** have fixed letters: **A = Affected Systems** (always present), **B = Incident Timeline** (optional; the checkbox is now "Appendix B — Timeline").
- **"Show structure"** now mirrors the real report exactly: the same sections, fields and where each is entered in the UI. Both sides carry KEEP IN SYNC comments.
- ~880 lines of unused legacy report renderers were removed.

**API** — `GET /api/incidents/{id}/reports/data` additionally returns:
- `incident.ref` and `decided_by_username`
- `regulatory_deadlines` (with `compliance` and `hours_late`)
- `stakeholders` (identity and role only)
- `attributions`
- `affected_systems`

### Incidents

- New field **`detected_at`** (when the incident was detected): column `incidents.detected_at` (added automatically at startup, safe to re-run), in `IncidentUpdate` / `IncidentOut`, settable and clearable via `PATCH /api/incidents/{id}`. In the UI: Details → Classification → Detected.

### UI / UX

- **Details:** Classification is a horizontal band between the snapshot strip and Description (3 fields per row at 1440 px, 5 at 1920 px).
- **Phase stepper:** each phase is coloured by its NIST CSF 2.0 function colour (nist.gov/cyberframework/faqs), with lightness matched to each theme. Prep = Protect (purple), Detect = Detect (amber), C/E/R = Respond (coral), Post = Recover (green). New tokens `--phase-prep/detect/respond/post` in all three themes. States: ✓ done, filled current, dimmed upcoming.
- **Dashboard:** Recent Activity is a bottom strip showing the latest 6 events, with **"List all (14 days)"** opening a popup of up to 200 events grouped by day. Open Incidents now uses the full width.
- **Control sizing standard** (`frontend/src/styles/base.css`):
  1. Toolbar buttons never wrap; toolbars wrap as rows instead.
  2. Toolbar dropdowns and search boxes are compact, at button height.
  3. Scrollbars are thin and theme-coloured.
  4. A wide table never widens the page (`.table-scroll`; `.settings-table.compact` for dense tables).
- **Date/time entry standard:** one component, `LocalDateTimePicker`, for every date+time field.
  - Entry is in the operator's timezone with the offset shown; values are stored in UTC. A `utc` option is used for filters over UTC data (Web Browser History).
  - The popup is pinned to the screen and never needs scrolling. The field matches neighbouring fields (one line, same height).
  - Converted: Details, Decisions, Legal ×2, LE package, Entity drawer, Audit log ×2, Audit exports ×2, Web history ×2.
  - `UtcDateTimeInput` and `UtcDateTimePicker` were removed.
- **Layout fixes:** the IOCs page no longer scrolls sideways; the table fits at ≥1440 px and scrolls only inside its panel below that. The Respond board uses 4 equal columns, dropping to 2×2 when narrow, instead of scrolling.

### Dependencies (backend)

Every version, including transitive ones, was released **at least 14 days** before pinning (cooldown against freshly published or compromised releases).

| Package | Before → After |
|---|---|
| fastapi | 0.115.6 → 0.141.1 (starlette 0.41.3 → 1.6.0) |
| uvicorn[standard] | 0.34.0 → 0.53.0 |
| pydantic[email] / pydantic-settings | 2.10.4 → 2.13.5 / 2.7.0 → 2.15.0 |
| sqlalchemy[asyncio] / asyncpg | 2.0.36 → 2.0.54 / 0.30.0 → 0.31.0 |
| redis | 5.2.1 → 8.1.0 |
| argon2-cffi | 23.1.0 → 25.1.0 |
| cryptography | 48.0.1 → 50.0.1 (supersedes Dependabot PR #18) |
| reportlab | 4.2.5 → 5.0.1 |
| python-evtx / extract-msg | 0.7.4 → 0.8.1 / 0.54.1 → 0.56.1 |
| python-multipart, pyotp, qrcode, pyyaml | patch / minor |

- `main`'s new packages (#24/#25: `pdfplumber` 0.11.10, `nh3` 0.3.7, `tnefparse` 1.4.0) were already the newest ≥ 14-day releases; kept as-is.
- **New `backend/constraints.txt`** locks every transitive package (73 packages in total after the merge); the Dockerfile installs with `-r requirements.txt -c constraints.txt`. When bumping `requirements.txt`, re-resolve it with the same 14-day rule.
- `dashboard/routes.py`: `Query(regex=…)` → `Query(pattern=…)` (FastAPI deprecation; same validation).
- **Behaviour changes, reviewed:**
  - `.msg` import now uses extract-msg's native converter and keeps **all** "To" recipients (the old fallback dropped all but the first); a missing Date header is `null` instead of `""`.
  - OpenAPI schema descriptions were refined (`additionalProperties`, `contentMediaType` for uploads). No path, method, parameter or status code changed.

### Operations

- `docker-compose.yml`: the frontend health check probes `http://127.0.0.1:3000`. `localhost` resolved to IPv6 `::1`, where nginx doesn't listen, so the container reported "unhealthy".

### Upgrading

- Rebuild `backend`, `audit-monitor` and `frontend` (`docker compose up -d --build backend audit-monitor frontend`). The `detected_at` column is added automatically on backend start.

### Verification

- **Dependencies:** a smoke test through the app's own code paths, run before and after the bump, passed 12/12, and **14/14 after merging `main`** (adds the Defender PDF parser, `nh3` sanitising and `tnefparse`): password hashing, TOTP/QR, Fernet, AES-GCM (including decrypting stored files), Ed25519, RSA/x509, EVTX, `.msg`, the audit PDF, report data, Redis, API/ASGI. `pip check` is clean; all 73 installed packages are ≥ 14 days old.
- **Report:** 58 automated render checks on real and synthetic data. "Show structure" and the report produce identical section lists in all 4 mode/appendix combinations.
- **UI:** headless-browser audit of 27 incident sub-pages (30 after the merge, including the new top-level IOCs tab and Defender PDF import) at 1100 / 1280 / 1440 / 1920 px — no wrapped toolbar buttons, and no page scrolls sideways.
- Logs of backend, frontend and Caddy were clean after each deploy.

### Known issues / not in this release

- **Incident reference redesign** (immutable `PREFIX-YYYY-NNNNN`, existing references kept): design written, awaiting go-ahead.
- Pre-existing report issues, not changed here:
  - Report timestamps use the browser's locale format.
  - The Cost Tracking "Phase" column is blank (reads `phase`; the column is `ir_phase`).
  - The Playbook assignee isn't printed.
  - The "Include sections" checkboxes have no effect.
- A pre-existing warning is still logged: duplicate OpenAPI operation ID `mint_evidence`.
- The frontend bundle grew ~11% (Markdown rendering in reports).
- `backend/requirements.txt` (from #25) describes `pdfplumber` as having "no native PDF renderer in the attack surface", but `pdfplumber` 0.11 depends on `pypdfium2` (native PDFium), which is installed in the image.

---

## IR workflow waves — branch `fix/ebm` (2026-10-03)

Built from the IR-expert workflow audit of 2026-10-01: 21 approved pieces (A1–A5, B1–B5, C1–C5, D1–D5, E3), two owner-approved extras (AX1, AX2) and six review fix passes. Pieces are tagged in brackets.

### Security
- **Dark Operation now blocks outbound alerts.** Teams, Slack and alert-email messages about a dark incident aren't sent, each blocked message is logged in the audit log, and an incident can be opened dark. (A1)
- **Dark Operation skips automatic email DNS checks.** The SPF/DKIM/DMARC lookups an email analysis makes on the sender's domain are skipped and audited. The manual domain check still works. (AX1)

### Fixed
- **Viewers and the Situation board.** (DE-fix)
  - Viewers land on Incidents instead of a broken Dashboard.
  - Situation board text is readable in every theme.
  - Switching incidents shows no stale panels.
  - Rail counts update right after a change.
  - LE package screens say HMAC-SHA-256.
- **LE packages and exports don't freeze the app.** Building an LE package and downloading an export no longer stall the server (from about 20 s to under 0.1 s on a 348 MB package). (DE-fix)
- **Phase colours and glyphs.** Phase colours are softened to the NIST CSF 2.0 hues and get a symbol each (◇ ◉ ⊘ ↺), so they no longer look like severity. Undefined button classes are fixed, and in-card dropdowns use the standard compact size. (D1)
- **Metrics leak closed.** Metrics count only incidents you can see; before, they included other teams' incidents. (E3)
- **Analysts can assign work.** Analysts can assign playbook tasks and response actions, record who decided, and pick colleagues as evidence witnesses. Names replace ID fragments. (A2)
- **Complete Timeline.** The Timeline and its CSV/HTML exports show every event, not only the first 500. Actions logged straight as Done get a completion time and a Timeline entry. (A3)
- **Evidence export and imports.** Select all and Unselect all work, and destroyed or verify-failed exhibits are greyed out and refused (409). PCAP IOC import no longer drops earlier rows or crashes. Importing email hops twice no longer duplicates them. (A4)
- **Edit draft and cost totals.** Saving Tags or Teams no longer discards unsaved Details edits. Costs are totalled per currency in the API (`by_currency`), the panel and reports. (A5)
- **Concurrent edits are kept.** Saving tags or teams refreshes every Details field you haven't edited, so another responder's change is no longer reverted. (A-fix)
- **Hop button and Timeline paging.** The email hop button matches what the server can import and offers "Re-import missing hops". Timeline paging can't repeat or skip rows. (A-fix)
- **Modals scroll.** Long forms scroll inside the modal, and the Save/Create button stays on screen at every window size (56 modals checked). (AX2)
- **Live notifications work.** The bell, toasts and Dashboard update live in every open tab, and only after the change is saved. (B-fix)
- **Gate integrity.** Marking an incident false or benign positive outside Detection & Analysis needs a reason. Milestones can't be earlier than Detected, and metrics show how many incidents they exclude. (B-fix)
- **Wave C security and integrity fixes.** (C-fix-1)
  - YARA promotes check incident access.
  - You can't transfer custody to yourself.
  - Parser column choice is deterministic (parser 2.1.0).
  - Truncated parses are flagged.
  - Decrypted evidence is parsed on a RAM-only tmpfs.
  - Hashing and exports no longer freeze the app.
- **Wave C UI and MCP fixes.** (C-fix-2)
  - Containment templates only accept matching target types.
  - Case-insensitive affected systems.
  - Timeline host linking is explicit.
  - Untimestamped import rows can become IOCs.
  - MCP `add_batch` works again and errors show their code.

### Added
- **Detection at intake.** New incidents capture Detected (pre-filled with now), How detected and Triage state. SIEM webhooks record the vendor's alert time. (B1)
- **Declare milestones.** Contained, eradicated and recovered are declared from the incident header, each with a Timeline entry. (B2)
- **Resolve ≠ Close.** Resolve moves an incident to Post-Incident and keeps it open. Close is a separate sign-off with a reason and records who closed it. Re-open asks for a reason and a phase. After Close, lessons-learned action items stay editable. (B3)
- **Legal clocks.** Deadlines start from the incident's Detected time, with optional per-regulation anchors. The header shows a countdown per regulation. In-app reminders arrive 12 h and 2 h before, and when overdue. Deadlines can be re-anchored with a reason. (B4)
- **Phase gates.** `GET /api/incidents/{id}/gates` shows what is still missing before Post-Incident (Gate 1) and before Close (Gate 2). The phase and Close dialogs list the gaps with links, and an override needs a reason, which is audited and posted to the Timeline. (B5)
- **Containment state on hosts and IOCs.** Response actions link to an entity or IOC. Entities and IOCs show Isolated, Disabled, Blocked or Pending, and the API and MCP can filter actions by target. (C1)
- **One scope list.** Affected systems are now the incident's compromised entities, so you add a host once. Timeline events pick their host from Entities and carry an IR phase. (C2)
- **Evidence intake check.** The hash reported by your imaging tool (MD5, SHA-1 or SHA-256) is checked against the uploaded file, and the acquisition time is recorded. Exhibits minted from Email or Browser history appear in the custody log. (C3)
- **Custody transfer acceptance.** The custodian requests a transfer, and custody changes only when the recipient accepts and records the condition and seals. A pending transfer blocks dispose and seal. (C4)
- **Timeline Import from an exhibit.** It parses a registered, hash-verified exhibit and logs the examination to custody. A source timezone is required, assumed or inferred times are marked, and untimestamped events are never placed at "now". YARA matches use their scan time. (C5)
- **Incident-lead rights.** An IC or Deputy analyst can read the incident audit log (the read is audited), build the LE package and set teams on their own incident. `GET /api/incidents/{id}/access` lists your rights. Assignees are notified. (E3)
- **Incident menu in 800-61 order.** The incident rail has phase-coloured groups, live counts and clearer names (Team, Shift handoffs, Supporting documents). On narrow screens it is one scrolling row. Old URLs still work. (D2)
- **Situation board.** It is the incident landing tab. Classification shows as one horizontal strip, with milestones, gate status, open actions, team gaps, handoff, next tasks and the newest events on one screen. The timeline API sorts newest-first with `?sort=-event_time`. (D3)
- **Forensic is now Examine.** Its tabs are in three workflow groups with Collector packages first. Attribution moved under ATT&CK, the Sandbox stub is hidden, and "Register as exhibit" replaces "Mint". Old links redirect. (D4)
- **Grouped sidebar.** Operate, Investigate, Intel, Prepare, Report and Admin, with Help and Account at the bottom. Metrics moved out of Admin to `/metrics` for analysts. Links follow what each role can open. (D5)

### Changed
- **Mixed-currency totals.** `GET …/costs/summary` returns `null` top-level totals and currency when an incident mixes currencies; the old totals added EUR and USD together. Use `by_currency`. (A5)
- **Start phase.** `POST /api/incidents` accepts only `detection_and_analysis` or `containment_eradication_recovery` as the starting phase, and rejects a `detected_at` before `occurred_at` or in the future (422). (B1)
- **Response metrics fixed.** Entering C/E/R no longer stamps Contained. MTTD, MTTC and MTTR are measured from Detected and drop negative intervals; the old MTTC could come out negative. (B2)
- ⚠ **Breaking API change: close and re-open need a body.** `POST /api/incidents/{id}/close` requires `{reason}` (≥10 characters), and `…/reopen` requires `{reason, phase}`. Calls without a body return 422. New errors use a flat `{detail, code}` shape. (B3)
- ⚠ **Legal API is stricter.** Waive needs `completion_notes` (10+ characters); deleting a deadline needs a reason; closed incidents reject initialise, add, delete and re-anchor (409). The NIS2 final report is due one calendar month after the 72h notification; GDPR Art. 34 is labelled an internal target. (B4)
- ⚠ **Breaking API change: phase gates.** A PATCH into `post_incident` and a POST close return 409 `gate_unmet` until the gate is met, or `override_gate=true` with a reason. `phase=preparation` returns 409, and moving back a phase needs `phase_reason`. False and benign positives close with only a reason. (B5)
- ⚠ **API changes in the Wave B fixes.**
  - Notification WebSocket frames are now `{type:"notification", notification:{…}}`.
  - The legal deadline DELETE takes `{reason}` in the body (`?reason=` is deprecated).
  - New 422 codes: `triage_reason_required`, `milestone_before_detection`, `milestone_before_occurred`.
  - Dashboard and metrics add `*_excluded` counts. (B-fix)
- **`/affected-systems` is deprecated.** DELETE now clears the compromised flag instead of deleting. Entities accept `compromised` and `?compromised=`; timeline events gain `entity_id`. (C2)
- ⚠ **Evidence upload refuses a mismatching hash.** A target hash that doesn't match the uploaded bytes now returns 422 `hash_mismatch` and nothing is stored. Hashing the data inside a container needs `target_hash_scope=container_media`. (C3)
- ⚠ **Internal evidence transfers are requests.** `POST …/transfer` no longer moves custody; the recipient must call `…/transfer/accept`. Only the custodian or an admin can start a transfer. (C4)
- ⚠ **Imported Timeline facts are immutable.** Editing them returns 409, as does disposing an import with promoted events. The LE `timeline.csv` gains four trailing provenance columns. (C5)
- ⚠ **Wave C fix API changes.** (C-fix-1)
  - New errors: 422 `recipient_is_requester`, 403 `not_authorised_take_back`, 409 `reparse_required`, 503 `evidence_read_error`.
  - IOC `entity_id` must belong to the incident.
  - New flat codes for closed, not-found and parse errors.
  - Imports add `truncated` and `total_seen`.
  - The backend has a new tmpfs mount.
- ⚠ **Containment target types are checked.** A containment template linked to the wrong target type returns 422 `target_type_mismatch`. The deprecated `POST /affected-systems` reuses an existing entity case-insensitively. (C-fix-2)
- ⚠ **Permission changes.** (E3)
  - Only the incident lead or an admin can override gates (403 `not_incident_lead`).
  - Assigning IC/Deputy needs the lead, or the creator or on-call while there is no lead.
  - An assignee without access gets 422.
  - `team_ids` is lead-only.
- ⚠ **Final fix pass changes.** (DE-fix)
  - A non-admin lead may only add teams they belong to and must keep one (409 `would_lock_out`).
  - A deactivated IC role grants no lead rights.
  - New LE packages record `signature_kind=hmac-sha256`.
  - Every audit-log page a lead reads is audited.

### Added (E-wave, 2026-10-03)

- **Readiness.** `GET /api/readiness` runs 11 CSF-tagged preparation checks. Prepare → Readiness shows them, the Dashboard shows a banner while a blocker fails, and the New-incident form lists failing blockers without stopping you. MCP gets a readiness view. (E1)

- **Contacts and DPO.** Prepare → Contacts holds supervisory authority, CSIRT, police, insurer, IR retainer and PR contacts, verified and copied into incidents. Fenrir gains a Data Protection Officer role. Responders' out-of-band contacts appear on On-call and the Dashboard. Readiness adds 3 checks. (E2)

- **Report additions.** Screenshots from Supporting documents can go into the final report as numbered figures with their SHA-256, alongside a communications log, an approval and sign-off block, NIST CSF 2.0 IDs on every section and NCISS severity. (E4)

- **E-wave fixes.** (E-fix)
  - A corrupt figure is marked "integrity failed" instead of breaking the report.
  - The sign-off reason comes from the close audit record, so it can't be forged.
  - The timeline refuses server-reserved event sources.
  - MCP hides out-of-band contacts by default.
  - Readiness details for sensitive checks are admin-only.
  - Over-large images are refused.
  - Figure hashes are stored.
- ⚠ **E-wave fix API changes.** (E-fix)
  - `POST /timeline` returns 422 `reserved_system_source` for server-only sources.
  - Files download/include return 409 `file_integrity_failed` for tampered files.
  - Including a report figure returns 422 `image_too_large` over 16384 px or 50 MP.
  - `report_files[]` gains `integrity`.
  - The new report-data timestamps end in `Z`.
  - Migration adds `entity_files.report_sha256` and `report_mime`.

### Backlog wave F (2026-10-03)

- **Security updates in images.** Images take distro security updates at build time; the High OpenSSL/PCRE2 CVEs are fixed in the backend, worker and frontend. (F1)
- **Exports don't freeze the app.** LE package and audit-log export builds run off the event loop, and audit-export downloads stream from disk. (F1)
- **Migrations don't hang.** They give up after 5 s on a locked table and roll back whole. (F1)
- ⚠ **People references are checked.** Assignee, decider, witness, handoff recipient and checklist owner must be an active user who can see the incident (404 `user_not_found`, 422 `assignee_no_access`). An explicit `null` unassigns. Analysts may restrict new incidents only to their own teams (409 `would_lock_out`). (F2)
- ⚠ **Closed record integrity.** (F3)
  - Defender, PCAP, Artifacts and Timeline Import writes return 409 on closed incidents.
  - Re-opening into Post runs Gate 1.
  - A false positive created outside D&A needs `triage_reason`.
  - Server-recorded timeline events are immutable (409 `system_event_immutable`).
  - The War Room drawer is locked to the current incident.
- **Disclosure accuracy.** (F4)
  - Exports record working copies only for items whose bytes are included.
  - ISO 27037 and NIST SP 800-86 clause citations are corrected.
  - LE packages describe their real encryption and include eradicated/recovered times and acquisition and hash-check columns.
  - Legal and custody timestamps end in Z.
- **List correctness.** (F5)
  - Tag filters and threat-actor search return results instead of 500.
  - Incident pages load every row of IOCs, entities, evidence, exports, actions, decisions and comments.
  - Paged lists have no duplicates or gaps.
  - The audit log shows when it's partial.
- **Redis CVE exception.** The 6 OpenSSL Highs in `redis:7.4-alpine` have no upstream fix and aren't reachable. They are excepted in `.grype.yaml` until 2026-10-17, pinned to 3.3.7-r1; `make scan` is green. (F1)

### Wave F fix pass (2026-10-04)

- **Deploys no longer fail while the app is open.** WebSockets no longer hold a database transaction.
- ⚠ **API contract changes:**
  - Sending `dark_operation` to PATCH incident returns 422 `use_dark_operation_endpoint`.
  - A corrupt PDF returns 422 `parse_failed`.
  - A tag with no usable characters returns 422 `invalid_tag`.
  - A false or benign positive leaving Detection & Analysis needs `triage_reason`.
- ⚠ **Closed incidents:** more evidence writes and deletes return 409 `incident_closed`. Communication records stay writable.
- ⚠ **War Room:** messages are paged newest-first with `next_cursor`, and `before` is honoured.
- **LE package:**
  - README, SOP and MANIFEST statements are corrected.
  - MANIFEST schema is 1.1.
  - `detected_at` is included.
  - Custody-export ZIP entry names are sanitised.
- **Smaller fixes:**
  - Deactivated users are no longer named in errors.
  - Exports lock their items.
  - Null threat-actor lists are stored as `[]`.
  - Correction notes were added for 6 historical working copies.

- **UI:**
  - The War Room has "Load older messages".
  - Phase change asks for the triage reason.
  - The IOC link picker loads one page at a time.
  - Page loads stop when you navigate away.
  - Closed incidents hide the scan and write controls they refuse.
- ⚠ **API:** a threat-actor PATCH with `name` or `motivation` set to null returns 422.
- ⚠ **MCP:**
  - `fenrir_artifact_write update` takes only `description`.
  - `fenrir_respond_list` adds `limit`/`cursor`.
  - `fenrir_intel_lookup` correlations add `tag`/`limit`/`cursor`.
- **Supply chain:**
  - `scan.sh` enforces image-scoped grype exceptions.
  - ADR 0008 records why images take distro security updates at build.

### Backlog wave G: evidence-first chain (2026-10-04)

**Encrypted storage (G1)**
- **New format, FENRGCM v2.** Every new evidence file, photo, entity file and incident file gets its own data key, wrapped by a key derived from the master key.
  - Files are written in authenticated 1 MiB chunks, so truncation and tampering are detected.
  - The format was frozen after two independent crypto reviews. Older files still read.
- **Reads are checked before decrypting:** size, header and nonce prefix. Tampering freezes the exhibit. An unreadable file is audited and admins are notified (de-duplicated).
- ⚠ **Chunked, resumable uploads** (`/api/incidents/{id}/uploads`) encrypt evidence as it arrives.
  - Plaintext never reaches server disk; any remaining multipart upload spools to RAM only.
  - `GET …/uploads` lists your open sessions.
- ⚠ **KEK rotation tool,** `python -m evidence.rotation`, covers evidence, photos, entity and incident files, collector keys and the backup mirror.
  - It is a dry run by default and crash-safe; `--breach` re-encrypts.
  - The runbook is rewritten.

**Streaming and limits (G2)**
- ⚠ **Evidence limit is 10 GiB.** Downloads, exports and LE packages stream with bounded memory (ZIP64).
- ⚠ **Size errors:**
  - A full disk returns 507 `insufficient_storage`.
  - An exhibit over an analyser's cap returns 413 `exhibit_too_large_for_analyser`.
  - Legacy multipart routes are capped at 512 MiB and deprecated.
- ⚠ **The export decrypt recipe now streams;** the old recipe fails above 2 GiB.

**Register first, with run records (G3, G4)**
- ⚠ **Email, PCAP and Browser history are register-first.** An upload creates an unsealed draft exhibit; analysis runs `from-evidence` with a run record.
- **Complete & seal** finishes a draft.
- ⚠ **Defender reports and Velociraptor collections link to exhibits:**
  - Defender imports run from an exhibit with a server-side commit; pre-G4 imports must be re-imported.
  - The collector container is hashed before decryption.
- **Device clock offset.** Exhibit imports correct event times and keep the recorded time. Defender cloud times are not shifted.
- **PCAP analyser 2.1.0:** capture times, conversations and DNS answers. PCAP and browser history feed the Timeline.

**Working copies, legal hold, sealed record (G5)**
- **Working copies:** analysts download a registered working copy, and the server records the hash of the exact bytes sent.
  - ⚠ Record copy needs the copy's own hash.
  - ⚠ Examinations name a verified copy, or "in place" with master pre/post verify.
- ⚠ **Legal hold:** `PUT …/legal-hold`. Analysts set it; the lead or an admin releases it. A held item can't be destroyed.
- ⚠ **Sealed items:** photos and collector role are immutable; other changes are logged as amended after seal.

**Fixes from the wave review**
- **Security:**
  - Files named like rotation journals can no longer block startup or be deleted.
  - Download tokens are redacted from the Caddy and backend logs.
- **Data integrity:**
  - Photo edits no longer drop stored photos.
- **Tamper handling:**
  - ⚠ LE packages label tampered exhibits `integrity_failed` and freeze them.
  - ⚠ Exports hash every file; a mismatch discards the bundle (409).
- ⚠ **Unsealed drafts are left out of LE packages and exports** unless a lead opts in (audited); inventories gain seal and lawful-basis columns.
- **Backup:**
  - ⚠ Backup skips runs during a key rotation and refuses unencrypted dumps.
  - The mirror purge can't glob.
  - Disposed exhibits are purged from the mirror after 30 days (audited).
- **Closed incidents:** ⚠ passphrase and Dark Operation changes return 409.
- **Bulk email** no longer holds the audit lock across a batch.
- **Exports** no longer lock exhibits during the build.
- ⚠ **MCP:**
  - New and changed tools for uploads, from-evidence, promote, working copies and legal hold (release needs `confirm=true`).
  - Long timeouts for export and LE.
  - The MCP never downloads evidence bytes.

**Verification:**
- Each piece had rolled-back DB tests with negative controls, mocked UI tests in 3 themes, MCP tests, and live checks through Caddy.
- The wave review found no Critical issues; regression found no real regressions.
- Rotation was tested only in an isolated environment.

### Backlog wave H (2026-10-05)

- ⚠ **Quarantine encrypted at rest** (the same v2 format as evidence). Migrate existing files once with `python -m artifacts.encrypt_quarantine --apply`; there is no downgrade afterwards. (H1)
- ⚠ **Artifact DELETE** needs a `{reason}`, and returns 409 `artifact_referenced` while another record uses the artifact. (H1)
- ⚠ **Uploads no longer create hash IOCs;** use `create_hash_iocs` or `POST …/artifacts/{id}/hash-iocs`. (H1)
- ⚠ **The worker receives decrypted bytes over TLS;** rebuild analysis-worker together with the backend. Key rotation covers quarantine files. (H1)
- ⚠ **Shared append-only case notes** (`/api/incidents/{id}/case-notes`) replace the private scratchpad (writes now 410).
  - Notes link to exhibits, IOCs, entities and events, and are corrected by appending.
  - They appear in the LE package and the full report. (H2)
- ⚠ **MCP:** the scratchpad tools are removed; `case_note_add` is added. (H2)
- **TLP:RED blocks automatic outbound** like Dark Operation: Teams/Slack, alert email and automatic email DNS checks. Suppressions are audited. (H3)
- ⚠ **Manual enrich, OSINT and domain checks** on RED or dark incidents need `confirm_outbound=true` (else 409 `outbound_confirmation_required`). They are audited, and MCP tools take the flag. (H3)
- **Supporting documents** get server hashes at upload, with a backfill tool for older files. (H4)
  - ⚠ Rename and delete need a `reason`.
  - ⚠ Delete returns 409 `file_referenced` while a file is in use.
  - ⚠ New `POST …/files/{id}/register-exhibit`.
  - MCP follows these changes.
- **Security:** entity-file download and delete are confined to the incident in the URL. (H4)

### Backlog wave I (2026-10-06)

- **Recovery tracker** for each in-scope system: restore point, restored and validated by whom, monitoring window. Declare recovered is offered once every system is done, never set automatically. Report and LE sections added. (I1)
- ⚠ **API:** `GET/PATCH /api/incidents/{id}/recovery`; the snapshot gains `recovery`; deleting an entity that has a recovery record returns 409. The MCP respond tools gain recovery. (I1)
- **Stakeholder notification tracker.** Matrix rules become countdowns from the moment the incident first reached that severity (escalations are recorded). Record each notification's time, sender and channel; a header chip shows "x of y". (I2)
- ⚠ **API and MCP:**
  - `…/stakeholder-notifications`.
  - The snapshot gains `notifications`.
  - Matrix rules gain `incident_types`.
  - LE adds `12_Notifications`. (I2)
- ⚠ **Playbooks:**
  - Templates are appended by default. Replacing the plan is lead or admin only, needs a reason, and keeps finished tasks as history.
  - Tasks follow the 800-61 phase order; skipping needs a reason.
  - Templates are suggested by incident type.
  - "Mark reviewed" sets the review date; Readiness warns until the core playbooks are reviewed. (I3)
- ⚠ **New incident requires** type, severity, detection method and Detected; POST /incidents otherwise returns 422 `required_fields_missing`. (I4)
  - The other intake fields are optional.
  - Start checks (warnings, overdue after 60 minutes) show in the header and on the Situation board.
  - SIEM incidents record whether Detected came from the alert or the receipt time.
- ⚠ **Gates v2:** checks are labelled block or warn. (I5)
  - Gate 1 also blocks on unvalidated systems, unlogged required notifications and breach obligations.
  - Gate 2 also blocks on exhibit custody or legal hold, open working copies and unacknowledged LE packages.
  - Close needs the IC's sign-off, and the DPO's for breaches (`POST …/gates/{gate}/sign-off`).
  - Checklist items can be N/A with a reason.

### Backlog wave J (2026-10-06)

- ⚠ **SIEM webhooks** check the key first. Bad bodies return a flat 422 and oversized bodies 413; the response adds `status` and `alert_count`. (J1)
- **SIEM intake:**
  - A re-fire within 24 h attaches to the open incident.
  - IOCs and hosts/users are extracted, and the category maps to a type.
  - On-call and admins get an in-app notice.
  - New table `siem_alerts`.
  - New start check "Incident type set". (J1)
- ⚠ **Deadline reminders by email:** legal deadlines and overdue stakeholder notifications are also emailed to the Legal Liaison and IC (admins as fallback), with ref, regulation and time left only. Never under Dark Operation or TLP:RED. New Integrations switch "Email deadline reminders" (`deadline_reminders`). (J2)
- **Post-Incident sub-tabs have URLs** (`…/post-incident/{analytics,lessons,attack-chain,costs,reports,closure}`). New Costs & Impact tab; Closure Checklist is last. (J3)
- ⚠ **Lessons learned are edited only on Post-Incident → Lessons Learned**, which now also holds the report text and remediation plan. Details and Reports show read-only summaries. New optional `meeting_minutes` field (API, MCP, exports). "Insert key timeline events" drafts the narrative. (J3)
- ⚠ **Gate check `route` values** now point to the sub-tab (`post-incident/lessons|closure|costs|reports`). (J3)
- **Shift handoff** in the incident header opens the form, prefilled with open actions and current-phase tasks; a next step can become a task for the recipient. Optionally, acknowledging makes the recipient Incident Commander: off by default, set by the IC, a lead or an admin, audited, with a notice to the old IC. (J4)
- ⚠ **A viewer can't be a handoff recipient** (422 `recipient_read_only`). Timeline `system_source` `ic_transfer` is reserved: 422 on create, and those events are immutable. (J4)
- **Promote** War Room messages and comments to a timeline event or a decision (`POST /api/incidents/{id}/promote`). (J4)
- **Respond actions link** to an approving decision and a playbook task, with chips shown both ways. Entity and IOC rows get **Isolate / Disable / Block** buttons that open the Respond form prefilled. (J5)

### Backlog wave K (2026-10-06)

- **Evidence sub-tabs follow the lifecycle:** Register, Exhibits, Custody log, Integrity, Disclosure package, SOP, Supporting documents. Old links redirect. Custody log and Integrity name exhibits by identifier. New device types: email export, vendor report and network capture export. (K1)
- **Disclosure package** (internal, law enforcement or regulator): Ed25519-signed, custody-logged per exhibit, audited, and the other admins are notified. `POST /api/incidents/{id}/disclosures`; MCP `disclosure_create`. (K1)
- ⚠ `POST …/evidence/exports`, `POST …/le-package` and `GET …/le-packages` are deprecated. Exports are open to the incident lead (they were admin-only), and `GET …/le-packages` lists only law-enforcement packages. The LE package UI moved from Post-Incident › Reports to Evidence › Disclosure package. (K1)
- **Audit log records the client user agent** next to the real client IP on every entry. The UA is sanitised and at most 512 characters. Both audit pages show "METHOD IP · client", with the full UA on hover and when expanded, and "system" for background entries. The audit API, MCP `fenrir_incident_audit`, signed export (JSONL/PDF) and LE package carry it. (AUD-1)
- ⚠ **Audit hash v3:** new rows include the user agent in the row hash; v1/v2 rows are unchanged and still verify. Offline verifiers must pick the payload by `hash_version` (fields are listed in the bundle README). Syslog audit frames gain the SD-PARAM `ua`, and the LE `Audit_Trail.csv` gains a `user_agent` column. Signed exports now write v1 rows' real payload. (AUD-1)
- ⚠ **Respond is three rail pages:** Containment, Eradication & Recovery, and Decisions. `/respond` redirects to Containment. Entities is now **Scope** (`/entities` redirects). (K2)
- **Time in phase** on the phase stepper and the Situation board. New `GET /api/incidents/{id}/phase-history`. The snapshot adds `phase_history`, `respond_containment`, `respond_eradication_recovery` and `decisions`. (K2)
- **Timeline:** server-side filters (entity, IOC, IR phase, origin, key, text) in a toolbar; an Import button; IOC chips with link and unlink; a key-event flag (`is_key`) and `key_event` marker; and a "Key timeline" on the Situation board. MCP `fenrir_timeline_list` takes the filters and `sort`. (K3)
- ⚠ **The server now decides what counts as a key event.** Manual annotations no longer count in "Insert key timeline events". (K3)
- **Scope:** "Compromised only" filter. **IOCs:** First / last seen column from the linked timeline events, and `?entity_id=`. The **entity drawer** shows the entity's timeline events, linked IOCs and containment actions. (K4)
- **ATT&CK:** Reconnaissance (TA0043) and Resource Development (TA0042) added, for 14 tactics. The attack chain moved to ATT&CK → Coverage, and `post-incident/attack-chain` redirects. (K4)
- ⚠ **Legal anchors in the future are rejected** (422 `anchor_in_future`). **Cost currencies must be ISO 4217** (422 `invalid_currency`). Legal regulation colours are theme tokens. (K5)
- **Data fixes:**
  - One bad row no longer fails a timeline batch.
  - Email `urls[].promoted_ioc_id` is set.
  - PCAP dedup uses type and value.
  - Evidence GET carries the derived transfer flags.
  - The demo seed no longer splits "Domain Controllers". (K5)
- **Admin script `python -m legal.fix_legacy_rows`** (dry run by default; `--apply --operator`). It is idempotent and audited, and covers three cases: duplicate legal rows from before B4, open NIS2 final-report rows on the old 720 h window, and the seed's split DC entities. (K5)

### Backlog wave L (2026-10-07)

- **Narrow screens:** no page scrolls sideways at 400 px, and the incident rail stays in view while you scroll. Every button, dropdown and input follows the shared size standard, and Examine page headings match their tabs. Esc in a date picker no longer closes the dialog around it. (L1)
- **Contrast:** every measured text colour reaches 4.5:1 in all three themes. Nordic Calm colours are darker, and its severity badges get darker text so they are readable. (L2)
- **Viewers** no longer see buttons that only end in "forbidden". LOLBins sync is shown to admins only. (L2)
- ⚠ **API errors:** 422 validation errors are `{detail: "<summary>", code: "validation_error", errors: [{loc, msg, type}]}`, and `detail` is no longer a list. Every error now carries a `code`. A missing `X-Fenrir-Key` is 403 `invalid_key` (was 422). A web-history re-mint is 409 `already_minted` (was 400). (L4)
- ⚠ **IOC Enrich and OSINT enrich need the Analyst role** (viewers get 403 `insufficient_role`). (L4)
- Audit API timestamps end in `Z`. The MCP identifies itself as `fenrir-mcp/<version>` in the audit log. (L4)
- **Teams/Slack:**
  - A phase and severity change in one update sends both cards.
  - The close card reads "Incident Closed".
  - Notifications carry the ref, never the title.
  - Custody requesters are told the outcome. (L3)
- The Incidents list gains an **Owner (IC)** column and a phase filter. The assignee picker shows on-call, availability and skills. The War Room drawer follows the topbar height. (L3)
- ⚠ **CSV exports are formula-safe:** the LE package, Defender IOC CSV, and Timeline and OSINT downloads put a `'` before cells that start with `=`, `+`, `-`, `@`, TAB or CR; plain numbers are unchanged. The LE package adds `10_Case_Notes/Case_Notes.json`, and its README says to recompute hashes from the JSON files. (SEC-1)
- ⚠ **`X-Request-Id`** is kept only when it is a canonical UUID (stored and echoed lower-case). Any other value is replaced by a server-minted UUID; an over-long value used to fail the request with 500. (SEC-1)
- **Help rewritten** to match the current app: roles, tabs, reports, disclosure packages and tokens. New topics include an end-to-end "Running an Incident from Intake to Closure" workflow. Help renders `[[topic]]` links, `code` and *italics*, and a link check before every build fails on a dangling link. (L5)
- **Docs:** `reports.md`, `audit-integrity.md` §4, the CoC procedure and the Help style guide now cover Ed25519-signed disclosure packages and spreadsheet-safe CSV. (L5)

### Upgrade notes

- **Wave G:**
  - Rebuild the backend, analysis-worker, backup, caddy and frontend images.
  - Run `fenrir-mcp login` and restart the MCP server.
  - Use the rotation tool only by following `docs/evidence-kek-rotation.md`.
- **Migrations run automatically** through the `migrate` service. They add columns and run guarded one-time backfills.
  - C2 copies affected systems into compromised entities.
  - C3 records a hash check for existing evidence.
  - C5 links old imports to exhibits only on an exact hash match.
- **Compose change:** the backend has a RAM-only tmpfs at `/run/fenrir-parse` for decrypted parse temp files. Recreate the backend with `docker compose up -d`; `make posture` must stay at 0 failures.
- **MCP server:** run `fenrir-mcp login` and restart it to pick up the matching tool changes.
- **API clients:** read the ⚠ entries under Changed. Close/reopen bodies, phase gates, evidence hash checks, custody transfer requests and incident-lead permissions all change request or response contracts.

### Verification

- **Each piece:** rolled-back database tests that call the real routes, plus headless-browser tests of the deployed bundle in all three themes.
- **Each wave:** an independent review, a full regression run, and negative controls showing the old code fails the new rules.
- **Final regression:** every suite passes, and nothing persisted.
- **Live checks passed (2026-10-03).** All pieces were checked against the running stack, through Caddy, with real admin, analyst and viewer accounts. `make smoke` passes 49/0.

### Known issue (pre-existing, not part of this release)

- ~~Tag filters and threat-actor search return 500.~~ Fixed in F5 (2026-10-04).
