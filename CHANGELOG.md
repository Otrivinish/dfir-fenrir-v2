# Changelog

All notable changes to DFIR-FENRIR v2. Dates are UTC (ISO 8601).

## [Unreleased] — container security hardening (2026-10-01) — **breaking for upgrades**

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

## [0.3.0] — unreleased (branch `fix/post-incident`, merged with `main` through #25)

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
