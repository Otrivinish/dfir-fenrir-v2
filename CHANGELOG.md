# Changelog

All notable changes to DFIR-FENRIR v2. Dates are UTC (ISO 8601).

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
