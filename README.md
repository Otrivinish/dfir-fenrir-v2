<div align="center">

# 🐺 DFIR-FENRIR v2

### A containerized **Digital Forensics & Incident Response** platform

*Run the whole incident lifecycle — detect → analyse → contain → recover → report*

<br>

![Status](https://img.shields.io/badge/status-active-success)
![Backend](https://img.shields.io/badge/backend-FastAPI%20%C2%B7%20Python%203.12-009688)
![Frontend](https://img.shields.io/badge/frontend-React%2019%20%C2%B7%20Vite-61dafb)
![Database](https://img.shields.io/badge/db-PostgreSQL%2016-336791)
![TLS](https://img.shields.io/badge/TLS-1.3%20%C2%B7%20Caddy-1f88c0)
![Deploy](https://img.shields.io/badge/deploy-Docker%20Compose-2496ed)
![Standards](https://img.shields.io/badge/aligned-CSF%202.0%20%C2%B7%20800--61%20R3%20%C2%B7%20CISA-6b46c1)
![API](https://img.shields.io/badge/API--first-OpenAPI%20%C2%B7%20MCP--ready-orange)

</div>

---

> [!NOTE]
> Quick install: git clone https://github.com/Otrivinish/dfir-fenrir-v2.git
> **One command to run it:** `./setup.sh` → open `https://localhost/` → use the printed first-run token. Everything below is detail.

---

## 📑 Table of contents

- [Why FENRIR](#-why-fenrir)
- [Screenshots](#-screenshots)
- [Highlights](#-highlights)
- [Architecture](#-architecture)
- [Tech stack & dependencies](#-tech-stack--dependencies)
- [Quick start (setup.sh)](#-quick-start)
- [Manual installation](#-manual-installation)
- [Configuration](#-configuration)
- [Feature overview](#-feature-overview) · *(full list → [FEATURES.md](FEATURES.md))*
- [Standards alignment](#-standards-alignment)
- [Themes](#-themes)
- [Security posture](#-security-posture)
- [Documentation](#-documentation)

---

## 🎯 Why FENRIR

Most incident-response tooling is either a SaaS that wants your evidence in someone else's cloud, or a pile of scripts with no chain of custody. FENRIR is a **single, self-hosted platform** that:

- Keeps **evidence on infrastructure you own**, encrypted at rest with AES-256-GCM.
- Produces a **tamper-evident, hash-chained audit log** and **court-ready Law-Enforcement packages**.
- Ships an **air-gapped malware-analysis worker** with no internet path.
- Is **API-first** — every feature is usable from `curl` or an MCP client, not just the browser.
- Is **built to the standards** auditors ask about: NIST CSF 2.0, SP 800-61 R3, CISA playbooks, ISO/IEC 27037/27041.

---

## 📸 Screenshots

| | |
|---|---|
| ![Operations dashboard](assets/dashboard.png)<br>**Operations dashboard** — Portfolio KPIs (open / critical / overdue, MTTA · MTTR), active-phase and severity breakdowns, a 30-day trend chart, and a live activity feed. | ![Incident register](assets/incidents.png)<br>**Incident register** — Filterable case list; every row carries its NIST SP 800-61 R3 phase, severity, and TLP marking. |
| ![Incident timeline](assets/timeline.png)<br>**Incident timeline** — Chronological event log with MITRE ATT&CK technique tags and one-click CSV / HTML export. | ![Entities table](assets/entities_1.png)<br>**Entities — table** — Hosts, users, services and IPs with criticality and compromised flags, plus bulk CSV import. |
| ![Entities graph](assets/entities_2.png)<br>**Entities — graph** — Interactive relationship graph linking entities (e.g. *communicates with*) with compromise highlighting. | ![Indicators of compromise](assets/iocs.png)<br>**Indicators of compromise** — Hashes, IPs and domains with confidence scoring, enrichment, defanging, and bulk import. |
| ![Evidence and chain of custody](assets/evidence_detail.png)<br>**Evidence & chain of custody** — SHA-256 hashes, full custody log, photos, integrity re-verification and sealed transfer. | ![Forensic artifacts](assets/artifacts.png)<br>**Forensic artifacts** — Quarantined-artifact browser with hex / string viewing for air-gapped static analysis. |
| ![Email analyzer](assets/email.png)<br>**Email analyzer** — Offline phishing triage: SPF / DKIM / DMARC, received-hop chain, extracted URLs and attachments, promotable to evidence. | ![OSINT lookup](assets/osint.png)<br>**OSINT lookup** — Passive enrichment (GeoIP, ASN, WHOIS, rDNS, DNS records) with one-click indicator extraction. |
| ![Host collections](assets/velociraptor.png)<br>**Host collections** — Signed, incident-scoped endpoint collection packages with per-host profiles and verifiable results. | ![MITRE ATT&CK coverage](assets/mitre.png)<br>**MITRE ATT&CK coverage** — Enterprise matrix of observed tactics and techniques across incidents, with per-technique drill-down. |
| ![Respond board](assets/respond.png)<br>**Respond board** — Containment / Eradication / Recovery Kanban with a logged decision record. | ![Playbook](assets/playbook.png)<br>**Playbook** — CISA-aligned, 800-61-phased checklist with per-step status and template application. |
| ![Regulatory deadlines](assets/legal.png)<br>**Regulatory deadlines** — Live countdown timers for statutory notifications and breach-report obligations. | ![Post-incident activity](assets/post-incident.png)<br>**Post-incident activity** — Closure checklist, lessons-learned capture, and report generation. |

<div align="center">

![Generated report](assets/report.png)

***Generated report*** — Executive summary with severity / TLP / phase metrics and full incident detail, export-ready. Shown in the **Aurora Night** theme — one of three runtime themes (Mission Control · Nordic Calm · Aurora Night) switchable from the top bar.

</div>

---

## ✨ Highlights

| | Capability | What it does |
|---|---|---|
| 🔗 | **Chain of custody & evidence integrity** | AES-256-GCM at rest, per-item custody timeline, hash-chained audit log, signed audit-log exports (Ed25519), one-time encrypted downloads, court-grade LE packages |
| 📦 | **Signed offline collectors** | Incident-scoped, signed Velociraptor collection packages (Windows + macOS ARM64). Responder runs air-gapped; output auto-parses into the timeline |
| 🧭 | **Standards-native IR** | 800-61 R3 phase stepper, CSF 2.0 tagging, 11 seeded playbooks (NIST, CISA, ransomware, phishing, DDoS, BEC…) and a 4-column Respond Kanban |
| 🔬 | **Forensic analysis pipeline** | Multi-format timeline import (EVTX/XML/CSV/JSON + syslog/journald + macOS unified log), process-tree viz, 11 static analysis tools, YARA, PCAP/DNS recon, email-header analyzer |
| 🌐 | **Threat intelligence** | Cross-incident IOC/entity correlation, 8 threat feeds, 25 MITRE-synced threat actors with TTP scoring, 7 OSINT sources, IOC export to 7 EDR/firewall formats |
| 📊 | **Reporting & metrics** | 6 report templates, executive/full modes, remediation roadmap, MTTD/MTTR/MTTC, regulatory deadline countdowns (GDPR, NIS2, DORA, HIPAA, CCPA, PCI-DSS) |
| 🔌 | **API-first & integrations** | OpenAPI source-of-truth, Bearer-token + cookie auth, SMTP/Graph email, Teams/Slack webhooks, SIEM inbound (Splunk/Sentinel/Elastic), syslog forwarding (TLS 1.3 / mTLS) |
| 🛡️ | **Secure by design** | TLS 1.3 edge, hardened CSP/HSTS, non-root read-only containers, air-gapped analysis network, Redis-backed rate limiting, TOTP 2FA, argon2id passwords |

➡️ The complete, categorised feature inventory lives in **[FEATURES.md](FEATURES.md)**.

---

## 🏗 Architecture

It's servered through Caddy as a pure TLS-terminating reverse proxy. The React SPA is served by a dedicated hardened **nginx** container; the API is the FastAPI **backend**. Everything reaches the edge only through Caddy.

```
┌─────────────────────────────────────────────────────────────────┐
│                       Internet / Browser                         │
└────────────────────────────┬────────────────────────────────────┘
                             │ HTTPS :443  (TLS 1.3, HSTS, CSP)
                   ┌─────────▼──────────┐
                   │       Caddy        │  TLS termination + reverse proxy ONLY
                   │    (pure proxy)    │ 
                   └────┬──────────┬────┘
              /  (SPA)  │          │  /api/*  ·  /download/*  ·  WS
              ┌─────────▼──┐   ┌───▼─────────┐
              │  Frontend  │   │   Backend   │  FastAPI async 
              │ nginx :3000│   │    :8000    │  
              │ static SPA │   └──┬───────┬──┘
              │ non-root,  │      │       │
              │ read-only  │  ┌───▼──┐ ┌──▼──────┐
              └────────────┘  │ PG16 │ │ Redis 7 │  (sessions · rate-limit · cache)
                              │ data │ └─────────┘
                              └───┬──┘
                  ┌───────────────┼──────────────────┐
            ┌─────▼─────┐   ┌─────▼───────┐    ┌──────▼────────┐
            │  Backup   │   │ Audit       │    │  (evidence    │
            │ daily     │   │ monitor     │    │   vol, ro)    │
            │ pg_dump   │   │ tamper anchor│   └───────────────┘
            └───────────┘   └─────────────┘

  ── fenrir-analysis network (internal=true — NO internet) ──────────────
              ┌─────────────────────────┐
              │     Analysis Worker     │  air-gapped · caps dropped · noexec /tmp
              │   (malware tooling)     │  reachable only from Backend
              └─────────────────────────┘
```

---

## 🧰 Tech stack & dependencies

### Runtime (host)

| Requirement | Notes |
|---|---|
| Windows or Linux (suggested 4vCPU, 8GB and 60GB disk)
| **Docker** + **Docker Compose v2** | Required |
| `openssl` *or* `python3` | Required to run the `setup.sh` |
| `curl` *(optional)* | Used by `setup.sh` for the post-start health poll. |


### Backend — Python 3.12 / FastAPI

<details><summary><b>Backend dependencies (<code>backend/requirements.txt</code>)</b></summary>

| Package | Purpose |
|---|---|
| `fastapi` · `uvicorn[standard]` · `python-multipart` | Async API server |
| `pydantic[email]` · `pydantic-settings` | Validation & typed config |
| `sqlalchemy[asyncio]` · `asyncpg` | ORM + async Postgres driver |
| `redis` | Sessions, rate-limit buckets, cache |
| `argon2-cffi` | argon2id password hashing |
| `cryptography` | Fernet (TOTP secret at rest), AES-256-GCM evidence crypto |
| `pyotp` · `qrcode[pil]` | RFC 6238 TOTP + provisioning QR |
| `httpx` · `pyyaml` | LOLBAS/GTFOBins sync, threat-feed pulls |
| `python-evtx` | Windows EVTX binary log parsing |
| `pyzipper` | AES-256 password-protected ZIP downloads |
| `python-magic` | MIME detection (wraps `libmagic1`) |
| `reportlab` | Signed audit-log export PDFs |
| `rfc3161ng` | RFC 3161 trusted timestamping (lazy; only when `TSA_URL` set) |
| `extract-msg` | Outlook `.msg` parsing for the email analyzer (offline) |

</details>

### Frontend — React 19 / Vite, served by hardened nginx

<details><summary><b>Frontend dependencies (<code>frontend/package.json</code>)</b></summary>

| Package | Purpose |
|---|---|
| `react` · `react-dom` (19) | UI |
| `react-router-dom` (7) | SPA routing |
| `react-markdown` | Markdown rendering (descriptions, reports) |
| `@xyflow/react` | Entity / asset relationship graph |
| `vite` (8) · `@vitejs/plugin-react` | Build tooling (`node:20-alpine` build → `nginx-unprivileged` serve) |

</details>

### Analysis worker — Python 3.12, air-gapped

<details><summary><b>Analysis-worker tooling (<code>analysis-worker/Dockerfile</code>)</b></summary>

**System tools:** `tshark` (PCAP), `binutils` (`strings`), `libimage-exiftool-perl` (metadata), `libmagic1` (MIME), `libyara-dev` (YARA engine).

**Python tools:** `pefile` (PE), `oletools` (Office macros), `pdfminer.six` (PDF), `yara-python`, `exifread`, `python-magic`.

Runs as non-root uid `1002`, all capabilities dropped, `/tmp` mounted `noexec`, on a network with **no internet route**. Quarantine is mounted read-only.

</details>

### Infrastructure images

`postgres:16-alpine` · `redis:7-alpine` · `caddy` (custom build) · backend image reused for the daily `backup` and the `audit-monitor`.

---

## 🚀 Quick start

```bash
git clone <your-repo-url> dfir-fenrir-v2
cd dfir-fenrir-v2
./setup.sh                 # or: make setup
```

`setup.sh` is **idempotent and offline-safe**. It:

1. Creates `.env` from `.env.example` if missing.
2. Generates every required secret if absent — `POSTGRES_PASSWORD`, `REDIS_PASSWORD`, `SECRET_KEY`, `EVIDENCE_KEK`, `AUDIT_SIGNING_KEY` (never overwrites an existing value).
3. Generates self-signed TLS certs (skipped for BYO-cert / DuckDNS modes).
4. Builds + starts the whole stack and waits for the backend to become healthy.
5. Prints the **first-run setup URL + bootstrap token**.

Then open **`https://localhost/`** and visit `/setup` with the printed token to create the first admin.

```bash
./setup.sh --print-token   # re-show the first-run token later
```

> [!TIP]
> In self-signed mode, import `certs/ca.crt` into your browser/OS trust store to silence TLS warnings locally.

### Make targets

| Command | Action |
|---|---|
| `make setup` | First-time install / resume (idempotent) |
| `make up` / `make down` | Start / stop the stack (volumes kept) |
| `make rebuild` | Rebuild images + start |
| `make logs` | Tail backend logs |
| `make token` | Re-show the first-run token |
| `make ps` | Container status |

---

## 🔧 Manual installation

<details><summary><b>What <code>setup.sh</code> automates, step by step</b></summary>

```bash
# 1. Create your env file
cp .env.example .env

# 2. Generate secrets and paste them into .env
#    (EVIDENCE_KEK and AUDIT_SIGNING_KEY are MANDATORY — the backend
#     refuses to start without them.)
openssl rand -hex 24          # → POSTGRES_PASSWORD
openssl rand -hex 24          # → REDIS_PASSWORD
openssl rand -hex 64          # → SECRET_KEY
openssl rand -hex 32          # → EVIDENCE_KEK   (32 bytes = AES-256 KEK)
./scripts/generate-audit-key.sh   # → AUDIT_SIGNING_KEY (Ed25519 seed, base64)

# 3. Generate local TLS certs (self-signed mode only)
./generate-certs.sh

# 4. Build and start
docker compose up -d --build

# 5. Verify
curl -sk https://localhost/api/health
# {"status":"ok","service":"fenrir-v2-backend"}

# 6. Grab the first-run token, then visit https://localhost/setup
docker compose logs backend | grep -i token
```

</details>

For a non-default deployment (custom domain, Let's Encrypt via DuckDNS, or bring-your-own cert), edit `.env` **before** running — the TLS modes are documented inline in [`.env.example`](.env.example) and in [`docs/deployment-runbook.md`](docs/deployment-runbook.md).

---

## ⚙ Configuration

All configuration lives in `.env` (copied from [`.env.example`](.env.example)). Key settings:

| Variable | Default | Purpose |
|---|---|---|
| `DOMAIN` | `localhost` | Hostname; drives Caddy's TLS mode auto-selection |
| `POSTGRES_PASSWORD` · `REDIS_PASSWORD` · `SECRET_KEY` | _generated_ | Core secrets |
| `EVIDENCE_KEK` | _generated_ | **Required.** AES-256 master KEK for evidence at rest |
| `AUDIT_SIGNING_KEY` | _generated_ | **Required.** Ed25519 seed for signed audit exports |
| `TOTP_REQUIRED` | `true` | Force 2FA enrolment on all users |
| `INACTIVITY_TIMEOUT_MINUTES` | `30` | Idle session revocation |
| `CORS_ORIGINS` · `ALLOWED_HOSTS` | `https://localhost` … | Browser origin / Host-header allowlists |
| `TLS_CERT_FILE` / `TLS_KEY_FILE` | _empty_ | Bring-your-own cert mode |
| `LETSENCRYPT_EMAIL` / `DUCKDNS_TOKEN` | _empty_ | Let's Encrypt-via-DuckDNS mode |
| `TSA_URL` | _empty_ | Optional RFC 3161 timestamp authority for chain anchoring |
| `ANCHOR_INTERVAL` | `3600` | Audit-monitor anchoring cadence (seconds) |

**TLS modes** (auto-selected by Caddy from what's set): **A** self-signed (default) · **B** Let's Encrypt via DuckDNS · **C** bring-your-own cert.

---

## 🧩 Feature overview

FENRIR covers the full incident lifecycle. This is the condensed map — the exhaustive, per-item list is in **[FEATURES.md](FEATURES.md)**.

<details open><summary><b>Incident management</b></summary>

Cursor-paginated incident list with filters · create/edit with inline validation · 800-61 R3 phase stepper with audited transitions · severity (internal Low/Med/High/Critical → NCISS at report time) · TLP 2.0 marking · CSF 2.0 function tag · affected systems → promote to entities · close/reopen with guards · per-incident & team-based access control · operational dark-mode toggle.

</details>

<details><summary><b>Investigation & forensics</b></summary>

**Timeline** (vertical spine, MITRE cascading dropdowns, CSV/HTML export, process-tree viz) · **forensic timeline import** (EVTX/XML/SQLite/CSV/JSON + Linux syslog/journald + macOS unified log, 36-EID classification engine, triage table, bulk-promote) · **IOCs** (dedup, confidence, correlation across incidents, bulk import, export to 7 EDR/firewall formats, threat-feed matching, enrichment) · **entities** (relationships, react-flow graph, asset logs, bulk import) · **artifacts** (drag-drop, MD5/SHA256/SHA512, 11 static analysis tools, AES-ZIP download) · **YARA detections** + SIEM query generation · **LOLBins** (LOLBAS + GTFOBins) · **PCAP** (tshark, 7-tab results, DNS recon) · **OSINT** (7 sources) · **threat-actor attribution** (25 MITRE-synced actors, TTP scoring) · **MITRE ATT&CK coverage matrix** · **email-header analyzer** (offline phishing triage).

</details>

<details><summary><b>Evidence & chain of custody</b></summary>

Digital + physical evidence models · AES-256-GCM at rest (fail-fast without `EVIDENCE_KEK`) · Transfer/Examine/Verify/Dispose custody timeline · one-time 24h encrypted download tokens · export bundles (files + CoC JSON + audit excerpt + SHA-256 manifest + decrypt recipe) · custody log · on-demand audit-chain verification · ISO 27037/27041 collection wizards, SOP & working-copy ledger · legal-hold flag · trusted RFC 3161 timestamping.

</details>

<details><summary><b>Response & recovery</b></summary>

11 seeded playbook templates (NIST 800-61, CISA Federal IR & Vuln Response, ransomware, credential stuffing, phishing, data egress, OAuth revocation, insider exfil, DDoS, BEC) · 4-column Respond Kanban (Containment/Eradication/Recovery/Decisions) with 42 action templates, revert workflow & auto-timeline logging · decision log · closure checklist · lessons learned · response analytics (TTD/TTC/TTR) · cost tracking · business-impact assessment · regulatory deadline countdowns.

</details>

<details><summary><b>Reporting & cross-incident analytics</b></summary>

6 report templates (Mission Control / Executive / Nordic Calm / Forensic / Compact / Tactical) with executive/full modes, remediation roadmap, audit-grade history & re-download · **Law-Enforcement package** (AES-256 ZIP, HMAC manifest, integrity files, decrypted evidence + custody CSV, full audit trail) · dashboard with 7 KPI cards + trend chart + workload + activity feed · global ⌘K search · correlations · threat-intel hub · portfolio metrics.

</details>

<details><summary><b>Collaboration & comms</b></summary>

Comments · out-of-band comms log (passphrase, channels, dark-op toggle) · WebSocket war room (live chat + presence) · real-time notifications (bell + toasts) · stakeholder contact directory.

</details>

<details><summary><b>Administration & API</b></summary>

Hash-chained audit log (global + per-incident viewers) · signed audit-log export (Ed25519, encrypted ZIP, one-time download) · session management · storage/volume monitoring · backup status & trigger · Fernet-encrypted API-key vault · theme & timezone pickers · users/teams/roles · OpenAPI docs (Swagger/ReDoc) · API tokens (Bearer) · CSP/HSTS · Redis rate limiting · authenticated WebSockets · integrations (SMTP/Graph email, Teams/Slack webhooks, SIEM inbound, syslog forwarding).

</details>

> A prioritised backlog and the future USP roadmap (U2–U8: continuous chain anchoring, DFIR copilot, detection-as-code, disk/FS parsers, C2 beacon detection, campaign clustering) are tracked in [`FENRIR2.md`](FENRIR2.md) and summarised at the end of [FEATURES.md](FEATURES.md).

---

## 🔒 Security posture

- **In transit:** TLS 1.3 at the Caddy edge; HSTS; hardened CSP (`object-src 'none'`, `frame-ancestors 'none'`, etc.); COOP/CORP/Permissions-Policy.
- **At rest:** AES-256-GCM evidence encryption (KEK from env, fail-fast); Fernet-encrypted TOTP secrets & API keys.
- **Identity:** argon2id passwords, RFC 6238 TOTP 2FA (org-enforceable), opaque sessions with idle timeout, two-axis RBAC, Bearer API tokens role-capped to `min(user, token)`.
- **Isolation:** non-root containers (backend 1001, worker 1002), read-only rootfs + tmpfs on frontend/worker, dropped capabilities, `no-new-privileges`, air-gapped analysis network (`internal: true`).
- **Integrity:** hash-chained tamper-evident audit log, Ed25519-signed exports, background audit-chain anchoring (+ optional RFC 3161 timestamps), per-IP/per-credential Redis rate limiting.

---

---

## 📚 Documentation

** Coming soon **

| Doc | What it covers |
|---|---|
| [FEATURES.md](FEATURES.md) | Complete categorised feature inventory |
| [docs/deployment-runbook.md](docs/deployment-runbook.md) | Bring-up, bootstrap, cert modes, full env reference |
| [docs/threat-model.md](docs/threat-model.md) | Trust boundaries, encryption, air-gap, deviations |
| [docs/audit-integrity.md](docs/audit-integrity.md) | Hash chain, signed export, audited events |
| [docs/backup-restore.md](docs/backup-restore.md) | Backup scope, retention, manual restore |
| [docs/standards-map.md](docs/standards-map.md) · [docs/coc-procedure-27037.md](docs/coc-procedure-27037.md) | Standards & chain-of-custody procedure |
| [docs/README.md](docs/README.md) | Full documentation index |

---