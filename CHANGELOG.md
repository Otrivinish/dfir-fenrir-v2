# Changelog

All notable changes to DFIR-FENRIR v2. Dates are UTC (ISO 8601).

## [0.4.0] — 2026-11-01 — Phishing fast path, Defender IOC export, email URL promotion, entity bulk import (2026-10-15); editable, signed case notes, timeline events pick up registered entities, unsaved edits survive a session timeout, timeline export layouts (2026-10-31); evidence source location, seal binding, photo record, screenshot capture record, container exhibits with manifests, automatic exhibit identifiers, deferring a failing readiness check, report section picker and exhibit list (2026-11-01) — **breaking for API clients, sealing scripts and package verifiers** (see ⚠ Upgrading below)

Everything since `v0.3.9`: the commits after that tag and all work not yet committed.

### ⚠ Upgrading — evidence S1–S6 (2026-11-01): breaking for API clients, sealing scripts and package verifiers

Nothing changes for exhibits that are already sealed, and no data is rewritten. The migration only adds columns and
two tables. What changes is what the API now refuses, and what a disclosure package contains.

**What to do when you update FENRIR:**

1. **Take a fresh database backup** first: the admin **Run backup now** button, or wait for the daily dump. The new
   table `evidence_manifest_entries` is append-only (a trigger blocks DELETE), so it can't be emptied, only dropped.
2. **Rebuild every image and start:** `make rebuild` (`docker compose up -d --build`). `migrate` runs first and the
   backend waits for it. Don't rebuild the backend alone: audit-monitor would stay on the old image (posture
   "image drift"). No new secrets or required settings. Optional: `EVIDENCE_MANIFEST_MAX_ENTRIES` (1,000,000),
   `EVIDENCE_MANIFEST_MAX_UNCOMPRESSED_BYTES` (64 GiB), `EVIDENCE_MANIFEST_MAX_PATH_CHARS` (32,768).
3. **Update the MCP server** (`dfir-fenrir-mcp`) and restart your MCP client so it lists the new fields and views.
   An older MCP server still works, but it can't send the source fields or read manifests.
4. **Check `make posture`** (0 failures). Pending container manifests are queued again when the backend starts.

**API clients and scripts: what is refused now**

- **Sealing a digital exhibit needs a source statement:** the device (a linked asset, `source_system` or `serial`;
  make and model alone don't count) and the path its handling needs. A full image needs a path of style `device`;
  live data and exports need no path; anything else needs `source_path` + `source_path_style`. Or give
  `source_unknown_reason` (at least 10 characters). Otherwise 422 `seal_fields_missing`, naming `source_device`,
  `source_path` or `source_path_style`.
- **Sealing a ZIP or TAR exhibit waits for its manifest:** 409 `manifest_pending`. Retry once `manifest_status` is
  `built` or `failed`.
- **Photo `taken_at` must be ISO 8601 with a timezone** (422 `invalid_taken_at`; stored as UTC). A stored value that
  isn't is returned as `taken_at: null` plus `taken_at_unparsed` (the text as stored).
- **`source_path_norm` is derived by the server.** Sending it returns 422 `source_path_norm_read_only`.
- **A linked supporting document can't be deleted** (409 `file_referenced`, naming the link) until it is unlinked.
- **A duplicate typed identifier on `POST …/evidence/physical` returns 409 `identifier_exists`** (it was the generic `conflict`), the same code as the other create routes.
- **The deprecated `POST …/evidence/digital` stores only the file's basename** as `original_filename`. A name with
  control characters returns 422 `invalid_filename`.
- **EI: identifiers FENRIR makes itself change format.** Drafts from supporting documents and from Email, PCAP and
  Browser history uploads (and the older Register as exhibit of an email or browser-history analysis) were
  `DOC-…`, `EMAIL-…`, `PCAP-…` and `WEBHIST-…`. They now follow the naming convention (default
  `{incident}-{date}-{seq:3}`, e.g. `INC-2026-00009-20261101-001`), so a script, filter or report that matches those
  prefixes must change; identifiers already assigned keep their form. The migration adds a third table,
  `evidence_identifier_counters` (one row per incident, nothing backfilled).

**Disclosure package recipients and verification scripts: what changed in a package**

- **`MANIFEST.tst` is a bare RFC 3161 token:** verify with
  `openssl ts -verify -token_in -data MANIFEST.json -in MANIFEST.tst -CAfile <TSA CA certificate>`. Packages built
  before this release print the command without `-token_in`, which fails on every token
  (`Field=status_info, Type=TS_RESP`). Add `-token_in` when you verify one of those.
- **A new seal's token covers the sealed record, not the file.** `seal_tst_subject` is `record_v1`: the token is
  over SHA-256 of `04_Evidence/Seal/<id>__seal_record.json` (= `seal_record_sha256`), and that record holds the
  file's hashes. Verify with `openssl ts -verify -token_in -in <id>__seal.tst -digest <SHA-256> -CAfile …`. Seals made
  before keep `file_sha256`, so check `seal_tst_subject` before choosing the digest.
- **`MANIFEST.json` no longer names FENRIR's internal storage path.** An exhibit file's `source` is now
  `evidence id=<id> (stored file)`.
- **`Evidence_Inventory.csv` has new columns at the end:** the acquisition record, the source record, then the
  container manifest. The existing columns keep their order, but a parser that checks the column count must accept
  the new ones.
- **New in the package:**
  - `04_Evidence/Photos/<id>/` + `photos.json`;
  - `04_Evidence/Seal/`;
  - `…__manifest.jsonl` / `.csv` next to a container exhibit;
  - in each `.meta.json`, `acquisition`, `source` and `container_manifest` blocks.

  The custody export's photo list no longer carries `storage_path`, `nonce_hex` or the API URL.

**Owner decisions applied (2026-11-01):**
- **Register as exhibit** now copies a screenshot's hash at capture into the draft's target hash, with the upload
  hash check `match`. That hash was compared with the bytes at upload.
- **Changed provenance:** the check **Acquisition source/target hash match** (`iso_27037_9_2_5_hash_match`) scores
  a single recorded hash (source or target alone) as advisory `manual` ("nothing to compare it with"). It used to be
  a mandatory `fail` ("hashes differ"), a false alarm that exhibits with only a target hash already got. Two hashes
  that differ are still a mandatory fail, and the seal's own source-vs-target refusal is unchanged.
- **Unchanged:** the device rule above; a manifest can be rebuilt after the seal; the row hold at a million entries
  is accepted; the seal does not bind `manifest_listing`.

**Fixed at review:** TAR and KAPE CopyLog inputs can no longer exhaust the backend's memory. A 4.5 MB `.tar.gz` that
declared a 1 GiB pax header was OOM-killed under 512 MiB before the fix; such a build now fails with
`tar_header_too_large`, at no extra memory.

**Rollback:** reverse-apply `ignore/revert/evidence-owner-decisions-2026-11-01/`, then the slice kits S6 → S1 (each
REVERT.md says how). The schema stays: it is additive and unused by the old code.

### Added — reports: pick sections and appendices, exhibit list with SHA-256

- **Sections panel on Post-Incident › Reports,** always visible (it was **Include sections**, folded inside Advanced options). One checkbox per section and per appendix, all ticked except the **Incident Timeline** appendix; **Select all** / **Clear all**. Each box shows the § number or appendix letter it will print as, and numbers close up as you untick. **Attack Chain** and **Figures** are marked *(if present)*: they print only when there is data, so the page can number one or two ahead of the report.
- **Appendices Affected Systems and Case Notes are now optional too.** Letters follow print order with no gap (they were fixed: A = Affected Systems), so with Affected Systems unticked the Timeline becomes Appendix A. Show structure mirrors it.
- **§ Evidence & Artifacts lists every exhibit** (full report): identifier, name, type, status and the full SHA-256; a physical item shows "no hash", a failed hash verification is flagged **Verify failed**.
- **API (additive):** `GET /api/incidents/{id}/reports/data` gains `evidence_items[]` {identifier, name, kind, status, sha256 (null for a physical item)}, in collection order; no storage path, crypto or custody fields. **MCP:** `fenrir_report_data(view="data")` passes it through (docstring updated).
- **Report options (renderer):** `sections.appendix_affected` / `sections.appendix_case_notes` (`false` leaves the appendix out; default included). No migration. Test: `backend/tests/test_report_evidence_items.py`.

### Added — readiness: defer a failing check for good (RD, [design + as built](docs/readiness-defer-slice.md))

- **An admin can defer a failing readiness check** the organisation has decided to live with, from **Defer…** on the Dashboard banner (the failing blockers, all ticked) or on the check in **Prepare › Readiness**. A reason is optional (up to 500 characters). It applies to everyone and holds until an admin presses **Undo** on the Readiness page.
- **Effect:** a deferred check leaves the Dashboard banner and the **+ New incident** list; with every failing blocker deferred, the banner disappears. A different blocker that starts failing later still shows, and so does a check deferred as a warning that has become a blocker (`audit_anchor` verification failed, `backup_recent` missing); it can be deferred again. The check keeps running: the Readiness page lists it with its real status, marked **⏸ Deferred by … on …** (and the reason), plus a deferred count in the summary.
- **Only a failing or unknown check can be deferred** (409 `check_not_failing`); a check already deferred is 409 `already_deferred`; all or none of a request is deferred.
- **Audit:** `readiness_check_deferred` (check, level, status at the time, reason) and `readiness_deferral_removed` (who deferred it, when, why).
- **API (additive):** `GET /api/readiness` gains `deferral {by_name, at, reason} | null` per check and `summary.blockers_deferred` / `warnings_deferred`; `summary.blockers_failing` / `warnings_failing` now leave deferred checks out (no change until an admin defers one). `POST /api/readiness/deferrals {check_ids, reason?}` and `DELETE /api/readiness/deferrals/{check_id}` (admin; both return the readiness response). For non-admins the reason on `admin_totp` / `audit_anchor` is null, like their details. **MCP:** `fenrir_dashboard(view="readiness")` passes `deferral` through; deferring and undoing go through `fenrir_api` (DELETE needs full mode).
- **Migration:** the new table `readiness_deferrals` (from `create_all`; nothing altered, nothing backfilled). Revert: `ignore/revert/readiness-defer-rd-2026-11-01/`.

### Added — evidence: automatic exhibit identifiers (EI, [design + as built](docs/evidence-auto-identifier-slice.md))

- **Leave the identifier empty and FENRIR assigns one** from an admin naming convention, in the transaction that creates the exhibit: `{incident}-{date}-{seq:3}` by default, e.g. `INC-2026-00009-20261101-001`. `{incident}` is the incident reference as stored, `{date}` the UTC day of registration (the exhibit's `collected_at`), `{seq}` / `{seq:N}` the exhibit's number in the incident (padded to N, 1–6; grows past it). Blank = left out, null or whitespace only. A typed identifier works exactly as before, including 409 on a duplicate.
- **The number:** per incident, never reset, from the new `evidence_identifier_counters` table (`INSERT … ON CONFLICT DO UPDATE … RETURNING`): concurrent registrations get different numbers, a rolled-back one gives its number back, and only assigned identifiers use numbers. One already typed by hand is skipped, so an assigned identifier never ends in 409.
- **FENRIR's own drafts follow it too (D4):** supporting documents (Register as exhibit), Email, PCAP and Browser history uploads, and the email / browser-history Register as exhibit, instead of `DOC-` / `EMAIL-` / `PCAP-` / `WEBHIST-` + random hex.
- **Settings › Incident Reference › Exhibit identifiers** (admin): the convention, its tokens and the next identifier of the most recent incident. Literal text `A–Z a–z 0–9 . _ -`; `{seq}` exactly once; at most 64 characters; the longest result fits 128. Anything else is 422 `invalid_identifier_template`, naming the rule. Changes are audited (`evidence_identifier_template_changed`, old / new) and apply to new exhibits only.
- **Collection wizard and Quick add:** the identifier is optional, with the hint "Leave empty to assign automatically, e.g. …". The wizard's result and Quick add show the identifier that was assigned.
- **Audit:** `evidence_collect` carries `identifier_assigned` (`auto` / `typed`) and, when assigned, `identifier_template`.
- **API (additive):** `identifier` optional on `POST …/evidence/physical`, the upload-session complete (purpose evidence) and the deprecated multipart `POST …/evidence/digital`; `GET` / `PATCH /api/settings/evidence-identifier` (admin); `GET …/evidence/next-identifier` (`{template, example}`, reserves nothing). **MCP:** `fenrir_evidence_register` says the identifier is optional and where the convention is set (`fenrir_api`).
- **Changed:** a duplicate typed identifier on `POST …/evidence/physical` returns 409 `identifier_exists`, not the generic `conflict` (owner decision 2026-11-01).
- **Migration:** the new table `evidence_identifier_counters` (from `create_all`; nothing altered, nothing backfilled). Revert: `ignore/revert/evidence-ei-auto-identifier-2026-11-01/`.

### Added — evidence: folders as container exhibits, with a per-file manifest (S6, [design + as built](docs/evidence-s6-container-manifest-slice.md))

- **One exhibit per container (EG-4, ISO/IEC 27037 §7.1.3.1.2, §7.1.3.4):** acquire the folders with your tool into a ZIP, TAR, AD1, L01 or AFF4-L and register it as one exhibit. The Collection wizard's **Acquisition** step has a **Logical container** select when the scope is logical.
- **Manifest:** for ZIP and TAR (also `.tar.gz` / `.tgz` / `.tar.bz2` / `.tar.xz`) FENRIR lists every member in the background, from the encrypted stored file and without extracting anything: the path as stored (with its raw bytes when it isn't UTF-8), type, sizes, times with their source (NTFS / Unix extra fields, DOS time marked "timezone unknown", TAR mtime and pax times) and FENRIR's own MD5, SHA-1 and SHA-256 of each member. Encrypted members are listed without hashes. AD1, L01 and AFF4-L are kept but not indexed.
- **Tool listings:** a KAPE `*_CopyLog.csv` or a Velociraptor offline collector's `uploads.json` inside a ZIP adds each file's original path, the source times and the tool's hash, compared with FENRIR's. A listing FENRIR can't read is not merged and the reason is shown.
- **Limits, never a refusal:** at most 1,000,000 entries, 64 GiB decompressed (the zip-bomb guard) and 32,768-character paths by default. A container over a limit, damaged, unreadable or tampered keeps its exhibit; the manifest is **Failed** with the reason (a tampered file is also frozen), and **Rebuild** tries again.
- **Seal:** waits while a manifest is being built (409 `manifest_pending`); a built manifest's SHA-256 is part of the sealed record and the manifest never changes (append-only in the database).
- **Exhibit detail › Contents:** status, entries, builder, manifest SHA-256, the tool-listing result, a searchable table (entry path, source path, type, size, times, SHA-256, tool hash) and **Download CSV**. An advisory provenance check, **Container contents listed** (fails when the tool's hashes differ).
- **Disclosure packages** carry `…__manifest.jsonl` (its SHA-256 is the manifest SHA-256) and `…__manifest.csv` next to the exhibit, a `container_manifest` block in its `.meta.json`, and seven inventory columns at the end.
- **API (additive):** `container_format` on the upload-session complete and `PATCH …/acquisition-record`; `GET …/evidence/{id}/manifest` (`limit`, `cursor`, `q`, `format=csv`); `POST …/evidence/{id}/manifest/rebuild`; `EvidenceOut` container / manifest fields. New codes `manifest_pending`, `manifest_not_built`, `manifest_built`, `manifest_not_indexed`, `container_format_not_applicable`. **MCP:** `fenrir_evidence_list(view="manifest")`, `fenrir_evidence_custody("manifest_rebuild")`, `container_format` documented.
- **Migration:** seven nullable `evidence` columns, `ck_evidence_container_format_s6`, `ck_evidence_manifest_status_s6`, the new table `evidence_manifest_entries` and its append-only trigger. Settings: `EVIDENCE_MANIFEST_MAX_ENTRIES`, `EVIDENCE_MANIFEST_MAX_UNCOMPRESSED_BYTES`, `EVIDENCE_MANIFEST_MAX_PATH_CHARS`. Revert: `ignore/revert/evidence-s6-container-manifest-2026-10-31/`.

### Added — evidence: the screenshot capture record, and links to what a supporting document corroborates (S5, [design + as built](docs/evidence-s5-screenshots-slice.md))

- **Capture record (EG-6, ISO/IEC 27037 §7.1.1.1):** a supporting document records when it was captured, by whom (you or a name; never assumed to be the uploader), the tool and version, the method (whole screen, window, region, full page, scrolling, photo of a screen, other), the host or display, the URL and what is visible. **+ Upload files** opens a dialog with a collapsed **Capture details** section; **Details › Edit capture record** changes it later (audited from / to).
- **Hash at capture:** a SHA-256 given at upload is compared with the file before anything is stored; a mismatch is refused (422 `capture_hash_mismatch`), audited, and nothing is stored. It can't be changed afterwards.
- **Links (EG-7):** **Details › Link to…** records that a file corroborates an exhibit, a timeline event or an IOC of the incident, with a note; the exhibit, event and IOC list their **Supporting documents**. A linked file can't be deleted until unlinked; deleting the event or IOC removes its links. The file stays a supporting document (no chain of custody, never in a disclosure package).
- **Register as exhibit** pre-fills the new draft from the capture record (acquired at, acquisition tool and version, source system, source path from the URL — `cloud_uri` for https, else `other` — and screen state), shows it first, and leaves out (and audits) anything the source check refuses.
- **API (additive):** capture form fields on `POST …/files` and `POST …/entities/{id}/files`; capture fields on `PATCH …/files/{id}` (`capture_sha256` read-only); `POST` / `DELETE …/files/{id}/links[/{link_id}]`; `GET …/files?linked_type=&linked_id=`; `GET …/files/{id}/exhibit-prefill`; `EntityFileOut` capture fields + `links`; `prefill` on the register response; a `link` reference in 409 `file_referenced`.
- **MCP:** `fenrir_file_upload` documents exactly the fields FENRIR accepts (FP-7); `fenrir_entity_write` `link_file` / `unlink_file` and the capture fields on `file_update`; `fenrir_entity_list view=incident_files` filters on `linked_type` + `linked_id`.
- **Migration:** ten nullable `entity_files` columns, `ck_entity_files_capture_method_s5`, `ck_entity_files_capture_s5`, and the new table `supporting_file_links`. Revert: `ignore/revert/evidence-s5-screenshots-2026-10-31/`.

### Added — evidence: the photo record and photos in packages; the seal binds the record and asks for the source (S4 + S3, [design + as built](docs/evidence-s3-s4-seal-photos-slice.md))

- **Photo record (S4, ISO/IEC 27037 §6.6):** each exhibit photo records who took it (**Me** or a name), the **Camera**, **What it shows**, the uploaded file name, and a **Taken at** that must carry a timezone (422 `invalid_taken_at`; stored as UTC). The detail shows each photo's record, SHA-256 (click to copy) and size. An advisory provenance check, **Photo record complete**.
- **Photos in disclosure packages (EG-8):** `04_Evidence/Photos/<exhibit id>/` holds each stored photo, hash-checked like the exhibit's file (a tampered one is left out and the item frozen; one that fails while written fails the build), plus `photos.json`.
- **The seal binds the record (S3, EG-11, §5.4.5):** sealing hashes one canonical record (identity, hashes, the acquisition and source records, photo hashes), keeps its exact text in the hash-chained `evidence_seal` row and points the RFC 3161 token at it. The detail's **What the seal binds** shows the record's SHA-256, what the timestamp covers and whether an amendment has changed it since. Packages carry the record and the token in `04_Evidence/Seal/`.
- **The source at seal (EG-12, owner Q1):** a digital exhibit needs its source device (asset, source system or serial) and the path its handling needs, or **Unknown source — reason**; **Seal readiness** shows it. Items sealed before are not re-checked. The **Source location** provenance check uses the same rule (mandatory once sealed with a record).
- **Fixed:** the live-justification check now covers mission-critical live systems (FP-4); provenance labels cite the right ISO/IEC 27037:2012 clauses, codes unchanged (FP-8); a photo time that isn't ISO 8601 no longer breaks reading its exhibit (FP-2).
- **API (additive):** `POST …/evidence/{id}/photos` form fields `taken_by_id`, `taken_by_name`, `camera`, `context`; `PATCH …/evidence/{id}` photo fields (only those sent change); `GET …/evidence/{id}/seal-record`; `EvidenceOut.seal_record_sha256` / `seal_tst_subject`; `seal_fields_missing` can name `source_device`, `source_path`, `source_path_style`; new codes `invalid_taken_at`, `taken_by_conflict`, `evidence_not_sealed`. **MCP:** `fenrir_evidence_list(view="seal_record")`, photo fields documented. **Migration:** `evidence.seal_record_sha256`, `evidence.seal_tst_subject` (backfilled `file_sha256` for old seals with a token) + `ck_evidence_seal_tst_subject_s3`. Revert: `ignore/revert/evidence-s3-s4-seal-photos-2026-10-31/`.

### Added — evidence: the source location record, and disclosure carries the acquisition record (S1 + S2, [design + as built](docs/evidence-s1-s2-source-record-slice.md))

- **Source location record (S2, ISO/IEC 27037 §5.4.2, §6.6, §7.1.3.4):** a digital exhibit records its source device (**Source system**, make, model, serial — the make / model / serial columns now also serve digital exhibits) and the **Source path** exactly as recorded with its **Path style** (windows, unc, posix, macos, android, ios, cloud_uri, mail_store, device, other). The path is never trimmed, case-folded or normalised; the server derives a search form (`source_path_norm`, norm_v1). Optional `source_details`: filename on source, volume, OS, asset tag, source MACB times (each with its basis and reader), owner, stream / link target, cloud provider ids and hash, mail ids. **Unknown source — reason** when it can't be stated.
- **Where:** the Collection wizard's Identification step (a **Source** section; **Device** for physical items, which now really sends make / model / serial / storage location — FP-1), **Quick add** (source system, path, style), **Complete & seal**, and a read-only **Source** section in the exhibit detail.
- **Provenance (advisory):** `iso_27037_source_location` (digital: device + path by handling mode; manual with an unknown-reason), `iso_27037_device_identifiers` (physical), `source_provider_hash_match` (a provider MD5 / SHA-1 / SHA-256, hex or base64, against the stored file; other algorithms n/a). Nothing new blocks the seal yet (S3).
- **Disclosure + custody export (S1, EG-10):** `04_Evidence/Evidence_Inventory.csv` appends the rest of the acquisition record (tool, params, hashes, write-blocker, system state, justifications, witness, device types and details, handling, scope, clock offset, screen state, changes made, 27041 validation, qualifications, sealed by, TST present / time / TSA) and then the source record; the existing columns keep their order. Each file's `.meta.json` and the custody export's `coc/{id}.json` gain `acquisition` and `source` blocks. The custody export's photo list no longer exposes `storage_path`, `nonce_hex` or the API url (FP-5).
- **API (additive):** the source fields on `POST …/uploads/{id}/complete` (evidence), the deprecated `POST …/evidence/digital` (form fields; `source_details` as JSON), `POST …/evidence/physical` (`source_system`, `source_details`), `PATCH …/acquisition-record` and `PATCH …/evidence/{id}` (an amendment on a sealed item; collector, custodian, lead or admin). New 422 codes: `invalid_source_path`, `invalid_source_text`, `source_path_style_required`, `source_path_style_mismatch`, `source_path_norm_read_only`, `source_unknown_reason_too_short`. Audited in `evidence_collect` / `evidence_acquisition_record` / `evidence_amend_after_seal`.
- **Changed:** the deprecated multipart route stores the upload's basename as `original_filename`, like the upload sessions (FP-6; 422 `invalid_filename` for a name with control characters).
- **MCP:** `fenrir_evidence_register` documents the fields (`data` passes them through). **Migration:** six nullable `evidence` columns + `ck_evidence_source_path_style_s2`. Revert: `ignore/revert/evidence-s1-s2-source-record-2026-10-31/`.

### Added — timeline export: six layouts (TX, [design + as built](docs/timeline-export-layouts-slice.md))

- **One Export button, six layouts:** **⇩ Export** in the Timeline toolbar replaces **Export CSV** and **Export HTML**. Pick **Rail** (vertical), **Horizon** (horizontal, time-scaled), **Swimlanes** (one lane per linked entity), **Ledger** (forensic table), **Brief** (executive one-pager) or **Zig-zag** (the original layout), or CSV. **Preview** shows the page before you save it.
- **Incidents over several days (Horizon):** quiet stretches over 6 h fold into labelled breaks, with one scale (4 px per minute) for every period; periods wrap onto new rows; a true-scale overview with one column per day sits on top.
- **Options:** key events only; raw logs (off by default — Rail, Ledger, Zig-zag and the CSV only); UTC or your Fenrir time zone, with the UTC offset in every page.
- **Built on the server now:** the export holds the events the page's filters show. Every HTML page is script-free with its own CSP and carries the TLP. The Ledger states the SHA-256 of the matching CSV.
- **API (additive):** `GET /api/incidents/{id}/timeline/export` (`layout`, `format`, `tz`, `include_raw_logs` + the list's filters); audited as `timeline_export`; 422 `invalid_timezone`, 422 `export_too_large` (over 10 000 events).
- **MCP:** `fenrir_timeline_list(export=…, tz=, include_raw_logs=)` returns the file as text.
- **Changed:** the Zig-zag and CSV leave raw logs out unless you include them (they always held them before); Zig-zag times follow the chosen time zone instead of the browser's.
- **Help:** **Export Timeline** rewritten. **No migration.** Revert: `ignore/revert/tx/`.

### Fixed — unsaved edits survive a session timeout (SE, [design + as built](docs/session-expiry-unsaved-work-slice.md))

- **The problem:** when the session ended (30 min idle, 8 h cap, or revoked), the next request's 401 sent the app to the login page, unmounting the page and losing anything not yet saved. Reads never restarted the idle timer, and typing never reaches the server.
- **Typing counts as activity:** the app reports real input (key, click, scroll, touch) with a heartbeat at most every 5 minutes. A tab nobody uses still signs out. Nothing extends the 8-hour cap.
- **Warnings 2 minutes before:** **Still there?** with a countdown before the idle limit (**Stay signed in**); a banner with the end time before the 8-hour limit (**Sign in again** starts a new session without leaving the page).
- **Expiry no longer leaves the page:** an opaque cover hides the content, and you sign in again on it (password, then TOTP) as the same user. Your unsaved changes stay on the page; save them again. Signing in as someone else reloads the page and drops them. A 401 now reads "Your session ended. Sign in again, then retry."
- **API (additive):** `GET /api/sessions/current` (pure read: `CurrentSessionOut` with `idle_expires_at`, `idle_timeout_seconds`, `expires_at`, `server_time`) and `POST /api/sessions/current/heartbeats` (counts as activity; not audited). Both are for a cookie session only: a Bearer token gets 401.
- **Help:** new topic **Session Timeouts**.
- **No migration. No MCP change** (API tokens have no idle timeout). Revert: `ignore/revert/se/`.

### Fixed — timeline events pick up registered entities (TE, [design + as built](docs/timeline-entity-link-slice.md))

- **The problem:** an event belongs to an entity only through its `entity_id` link, and only a click in the event form set it. Imported events kept the host as text, so the entity filter, the entity's **Timeline events** and reports missed them, and registering an entity later linked nothing.
- **One matching rule, on the server** (`entities/match.py`): the host equals the entity's value ignoring case and surrounding spaces; any entity type; ties go to the exact-case value, then the host; a tie that remains matches nothing. It replaces the browser-side `lib/entityMatch.js`.
- **Suggest, then link on a click** (owner decision D1): nothing is linked silently.
  - Each event shows its linked entity as a chip (red with ⚠ when compromised), or **≈ Host DC01 · not linked** when its host names one. Expanded: **Link this event**, and **Link them** for every unlinked event that names it.
  - The entity drawer, adding an entity in **Scope**, adding an affected system on **Details** and **Add … to Entities** in the event form offer to link the events that already name it.
- **Imports link by host** (D3, on by default, visible): a **Link to entities by host** checkbox on Logs & triage, Network capture, Vendor reports and an email's **Import hops**. The host as recorded never changes; the link is an annotation, so imported facts stay immutable.
- **API (additive):**
  - `TimelineEventOut` gains read-only `entity` and `entity_match`.
  - New: `POST …/timeline/entity-links {entity_id, dry_run}` → `{entity_id, matched, linked}`; audited once as `timeline_entity_link` with the event ids; a repeat links 0; already-linked and server-recorded events are never touched.
  - `GET …/entities?match=` returns the entity a typed name resolves to (with `type`, within that type).
  - `link_entities` (default true) on the forensic, Defender and PCAP promotes, `…/timeline/batch` and `…/email/{id}/import-hops` (query); their results and audit rows carry `entities_linked`.
- **MCP:** new `fenrir_timeline_write(action="link_entity", entity_id, dry_run)`, `match` on `fenrir_entity_list`, `link_entities` on batch and import tools.
- **No migration.** Revert: `ignore/revert/te/`.

### Changed — editable, signed case notes (CN-2, [design + as built](docs/case-notes-editable-slice.md))

- **Edit a case note.** **Edit** on a note saves its next revision. Nothing stored is changed: the H2 append-only trigger is untouched, and every earlier revision stays in the note's **History**, with a diff of what each revision changed.
  - Only the note's author or an admin can edit it. This fixes H2, where the author could no longer correct a note once an admin had.
  - An edit that loses a race returns the existing 409 `already_corrected`. The UI says so and offers **Reload**.
  - The Case notes page shows one card per note, kept in the order the notes were first written. The struck-through "correction" entries are gone.
- **Signed.** From now on every entry carries a signature recorded when it is saved: `signed_name` (full name, else username) and `signed_as` (the operational role keys held on the incident, else the platform role).
  - The signature is part of the entry's SHA-256 (`hash_v` 2).
  - Entries written before CN-2 keep `hash_v` 1, show as **unsigned**, and still verify.
- **API (additive):**
  - `CaseNoteOut` gains `root_id`, `revision`, `root_author_id`, `root_author_username`, `signed_name`, `signed_as` and `hash_v`.
  - `GET …/case-notes?current=true` lists each note's current revision.
  - New: `GET …/case-notes/{id}/revisions`.
  - An edit is the existing `POST …/case-notes` with `corrects_id` = the current revision.
  - The default list is unchanged.
- **Exports:** the LE package's `10_Case_Notes/` lists every revision. It gains the columns `root_id`, `revision`, `signed_name`, `signed_as` and `hash_v` (appended; existing columns keep their positions), and the README hash recipe documents v2. The full report's Case Notes appendix prints each note's current revision with its signature.
- **MCP:** new action `fenrir_comms_write(action="case_note_edit", item_id=<current revision>)`, new view `case_note_revisions`, and a `current` filter on `case_notes`.
- **Migration:** three additive columns on `case_notes` plus a CHECK. Metadata-only, with no backfill.

### Added — phishing fast path ([design + as built](docs/phishing-fast-path-slices.md))

- **Seen before (P1).** An email analysis now shows earlier incidents that already hold its indicators as IOCs, strongest first, with each incident's triage state and whether the IOC is marked malicious. The indicators checked are the sender, Reply-To / Return-Path, each link and its host, attachment hashes and the public origin IP.
  - A ⋈ badge marks each matching link and attachment.
  - Only incidents you can open are searched, never the current one.
  - Surfaces: `GET /api/incidents/{id}/email/{aid}/seen-before`; MCP `fenrir_forensic_list(view="email_seen_before")`.
  - `POST /api/correlations/lookup` hits now also carry `ref`, `status` and `triage_state` (additive).
- **Scope in Defender (P2).** Ready-to-run Defender XDR Advanced Hunting queries built from the analysis:
  - who received it and where it is now;
  - the same campaign (Microsoft's similarity cluster, same sender);
  - every mail with the same links;
  - who clicked;
  - who received the attachment;
  - the devices the file reached.

  FENRIR runs nothing. Every value from the message is an escaped KQL literal and never appears in a comment. The call is audited as `email_hunting_queries` (query ids only) and doesn't mark reports stale. Surfaces: `GET …/email/{aid}/hunting-queries?lookback_days=1-30`; MCP view `email_hunting_queries`.
- **Contain from the analysis (P3).** **Contain…** shows a plan worked out on the server: quarantine the message, block the sender, sender domain or Reply-To, each link (URL, domain or IP as it is promoted), each attachment, the origin IP. Each item comes with a suggestion and its reason.
  - Confirming adds the IOCs and open Respond actions with the matching templates, through the same rules as the Respond form.
  - It is idempotent and all or nothing.
  - It then offers a Defender CSV / JSON of exactly those IOCs.
  - A sender that failed DMARC is never suggested: the address is forged. Neither is one whose DMARC pass the live DNS check didn't confirm, since a header pass can be forged.
  - Links are suggested only when an earlier incident confirmed them, because a risk signal can point at a legitimate site; the signal is shown as the reason. MCP refuses an empty `ioc_ids` instead of exporting everything.
  - Surfaces: `GET …/email/{aid}/containment-plan`, `POST …/email/{aid}/containment` (items by `{kind, ref}` only); MCP view `email_containment_plan`, `fenrir_email_analyze(action="containment")`.
- **IOC export filter:** `GET …/iocs/export/{fmt}?ioc_id=…` (repeatable, at most 500) exports only those IOCs (422 `ioc_other_incident` / `too_many_iocs`). MCP: `fenrir_ioc_export(ioc_ids=…)`.

### Fixed

- **Security: uploaded file names no longer reach a file path** (GitHub CodeQL `py/path-injection`, `files/routes.py`). New incident Files, entity attachments and quarantined artifacts (artifact uploads, collector output, email attachments, Defender PDFs) are stored as `<server id>.enc` under the incident or entity of the database row. The uploaded name stays in the row (`original_name` / `original_filename`) and on downloads. Existing files keep their `<id>_<name>.enc` path; readers use the row's path. It wasn't exploitable before (the name was cleaned to `\w . -` behind a server UUID, and a containment check followed), but file names no longer sit in plain text on the encrypted volumes. Revert: `ignore/revert/path-injection-2026-11-01/`.
- **Frontend dependencies (security):** `vite` 8.0.16 → 8.3.4, `react-router` / `react-router-dom` 7.18.0 → 7.18.2, `postcss` 8.5.15 → 8.5.30 and `nanoid` 3.3.12 → 3.3.20. `npm audit` goes from 5 findings (Vite / launch-editor GHSA-587h-7wmj-h5pm, -r825-w8mm-5pxw, -698v-4r3x-3vcv, -rq7h-c2jc-7f22, -9jrq-w75r-8gcw; React Router GHSA-qwww-vcr4-c8h2; PostCSS GHSA-r28c-9q8g-f849, -fxqj-rqcc-2cmp; nanoid GHSA-28wg-ghj8-5hjv, -2v37-7h3g-55p8) to 0. Vite and PostCSS run only at build time and the app doesn't use React Router's RSC mode, so the served app was not exposed in practice.
  - **14-day cooldown:** every new version is at least 14 days old. Vite 8.3.5 (2026-10-21) waits until 2026-11-04. `package.json` `overrides` hold back the newer transitive releases (`postcss` 8.5.30, `rolldown` 1.2.14, `set-cookie-parser` 2.7.2); re-check them at the next bump.
  - Same build output: the CSS is byte-identical and the JS is about 3 KB smaller. Rebuild the frontend image. Revert: `ignore/revert/deps-frontend-2026-11-01/`.
- **Timeline export: the time-zone name is checked without a regex** (GitHub CodeQL `py/polynomial-redos` on `?tz=`). The rule is unchanged (1–3 `/` parts of `A–Z a–z 0–9 _ + -`), plus a 64-character cap; anything else is 422 `invalid_timezone`. The old regex was linear under `fullmatch` in practice, but it no longer exists. The same pass cleared the PR's eight code-quality notes (comments on three empty `except` blocks, one test helper uses `contextlib.closing`, test imports). Revert: `ignore/revert/code-quality-2026-11-01/`.
- **Security: the IOC export ignored team access.** `GET /api/incidents/{id}/iocs/export/{fmt}` only checked that the incident existed, so anyone signed in could export the IOCs of a team-restricted incident by its UUID. It now uses the same access check as the IOC list (404 `incident_not_found`). The gap predates this release; the independent review found it.
- **Entity bulk import rejected every row** (`Unknown type "", Value is required` from line 2) unless the input was a comma CSV with a `type,value` header. Fixed cases:
  - A semicolon CSV (Excel in many locales) or tab-separated cells pasted from a spreadsheet now parse.
  - A plain list (one value per line, no header) imports with a chosen **Type for a plain list**. **Auto-detect** recognises IPs, ranges, emails, `DOMAIN\user` and domain names.
  - A header row without `type` and `value` columns now gives one clear error that names the columns found.
- **Defender export defaults to Block execution** (`action=Block`), not Audit, in the GUI and in the API (`GET …/iocs/export/mde-csv|mde-json`). The Action list uses the portal's names.
- **Defender URL and domain indicators use Microsoft's value forms** ([indicators overview](https://learn.microsoft.com/defender-endpoint/indicators-overview)). A URL or domain IOC is sorted by its value. A bare host becomes a `DomainName` (`contoso.com`), or an `IpAddress` if the host is an IP. A value with a path or query becomes a full `Url` (`https://contoso.com/page`); `https://` is added when the scheme is missing. Defanged values are refanged. Each indicator appears once per file.
- **Defender CSV follows the [import format](https://learn.microsoft.com/defender-endpoint/indicator-manage):**
  - `ExpirationTime` is `YYYY-MM-DDTHH:MM:SS.0Z`.
  - `GenerateAlert` is `True`/`False`.
  - MD5 rows are left out, because the CSV import doesn't take `FileMd5`.
- **Defender JSON is the [import API](https://learn.microsoft.com/defender-endpoint/api/import-ti-indicators) body** (`{"Indicators": […]}`, previously `{"value": […]}`).
- **Defender actions per indicator type (both formats):**
  - IPs, domains and URLs get `Block` when `BlockAndRemediate` is chosen, because Defender won't import that action for network indicators.
  - `Audit` always sets generate-alert to true, as the API requires.
- **Email analyser: Promote → IOC adds one IOC per link, typed by what the link is.** A link with a path or query becomes a URL IOC with the full request URL. A bare-domain link becomes a domain IOC (or an IP IOC). Previously every link added both its URL and its host's domain. Each `urls[]` row in the API now carries `ioc_type`/`ioc_value`, and the URL table shows them in a **Promote as** column.

### Upgrade notes

- Rebuild the backend and frontend images.
- **API clients:** the `mde-json` body key changed from `value` to `Indicators`. The default `action` is now `Block`.

### Verification

- `backend/tests/test_ioc_url_indicator.py`: 12 tests pass. 8 of them fail against the previous `exports.py`/`schemas.py` (negative control).
- The frontend builds. The entity import parser was checked in node against plain, semicolon, tab, BOM, quoted, bad-header and header-only inputs; the first three reproduced the error before the fix.
- Phishing fast path:
  - Rolled-back DB tests through the real routes, after the review fixes: P1 26/0, P2 15/0, P3 32/0 (including export access).
  - `backend/tests/test_phish_fast_path.py`: 21 tests, including KQL literal round-trip and fuzz tests with hostile values.
  - One independent review. Fixed: export access, link pre-ticks, unconfirmed DMARC pass, duplicate-row merge, values over 2048 characters (a 500 before), MCP empty `ioc_ids`, dialog accessibility, the assignee picker. The noted, not-changed items are in the design doc's As-built section.
  - The `scoring.py` refactor scores 5000 random messages and all 53 stored analyses identically.
  - Earlier waves' DB scripts: K4/K5 70/0, J4/J5 63/0, SEC1 18/0. Older scripts that predate required incident fields (e.g. C1) were not run.
  - MCP suite: 532 passed.
- Not yet run against the live stack, not yet imported into a Defender tenant, and the KQL not yet run in Defender.

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

### Post-backlog owner items (2026-10-07)

- **API tokens screens:** Settings → Account → API tokens and Admin → API Tokens. List tokens, create one with an expiry (the secret is shown once), and revoke in the row; an admin revoke notifies the owner. New `fenrir-mcp tokens list|revoke`. (OD-1)
- ⚠ **`POST /api/tokens` requires `expires_in_days`** (1–90; it was optional, up to 3650). Existing tokens keep their expiry. Token objects gain `status`, and errors carry `token_role_exceeds_user` / `token_not_found`. (OD-1)
- **SIEM forwarding:** for TLP:RED and Dark Operation incidents, forwarded audit lines replace the indicator with `redacted:tlp-red` / `redacted:dark-op`. The stored audit row and its hash are unchanged. (OD-2)
- ⚠ **Edge limits:** Caddy refuses multipart bodies over 520 MiB (was 2,200 MiB) and other bodies over 10 MiB. It answers with a JSON 413 `{"detail":"Request body too large","code":"file_too_large"}` instead of an empty body. (OD-4)
- **Analysis worker:** the `/quarantine` mount and the 12 path-based `/analyze/{tool}` routes are removed. Artifacts reach the worker only as bytes over TLS. This is an internal API, so no client change. (OD-3)
- ⚠ **`POST /api/tokens` needs an interactive login** (password + TOTP). A request with an API token gets 403 `token_create_requires_session`, and the refusal is audited. Listing and revoking with a token still work, and `fenrir-mcp login` is unaffected. (R146)
- ⚠ **MCP `fenrir_api` refuses credential endpoints** whatever the path encoding: tokens, sessions, user credential and role writes, and SIEM and service keys. Use the GUI or `fenrir-mcp tokens list|revoke` instead. (R146)
- ⚠ **MCP never receives a secret or grants access:** it no longer creates users, changes roles, resets passwords, adds team members, generates the SIEM key, or sets service keys or SMTP/webhook/syslog config. These actions are removed from the tool schemas and their endpoints are hard-denied on every path; use the FENRIR GUI. Revoke, unlock, delete and reads stay. (R150/R151)
- **Fixed MCP denylist bypass:** the query and fragment are now cut before percent-decoding, so `%3F`/`%23` can no longer hide a `/../` route to a denied endpoint. (R150)
- **Stakeholder matrix and Validated tools are their own pages** under Prepare in the sidebar (`/stakeholder-matrix`, `/validated-tools`, admin only) and are no longer inside Settings. Old `/settings/...` links redirect. Readiness "fix" links point to the new pages. (owner request)

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
