"""Per-evidence provenance scoring.

Mirrors the SOP autoCheck logic into the server so external consumers (MCP
tools, scripts, the handoff wizard) get the same score the UI computes.

Score semantics:
  green  — every applicable mandatory + advisory check passes
  amber  — at least one advisory check fails, or any check is 'manual'
  red    — at least one mandatory check fails
"""
from __future__ import annotations

from typing import Optional

from evidence.hashing import hash_algorithm
from evidence.source import provider_hash_check, seal_source_missing
from models import Evidence
from schemas import offset_datetime


_ALGO_LABEL = {"md5": "MD5", "sha1": "SHA-1", "sha256": "SHA-256"}
_ONE_HASH_NOTE = {
    "target": "Only the target hash is recorded, so there is nothing to compare it with: confirm the source hash in "
              "the tool's report (a screenshot or other capture has none)",
    "source": "Only the source hash is recorded, so there is nothing to compare it with: record the target hash from "
              "the tool's report",
}
_SOURCE_MISSING = {"source_device": "the source device (an entity, the source system or the serial)",
                   "source_path": "the source path and its style",
                   "source_path_style": "a device path (style device) for the full image"}


def _blank(v: Optional[str]) -> bool:
    return not (v or "").strip()


def _source_location(ev: Evidence) -> dict:
    """S2/S3 — HLD §3.3 (ISO/IEC 27037 §5.4.2, §6.6, §7.1.3.4): the seal gate's own rule (evidence/source.py
    seal_source_missing). Mandatory once a seal bound it (a record_v1 seal: seal_record_sha256 set), advisory
    otherwise; met only by source_unknown_reason = manual, never pass."""
    missing = seal_source_missing(ev)
    if not missing:
        status, note = "pass", None
    elif not _blank(ev.source_unknown_reason):
        status, note = "manual", f"Source stated as unknown: {ev.source_unknown_reason[:200]}"
    else:
        status, note = "fail", f"Record {' and '.join(_SOURCE_MISSING[m] for m in missing)}, or say why the source is unknown"
    return _check(code="iso_27037_source_location", label="Source location recorded (device + path)",
                  status=status, severity="mandatory" if ev.coc_sealed and ev.seal_record_sha256 else "advisory",
                  note=note)


def _photo_record(ev: Evidence) -> Optional[dict]:
    """S4 (EG-9; ISO/IEC 27037 §6.6, §7.1.3.1.3) — each photo says who took it, when (ISO 8601 with an offset) and
    with what camera. Advisory; no check when the item has no photo."""
    photos = [p for p in ev.photos or [] if isinstance(p, dict)]
    if not photos:
        return None
    gaps = {"taken by": 0, "taken at": 0, "camera": 0}
    incomplete = 0
    for p in photos:
        lacks = [k for k, ok in (("taken by", p.get("taken_by_id") or not _blank(p.get("taken_by_name"))),
                                 ("taken at", offset_datetime(p.get("taken_at")) is not None),
                                 ("camera", not _blank(p.get("camera")))) if not ok]
        incomplete += bool(lacks)
        for k in lacks:
            gaps[k] += 1
    note = (f"{incomplete} of {len(photos)} photo(s) lack: " + ", ".join(k for k, n in gaps.items() if n)
            if incomplete else None)
    return _check(code="iso_27037_photo_record", label="Photo record complete (taken by, taken at, camera)",
                  status="fail" if incomplete else "pass", severity="advisory", note=note)


def _provider_hash(ev: Evidence) -> Optional[dict]:
    """EG-5 — the cloud provider's own hash vs the stored file (advisory; only MD5 / SHA-1 / SHA-256)."""
    r = provider_hash_check(ev.source_details, md5=ev.md5, sha1=ev.sha1, sha256=ev.sha256)
    if r is None:
        return None
    if not r["comparable"]:
        why = {"algorithm": f"{r['algorithm']} is recorded as given; FENRIR compares only MD5, SHA-1 and SHA-256",
               "value": "the value is not hex or base64 of that algorithm", "no_file": "no stored file to compare"}
        return _check(code="source_provider_hash_match", label="Provider's hash matches the stored file",
                      status="n_a", severity="advisory", note=why[r["reason"]])
    label = _ALGO_LABEL[r["algorithm"]]
    return _check(code="source_provider_hash_match", label="Provider's hash matches the stored file",
                  status="pass" if r["match"] else "fail", severity="advisory",
                  note=None if r["match"] else f"The provider's {label} differs from the stored file's: the copy "
                                               "may not be the provider's object")


def _container_manifest(ev: Evidence) -> dict:
    """S6 (EG-4; ISO/IEC 27037 §7.1.3.4, §7.1.3.1.2) — a container exhibit's per-file manifest: built → pass (fail
    when the tool listing's hashes disagree with FENRIR's); failed, not indexed or still pending → manual; not a
    container → n/a. Advisory."""
    status_ = getattr(ev, "manifest_status", None)
    label = "Container contents listed (per-file manifest)"
    if not getattr(ev, "container_format", None):
        return _check(code="container_manifest", label=label, status="n_a", severity="advisory",
                      note="Not a container exhibit")
    if status_ == "built":
        bad = sum(int((s or {}).get("tool_hash_mismatches") or 0) for s in getattr(ev, "manifest_listing", None) or [])
        return _check(code="container_manifest", label=label, status="fail" if bad else "pass", severity="advisory",
                      note=f"{bad} member(s) differ from the tool listing's hash" if bad else None)
    note = {"pending": "The manifest is still being built",
            "not_indexed": f"FENRIR does not index {ev.container_format} containers: list the contents from the "
                           "tool's own report",
            "failed": f"The manifest could not be built: {(getattr(ev, 'manifest_error', None) or '')[:200]}"}
    return _check(code="container_manifest", label=label, status="manual", severity="advisory",
                  note=note.get(status_, "No manifest"))


def _passes(b: Optional[bool]) -> str:
    if b is True:  return "pass"
    if b is False: return "fail"
    return "manual"


def _check(*, code: str, label: str, status: str, severity: str,
           note: Optional[str] = None) -> dict:
    return {"code": code, "label": label, "status": status,
            "severity": severity, "note": note}


def score_evidence(ev: Evidence) -> dict:
    """Returns a dict matching the ProvenanceScore schema."""
    checks: list[dict] = []
    is_digital  = ev.kind == "digital_file"
    is_physical = ev.kind == "physical_item"

    # ── ISO/IEC 27037 §5.4.2 — Identification (in-situ photo: §6.2.1) ──
    if is_physical:
        photos_ok = bool(ev.photos and len(ev.photos) > 0)
        checks.append(_check(
            code="iso_27037_9_1_4", label="In-situ photograph captured (physical; ISO/IEC 27037 §6.2.1)",
            status=("pass" if photos_ok else "fail"),
            severity="mandatory",
            note=None if photos_ok else "Physical evidence requires at least one photo",
        ))
        # S2 — make, model and serial "when possible" (ISO/IEC 27037 §7.1.1.1; advisory, never a gate)
        missing = [f for f in ("make", "model", "serial") if _blank(getattr(ev, f))]
        checks.append(_check(
            code="iso_27037_device_identifiers", label="Device identifiers recorded (make, model, serial)",
            status="fail" if missing else "pass", severity="advisory",
            note=f"Record the item's {', '.join(missing)} where possible" if missing else None,
        ))
    photo_record = _photo_record(ev)
    if photo_record:
        checks.append(photo_record)

    # Collector + location (ISO 27037 §6.1 + NIST 800-86 §3.1.2)
    has_collector = bool(ev.collected_by_id)
    has_location  = bool((ev.collected_location or "").strip())
    checks.append(_check(
        code="iso_27037_collector",
        label="Collector identified",
        status=("pass" if has_collector else "fail"),
        severity="mandatory",
    ))
    checks.append(_check(
        code="iso_27037_collection_location",
        label="Collection location recorded",
        status=("pass" if has_location else "fail"),
        severity="advisory",
    ))
    if is_digital:
        checks.append(_source_location(ev))

    # Lawful basis (GDPR Art. 5.1(c))
    checks.append(_check(
        code="gdpr_5_1_c_lawful_basis",
        label="Lawful basis recorded",
        status=("pass" if ev.lawful_basis else "fail"),
        severity="mandatory",
        note=None if ev.lawful_basis else "Required under GDPR Art. 5.1(c) — pick a basis or justify ad-hoc",
    ))

    # ── ISO/IEC 27037 §5.4.4 — Hash at acquisition ──
    if is_digital:
        checks.append(_check(
            code="iso_27037_9_2_3_sha256",
            label="SHA-256 hash captured at acquisition (ISO/IEC 27037 §5.4.4)",
            status=("pass" if ev.sha256 else "fail"),
            severity="mandatory",
        ))
        # ISO 27037 §5.4.4 — write-blocker / live-acquisition justified
        wb = ev.write_blocker_used
        sys_state = (ev.system_state or "").lower()
        if wb is None and not sys_state:
            checks.append(_check(
                code="iso_27037_9_2_1_writeblocker",
                label="Write-blocker / live-acquisition status recorded (ISO/IEC 27037 §5.4.4, §7.1.3)",
                status="fail", severity="advisory",
                note="Capture write_blocker_used + system_state via the acquisition wizard",
            ))
        else:
            live_ok = True
            note = None
            # FP-4: live and live_critical both need a justification, as at the seal (§7.1.3.1.1).
            if sys_state in ("live", "live_critical") and not (ev.live_justification or "").strip():
                live_ok = False
                note = "Live acquisition requires justification (ISO 27037 §5.4.4)"
            checks.append(_check(
                code="iso_27037_9_2_1_writeblocker",
                label="Write-blocker / live-acquisition status recorded (ISO/IEC 27037 §5.4.4, §7.1.3)",
                status=("pass" if live_ok else "fail"),
                severity="advisory", note=note,
            ))

        # ISO 27037 §5.4.4 + NIST 800-86 §3.1.2 — acquisition tool + version
        tool_ok = bool(ev.acquisition_tool and ev.acquisition_tool_version)
        checks.append(_check(
            code="iso_27037_9_2_4_tool",
            label="Acquisition tool + version documented (ISO/IEC 27037 §5.4.4)",
            status=("pass" if tool_ok else "fail"),
            severity="mandatory" if ev.coc_sealed else "advisory",
            note=None if tool_ok else "Required for reproducibility (ISO 27037 §5.4.4, NIST 800-86 §3.1.2)",
        ))

        # ISO 27037 §5.4.4 / §7.1.4 — source vs target hash match (acquisition integrity). C3: two hashes
        # of different algorithms (e.g. MD5 source, SHA-256 target) can't be compared here,
        # so that case is advisory ("manual"), never a mandatory fail.
        src_algo = hash_algorithm(ev.acquisition_hash_source)
        tgt_algo = hash_algorithm(ev.acquisition_hash_target)
        if src_algo and tgt_algo and src_algo != tgt_algo:
            checks.append(_check(
                code="iso_27037_9_2_5_hash_match",
                label="Acquisition source/target hash match (ISO/IEC 27037 §5.4.4)",
                status="manual", severity="advisory",
                note=(f"Source ({_ALGO_LABEL[src_algo]}) and target ({_ALGO_LABEL[tgt_algo]}) use "
                      "different algorithms — confirm the match in the imaging tool's report"),
            ))
        elif bool(ev.acquisition_hash_source) != bool(ev.acquisition_hash_target):
            # Owner decision 2026-11-01: one hash alone has nothing to compare with, which is not a mismatch (a
            # screenshot registered as an exhibit has its hash at capture as the target hash, and no source hash).
            checks.append(_check(
                code="iso_27037_9_2_5_hash_match",
                label="Acquisition source/target hash match (ISO/IEC 27037 §5.4.4)",
                status="manual", severity="advisory",
                note=_ONE_HASH_NOTE["target" if ev.acquisition_hash_target else "source"],
            ))
        elif ev.acquisition_hash_source or ev.acquisition_hash_target:
            match = (ev.acquisition_hash_source or "").lower() == (ev.acquisition_hash_target or "").lower()
            checks.append(_check(
                code="iso_27037_9_2_5_hash_match",
                label="Acquisition source/target hash match (ISO/IEC 27037 §5.4.4)",
                status=("pass" if match else "fail"),
                severity="mandatory",
                note=None if match else "Source and target hashes differ — acquisition integrity broken",
            ))
        provider = _provider_hash(ev)
        if provider:
            checks.append(provider)
        checks.append(_container_manifest(ev))

    # ── Chain-of-custody status ──
    chain_ok = ev.status in ("active", "archived", "returned", "destroyed")
    chain_note = None
    if ev.status == "verify_failed":
        chain_ok = False
        chain_note = "Integrity verify failed — chain broken"
    checks.append(_check(
        code="custody_chain_unbroken",
        label="Chain unbroken (no verify_failed state)",
        status=("pass" if chain_ok else "fail"),
        severity="mandatory",
        note=chain_note,
    ))

    # ── External-custody flag (ISO 27037 §6.1 — chain still has accountability,
    # but the current holder isn't a platform user so the integrity guarantees
    # we provide are paused while the row is externally held).
    is_external_now = (ev.current_custodian_id is None
                       and bool(ev.current_custodian_external_name))
    if is_external_now:
        holder = ev.current_custodian_external_name
        if ev.current_custodian_external_org:
            holder = f"{holder} ({ev.current_custodian_external_org})"
        checks.append(_check(
            code="custody_internal_holder",
            label="Currently held by an internal accountable user",
            status="fail",
            severity="advisory",
            note=f"In external custody: {holder}. Take it back to re-enable examine/verify/seal.",
        ))
    else:
        checks.append(_check(
            code="custody_internal_holder",
            label="Currently held by an internal accountable user",
            status="pass",
            severity="advisory",
        ))

    # ── C4 — internal custody transfers accepted by the recipient (ISO/IEC 27037 §6.1;
    # SWGDE §6.2/§6.3). Transfers recorded before recipient acceptance existed are advisory
    # ("manual"), never a fail. No internal transfer → not applicable (no check).
    acked  = getattr(ev, "internal_transfers_acknowledged", 0)
    legacy = getattr(ev, "internal_transfers_legacy", 0)
    if legacy:
        checks.append(_check(
            code="custody_transfers_acknowledged",
            label="Custody transfers acknowledged by the recipient",
            status="manual", severity="advisory",
            note=(f"{legacy} transfer(s) recorded before recipient acceptance existed — "
                  "confirm receipt and condition from the paper record"),
        ))
    elif acked:
        checks.append(_check(
            code="custody_transfers_acknowledged",
            label="Custody transfers acknowledged by the recipient",
            status="pass", severity="mandatory",
        ))

    # ── Wizard A seal ──
    checks.append(_check(
        code="wizard_a_sealed",
        label="Acquisition wizard sealed",
        status=("pass" if ev.coc_sealed else "manual"),
        severity="advisory",
        note=None if ev.coc_sealed else "Run the acquisition wizard to seal this row for court-grade use",
    ))

    # ── ISO/IEC 27041 — method/tool validation (Slice B; advisory/soft) ──
    if is_digital:
        val_ok = ev.acquisition_tool_validated is True
        checks.append(_check(
            code="iso_27041_method_validated",
            label="Acquisition tool/method validated (ISO/IEC 27041)",
            status=("pass" if val_ok else "fail"),
            severity="advisory",
            note=None if val_ok else "Record that the acquisition tool/method was validated as suitable (27041 §7 / checklist item 7)",
        ))

    # ── Expert qualifications (ISO 27037 Annex A / 27041; advisory) ──
    qual_ok = bool((ev.collected_by_qualifications or "").strip())
    checks.append(_check(
        code="iso_27037_annex_a_qualifications",
        label="Collector qualifications recorded",
        status=("pass" if qual_ok else "fail"),
        severity="advisory",
        note=None if qual_ok else "Set the collector's qualifications on their user profile (ISO 27037 Annex A / 27041 checklist item 10)",
    ))

    # ── Collector role DEFR/DES (ISO/IEC 27037 §3.7/§3.8; GS-12; advisory) ──
    role_ok = ev.collected_as_role in ("defr", "des")
    checks.append(_check(
        code="iso_27037_3_7_collector_role",
        label="Collector role recorded (DEFR/DES)",
        status=("pass" if role_ok else "fail"),
        severity="advisory",
        note=None if role_ok else "Record whether collection was by a DEFR (first responder) or DES (specialist) — ISO 27037 §3.7/§3.8",
    ))

    # ── ISO/IEC 27037 §7.1.3.1.1 — working copy verified vs master (Slice D; advisory) ──
    if is_digital:
        wc_ok = bool(getattr(ev, "has_verified_working_copy", False))
        checks.append(_check(
            code="iso_27037_7_1_3_1_1_working_copy",
            label="Analysis used a master-verified working copy",
            status=("pass" if wc_ok else "manual"),
            severity="advisory",
            note=None if wc_ok else ("No verified working copy yet — download one, or record a lab copy with the hash "
                                     "its tool reported, in the evidence detail (a legacy record holds the master's "
                                     "hash, not the copy's, and doesn't count)"),
        ))

    # ── L10 — a working-copy record corrected by an append-only audit note (advisory) ──
    corrections = getattr(ev, "copy_corrections", 0)
    if corrections:
        checks.append(_check(
            code="working_copy_record_corrected",
            label="Working-copy records accurate",
            status="manual", severity="advisory",
            note=(f"{corrections} working-copy record(s) minted by an export say 'verified against master' "
                  "although the item's bytes were not in that export; a correction note "
                  "(evidence_copy_correction) in the custody log says to read them as not verified"),
        ))

    # ── GS-4 — trusted timestamp on the seal (RFC 3161; advisory) ──
    if ev.coc_sealed:
        ts_ok = bool((getattr(ev, "seal_tst_time", None) or "").strip())
        checks.append(_check(
            code="rfc3161_seal_timestamp",
            label="Seal carries an independent trusted timestamp",
            status=("pass" if ts_ok else "manual"),
            severity="advisory",
            note=None if ts_ok else "Server-clock only — configure a TSA (TSA_URL) for an RFC-3161 timestamp at seal (27037 §6.6 / eIDAS)",
        ))

    # ── ISO/IEC 27042 — examination documentation (GS-3; advisory) ──
    # Only applies once the item has been examined (Wizard B is digital-only).
    if is_digital and getattr(ev, "has_examination", False):
        f_ok = bool(getattr(ev, "has_examination_findings", False))
        checks.append(_check(
            code="iso_27042_findings",
            label="Examination findings/interpretation recorded",
            status=("pass" if f_ok else "fail"),
            severity="advisory",
            note=None if f_ok else "Record findings + interpretation in the examination wizard (ISO 27042 item 8)",
        ))
        s_ok = bool(getattr(ev, "has_examination_scope", False))
        checks.append(_check(
            code="iso_27042_scope_limitations",
            label="Examination scope limitations recorded",
            status=("pass" if s_ok else "fail"),
            severity="advisory",
            note=None if s_ok else "Record what was NOT examined / caveats (ISO 27042 item 12)",
        ))

    # ── Roll up ──
    score = "green"
    fail_mand = sum(1 for c in checks if c["status"] == "fail" and c["severity"] == "mandatory")
    fail_adv  = sum(1 for c in checks if c["status"] == "fail" and c["severity"] == "advisory")
    has_manual = any(c["status"] == "manual" for c in checks)
    if fail_mand:
        score = "red"
        summary = f"{fail_mand} mandatory check(s) failing"
    elif fail_adv:
        score = "amber"
        summary = f"{fail_adv} advisory check(s) failing"
    elif has_manual:
        score = "amber"
        summary = "Manual confirmation pending"
    else:
        summary = "All applicable checks pass"

    # Completeness ratio (ISO/IEC 27041 paper rubric): % of determinable checks
    # (pass|fail) that pass. >90% reads as "good".
    determinable = [c for c in checks if c["status"] in ("pass", "fail")]
    passes = sum(1 for c in determinable if c["status"] == "pass")
    completeness = round(100 * passes / len(determinable)) if determinable else 100

    return {"score": score, "checks": checks, "summary": summary, "completeness": completeness}
