"""Readiness v1 checks: is the organisation prepared to handle the next incident?

Each check is one small async function registered with @check(...) in CHECKS (declaration
order = response order). It returns `(status, detail)`, or `(status, detail, overrides)` to
change `level` / `fix_route` for this evaluation. Rules for every check:
  - status is "pass", "fail" or "unknown". "unknown" means the data source is missing (or the
    check raised); it is never reported as a pass.
  - detail carries counts, ages and calendar dates only: never a username, email or host name
    (analysts read this, and it describes security posture). The ADMIN_ONLY_DETAIL checks show
    non-admins their status only.
  - blocking or disk I/O runs in a thread (single uvicorn worker; CLAUDE.md "freeze loop").
  - each check runs in its own SAVEPOINT, so a DB error in one can't abort the others.
Adding a check = one more decorated function; ids are stable API contract, never renamed.
"""
import asyncio
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

import backup.routes as backup_routes
from core.config import settings
from core.security import decrypt_secret
from models import (AuditAnchor, OnCallEntry, OperationalRole, OrgContact, PlatformSetting, PlaybookTemplate,
                    ResponderProfile, StakeholderMatrixRule, ThreatFeed, User, ValidatedTool, utc_today)
from schemas import ENRICHMENT_SERVICES
from settings_api.routes import _db_key as _api_key_row, _env_value as _api_key_env

log = logging.getLogger("fenrir.readiness")

CHECKS: list[tuple[dict, object]] = []

ON_CALL_DAYS = 14
BACKUP_MAX_AGE = timedelta(hours=26)
ANCHOR_MAX_AGE = timedelta(hours=26)
FEED_MAX_AGE = timedelta(hours=24)
PLAYBOOK_MAX_AGE = timedelta(days=365)
# Operational role keys (auth/bootstrap.py SEED_ROLES) every install needs filled.
REQUIRED_ROLE_KEYS = {"incident_commander": "Incident Commander",
                      "communications_lead": "Communications Lead",
                      "legal_liaison": "Legal Liaison"}
# Seeded playbook template keys (playbook/seeds.py).
REQUIRED_PLAYBOOK_KEYS = {"ransomware_containment": "Ransomware", "data_breach_notification": "Data breach"}
# E2. The DPO role key (auth/bootstrap.py SEED_ROLES).
DPO_ROLE_KEY = "data_protection_officer"
# E2. The six external contacts every organisation should have prepared, as StakeholderType values
# (audit P1: lead supervisory authority, national CSIRT, police cyber unit, insurer, IR retainer, PR).
REQUIRED_CONTACT_TYPES = {"supervisory_authority": "Supervisory authority", "csirt": "National CSIRT",
                          "law_enforcement": "Police cyber unit", "insurer": "Insurer",
                          "ir_firm": "IR retainer", "media_pr": "PR"}
CONTACT_MAX_AGE = timedelta(days=90)
# Only these account roles can respond (viewers can't act on an incident), so only their shifts count.
RESPONDER_ROLES = ("admin", "analyst")
# L1: these details name attack targets (how many admins lack a second factor; a possibly tampered
# audit chain). Non-admins get the status and a pointer to an admin instead.
ADMIN_ONLY_DETAIL = frozenset({"admin_totp", "audit_anchor"})
_STATUS_ONLY = {"pass": "Passing", "fail": "Failing", "unknown": "Not checked"}


def check(id: str, title: str, level: str, csf: list[str], fix_route: str):
    def register(fn):
        CHECKS.append(({"id": id, "title": title, "level": level, "csf": csf, "fix_route": fix_route}, fn))
        return fn
    return register


def _plural(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


def _date_runs(days: list) -> str:
    """Sorted dates as "2026-10-06, 2026-10-09 to 2026-10-12": consecutive days collapse into a run."""
    runs = []
    for d in days:
        if runs and (d - runs[-1][1]).days == 1:
            runs[-1][1] = d
        else:
            runs.append([d, d])
    return ", ".join(a.isoformat() if a == b else f"{a.isoformat()} to {b.isoformat()}" for a, b in runs)


def _age(td: timedelta) -> str:
    h = td.total_seconds() / 3600
    if h < 1:
        return f"{max(int(h * 60), 0)} min"
    if h < 48:
        return f"{h:.1f} h"
    return f"{int(h // 24)} days"


@check("admins_active", "At least 2 active admins", "blocker", ["GV.RR-02"], "/settings/users")
async def _admins_active(db: AsyncSession, now: datetime):
    n = (await db.execute(select(func.count()).select_from(User)
                          .where(User.role == "admin", User.is_active.is_(True)))).scalar_one()
    return ("pass" if n >= 2 else "fail"), f"{_plural(n, 'active admin')}; at least 2 are needed so one can cover for the other."


@check("admin_totp", "TOTP enforced and every admin enrolled", "blocker", ["PR.AA-03"], "/settings/users")
async def _admin_totp(db: AsyncSession, now: datetime):
    if not settings.totp_required:
        return "fail", "TOTP is not enforced (TOTP_REQUIRED is off), so accounts can sign in with a password only."
    rows = (await db.execute(select(User.totp_enabled, func.count()).where(User.role == "admin", User.is_active.is_(True))
                             .group_by(User.totp_enabled))).all()
    by = {bool(enrolled): n for enrolled, n in rows}
    missing, total = by.get(False, 0), sum(by.values())
    if missing:
        return "fail", f"TOTP is enforced, but {missing} of {_plural(total, 'active admin')} have not enrolled."
    return "pass", f"TOTP is enforced and all {_plural(total, 'active admin')} are enrolled."


@check("operational_roles", "IC, Comms Lead and Legal Liaison roles active", "blocker", ["GV.RR-02"],
       "/settings/operational-roles")
async def _operational_roles(db: AsyncSession, now: datetime):
    active = {k for (k,) in (await db.execute(select(OperationalRole.key).where(
        OperationalRole.key.in_(REQUIRED_ROLE_KEYS), OperationalRole.is_active.is_(True)))).all()}
    missing = [label for key, label in REQUIRED_ROLE_KEYS.items() if key not in active]
    if missing:
        return "fail", f"Missing or inactive: {', '.join(missing)}."
    return "pass", "Incident Commander, Communications Lead and Legal Liaison are active."


@check("on_call_14d", "Someone on call every day of the next 14", "blocker", ["GV.RR-02"], "/on-call")
async def _on_call(db: AsyncSession, now: datetime):
    first = utc_today()
    last = first + timedelta(days=ON_CALL_DAYS - 1)
    # Only shifts held by an active analyst or admin count: a deactivated user can't be reached in the
    # app, and a viewer can't respond.
    ranges = (await db.execute(select(OnCallEntry.start_date, OnCallEntry.end_date)
                               .join(User, User.id == OnCallEntry.user_id)
                               .where(User.is_active.is_(True), User.role.in_(RESPONDER_ROLES),
                                      OnCallEntry.start_date <= last, OnCallEntry.end_date >= first))).all()
    gaps = [d for d in (first + timedelta(days=i) for i in range(ON_CALL_DAYS))
            if not any(s <= d <= e for s, e in ranges)]
    if gaps:
        return "fail", f"No one on call on {_plural(len(gaps), 'day')} (UTC dates): {_date_runs(gaps)}."
    return "pass", f"Every UTC day from {first.isoformat()} to {last.isoformat()} has an active on-call responder."


@check("matrix_high_critical", "Stakeholder matrix has required rules for High and Critical", "blocker",
       ["RS.CO-02"], "/settings/stakeholder-matrix")
async def _matrix(db: AsyncSession, now: datetime):
    rows = dict((await db.execute(select(StakeholderMatrixRule.severity, func.count())
                                  .where(StakeholderMatrixRule.required.is_(True),
                                         StakeholderMatrixRule.severity.in_(("high", "critical")))
                                  .group_by(StakeholderMatrixRule.severity))).all())
    counts = f"High {rows.get('high', 0)}, Critical {rows.get('critical', 0)} required rule(s)"
    missing = [s.capitalize() for s in ("high", "critical") if not rows.get(s)]
    if missing:
        return "fail", f"No required notification rule for {' or '.join(missing)} ({counts})."
    return "pass", f"{counts}."


@check("playbooks_core", "Ransomware and Data-breach playbooks reviewed within 12 months", "warning", ["ID.IM-04"],
       "/playbooks")
async def _playbooks(db: AsyncSession, now: datetime):
    have = dict((await db.execute(select(PlaybookTemplate.key, PlaybookTemplate.updated_at)
                                  .where(PlaybookTemplate.key.in_(REQUIRED_PLAYBOOK_KEYS)))).all())
    problems, ages = [], []
    for key, label in REQUIRED_PLAYBOOK_KEYS.items():
        updated = have.get(key)
        if updated is None:
            problems.append(f"{label} playbook (template key {key}) is missing")
        elif now - updated > PLAYBOOK_MAX_AGE:
            problems.append(f"{label} playbook last updated {_age(now - updated)} ago")
        else:
            ages.append(f"{label} updated {_age(now - updated)} ago")
    if problems:
        return "fail", "; ".join(problems) + " (review within 12 months)."
    return "pass", "; ".join(ages) + "."


@check("threat_intel", "Threat-intel keys configured and feeds pulled within 24 h", "warning", ["ID.RA-02"],
       "/settings/threat-intel")
async def _threat_intel(db: AsyncSession, now: datetime):
    db_keys = {k for (k,) in (await db.execute(select(PlatformSetting.key).where(
        PlatformSetting.key.in_([_api_key_row(s) for s in ENRICHMENT_SERVICES])))).all()}
    keys = sum(1 for s in ENRICHMENT_SERVICES if _api_key_row(s) in db_keys or _api_key_env(s))
    pulled = [p for (p,) in (await db.execute(select(ThreatFeed.last_pulled_at)
                                              .where(ThreatFeed.enabled.is_(True)))).all()]
    never = sum(1 for p in pulled if p is None)
    stale = sum(1 for p in pulled if p is not None and now - p > FEED_MAX_AGE)
    detail = f"{keys} of {len(ENRICHMENT_SERVICES)} enrichment API keys configured; {_plural(len(pulled), 'enabled feed')}"
    if stale + never:
        detail += f", {stale + never} not pulled in the last 24 h" + (f" ({never} never pulled)" if never else "")
    detail += "."
    if keys == 0:
        return "fail", detail, {"fix_route": "/settings/api-keys"}
    if not pulled or stale or never:
        return "fail", detail
    return "pass", detail


@check("smtp", "Email (SMTP or Microsoft Graph) configured", "warning", [], "/settings/integrations")
async def _smtp(db: AsyncSession, now: datetime):
    keys = ("smtp.mode", "smtp.host", "graph.tenant_id", "graph.client_id", "graph.client_secret", "graph.sender")
    vals = {}
    for row in (await db.execute(select(PlatformSetting).where(PlatformSetting.key.in_(keys)))).scalars():
        try:
            vals[row.key] = decrypt_secret(row.encrypted_value)
        except Exception:      # unreadable = not configured, as mailer.service treats it
            vals[row.key] = ""
    mode = vals.get("smtp.mode") or ""
    if mode == "smtp":
        return ("pass", "SMTP mode; host set.") if vals.get("smtp.host") else ("fail", "SMTP mode, but no host is set.")
    if mode == "graph":
        missing = [k.split(".", 1)[1] for k in keys[2:] if not vals.get(k)]
        return ("fail", f"Microsoft Graph mode, but missing: {', '.join(missing)}.") if missing \
            else ("pass", "Microsoft Graph mode; tenant, app and sender set.")
    return "fail", "Email is off, so admin alerts can't be sent by email."


@check("validated_tools", "At least one active validated tool", "warning", ["ISO/IEC 27041"], "/settings/validated-tools")
async def _validated_tools(db: AsyncSession, now: datetime):
    n = (await db.execute(select(func.count()).select_from(ValidatedTool)
                          .where(ValidatedTool.is_active.is_(True)))).scalar_one()
    return ("pass" if n else "fail"), f"{_plural(n, 'active validated tool')}."


def _backup_listing():
    """Thread: the backup directory listing (stat per file). None when the volume is not mounted."""
    if not Path(settings.backup_path).is_dir():
        return None
    return backup_routes._list_backups()


@check("backup_recent", "Backup under 26 h old and not failing", "blocker", ["PR.DS-11"], "/admin/backup")
async def _backup(db: AsyncSession, now: datetime):
    """Also fails, at warning level, when the newest backup is fresh but not age-encrypted: backups
    must be encrypted at rest (CLAUDE.md), but a plaintext backup still restores."""
    files = await asyncio.to_thread(_backup_listing)
    if files is None:
        return "unknown", "The backup directory is not available to the backend, so backups can't be checked."
    last = backup_routes._last_run_model()
    newest = (datetime.strptime(files[0].created_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
              if files else None)
    if last.state == "error":
        failed = datetime.strptime(last.finished_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc) \
            if last.finished_at else now
        if newest is None or newest <= failed:     # a later successful backup supersedes the failure
            return "fail", f"The last manual backup run failed {_age(now - failed)} ago: {last.error or 'see server logs'}"
    if newest is None:
        return "fail", "No backup file found."
    age = now - newest
    plaintext = "" if files[0].filename.endswith(".age") else (
        " It is NOT encrypted (no .age): backups must be encrypted at rest; set BACKUP_AGE_RECIPIENT.")
    if age > BACKUP_MAX_AGE:
        return "fail", f"Newest backup is {_age(age)} old (limit 26 h).{plaintext}"
    if plaintext:
        return "fail", f"Newest backup is {_age(age)} old.{plaintext}", {"level": "warning"}
    return "pass", f"Newest backup is {_age(age)} old and age-encrypted; {_plural(len(files), 'backup file')} kept."


@check("audit_anchor", "Audit-chain anchor verified within 26 h", "blocker", ["PR.PS-04"], "/admin/audit-log")
async def _audit_anchor(db: AsyncSession, now: datetime):
    """Reads the audit-monitor's latest anchor (no re-verification here). A failed verification is a
    blocker; a missing or stale anchor is a warning (the sidecar may simply be down)."""
    a = (await db.execute(select(AuditAnchor.anchored_at, AuditAnchor.verify_ok)
                          .order_by(AuditAnchor.anchored_at.desc(), AuditAnchor.id.desc()).limit(1))).first()
    if a is None:
        return "fail", "No audit-chain anchor recorded yet: is the audit-monitor running?", {"level": "warning"}
    age = now - a.anchored_at
    if not a.verify_ok:
        return "fail", (f"The latest anchor ({_age(age)} ago) found the audit chain broken. "
                        "Treat it as possible tampering; see the audit-monitor log.")
    if age > ANCHOR_MAX_AGE:
        return "fail", f"Latest anchor is {_age(age)} old (limit 26 h): is the audit-monitor running?", {"level": "warning"}
    return "pass", f"Latest anchor {_age(age)} ago; the audit chain verified."


# ── E2: preparation data (appended, so the v1 order is unchanged) ──

def _entries(n: int) -> str:
    return f"{n} {'entry' if n == 1 else 'entries'}"


@check("dpo_role", "Data Protection Officer role active", "blocker", ["GV.RR-02", "GV.OC-03"],
       "/settings/operational-roles")
async def _dpo_role(db: AsyncSession, now: datetime):
    active = (await db.execute(select(OperationalRole.is_active)
                               .where(OperationalRole.key == DPO_ROLE_KEY))).scalar_one_or_none()
    if active is None:
        return "fail", f"No Data Protection Officer role (key {DPO_ROLE_KEY}); a backend restart re-seeds it."
    if not active:
        return "fail", "The Data Protection Officer role is inactive."
    return "pass", "The Data Protection Officer role is active."


@check("on_call_oob", "Everyone on call in the next 14 days has an out-of-band contact", "blocker", ["RS.CO-02"],
       "/roster")
async def _on_call_oob(db: AsyncSession, now: datetime):
    first = utc_today()
    last = first + timedelta(days=ON_CALL_DAYS - 1)
    rows = (await db.execute(select(OnCallEntry.user_id, OnCallEntry.start_date, OnCallEntry.end_date,
                                    ResponderProfile.oob_contact_methods)
                             .join(User, User.id == OnCallEntry.user_id)
                             .outerjoin(ResponderProfile, ResponderProfile.user_id == OnCallEntry.user_id)
                             .where(User.is_active.is_(True), User.role.in_(RESPONDER_ROLES),
                                    OnCallEntry.start_date <= last, OnCallEntry.end_date >= first))).all()
    if not rows:
        return "fail", "No one is on call in the next 14 days, so no out-of-band contact can be checked."
    has_oob = {r.user_id: bool(r.oob_contact_methods) for r in rows}
    missing = [u for u, ok in has_oob.items() if not ok]
    if missing:
        days = sorted({first + timedelta(days=i) for r in rows if r.user_id in missing for i in range(ON_CALL_DAYS)
                       if r.start_date <= first + timedelta(days=i) <= r.end_date})
        return "fail", (f"{len(missing)} of {_plural(len(has_oob), 'responder')} on call in the next 14 days "
                        f"{'has' if len(missing) == 1 else 'have'} no out-of-band contact; on call on (UTC dates): "
                        f"{_date_runs(days)}.")
    n = len(has_oob)
    return "pass", (f"All {n} responders on call in the next 14 days have an out-of-band contact." if n > 1
                    else "The 1 responder on call in the next 14 days has an out-of-band contact.")


@check("contacts_directory", "Contacts directory lists the six key contacts, verified within 90 days", "warning",
       ["RS.CO-03"], "/contacts")
async def _contacts_directory(db: AsyncSession, now: datetime):
    rows = (await db.execute(select(OrgContact.type, OrgContact.last_verified_at)
                             .where(OrgContact.type.in_(REQUIRED_CONTACT_TYPES)))).all()
    missing = [label for t, label in REQUIRED_CONTACT_TYPES.items() if not any(r.type == t for r in rows)]
    never = sum(1 for r in rows if r.last_verified_at is None)
    stale = sum(1 for r in rows if r.last_verified_at is not None and now - r.last_verified_at > CONTACT_MAX_AGE)
    problems = []
    if missing:
        problems.append(f"Missing: {', '.join(missing)}")
    if never or stale:
        problems.append(f"{never + stale} of {_entries(len(rows))} of these types not verified in the last "
                        f"90 days" + (f" ({never} never verified)" if never else ""))
    if problems:
        return "fail", "; ".join(problems) + "."
    oldest = min(r.last_verified_at for r in rows)
    return "pass", f"All six types listed ({_entries(len(rows))}); the oldest verification is {_age(now - oldest)} old."


async def evaluate(db: AsyncSession, is_admin: bool) -> dict:
    """Run every check now. One failing check never hides the others: it reports `unknown`, and its
    SAVEPOINT is rolled back so a DB error doesn't leave the session aborted for the checks after it.
    Non-admins get only the status of the ADMIN_ONLY_DETAIL checks."""
    now = datetime.now(timezone.utc).replace(microsecond=0)
    out = []
    for meta, fn in CHECKS:
        try:
            async with db.begin_nested():
                res = await fn(db, now)
        except Exception:                                  # noqa: BLE001 — report, never fake a pass
            log.exception("readiness check %s failed", meta["id"])
            res = ("unknown", "The check could not run (see server logs).")
        status, detail, over = (*res, {}) if len(res) == 2 else res
        if not is_admin and meta["id"] in ADMIN_ONLY_DETAIL:
            detail = f"{_STATUS_ONLY[status]}; an admin has details."
        out.append({**meta, **over, "status": status, "detail": detail})
    return {
        "generated_at": now,
        "summary": {
            "blockers_failing": sum(c["status"] == "fail" and c["level"] == "blocker" for c in out),
            "warnings_failing": sum(c["status"] == "fail" and c["level"] == "warning" for c in out),
            "unknown": sum(c["status"] == "unknown" for c in out),
        },
        "checks": out,
    }
