"""K5 (R41, R49): one-off admin fix for legacy rows. DRY RUN by default; never deletes anything.

    python -m legal.fix_legacy_rows                                   DRY RUN (read-only): list every row it would change
    python -m legal.fix_legacy_rows --apply --operator <username>     change them; one audit record per row

Runs in the backend container (the app's DML-only DB role). --operator must be an active admin; the audit
records carry that user. --apply runs in ONE transaction with the rows locked: any error changes nothing.

1. duplicates  Re-initialising Legal before B4 created built-in template deadlines twice. Per incident and
               template (regulation, article, obligation) the OLDEST row is kept; every other row still open
               (pending / in_progress) is waived with completion_notes "duplicate (pre-B4 re-init)". Completed
               and waived rows are not touched. Audit: legal_deadline_update (status waived, reason).
2. nis2_final  NIS2 final reports created before B4 run 720 h from their anchor, and a 72h notification completed
               before B4 never re-anchored them. Owner decision 2026-10-06: OPEN rows only are re-anchored to the
               72h incident notification: its completion time when that row is completed (as the API does since
               B4), else the row's own anchor, the deadline being one calendar month later (Art. 23(4)(d)).
               Skipped: rows already on that rule, rows ever re-anchored (an analyst's or the API's re-anchor
               wins: any legal_deadline_reanchor audit record for the row) and rows waived by step 1.
               reminder_stage is set to the stage already reached at the new due time, so the fix sends no
               catch-up reminders. Audit: legal_deadline_reanchor (old/new).
3. seed_dc     The demo seed split "Domain Controllers (DC01, DC02)" into the entities "Domain Controllers (DC01"
               and "DC02)". Each is renamed in place (value and name) to "Domain Controller (DC01)" /
               "Domain Controller (DC02)": id, compromised flag, links and asset log are kept. Skipped when the
               corrected value already exists in that incident. Audit: entity_update (changes from/to).

Idempotent: a second run finds nothing to change. Exit codes: 0 done (or nothing to do), 1 an argument / operator
problem, 2 the dry run found rows to change (so a scheduler notices).
"""
from __future__ import annotations

import argparse
import asyncio
import sys
from datetime import datetime, timezone

from sqlalchemy import select

from audit.service import write_audit
from core.database import SessionLocal
from legal.reminders import target_stage
from legal.routes import _NIS2_FINAL, _NIS2_NOTIFICATION, _OPEN_STATUSES, _TEMPLATES_BY_KEY, _iso, _key, _window
from models import AuditLog, Entity, Incident, RegulatoryDeadline, User

TOOL = "legal.fix_legacy_rows"
DUP_NOTE = "duplicate (pre-B4 re-init)"
NIS2_REASON = ("NIS2 Art. 23(4)(d): final report due one month after the incident notification "
               "(legacy 720 h row re-anchored; owner decision 2026-10-06)")
DC_FIXES = {"Domain Controllers (DC01": "Domain Controller (DC01)", "DC02)": "Domain Controller (DC02)"}


def _z(dt) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if dt else "-"


async def plan(db, lock: bool = False) -> dict:
    """What would change, read in `db` (rows locked FOR UPDATE when `lock`)."""
    def q(stmt):
        return stmt.with_for_update() if lock else stmt

    rows = (await db.execute(q(
        select(RegulatoryDeadline).order_by(RegulatoryDeadline.created_at, RegulatoryDeadline.id)
    ).execution_options(populate_existing=True))).scalars().all()
    refs = dict((await db.execute(select(Incident.id, Incident.ref))).all())

    # 1. duplicates of a built-in template: keep the oldest, waive the other open ones
    groups: dict = {}
    for d in rows:
        if _key(d) in _TEMPLATES_BY_KEY:
            groups.setdefault((d.incident_id, *_key(d)), []).append(d)
    dups = [d for g in groups.values() if len(g) > 1 for d in g[1:] if d.status in _OPEN_STATUSES]
    waived = {d.id for d in dups}

    # 2. open NIS2 final reports not on the one-month rule
    notified: dict = {}
    for d in rows:
        if _key(d) == _NIS2_NOTIFICATION and d.status == "completed" and d.completed_at:
            prev = notified.get(d.incident_id)
            notified[d.incident_id] = d.completed_at if prev is None else min(prev, d.completed_at)
    tmpl = _TEMPLATES_BY_KEY[_NIS2_FINAL]
    finals = [d for d in rows if _key(d) == _NIS2_FINAL and d.status in _OPEN_STATUSES and d.id not in waived]
    reanchored = set((await db.execute(select(AuditLog.details["deadline_id"].as_string()).where(
        AuditLog.action == "legal_deadline_reanchor",
        AuditLog.details["deadline_id"].as_string().in_([str(d.id) for d in finals])))).scalars().all()) if finals else set()
    nis2 = []
    for d in finals:
        if str(d.id) in reanchored:
            continue
        anchor = notified.get(d.incident_id) or d.breach_detected_at
        due, hours = _window(anchor, tmpl["deadline_hours"], tmpl["deadline_months"])
        if d.breach_detected_at != anchor or d.deadline_at != due or d.deadline_hours != hours:
            nis2.append((d, anchor, due, hours, "notification completed" if d.incident_id in notified else "own anchor"))

    # 3. the seed's split Domain Controllers entities
    ents = (await db.execute(q(select(Entity).where(Entity.value.in_(tuple(DC_FIXES)))))).scalars().all()
    taken = set((await db.execute(select(Entity.incident_id, Entity.type, Entity.value).where(
        Entity.value.in_(tuple(DC_FIXES.values()))))).all())
    dc = [(e, DC_FIXES[e.value]) for e in ents if (e.incident_id, e.type, DC_FIXES[e.value]) not in taken]
    dc_skipped = [e for e in ents if (e.incident_id, e.type, DC_FIXES[e.value]) in taken]
    return {"dups": dups, "nis2": nis2, "dc": dc, "dc_skipped": dc_skipped, "refs": refs}


def report(p: dict, apply: bool) -> None:
    verb = "WAIVED" if apply else "would waive"
    ref = lambda iid: p["refs"].get(iid) or str(iid)   # noqa: E731
    print(f"== 1. duplicates: {len(p['dups'])} open duplicate deadline(s) {verb} ==")
    for d in p["dups"]:
        print(f"  {ref(d.incident_id)}  deadline {d.id}  {d.regulation} | {d.article} | status {d.status} "
              f"| created {_z(d.created_at)}  ->  waived, notes '{DUP_NOTE}'")
    verb = "RE-ANCHORED" if apply else "would re-anchor"
    print(f"== 2. nis2_final: {len(p['nis2'])} open NIS2 final report(s) {verb} ==")
    for d, anchor, due, hours, why in p["nis2"]:
        print(f"  {ref(d.incident_id)}  deadline {d.id}  status {d.status}  anchor {_z(d.breach_detected_at)} -> "
              f"{_z(anchor)} ({why})  due {_z(d.deadline_at)} ({d.deadline_hours} h) -> {_z(due)} ({hours} h)")
    verb = "RENAMED" if apply else "would rename"
    print(f"== 3. seed_dc: {len(p['dc'])} split Domain Controllers entit(y/ies) {verb} ==")
    for e, new in p["dc"]:
        print(f"  {ref(e.incident_id)}  entity {e.id}  {e.type} '{e.value}' -> '{new}'"
              f"  (compromised={e.compromised})")
    for e in p["dc_skipped"]:
        print(f"  SKIPPED {ref(e.incident_id)}  entity {e.id}  '{e.value}': '{DC_FIXES[e.value]}' already exists")


async def apply_plan(db, p: dict, op: User, now: datetime) -> int:
    audit = dict(user_id=op.id, username=op.username, role_at_time=op.role, outcome="success",
                 resource_type="incident", request_method="CLI", request_path=f"{TOOL} --apply")
    n = 0
    for d in p["dups"]:
        old = d.status
        d.status, d.completion_notes = "waived", DUP_NOTE
        await write_audit(db, "legal_deadline_update", resource_id=str(d.incident_id), **audit,
                          details={"incident_id": str(d.incident_id), "deadline_id": str(d.id),
                                   "regulation": d.regulation, "article": d.article, "status": "waived",
                                   "old_status": old, "reason": DUP_NOTE, "tool": TOOL})
        n += 1
    for d, anchor, due, hours, why in p["nis2"]:
        change = {"old_anchor": _iso(d.breach_detected_at), "old_deadline_at": _iso(d.deadline_at),
                  "old_deadline_hours": d.deadline_hours}
        d.breach_detected_at, d.deadline_at, d.deadline_hours = anchor, due, hours
        d.reminder_stage = target_stage(due, now)
        await write_audit(db, "legal_deadline_reanchor", resource_id=str(d.incident_id), **audit,
                          details={"incident_id": str(d.incident_id), "deadline_id": str(d.id),
                                   "regulation": d.regulation, "article": d.article, "auto": False,
                                   "reason": NIS2_REASON, "anchor_source": why, **change,
                                   "new_anchor": _iso(anchor), "new_deadline_at": _iso(due),
                                   "new_deadline_hours": hours, "reminder_stage": d.reminder_stage,
                                   "tool": TOOL})
        n += 1
    for e, new in p["dc"]:
        changes = {"value": {"from": e.value, "to": new}, "name": {"from": e.name, "to": new}}
        e.value = e.name = new
        await write_audit(db, "entity_update", resource_id=str(e.incident_id), **audit,
                          details={"incident_id": str(e.incident_id), "entity_id": str(e.id), "changes": changes,
                                   "reason": "demo seed split 'Domain Controllers (DC01, DC02)' into two "
                                             "entities (K5/R49)", "tool": TOOL})
        n += 1
    return n


async def main(apply: bool, operator: str | None) -> int:
    async with SessionLocal() as db:
        async with db.begin():
            op = None
            if apply:
                op = (await db.execute(select(User).where(User.username == operator))).scalar_one_or_none()
                if op is None or not op.is_active or op.role != "admin":
                    print(f"--operator {operator!r}: not an active admin user; nothing changed", file=sys.stderr)
                    return 1
            p = await plan(db, lock=apply)
            report(p, apply)
            total = len(p["dups"]) + len(p["nis2"]) + len(p["dc"])
            if not apply:
                print(f"DRY RUN: {total} row(s) would change. Run with --apply --operator <admin username>.")
                return 2 if total else 0
            n = await apply_plan(db, p, op, datetime.now(timezone.utc))
        print(f"APPLIED: {n} row(s) changed, {n} audit record(s) written (operator {op.username}).")
        return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser(prog=f"python -m {TOOL}", description=__doc__.split("\n")[0])
    ap.add_argument("--apply", action="store_true", help="change the rows (default: dry run)")
    ap.add_argument("--operator", help="username of the active admin the audit records name (required with --apply)")
    a = ap.parse_args()
    if a.apply and not a.operator:
        ap.error("--apply needs --operator <username>")
    sys.exit(asyncio.run(main(a.apply, a.operator)))
