"""MITRE ATT&CK threat-actor sync.

Pulls the Enterprise ATT&CK STIX bundle from the official MITRE CTI repo and
upserts `intrusion-set` records into the `threat_actors` table. Analyst-
created actors (`is_system=False`) are never touched.

Pattern follows lolbins/service.py: an `async sync()` guarded by an asyncio
lock, with `ensure_loaded()` that **awaits** the sync on first call (matching
the post-2026-05-17 fix) instead of firing-and-forgetting.

The bundle is large (~30MB JSON, ~150 groups, ~600 techniques, ~700 software
items) but parses quickly. A 7-day TTL is fine — ATT&CK ships ~quarterly.
"""
from __future__ import annotations

import asyncio
import logging
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

import httpx
from sqlalchemy.dialects.postgresql import insert as pg_insert

from core.database import SessionLocal
from models import ThreatActor

_log = logging.getLogger("fenrir.threat_actors")

SYNC_INTERVAL = 7 * 86_400   # 7 days
_last_sync: float = 0.0
_sync_lock = asyncio.Lock()

STIX_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master"
    "/enterprise-attack/enterprise-attack.json"
)
_USER_AGENT = "DFIR-FENRIR/2.0 (security research platform)"


# Map MITRE STIX motivation hints onto our enum. STIX itself doesn't carry a
# motivation field on intrusion-set; we infer from group descriptions where we
# can, otherwise fall back to "unknown".
_MOTIVATION_HINTS = [
    ("ransomware",        "ransomware"),
    ("financial",         "financial"),
    ("financially motiv", "financial"),
    ("espionage",         "espionage"),
    ("state-sponsor",     "espionage"),
    ("hacktiv",           "hacktivist"),
    ("destruct",          "destructive"),
    ("wiper",             "destructive"),
]


def _infer_motivation(description: str) -> str:
    desc = (description or "").lower()
    for needle, motivation in _MOTIVATION_HINTS:
        if needle in desc:
            return motivation
    return "unknown"


def _stix_ref(obj: dict, source: str) -> dict | None:
    for r in (obj.get("external_references") or []):
        if r.get("source_name") == source:
            return r
    return None


def _parse_bundle(bundle: dict) -> list[dict]:
    """Walk the STIX bundle once, build technique + software lookup tables,
    then walk relationship objects to attach those to each intrusion-set.

    Returns a list of `{mitre_id, name, aliases, description, motivation,
    associated_techniques, software, mitre_url}` dicts ready for upsert.
    """
    objects = bundle.get("objects") or []

    # ── First pass: build STIX-id → minimal info maps for techniques + software.
    techniques_by_stix: dict[str, dict] = {}
    software_by_stix:   dict[str, dict] = {}

    for obj in objects:
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        otype = obj.get("type")
        if otype == "attack-pattern":
            ref = _stix_ref(obj, "mitre-attack")
            if not ref or not ref.get("external_id"):
                continue
            techniques_by_stix[obj["id"]] = {
                "id":   ref["external_id"],
                "name": obj.get("name", ""),
            }
        elif otype in ("malware", "tool"):
            ref = _stix_ref(obj, "mitre-attack")
            software_by_stix[obj["id"]] = {
                "name":     obj.get("name", ""),
                "type":     "malware" if otype == "malware" else "tool",
                "mitre_id": ref["external_id"] if ref else None,
            }

    # ── Index intrusion-sets so we can attach edges as we walk relationships.
    actors_by_stix: dict[str, dict] = {}
    for obj in objects:
        if obj.get("type") != "intrusion-set":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        ref = _stix_ref(obj, "mitre-attack")
        if not ref or not ref.get("external_id"):
            continue
        actors_by_stix[obj["id"]] = {
            "mitre_id":              ref["external_id"],
            "mitre_url":             ref.get("url", ""),
            "name":                  obj.get("name", ""),
            "aliases":               obj.get("aliases", []),
            "description":           obj.get("description", ""),
            "motivation":            _infer_motivation(obj.get("description", "")),
            "associated_techniques": [],
            "software":              [],
            "_seen_tech":            set(),   # local dedup helper
            "_seen_sw":              set(),
        }

    # ── Walk `relationship` objects with type 'uses'. STIX puts the actor on
    # source_ref, and either an attack-pattern or malware/tool on target_ref.
    for obj in objects:
        if obj.get("type") != "relationship" or obj.get("relationship_type") != "uses":
            continue
        src = obj.get("source_ref"); tgt = obj.get("target_ref")
        actor = actors_by_stix.get(src)
        if actor is None:
            continue
        if tgt in techniques_by_stix:
            tid = techniques_by_stix[tgt]["id"]
            if tid not in actor["_seen_tech"]:
                actor["_seen_tech"].add(tid)
                actor["associated_techniques"].append(tid)
        elif tgt in software_by_stix:
            sw = software_by_stix[tgt]
            key = sw["mitre_id"] or sw["name"]
            if key and key not in actor["_seen_sw"]:
                actor["_seen_sw"].add(key)
                actor["software"].append(sw)

    # Strip the temporary dedup helpers before returning.
    out = []
    for a in actors_by_stix.values():
        a.pop("_seen_tech", None)
        a.pop("_seen_sw", None)
        out.append(a)
    return out


# ── Public sync API ──────────────────────────────────────────────────────────

async def _fetch_bundle() -> dict:
    async with httpx.AsyncClient(
        headers={"User-Agent": _USER_AGENT},
        follow_redirects=True,
        timeout=httpx.Timeout(120.0),    # bundle is ~30MB; allow generous time
    ) as c:
        r = await c.get(STIX_URL)
        r.raise_for_status()
        return r.json()


async def sync(*, force: bool = False) -> int:
    """Run the sync. Returns the number of actors upserted.

    Uses its own `SessionLocal` session — independent of any web-request
    `Depends(get_db)` so this works the same whether called from a route or
    a background task.
    """
    global _last_sync
    async with _sync_lock:
        if not force and time.time() - _last_sync < SYNC_INTERVAL:
            return 0

        _log.info("threat_actors: starting MITRE ATT&CK sync …")
        try:
            bundle = await _fetch_bundle()
        except Exception as exc:
            _log.warning("threat_actors: bundle fetch failed: %s", exc)
            return 0

        parsed = _parse_bundle(bundle)
        if not parsed:
            _log.warning("threat_actors: bundle parsed empty — STIX schema change?")
            return 0

        now = datetime.now(timezone.utc)
        upserts = 0
        async with SessionLocal() as session:
            for actor_data in parsed:
                stmt = pg_insert(ThreatActor).values(
                    name=actor_data["name"],
                    aliases=actor_data["aliases"],
                    description=actor_data["description"],
                    motivation=actor_data["motivation"],
                    associated_techniques=actor_data["associated_techniques"],
                    software=actor_data["software"],
                    is_system=True,
                    mitre_id=actor_data["mitre_id"],
                    mitre_url=actor_data["mitre_url"],
                    last_synced_at=now,
                )
                # Upsert keyed on mitre_id so the catalogue stays stable across
                # rename/alias updates. We deliberately do NOT touch
                # is_system=False rows (they're analyst-created).
                stmt = stmt.on_conflict_do_update(
                    index_elements=["mitre_id"],
                    set_={
                        "name":                  stmt.excluded.name,
                        "aliases":               stmt.excluded.aliases,
                        "description":           stmt.excluded.description,
                        "motivation":            stmt.excluded.motivation,
                        "associated_techniques": stmt.excluded.associated_techniques,
                        "software":              stmt.excluded.software,
                        "mitre_url":             stmt.excluded.mitre_url,
                        "last_synced_at":        stmt.excluded.last_synced_at,
                    },
                    where=ThreatActor.is_system == True,  # noqa: E712
                )
                await session.execute(stmt)
                upserts += 1
            await session.commit()

        _last_sync = time.time()
        _log.info("threat_actors: sync complete — %d actors upserted", upserts)
        return upserts


async def ensure_loaded() -> None:
    """Awaits the sync if we've never run it. Subsequent calls within the TTL
    are no-ops thanks to the `_last_sync` guard inside `sync()`."""
    if _last_sync > 0:
        return
    await sync()


def status() -> dict:
    return {
        "last_sync":      _last_sync,
        "synced":         _last_sync > 0,
        "sync_interval":  SYNC_INTERVAL,
    }
