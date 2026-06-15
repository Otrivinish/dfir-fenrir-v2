"""LOLBins reference service — Windows LOLBAS + Linux GTFOBins.

In-memory cache synced from upstream on first request, then refreshed every 24h.
Sources:
  LOLBAS   → https://lolbas-project.github.io/api/lolbas.json
  GTFOBins → https://codeload.github.com/GTFOBins/GTFOBins.github.io/tar.gz/refs/heads/master
"""
import asyncio
import io
import logging
import re
import tarfile
import time
from typing import Optional

import httpx
import yaml

_log = logging.getLogger("fenrir.lolbins")

_cache: dict[str, dict] = {}
_last_sync: float = 0.0
_sync_lock = asyncio.Lock()

SYNC_INTERVAL = 86400  # 24 h
_USER_AGENT = "DFIR-FENRIR/2.0 (security research platform)"


# ── Normalisation ─────────────────────────────────────────────────────────────

def _norm(name: str) -> str:
    n = name.strip().lower()
    n = n.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    return re.sub(r"\.exe$", "", n)


def _parse_lolbas(entry: dict) -> dict:
    name = _norm(entry.get("Name", ""))
    techniques = []
    for cmd in entry.get("Commands") or []:
        mitre = [cmd["MitreID"]] if cmd.get("MitreID") else []
        techniques.append({
            "type":        cmd.get("Category", ""),
            "command":     (cmd.get("Command") or "")[:800],
            "description": cmd.get("Description", ""),
            "usecase":     cmd.get("Usecase", ""),
            "mitre":       mitre,
            "privileges":  cmd.get("Privileges", ""),
            "detect":      cmd.get("Detect", ""),
        })
    return {
        "name":        name,
        "full_name":   entry.get("Name", ""),
        "platform":    "windows",
        "description": entry.get("Description", ""),
        "techniques":  techniques,
        "paths":       [p.get("Path", "") for p in (entry.get("Full_Path") or [])],
        "source":      "lolbas",
    }


def _parse_gtfobins(content: str, filename: str) -> Optional[dict]:
    try:
        if not content.startswith("---"):
            return None
        m = re.search(r'\n(---|\.\.\.)[ \t]*(\n|$)', content[3:])
        yaml_body = content[3: 3 + m.start()] if m else content[3:]
        data = yaml.safe_load(yaml_body.strip())
        if not data:
            return None
        name = filename[:-3] if filename.endswith(".md") else filename
        techniques = []
        for func_type, func_list in (data.get("functions") or {}).items():
            for func in (func_list or []):
                cmd = func.get("command") or func.get("code") or ""
                techniques.append({
                    "type":        func_type,
                    "command":     str(cmd)[:800],
                    "description": func.get("description", ""),
                    "usecase":     func_type,
                    "mitre":       [],
                    "privileges":  "",
                    "detect":      str(func.get("limitations", "")),
                })
        return {
            "name":        name,
            "full_name":   name,
            "platform":    "linux",
            "description": (data.get("description") or "").strip(),
            "techniques":  techniques,
            "paths":       [],
            "source":      "gtfobins",
        }
    except Exception as exc:
        _log.debug("GTFOBins parse error %s: %s", filename, exc)
        return None


# ── Sync ──────────────────────────────────────────────────────────────────────

async def _sync_lolbas(client: httpx.AsyncClient) -> int:
    try:
        r = await client.get("https://lolbas-project.github.io/api/lolbas.json", timeout=30)
        r.raise_for_status()
        count = 0
        for entry in r.json():
            parsed = _parse_lolbas(entry)
            if parsed["name"]:
                _cache[parsed["name"]] = parsed
                count += 1
        return count
    except Exception as exc:
        _log.warning("LOLBAS sync failed: %s", exc)
        return 0


async def _sync_gtfobins(client: httpx.AsyncClient) -> int:
    try:
        r = await client.get(
            "https://codeload.github.com/GTFOBins/GTFOBins.github.io/tar.gz/refs/heads/master",
            timeout=120,
        )
        r.raise_for_status()
        count = 0
        with tarfile.open(fileobj=io.BytesIO(r.content), mode="r:gz") as tar:
            for member in tar.getmembers():
                if "/_gtfobins/" not in member.name or member.isdir():
                    continue
                f = tar.extractfile(member)
                if f is None:
                    continue
                content = f.read().decode("utf-8", errors="replace")
                filename = member.name.rsplit("/", 1)[-1]
                entry = _parse_gtfobins(content, filename)
                if entry and entry["name"]:
                    _cache[entry["name"]] = entry
                    count += 1
        return count
    except Exception as exc:
        _log.warning("GTFOBins sync failed: %s", exc)
        return 0


async def sync(force: bool = False) -> None:
    global _last_sync
    async with _sync_lock:
        if not force and time.time() - _last_sync < SYNC_INTERVAL:
            return
        _log.info("LOLBins: starting sync…")
        async with httpx.AsyncClient(
            headers={"User-Agent": _USER_AGENT},
            follow_redirects=True,
        ) as client:
            lolbas_n, gtfo_n = await asyncio.gather(
                _sync_lolbas(client), _sync_gtfobins(client)
            )
        _last_sync = time.time()
        _log.info("LOLBins: sync complete — %d LOLBAS + %d GTFOBins", lolbas_n, gtfo_n)


async def ensure_loaded() -> None:
    if not _cache:
        await sync()


# ── Query API ─────────────────────────────────────────────────────────────────

def lookup(name: str) -> Optional[dict]:
    return _cache.get(_norm(name))


_BINARY_RE = re.compile(r"\b([\w][\w.-]{1,30}(?:\.exe)?)\b")


def lookup_in_text(text: str) -> list[dict]:
    results, seen = [], set()
    for m in _BINARY_RE.finditer(text.lower()):
        key = _norm(m.group(1))
        if key and key not in seen and key in _cache:
            seen.add(key)
            results.append(_cache[key])
    return results


def search(q: str, platform: Optional[str] = None) -> list[dict]:
    q = q.lower()
    matches = []
    for entry in _cache.values():
        if platform and entry["platform"] != platform:
            continue
        if (q in entry["name"]
                or q in entry["description"].lower()
                or any(
                    q in t.get("type", "").lower() or q in t.get("description", "").lower()
                    for t in entry["techniques"]
                )):
            matches.append(entry)
    return sorted(matches, key=lambda x: x["name"])[:100]


def get_all(platform: Optional[str] = None) -> list[dict]:
    items = [v for v in _cache.values() if not platform or v["platform"] == platform]
    return sorted(items, key=lambda x: (x["platform"], x["name"]))


def status() -> dict:
    windows = sum(1 for v in _cache.values() if v["platform"] == "windows")
    linux   = sum(1 for v in _cache.values() if v["platform"] == "linux")
    return {
        "total":     len(_cache),
        "windows":   windows,
        "linux":     linux,
        "last_sync": _last_sync,
        "synced":    _last_sync > 0,
    }
