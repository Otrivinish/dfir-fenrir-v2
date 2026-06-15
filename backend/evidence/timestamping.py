"""RFC 3161 trusted timestamping (GS-4).

Optional + best-effort. If no TSA is configured (`settings.tsa_url` unset), the TSA is
unreachable, or `rfc3161ng` isn't installed, `timestamp_sha256` returns None and callers
proceed on the server clock — nothing blocks. Only the **hash** is sent to the TSA, never
the evidence.

A Time-Stamp Token (TST) cryptographically binds a hash to a trusted time signed by the
TSA, verifiable independently of FENRIR's clock (`openssl ts -verify`).
"""
from __future__ import annotations

import asyncio
import base64
import logging
from datetime import timezone
from typing import Optional

from core.config import settings

log = logging.getLogger("fenrir.timestamp")


def _fetch_tst_sync(sha256_hex: str) -> Optional[dict]:
    """Blocking RFC-3161 round-trip (run in a threadpool). Lazy-imports rfc3161ng so the
    rest of the app loads even when the dependency is absent."""
    import rfc3161ng  # noqa: PLC0415 — intentional lazy import

    timestamper = rfc3161ng.RemoteTimestamper(
        settings.tsa_url,
        hashname="sha256",
        timeout=settings.tsa_timeout_seconds,
    )
    tst: bytes = timestamper(digest=bytes.fromhex(sha256_hex))
    gen_time = rfc3161ng.get_timestamp(tst)
    iso = None
    if gen_time is not None:
        if gen_time.tzinfo is None:
            gen_time = gen_time.replace(tzinfo=timezone.utc)
        iso = gen_time.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    return {
        "tst_b64": base64.b64encode(tst).decode("ascii"),
        "time":    iso,
        "tsa":     settings.tsa_url,
    }


async def timestamp_sha256(sha256_hex: Optional[str]) -> Optional[dict]:
    """Best-effort TST over a SHA-256 hex digest. Returns
    {tst_b64, time, tsa} or None (no TSA / unreachable / lib missing / any error)."""
    if not sha256_hex or not settings.tsa_url:
        return None
    try:
        return await asyncio.to_thread(_fetch_tst_sync, sha256_hex)
    except ImportError:
        log.warning("TSA configured (%s) but rfc3161ng not installed — skipping timestamp", settings.tsa_url)
        return None
    except Exception as e:  # best-effort — never block the caller
        log.warning("Trusted timestamp failed (%s): %s", settings.tsa_url, e)
        return None
