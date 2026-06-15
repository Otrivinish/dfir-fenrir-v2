"""Token-bucket rate-limit middleware.

One bucket per credential (or per source IP for anonymous requests). The
bucket refills at a configurable steady rate and has a configurable burst
capacity. Token deduction and refill happen atomically inside a Redis Lua
script so concurrent requests can't race past the limit.

Why this and not the existing login-lockout counters: those are per-username,
defence-in-depth against credential stuffing on a single account. This
middleware caps total request volume per credential / IP — generic protection
for any endpoint, including read-only paths that have no other gate.

Buckets:
  • `anon`  — pre-auth requests. Keyed by client IP. Tight.
  • `auth`  — anything carrying a session cookie or Bearer token. Looser.
            Keyed by a *hash of the credential*, so each token / session has
            its own bucket (no shared-NAT punishment).

Excluded paths (always allowed):
  • Health / version (load-balancer probes)
  • WebSocket upgrades (one long-lived connection per client; per-message
    rate limits belong inside the WS handler)
"""
import hashlib
import logging
import time
from typing import Tuple

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from auth.service import SESSION_COOKIE
from core.config import settings
from core.redis_client import get_redis


log = logging.getLogger(__name__)


# ── Lua: atomic token-bucket refill + deduct ────────────────────────────────
# Stores `tokens` (float) and `ts` (unix seconds) per bucket. Returns
# {allowed, tokens_remaining, retry_after_seconds}.
_BUCKET_LUA = """
local key            = KEYS[1]
local capacity       = tonumber(ARGV[1])
local refill_per_sec = tonumber(ARGV[2])
local now            = tonumber(ARGV[3])
local cost           = tonumber(ARGV[4])

local b = redis.call('HMGET', key, 'tokens', 'ts')
local tokens = tonumber(b[1])
local ts = tonumber(b[2])
if not tokens then tokens = capacity end
if not ts then ts = now end

local delta = now - ts
if delta < 0 then delta = 0 end
tokens = math.min(capacity, tokens + delta * refill_per_sec)

local allowed = 0
local retry_after = 0
if tokens >= cost then
    tokens = tokens - cost
    allowed = 1
else
    retry_after = (cost - tokens) / refill_per_sec
end

redis.call('HSET', key, 'tokens', tokens, 'ts', now)
redis.call('EXPIRE', key, math.ceil(capacity / refill_per_sec) + 2)
return {allowed, tostring(tokens), tostring(retry_after)}
"""


# Excluded path prefixes — never rate-limited.
_EXCLUDED_PREFIXES: tuple[str, ...] = (
    "/api/health",
    "/api/version",
    "/api/warroom/ws",
    "/api/notifications/ws",
)


def _client_ip(request: Request) -> str:
    """Trust the rightmost X-Forwarded-For entry — Caddy appends the real client
    IP to whatever the client sent, so the leftmost is attacker-controlled and
    the rightmost is what our single trusted hop added."""
    xff = request.headers.get("x-forwarded-for")
    if xff:
        last = xff.rsplit(",", 1)[-1].strip()
        if last:
            return last
    if request.client and request.client.host:
        return request.client.host
    return "unknown"


def _credential_fingerprint(request: Request) -> str | None:
    """Short SHA-256 prefix of whatever credential the request carries. None if anonymous."""
    # Authorization: Bearer …
    h = request.headers.get("authorization") or request.headers.get("Authorization")
    if h:
        parts = h.split(None, 1)
        if len(parts) == 2 and parts[0].lower() == "bearer" and parts[1].strip():
            return "tok:" + hashlib.sha256(parts[1].strip().encode("utf-8")).hexdigest()[:32]
    # Cookie session
    sess = request.cookies.get(SESSION_COOKIE)
    if sess:
        return "ses:" + hashlib.sha256(sess.encode("utf-8")).hexdigest()[:32]
    return None


def _classify(request: Request) -> Tuple[str, str, int, float]:
    """Return (tier, identity_key, capacity, refill_per_sec) for a request."""
    cred = _credential_fingerprint(request)
    if cred:
        cap = settings.rate_limit_auth_burst
        rate = settings.rate_limit_auth_per_min / 60.0
        return "auth", cred, cap, rate
    ident = "ip:" + _client_ip(request)
    cap = settings.rate_limit_anon_burst
    rate = settings.rate_limit_anon_per_min / 60.0
    return "anon", ident, cap, rate


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app):
        super().__init__(app)
        self._script_sha: str | None = None

    async def _eval(self, key: str, capacity: int, refill_per_sec: float, cost: int) -> tuple[bool, float, float]:
        r = get_redis()
        now = time.time()
        try:
            if self._script_sha is None:
                self._script_sha = await r.script_load(_BUCKET_LUA)
            res = await r.evalsha(self._script_sha, 1, key, capacity, refill_per_sec, now, cost)
        except Exception as exc:
            # NOSCRIPT (script cache flushed) or transient — fall back to eval.
            try:
                res = await r.eval(_BUCKET_LUA, 1, key, capacity, refill_per_sec, now, cost)
                self._script_sha = None  # force reload next time
            except Exception:
                log.warning("rate-limit Redis eval failed; allowing request", exc_info=exc)
                return True, float(capacity), 0.0
        allowed = int(res[0]) == 1
        tokens = float(res[1])
        retry_after = float(res[2])
        return allowed, tokens, retry_after

    async def dispatch(self, request: Request, call_next) -> Response:
        if not settings.rate_limit_enabled:
            return await call_next(request)

        path = request.url.path
        if any(path.startswith(p) for p in _EXCLUDED_PREFIXES):
            return await call_next(request)

        tier, ident, capacity, refill = _classify(request)
        key = f"rl:{tier}:{ident}"

        allowed, tokens_left, retry_after = await self._eval(key, capacity, refill, cost=1)

        if not allowed:
            retry_s = max(1, int(retry_after) + 1)
            return JSONResponse(
                status_code=429,
                content={"detail": "Too many requests", "code": "rate_limited", "retry_after": retry_s},
                headers={
                    "Retry-After": str(retry_s),
                    "X-RateLimit-Limit": str(capacity),
                    "X-RateLimit-Remaining": "0",
                },
            )

        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(capacity)
        response.headers["X-RateLimit-Remaining"] = str(max(0, int(tokens_left)))
        return response
