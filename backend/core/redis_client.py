"""Redis client — session store, rate-limit counters, TOTP lockouts."""
import ssl

import redis.asyncio as redis
from core.config import settings

# rediss:// = TLS 1.3, server verified (chain + hostname) against the internal CA,
# with our client certificate presented — Redis enforces mutual TLS.
_tls = {}
if settings.redis_url.startswith("rediss://"):
    _tls = dict(
        ssl_ca_certs=settings.redis_tls_ca,
        ssl_certfile=settings.redis_tls_cert,
        ssl_keyfile=settings.redis_tls_key,
        ssl_cert_reqs="required",
        ssl_check_hostname=True,
        ssl_min_version=ssl.TLSVersion.TLSv1_3,
    )

_pool = redis.ConnectionPool.from_url(
    settings.redis_url,
    password=settings.redis_password or None,
    decode_responses=True,
    socket_connect_timeout=3,
    **_tls,
)


def get_redis() -> redis.Redis:
    return redis.Redis(connection_pool=_pool)
