"""Redis client — session store, rate-limit counters, TOTP lockouts."""
import redis.asyncio as redis
from core.config import settings


_pool = redis.ConnectionPool.from_url(
    settings.redis_url,
    password=settings.redis_password or None,
    decode_responses=True,
    socket_connect_timeout=3,
)


def get_redis() -> redis.Redis:
    return redis.Redis(connection_pool=_pool)
