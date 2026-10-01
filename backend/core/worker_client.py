"""The analysis worker: one place for its URL, TLS trust and service credential."""
import ssl

import httpx

from core.config import settings

WORKER_URL = settings.worker_url


def worker_headers() -> dict[str, str]:
    """Bearer credential for the worker (the `worker_token` secret). The worker
    refuses every request without it — being on its network is not authentication."""
    return {"Authorization": f"Bearer {settings.worker_token}"} if settings.worker_token else {}


def worker_client(timeout: float) -> httpx.AsyncClient:
    """HTTP client for the worker: https is verified against the internal CA (TLS 1.3)."""
    verify: ssl.SSLContext | bool = True
    if settings.worker_tls_ca:
        verify = ssl.create_default_context(cafile=settings.worker_tls_ca)
        verify.minimum_version = ssl.TLSVersion.TLSv1_3
    return httpx.AsyncClient(timeout=timeout, verify=verify)
