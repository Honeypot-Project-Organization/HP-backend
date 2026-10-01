from starlette.requests import Request
from slowapi import Limiter

from app.config import settings


def client_ip(request: Request) -> str:
    """
    The real client IP, for rate limiting.

    Behind a platform load balancer (FastAPI Cloud, Render, etc.) the TCP
    peer is the proxy, so every visitor would share ONE rate-limit bucket -
    ten failed logins from anyone would lock out everyone. When
    TRUSTED_PROXY_HOPS=N, we read X-Forwarded-For and take the Nth entry
    from the RIGHT: those are the ones appended by proxies you trust. The
    left-hand entries are whatever the client claimed and are ignored, so a
    client can't dodge the limit by sending a fake X-Forwarded-For header.
    """
    hops = settings.trusted_proxy_hops
    if hops > 0:
        forwarded = request.headers.get("x-forwarded-for", "")
        parts = [p.strip() for p in forwarded.split(",") if p.strip()]
        if len(parts) >= hops:
            return parts[-hops]
    return request.client.host if request.client else "unknown"


# Shared across routers - ingest and auth each apply their own limits to
# this same instance, and main.py registers it once with the app.
# Storage is in-memory: limits are per running instance. That's fine for a
# single-instance deployment; if you scale out, point storage_uri at Redis.
limiter = Limiter(key_func=client_ip)
