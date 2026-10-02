"""
Pure-ASGI middleware (not BaseHTTPMiddleware) so we can police the request
body as it streams in, rather than trusting the Content-Length header.
"""
import json
from typing import Any, Callable, Dict

# A single Cowrie event is a few KB at most. /ingest/batch accepts up to
# MAX_BATCH_EVENTS (see routers/ingest.py) events per request, so the cap
# is sized for a full batch with generous headroom.
MAX_BODY_SIZE_BYTES = 1_000_000

Scope = Dict[str, Any]
Receive = Callable[[], Any]
Send = Callable[[Dict[str, Any]], Any]


async def _send_413(send: Send) -> None:
    body = json.dumps({"detail": "Payload too large"}).encode()
    await send(
        {
            "type": "http.response.start",
            "status": 413,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
                (b"connection", b"close"),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


class LimitBodySizeMiddleware:
    """
    Rejects oversized requests with 413, whether they declare a
    Content-Length or use chunked transfer encoding (which has none and
    previously bypassed the check entirely).
    """

    def __init__(self, app: Any, max_body_size: int = MAX_BODY_SIZE_BYTES) -> None:
        self.app = app
        self.max_body_size = max_body_size

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        for name, value in scope.get("headers", []):
            if name == b"content-length":
                try:
                    if int(value) > self.max_body_size:
                        await _send_413(send)
                        return
                except ValueError:
                    await _send_413(send)
                    return

        received = 0
        response_started = False
        rejected = False

        async def limited_receive() -> Dict[str, Any]:
            nonlocal received, rejected
            if rejected:
                return {"type": "http.disconnect"}
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_body_size:
                    # Answer 413 ourselves right away, then tell the app the
                    # client went away so it stops reading. (Raising here
                    # instead would be caught by FastAPI and turned into 400.)
                    rejected = True
                    if not response_started:
                        await _send_413(send)
                    return {"type": "http.disconnect"}
            return message

        async def guarded_send(message: Dict[str, Any]) -> None:
            nonlocal response_started
            if rejected:
                return  # we've already answered 413; drop the app's response
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, guarded_send)
        except Exception:
            if not rejected:
                raise


# Applied to every API response. The API only ever returns JSON, so the
# CSP can be locked all the way down - it stops a browser from executing
# anything even if someone opens an API URL directly.
_SECURITY_HEADERS = [
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"DENY"),
    (b"referrer-policy", b"no-referrer"),
    (b"content-security-policy", b"default-src 'none'; frame-ancestors 'none'"),
    (b"cache-control", b"no-store"),
    (b"strict-transport-security", b"max-age=31536000"),
]

# Swagger UI (only when ENABLE_API_DOCS=true) needs scripts/styles from a
# CDN, so the strict CSP isn't applied to those two pages.
_DOCS_PATHS = ("/docs", "/docs/oauth2-redirect", "/redoc")


class SecurityHeadersMiddleware:
    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        is_docs = scope.get("path") in _DOCS_PATHS

        async def send_with_headers(message: Dict[str, Any]) -> None:
            if message["type"] == "http.response.start":
                existing = {k.lower() for k, _ in message.get("headers", [])}
                headers = list(message.get("headers", []))
                for name, value in _SECURITY_HEADERS:
                    if is_docs and name == b"content-security-policy":
                        continue
                    if name not in existing:
                        headers.append((name, value))
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_with_headers)
