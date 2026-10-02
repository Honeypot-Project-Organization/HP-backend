from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.config import settings
from app.database import create_indexes, get_client, ping
from app.limiter import limiter
from app.middleware import LimitBodySizeMiddleware, SecurityHeadersMiddleware
from app.routers import auth, dashboard, ingest


@asynccontextmanager
async def lifespan(app: FastAPI):
    await create_indexes()
    yield
    get_client().close()


docs_kwargs = {} if settings.enable_api_docs else {"docs_url": None, "redoc_url": None, "openapi_url": None}
app = FastAPI(title="Honeypot API", lifespan=lifespan, **docs_kwargs)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Starlette runs the LAST-added middleware first. Order (outermost first):
# CORS -> security headers -> body size limit -> app.
app.add_middleware(LimitBodySizeMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
# Scoped to the real dashboard origin, never "*". The dashboard sends its
# JWT in an Authorization header (not a cookie), so credentials mode is
# off and only the methods/headers it actually uses are allowed.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.cors_allowed_origin],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
    max_age=600,
)

app.include_router(ingest.router)
app.include_router(auth.router)
app.include_router(dashboard.router)


@app.get("/health")
async def health():
    """200 only if the app is up AND MongoDB answers a ping; 503 otherwise."""
    if await ping():
        return {"status": "ok"}
    return JSONResponse({"status": "degraded", "database": "unreachable"}, status_code=503)
