from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Any secret that starts with one of these is a placeholder copied from an
# .env.example or the setup guide, never a real value.
_PLACEHOLDER_PREFIXES = ("replace-", "paste-", "change-me", "your-", "<")
_MIN_SECRET_LENGTH = 32


class Settings(BaseSettings):
    """Covers both the ingestion pipeline and the dashboard/auth API."""

    # Required - no localhost fallback, so a missing value fails loudly at
    # startup instead of the app silently trying to reach a local database.
    mongo_uri: str
    db_name: str = "honeypot"

    # Shared secret the Cowrie VPS's log shipper presents. No default on
    # purpose - the app refuses to start without a real value.
    ingest_api_key: str

    # Signs admin login JWTs. Same "no silent weak default" treatment.
    # The algorithm is fixed to HS256 in app/auth.py and is deliberately
    # NOT configurable from the environment.
    jwt_secret_key: str
    jwt_expire_minutes: int = 60

    # The dashboard frontend's real origin (Firebase Hosting URL in
    # production). Never "*".
    cors_allowed_origin: str = "http://localhost:5173"

    # How many reverse proxies sit in front of this app and append to
    # X-Forwarded-For. 0 = use the direct TCP peer address (local dev).
    # See app/limiter.py and the setup guide for how to pick the value.
    trusted_proxy_hops: int = 0

    # raw_events older than this are deleted automatically by a MongoDB TTL
    # index, so the free Atlas tier (512 MB) doesn't fill up. 0 disables.
    raw_event_retention_days: int = 30

    # Serve /docs and /openapi.json. Handy locally; turn off in production.
    enable_api_docs: bool = False

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    @field_validator("ingest_api_key", "jwt_secret_key")
    @classmethod
    def validate_secret_strength(cls, v: str) -> str:
        if not v or v.strip().lower().startswith(_PLACEHOLDER_PREFIXES):
            raise ValueError(
                "A required secret is missing or still set to a placeholder value. "
                "Generate a real one with: python -c \"import secrets; print(secrets.token_hex(32))\" "
                "and set it in your environment before starting the app."
            )
        if len(v) < _MIN_SECRET_LENGTH:
            raise ValueError(
                f"A required secret is only {len(v)} characters - use at least "
                f"{_MIN_SECRET_LENGTH}, ideally the full output of secrets.token_hex(32)."
            )
        return v

    @field_validator("mongo_uri")
    @classmethod
    def validate_mongo_uri(cls, v: str) -> str:
        if "<user>" in v or "<password>" in v or "<cluster>" in v:
            raise ValueError("MONGO_URI still contains the <user>/<password>/<cluster> placeholders.")
        return v

    @field_validator("cors_allowed_origin")
    @classmethod
    def validate_cors_origin(cls, v: str) -> str:
        if v.strip() == "*":
            raise ValueError("CORS_ALLOWED_ORIGIN must be your real dashboard URL, not '*'.")
        return v.rstrip("/")

    @model_validator(mode="after")
    def secrets_must_differ(self) -> "Settings":
        if self.ingest_api_key == self.jwt_secret_key:
            raise ValueError(
                "INGEST_API_KEY and JWT_SECRET_KEY must be different values - "
                "otherwise the log shipper's key could be used to forge admin logins."
            )
        return self


settings = Settings()
