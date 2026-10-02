from datetime import datetime, timedelta, timezone
from typing import Any, Dict

import bcrypt
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.config import settings
from app.database import get_database

# Fixed on purpose - never read the algorithm from the environment or from
# the token header (that's how "alg: none" / algorithm-confusion attacks work).
JWT_ALGORITHM = "HS256"
JWT_ISSUER = "honeypot-api"
JWT_AUDIENCE = "honeypot-dashboard"

# bcrypt only looks at the first 72 bytes, and bcrypt>=5 raises ValueError
# for anything longer. Reject early so a long password is a clean 401,
# not a 500.
BCRYPT_MAX_BYTES = 72

# Checked against when the username doesn't exist, so a wrong username and
# a wrong password take the same amount of time (no username enumeration).
_DUMMY_HASH = bcrypt.hashpw(b"timing-equalizer-not-a-real-password", bcrypt.gensalt())

security = HTTPBearer()


def password_too_long(password: str) -> bool:
    return len(password.encode("utf-8")) > BCRYPT_MAX_BYTES


def hash_password(password: str) -> str:
    if password_too_long(password):
        raise ValueError(f"Password must be at most {BCRYPT_MAX_BYTES} bytes (bcrypt limit).")
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain_password: str, password_hash: str) -> bool:
    if password_too_long(plain_password):
        return False
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), password_hash.encode("utf-8"))
    except ValueError:
        return False


def create_access_token(username: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": username,
        "iat": now,
        "exp": now + timedelta(minutes=settings.jwt_expire_minutes),
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
    }
    return jwt.encode(payload, settings.jwt_secret_key, algorithm=JWT_ALGORITHM)


async def authenticate_admin(username: str, password: str) -> bool:
    """Checks credentials against the single admins document. No signup path exists anywhere."""
    db = get_database()
    admin = await db.admins.find_one({"username": username})
    if not admin:
        # Burn the same bcrypt time as a real check, then fail.
        bcrypt.checkpw(b"x", _DUMMY_HASH)
        return False
    return verify_password(password, admin["password_hash"])


def _as_utc(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    return datetime.fromtimestamp(0, tz=timezone.utc)


async def get_current_admin(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> str:
    """FastAPI dependency: Depends(get_current_admin) on any route that needs a valid login."""
    unauthorized = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload: Dict[str, Any] = jwt.decode(
            credentials.credentials,
            settings.jwt_secret_key,
            algorithms=[JWT_ALGORITHM],
            issuer=JWT_ISSUER,
            audience=JWT_AUDIENCE,
            options={"require": ["exp", "iat", "sub", "iss", "aud"]},
        )
    except jwt.PyJWTError:
        raise unauthorized

    username = payload.get("sub")
    if not isinstance(username, str):
        raise unauthorized

    # The account must still exist, and the token must have been issued
    # after the account was (re)created. Re-running create_admin.py
    # therefore logs out every existing session immediately.
    admin = await get_database().admins.find_one({"username": username})
    if not admin:
        raise unauthorized
    issued_at = datetime.fromtimestamp(int(payload["iat"]), tz=timezone.utc)
    if issued_at < _as_utc(admin.get("created_at")).replace(microsecond=0):
        raise unauthorized
    return username
