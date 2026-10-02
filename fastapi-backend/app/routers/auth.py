from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, Field

from app.auth import authenticate_admin, create_access_token
from app.limiter import limiter

router = APIRouter(tags=["auth"])


class LoginRequest(BaseModel):
    # Bounded so an oversized value is a clean validation error, never a
    # 500 from bcrypt (which rejects >72-byte passwords).
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


@router.post("/login", response_model=LoginResponse)
@limiter.limit("10/minute")  # bounds brute-force password guessing (per client IP)
async def login(request: Request, payload: LoginRequest) -> LoginResponse:
    ok = await authenticate_admin(payload.username, payload.password)
    if not ok:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )
    return LoginResponse(access_token=create_access_token(payload.username))
