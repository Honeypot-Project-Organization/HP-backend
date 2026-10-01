"""
Receives Cowrie events from the log shipper on the honeypot VPS.

SECURITY NOTE - everything in an event is attacker-influenced (usernames,
passwords, commands typed, URLs). Rules this module follows, keep them:
  * Every field is type-checked by `CowrieEvent` before use. A value that
    is used in a query filter (session id, source IP) must be a plain,
    pattern-checked string - never a dict like {"$ne": null}.
  * Attacker text is only ever stored as a field VALUE, never as a key,
    never evaluated, and never rendered by this API as HTML.
  * Keys in the stored raw copy are sanitized so a "$"-prefixed or dotted
    key can't be interpreted as a MongoDB operator/path.
"""
import hashlib
import json
import secrets
from datetime import datetime, timezone
from ipaddress import ip_address
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Body, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator
from pymongo.errors import DuplicateKeyError

from app.config import settings
from app.database import get_database
from app.limiter import limiter

router = APIRouter(prefix="/ingest", tags=["ingest"])

MAX_BATCH_EVENTS = 200
MAX_TEXT_LEN = 4096  # longer attacker input is truncated, not rejected
MAX_RAW_DEPTH = 8


async def verify_ingest_key(x_ingest_key: str = Header(...)) -> None:
    """
    Completely separate from the admin login. The Cowrie VPS's shipper
    holds this one shared secret and nothing else. compare_digest keeps
    the comparison constant-time.
    """
    if not secrets.compare_digest(
        x_ingest_key.encode("utf-8"), settings.ingest_api_key.encode("utf-8")
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid ingest key",
        )


def _truncate(v: Any) -> Any:
    if isinstance(v, str) and len(v) > MAX_TEXT_LEN:
        return v[:MAX_TEXT_LEN] + "…[truncated]"
    return v


class CowrieEvent(BaseModel):
    """
    The subset of Cowrie's JSON event fields this API uses, strictly typed.
    Unknown fields are allowed (Cowrie adds fields between versions) and are
    kept in the raw copy, but are never used for anything else.
    """

    model_config = ConfigDict(extra="allow", str_strip_whitespace=False)

    eventid: str = Field(pattern=r"^cowrie\.[a-z0-9_.]{1,64}$")
    session: Optional[str] = Field(default=None, pattern=r"^[A-Za-z0-9_-]{1,64}$")
    src_ip: Optional[str] = None
    src_port: Optional[int] = Field(default=None, ge=0, le=65535)
    dst_port: Optional[int] = Field(default=None, ge=0, le=65535)
    protocol: Optional[str] = None
    timestamp: Optional[datetime] = None

    username: Optional[str] = None
    password: Optional[str] = None
    input: Optional[str] = None
    version: Optional[str] = None  # cowrie.client.version

    url: Optional[str] = None
    filename: Optional[str] = None
    outfile: Optional[str] = None
    shasum: Optional[str] = Field(default=None, pattern=r"^[0-9a-fA-F]{64}$")
    size: Optional[int] = Field(default=None, ge=0)
    duration: Optional[float] = Field(default=None, ge=0)

    @field_validator("src_ip")
    @classmethod
    def valid_ip(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        return str(ip_address(v))  # raises ValueError -> 422 for non-IPs

    @field_validator("username", "password", "input", "version", "url", "filename", "outfile", mode="before")
    @classmethod
    def cap_text(cls, v: Any) -> Any:
        return _truncate(v)

    @field_validator("timestamp")
    @classmethod
    def utc(cls, v: Optional[datetime]) -> Optional[datetime]:
        if v is None:
            return v
        return v.astimezone(timezone.utc) if v.tzinfo else v.replace(tzinfo=timezone.utc)


def _sanitize(value: Any, depth: int = 0) -> Any:
    """Copy of the raw event that is always safe to store as a document."""
    if depth > MAX_RAW_DEPTH:
        return "…[nested too deep]"
    if isinstance(value, dict):
        clean: Dict[str, Any] = {}
        for k, v in value.items():
            key = str(k).replace(".", "_")
            if key.startswith("$"):
                key = "_" + key[1:]
            clean[key[:128]] = _sanitize(v, depth + 1)
        return clean
    if isinstance(value, list):
        return [_sanitize(v, depth + 1) for v in value[:500]]
    return _truncate(value)


def event_id(raw: Dict[str, Any]) -> str:
    """
    Deterministic id from the event's content. If the shipper re-sends an
    event (e.g. the response was lost after the server already saved it),
    the second copy hits the same _id and is ignored instead of being
    counted twice.
    """
    canonical = json.dumps(raw, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


async def _ip_touch(db: Any, src_ip: Optional[str], ts: datetime, now: datetime, inc: Dict[str, int]) -> None:
    if not src_ip:
        return
    await db.ip_intel.update_one(
        {"_id": src_ip},
        {
            # $min/$max keep first/last seen correct even if events arrive out of order.
            "$min": {"first_seen": ts},
            "$max": {"last_seen": ts},
            "$set": {"updated_at": now},
            "$setOnInsert": {"threat_score": 0.0},
            "$inc": inc,
        },
        upsert=True,
    )


async def process_event(raw: Any) -> str:
    """
    Store one event. Returns "ok", "duplicate" or "stored_raw_only".
    Raises ValidationError / ValueError for malformed events.
    """
    if not isinstance(raw, dict):
        raise ValueError("event must be a JSON object")

    ev = CowrieEvent.model_validate(raw)
    db = get_database()
    now = datetime.now(timezone.utc)
    ts = ev.timestamp or now
    sid = ev.session
    ip = ev.src_ip

    # 1. Raw copy first - its _id doubles as the duplicate detector.
    try:
        await db.raw_events.insert_one(
            {
                "_id": event_id(raw),
                "session_id": sid,
                "eventid": ev.eventid,
                "received_at": now,
                "raw": _sanitize(raw),
            }
        )
    except DuplicateKeyError:
        return "duplicate"

    if not sid:
        return "stored_raw_only"

    # 2. Normalized collections. `sid` and `ip` are validated plain strings.
    eid = ev.eventid
    if eid == "cowrie.session.connect":
        protocol = ev.protocol if ev.protocol in ("ssh", "telnet") else "ssh"
        await db.sessions.update_one(
            {"_id": sid},
            {
                "$set": {
                    "src_ip": ip,
                    "src_port": ev.src_port,
                    "dst_port": ev.dst_port,
                    "protocol": protocol,
                    "start_time": ts,
                },
                "$setOnInsert": {
                    "command_count": 0,
                    "download_count": 0,
                    "login_success": False,
                    "status": "open",
                },
            },
            upsert=True,
        )
        await _ip_touch(db, ip, ts, now, {"total_sessions": 1})

    elif eid in ("cowrie.login.success", "cowrie.login.failed"):
        success = eid == "cowrie.login.success"
        await db.auth_attempts.insert_one(
            {
                "session_id": sid,
                "src_ip": ip,
                "username": ev.username,
                "password": ev.password,
                "success": success,
                "timestamp": ts,
            }
        )
        if success:
            await db.sessions.update_one(
                {"_id": sid},
                {"$set": {"login_success": True, "username": ev.username, "password": ev.password}},
            )
        inc = {"total_auth_attempts": 1}
        if success:
            inc["successful_logins"] = 1
        await _ip_touch(db, ip, ts, now, inc)

    elif eid in ("cowrie.command.input", "cowrie.command.failed"):
        await db.commands.insert_one(
            {"session_id": sid, "src_ip": ip, "timestamp": ts, "input": ev.input or ""}
        )
        await db.sessions.update_one({"_id": sid}, {"$inc": {"command_count": 1}})
        await _ip_touch(db, ip, ts, now, {"total_commands": 1})

    elif eid in ("cowrie.session.file_upload", "cowrie.session.file_download"):
        await db.downloads.insert_one(
            {
                "session_id": sid,
                "src_ip": ip,
                "timestamp": ts,
                "url": ev.url,
                "filename": ev.filename or ev.outfile,
                "sha256": (ev.shasum or "").lower(),
                "size_bytes": ev.size,
            }
        )
        await db.sessions.update_one({"_id": sid}, {"$inc": {"download_count": 1}})

    elif eid == "cowrie.client.version":
        await db.sessions.update_one({"_id": sid}, {"$set": {"client_version": ev.version}})

    elif eid == "cowrie.session.closed":
        await db.sessions.update_one(
            {"_id": sid},
            {"$set": {"status": "closed", "duration_seconds": ev.duration, "end_time": ts}},
        )

    return "ok"


def _error_summary(exc: Exception) -> str:
    if isinstance(exc, ValidationError):
        return "; ".join(
            f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors()[:5]
        )
    return str(exc)[:300]


@router.post("", status_code=status.HTTP_202_ACCEPTED, dependencies=[Depends(verify_ingest_key)])
@limiter.limit("120/minute")
async def ingest_event(request: Request, event: Dict[str, Any] = Body(...)) -> Dict[str, str]:
    """One raw Cowrie event (kept for testing and backwards compatibility)."""
    try:
        result = await process_event(event)
    except (ValidationError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=_error_summary(exc))
    return {"status": result}


@router.post("/batch", status_code=status.HTTP_202_ACCEPTED, dependencies=[Depends(verify_ingest_key)])
@limiter.limit("120/minute")
async def ingest_batch(request: Request, events: List[Any] = Body(...)) -> Dict[str, Any]:
    """
    Up to MAX_BATCH_EVENTS events per request - what the shipper uses, so a
    brute-force bot generating thousands of events a minute doesn't blow
    through the rate limit. Malformed events are reported back and skipped
    (the shipper logs them); they don't block the rest of the batch.
    """
    if len(events) > MAX_BATCH_EVENTS:
        raise HTTPException(status_code=413, detail=f"At most {MAX_BATCH_EVENTS} events per batch")

    counts = {"ok": 0, "duplicate": 0, "stored_raw_only": 0}
    rejected: List[Dict[str, Any]] = []
    for index, raw in enumerate(events):
        try:
            counts[await process_event(raw)] += 1
        except (ValidationError, ValueError) as exc:
            rejected.append({"index": index, "error": _error_summary(exc)})

    return {
        "accepted": counts["ok"] + counts["stored_raw_only"],
        "duplicates": counts["duplicate"],
        "rejected": rejected,
    }
