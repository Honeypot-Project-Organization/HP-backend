"""
Read-only dashboard API. Every route requires a valid admin JWT.

Reminder for the frontend: every string returned here that came from the
honeypot (usernames, passwords, commands, client versions, URLs, file
names) was typed by an attacker. Render it as text only - see
docs/FRONTEND_SECURITY.md in the frontend repo.
"""
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request

from app import geo
from app.auth import get_current_admin
from app.config import settings
from app.database import aggregate, get_database
from app.limiter import client_ip

router = APIRouter(prefix="/api", tags=["dashboard"])

# Upper bound on any list endpoint, so a typo like ?limit=100000000 (or
# ?limit=0, which Mongo treats as "no limit") can't dump a whole collection.
MAX_PAGE = 500


@router.get("/stats")
async def get_stats(current_admin: str = Depends(get_current_admin)) -> Dict[str, Any]:
    db = get_database()

    total_sessions = await db.sessions.count_documents({})
    total_commands = await db.commands.count_documents({})
    total_auth_attempts = await db.auth_attempts.count_documents({})
    successful_logins = await db.auth_attempts.count_documents({"success": True})
    unique_ips = await db.ip_intel.count_documents({})

    success_rate = (
        round(successful_logins / total_auth_attempts * 100, 1) if total_auth_attempts else 0.0
    )

    # Lets the dashboard show "last event received" - if this stops
    # advancing, the shipper on the VPS has stopped delivering.
    latest = await db.raw_events.find_one({}, sort=[("received_at", -1)], projection={"received_at": 1})

    return {
        "total_sessions": total_sessions,
        "total_commands": total_commands,
        "total_auth_attempts": total_auth_attempts,
        "successful_logins": successful_logins,
        "success_rate_percent": success_rate,
        "unique_ips": unique_ips,
        "last_event_received_at": latest["received_at"] if latest else None,
    }


@router.get("/stats/daily")
async def get_daily_stats(
    days: int = Query(30, ge=1, le=365),
    current_admin: str = Depends(get_current_admin),
) -> List[Dict[str, Any]]:
    """
    Sessions per day (UTC) for the most recent `days` days that have data,
    oldest first. Handles both real dates (current ingest) and the ISO
    strings stored before timestamps were converted (see
    scripts/migrate_timestamps.py), so mixed data still groups correctly.
    """
    db = get_database()
    # Two small aggregations (real dates, legacy strings) merged in Python.
    by_type = [
        ("date", {"$dateToString": {"format": "%Y-%m-%d", "date": "$start_time"}}),
        ("string", {"$substr": ["$start_time", 0, 10]}),  # ASCII "YYYY-MM-DD" prefix
    ]
    totals: Dict[str, int] = {}
    for bson_type, day_expr in by_type:
        pipeline = [
            {"$match": {"start_time": {"$type": bson_type}}},
            {"$group": {"_id": day_expr, "attacks": {"$sum": 1}}},
            # Newest first so $limit keeps the LATEST days.
            {"$sort": {"_id": -1}},
            {"$limit": days},
        ]
        async for d in await aggregate(db.sessions, pipeline):
            totals[d["_id"]] = totals.get(d["_id"], 0) + d["attacks"]

    latest_days = sorted(totals)[-days:]  # oldest-first for charting
    return [{"date": day, "attacks": totals[day]} for day in latest_days]


@router.get("/stats/top-credentials")
async def get_top_credentials(
    limit: int = Query(5, ge=1, le=100),
    current_admin: str = Depends(get_current_admin),
) -> List[Dict[str, Any]]:
    db = get_database()
    pipeline = [
        {"$group": {"_id": {"username": "$username", "password": "$password"}, "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": limit},
    ]
    results = []
    async for doc in await aggregate(db.auth_attempts, pipeline):
        # Separate fields rather than a pre-joined "user:pass" string, so the
        # frontend doesn't have to split attacker text on ":".
        results.append(
            {"username": doc["_id"].get("username"), "password": doc["_id"].get("password"), "count": doc["count"]}
        )
    return results


@router.get("/sessions")
async def list_sessions(
    limit: int = Query(50, ge=1, le=MAX_PAGE),
    skip: int = Query(0, ge=0, le=100_000),
    current_admin: str = Depends(get_current_admin),
) -> List[Dict[str, Any]]:
    db = get_database()
    cursor = db.sessions.find().sort("start_time", -1).skip(skip).limit(limit)
    sessions = []
    async for doc in cursor:
        doc["id"] = str(doc.pop("_id"))
        sessions.append(doc)
    return sessions


@router.get("/sessions/{session_id}/commands")
async def get_session_commands(
    session_id: str = Path(pattern=r"^[A-Za-z0-9_-]{1,64}$"),
    limit: int = Query(MAX_PAGE, ge=1, le=MAX_PAGE),
    current_admin: str = Depends(get_current_admin),
) -> List[Dict[str, Any]]:
    db = get_database()
    cursor = db.commands.find({"session_id": session_id}).sort("timestamp", 1).limit(limit)
    commands = []
    async for doc in cursor:
        doc["id"] = str(doc.pop("_id"))
        commands.append(doc)
    return commands


@router.get("/ips")
async def list_attackers(
    limit: int = Query(100, ge=1, le=MAX_PAGE),
    skip: int = Query(0, ge=0, le=100_000),
    current_admin: str = Depends(get_current_admin),
) -> List[Dict[str, Any]]:
    db = get_database()
    cursor = db.ip_intel.find().sort("last_seen", -1).skip(skip).limit(limit)
    attackers = []
    async for doc in cursor:
        doc["ip"] = doc.pop("_id")
        attackers.append(doc)
    # Older IPs that predate the geo database get located on first view.
    await geo.enrich_docs(db, attackers)
    return attackers


@router.get("/debug/client-ip")
async def debug_client_ip(request: Request, current_admin: str = Depends(get_current_admin)) -> Dict[str, Any]:
    """
    Helps you pick TRUSTED_PROXY_HOPS after deploying (assets repo: cowrie_vps_setup_guide.md, Step 0b):
    call this from your own machine, compare with your real public IP
    (e.g. from https://ifconfig.me), and choose the hop count that makes
    `rate_limit_key` equal your IP.
    """
    return {
        "tcp_peer": request.client.host if request.client else None,
        "x_forwarded_for": request.headers.get("x-forwarded-for"),
        "trusted_proxy_hops": settings.trusted_proxy_hops,
        "rate_limit_key": client_ip(request),
    }


# ---- Per-IP and command views (used by the dashboard's detail pages) ----

IP_PATTERN = r"^[0-9A-Fa-f:.]{2,45}$"  # IPv4 / IPv6 characters only


@router.get("/ips/{ip}")
async def get_attacker(
    ip: str = Path(pattern=IP_PATTERN),
    current_admin: str = Depends(get_current_admin),
) -> Dict[str, Any]:
    db = get_database()
    doc = await db.ip_intel.find_one({"_id": ip})
    if not doc:
        raise HTTPException(status_code=404, detail="IP not found")
    doc["ip"] = doc.pop("_id")
    await geo.enrich_docs(db, [doc])
    return doc


@router.get("/ips/{ip}/sessions")
async def get_ip_sessions(
    ip: str = Path(pattern=IP_PATTERN),
    limit: int = Query(100, ge=1, le=MAX_PAGE),
    skip: int = Query(0, ge=0, le=100_000),
    current_admin: str = Depends(get_current_admin),
) -> List[Dict[str, Any]]:
    db = get_database()
    cursor = db.sessions.find({"src_ip": ip}).sort("start_time", -1).skip(skip).limit(limit)
    sessions = []
    async for doc in cursor:
        doc["id"] = str(doc.pop("_id"))
        sessions.append(doc)
    return sessions


@router.get("/ips/{ip}/commands")
async def get_ip_commands(
    ip: str = Path(pattern=IP_PATTERN),
    limit: int = Query(MAX_PAGE, ge=1, le=MAX_PAGE),
    skip: int = Query(0, ge=0, le=100_000),
    current_admin: str = Depends(get_current_admin),
) -> List[Dict[str, Any]]:
    db = get_database()
    cursor = db.commands.find({"src_ip": ip}).sort("timestamp", -1).skip(skip).limit(limit)
    commands = []
    async for doc in cursor:
        doc["id"] = str(doc.pop("_id"))
        commands.append(doc)
    return commands


@router.get("/commands")
async def list_commands(
    limit: int = Query(100, ge=1, le=MAX_PAGE),
    skip: int = Query(0, ge=0, le=100_000),
    current_admin: str = Depends(get_current_admin),
) -> List[Dict[str, Any]]:
    db = get_database()
    cursor = db.commands.find().sort("timestamp", -1).skip(skip).limit(limit)
    commands = []
    async for doc in cursor:
        doc["id"] = str(doc.pop("_id"))
        commands.append(doc)
    return commands


@router.get("/sessions/{session_id}")
async def get_session(
    session_id: str = Path(pattern=r"^[A-Za-z0-9_-]{1,64}$"),
    current_admin: str = Depends(get_current_admin),
) -> Dict[str, Any]:
    db = get_database()
    doc = await db.sessions.find_one({"_id": session_id})
    if not doc:
        raise HTTPException(status_code=404, detail="Session not found")
    doc["id"] = str(doc.pop("_id"))
    return doc


@router.get("/geo/status")
async def geo_status(current_admin: str = Depends(get_current_admin)) -> Dict[str, Any]:
    """Which location databases have been uploaded (metadata only)."""
    return await geo.get_status(get_database())
