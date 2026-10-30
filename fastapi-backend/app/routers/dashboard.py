"""
Read-only dashboard API. Every route requires a valid admin JWT.

Reminder for the frontend: every string returned here that came from the
honeypot (usernames, passwords, commands, client versions, URLs, file
names) was typed by an attacker. Render it as text only - see
docs/FRONTEND_SECURITY.md in the frontend repo.
"""
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, Response

from app import geo
from app.cmdkey import KEY_PATTERN
from app.auth import get_current_admin
from app.config import settings
from app.database import aggregate, get_database
from app.limiter import client_ip

router = APIRouter(prefix="/api", tags=["dashboard"])

# Upper bound on any list endpoint, so a typo like ?limit=100000000 (or
# ?limit=0, which Mongo treats as "no limit") can't dump a whole collection.
MAX_PAGE = 500
TOTAL_HEADER = "X-Total-Count"  # exposed to the browser via CORS (see main.py)


def _utc(d: Optional[datetime]) -> Optional[datetime]:
    if d is None:
        return None
    return d.astimezone(timezone.utc) if d.tzinfo else d.replace(tzinfo=timezone.utc)


def _date_range(date_from: Optional[datetime], date_to: Optional[datetime]) -> Dict[str, datetime]:
    """{"$gte": from, "$lte": to} (UTC); either end may be omitted."""
    lo, hi = _utc(date_from), _utc(date_to)
    if lo and hi and lo > hi:
        raise HTTPException(status_code=422, detail="date_from must not be after date_to")
    out: Dict[str, datetime] = {}
    if lo:
        out["$gte"] = lo
    if hi:
        out["$lte"] = hi
    return out


def _contains(text: Optional[str]) -> Optional[Dict[str, Any]]:
    """Case-insensitive 'contains' filter. The text is escaped, so it is only
    ever matched literally - never interpreted as a regular expression."""
    t = (text or "").strip()
    return {"$regex": re.escape(t), "$options": "i"} if t else None


def _sort(field: str, order: str, tiebreak: str = "_id") -> List[Any]:
    d = 1 if order == "asc" else -1
    return [(field, d), (tiebreak, 1)] if field != tiebreak else [(field, d)]


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


SESSION_SORTS = {"src_ip", "start_time", "duration_seconds", "login_success", "username", "command_count"}


@router.get("/sessions")
async def list_sessions(
    response: Response,
    limit: int = Query(50, ge=1, le=MAX_PAGE),
    skip: int = Query(0, ge=0, le=100_000),
    q: Optional[str] = Query(None, max_length=64, description="source IP contains"),
    login: Literal["all", "granted", "denied"] = "all",
    date_from: Optional[datetime] = None,
    date_to: Optional[datetime] = None,
    sort: str = Query("start_time"),
    order: Literal["asc", "desc"] = "desc",
    current_admin: str = Depends(get_current_admin),
) -> List[Dict[str, Any]]:
    """Filters apply to ALL sessions; X-Total-Count is the match count."""
    if sort not in SESSION_SORTS:
        raise HTTPException(status_code=422, detail=f"sort must be one of {sorted(SESSION_SORTS)}")
    flt: Dict[str, Any] = {}
    if (rx := _contains(q)):
        flt["src_ip"] = rx
    if login == "granted":
        flt["login_success"] = True
    elif login == "denied":
        flt["login_success"] = {"$ne": True}
    if (rng := _date_range(date_from, date_to)):
        flt["start_time"] = rng

    db = get_database()
    response.headers[TOTAL_HEADER] = str(await db.sessions.count_documents(flt))
    cursor = db.sessions.find(flt).sort(_sort(sort, order)).skip(skip).limit(limit)
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


ATTACKER_SORTS = {
    "ip": "_id", "total_sessions": "total_sessions", "successful_logins": "successful_logins",
    "total_auth_attempts": "total_auth_attempts", "total_commands": "total_commands",
    "first_seen": "first_seen", "last_seen": "last_seen",
}


@router.get("/ips")
async def list_attackers(
    response: Response,
    limit: int = Query(100, ge=1, le=MAX_PAGE),
    skip: int = Query(0, ge=0, le=100_000),
    q: Optional[str] = Query(None, max_length=64, description="IP contains"),
    date_from: Optional[datetime] = None,
    date_to: Optional[datetime] = None,
    date_field: Literal["last_seen", "first_seen"] = "last_seen",
    sort: str = Query("last_seen"),
    order: Literal["asc", "desc"] = "desc",
    current_admin: str = Depends(get_current_admin),
) -> List[Dict[str, Any]]:
    """Filters apply to ALL IPs; X-Total-Count is the match count."""
    if sort not in ATTACKER_SORTS:
        raise HTTPException(status_code=422, detail=f"sort must be one of {sorted(ATTACKER_SORTS)}")
    flt: Dict[str, Any] = {}
    if (rx := _contains(q)):
        flt["_id"] = rx
    if (rng := _date_range(date_from, date_to)):
        flt[date_field] = rng

    db = get_database()
    response.headers[TOTAL_HEADER] = str(await db.ip_intel.count_documents(flt))
    cursor = db.ip_intel.find(flt).sort(_sort(ATTACKER_SORTS[sort], order)).skip(skip).limit(limit)
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
    response: Response,
    limit: int = Query(100, ge=1, le=MAX_PAGE),
    skip: int = Query(0, ge=0, le=100_000),
    current_admin: str = Depends(get_current_admin),
) -> List[Dict[str, Any]]:
    db = get_database()
    response.headers[TOTAL_HEADER] = str(await db.commands.count_documents({}))
    cursor = db.commands.find().sort("timestamp", -1).skip(skip).limit(limit)
    commands = []
    async for doc in cursor:
        doc["id"] = str(doc.pop("_id"))
        commands.append(doc)
    return commands


# ---- Commands grouped by identical text (done in MongoDB, over ALL commands) ----

GROUP_SORTS = {"count", "ip_count", "session_count", "last_ts", "first_ts", "text"}


def _group_stages(match: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [
        {"$match": match},
        {"$group": {
            "_id": "$cmd_key",
            "text": {"$first": "$input"},
            "count": {"$sum": 1},
            "ips": {"$addToSet": "$src_ip"},
            "sessions": {"$addToSet": "$session_id"},
            "first_ts": {"$min": "$timestamp"},
            "last_ts": {"$max": "$timestamp"},
        }},
        {"$project": {
            "_id": 0, "key": "$_id", "text": 1, "count": 1,
            "ip_count": {"$size": "$ips"}, "session_count": {"$size": "$sessions"},
            "first_ts": 1, "last_ts": 1,
        }},
    ]


@router.get("/commands/groups")
async def list_command_groups(
    response: Response,
    limit: int = Query(100, ge=1, le=MAX_PAGE),
    skip: int = Query(0, ge=0, le=100_000),
    q: Optional[str] = Query(None, max_length=200, description="command text contains"),
    sort: str = Query("count"),
    order: Literal["asc", "desc"] = "desc",
    current_admin: str = Depends(get_current_admin),
) -> List[Dict[str, Any]]:
    """Distinct commands with how often / by how many IPs they were run.
    X-Total-Count is the number of distinct commands that match."""
    if sort not in GROUP_SORTS:
        raise HTTPException(status_code=422, detail=f"sort must be one of {sorted(GROUP_SORTS)}")
    match: Dict[str, Any] = {"cmd_key": {"$exists": True}}
    if (rx := _contains(q)):
        match["input"] = rx
    db = get_database()

    total = 0
    async for d in await aggregate(db.commands, [{"$match": match}, {"$group": {"_id": "$cmd_key"}}, {"$count": "n"}]):
        total = d["n"]
    response.headers[TOTAL_HEADER] = str(total)

    pipeline = _group_stages(match) + [
        {"$sort": {sort: 1 if order == "asc" else -1, "key": 1}},
        {"$skip": skip},
        {"$limit": limit},
    ]
    return [d async for d in await aggregate(db.commands, pipeline)]


@router.get("/commands/groups/{key}")
async def get_command_group(
    key: str = Path(pattern=KEY_PATTERN),
    current_admin: str = Depends(get_current_admin),
) -> Dict[str, Any]:
    db = get_database()
    async for d in await aggregate(db.commands, _group_stages({"cmd_key": key})):
        return d
    raise HTTPException(status_code=404, detail="Command not found")


@router.get("/commands/groups/{key}/occurrences")
async def list_command_occurrences(
    response: Response,
    key: str = Path(pattern=KEY_PATTERN),
    limit: int = Query(100, ge=1, le=MAX_PAGE),
    skip: int = Query(0, ge=0, le=100_000),
    current_admin: str = Depends(get_current_admin),
) -> List[Dict[str, Any]]:
    db = get_database()
    response.headers[TOTAL_HEADER] = str(await db.commands.count_documents({"cmd_key": key}))
    cursor = db.commands.find({"cmd_key": key}).sort([("timestamp", -1), ("_id", 1)]).skip(skip).limit(limit)
    rows = []
    async for doc in cursor:
        doc["id"] = str(doc.pop("_id"))
        rows.append(doc)
    return rows


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



# ---- Aggregates over ALL IPs (the dashboard's country table and map) ----

def _located_filter() -> Dict[str, Any]:
    return {"geo.found": True, "geo.country_code": {"$type": "string"}}


@router.get("/stats/top-countries")
async def get_top_countries(
    limit: int = Query(10, ge=1, le=50),
    current_admin: str = Depends(get_current_admin),
) -> Dict[str, Any]:
    """Countries ranked by sessions then IPs, across every IP in the database."""
    db = get_database()
    await geo.backfill(db, limit=200)  # locate a few not-yet-located IPs first
    pipeline = [
        {"$match": _located_filter()},
        {"$group": {
            "_id": "$geo.country_code",
            "name": {"$first": "$geo.country"},
            "ips": {"$sum": 1},
            "sessions": {"$sum": {"$ifNull": ["$total_sessions", 0]}},
        }},
        {"$sort": {"sessions": -1, "ips": -1, "_id": 1}},
        {"$limit": limit},
    ]
    countries = [
        {"code": d["_id"], "name": d.get("name") or d["_id"], "ips": d["ips"], "sessions": d["sessions"]}
        async for d in await aggregate(db.ip_intel, pipeline)
    ]
    return {
        "countries": countries,
        "located": await db.ip_intel.count_documents(_located_filter()),
        "total": await db.ip_intel.count_documents({}),
        "pending": await db.ip_intel.count_documents({"geo": {"$exists": False}}),
    }


CELL_DEGREES = 0.5  # same grid as the old in-browser clustering (~55 km)
MAX_DOTS = 2000
_RANK = {"city": 3, "region": 2, "country": 1}


@router.get("/geo/points")
async def get_geo_points(current_admin: str = Depends(get_current_admin)) -> Dict[str, Any]:
    """Map dots for ALL located IPs, grouped into 0.5-degree cells."""
    db = get_database()
    await geo.backfill(db, limit=200)
    pipeline = [
        {"$match": {"geo.found": True, "geo.latitude": {"$ne": None}, "geo.longitude": {"$ne": None}}},
        {"$sort": {"total_sessions": -1, "_id": 1}},  # so $push keeps the busiest IPs first
        {"$group": {
            "_id": {"lat": "$geo.latitude", "lng": "$geo.longitude"},
            "ips": {"$push": "$_id"},
            "sessions": {"$sum": {"$ifNull": ["$total_sessions", 0]}},
            "country": {"$first": "$geo.country"},
            "region": {"$first": "$geo.region"},
            "city": {"$first": "$geo.city"},
            "precision": {"$first": "$geo.precision"},
        }},
    ]
    cells: Dict[str, Dict[str, Any]] = {}
    placed = 0
    async for g in await aggregate(db.ip_intel, pipeline):
        lat, lng, n = g["_id"]["lat"], g["_id"]["lng"], len(g["ips"])
        placed += n
        key = f"{round(lat / CELL_DEGREES)}:{round(lng / CELL_DEGREES)}"
        c = cells.get(key)
        if c is None:
            c = cells[key] = {"key": key, "lat_sum": 0.0, "lng_sum": 0.0, "count": 0, "sessions": 0, "ips": [],
                              "country": None, "region": None, "city": None, "precision": None}
        c["lat_sum"] += lat * n
        c["lng_sum"] += lng * n
        c["count"] += n
        c["sessions"] += g["sessions"]
        c["ips"].extend(g["ips"][:20])
        if _RANK.get(g.get("precision"), 0) > _RANK.get(c["precision"], 0) or c["country"] is None:
            c.update(country=g.get("country"), region=g.get("region"), city=g.get("city"), precision=g.get("precision"))

    dots = []
    for c in cells.values():
        dots.append({
            "key": c["key"], "latitude": c["lat_sum"] / c["count"], "longitude": c["lng_sum"] / c["count"],
            "count": c["count"], "sessions": c["sessions"], "ips": c["ips"][:20],
            "country": c["country"], "region": c["region"], "city": c["city"], "precision": c["precision"],
        })
    dots.sort(key=lambda d: (-d["sessions"], d["key"]))
    located = await db.ip_intel.count_documents({"geo.found": True})
    return {
        "dots": dots[:MAX_DOTS],
        "located": located,
        "unplaced": max(0, located - placed),
        "total": await db.ip_intel.count_documents({}),
        "pending": await db.ip_intel.count_documents({"geo": {"$exists": False}}),
    }
