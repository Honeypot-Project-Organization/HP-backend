"""
MITRE ATT&CK views. Tags are produced by app/mitre.py at ingest time and stored as
`techniques` (a list of IDs) on commands, sessions and ip_intel. Every route needs
the admin JWT. All matches are heuristic - see app/mitre.py.

Counting rules:
  * command-based technique: occurrences = number of commands tagged with it
  * event-based technique:   occurrences = number of events (T1133 connections,
                             T1110.001 failed logins, T1078 successful logins)
  * ips = number of IPs carrying the tag
"""
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Response

from app import mitre
from app.auth import get_current_admin
from app.database import aggregate, get_database

router = APIRouter(prefix="/api/mitre", tags=["mitre"])

MAX_PAGE = 500
TOTAL_HEADER = "X-Total-Count"


def _basis(tid: str) -> str:
    return mitre.CATALOG.get(tid, {}).get("basis") or ("event" if tid in mitre.EVENT_TECHNIQUES else "command")


def _label(tid: str) -> Dict[str, Any]:
    c = mitre.CATALOG.get(tid)
    return {
        "id": tid,
        "name": c["name"] if c else None,
        "tactics": c["tactics"] if c else [],
        "basis": _basis(tid),
    }


async def _command_stats(db: Any) -> Dict[str, Dict[str, Any]]:
    pipeline = [
        {"$match": {"techniques.0": {"$exists": True}}},
        {"$unwind": "$techniques"},
        {"$group": {"_id": "$techniques", "occurrences": {"$sum": 1}, "last": {"$max": "$timestamp"}}},
    ]
    return {d["_id"]: {"occurrences": d["occurrences"], "last": d["last"]} async for d in await aggregate(db.commands, pipeline)}


async def _event_stats(db: Any) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for tid, src in mitre.EVENT_TECHNIQUES.items():
        coll = db[src["collection"]]
        n = await coll.count_documents(src["filter"])
        last = None
        if n:
            doc = await coll.find_one(src["filter"], sort=[(src["time"], -1)], projection={src["time"]: 1})
            last = doc.get(src["time"]) if doc else None
        out[tid] = {"occurrences": n, "last": last}
    return out


async def _ip_counts(db: Any) -> Dict[str, int]:
    pipeline = [
        {"$match": {"techniques.0": {"$exists": True}}},
        {"$unwind": "$techniques"},
        {"$group": {"_id": "$techniques", "ips": {"$sum": 1}}},
    ]
    return {d["_id"]: d["ips"] async for d in await aggregate(db.ip_intel, pipeline)}


async def build_rows(db: Any) -> List[Dict[str, Any]]:
    cmd, ev, ips = await _command_stats(db), await _event_stats(db), await _ip_counts(db)
    rows = []
    for tid in set(cmd) | {t for t, v in ev.items() if v["occurrences"]} | set(ips):
        stat = ev.get(tid) if tid in mitre.EVENT_TECHNIQUES else cmd.get(tid)
        stat = stat or {"occurrences": 0, "last": None}
        rows.append({**_label(tid), "occurrences": stat["occurrences"], "ips": ips.get(tid, 0), "last_seen": stat["last"]})
    rows.sort(key=lambda r: (-r["occurrences"], -r["ips"], r["id"]))
    return rows


@router.get("/catalog")
async def get_catalog(current_admin: str = Depends(get_current_admin)) -> List[Dict[str, Any]]:
    """ID, name, tactics, basis and attack.mitre.org link for every technique the rules can produce."""
    return mitre.public_catalog()


@router.get("/summary")
async def get_summary(current_admin: str = Depends(get_current_admin)) -> Dict[str, Any]:
    """All techniques seen, most frequent first, plus the headline numbers."""
    rows = await build_rows(get_database())

    def top(basis: Optional[str]) -> Optional[Dict[str, Any]]:
        return next((r for r in rows if basis is None or r["basis"] == basis), None)

    return {
        "total_ids": sum(r["occurrences"] for r in rows),
        "unique_ids": len(rows),
        "top": top(None),
        "top_event": top("event"),
        "top_command": top("command"),
        "techniques": rows,
    }


async def _source(db: Any, tid: str):
    """(collection, filter, time field) that counts this technique's occurrences."""
    if tid in mitre.EVENT_TECHNIQUES:
        s = mitre.EVENT_TECHNIQUES[tid]
        return db[s["collection"]], dict(s["filter"]), s["time"]
    return db.commands, {"techniques": tid}, "timestamp"


@router.get("/{tid}/daily")
async def get_daily(
    tid: str = Path(pattern=mitre.TECH_PATTERN),
    days: int = Query(30, ge=1, le=365),
    current_admin: str = Depends(get_current_admin),
) -> List[Dict[str, Any]]:
    """Occurrences per day (UTC) for the latest `days` days that have data, oldest first."""
    db = get_database()
    coll, flt, tfield = await _source(db, tid)
    pipeline = [
        {"$match": {**flt, tfield: {"$type": "date"}}},
        {"$group": {"_id": {"$dateToString": {"format": "%Y-%m-%d", "date": f"${tfield}"}}, "count": {"$sum": 1}}},
        {"$sort": {"_id": -1}},
        {"$limit": days},
    ]
    rows = [{"date": d["_id"], "count": d["count"]} async for d in await aggregate(coll, pipeline)]
    return sorted(rows, key=lambda r: r["date"])


@router.get("/{tid}")
async def get_technique(tid: str = Path(pattern=mitre.TECH_PATTERN), current_admin: str = Depends(get_current_admin)) -> Dict[str, Any]:
    db = get_database()
    coll, flt, tfield = await _source(db, tid)
    occurrences = await coll.count_documents(flt)
    ips = await db.ip_intel.count_documents({"techniques": tid})
    if tid not in mitre.CATALOG and not occurrences and not ips:
        raise HTTPException(status_code=404, detail="Technique not found")

    async def edge(direction: int) -> Any:
        if not occurrences:
            return None
        doc = await coll.find_one(flt, sort=[(tfield, direction)], projection={tfield: 1})
        return doc.get(tfield) if doc else None

    return {
        **_label(tid),
        "url": mitre.technique_url(tid),
        "known": tid in mitre.CATALOG,
        "rules": mitre.rules_for(tid),
        "occurrences": occurrences,
        "ips": ips,
        "sessions": await db.sessions.count_documents({"techniques": tid}),
        "commands": await db.commands.count_documents({"techniques": tid}),
        "first_seen": await edge(1),
        "last_seen": await edge(-1),
    }


async def _page(coll: Any, flt: Dict[str, Any], sort_field: str, response: Response, limit: int, skip: int,
                rename_to: str) -> List[Dict[str, Any]]:
    response.headers[TOTAL_HEADER] = str(await coll.count_documents(flt))
    rows = []
    async for doc in coll.find(flt).sort([(sort_field, -1), ("_id", 1)]).skip(skip).limit(limit):
        doc[rename_to] = str(doc.pop("_id")) if rename_to == "id" else doc.pop("_id")
        rows.append(doc)
    return rows


@router.get("/{tid}/commands")
async def list_commands(
    response: Response, tid: str = Path(pattern=mitre.TECH_PATTERN),
    limit: int = Query(100, ge=1, le=MAX_PAGE), skip: int = Query(0, ge=0, le=100_000),
    current_admin: str = Depends(get_current_admin),
) -> List[Dict[str, Any]]:
    db = get_database()
    return await _page(db.commands, {"techniques": tid}, "timestamp", response, limit, skip, "id")


@router.get("/{tid}/ips")
async def list_ips(
    response: Response, tid: str = Path(pattern=mitre.TECH_PATTERN),
    limit: int = Query(100, ge=1, le=MAX_PAGE), skip: int = Query(0, ge=0, le=100_000),
    current_admin: str = Depends(get_current_admin),
) -> List[Dict[str, Any]]:
    db = get_database()
    return await _page(db.ip_intel, {"techniques": tid}, "last_seen", response, limit, skip, "ip")


@router.get("/{tid}/sessions")
async def list_sessions(
    response: Response, tid: str = Path(pattern=mitre.TECH_PATTERN),
    limit: int = Query(100, ge=1, le=MAX_PAGE), skip: int = Query(0, ge=0, le=100_000),
    current_admin: str = Depends(get_current_admin),
) -> List[Dict[str, Any]]:
    db = get_database()
    return await _page(db.sessions, {"techniques": tid}, "start_time", response, limit, skip, "id")
