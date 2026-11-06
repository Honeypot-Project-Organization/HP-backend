"""
One-off / idempotent repairs for data stored before newer API versions:

  * commands.cmd_key       - lets the API group identical commands in MongoDB
  * sessions.duration_seconds - closed sessions that never got a duration
                               (end_time - start_time is used)
  * ip_intel.geo           - IPs not yet located (needs the uploaded geo DBs)

Safe to run any number of times and while the API is serving. Used by
scripts/backfill.py and, in the background, at API startup.
"""
import logging
from datetime import datetime
from typing import Any, Dict, List

from app import geo
from app.cmdkey import cmd_key
from app.database import aggregate
from app.mitre import EVENT_TECHNIQUES, RULES_VERSION, techniques_for_command

log = logging.getLogger("honeypot.backfill")
BATCH = 1000


async def backfill_command_keys(db: Any) -> int:
    total = 0
    while True:
        texts: Dict[str, int] = {}
        async for d in db.commands.find({"cmd_key": {"$exists": False}}, {"input": 1}).limit(BATCH):
            t = d.get("input")
            texts[t if isinstance(t, str) else ""] = 1
        if not texts:
            return total
        changed = 0
        for text in texts:
            # Match on the exact stored text; a missing/non-string input is treated as "".
            flt: Dict[str, Any] = {"input": text, "cmd_key": {"$exists": False}}
            if text == "":
                flt = {"$or": [{"input": ""}, {"input": None}, {"input": {"$exists": False}}],
                       "cmd_key": {"$exists": False}}
            res = await db.commands.update_many(flt, {"$set": {"cmd_key": cmd_key(text)}})
            changed += getattr(res, "modified_count", 0)
        total += changed
        if changed == 0:  # nothing matched: stop rather than loop forever
            return total


async def backfill_durations(db: Any) -> int:
    done = 0
    flt = {"status": "closed", "duration_seconds": None}
    async for s in db.sessions.find(flt, {"start_time": 1, "end_time": 1}).limit(5000):
        st, en = s.get("start_time"), s.get("end_time")
        if isinstance(st, datetime) and isinstance(en, datetime):
            secs = max(0.0, (en - st).total_seconds())
            await db.sessions.update_one({"_id": s["_id"], "duration_seconds": None},
                                         {"$set": {"duration_seconds": secs}})
            done += 1
    return done


CHUNK = 1000


async def _add_technique(coll: Any, ids: List[Any], tech: str) -> None:
    await coll.update_many({"_id": {"$in": ids}}, {"$addToSet": {"techniques": tech}})


async def _tag_from(db: Any, source: Any, match: Dict[str, Any], id_field: str, target: Any, tech: str) -> int:
    """Add `tech` to every `target` row whose id appears in `source` rows matching `match`."""
    n = 0
    chunk: List[Any] = []
    async for d in await aggregate(source, [{"$match": match}, {"$group": {"_id": f"${id_field}"}}]):
        if d["_id"] is None:
            continue
        chunk.append(d["_id"])
        if len(chunk) >= CHUNK:
            await _add_technique(target, chunk, tech)
            n += len(chunk)
            chunk = []
    if chunk:
        await _add_technique(target, chunk, tech)
        n += len(chunk)
    return n


async def backfill_mitre(db: Any, rebuild: bool = False) -> Dict[str, Any]:
    """
    Tag commands with MITRE techniques, then copy the tags onto their sessions and IPs.
    Skipped when the stored marker says this RULES_VERSION was already applied.
    rebuild=True first DROPS all tags (use when a rule was removed/changed; run while
    nothing is being ingested, otherwise events that arrive meanwhile lose their tags).
    """
    marker = await db.app_meta.find_one({"_id": "mitre"})
    if not rebuild and marker and marker.get("version") == RULES_VERSION:
        return {"skipped": True}

    if rebuild:
        await db.commands.update_many({}, {"$unset": {"techniques": "", "rules_version": ""}})
        await db.sessions.update_many({}, {"$unset": {"techniques": ""}})
        await db.ip_intel.update_many({}, {"$unset": {"techniques": ""}})

    # 1. commands (grouped by identical text, so each distinct command is matched once)
    tagged = 0
    while True:
        texts: Dict[str, int] = {}
        async for d in db.commands.find({"rules_version": {"$ne": RULES_VERSION}}, {"input": 1}).limit(CHUNK):
            t = d.get("input")
            texts[t if isinstance(t, str) else ""] = 1
        if not texts:
            break
        changed = 0
        for text in texts:
            flt: Dict[str, Any] = {"input": text, "rules_version": {"$ne": RULES_VERSION}}
            if text == "":
                flt = {"$or": [{"input": ""}, {"input": None}, {"input": {"$exists": False}}],
                       "rules_version": {"$ne": RULES_VERSION}}
            res = await db.commands.update_many(
                flt, {"$set": {"techniques": techniques_for_command(text), "rules_version": RULES_VERSION}})
            changed += getattr(res, "modified_count", 0)
        tagged += changed
        if changed == 0:
            break

    # 2. sessions and IPs. $addToSet makes every step safe to repeat.
    out = {"skipped": False, "commands": tagged, "sessions": 0, "ips": 0}
    res = await db.sessions.update_many({}, {"$addToSet": {"techniques": "T1133"}})
    out["sessions"] += getattr(res, "modified_count", 0)
    await db.ip_intel.update_many({"total_sessions": {"$gt": 0}}, {"$addToSet": {"techniques": "T1133"}})
    for tech in ("T1110.001", "T1078"):
        flt = EVENT_TECHNIQUES[tech]["filter"]
        out["sessions"] += await _tag_from(db, db.auth_attempts, flt, "session_id", db.sessions, tech)
        out["ips"] += await _tag_from(db, db.auth_attempts, flt, "src_ip", db.ip_intel, tech)

    by_tech_sessions: Dict[str, List[Any]] = {}
    by_tech_ips: Dict[str, List[Any]] = {}
    pipeline = [
        {"$match": {"techniques.0": {"$exists": True}}},
        {"$unwind": "$techniques"},
        {"$group": {"_id": {"t": "$techniques", "s": "$session_id", "i": "$src_ip"}}},
    ]
    async for d in await aggregate(db.commands, pipeline):
        k = d["_id"]
        if k.get("s") is not None:
            by_tech_sessions.setdefault(k["t"], []).append(k["s"])
        if k.get("i") is not None:
            by_tech_ips.setdefault(k["t"], []).append(k["i"])
    for target, groups, key in ((db.sessions, by_tech_sessions, "sessions"), (db.ip_intel, by_tech_ips, "ips")):
        for tech, ids in groups.items():
            ids = list(dict.fromkeys(ids))
            for i in range(0, len(ids), CHUNK):
                await _add_technique(target, ids[i:i + CHUNK], tech)
            out[key] += len(ids)

    await db.app_meta.update_one({"_id": "mitre"}, {"$set": {"version": RULES_VERSION}}, upsert=True)
    return out


async def backfill_all(db: Any) -> Dict[str, Any]:
    out = {
        "command_keys": await backfill_command_keys(db),
        "durations": await backfill_durations(db),
        "mitre": await backfill_mitre(db),
        "geo": 0,
    }
    # Locate IPs in rounds until none are left (or no geo database is available).
    while True:
        n = await geo.backfill(db, limit=500)
        out["geo"] += n
        if n == 0:
            break
    return out


async def run_in_background(db: Any) -> None:
    try:
        result = await backfill_all(db)
        log.info("startup backfill finished: %s", result)
    except Exception:  # noqa: BLE001 - must never take the API down
        log.exception("startup backfill failed")
