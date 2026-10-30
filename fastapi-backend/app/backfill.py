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
from typing import Any, Dict

from app import geo
from app.cmdkey import cmd_key

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


async def backfill_all(db: Any) -> Dict[str, int]:
    out = {
        "command_keys": await backfill_command_keys(db),
        "durations": await backfill_durations(db),
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
