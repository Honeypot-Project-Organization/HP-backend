"""
Repair rows stored by earlier versions of the API. Safe to re-run.

    python scripts/backfill.py

  * commands.cmd_key           (needed for the grouped Commands page)
  * sessions.duration_seconds  (closed sessions with no duration: end - start)
  * ip_intel.geo               (needs the location databases uploaded first)
  * MITRE ATT&CK tags on commands, sessions and IPs (rules: app/mitre.py)

    python scripts/backfill.py --rebuild-mitre
        drops every MITRE tag and recomputes it. Use it after REMOVING or
        changing a rule, while nothing is being ingested. Without the flag,
        tags are only ever added, and only when RULES_VERSION changed.

The API also does this in the background every time it starts, so running
this by hand is optional; it just prints what it did. If you still have
string timestamps from before the security update, run
scripts/migrate_timestamps.py first (durations need real dates).
"""
import argparse
import asyncio
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

from app.backfill import backfill_all, backfill_mitre  # noqa: E402
from app.database import close_client, get_database  # noqa: E402


async def main(rebuild: bool) -> None:
    db = get_database()
    if rebuild:
        print("MITRE rebuild:", await backfill_mitre(db, rebuild=True))
    result = await backfill_all(db)
    print("command keys set:  ", result["command_keys"])
    print("durations filled:  ", result["durations"])
    print("MITRE tags:        ", result["mitre"])
    print("IPs located:       ", result["geo"])
    await close_client()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--rebuild-mitre", action="store_true", help="drop and recompute all MITRE tags")
    asyncio.run(main(ap.parse_args().rebuild_mitre))
