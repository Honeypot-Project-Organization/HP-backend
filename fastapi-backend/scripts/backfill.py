"""
Repair rows stored by earlier versions of the API. Safe to re-run.

    python scripts/backfill.py

  * commands.cmd_key           (needed for the grouped Commands page)
  * sessions.duration_seconds  (closed sessions with no duration: end - start)
  * ip_intel.geo               (needs the location databases uploaded first)

The API also does this in the background every time it starts, so running
this by hand is optional; it just prints what it did. If you still have
string timestamps from before the security update, run
scripts/migrate_timestamps.py first (durations need real dates).
"""
import asyncio
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

from app.backfill import backfill_all  # noqa: E402
from app.database import close_client, get_database  # noqa: E402


async def main() -> None:
    result = await backfill_all(get_database())
    print("command keys set:  ", result["command_keys"])
    print("durations filled:  ", result["durations"])
    print("IPs located:       ", result["geo"])
    await close_client()


if __name__ == "__main__":
    asyncio.run(main())
