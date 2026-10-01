"""
One-time migration for data ingested BEFORE the security update, when
timestamps were stored as ISO strings instead of real dates.

Run once from fastapi-backend/ (safe to re-run - it only touches string
values):   python scripts/migrate_timestamps.py

Newer data is already stored as dates. The dashboard copes with mixed data,
but sorting by time is only fully correct once this has run.
"""
import asyncio
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

from app.database import get_client, get_database  # noqa: E402

FIELDS = {
    "sessions": ["start_time", "end_time"],
    "auth_attempts": ["timestamp"],
    "commands": ["timestamp"],
    "downloads": ["timestamp"],
    "ip_intel": ["first_seen", "last_seen"],
}


def parse(value: str):
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


async def main() -> None:
    db = get_database()
    for collection, fields in FIELDS.items():
        for field in fields:
            converted = skipped = 0
            async for doc in db[collection].find({field: {"$type": "string"}}, {field: 1}):
                dt = parse(doc[field])
                if dt is None:
                    skipped += 1
                    continue
                await db[collection].update_one({"_id": doc["_id"]}, {"$set": {field: dt}})
                converted += 1
            print(f"{collection}.{field}: converted {converted}, unparseable {skipped}")
    get_client().close()


if __name__ == "__main__":
    asyncio.run(main())
