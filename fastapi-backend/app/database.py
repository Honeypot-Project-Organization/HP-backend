import inspect
import logging
from typing import Any, Optional

from pymongo import ASCENDING, DESCENDING, AsyncMongoClient
from pymongo.errors import OperationFailure

from app.config import settings

log = logging.getLogger(__name__)

# PyMongo's native async client (Motor is deprecated as of 2026-05-14).
_client: Optional[AsyncMongoClient] = None


def get_client() -> AsyncMongoClient:
    global _client
    if _client is None:
        # tz_aware=True: datetimes come back as timezone-aware UTC, matching
        # what ingest.py writes. serverSelectionTimeoutMS keeps a bad
        # MONGO_URI from hanging startup for the 30s default.
        _client = AsyncMongoClient(
            settings.mongo_uri, tz_aware=True, serverSelectionTimeoutMS=10_000
        )
    return _client


def get_database() -> Any:
    return get_client()[settings.db_name]


async def close_client() -> None:
    """AsyncMongoClient.close() is a coroutine (Motor's was a plain call). The
    isawaitable check also keeps the in-memory test fake working."""
    global _client
    client, _client = _client, None
    if client is not None:
        result = client.close()
        if inspect.isawaitable(result):
            await result


async def aggregate(collection: Any, pipeline: list) -> Any:
    """PyMongo's async aggregate() must be awaited to get the cursor (Motor's
    returned it directly). Handles both so the test fake keeps working."""
    cursor = collection.aggregate(pipeline)
    if inspect.isawaitable(cursor):
        cursor = await cursor
    return cursor


async def ping() -> bool:
    try:
        await get_client().admin.command("ping")
        return True
    except Exception:  # noqa: BLE001 - health check must never raise
        return False


async def _ensure_raw_event_ttl(db: Any) -> None:
    """
    TTL index on raw_events.received_at so old raw events are deleted
    automatically (Atlas M0 has 512 MB total). The normalized collections
    (sessions, commands, ...) are kept - they're small and are what the
    dashboard actually reads.
    """
    info = await db.raw_events.index_information()

    # Older versions of this project created a plain descending index on
    # the same field; the TTL index replaces it.
    if "received_at_-1" in info:
        await db.raw_events.drop_index("received_at_-1")

    days = settings.raw_event_retention_days
    ttl_name = "received_at_ttl"
    if days <= 0:
        if ttl_name in info:
            await db.raw_events.drop_index(ttl_name)
        await db.raw_events.create_index([("received_at", DESCENDING)], name="received_at_-1")
        return

    seconds = days * 86400
    existing = info.get(ttl_name)
    if existing and existing.get("expireAfterSeconds") != seconds:
        try:
            await db.command(
                "collMod", "raw_events",
                index={"name": ttl_name, "expireAfterSeconds": seconds},
            )
            return
        except OperationFailure:
            await db.raw_events.drop_index(ttl_name)
    await db.raw_events.create_index(
        [("received_at", ASCENDING)], name=ttl_name, expireAfterSeconds=seconds
    )


async def create_indexes() -> None:
    """Indexes for every collection the app reads or writes. Safe to re-run."""
    db = get_database()

    # sessions: _id IS the Cowrie session id (string) - no separate id index needed.
    await db.sessions.create_index([("src_ip", ASCENDING)])
    await db.sessions.create_index([("start_time", DESCENDING)])
    await db.sessions.create_index([("src_ip", ASCENDING), ("start_time", DESCENDING)])

    await db.auth_attempts.create_index([("session_id", ASCENDING)])
    await db.auth_attempts.create_index([("src_ip", ASCENDING), ("timestamp", DESCENDING)])

    await db.commands.create_index([("session_id", ASCENDING), ("timestamp", ASCENDING)])
    await db.commands.create_index([("src_ip", ASCENDING), ("timestamp", DESCENDING)])
    await db.commands.create_index([("timestamp", DESCENDING)])
    await db.commands.create_index([("cmd_key", ASCENDING), ("timestamp", DESCENDING)])

    await db.downloads.create_index([("session_id", ASCENDING)])
    await db.downloads.create_index([("sha256", ASCENDING)])
    await db.downloads.create_index([("src_ip", ASCENDING), ("timestamp", DESCENDING)])

    # ip_intel: _id IS the IP address itself - already unique by nature of _id.
    await db.ip_intel.create_index([("last_seen", DESCENDING)])
    await db.ip_intel.create_index([("first_seen", DESCENDING)])
    await db.ip_intel.create_index([("total_sessions", DESCENDING)])
    await db.ip_intel.create_index([("geo.country_code", ASCENDING)])

    # raw_events: _id is a SHA-256 of the event's content (see ingest.py),
    # which is what makes re-sent events idempotent.
    await db.raw_events.create_index([("session_id", ASCENDING)])
    await db.raw_events.create_index([("eventid", ASCENDING)])
    await _ensure_raw_event_ttl(db)

    # Usernames are unique. (create_admin.py is what keeps it to ONE admin.)
    await db.admins.create_index([("username", ASCENDING)], unique=True)
