"""
IP geolocation from MMDB files (DB-IP Lite or GeoLite2 City / ASN) that you
upload to MongoDB once with scripts/upload_geoip.py.

How it works
  * The .mmdb files are stored in MongoDB as 4 MB chunk documents
    (collections `geoip_chunks` + `geoip_meta`). Not GridFS, and not one
    record per IP range - the whole file is kept intact.
  * The first time a lookup is needed, the API reads the chunks, writes them
    to a temp file and opens it with the `maxminddb` reader. Lookups are
    then in-process and take microseconds.
  * Each attacker IP is looked up once; the result is saved as a `geo`
    sub-document on its `ip_intel` record. The dashboard just reads it.

Design rules
  * Nothing in here may break ingest or the dashboard: every public
    coroutine swallows (and logs) its own errors.
  * If no database has been uploaded, nothing is written - so IPs are
    picked up automatically once you do upload one.
  * This module does not import app.config, so it can be imported (and
    unit-tested) without the API's environment variables.
"""
import asyncio
import hashlib
import logging
import os
import tempfile
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger(__name__)

CHUNK_BYTES = 4 * 1024 * 1024  # well under MongoDB's 16 MB document limit
META_COLLECTION = "geoip_meta"
CHUNK_COLLECTION = "geoip_chunks"
KINDS = ("city", "asn")

# After a failed/empty load, don't ask MongoDB again for this long.
RETRY_SECONDS = 300
# Existing IPs without a `geo` field are filled in this many per API call.
BACKFILL_BATCH = 100
MAX_TEXT = 120


# ------------------------------------------------------------- storage ---
async def store_blob(db: Any, kind: str, data: bytes, meta: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Save one MMDB file as chunks and make it the current version of `kind`.
    Older versions of the same kind are deleted afterwards."""
    if kind not in KINDS:
        raise ValueError(f"kind must be one of {KINDS}")
    sha = hashlib.sha256(data).hexdigest()
    version = sha[:16]
    # Re-uploading identical bytes: clear any partial/previous copy first.
    await db[CHUNK_COLLECTION].delete_many({"kind": kind, "version": version})
    count = 0
    for start in range(0, len(data), CHUNK_BYTES):
        await db[CHUNK_COLLECTION].insert_one(
            {
                "_id": f"{kind}:{version}:{count}",
                "kind": kind,
                "version": version,
                "n": count,
                "data": data[start : start + CHUNK_BYTES],
            }
        )
        count += 1
    doc: Dict[str, Any] = {
        "_id": kind,
        "version": version,
        "chunks": count,
        "size": len(data),
        "sha256": sha,
        "uploaded_at": datetime.now(timezone.utc),
        **(meta or {}),
    }
    await db[META_COLLECTION].replace_one({"_id": kind}, doc, upsert=True)
    await db[CHUNK_COLLECTION].delete_many({"kind": kind, "version": {"$ne": version}})
    return doc


async def load_blob(db: Any, kind: str) -> Optional[Tuple[bytes, Dict[str, Any]]]:
    """Reassemble the current file for `kind`; None if absent or corrupt."""
    meta = await db[META_COLLECTION].find_one({"_id": kind})
    if not meta:
        return None
    parts: List[bytes] = []
    for n in range(int(meta["chunks"])):
        chunk = await db[CHUNK_COLLECTION].find_one({"_id": f"{kind}:{meta['version']}:{n}"})
        if not chunk:
            log.warning("geoip %s: chunk %s missing, ignoring database", kind, n)
            return None
        parts.append(bytes(chunk["data"]))
    data = b"".join(parts)
    if hashlib.sha256(data).hexdigest() != meta.get("sha256"):
        log.warning("geoip %s: checksum mismatch, ignoring database", kind)
        return None
    return data, meta


async def get_status(db: Any) -> Dict[str, Any]:
    """What has been uploaded (metadata only - cheap, never loads the files)."""
    out: Dict[str, Any] = {}
    for kind in KINDS:
        meta = await db[META_COLLECTION].find_one({"_id": kind}, {"_id": 0, "version": 0})
        out[kind] = meta or None
    out["available"] = bool(out["city"] or out["asn"])
    return out


# --------------------------------------------------------------- readers ---
class _State:
    city: Any = None
    asn: Any = None
    source: Optional[str] = None
    checked_at: Optional[float] = None
    lock: Optional[asyncio.Lock] = None


_state = _State()


def reset() -> None:
    """Forget loaded databases (used by tests)."""
    _state.city = _state.asn = _state.source = _state.checked_at = _state.lock = None


def set_readers(city: Any = None, asn: Any = None, source: Optional[str] = None) -> None:
    """Inject readers (used by tests)."""
    _state.city, _state.asn, _state.source = city, asn, source
    _state.checked_at = time.monotonic()


def _open_reader_sync(data: bytes) -> Any:
    import maxminddb  # imported lazily so this module works without it

    fd, path = tempfile.mkstemp(suffix=".mmdb")
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    try:
        return maxminddb.open_database(path)
    finally:
        try:
            os.unlink(path)  # the open reader keeps its own mapping
        except OSError:
            pass  # e.g. Windows: file stays until exit


async def ensure_loaded(db: Any) -> bool:
    """True if at least one database is available. Loads on first use."""
    if _state.city is not None and _state.asn is not None:
        return True
    if _state.lock is None:
        _state.lock = asyncio.Lock()
    async with _state.lock:
        now = time.monotonic()
        stale = _state.checked_at is None or now - _state.checked_at > RETRY_SECONDS
        if stale:
            for kind in KINDS:
                if getattr(_state, kind) is not None:
                    continue
                try:
                    blob = await load_blob(db, kind)
                    if blob:
                        data, meta = blob
                        setattr(_state, kind, await asyncio.to_thread(_open_reader_sync, data))
                        if kind == "city":
                            _state.source = meta.get("source")
                        log.info("geoip %s database loaded (%d bytes)", kind, len(data))
                except Exception:  # noqa: BLE001 - never break the caller
                    log.exception("geoip %s database could not be loaded", kind)
            _state.checked_at = now
    return _state.city is not None or _state.asn is not None


# ---------------------------------------------------------------- lookup ---
def _text(v: Any) -> Optional[str]:
    if not isinstance(v, str):
        return None
    v = v.strip()
    return v[:MAX_TEXT] if v else None


def _en(node: Any) -> Optional[str]:
    names = node.get("names") if isinstance(node, dict) else None
    return _text(names.get("en")) if isinstance(names, dict) else None


def _coord(v: Any, limit: float) -> Optional[float]:
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return None
    return float(v) if -limit <= v <= limit else None


def extract_geo(
    city_rec: Any, asn_rec: Any, now: Optional[datetime] = None, source: Optional[str] = None
) -> Dict[str, Any]:
    """Turn raw MMDB records into the `geo` sub-document. Every input field is
    optional (DB-IP and MaxMind files differ), and the output never contains
    anything but short plain strings and numbers."""
    now = now or datetime.now(timezone.utc)
    c = city_rec if isinstance(city_rec, dict) else {}
    a = asn_rec if isinstance(asn_rec, dict) else {}

    country = c.get("country") if isinstance(c.get("country"), dict) else {}
    code = _text(country.get("iso_code"))
    continent = c.get("continent") if isinstance(c.get("continent"), dict) else {}
    subs = c.get("subdivisions")
    region = _en(subs[0]) if isinstance(subs, list) and subs else None
    city = _en(c.get("city"))
    loc = c.get("location") if isinstance(c.get("location"), dict) else {}
    lat, lng = _coord(loc.get("latitude"), 90), _coord(loc.get("longitude"), 180)
    if lat is None or lng is None:
        lat = lng = None
    radius = loc.get("accuracy_radius")
    radius = int(radius) if isinstance(radius, int) and not isinstance(radius, bool) and radius >= 0 else None

    asn = a.get("autonomous_system_number")
    asn = int(asn) if isinstance(asn, int) and not isinstance(asn, bool) and asn >= 0 else None
    network = _text(a.get("autonomous_system_organization"))

    if city:
        precision = "city"
    elif region:
        precision = "region"
    elif code or _en(country):
        precision = "country"
    else:
        precision = None

    found = bool(precision or asn is not None or network)
    geo: Dict[str, Any] = {"found": found, "looked_up_at": now, "source": _text(source)}
    if not found:
        return geo
    geo.update(
        {
            "country_code": code.upper()[:2] if code else None,
            "country": _en(country),
            "continent_code": _text(continent.get("code")),
            "region": region,
            "city": city,
            "latitude": lat,
            "longitude": lng,
            "accuracy_radius_km": radius,
            "precision": precision,
            "asn": asn,
            "network": network,
        }
    )
    return geo


def _safe_get(reader: Any, ip: str) -> Any:
    if reader is None:
        return None
    try:
        return reader.get(ip)
    except Exception:  # noqa: BLE001 - bad address, IPv6 in IPv4 db, corrupt record...
        return None


def lookup(ip: str, city_reader: Any, asn_reader: Any, source: Optional[str] = None) -> Dict[str, Any]:
    return extract_geo(_safe_get(city_reader, ip), _safe_get(asn_reader, ip), source=source)


# ------------------------------------------------------------ enrichment ---
async def enrich_ip(db: Any, ip: Optional[str]) -> bool:
    """Look up one IP and save `geo` on its ip_intel record, if it has none
    yet. Returns True if something was written. Never raises."""
    try:
        if not ip:
            return False
        if await db.ip_intel.find_one({"_id": ip, "geo": {"$exists": True}}, {"_id": 1}):
            return False
        if not await ensure_loaded(db):
            return False
        geo = lookup(ip, _state.city, _state.asn, _state.source)
        result = await db.ip_intel.update_one({"_id": ip}, {"$set": {"geo": geo}})
        return bool(getattr(result, "matched_count", 1))
    except Exception:  # noqa: BLE001
        log.exception("geoip enrichment failed for %s", ip)
        return False


async def enrich_docs(db: Any, docs: List[Dict[str, Any]], limit: int = BACKFILL_BATCH) -> int:
    """Fill in `geo` for already-fetched ip_intel dicts (key "ip") that lack it,
    saving each to MongoDB too. At most `limit` per call. Never raises."""
    try:
        missing = [d for d in docs if d.get("ip") and "geo" not in d][:limit]
        if not missing or not await ensure_loaded(db):
            return 0
        done = 0
        for d in missing:
            geo = lookup(d["ip"], _state.city, _state.asn, _state.source)
            await db.ip_intel.update_one({"_id": d["ip"]}, {"$set": {"geo": geo}})
            d["geo"] = geo
            done += 1
        return done
    except Exception:  # noqa: BLE001
        log.exception("geoip backfill failed")
        return 0


async def _locate_one(db: Any, ip: str) -> bool:
    geo = lookup(ip, _state.city, _state.asn, _state.source)
    res = await db.ip_intel.update_one({"_id": ip, "geo": {"$exists": False}}, {"$set": {"geo": geo}})
    return bool(getattr(res, "modified_count", 1))


async def backfill(db: Any, limit: int = 500, chunk: int = 25) -> int:
    """Locate up to `limit` IPs that have no `geo` yet, `chunk` lookups at a
    time. Returns how many were saved. Never raises."""
    try:
        if not await ensure_loaded(db):
            return 0
        ips = [d["_id"] async for d in db.ip_intel.find({"geo": {"$exists": False}}, {"_id": 1}).limit(limit)]
        done = 0
        for i in range(0, len(ips), chunk):
            results = await asyncio.gather(*(_locate_one(db, ip) for ip in ips[i:i + chunk]))
            done += sum(1 for r in results if r)
        return done
    except Exception:  # noqa: BLE001
        log.exception("geoip bulk backfill failed")
        return 0
