"""
One-time upload of the IP-location databases to MongoDB.

1. Download the MMDB files (NOT the CSV ones) and unpack them:
     DB-IP Lite:  "IP to City Lite" (+ optionally "IP to ASN Lite") from https://db-ip.com/db/
     or MaxMind:  GeoLite2 City (+ optionally GeoLite2 ASN)
2. From the backend repo root, with your .env pointing at the database:

     python scripts/upload_geoip.py --city path/to/city.mmdb [--asn path/to/asn.mmdb]

Each file is checked first (it must open as an MMDB and resolve 8.8.8.8), so a
wrong or corrupted file fails here instead of silently showing no locations.
Re-running replaces the stored copy. Add --relookup afterwards to forget every
saved location so all IPs are looked up again with the new database.

Never commit the .mmdb files (they are large and covered by their providers'
licences; *.mmdb is in .gitignore).
"""
import argparse
import asyncio
import sys
from pathlib import Path
from typing import Any, Dict, Optional

sys.path.append(str(Path(__file__).resolve().parent.parent))

from app.geo import extract_geo, store_blob  # noqa: E402

MAX_BYTES = 250 * 1024 * 1024
TEST_IP = "8.8.8.8"


def fail(msg: str) -> None:
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(1)


def check_file(path: Path, kind: str, force: bool) -> bytes:
    """Validate one MMDB file and return its bytes."""
    try:
        import maxminddb
    except ImportError:
        fail("The 'maxminddb' package is missing. Run: pip install -r requirements.txt")
    if not path.is_file():
        fail(f"{path} does not exist.")
    data = path.read_bytes()
    if not data or len(data) > MAX_BYTES:
        fail(f"{path} is empty or larger than {MAX_BYTES // (1024 * 1024)} MB - is it the right file?")
    if path.suffix.lower() == ".csv":
        fail(f"{path} is a CSV. Download the MMDB version instead.")
    try:
        reader = maxminddb.open_database(str(path))
    except Exception as exc:  # noqa: BLE001
        fail(f"{path} is not a readable MMDB file: {exc}")
    meta = reader.metadata()
    db_type = (meta.database_type or "").lower()
    if kind not in db_type:
        fail(f"{path} reports type '{meta.database_type}', which doesn't look like a {kind.upper()} database. "
             f"Did you swap --city and --asn?")
    try:
        record = reader.get(TEST_IP)
    finally:
        reader.close()
    print(f"[{kind}] {path.name}: type={meta.database_type}, built={meta.build_epoch}, {len(data) / 1e6:.1f} MB")
    if kind == "city":
        geo = extract_geo(record, None)
        print(f"       test lookup {TEST_IP} -> country={geo.get('country')!r} region={geo.get('region')!r} "
              f"city={geo.get('city')!r} lat/lng={geo.get('latitude')}/{geo.get('longitude')}")
        if not geo.get("country_code") and not force:
            fail("The test lookup returned no country. Use --force only if you are sure the file is right.")
    else:
        geo = extract_geo(None, record)
        print(f"       test lookup {TEST_IP} -> AS{geo.get('asn')} {geo.get('network')!r}")
        if geo.get("asn") is None and not force:
            fail("The test lookup returned no ASN. Use --force only if you are sure the file is right.")
    return data


async def run(city: Optional[Path], asn: Optional[Path], source: str, relookup: bool, force: bool) -> None:
    from pymongo import AsyncMongoClient

    from app.config import settings

    blobs: Dict[str, Any] = {}
    if city:
        blobs["city"] = check_file(city, "city", force)
    if asn:
        blobs["asn"] = check_file(asn, "asn", force)

    client = AsyncMongoClient(settings.mongo_uri, tz_aware=True, serverSelectionTimeoutMS=10_000)
    try:
        db = client[settings.db_name]
        for kind, data in blobs.items():
            doc = await store_blob(db, kind, data, {"source": source})
            print(f"[{kind}] stored {doc['chunks']} chunk(s), {doc['size'] / 1e6:.1f} MB, version {doc['version']}")
        if relookup:
            result = await db.ip_intel.update_many({}, {"$unset": {"geo": ""}})
            print(f"Cleared saved locations on {result.modified_count} IP record(s); they will be looked up again.")
        print("Done. The API loads the database on its next start (or within ~5 minutes of its first lookup).")
    finally:
        await client.close()


def main() -> None:
    p = argparse.ArgumentParser(description="Upload IP-location MMDB files to MongoDB.")
    p.add_argument("--city", type=Path, help="City database (.mmdb)")
    p.add_argument("--asn", type=Path, help="ASN database (.mmdb), optional")
    p.add_argument("--source", default="dbip", help="label stored with the data (default: dbip)")
    p.add_argument("--relookup", action="store_true", help="forget all saved locations after uploading")
    p.add_argument("--force", action="store_true", help="skip the 8.8.8.8 sanity check")
    args = p.parse_args()
    if not args.city and not args.asn:
        p.error("give at least --city or --asn")
    asyncio.run(run(args.city, args.asn, args.source, args.relookup, args.force))


if __name__ == "__main__":
    main()
