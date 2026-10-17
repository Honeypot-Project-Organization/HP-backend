"""
Tests for IP geolocation (app/geo.py) and its hooks in ingest and the
dashboard. Uses fake MMDB readers - no real database file needed.
Run from the backend repo root:   python -m pytest tests
"""
import os
import unittest
from datetime import datetime, timedelta, timezone

os.environ.update(
    {
        "MONGO_URI": "mongodb://unused-in-tests",
        "INGEST_API_KEY": "i" * 64,
        "JWT_SECRET_KEY": "j" * 64,
        "CORS_ALLOWED_ORIGIN": "http://localhost:5173",
        "TRUSTED_PROXY_HOPS": "0",
    }
)

from fastapi.testclient import TestClient  # noqa: E402
from mongomock_motor import AsyncMongoMockClient  # noqa: E402

import app.database as database  # noqa: E402
import app.geo as geo  # noqa: E402
from app.auth import hash_password  # noqa: E402
from app.config import settings  # noqa: E402
from app.limiter import limiter  # noqa: E402
from app.main import app  # noqa: E402

INGEST = {"X-Ingest-Key": "i" * 64}
IP = "203.0.113.9"

CITY_RECORD = {
    "continent": {"code": "EU"},
    "country": {"iso_code": "de", "names": {"en": "Germany"}},
    "subdivisions": [{"names": {"en": "Hesse"}}],
    "city": {"names": {"en": "Frankfurt am Main"}},
    "location": {"latitude": 50.11, "longitude": 8.68},
}
ASN_RECORD = {"autonomous_system_number": 14061, "autonomous_system_organization": "DIGITALOCEAN-ASN"}


class FakeReader:
    def __init__(self, table):
        self.table = table

    def get(self, ip):
        if ip == "bad":
            raise ValueError("not an address")
        return self.table.get(ip)


class ExtractGeoTests(unittest.TestCase):
    def test_city_level(self):
        g = geo.extract_geo(CITY_RECORD, ASN_RECORD, source="dbip")
        self.assertTrue(g["found"])
        self.assertEqual((g["country_code"], g["country"], g["region"], g["city"]), ("DE", "Germany", "Hesse", "Frankfurt am Main"))
        self.assertEqual((g["latitude"], g["longitude"]), (50.11, 8.68))
        self.assertEqual(g["precision"], "city")
        self.assertIsNone(g["accuracy_radius_km"])  # DB-IP records have none
        self.assertEqual((g["asn"], g["network"]), (14061, "DIGITALOCEAN-ASN"))
        self.assertEqual(g["source"], "dbip")

    def test_country_only_and_missing_fields(self):
        g = geo.extract_geo({"country": {"iso_code": "FR", "names": {"en": "France"}}}, None)
        self.assertEqual(g["precision"], "country")
        self.assertIsNone(g["latitude"])
        self.assertIsNone(g["asn"])

    def test_not_found(self):
        for rec in (None, {}, "garbage", {"country": "nope"}):
            g = geo.extract_geo(rec, None)
            self.assertFalse(g["found"])
            self.assertNotIn("country", g)

    def test_hostile_and_invalid_values(self):
        rec = {
            "country": {"iso_code": "US", "names": {"en": "<script>" + "x" * 500}},
            "location": {"latitude": 999, "longitude": 10},
        }
        g = geo.extract_geo(rec, {"autonomous_system_number": "AS1", "autonomous_system_organization": 5})
        self.assertLessEqual(len(g["country"]), geo.MAX_TEXT)
        self.assertIsNone(g["latitude"])  # out of range -> both dropped
        self.assertIsNone(g["longitude"])
        self.assertIsNone(g["asn"])
        self.assertIsNone(g["network"])

    def test_lookup_swallows_reader_errors(self):
        g = geo.lookup("bad", FakeReader({}), FakeReader({}))
        self.assertFalse(g["found"])


class GeoDbBase(unittest.TestCase):
    def setUp(self):
        database._client = AsyncMongoMockClient(tz_aware=True)
        limiter.reset()
        geo.reset()
        self.client = TestClient(app)
        self.client.__enter__()

    def tearDown(self):
        geo.reset()
        self.client.__exit__(None, None, None)

    def db(self):
        return database.get_database()

    def run_async(self, coro):
        return self.client.portal.call(lambda: coro)

    def make_admin(self):
        doc = {"username": "admin", "password_hash": hash_password("correct horse battery"),
               "created_at": datetime.now(timezone.utc) - timedelta(minutes=5)}
        self.run_async(self.db().admins.insert_one(doc))

    def auth(self):
        self.make_admin()
        tok = self.client.post("/login", json={"username": "admin", "password": "correct horse battery"}).json()["access_token"]
        return {"Authorization": f"Bearer {tok}"}

    def seed_ip(self, ip=IP):
        now = datetime.now(timezone.utc)
        self.run_async(self.db().ip_intel.insert_one(
            {"_id": ip, "first_seen": now, "last_seen": now, "total_sessions": 1, "total_commands": 0,
             "total_auth_attempts": 0, "successful_logins": 0, "threat_score": 0.0, "updated_at": now}))

    def inject(self):
        geo.set_readers(FakeReader({IP: CITY_RECORD}), FakeReader({IP: ASN_RECORD}), source="dbip")


class StorageTests(GeoDbBase):
    def test_chunk_roundtrip_and_replacement(self):
        old = geo.CHUNK_BYTES
        geo.CHUNK_BYTES = 10
        try:
            data = bytes(range(256)) * 3
            meta = self.run_async(geo.store_blob(self.db(), "city", data, {"source": "dbip"}))
            self.assertGreater(meta["chunks"], 1)
            loaded, m = self.run_async(geo.load_blob(self.db(), "city"))
            self.assertEqual(loaded, data)
            self.assertEqual(m["source"], "dbip")

            new = b"second version " * 5
            self.run_async(geo.store_blob(self.db(), "city", new))
            self.assertEqual(self.run_async(geo.load_blob(self.db(), "city"))[0], new)
            left = self.run_async(self.db()[geo.CHUNK_COLLECTION].count_documents({"kind": "city"}))
            self.assertEqual(left, self.run_async(geo.load_blob(self.db(), "city"))[1]["chunks"])  # old chunks deleted
        finally:
            geo.CHUNK_BYTES = old

    def test_missing_chunk_or_bad_checksum_is_ignored(self):
        self.run_async(geo.store_blob(self.db(), "asn", b"abc" * 10))
        self.run_async(self.db()[geo.META_COLLECTION].update_one({"_id": "asn"}, {"$set": {"sha256": "0" * 64}}))
        self.assertIsNone(self.run_async(geo.load_blob(self.db(), "asn")))
        self.assertIsNone(self.run_async(geo.load_blob(self.db(), "city")))  # never uploaded

    def test_status(self):
        s = self.client.get("/api/geo/status")
        self.assertEqual(s.status_code, 401)
        h = self.auth()
        self.assertFalse(self.client.get("/api/geo/status", headers=h).json()["available"])
        self.run_async(geo.store_blob(self.db(), "city", b"x", {"source": "dbip"}))
        st = self.client.get("/api/geo/status", headers=h).json()
        self.assertTrue(st["available"])
        self.assertEqual(st["city"]["source"], "dbip")
        self.assertNotIn("version", st["city"])


class EnrichmentTests(GeoDbBase):
    def test_no_database_uploaded_writes_nothing(self):
        self.seed_ip()
        self.assertFalse(self.run_async(geo.enrich_ip(self.db(), IP)))
        self.assertNotIn("geo", self.run_async(self.db().ip_intel.find_one({"_id": IP})))

    def test_enrich_ip_once(self):
        self.seed_ip()
        self.inject()
        self.assertTrue(self.run_async(geo.enrich_ip(self.db(), IP)))
        saved = self.run_async(self.db().ip_intel.find_one({"_id": IP}))["geo"]
        self.assertEqual(saved["country_code"], "DE")
        self.assertEqual(saved["asn"], 14061)
        # second call does nothing
        self.assertFalse(self.run_async(geo.enrich_ip(self.db(), IP)))

    def test_unknown_ip_is_marked_not_found(self):
        self.seed_ip("198.51.100.4")
        self.inject()
        self.run_async(geo.enrich_ip(self.db(), "198.51.100.4"))
        saved = self.run_async(self.db().ip_intel.find_one({"_id": "198.51.100.4"}))["geo"]
        self.assertFalse(saved["found"])

    def test_ingest_connect_event_adds_geo(self):
        self.inject()
        ev = {"eventid": "cowrie.session.connect", "session": "abc123", "src_ip": IP, "src_port": 5555,
              "dst_port": 22, "protocol": "ssh", "timestamp": "2026-09-20T10:00:00.000000Z"}
        self.assertEqual(self.client.post("/ingest", json=ev, headers=INGEST).status_code, 202)
        doc = self.run_async(self.db().ip_intel.find_one({"_id": IP}))
        self.assertEqual(doc["geo"]["city"], "Frankfurt am Main")

    def test_ingest_still_works_without_database(self):
        ev = {"eventid": "cowrie.session.connect", "session": "abc123", "src_ip": IP, "dst_port": 22,
              "protocol": "ssh", "timestamp": "2026-09-20T10:00:00.000000Z"}
        self.assertEqual(self.client.post("/ingest", json=ev, headers=INGEST).status_code, 202)
        self.assertNotIn("geo", self.run_async(self.db().ip_intel.find_one({"_id": IP})))

    def test_dashboard_backfills_existing_ips(self):
        self.seed_ip()
        self.inject()
        h = self.auth()
        rows = self.client.get("/api/ips", headers=h).json()
        self.assertEqual(rows[0]["geo"]["country"], "Germany")
        self.assertIn("geo", self.run_async(self.db().ip_intel.find_one({"_id": IP})))  # persisted
        one = self.client.get(f"/api/ips/{IP}", headers=h).json()
        self.assertEqual(one["geo"]["region"], "Hesse")


class RetentionDefaultTests(unittest.TestCase):
    def test_raw_event_retention_default_is_seven_days(self):
        self.assertEqual(settings.raw_event_retention_days, 7)


if __name__ == "__main__":
    unittest.main()
