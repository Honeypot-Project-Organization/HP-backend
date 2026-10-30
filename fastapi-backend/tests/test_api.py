"""
API tests against an in-memory fake MongoDB (mongomock-motor) - no Atlas
needed. From the backend repo root:

    pip install -r requirements-dev.txt
    python -m pytest tests
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
from app.auth import hash_password  # noqa: E402
from app.limiter import limiter  # noqa: E402
from app.main import app  # noqa: E402

INGEST = {"X-Ingest-Key": "i" * 64}


def ev(eventid, session="abc123", **kw):
    base = {"eventid": eventid, "session": session, "src_ip": "203.0.113.9",
            "timestamp": "2026-09-20T10:00:00.000000Z"}
    base.update(kw)
    return base


class ApiTests(unittest.TestCase):
    def setUp(self):
        database._client = AsyncMongoMockClient(tz_aware=True)
        limiter.reset()
        self.client = TestClient(app)
        self.client.__enter__()

    def tearDown(self):
        self.client.__exit__(None, None, None)

    def db(self):
        return database.get_database()

    def run_async(self, coro):
        return self.client.portal.call(lambda: coro)

    def make_admin(self, created_at=None):
        doc = {"username": "admin", "password_hash": hash_password("correct horse battery"),
               "created_at": created_at or datetime.now(timezone.utc) - timedelta(minutes=5)}
        self.run_async(self.db().admins.insert_one(doc))

    def login(self):
        r = self.client.post("/login", json={"username": "admin", "password": "correct horse battery"})
        self.assertEqual(r.status_code, 200, r.text)
        return {"Authorization": f"Bearer {r.json()['access_token']}"}

    # ---- ingest ---------------------------------------------------------
    def test_ingest_requires_key(self):
        self.assertEqual(self.client.post("/ingest", json=ev("cowrie.session.connect")).status_code, 422)
        r = self.client.post("/ingest", json=ev("cowrie.session.connect"), headers={"X-Ingest-Key": "nope"})
        self.assertEqual(r.status_code, 401)

    def test_full_session_and_dedup(self):
        events = [
            ev("cowrie.session.connect", src_port=5555, dst_port=22, protocol="ssh"),
            ev("cowrie.login.failed", username="a", password="b", timestamp="2026-09-20T10:00:01Z"),
            ev("cowrie.login.success", username="root", password="x", timestamp="2026-09-20T10:00:02Z"),
            ev("cowrie.command.input", input="uname -a", timestamp="2026-09-20T10:00:03Z"),
            ev("cowrie.session.file_download", url="http://x.invalid/a", outfile="a",
               shasum="A" * 64, size=10, timestamp="2026-09-20T10:00:04Z"),
            ev("cowrie.session.closed", duration=5.0, timestamp="2026-09-20T10:00:05Z"),
        ]
        r = self.client.post("/ingest/batch", json=events, headers=INGEST)
        self.assertEqual(r.status_code, 202, r.text)
        self.assertEqual(r.json(), {"accepted": 6, "duplicates": 0, "rejected": []})

        r2 = self.client.post("/ingest/batch", json=events, headers=INGEST)
        self.assertEqual(r2.json()["duplicates"], 6)

        s = self.run_async(self.db().sessions.find_one({"_id": "abc123"}))
        self.assertEqual(s["command_count"], 1)
        self.assertEqual(s["download_count"], 1)
        self.assertTrue(s["login_success"])
        self.assertEqual(s["status"], "closed")
        self.assertIsInstance(s["start_time"], datetime)
        self.assertEqual(self.run_async(self.db().auth_attempts.count_documents({})), 2)
        ip = self.run_async(self.db().ip_intel.find_one({"_id": "203.0.113.9"}))
        self.assertEqual(ip["total_sessions"], 1)
        self.assertEqual(ip["total_auth_attempts"], 2)
        self.assertEqual(ip["successful_logins"], 1)
        self.assertEqual(self.run_async(self.db().raw_events.count_documents({})), 6)

    def test_operator_injection_rejected(self):
        bad = [
            ev("cowrie.session.closed", session={"$ne": None}),
            ev("cowrie.session.connect", src_ip={"$gt": ""}),
            ev("cowrie.session.connect", src_ip="not-an-ip"),
            ev("$where"),
            "not an object",
        ]
        r = self.client.post("/ingest/batch", json=bad, headers=INGEST)
        self.assertEqual(r.status_code, 202)
        self.assertEqual(len(r.json()["rejected"]), 5)
        self.assertEqual(self.run_async(self.db().raw_events.count_documents({})), 0)

    def test_raw_keys_sanitized_and_text_truncated(self):
        r = self.client.post(
            "/ingest", headers=INGEST,
            json=ev("cowrie.command.input", input="A" * 10000, **{"$set": 1, "a.b": 2}),
        )
        self.assertEqual(r.status_code, 202, r.text)
        raw = self.run_async(self.db().raw_events.find_one({}))["raw"]
        self.assertNotIn("$set", raw)
        self.assertIn("_set", raw)
        self.assertIn("a_b", raw)
        cmd = self.run_async(self.db().commands.find_one({}))
        self.assertLess(len(cmd["input"]), 4200)

    def test_batch_size_cap(self):
        r = self.client.post("/ingest/batch", headers=INGEST,
                             json=[ev("cowrie.session.connect", session=f"s{i}") for i in range(201)])
        self.assertEqual(r.status_code, 413)

    def test_body_limit_chunked(self):
        def gen():
            for _ in range(30):
                yield b"x" * 50_000
        r = self.client.post("/ingest", content=gen(), headers={**INGEST, "content-type": "application/json"})
        self.assertEqual(r.status_code, 413)

    def test_body_limit_declared(self):
        r = self.client.post("/ingest", content=b"x" * 1_100_000,
                             headers={**INGEST, "content-type": "application/json"})
        self.assertEqual(r.status_code, 413)

    # ---- auth -------------------------------------------------------------
    def test_login_and_protected_routes(self):
        self.make_admin()
        self.assertEqual(self.client.get("/api/stats").status_code, 401)
        headers = self.login()
        r = self.client.get("/api/stats", headers=headers)
        self.assertEqual(r.status_code, 200, r.text)
        self.assertIn("last_event_received_at", r.json())

    def test_bad_login(self):
        self.make_admin()
        self.assertEqual(self.client.post("/login", json={"username": "admin", "password": "wrong"}).status_code, 401)
        self.assertEqual(self.client.post("/login", json={"username": "ghost", "password": "wrong"}).status_code, 401)

    def test_long_password_is_401_not_500(self):
        self.make_admin()
        r = self.client.post("/login", json={"username": "admin", "password": "é" * 100})
        self.assertEqual(r.status_code, 401)

    def test_login_rate_limited(self):
        self.make_admin()
        codes = [self.client.post("/login", json={"username": "admin", "password": "wrong"}).status_code
                 for _ in range(11)]
        self.assertEqual(codes[-1], 429)

    def test_forged_and_none_alg_tokens_rejected(self):
        import jwt
        self.make_admin()
        now = datetime.now(timezone.utc)
        claims = {"sub": "admin", "iat": now, "exp": now + timedelta(hours=1),
                  "iss": "honeypot-api", "aud": "honeypot-dashboard"}
        wrong_key = jwt.encode(claims, "k" * 64, algorithm="HS256")
        none_alg = jwt.encode(claims, None, algorithm="none")
        for tok in (wrong_key, none_alg, "garbage"):
            r = self.client.get("/api/stats", headers={"Authorization": f"Bearer {tok}"})
            self.assertEqual(r.status_code, 401)

    def test_token_revoked_when_admin_recreated(self):
        self.make_admin()
        headers = self.login()
        self.run_async(self.db().admins.update_one(
            {"username": "admin"}, {"$set": {"created_at": datetime.now(timezone.utc) + timedelta(seconds=5)}}))
        self.assertEqual(self.client.get("/api/stats", headers=headers).status_code, 401)

    # ---- dashboard --------------------------------------------------------
    def test_limits_bounded(self):
        self.make_admin()
        headers = self.login()
        for path in ("/api/sessions?limit=0", "/api/sessions?limit=100000", "/api/ips?limit=-1",
                     "/api/stats/top-credentials?limit=0"):
            self.assertEqual(self.client.get(path, headers=headers).status_code, 422, path)
        self.assertEqual(self.client.get("/api/sessions/%7B%24ne%7D/commands", headers=headers).status_code, 422)

    def test_debug_client_ip_requires_auth(self):
        self.assertEqual(self.client.get("/api/debug/client-ip").status_code, 401)
        self.make_admin()
        r = self.client.get("/api/debug/client-ip", headers=self.login())
        self.assertEqual(r.status_code, 200)
        self.assertIn("rate_limit_key", r.json())

    def test_daily_stats_latest_days_with_mixed_timestamp_types(self):
        self.make_admin()
        headers = self.login()
        base = datetime(2026, 1, 1, tzinfo=timezone.utc)
        docs = [{"_id": f"s{i}", "start_time": base + timedelta(days=i)} for i in range(40)]
        docs.append({"_id": "legacy", "start_time": "2025-12-31T23:00:00.000000Z"})  # pre-migration string
        self.run_async(self.db().sessions.insert_many(docs))
        r = self.client.get("/api/stats/daily?days=30", headers=headers)
        self.assertEqual(r.status_code, 200, r.text)
        dates = [d["date"] for d in r.json()]
        self.assertEqual(len(dates), 30)
        self.assertEqual(dates[-1], "2026-02-09")  # newest day included
        self.assertEqual(dates, sorted(dates))       # oldest-first for charting
        r = self.client.get("/api/stats/daily?days=365", headers=headers)
        self.assertEqual(r.json()[0]["date"], "2025-12-31")

    def test_detail_routes(self):
        self.make_admin()
        for e in (ev("cowrie.session.connect", dst_port=22, protocol="ssh"),
                  ev("cowrie.login.success", username="root", password="x"),
                  ev("cowrie.command.input", input="uname -a")):
            self.client.post("/ingest", json=e, headers=INGEST)
        tok = self.client.post("/login", json={"username": "admin", "password": "correct horse battery"}).json()["access_token"]
        h = {"Authorization": f"Bearer {tok}"}
        ip = "203.0.113.9"
        self.assertEqual(self.client.get(f"/api/ips/{ip}", headers=h).json()["ip"], ip)
        self.assertEqual(len(self.client.get(f"/api/ips/{ip}/sessions", headers=h).json()), 1)
        self.assertEqual(self.client.get(f"/api/ips/{ip}/commands", headers=h).json()[0]["input"], "uname -a")
        self.assertEqual(self.client.get("/api/commands", headers=h).json()[0]["input"], "uname -a")
        self.assertEqual(self.client.get("/api/sessions/abc123", headers=h).json()["id"], "abc123")
        self.assertEqual(self.client.get("/api/sessions/nope", headers=h).status_code, 404)
        self.assertEqual(self.client.get("/api/ips/9.9.9.9", headers=h).status_code, 404)
        self.assertEqual(self.client.get("/api/ips/bad%20ip", headers=h).status_code, 422)
        self.assertEqual(self.client.get(f"/api/ips/{ip}").status_code, 401)


    def _seed(self):
        """3 IPs, 5 sessions, commands, so paging/filtering can be checked."""
        base = datetime(2026, 9, 1, tzinfo=timezone.utc)
        sessions = [
            {"_id": f"s{i}", "src_ip": ip, "start_time": base + timedelta(hours=i),
             "login_success": ok, "duration_seconds": float(i), "command_count": i, "username": "u"}
            for i, (ip, ok) in enumerate([("10.0.0.1", True), ("10.0.0.2", False), ("10.0.0.11", False),
                                          ("192.168.1.5", True), ("10.0.0.1", False)])
        ]
        self.run_async(self.db().sessions.insert_many(sessions))
        ips = [{"_id": ip, "total_sessions": n, "first_seen": base, "last_seen": base + timedelta(days=d)}
               for ip, n, d in [("10.0.0.1", 5, 3), ("10.0.0.2", 1, 1), ("10.0.0.11", 2, 2), ("192.168.1.5", 9, 5)]]
        self.run_async(self.db().ip_intel.insert_many(ips))

    def test_sessions_filters_apply_to_all_rows_and_total_header(self):
        self.make_admin()
        h = self.login()
        self._seed()
        r = self.client.get("/api/sessions?limit=2&skip=0", headers=h)
        self.assertEqual(r.headers["x-total-count"], "5")
        self.assertEqual(len(r.json()), 2)
        r = self.client.get("/api/sessions?q=10.0.0.1&limit=1", headers=h)  # matches 10.0.0.1 and 10.0.0.11
        self.assertEqual(r.headers["x-total-count"], "3")
        r = self.client.get("/api/sessions?login=granted", headers=h)
        self.assertEqual(r.headers["x-total-count"], "2")
        r = self.client.get("/api/sessions?login=denied&q=10.0.0.1", headers=h)
        self.assertEqual(r.headers["x-total-count"], "2")
        r = self.client.get("/api/sessions?date_from=2026-09-01T02:00:00Z&date_to=2026-09-01T03:00:00Z", headers=h)
        self.assertEqual(sorted(s["id"] for s in r.json()), ["s2", "s3"])
        r = self.client.get("/api/sessions?sort=duration_seconds&order=asc&limit=1", headers=h)
        self.assertEqual(r.json()[0]["id"], "s0")
        self.assertEqual(self.client.get("/api/sessions?sort=password", headers=h).status_code, 422)
        self.assertEqual(self.client.get("/api/sessions?date_from=2026-09-02T00:00:00Z&date_to=2026-09-01T00:00:00Z",
                                         headers=h).status_code, 422)
        # regex characters in the search box are literal
        r = self.client.get("/api/sessions?q=.*", headers=h)
        self.assertEqual(r.headers["x-total-count"], "0")

    def test_attackers_filters_sort_and_total(self):
        self.make_admin()
        h = self.login()
        self._seed()
        r = self.client.get("/api/ips?sort=total_sessions&order=desc&limit=2", headers=h)
        self.assertEqual([a["ip"] for a in r.json()], ["192.168.1.5", "10.0.0.1"])
        self.assertEqual(r.headers["x-total-count"], "4")
        r = self.client.get("/api/ips?q=10.0.0.1", headers=h)
        self.assertEqual(r.headers["x-total-count"], "2")
        r = self.client.get("/api/ips?date_from=2026-09-03T00:00:00Z", headers=h)  # last_seen >= Sep 3
        self.assertEqual(sorted(a["ip"] for a in r.json()), ["10.0.0.1", "10.0.0.11", "192.168.1.5"])

    def test_command_groups_over_all_commands(self):
        self.make_admin()
        h = self.login()
        for i in range(3):
            for e in (ev("cowrie.session.connect", session=f"c{i}", src_ip=f"10.1.0.{i}"),
                      ev("cowrie.command.input", session=f"c{i}", src_ip=f"10.1.0.{i}", input="uname -a ")):
                self.client.post("/ingest", json=e, headers=INGEST)
        self.client.post("/ingest", json=ev("cowrie.command.input", session="c0", src_ip="10.1.0.0", input="ls",
                                            timestamp="2026-09-20T10:00:05.000000Z"), headers=INGEST)
        r = self.client.get("/api/commands/groups", headers=h)
        self.assertEqual(r.headers["x-total-count"], "2")
        top = r.json()[0]
        self.assertEqual((top["text"].strip(), top["count"], top["ip_count"], top["session_count"]), ("uname -a", 3, 3, 3))
        r = self.client.get("/api/commands/groups?q=LS", headers=h)
        self.assertEqual(r.headers["x-total-count"], "1")
        self.assertEqual(self.client.get(f"/api/commands/groups/{top['key']}", headers=h).json()["count"], 3)
        occ = self.client.get(f"/api/commands/groups/{top['key']}/occurrences?limit=2", headers=h)
        self.assertEqual((len(occ.json()), occ.headers["x-total-count"]), (2, "3"))
        self.assertEqual(self.client.get("/api/commands/groups/" + "0" * 24, headers=h).status_code, 404)
        self.assertEqual(self.client.get("/api/commands/groups/NOTAKEY", headers=h).status_code, 422)

    def test_session_duration_from_seconds_ms_or_timestamps(self):
        self.make_admin()
        h = self.login()
        t0 = "2026-09-20T10:00:00.000000Z"
        cases = {
            "d1": ({"duration": 12.5}, 12.5),
            "d2": ({"duration_ms": 3400}, 3.4),
            "d3": ({}, 30.0),  # neither field: closing time - start time
        }
        for sid, (extra, _) in cases.items():
            self.client.post("/ingest", json=ev("cowrie.session.connect", session=sid, timestamp=t0), headers=INGEST)
            self.client.post("/ingest", json=ev("cowrie.session.closed", session=sid,
                                                timestamp="2026-09-20T10:00:30.000000Z", **extra), headers=INGEST)
        for sid, (_, want) in cases.items():
            got = self.client.get(f"/api/sessions/{sid}", headers=h).json()["duration_seconds"]
            self.assertAlmostEqual(got, want, places=3, msg=sid)

    def test_backfill_repairs_old_rows(self):
        from app import backfill
        t = datetime(2026, 9, 1, tzinfo=timezone.utc)
        self.run_async(self.db().commands.insert_many([
            {"session_id": "a", "src_ip": "1.1.1.1", "timestamp": t, "input": "id"},
            {"session_id": "b", "src_ip": "1.1.1.2", "timestamp": t, "input": " id "},
        ]))
        self.run_async(self.db().sessions.insert_one(
            {"_id": "x", "status": "closed", "start_time": t, "end_time": t + timedelta(seconds=7)}))
        self.run_async(backfill.backfill_command_keys(self.db()))
        self.run_async(backfill.backfill_durations(self.db()))
        keys = {d["cmd_key"] for d in self.client.portal.call(lambda: self.db().commands.find().to_list(10))}
        self.assertEqual(len(keys), 1)  # "id" and " id " are the same command
        self.assertEqual(self.client.portal.call(lambda: self.db().sessions.find_one({"_id": "x"}))["duration_seconds"], 7.0)

    def test_total_count_header_is_exposed_to_the_browser(self):
        r = self.client.options("/api/sessions", headers={"Origin": "http://localhost:5173",
                                                          "Access-Control-Request-Method": "GET"})
        self.assertEqual(r.status_code, 200)
        self.make_admin()
        r = self.client.get("/api/sessions", headers={**self.login(), "Origin": "http://localhost:5173"})
        self.assertIn("x-total-count", r.headers["access-control-expose-headers"].lower())

    def test_security_headers_and_cors(self):
        r = self.client.get("/health")
        self.assertEqual(r.headers["x-content-type-options"], "nosniff")
        self.assertIn("default-src 'none'", r.headers["content-security-policy"])
        pre = self.client.options("/api/stats", headers={"Origin": "https://evil.example",
                                                         "Access-Control-Request-Method": "GET"})
        self.assertNotEqual(pre.headers.get("access-control-allow-origin"), "https://evil.example")

    def test_docs_disabled_by_default(self):
        self.assertEqual(self.client.get("/docs").status_code, 404)
        self.assertEqual(self.client.get("/openapi.json").status_code, 404)



class DriverCompatTests(unittest.TestCase):
    """The helpers must cope with PyMongo's async API (coroutines) AND the
    in-memory fake (plain returns)."""

    def test_aggregate_and_close_handle_both_shapes(self):
        import asyncio

        class Cursor:  # what the fake / old Motor returned directly
            pass

        class SyncAgg:
            def aggregate(self, pipeline):
                return "cursor"

        class AsyncAgg:  # what PyMongo's AsyncCollection does
            async def aggregate(self, pipeline):
                return "cursor"

        class AsyncClose:
            closed = False

            async def close(self):
                AsyncClose.closed = True

        async def run():
            self.assertEqual(await database.aggregate(SyncAgg(), []), "cursor")
            self.assertEqual(await database.aggregate(AsyncAgg(), []), "cursor")
            database._client = AsyncClose()
            await database.close_client()
            self.assertTrue(AsyncClose.closed)
            self.assertIsNone(database._client)

        asyncio.run(run())


class LimiterKeyTests(unittest.TestCase):
    def test_trusted_hops(self):
        from starlette.requests import Request
        from app import limiter as lim
        scope = {"type": "http", "client": ("10.0.0.1", 1),
                 "headers": [(b"x-forwarded-for", b"1.1.1.1, 198.51.100.7")]}
        old = lim.settings.trusted_proxy_hops
        try:
            lim.settings.trusted_proxy_hops = 0
            self.assertEqual(lim.client_ip(Request(scope)), "10.0.0.1")
            lim.settings.trusted_proxy_hops = 1
            self.assertEqual(lim.client_ip(Request(scope)), "198.51.100.7")
        finally:
            lim.settings.trusted_proxy_hops = old


class ConfigTests(unittest.TestCase):
    def build(self, **overrides):
        from app.config import Settings
        values = {"mongo_uri": "mongodb://x", "ingest_api_key": "a" * 40, "jwt_secret_key": "b" * 40}
        values.update(overrides)
        return Settings(**values)

    def test_rejects_placeholders_short_and_equal(self):
        from pydantic import ValidationError
        for bad in (
            {"jwt_secret_key": "replace-with-a-different-long-random-string"},
            {"ingest_api_key": "paste-the-same-value-you-set-in-fastapi-cloud"},
            {"ingest_api_key": "short"},
            {"jwt_secret_key": "a" * 40},
            {"cors_allowed_origin": "*"},
            {"mongo_uri": "mongodb+srv://<user>:<password>@<cluster>.mongodb.net"},
        ):
            with self.assertRaises(ValidationError, msg=str(bad)):
                self.build(**bad)
        self.build()  # a valid config passes


if __name__ == "__main__":
    unittest.main()
