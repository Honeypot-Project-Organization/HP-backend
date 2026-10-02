"""
Sends a fake but realistic sequence of Cowrie events to a running API, so
you can verify the whole pipeline works without waiting for a real attacker.
It uses the same /ingest/batch endpoint as the shipper, then re-sends the
batch to prove duplicates are ignored.

Usage (from fastapi-backend/):
    INGEST_URL=http://localhost:8000/ingest \
    INGEST_API_KEY=your-secret \
    python scripts/test_ingest.py
"""
import os
import sys
import uuid
from datetime import datetime, timedelta, timezone

import requests

INGEST_URL = os.environ.get("INGEST_URL", "http://localhost:8000/ingest").rstrip("/")
INGEST_API_KEY = os.environ["INGEST_API_KEY"]

session_id = uuid.uuid4().hex[:12]
src_ip = "203.0.113.42"  # TEST-NET-3, safe to use as a fake example IP
now = datetime.now(timezone.utc)


def ts(offset_seconds: float) -> str:
    return (now + timedelta(seconds=offset_seconds)).isoformat().replace("+00:00", "Z")


events = [
    {"eventid": "cowrie.session.connect", "session": session_id, "src_ip": src_ip,
     "src_port": 51234, "dst_port": 22, "protocol": "ssh", "timestamp": ts(0)},
    {"eventid": "cowrie.client.version", "session": session_id, "src_ip": src_ip,
     "version": "SSH-2.0-libssh_0.9.6", "timestamp": ts(0.5)},
    {"eventid": "cowrie.login.failed", "session": session_id, "src_ip": src_ip,
     "username": "admin", "password": "admin", "timestamp": ts(1)},
    {"eventid": "cowrie.login.success", "session": session_id, "src_ip": src_ip,
     "username": "root", "password": "Summer2024!", "timestamp": ts(2)},
    {"eventid": "cowrie.command.input", "session": session_id, "src_ip": src_ip,
     "input": "uname -a", "timestamp": ts(3)},
    # An XSS-style payload, like real bots send - use it to check that the
    # dashboard shows this as literal text and never runs it.
    {"eventid": "cowrie.command.input", "session": session_id, "src_ip": src_ip,
     "input": "echo '<img src=x onerror=alert(1)>'", "timestamp": ts(4)},
    {"eventid": "cowrie.session.file_download", "session": session_id, "src_ip": src_ip,
     "url": "http://example.invalid/malware.sh", "outfile": "malware.sh",
     "shasum": "0" * 64, "size": 4096, "timestamp": ts(5)},
    {"eventid": "cowrie.session.closed", "session": session_id, "src_ip": src_ip,
     "duration": 6.0, "timestamp": ts(6)},
]

headers = {"X-Ingest-Key": INGEST_API_KEY}

print(f"Sending {len(events)} test events for session {session_id} ...")
first = requests.post(f"{INGEST_URL}/batch", json=events, headers=headers, timeout=30)
print(f"  first send  -> {first.status_code} {first.text}")
second = requests.post(f"{INGEST_URL}/batch", json=events, headers=headers, timeout=30)
print(f"  resend      -> {second.status_code} {second.text}  (expect duplicates={len(events)})")

bad = requests.post(f"{INGEST_URL}/batch", json=events, headers={"X-Ingest-Key": "wrong"}, timeout=30)
print(f"  wrong key   -> {bad.status_code} (expect 401)")

ok = first.ok and second.ok and second.json().get("duplicates") == len(events) and bad.status_code == 401
print("\nPASS" if ok else "\nFAIL - see responses above")
print(f"Check MongoDB: sessions _id='{session_id}', ip_intel for {src_ip}, "
      f"2 auth_attempts, 2 commands, 1 download, {len(events)} raw_events.")
sys.exit(0 if ok else 1)
