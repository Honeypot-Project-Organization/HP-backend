"""
Tails Cowrie's JSON log and forwards events to the API's /ingest/batch
endpoint. This is the ONLY thing on the honeypot VPS with outbound network
access.

Reliability guarantees:
  * Log rotation: Cowrie starts a new cowrie.json every day (the old one is
    renamed cowrie.json.YYYY-MM-DD). We notice the new file, finish the old
    one, and switch - the pipeline doesn't go quiet after the first midnight.
  * No data loss on restart: after each batch the API accepts, we save
    (file identity, byte offset) to /state. On startup we resume from there,
    including finishing a file that was rotated while we were down.
  * No double counting: re-sent events are ignored by the API (it dedups on
    a hash of each event), so "resend when unsure" is always safe.
  * Floods: events are sent in batches; if the API is down or rate-limits
    us, we back off and retry the SAME batch until it's accepted. Nothing is
    skipped, we just fall behind and catch up.

Env vars:
  INGEST_URL        required, e.g. https://your-app.fastapicloud.dev/ingest
  INGEST_API_KEY    required
  ALLOW_INSECURE_HTTP=1   only for local development against http://
"""
import json
import os
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

import requests

INGEST_URL = os.environ["INGEST_URL"].rstrip("/")
BATCH_URL = os.environ.get("INGEST_BATCH_URL", INGEST_URL + "/batch")
INGEST_API_KEY = os.environ["INGEST_API_KEY"]
LOG_PATH = sys.argv[1] if len(sys.argv) > 1 else "/cowrie-logs/cowrie.json"
STATE_PATH = os.environ.get("SHIPPER_STATE_PATH", "/state/offset.json")

BATCH_MAX_EVENTS = 100          # server accepts up to 200
BATCH_MAX_BYTES = 400_000       # server body cap is 1 MB
BATCH_MAX_WAIT_SECONDS = 2.0    # send a partial batch after this long
POLL_SECONDS = 0.5
REQUEST_TIMEOUT_SECONDS = 30
BACKOFF_START, BACKOFF_MAX = 5, 300
MAX_LINE_BYTES = 1_000_000      # a single log line longer than this is skipped

if not BATCH_URL.startswith("https://") and os.environ.get("ALLOW_INSECURE_HTTP") != "1":
    sys.exit("Refusing to send the ingest key over plain HTTP. Use an https:// INGEST_URL "
             "(or set ALLOW_INSECURE_HTTP=1 for local development only).")


def log(msg: str) -> None:
    print(time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), msg, file=sys.stderr, flush=True)


# ---------------------------------------------------------------- state ---
def file_id(st: os.stat_result) -> Tuple[int, int]:
    return (st.st_dev, st.st_ino)


def load_state() -> Optional[Dict[str, Any]]:
    try:
        with open(STATE_PATH, encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def save_state(fid: Tuple[int, int], offset: int) -> None:
    tmp = STATE_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump({"dev": fid[0], "ino": fid[1], "offset": offset}, f)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, STATE_PATH)  # atomic: never a half-written state file


def find_file_by_id(fid: Tuple[int, int]) -> Optional[str]:
    """Locate a rotated log (cowrie.json.YYYY-MM-DD) by its inode."""
    directory = os.path.dirname(LOG_PATH) or "."
    base = os.path.basename(LOG_PATH)
    for name in sorted(os.listdir(directory)):
        if not name.startswith(base):
            continue
        path = os.path.join(directory, name)
        try:
            if file_id(os.stat(path)) == fid:
                return path
        except FileNotFoundError:
            continue
    return None


# --------------------------------------------------------------- sending ---
def post_batch(events: List[Dict[str, Any]]) -> None:
    """Blocks until the API accepts the batch. Never drops events."""
    backoff = BACKOFF_START
    while True:
        try:
            r = requests.post(
                BATCH_URL,
                json=events,
                headers={"X-Ingest-Key": INGEST_API_KEY},
                timeout=REQUEST_TIMEOUT_SECONDS,
            )
            if r.status_code in (200, 202):
                body = r.json()
                for rej in body.get("rejected", []):
                    ev = events[rej.get("index", 0)] if isinstance(rej.get("index"), int) and rej["index"] < len(events) else {}
                    log(f"API rejected malformed event {ev.get('eventid')!r}: {rej.get('error')}")
                return
            if r.status_code == 401:
                log("API says the ingest key is wrong (401). Check INGEST_API_KEY matches the API's. Retrying...")
            elif r.status_code == 429:
                retry_after = r.headers.get("Retry-After", "")
                if retry_after.isdigit():
                    backoff = max(backoff, int(retry_after))
                log(f"Rate limited (429); waiting {backoff}s")
            elif r.status_code == 413:
                # Shouldn't happen with our batch caps; split and retry halves.
                if len(events) > 1:
                    mid = len(events) // 2
                    post_batch(events[:mid])
                    post_batch(events[mid:])
                    return
                log("Single event too large for the API (413); skipping it.")
                return
            else:
                log(f"API returned {r.status_code}: {r.text[:200]}")
        except requests.RequestException as e:
            log(f"Could not reach API: {e}")
        time.sleep(backoff)
        backoff = min(backoff * 2, BACKOFF_MAX)


# --------------------------------------------------------------- tailing ---
class Batcher:
    def __init__(self) -> None:
        self.events: List[Dict[str, Any]] = []
        self.size = 0
        self.started = 0.0

    def add(self, event: Dict[str, Any], nbytes: int) -> None:
        if not self.events:
            self.started = time.monotonic()
        self.events.append(event)
        self.size += nbytes

    def full(self) -> bool:
        return len(self.events) >= BATCH_MAX_EVENTS or self.size >= BATCH_MAX_BYTES

    def due(self) -> bool:
        return bool(self.events) and time.monotonic() - self.started >= BATCH_MAX_WAIT_SECONDS


def ship_file(path: str, start_offset: int, is_current: bool) -> Tuple[Tuple[int, int], int]:
    """
    Ship `path` from start_offset. For a rotated (old) file, stop at EOF.
    For the live file, keep tailing until Cowrie rotates it, then return.
    Offsets only advance (and are only saved) after the API accepts a batch.
    """
    with open(path, "rb") as f:
        fid = file_id(os.fstat(f.fileno()))
        if start_offset > os.fstat(f.fileno()).st_size:
            log(f"{path} is shorter than the saved offset (truncated?); starting from the top")
            start_offset = 0
        f.seek(start_offset)
        committed = start_offset
        batch = Batcher()
        partial = b""

        def flush() -> None:
            nonlocal committed, batch
            if batch.events:
                post_batch(batch.events)
            committed = f.tell() - len(partial)
            save_state(fid, committed)
            batch = Batcher()

        while True:
            chunk = f.readline(MAX_LINE_BYTES)
            if chunk:
                if not chunk.endswith(b"\n"):
                    if len(partial) + len(chunk) >= MAX_LINE_BYTES:
                        log("Skipping an oversized log line")
                        partial = b""
                        f.readline()  # discard the remainder of the line
                        continue
                    partial += chunk  # line still being written; wait for the rest
                    continue
                line, partial = partial + chunk, b""
                text = line.decode("utf-8", errors="replace").strip()
                if text:
                    try:
                        event = json.loads(text)
                        if isinstance(event, dict):
                            batch.add(event, len(line))
                    except json.JSONDecodeError:
                        log(f"Skipping malformed line: {text[:200]}")
                if batch.full():
                    flush()
                continue

            # At EOF.
            if not is_current:
                flush()
                return fid, committed
            if batch.due():
                flush()

            try:
                rotated = file_id(os.stat(path)) != fid
            except FileNotFoundError:
                rotated = True
            if rotated:
                # Cowrie opened a new file. Drain anything written to the old
                # handle after our last read, ship it, then move on.
                time.sleep(POLL_SECONDS)
                if f.readline(1):
                    f.seek(-1, os.SEEK_CUR)
                    continue
                flush()
                return fid, committed
            if not batch.events and committed != f.tell() - len(partial):
                save_state(fid, f.tell() - len(partial))
                committed = f.tell() - len(partial)
            time.sleep(POLL_SECONDS)


def main() -> None:
    log(f"Tailing {LOG_PATH}, shipping to {BATCH_URL}")
    while not os.path.exists(LOG_PATH):
        log(f"Waiting for {LOG_PATH} to be created by Cowrie...")
        time.sleep(5)

    state = load_state()
    if state:
        saved = (state["dev"], state["ino"])
        current = file_id(os.stat(LOG_PATH))
        if saved != current:
            old = find_file_by_id(saved)
            if old:
                log(f"Finishing {old} (rotated while the shipper was down)")
                ship_file(old, state["offset"], is_current=False)
            else:
                log("Previous log file no longer exists; starting the current file from the top")
            offset = 0
        else:
            offset = state["offset"]
    else:
        # First run: ship today's whole file. The API ignores duplicates,
        # so this is safe even if some were sent before.
        offset = 0

    while True:
        ship_file(LOG_PATH, offset, is_current=True)
        offset = 0  # after a rotation, the new file is read from the start
        while not os.path.exists(LOG_PATH):
            time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
