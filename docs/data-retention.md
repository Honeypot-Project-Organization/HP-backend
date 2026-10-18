# Data Retention: raw_events (7 days)

Jira: HONEYPOT-206

Raw Cowrie events in the `raw_events` collection are deleted automatically
after **7 days**. Everything the dashboard reads (`sessions`, `commands`,
`auth_attempts`, `downloads`, `ip_intel`) is **kept**; only the raw event
copies expire.

## Why

The project runs on the MongoDB Atlas free tier (M0, 512 MB total).
`raw_events` is by far the largest collection, so without a limit it would
fill the cluster. Keeping a week of raw events leaves enough history to
debug the pipeline while the normalized collections keep the long-term data.

## How it works

| Piece | Value |
|---|---|
| Setting | `RAW_EVENT_RETENTION_DAYS` (env var), read as `raw_event_retention_days` in `fastapi-backend/app/config.py` |
| Default | `7` (set in `config.py` and `.env.example`) |
| Index name | `received_at_ttl` on `raw_events.received_at` (ascending) |
| Index option | `expireAfterSeconds = days × 86400` → **604800** for 7 days |
| Created by | `_ensure_raw_event_ttl()` in `fastapi-backend/app/database.py`, which runs on every backend startup |

On startup the backend checks the index:

- If `received_at_ttl` is missing, it creates it.
- If it exists with a different `expireAfterSeconds`, it updates it in place
  (`collMod`), or drops and recreates it if that fails.
- If `RAW_EVENT_RETENTION_DAYS` is `0` or less, the TTL index is removed and
  raw events are kept forever (a plain `received_at_-1` index is used
  instead).

MongoDB's TTL monitor runs about once a minute and deletes documents whose
`received_at` is older than the limit. The first cleanup after a change can
take several minutes on a large collection.

> **Important:** because the backend resets the index on every startup, the
> server's `RAW_EVENT_RETENTION_DAYS` value is what actually wins. Changing
> the index by hand in Atlas only lasts until the next backend restart.

## Changing the retention period

1. Set `RAW_EVENT_RETENTION_DAYS=<days>` in the backend's environment
   (FastAPI Cloud environment variables, or `.env` for local runs).
2. Restart or redeploy the backend.
3. Verify in Atlas (below).

Shortening the period deletes older events within a few minutes and cannot
be undone. Export `raw_events` first if the old data is needed.

## Verifying in Atlas

1. Atlas → Data Explorer → `honeypot-project` → `raw_events` → **Indexes**.
2. Hover the **TTL ⓘ** badge on `received_at_ttl`. It should read
   `expireAfterSeconds: 604800`.
3. **Documents** tab → Options → Sort `{ "received_at": 1 }` → Find. The
   oldest event should be no more than 7 days old.

## History

| Date | Change |
|---|---|
| 2026-10-13 | TTL index changed from 30 days (2592000 s) to 7 days in Atlas by hand. `raw_events` dropped from ~266K to ~130K documents. |
| 2026-10-16 | A backend restart with the old 30-day default reset the index to 2592000 s. |
| 2026-10-17 | Code default changed to 7 days (HP-backend PR #10) and `RAW_EVENT_RETENTION_DAYS=7` set in FastAPI Cloud. Index verified at 604800 s (~11K documents). |
