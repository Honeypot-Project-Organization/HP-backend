# Honeypot backend (FastAPI API + Cowrie honeypot)

This repo has two parts:

| Folder | What |
|---|---|
| `fastapi-backend/` | the API (everything below). Run its commands from this folder |
| `cowrie-vps/` | the honeypot that runs on the VPS: Cowrie image (pinned version), log shipper, egress firewall script, bait manifest, `docker-compose.yml` |

Also here: the VPS setup guide (`cowrie_vps_setup_guide.md`: Atlas, API, VPS, firewall, location databases) and the
laptop stack `docker-compose.dev.yml` (MongoDB + API + Cowrie + shipper). Adjust these names if your layout differs.

The API for the Cowrie SSH honeypot analytics project. It receives events from the honeypot's log shipper (`/ingest`),
serves the dashboard API (`/api/*`), handles the single admin login, locates attacker IPs from an uploaded DB-IP/GeoLite
database, and tags commands, sessions and IPs with MITRE ATT&CK techniques. MongoDB (Atlas M0 in production) is the only datastore.

Part of a four-repo project: **backend** (this repo), **frontend** (dashboard), **assets** (sprint reports, videos, code analysis, branch protection, design and requirements) and **contracts** (API and database shapes: `docs/api.md`, `docs/database.md`, JSON Schemas).

## Stack
Python 3.12+, FastAPI, PyMongo (async), JWT auth, bcrypt, slowapi rate limits.

## Configuration (`.env`)
Copy `.env.example` to `.env`. Never commit `.env`.

| Variable | Meaning |
|---|---|
| `MONGO_URI` | MongoDB connection string. Atlas: copy from Connect > Drivers. Local: `mongodb://localhost:27017` |
| `DB_NAME` | database name (default `honeypot`; use another name, e.g. `honeypot_test`, for testing) |
| `INGEST_API_KEY` | shared secret the log shipper sends. 32+ characters |
| `JWT_SECRET_KEY` | signs login tokens. 32+ characters, must differ from `INGEST_API_KEY` |
| `JWT_EXPIRE_MINUTES` | token lifetime (default 60) |
| `CORS_ALLOWED_ORIGIN` | the dashboard's exact origin, no trailing slash (not `*`) |
| `TRUSTED_PROXY_HOPS` | reverse proxies in front of the API (0 for local) |
| `RAW_EVENT_RETENTION_DAYS` | raw events older than this are deleted (default 7, 0 = keep) |
| `ENABLE_API_DOCS` | serve `/docs` (keep false in production) |

Generate secrets with `python -c "import secrets; print(secrets.token_hex(32))"`. The app refuses to start if a secret is
short, still a `replace-...` placeholder, or if the two secrets match.

## Run locally
```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
cp .env.example .env            # fill in
python -m uvicorn app.main:app --reload --port 8000
python scripts/create_admin.py  # create the dashboard login
python -m pytest tests          # tests
```
Easier: `docker-compose.dev.yml` starts the API, MongoDB, the honeypot and the shipper together
(`docker compose -f docker-compose.dev.yml up --build`; everything is bound to 127.0.0.1 and its secrets are dev-only).

## Deploy (FastAPI Cloud)
Deploy this repo. Dependencies come from `pyproject.toml` (keep it in sync with `requirements.txt`). Set the variables
above; `CORS_ALLOWED_ORIGIN` must be the dashboard's URL. Then, from your own machine with a `.env` pointing at Atlas:
```bash
python scripts/create_admin.py
python scripts/upload_geoip.py --city city.mmdb --asn asn.mmdb   # optional, for the map
```
Never commit `.env` or `*.mmdb`.

## Scripts
| Script | Purpose |
|---|---|
| `create_admin.py` | create/replace the admin user (invalidates existing tokens) |
| `init_db.py` | create collections and indexes |
| `backfill.py` | tag and fill data stored by older versions (see below) |
| `upload_geoip.py` | upload DB-IP/GeoLite databases into MongoDB (`--relookup` re-locates every IP) |
| `migrate_timestamps.py` | convert old ISO-string timestamps to datetimes |
| `test_ingest.py` | send test events to a running API |

## API overview
Full details are in the contracts repo (`docs/api.md`).
- `GET /health`, `POST /login`
- `POST /ingest`, `POST /ingest/batch` (ingest key, up to 200 events)
- `GET /api/stats*`, `/api/geo/*`, `/api/sessions*`, `/api/ips*`, `/api/commands*`
- `GET /api/mitre/*` (catalog, summary, per-technique detail, daily, linked commands/IPs/sessions)

List endpoints are paged (`limit`, `skip`) and filtered on the server. They return the match count in `X-Total-Count`.
Sessions, IPs and command groups also accept `technique=T1082` style filters.

## MITRE ATT&CK mapping
Rules live in `app/mitre.py`. Command text is split on `; && || |` and matched against regexes; a few techniques come
from events (T1133 per connection, T1110.001 per failed login, T1078 per successful login). Matching is heuristic, not
confirmation. Technique ids and names were checked against ATT&CK v19 on 2026-11-02.

Only technique ids are stored (`techniques` on sessions, commands and `ip_intel`); names and tactics come from the in-code
`CATALOG`. After editing rules, raise `RULES_VERSION` and run:
```bash
python scripts/backfill.py --rebuild-mitre
```

## Backfill
After upgrading from an older version, run `python scripts/backfill.py` once. The API also does this in the background at
startup. It adds the grouping key to old commands, fills missing session durations, locates IPs without a location, and
applies MITRE tags. A marker document in `app_meta` stops the MITRE pass repeating on every start.

## Layout
- `app/` the API: `routers/` (ingest, auth, dashboard, mitre), `mitre.py` rules, `geo.py` locations, `database.py` indexes, `backfill.py`, `models/`
- `scripts/` one-off tools
- `tests/` unit and API tests (`test_mitre.py` needs no database)

## Security notes
Passwords are bcrypt-hashed, login and ingest are rate-limited per client IP, request bodies are capped at 1 MB, raw
events expire automatically, and attacker text is stored as data and never executed. 

## Honeypot (`cowrie-vps/`)
```
attackers -> Cowrie (Docker) -> JSON log -> shipper -> POST /ingest/batch -> this API -> MongoDB
```
- Follow `cowrie_vps_setup_guide.md` on the VPS. Clone only what the VPS needs.
- Set up the firewall (`cowrie-vps/firewall/block-honeypot-egress.sh`) **before** starting the honeypot, so it can't attack others.
- Move your real SSH off port 22 before exposing the honeypot, and get your instructor's OK first.
- Bait files (`cowrie-vps/cowrie-honeyfs/`) are fake but credential-shaped and are kept out of git. The image build refuses to run
  without them unless `REQUIRE_BAIT=false` (dev only).
- Never commit `.env` files, keys or `*.mmdb`. Never reuse a real password as a honeypot login.
