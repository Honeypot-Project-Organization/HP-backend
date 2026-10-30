# Honeypot backend (FastAPI)

Receives Cowrie events from the honeypot's log shipper (`/ingest`), serves the dashboard API (`/api/*`),
handles the single admin login, and locates attacker IPs from an uploaded DB-IP/GeoLite database.
MongoDB Atlas (M0) is the only datastore.

The API, collections and environment variables are specified in the **contracts** repo. The honeypot,
firewall and the setup guide are in the **assets** repo. The dashboard is the **frontend** repo.

## Run locally
```
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
cp .env.example .env        # fill in; never commit .env
python -m uvicorn app.main:app --reload
python scripts/create_admin.py
python -m pytest tests
```
Easier: use `docker-compose.dev.yml` in the assets repo, which starts this API, MongoDB and the honeypot.

## Deploy (FastAPI Cloud)
Deploy this repo. Dependencies come from `pyproject.toml` (keep it in sync with `requirements.txt`).
Set the variables listed in `.env.example`; `CORS_ALLOWED_ORIGIN` must be the dashboard's URL.
Then create the admin and upload the location databases from your own machine, with a `.env` that points
at Atlas:
```
python scripts/create_admin.py
python scripts/upload_geoip.py --city city.mmdb --asn asn.mmdb
```
Never commit `.env` or `*.mmdb`.

After upgrading from an older version, run `python scripts/backfill.py` once (the API also does the same in
the background when it starts). It adds the grouping key to old commands, fills missing session durations and
locates IPs that have no location yet.

## Layout
`app/` the API (`routers/` ingest, auth, dashboard; `geo.py` locations; `models/`),
`scripts/` one-off tools (create_admin, init_db, migrate_timestamps, test_ingest, upload_geoip, backfill),
`tests/` unit tests (no real database needed).
