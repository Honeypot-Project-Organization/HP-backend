# Database Security: MongoDB Atlas

Jira: HONEYPOT-221 (write-up), HONEYPOT-223 (custom role)

How the project's MongoDB Atlas database is protected, who can reach it, and
how the database users are set up. This file is safe to keep in a public
repo: it describes the configuration, never credentials or connection
strings.

## Why there are no "Security Rules"

Firestore apps need Security Rules because the browser queries the database
directly, so the rules must judge every request. In this project the
browser never connects to MongoDB:

```
Browser (dashboard) ──HTTPS + JWT──┐
                                   ├──► FastAPI backend ──TLS + db user──► MongoDB Atlas
Cowrie log shipper ──HTTPS + key───┘
```

The FastAPI backend is the only client that holds database credentials.
The checks that Firestore rules would make (who is logged in, what they may
read, what they may write) happen in the API before any query runs: JWT
login, strict input validation, and only fixed, bounded queries. Nobody can
send their own database query. See `SECURITY.md` for the API's defenses.

## What Atlas does for us

| Control | What it does |
|---|---|
| TLS in transit | Required on every connection (the API connects with `mongodb+srv`) |
| Encryption at rest | All storage and snapshots are encrypted with AES-256 by default |
| IP access list | Only listed addresses can connect. The API host has no fixed outbound IP, so the list is open (`0.0.0.0/0`), and the login, TLS and the role below are what protect the data |
| Database users and roles | Every connection must log in, and the user's role limits what it can do |
| Console access | Team members use the Atlas web console with MFA; project roles limit who can change settings |

The free tier (M0) has no database auditing, access history, private
endpoints or network peering, so the IP access list and database user roles
are the main controls available.

## Who can reach the data

| Who | How | What they can do |
|---|---|---|
| FastAPI backend | Its own database user (custom role below); the connection string lives only in the API host's environment | Read and write the collections it needs in `honeypot-project`, nothing else |
| Cowrie log shipper | No database credentials; HTTPS to the API with an ingest key | Add events only, after type checks, size limits and rate limits |
| Dashboard users | API login only (bcrypt password, JWT, rate-limited) | View fixed, bounded summaries; no writes |
| Attackers | Only the Cowrie honeypot | What they type is stored as text and never run |
| Team members | Atlas console with MFA | Manage settings according to their project role |

## The API's custom role

The API's database user has one custom role and nothing else. A built-in
`readWrite` role would also let the API write to `admins`, so the role is
built from collection-level privileges instead. All privileges are on the
`honeypot-project` database:

| Resource | Actions | Why |
|---|---|---|
| `sessions`, `commands`, `auth_attempts`, `downloads`, `ip_intel`, `raw_events`, `app_meta` | `find`, `insert`, `update` | Ingest, dashboard reads, MITRE tagging and backfill |
| `admins` | `find` | Dashboard login only reads the admin account |
| `geoip_chunks`, `geoip_meta` | `find` | The API only reads the location data |
| whole database | `createCollection`, `createIndex`, `listCollections`, `listIndexes` | Startup creates indexes (and collections such as `raw_events` if missing) |
| `raw_events` | `collMod`, `dropIndex` | Startup keeps the 7-day TTL index current (see `docs/data-retention.md`) |

The API never deletes documents itself: raw events expire through the TTL
index, which MongoDB runs on the server. If a new version of the API starts
using another collection, add it to the first row before deploying.

After changing the role, restart the API and check that `/health` returns
`{"status": "ok"}` and the dashboard loads. On free clusters a role change
can take up to 30 seconds to apply.

## No permanent admin user

There is no standing admin database user. The one-time scripts need more
than the API's role:

| Script | Writes to |
|---|---|
| `create_admin.py` | `admins` |
| `upload_geoip.py` | `geoip_chunks`, `geoip_meta` |
| `migrate_timestamps.py` | older data in several collections |

To run one, create a **temporary** database user in Atlas (Database Users →
Add New Database User → turn on "Temporary User", e.g. 6 hours) with
`readWrite` on `honeypot-project`. Use its connection string in your local
`.env` only while the script runs, then switch back. Atlas deletes the user
automatically, so an admin login exists only for that window.

## If a connection string leaks

1. In Atlas, change that user's password right away (or delete a temporary
   user).
2. Update `MONGO_URI` on the API host and redeploy, then check `/health`.
3. Rotating is what fixes a leak; removing it from git history afterwards
   doesn't (see `SECURITY.md`).

## References

- [Configure security features for clusters](https://www.mongodb.com/docs/atlas/setup-cluster-security/)
- [Configure custom database roles](https://www.mongodb.com/docs/atlas/security-add-mongodb-roles/)
- [Custom role actions](https://www.mongodb.com/docs/atlas/reference/custom-role-actions/)
- [Free and Flex cluster limitations](https://www.mongodb.com/docs/atlas/reference/free-shared-limitations/)
