# Security Notes for This Repository

This is an academic honeypot project, designed so the repository can be
public on GitHub.

## Before you expose anything

- **Get sign-off.** Check with the instructor, and read your VPS provider's
  terms of service, before opening port 22 to the internet. Some providers
  restrict honeypots, and all of them will act on abuse complaints.
- **Treat collected data as sensitive.** It contains real IP addresses
  (personal data in many jurisdictions). The passwords attackers try often
  come from real leaked-credential lists. Keep the dashboard private, and
  don't commit exports of real data.

## Honeypot bait - fake, and kept out of git

The bait files (`cowrie-vps/cowrie-honeyfs/`) contain realistic-looking fake
SSH keys, password hashes and API-key-shaped strings. None of them grant
access to anything real. They are **gitignored**: GitHub push protection,
and partner scanners like AWS/Stripe/npm, flag strings with those shapes,
so committing them causes blocked pushes and false alarms. Share the bait
bundle through your team's shared drive instead. The image build refuses to
run if any bait file listed in `cowrie-vps/cowrie/honeyfs-manifest.txt` is
missing.

## What actually needs to stay secret

| Secret | Lives in |
|---|---|
| MongoDB Atlas connection string (least-privilege user: `readWrite` on the `honeypot` DB only) | `fastapi-backend/.env` / the API host's environment |
| `INGEST_API_KEY` (shared by the shipper and the API) | `fastapi-backend/.env` and `cowrie-vps/.env` |
| `JWT_SECRET_KEY` (signs admin logins; must differ from the ingest key) | `fastapi-backend/.env` only |
| Admin password | Never written to a file. Typed into `create_admin.py` (14+ characters) |

Every `.env` is gitignored. `.dockerignore` keeps them out of Docker images.
The API refuses to start if a secret is missing, shorter than 32
characters, still a `replace-…`/`paste-…` placeholder, or if the two
secrets are the same.

## Defenses that are built in

**Honeypot VPS**
- Cowrie runs on an isolated Docker network. A `DOCKER-USER` firewall rule
  (`cowrie-vps/firewall/block-honeypot-egress.sh`) drops every new outbound
  connection from it. It also can't reach services on the VPS itself. Note
  that ufw alone does **not** filter container traffic.
- Cowrie's SSH port forwarding and tunnelling, SFTP and telnet are disabled
  and baked into the image, so the honeypot can't be used as a proxy.
- The Cowrie image version is pinned. Both containers drop all Linux
  capabilities, have `no-new-privileges`, and have memory/CPU/PID limits.
  The shipper runs as a non-root user on a read-only filesystem.
- The shipper only sends over HTTPS, holds only the ingest key, and never
  has database credentials.

**API**
- Ingest: constant-time key check, 120 requests/minute per client IP,
  batches of at most 200 events, and a 1 MB body cap that is enforced even
  for chunked uploads.
- Every event field is type-checked. Session IDs and IPs used in database
  filters must match strict patterns, so operator injection like
  `{"$ne": null}` is rejected. Attacker text is stored only as values, and
  is truncated at 4 KB.
- Duplicate events (resends) are ignored by content hash.
- Login: PyJWT with HS256 hard-coded, plus issuer/audience/expiry checks.
  bcrypt passwords, constant-time handling of unknown usernames, and 10
  attempts per minute per IP. Re-running `create_admin.py` revokes all
  existing tokens.
- Every list endpoint has a bounded `limit`. `/docs` is off by default.
  Strict security headers are on every response. CORS allows only the
  dashboard origin.
- Raw events expire after `RAW_EVENT_RETENTION_DAYS` (default 30).

**Frontend.** See `docs/FRONTEND_SECURITY.md`. All displayed data is
attacker-controlled; render it as text only.

## If a real secret is ever accidentally committed

1. **Rotate it immediately:** new Atlas password, new `INGEST_API_KEY`,
   new `JWT_SECRET_KEY`, whatever leaked. The old value is compromised the
   moment it's pushed, whatever you do to git history afterwards.
2. Only after rotating, consider scrubbing it from history (e.g. with
   `git filter-repo`). Deleting the file in a new commit doesn't remove it
   from earlier commits.

## Commit-time secret checks

Preferred (shared by the whole team):
```
pip install pre-commit
pre-commit install
```
This runs gitleaks and blocks `.env` files on every commit (see
`.pre-commit-config.yaml`). If you can't install it, a lightweight fallback
is `scripts/pre-commit-secret-check.sh` (install instructions are at the
top of the file).

## Keeping dependencies patched

Versions are pinned in `fastapi-backend/requirements.txt` and in the
Dockerfiles. Every few weeks, run `pip-audit -r requirements.txt` (it's
installed by `requirements-dev.txt`), bump anything flagged, and run the
tests.
