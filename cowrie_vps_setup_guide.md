# Honeypot Setup Guide: Atlas, API, Cowrie VPS, Firewall

Three parts, in this order:

1. **MongoDB Atlas.** Stores everything.
2. **The FastAPI backend.** Receives events and serves the dashboard.
3. **The honeypot VPS.** Cowrie plus the log shipper, locked down so it
   can't be used to attack anyone else.

To try the whole pipeline on your own laptop first (no VPS or Atlas
needed), see **Local development** at the end.

> Before exposing port 22 to the internet, get the instructor's OK and check
> your VPS provider's terms of service. See `SECURITY.md`.

---

## Step 0 — MongoDB Atlas

1. **Create the cluster:** Atlas → Build a Database → M0 (free tier), any region.
2. **Create a least-privilege database user:** Atlas → Database Access →
   Add New Database User (username/password auth). Under *Database User
   Privileges*, choose **Specific Privileges → `readWrite` @ `honeypot`**.
   Don't use "Atlas admin". If this password ever leaks, the damage is then
   limited to this one database.
3. **Network Access:** Atlas → Network Access → Add IP Address. Use your API
   host's published outbound IPs if it has any. Otherwise `0.0.0.0/0` is
   the fallback: credentials are still required, and the user above can
   only touch one database.
4. **Get the connection string:** Atlas → Database → Connect → Drivers:
   `mongodb+srv://<user>:<password>@<cluster>.mongodb.net/?retryWrites=true&w=majority`.
   This is your `MONGO_URI`.
5. **Indexes are automatic.** The API creates every index it needs on
   startup, including a TTL index that deletes raw events after
   `RAW_EVENT_RETENTION_DAYS` (default 30), so the 512 MB free tier doesn't
   fill up. You can also run `python scripts/init_db.py` from
   `fastapi-backend/` by hand.
6. **Upgrading from the old version, with data already in Atlas?** Run
   `python scripts/migrate_timestamps.py` once. It converts old
   string timestamps into real dates.

## Step 0b — Deploy the API (FastAPI Cloud or similar)

1. Set these environment variables on the host (full list and comments are
   in `fastapi-backend/.env.example`):
   - `MONGO_URI`, `DB_NAME=honeypot`
   - `INGEST_API_KEY` and `JWT_SECRET_KEY`: two **different** values,
     each generated with
     `python -c "import secrets; print(secrets.token_hex(32))"`
   - `CORS_ALLOWED_ORIGIN`: the dashboard's real URL, e.g.
     `https://your-project.web.app`
   - `ENABLE_API_DOCS=false`
2. Deploy. `https://<your-api>/health` should return `{"status": "ok"}`. A
   503 means the API can't reach Atlas: check `MONGO_URI` and Network
   Access.
3. **Create the admin account** from your own machine, with the same `.env`
   values: `cd fastapi-backend && python scripts/create_admin.py`. The
   password needs at least 14 characters; a passphrase of 4+ random words
   works well.
4. **Rate limiting behind a proxy.** The login limit of 10 per minute is
   per client IP. Behind a platform load balancer, the API may see the
   proxy's IP for everyone. To check:
   - Log in, then call `GET /api/debug/client-ip` with your token.
   - Compare `rate_limit_key` with your real public IP (for example from
     https://ifconfig.me).
   - If they differ, set `TRUSTED_PROXY_HOPS` to the position of your IP in
     `x_forwarded_for`, counting from the right (usually `1`). Redeploy and
     check again.
   - Don't set it higher than needed: entries further left can be spoofed
     by clients.

## Step 1 — VPS baseline setup (before touching Cowrie at all)

1. SSH into your fresh VPS as the provider gives you (usually `root` on port 22).
2. Create a non-root admin user for yourself:
   ```
   adduser youradmin
   usermod -aG sudo youradmin
   ```
3. **Critical: move real admin SSH off port 22 before Cowrie ever touches it.**
   Edit `/etc/ssh/sshd_config`:
   ```
   Port 2200
   PermitRootLogin no
   ```
   Restart sshd: `sudo systemctl restart sshd`
   **Before closing your current session**, open a *second* terminal and confirm you can log in on the new port:
   ```
   ssh -p 2200 youradmin@your-vps-ip
   ```
   Do not proceed until this works — you will lock yourself out otherwise.
4. Basic OS updates: `sudo apt update && sudo apt upgrade -y`

## Step 2 — Install Docker and Docker Compose

```
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER
```
Log out and back in for the group change to apply, then confirm:
```
docker --version
docker compose version
```

## Step 3 — Put the project and the bait files on the VPS

```
git clone <your repo> ~/honeypot      # or copy the folder with scp
cd ~/honeypot/cowrie-vps
```

The bait files aren't in git (see `SECURITY.md`). Copy the contents of the
`honeyfs/` folder from the fake-files bundle into `cowrie-vps/cowrie-honeyfs/`,
keeping the paths (`root/`, `home/dave/`, `etc/`, `opt/`, `var/`). From your
own machine, for example:
```
scp -P 2200 -r honeyfs/* youradmin@your-vps-ip:~/honeypot/cowrie-vps/cowrie-honeyfs/
```
You don't need to register the files with Cowrie by hand. The image build
embeds them into Cowrie's fake filesystem with realistic owners and
permissions (`cowrie/build_fs_pickle.py`).

## Step 4 — Set the shipper's secrets

```
cp .env.example .env
nano .env
```
- `INGEST_URL`: `https://<your-api>/ingest`. It must be `https://`; the
  shipper refuses to send the key over plain HTTP.
- `INGEST_API_KEY`: exactly the same value as on the API.

## Step 5 — Firewall (do this BEFORE starting the honeypot)

**Host rules (ufw).** These protect the VPS itself:
```
sudo ufw default deny incoming
sudo ufw default deny outgoing
sudo ufw allow 2200/tcp        # your real admin SSH
sudo ufw allow 22/tcp          # Cowrie's fake SSH
sudo ufw allow out 53          # DNS
sudo ufw allow out 443/tcp     # HTTPS (the shipper -> your API; apt updates)
sudo ufw allow out 80/tcp      # apt updates
sudo ufw enable
```

**Container rules.** ufw does *not* filter traffic from Docker containers:
Docker inserts its own firewall rules ahead of ufw. The script below adds a
rule in Docker's `DOCKER-USER` chain:
- It drops every new outbound connection from the honeypot's network
  (`172.30.0.0/24`), so an attacker can't use Cowrie to reach anything.
- It blocks the honeypot from reaching services on the VPS itself, such as
  your real SSH.
- Attackers can still connect in.
- The rule persists across reboots.
```
sudo ./firewall/block-honeypot-egress.sh
```
It prints the installed rules and a command to verify them.

## Step 6 — Build

```
docker compose build
```
The build fails with a list of missing files if any bait file named in
`cowrie/honeyfs-manifest.txt` isn't in `cowrie-honeyfs/`. Copy those in and
build again. The Cowrie version is pinned in `cowrie/Dockerfile`
(`COWRIE_VERSION`). If `cowrie/cowrie:3.0.9` won't pull, check
https://hub.docker.com/r/cowrie/cowrie/tags for the current tag and update
that line.

## Step 7 — Start

```
docker compose up -d
docker compose logs -f
```
You should see Cowrie start, and the shipper print `Tailing ... shipping to ...`.

## Step 8 — Test end to end

1. **API only**, from your own machine:
   ```
   cd fastapi-backend
   INGEST_URL=https://<your-api>/ingest INGEST_API_KEY=<key> python scripts/test_ingest.py
   ```
   It should print `PASS`: the batch was accepted, the resend was treated as
   duplicates, and the wrong key got 401.
2. **The real honeypot**, from a machine other than the VPS:
   ```
   ssh root@your-vps-ip       # password: Summer2024! (from cowrie-etc/userdb.txt)
   ls -la ~ ; cat ~/.ssh/id_rsa ; cat /etc/passwd
   ```
   The bait should be there. Within a few seconds the session appears in
   Atlas and on the dashboard.
3. **Egress is blocked.** Inside the fake shell, `wget http://example.com`
   should fail. On the VPS, run the verify command printed in Step 5; it
   should time out.
4. **Forwarding is off:**
   `ssh -N -L 8080:example.com:80 root@your-vps-ip` should be refused.

## Step 9 — Keep it running

- Both containers restart automatically (`restart: unless-stopped`).
- **Health at a glance:** the dashboard's "last event received" time
  (`/api/stats` → `last_event_received_at`) should keep moving. If it stops,
  run `docker compose logs --tail 50 log-shipper`.
- **The shipper is crash-safe.** It saves its position in the log and
  resumes after restarts and daily log rotation. If the API is down it
  waits and retries; nothing is lost.
- **Disk cleanup.** Cowrie keeps a rotated log per day plus session
  recordings. Add a daily cleanup with `sudo crontab -e`:
  ```
  15 3 * * * find /var/lib/docker/volumes/honeypot_cowrie_logs/_data -name 'cowrie.json.*' -mtime +14 -delete
  20 3 * * * find /var/lib/docker/volumes/honeypot_cowrie_state/_data/tty -type f -mtime +14 -delete
  ```
- **Updates:** `sudo apt update && sudo apt upgrade` monthly. To update
  Cowrie, bump `COWRIE_VERSION`, then run `docker compose build --pull &&
  docker compose up -d`, then repeat Step 8.

---

## Local development (no VPS, no Atlas)

From the repo root, with Docker Desktop running:
```
docker compose -f docker-compose.dev.yml up --build
docker compose -f docker-compose.dev.yml exec api python scripts/create_admin.py
ssh -p 2222 root@127.0.0.1            # Summer2024!
```
- API: http://127.0.0.1:8000 (interactive docs at `/docs`)
- MongoDB: `mongodb://127.0.0.1:27017` (MongoDB Compass works)
- Point the frontend's dev server (http://localhost:5173) at
  `http://127.0.0.1:8000`.

The local stack builds even without the bait files. Everything is bound to
127.0.0.1, and its secrets are dev-only.

**Backend tests** (no database needed):
```
cd fastapi-backend
pip install -r requirements-dev.txt
python -m pytest tests
```
