"""
Build-time script (runs inside `docker compose build`, never at runtime).

Cowrie 3.x keeps its whole fake filesystem - names, owners, permissions AND
file contents - in one pickle file. A file only "exists" for an attacker
(ls, cat, stat) if it is in that pickle. This script takes Cowrie's stock
pickle and embeds every file under honeyfs/ into it, with realistic owners
and permissions, so the bait appears with no manual `fsctl` step.

It fails the build if any file listed in honeyfs-manifest.txt is missing,
so a teammate who forgot to copy the bait files gets a clear error instead
of a honeypot with no bait.

Usage: python build_fs_pickle.py <base.pickle> <honeyfs_dir> <manifest> <out.pickle>
"""
import os
import pickle
import stat
import sys
import time
from typing import Any, Dict, List, Optional

# Field indices / types from cowrie/shell/fs.py (Cowrie 3.x).
A_NAME, A_TYPE, A_UID, A_GID, A_SIZE, A_MODE, A_CTIME, A_CONTENTS, A_TARGET, A_REALFILE = range(10)
T_LINK, T_DIR, T_FILE = 0, 1, 2

# Largest bait file we'll embed; the pickle is loaded into memory per session.
MAX_FILE_BYTES = 5_000_000

# (path suffix or exact path, mode) - first match wins. Anything else is 0644.
FILE_MODES = [
    ("/etc/shadow", 0o640),
    ("/etc/sudoers.d/", 0o440),
    ("/.ssh/id_rsa", 0o600),
    ("/.ssh/id_ed25519", 0o600),
    ("/.ssh/authorized_keys", 0o600),
    ("/.git-credentials", 0o600),
    ("/.aws/credentials", 0o600),
    ("/.my.cnf", 0o600),
    ("/.npmrc", 0o600),
    ("/.docker/config.json", 0o600),
    ("/.bash_history", 0o600),
    ("/.env", 0o600),
    ("/.bitcoin/wallet.dat", 0o600),
    ("/crontab", 0o644),
]
DIR_MODES = {".ssh": 0o700, ".aws": 0o700, ".docker": 0o700, ".bitcoin": 0o700, ".backup": 0o700, "root": 0o700}
SHADOW_GID = 42


def fail(msg: str) -> None:
    print(f"\nBUILD FAILED: {msg}\n", file=sys.stderr)
    sys.exit(1)


def load_users(honeyfs: str) -> Dict[str, tuple]:
    """username -> (uid, gid, home) from the bait etc/passwd, if provided."""
    users: Dict[str, tuple] = {"root": (0, 0, "/root")}
    path = os.path.join(honeyfs, "etc", "passwd")
    if os.path.isfile(path):
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) >= 6 and parts[2].isdigit() and parts[3].isdigit():
                    users[parts[0]] = (int(parts[2]), int(parts[3]), parts[5])
    return users


def owner_for(vpath: str, users: Dict[str, tuple]) -> tuple:
    if vpath.startswith("/home/"):
        name = vpath.split("/")[2]
        if name in users:
            return users[name][0], users[name][1]
        return 1000, 1000
    return 0, 0


def file_mode(vpath: str) -> int:
    for pattern, mode in FILE_MODES:
        if vpath.endswith(pattern) or (pattern.endswith("/") and pattern in vpath):
            return mode
    return 0o644


def child(node: List[Any], name: str) -> Optional[List[Any]]:
    return next((c for c in node[A_CONTENTS] if c[A_NAME] == name), None)


def ensure_dir(tree: List[Any], parts: List[str], users: Dict[str, tuple], ctime: int) -> List[Any]:
    node = tree
    walked = ""
    for part in parts:
        walked += "/" + part
        nxt = child(node, part)
        if nxt is None:
            uid, gid = owner_for(walked, users)
            mode = stat.S_IFDIR | DIR_MODES.get(part, 0o755)
            if walked.startswith("/home/") and walked.count("/") == 2:
                mode = stat.S_IFDIR | 0o750
            nxt = [part, T_DIR, uid, gid, 4096, mode, ctime, [], None, None]
            node[A_CONTENTS].append(nxt)
        elif nxt[A_TYPE] != T_DIR:
            fail(f"{walked} is a file in Cowrie's base filesystem but the bait needs it to be a directory")
        node = nxt
    return node


def main() -> None:
    base_pickle, honeyfs, manifest, out = sys.argv[1:5]

    with open(manifest, encoding="utf-8") as f:
        required = [ln.strip() for ln in f if ln.strip() and not ln.lstrip().startswith("#")]
    missing = [p for p in required if not os.path.isfile(os.path.join(honeyfs, p.lstrip("/")))]
    if missing:
        fail(
            "these bait files are missing from cowrie-vps/cowrie-honeyfs/ "
            "(copy them in from the honeyfs bundle - see the setup guide, Step 3):\n  "
            + "\n  ".join(missing)
        )

    with open(base_pickle, "rb") as f:
        tree = pickle.load(f)

    users = load_users(honeyfs)
    added = replaced = 0
    for root, dirs, files in os.walk(honeyfs):
        dirs.sort()
        for name in sorted(files):
            real = os.path.join(root, name)
            vpath = "/" + os.path.relpath(real, honeyfs).replace(os.sep, "/")
            if vpath in ("/README.md", "/PUT_HONEYFS_FILES_HERE.txt") or name == ".gitkeep":
                continue
            if os.path.islink(real):
                fail(f"{vpath} is a symlink - use a regular file")
            size = os.path.getsize(real)
            if size > MAX_FILE_BYTES:
                fail(f"{vpath} is {size} bytes; keep bait files under {MAX_FILE_BYTES} bytes")
            with open(real, "rb") as fh:
                data = fh.read()

            mtime = int(os.path.getmtime(real)) or int(time.time())
            parts = vpath.strip("/").split("/")
            parent = ensure_dir(tree, parts[:-1], users, mtime)
            uid, gid = owner_for(vpath, users)
            if vpath == "/etc/shadow":
                gid = SHADOW_GID
            entry = [parts[-1], T_FILE, uid, gid, len(data), stat.S_IFREG | file_mode(vpath), mtime, data, None, None]

            existing = child(parent, parts[-1])
            if existing is not None:
                if existing[A_TYPE] == T_DIR:
                    fail(f"{vpath} is a directory in Cowrie's base filesystem")
                parent[A_CONTENTS][parent[A_CONTENTS].index(existing)] = entry
                replaced += 1
            else:
                parent[A_CONTENTS].append(entry)
                added += 1

    # Cowrie's stock image ships a sample user "phil". If the bait passwd
    # defines its own users and phil isn't one of them, drop his home dir so
    # the fake box is self-consistent.
    home = child(tree, "home")
    if home is not None and "phil" not in users and len(users) > 1:
        home[A_CONTENTS] = [c for c in home[A_CONTENTS] if c[A_NAME] != "phil"]

    with open(out, "wb") as f:
        pickle.dump(tree, f, protocol=4)
    print(f"fs.pickle built: {added} bait files added, {replaced} replaced, {len(required)} required files present.")


if __name__ == "__main__":
    main()
