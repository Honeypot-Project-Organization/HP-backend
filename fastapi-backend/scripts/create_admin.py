"""
One-time script to create (or replace) the single admin account.
Run manually from the backend repo root:  python scripts/create_admin.py

Never called by the running app - there is no API route that reaches this
logic, so there is no way to create an admin account except by running
this script yourself. Replacing the admin also invalidates every login
token issued before now (see get_current_admin in app/auth.py).
"""
import asyncio
import getpass
import sys
from datetime import datetime, timezone
from pathlib import Path

from pymongo import AsyncMongoClient

sys.path.append(str(Path(__file__).resolve().parent.parent))

from app.auth import BCRYPT_MAX_BYTES, hash_password, password_too_long  # noqa: E402
from app.config import settings  # noqa: E402

MIN_PASSWORD_LENGTH = 14


async def create_admin(username: str, password: str) -> None:
    client = AsyncMongoClient(settings.mongo_uri, tz_aware=True)
    try:
        db = client[settings.db_name]
        if await db.admins.count_documents({}) > 0:
            confirm = input("An admin account already exists. Replace it? (yes/no): ").strip().lower()
            if confirm != "yes":
                print("Aborted. No changes made.")
                return
            await db.admins.delete_many({})

        await db.admins.insert_one(
            {
                "username": username,
                "password_hash": hash_password(password),
                "created_at": datetime.now(timezone.utc),
            }
        )
        print(f"Admin account '{username}' created successfully.")
    finally:
        await client.close()


def main() -> None:
    username = input("Admin username: ").strip()
    if not username or len(username) > 64:
        print("Username must be 1-64 characters.")
        sys.exit(1)

    password = getpass.getpass("Admin password: ")
    if getpass.getpass("Confirm password: ") != password:
        print("Passwords do not match.")
        sys.exit(1)
    if len(password) < MIN_PASSWORD_LENGTH:
        print(f"Password must be at least {MIN_PASSWORD_LENGTH} characters. A passphrase of 4+ random words works well.")
        sys.exit(1)
    if password_too_long(password):
        print(f"Password must be at most {BCRYPT_MAX_BYTES} bytes (bcrypt limit).")
        sys.exit(1)

    asyncio.run(create_admin(username, password))


if __name__ == "__main__":
    main()
