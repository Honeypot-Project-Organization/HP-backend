"""
Run once after setting up your Atlas cluster (safe to re-run anytime):
    python scripts/init_db.py
"""
import asyncio
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

from app.database import create_indexes  # noqa: E402


async def main() -> None:
    await create_indexes()
    print("Indexes created (or already existed).")


if __name__ == "__main__":
    asyncio.run(main())
