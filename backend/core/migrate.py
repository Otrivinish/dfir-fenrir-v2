"""One-shot schema migration — the `migrate` compose service.

Runs create_all + the idempotent in-place migrations (core.database.init_db) as the
schema owner role (DB_OWNER_ROLE, via SET LOCAL ROLE), then exits. The backend
starts only after this completes, and itself holds data privileges only.
"""
import asyncio

from core.database import engine, init_db


async def _main() -> None:
    try:
        await init_db()
    finally:
        await engine.dispose()


if __name__ == "__main__":
    asyncio.run(_main())
    print("migrate: schema up to date")
