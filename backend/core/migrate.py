"""One-shot schema migration — the `migrate` compose service.

Runs create_all + the idempotent in-place migrations (core.database.init_db) as the
schema owner role (DB_OWNER_ROLE, via SET LOCAL ROLE), then exits. The backend
starts only after this completes, and itself holds data privileges only.

The run is one transaction with a lock_timeout: if a table stays locked longer,
nothing is applied, the exit code is 1 and the backend does not start.
"""
import asyncio
import sys

from sqlalchemy.exc import DBAPIError

from core.database import MIGRATE_LOCK_TIMEOUT, engine, init_db


async def _main() -> int:
    try:
        await init_db()
    except DBAPIError as e:
        if getattr(e.orig, "sqlstate", None) != "55P03":       # lock_not_available
            raise
        print(f"migrate: FAILED, a table stayed locked longer than lock_timeout ({MIGRATE_LOCK_TIMEOUT}). "
              "Nothing was applied (one transaction, rolled back) and the backend will not start. "
              "Find the blocking session in pg_stat_activity, then re-run migrate. "
              f"Postgres: {e.orig}", file=sys.stderr)
        return 1
    finally:
        await engine.dispose()
    return 0


if __name__ == "__main__":
    rc = asyncio.run(_main())
    if rc == 0:
        print("migrate: schema up to date")
    sys.exit(rc)
