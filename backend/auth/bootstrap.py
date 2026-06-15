"""First-run bootstrap: print/persist a one-time setup token; seed CISA roles."""
import logging
import os
import uuid
from datetime import datetime
from pathlib import Path

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import settings
from core.security import new_bootstrap_token
from models import OperationalRole, User

logger = logging.getLogger("auth.bootstrap")


# CISA / NIST 800-61 R3 IR roles. is_system=True → cannot be deleted, key cannot be changed.
SEED_ROLES = [
    ("incident_commander",   "Incident Commander",
     "Owns coordination, authority, and decision-making for the incident."),
    ("deputy_commander",     "Deputy Incident Commander",
     "Backs up the IC; takes over during handoff."),
    ("lead_investigator",    "Lead Investigator",
     "Technical lead — directs investigation, evidence collection, and analysis."),
    ("communications_lead",  "Communications Lead",
     "Manages internal and external communications, including stakeholder updates."),
    ("legal_liaison",        "Legal Liaison",
     "Coordinates with legal counsel, regulators, and law enforcement."),
    ("recorder",             "Recorder",
     "Maintains the contemporaneous record of decisions, actions, and timeline."),
]


async def bootstrap_on_startup(db: AsyncSession) -> None:
    """Run idempotent startup tasks."""
    await _seed_operational_roles(db)
    await _ensure_bootstrap_token(db)
    await db.commit()


async def _seed_operational_roles(db: AsyncSession) -> None:
    existing = await db.execute(select(OperationalRole.key))
    have = {k for (k,) in existing.all()}
    for i, (key, label, desc) in enumerate(SEED_ROLES):
        if key in have:
            continue
        db.add(OperationalRole(
            id=uuid.uuid4(),
            key=key, label=label, description=desc,
            is_system=True, is_active=True,
            sort_order=10 + i * 10,
            # Naive: operational_roles.created_at is a TIMESTAMP WITHOUT TIME ZONE
            # column (see models.py). Don't convert to tz-aware here without also
            # migrating the column — asyncpg will reject the bind otherwise.
            created_at=datetime.utcnow(),
        ))
    logger.info("Operational roles seeded (%d ensured)", len(SEED_ROLES))


async def _ensure_bootstrap_token(db: AsyncSession) -> None:
    """If users table is empty, ensure a bootstrap token file exists.

    Token is printed to logs the first time it's generated. Idempotent: if the
    file already exists we reuse it (so restarting the container before setup
    completes doesn't invalidate the token).
    """
    count_q = await db.execute(select(func.count(User.id)))
    n = int(count_q.scalar_one())
    if n > 0:
        # Setup already complete — remove any stale token.
        try:
            Path(settings.bootstrap_token_file).unlink(missing_ok=True)
        except Exception:
            pass
        return

    p = Path(settings.bootstrap_token_file)
    p.parent.mkdir(parents=True, exist_ok=True)
    if p.exists():
        token = p.read_text().strip()
        logger.warning("Bootstrap token reused from %s", p)
    else:
        token = new_bootstrap_token()
        p.write_text(token + "\n")
        try:
            os.chmod(p, 0o600)
        except Exception:
            pass
        logger.warning(
            "=" * 60 + "\n"
            "FIRST-RUN SETUP REQUIRED\n"
            "Visit https://<host>/setup and provide this token:\n"
            "\n    %s\n\n"
            "Token also saved (chmod 600) at: %s\n"
            + "=" * 60,
            token, p,
        )


def read_bootstrap_token() -> str | None:
    p = Path(settings.bootstrap_token_file)
    if not p.exists():
        return None
    try:
        return p.read_text().strip()
    except Exception:
        return None


def consume_bootstrap_token() -> None:
    """Remove the bootstrap token file — called once setup completes."""
    try:
        Path(settings.bootstrap_token_file).unlink(missing_ok=True)
    except Exception:
        pass
