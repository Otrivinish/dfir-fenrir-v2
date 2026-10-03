"""Containment state of entities and IOCs, derived from the Respond board (C1).

For each entity or IOC, the latest containment action linked to it decides the
state (latest = most recently created). Only actions whose template has a
containment effect count, and only while they are open, in progress or done:
reverted actions are rolled back and deferred ones are neither in effect nor
under way, so neither hides an earlier action.

  done               -> state = the effect (isolated / disabled / blocked)
  open / in_progress -> state = "pending" (effect says what is pending)

The template -> effect map lives here, not in the frontend, so every API client
sees the same state. So does the template -> target-type map: an effect may only
be linked to its kind of target (no "Isolated" hash IOC).
"""
import uuid
from collections.abc import Iterable
from typing import Optional

from fastapi import status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import InstrumentedAttribute

from core.errors import ApiError
from models import RespondAction
from schemas import ContainmentOut

# Containment template ids from frontend/src/pages/incident/respond/actionTemplates.js.
# Templates not listed here (firewall rule, kill process, quarantine email, …) set no state.
TEMPLATE_EFFECT: dict[str, str] = {
    "isolate_host":    "isolated",
    "quarantine_ep":   "isolated",   # EDR network quarantine
    "take_offline":    "isolated",
    "disable_account": "disabled",
    "reset_creds":     "disabled",
    "revoke_sessions": "disabled",
    "revoke_mfa":      "disabled",
    "revoke_tokens":   "disabled",
    "block_ip":        "blocked",
    "block_domain":    "blocked",
    "block_url":       "blocked",
    "block_hash":      "blocked",
    "block_sender":    "blocked",
}

# The entity / IOC types each template with an effect may be linked to (schemas.EntityType /
# IocType); an empty set refuses that kind of link. Free-text targets (no link) aren't checked.
# The frontend mirrors this only to filter its Link target picker (actionTemplates.js).
_HOST    = {"entity": frozenset({"host"}), "ioc": frozenset()}
_ACCOUNT = {"entity": frozenset({"user", "email"}), "ioc": frozenset()}
TEMPLATE_TARGET_TYPES: dict[str, dict[str, frozenset[str]]] = {
    "isolate_host":    _HOST,
    "quarantine_ep":   _HOST,
    "take_offline":    _HOST,
    "disable_account": _ACCOUNT,
    "reset_creds":     _ACCOUNT,
    "revoke_sessions": _ACCOUNT,
    "revoke_mfa":      _ACCOUNT,
    "revoke_tokens":   _ACCOUNT,
    "block_ip":        {"entity": frozenset({"ip", "network_range"}), "ioc": frozenset({"ip"})},
    "block_domain":    {"entity": frozenset({"domain"}), "ioc": frozenset({"domain"})},
    "block_url":       {"entity": frozenset(), "ioc": frozenset({"url"})},
    "block_hash":      {"entity": frozenset(), "ioc": frozenset({"hash_md5", "hash_sha1", "hash_sha256"})},
    "block_sender":    {"entity": frozenset({"email", "domain"}), "ioc": frozenset({"email", "domain"})},
}


def check_target_type(template_id: Optional[str], entity, ioc) -> None:
    """422 target_type_mismatch when the template's effect can't apply to the linked entity / IOC
    type (e.g. isolate_host on a hash IOC). Templates without an effect accept any target."""
    allowed = TEMPLATE_TARGET_TYPES.get(template_id or "")
    if allowed is None:
        return
    for kind, obj in (("entity", entity), ("ioc", ioc)):
        if obj is not None and obj.type not in allowed[kind]:
            label = "an entity" if kind == "entity" else "an IOC"
            ok = ", ".join(sorted(allowed[kind])) or f"none (link {'an IOC' if kind == 'entity' else 'an entity'} instead)"
            raise ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, "target_type_mismatch",
                           f"{template_id} can't target {label} of type {obj.type}; "
                           f"allowed {kind} types: {ok}")


_COUNTED_STATUSES = ("open", "in_progress", "done")


async def containment_map(db: AsyncSession, link: InstrumentedAttribute,
                          ids: Iterable[uuid.UUID]) -> dict[uuid.UUID, ContainmentOut]:
    """Return {entity or IOC id: ContainmentOut} for `ids` (ids without a state are absent).

    `link` is RespondAction.entity_id or RespondAction.ioc_id. One query: DISTINCT ON
    the link column, newest action first.
    """
    ids = list(ids)
    if not ids:
        return {}
    rows = (await db.execute(
        select(link.label("target_id"), RespondAction.id, RespondAction.status,
               RespondAction.template_id, RespondAction.updated_at)
        .where(link.in_(ids),
               RespondAction.category == "containment",
               RespondAction.status.in_(_COUNTED_STATUSES),
               RespondAction.template_id.in_(tuple(TEMPLATE_EFFECT)))
        .distinct(link)
        .order_by(link, RespondAction.created_at.desc(), RespondAction.id.desc())
    )).all()
    out: dict[uuid.UUID, ContainmentOut] = {}
    for r in rows:
        effect = TEMPLATE_EFFECT[r.template_id]
        out[r.target_id] = ContainmentOut(
            state=effect if r.status == "done" else "pending",
            effect=effect,
            action_id=r.id,
            updated_at=r.updated_at,
        )
    return out
