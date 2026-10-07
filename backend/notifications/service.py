"""Notification creation helpers — called from route handlers after writes."""
import re
import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from models import Notification, User, incident_teams, user_team
from notifications.ws import notification_manager

# Matches @<username> tokens. Username charset matches the User.username column.
_MENTION_RE = re.compile(r'(?:^|\s)@([a-zA-Z0-9_.-]+)')


async def _incident_recipients(db: AsyncSession, incident_id: uuid.UUID) -> list[User]:
    """Active users allowed to see this incident — mirrors incidents.access rules
    so notifications (which carry incident titles and message/comment snippets)
    don't leak restricted-incident content to users with no access.

    No team assigned → all active users. Otherwise → active admins + active
    members of an assigned team.
    """
    has_team = (await db.execute(
        select(incident_teams.c.team_id)
        .where(incident_teams.c.incident_id == incident_id)
        .limit(1)
    )).scalar_one_or_none()
    if has_team is None:
        return (await db.execute(
            select(User).where(User.is_active == True)  # noqa: E712
        )).scalars().all()

    admins = (await db.execute(
        select(User).where(User.is_active == True, User.role == "admin")  # noqa: E712
    )).scalars().all()
    members = (await db.execute(
        select(User)
        .join(user_team, user_team.c.user_id == User.id)
        .join(incident_teams, incident_teams.c.team_id == user_team.c.team_id)
        .where(User.is_active == True, incident_teams.c.incident_id == incident_id)  # noqa: E712
    )).scalars().all()
    by_id = {u.id: u for u in (*admins, *members)}
    return list(by_id.values())


def _fmt(n: Notification) -> dict:
    ts = n.created_at
    return {
        "id": str(n.id),
        "type": n.type,
        "title": n.title,
        "body": n.body,
        "incident_id": str(n.incident_id) if n.incident_id else None,
        "read": n.read,
        "created_at": ts.strftime("%Y-%m-%dT%H:%M:%SZ") if ts else None,
    }


# Session.info key for WebSocket pushes waiting for their transaction to commit.
_PENDING_PUSHES = "pending_notification_pushes"


async def _create_and_push(
    db: AsyncSession,
    user_id: uuid.UUID,
    type: str,
    title: str,
    body: str | None,
    incident_id: uuid.UUID | None,
) -> Notification:
    """Add a notification and queue its WebSocket push. The push is sent by
    commit_and_push() only once the transaction has committed; after a rollback,
    discard_pushes() drops it. The frame is {"type": "notification", "notification":
    <item>}, the item shaped exactly like GET /api/notifications items."""
    n = Notification(
        user_id=user_id,
        type=type,
        title=title,
        body=body,
        incident_id=incident_id,
    )
    db.add(n)
    await db.flush()   # get id/created_at without full commit
    db.info.setdefault(_PENDING_PUSHES, []).append(
        (str(user_id), {"type": "notification", "notification": _fmt(n)}))
    return n


async def commit_and_push(db: AsyncSession) -> None:
    """Commit, then push the notifications queued in this transaction to every open
    socket of their users. A failed commit pushes nothing."""
    pending = db.info.pop(_PENDING_PUSHES, [])
    await db.commit()
    for user_id, frame in pending:
        await notification_manager.push(user_id, frame)


def discard_pushes(db: AsyncSession) -> None:
    """Drop the queued pushes after a rollback: those notifications were never stored."""
    db.info.pop(_PENDING_PUSHES, None)


async def notify_warroom_message(
    db: AsyncSession,
    sender_id: uuid.UUID,
    incident_id: uuid.UUID,
    sender_username: str,
    body: str,
):
    """Notify users of a new war-room message.

    Mentioned users (@username) receive an elevated `warroom_mention` notification.
    Other active users (except sender) receive a `warroom_message` notification.
    """
    mention_names = {m.lower() for m in _MENTION_RE.findall(body)}

    users = await _incident_recipients(db, incident_id)
    snippet = body[:80] + ("…" if len(body) > 80 else "")
    for user in users:
        if user.id == sender_id:
            continue
        if user.username.lower() in mention_names:
            await _create_and_push(
                db,
                user.id,
                type="warroom_mention",
                title=f"{sender_username} mentioned you in war room",
                body=snippet,
                incident_id=incident_id,
            )
        else:
            await _create_and_push(
                db,
                user.id,
                type="warroom_message",
                title=f"{sender_username} in war room",
                body=snippet,
                incident_id=incident_id,
            )
    await commit_and_push(db)


async def notify_handoff(
    db: AsyncSession,
    recipient_id: uuid.UUID,
    incident_id: uuid.UUID,
    incident_ref: str,
    outgoing_username: str,
):
    """Notify the incoming analyst that a handoff is waiting for acknowledgment."""
    await _create_and_push(
        db,
        recipient_id,
        type="handoff_pending",
        title=f"Handoff from {outgoing_username}",
        body=f"You have a pending handoff on {incident_ref}",
        incident_id=incident_id,
    )
    await commit_and_push(db)


async def queue_ic_transferred(
    db: AsyncSession,
    recipient_id: uuid.UUID,
    incident_id: uuid.UUID,
    incident_ref: str,
    new_ic_username: str,
) -> None:
    """J4: tell a former Incident Commander that a handoff acknowledgement moved the role. In-app only,
    incident ref only. Queued, not committed: the caller commits with commit_and_push()."""
    await _create_and_push(
        db,
        recipient_id,
        type="ic_transferred",
        title="Incident Commander changed",
        body=f"{new_ic_username} is now Incident Commander on {incident_ref} (handoff acknowledged)",
        incident_id=incident_id,
    )


async def notify_custody_transfer(
    db: AsyncSession,
    recipient_id: uuid.UUID,
    incident_id: uuid.UUID,
    incident_ref: str,
    requester_username: str,
):
    """Notify the recipient that an evidence custody transfer awaits their acceptance (C4).
    Like notify_handoff: the incident ref only — no incident title or item name. Commits and
    pushes after the commit."""
    await _create_and_push(
        db,
        recipient_id,
        type="custody_transfer",
        title=f"Custody transfer from {requester_username}",
        body=f"An evidence item on {incident_ref} awaits your acceptance",
        incident_id=incident_id,
    )
    await commit_and_push(db)


async def notify_custody_transfer_outcome(
    db: AsyncSession,
    requester_id: uuid.UUID,
    incident_id: uuid.UUID,
    incident_ref: str,
    actor_username: str,
    outcome: str,
):
    """L3 (R47): tell the requester of an internal custody transfer that it was accepted or declined
    (outcome "accepted" | "declined" | "cancelled"). The incident ref only, like the request itself.
    Commits, then pushes."""
    await _create_and_push(
        db,
        requester_id,
        type="custody_transfer",
        title=f"Custody transfer {outcome} by {actor_username}",
        body=f"Your custody transfer request on {incident_ref} was {outcome}",
        incident_id=incident_id,
    )
    await commit_and_push(db)


async def notify_assignment(
    db: AsyncSession,
    assignee_id: uuid.UUID,
    incident_id: uuid.UUID,
    incident_ref: str,
    role_label: str,
    assigner_username: str,
):
    """Tell a user they were given an operational role on an incident (E3). The incident
    ref only, no title (the caller skips self-assignment). Commits, then pushes."""
    await _create_and_push(
        db,
        assignee_id,
        type="assignment",
        title=f"Assigned as {role_label}",
        body=f"{assigner_username} assigned you as {role_label} on {incident_ref}",
        incident_id=incident_id,
    )
    await commit_and_push(db)


_DISCLOSURE_PURPOSE_LABEL = {"law_enforcement": "law enforcement", "regulator": "regulator", "internal": "internal",
                             "evidence_export": "evidence export"}


async def notify_disclosure_built(
    db: AsyncSession,
    incident_id: uuid.UUID,
    incident_ref: str,
    builder: User,
    purpose: str,
):
    """K1: tell every active admin except the builder that a Disclosure package was built (E3 told them only
    of a non-admin lead's LE package). The incident ref and the purpose only. In-app only, so Dark Operation
    allows it. Commits, then pushes."""
    admins = (await db.execute(
        select(User).where(User.is_active == True, User.role == "admin", User.id != builder.id)  # noqa: E712
    )).scalars().all()
    label = _DISCLOSURE_PURPOSE_LABEL.get(purpose, purpose)
    for admin in admins:
        await _create_and_push(
            db,
            admin.id,
            type="disclosure",
            title=f"Disclosure package built on {incident_ref}",
            body=f"{builder.username} built a disclosure package ({label})",
            incident_id=incident_id,
        )
    await commit_and_push(db)


async def notify_stored_file_unreadable(
    db: AsyncSession,
    incident_id: uuid.UUID | None,
    incident_ref: str | None,
    what: str,
    reason: str,
):
    """Tell every active admin that a stored encrypted file could not be read (G1 stage 3a: a
    missing file, an I/O error, or a wrong or missing EVIDENCE_KEK). In-app only, so Dark
    Operation allows it; the incident ref and the reason class only, no file name. Commits,
    then pushes."""
    admins = (await db.execute(
        select(User).where(User.is_active == True, User.role == "admin")  # noqa: E712
    )).scalars().all()
    for admin in admins:
        await _create_and_push(
            db,
            admin.id,
            type="stored_file_unreadable",
            title=f"{what} could not be read" + (f" on {incident_ref}" if incident_ref else ""),
            body=f"Reason: {reason}. Nothing was frozen. Check the storage volume and EVIDENCE_KEK.",
            incident_id=incident_id,
        )
    await commit_and_push(db)


async def notify_incident_created(
    db: AsyncSession,
    creator_id: uuid.UUID,
    incident_id: uuid.UUID,
    incident_ref: str,
    creator_username: str,
    severity: str,
):
    """Notify every active user who can see a new incident, except its creator. The ref and severity
    only, never the title (L3, R47: like every other notification)."""
    users = await _incident_recipients(db, incident_id)
    for user in users:
        if user.id == creator_id:
            continue
        await _create_and_push(
            db,
            user.id,
            type="incident_created",
            title=f"New incident {incident_ref}",
            body=f"{creator_username} opened {incident_ref} (severity {severity})",
            incident_id=incident_id,
        )
    await commit_and_push(db)


async def notify_siem_incident(
    db: AsyncSession,
    incident_id: uuid.UUID,
    incident_ref: str,
    source_label: str,
    alert_title: str,
):
    """Tell the on-call responder of today (UTC date, On-Call page) and every active admin that a SIEM
    alert opened an incident (J1). In-app only, so it is sent under Dark Operation and TLP:RED too;
    only users who can see the incident. Commits, then pushes."""
    from models import OnCallEntry, utcnow   # local: keep this module's import surface as it was
    today = utcnow().date()
    on_call = set((await db.execute(
        select(OnCallEntry.user_id).where(OnCallEntry.start_date <= today, OnCallEntry.end_date >= today,
                                          OnCallEntry.user_id.is_not(None))
    )).scalars())
    for user in await _incident_recipients(db, incident_id):
        if user.role != "admin" and user.id not in on_call:
            continue
        await _create_and_push(
            db,
            user.id,
            type="incident_created",
            title=f"SIEM alert opened {incident_ref}",
            body=f"{source_label}: {alert_title}"[:300],
            incident_id=incident_id,
        )
    await commit_and_push(db)


# NIST SP 800-61 R3 phase names (L3, R47: "Containment Eradication Recovery" lost its comma and "&").
PHASE_LABEL = {
    "preparation":                      "Preparation",
    "detection_and_analysis":           "Detection & Analysis",
    "containment_eradication_recovery": "Containment, Eradication & Recovery",
    "post_incident":                    "Post-Incident Activity",
}


async def notify_phase_changed(
    db: AsyncSession,
    actor_id: uuid.UUID,
    incident_id: uuid.UUID,
    incident_ref: str,
    actor_username: str,
    new_phase: str,
):
    """Notify every active user who can see the incident (except the actor) that its phase changed.
    The ref only, never the title (L3, R47)."""
    phase_label = PHASE_LABEL.get(new_phase, new_phase)
    users = await _incident_recipients(db, incident_id)
    for user in users:
        if user.id == actor_id:
            continue
        await _create_and_push(
            db,
            user.id,
            type="phase_changed",
            title=f"{incident_ref} → {phase_label}",
            body=f"{actor_username} moved {incident_ref} to {phase_label}",
            incident_id=incident_id,
        )
    await commit_and_push(db)


async def notify_comment(
    db: AsyncSession,
    author_id: uuid.UUID,
    incident_id: uuid.UUID,
    incident_ref: str,
    author_username: str,
    body: str,
):
    """Notify users of a new comment.

    Mentioned users (@username) receive an elevated `comment_mention` notification.
    Other active users (except the author) receive a `comment` notification.
    """
    mention_names = {m.lower() for m in _MENTION_RE.findall(body)}

    users = await _incident_recipients(db, incident_id)
    snippet = body[:80] + ("…" if len(body) > 80 else "")
    for user in users:
        if user.id == author_id:
            continue
        if user.username.lower() in mention_names:
            await _create_and_push(
                db,
                user.id,
                type="comment_mention",
                title=f"{author_username} mentioned you on {incident_ref}",
                body=snippet,
                incident_id=incident_id,
            )
        else:
            await _create_and_push(
                db,
                user.id,
                type="comment",
                title=f"{author_username} commented on {incident_ref}",
                body=snippet,
                incident_id=incident_id,
            )
    await commit_and_push(db)


async def notify_api_token_revoked(db: AsyncSession, owner_id: uuid.UUID, token_name: str, admin: User):
    """R144: tell a token's owner that an admin revoked it (never when they revoked their own).
    The token name and the admin only. In-app only. Commits, then pushes."""
    if owner_id == admin.id:
        return
    await _create_and_push(
        db,
        owner_id,
        type="api_token_revoked",
        title=f"An admin revoked your API token “{token_name}”",
        body=f"Revoked by {admin.username}. Calls made with it now get 401; issue a new token under "
             "Settings → Account → API tokens if you still need one.",
        incident_id=None,
    )
