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


async def notify_le_package_built(
    db: AsyncSession,
    incident_id: uuid.UUID,
    incident_ref: str,
    builder_username: str,
):
    """Tell every active admin that a non-admin incident lead built a law-enforcement
    package (E3). The incident ref only. Commits, then pushes."""
    admins = (await db.execute(
        select(User).where(User.is_active == True, User.role == "admin")  # noqa: E712
    )).scalars().all()
    for admin in admins:
        await _create_and_push(
            db,
            admin.id,
            type="le_package",
            title=f"LE package built on {incident_ref}",
            body=f"{builder_username} built a law-enforcement package as incident lead",
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
    incident_title: str,
):
    """Notify all active users except the creator of a new incident."""
    users = await _incident_recipients(db, incident_id)
    for user in users:
        if user.id == creator_id:
            continue
        await _create_and_push(
            db,
            user.id,
            type="incident_created",
            title="New incident opened",
            body=incident_title,
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


async def notify_phase_changed(
    db: AsyncSession,
    actor_id: uuid.UUID,
    incident_id: uuid.UUID,
    incident_ref: str,
    incident_title: str,
    new_phase: str,
):
    """Notify all active users (except the actor) that an incident's phase changed."""
    phase_label = new_phase.replace("_", " ").title()
    users = await _incident_recipients(db, incident_id)
    for user in users:
        if user.id == actor_id:
            continue
        await _create_and_push(
            db,
            user.id,
            type="phase_changed",
            title=f"{incident_ref} → {phase_label}",
            body=incident_title,
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
