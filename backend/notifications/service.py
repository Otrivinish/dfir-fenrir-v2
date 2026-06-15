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


async def _create_and_push(
    db: AsyncSession,
    user_id: uuid.UUID,
    type: str,
    title: str,
    body: str | None,
    incident_id: uuid.UUID | None,
) -> Notification:
    n = Notification(
        user_id=user_id,
        type=type,
        title=title,
        body=body,
        incident_id=incident_id,
    )
    db.add(n)
    await db.flush()   # get id/created_at without full commit
    await notification_manager.push(str(user_id), {"type": "notification", **_fmt(n)})
    return n


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
    await db.commit()


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
    await db.commit()


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
    await db.commit()


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
    await db.commit()


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
    await db.commit()
