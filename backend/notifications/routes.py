"""Notifications: list, mark-read, and WebSocket push endpoint."""
import json
import uuid

from fastapi import APIRouter, Depends, Query, WebSocket, WebSocketDisconnect
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from auth.deps import current_user
from auth.service import SESSION_COOKIE
from core.database import get_db
from core.redis_client import get_redis
from core.security import hash_token
from models import Notification, User
from notifications.ws import notification_manager

router = APIRouter()


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


@router.get("/notifications", summary="List notifications")
async def list_notifications(
    limit: int = Query(40, ge=1, le=100),
    unread_only: bool = Query(False),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(current_user),
):
    """List the current user's notifications, newest first. `limit` caps the
    page size (1-100, default 40) and `unread_only` restricts to unread items.
    Returns the items plus the user's total unread count."""
    q = (
        select(Notification)
        .where(Notification.user_id == user.id)
        .order_by(Notification.created_at.desc())
        .limit(limit)
    )
    if unread_only:
        q = q.where(Notification.read == False)  # noqa: E712
    result = await db.execute(q)
    rows = result.scalars().all()

    unread_q = await db.execute(
        select(Notification)
        .where(Notification.user_id == user.id, Notification.read == False)  # noqa: E712
    )
    unread_count = len(unread_q.scalars().all())

    return {"items": [_fmt(n) for n in rows], "unread_count": unread_count}


@router.patch("/notifications/{notification_id}/read", summary="Mark a notification read")
async def mark_read(
    notification_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(current_user),
):
    """Mark a single notification as read. Scoped to the current user, so it
    only affects a notification the caller owns. Returns {"ok": true}."""
    await db.execute(
        update(Notification)
        .where(Notification.id == notification_id, Notification.user_id == user.id)
        .values(read=True)
    )
    await db.commit()
    return {"ok": True}


@router.post("/notifications/read-all", summary="Mark all notifications read")
async def mark_all_read(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(current_user),
):
    """Mark all of the current user's unread notifications as read. Returns
    {"ok": true}."""
    await db.execute(
        update(Notification)
        .where(Notification.user_id == user.id, Notification.read == False)  # noqa: E712
        .values(read=True)
    )
    await db.commit()
    return {"ok": True}


# ─── WebSocket ────────────────────────────────────────────────────────────────

async def _ws_auth(websocket: WebSocket, db: AsyncSession) -> User | None:
    token = websocket.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    th = hash_token(token)
    r = get_redis()
    raw = await r.get(f"session:{th}")
    if not raw:
        return None
    data = json.loads(raw)
    q = await db.execute(
        select(User).where(User.id == uuid.UUID(data["user_id"]), User.is_active == True)  # noqa: E712
    )
    return q.scalar_one_or_none()


@router.websocket("/notifications/ws")
async def notifications_ws(
    websocket: WebSocket,
    db: AsyncSession = Depends(get_db),
):
    user = await _ws_auth(websocket, db)
    if not user:
        await websocket.close(code=4001)
        return

    uid = str(user.id)
    try:
        await notification_manager.connect(uid, websocket)
        while True:
            await websocket.receive_text()   # keep-alive; server pushes only
    except WebSocketDisconnect:
        notification_manager.disconnect(uid)
