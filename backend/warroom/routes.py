"""War Room: per-incident live chat (REST + WebSocket)."""
import json
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, WebSocket, WebSocketDisconnect, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from auth.deps import current_user, require_analyst
from auth.service import SESSION_COOKIE
from core.database import get_db
from core.redis_client import get_redis
from core.security import hash_token
from incidents.access import get_accessible_incident
from models import ChatMessage, Incident, User
from warroom.ws import warroom_manager

router = APIRouter()


class MessageIn(BaseModel):
    body: str


def _fmt(m: ChatMessage) -> dict:
    ts = m.created_at
    iso = ts.strftime("%Y-%m-%dT%H:%M:%SZ") if ts else None
    return {
        "id": str(m.id),
        "incident_id": str(m.incident_id),
        "user_id": str(m.user_id) if m.user_id else None,
        "username": m.username,
        "body": m.body,
        "created_at": iso,
    }


async def _get_incident(incident_id: uuid.UUID, db: AsyncSession, user: User) -> Incident:
    return await get_accessible_incident(db, incident_id, user)


@router.get("/{incident_id}/warroom/messages", summary="List war-room messages")
async def list_messages(
    incident_id: uuid.UUID,
    limit: int = Query(50, ge=1, le=200),
    before: str | None = Query(None, description="ISO timestamp cursor — return messages older than this"),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(current_user),
):
    """List chat messages for an incident's war room, oldest first, capped by
    `limit` (1-200, default 50). Requires an authenticated user with access to
    the incident. Returns the messages plus the current online user count."""
    await _get_incident(incident_id, db, user)
    q = (
        select(ChatMessage)
        .where(ChatMessage.incident_id == incident_id)
        .order_by(ChatMessage.created_at.asc())
        .limit(limit)
    )
    result = await db.execute(q)
    rows = result.scalars().all()
    return {
        "items": [_fmt(m) for m in rows],
        "online": warroom_manager.online_count(str(incident_id)),
    }


@router.post("/{incident_id}/warroom/messages", status_code=201,
             summary="Post a war-room message")
async def send_message(
    incident_id: uuid.UUID,
    payload: MessageIn,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_analyst),
):
    """Post a chat message to an incident's war room. The message is broadcast
    over the WebSocket and triggers notifications to other users. Requires the
    analyst role and access to the incident. Returns the created message; 422 if
    the body is empty."""
    body = payload.body.strip()
    if not body:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Message body cannot be empty")

    await _get_incident(incident_id, db, user)

    msg = ChatMessage(incident_id=incident_id, user_id=user.id, username=user.username, body=body)
    db.add(msg)
    await db.commit()
    await db.refresh(msg)

    out = _fmt(msg)
    await warroom_manager.broadcast_message(str(incident_id), out)

    # Push notification to all other users via the notifications manager.
    # Import here to avoid circular dependency at module load time.
    from notifications.service import notify_warroom_message  # noqa: PLC0415
    await notify_warroom_message(db, user.id, incident_id, user.username, body)

    return out


@router.get("/{incident_id}/warroom/online", summary="Get war-room online count")
async def online_count(
    incident_id: uuid.UUID,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return the number of users currently connected to an incident's war-room
    WebSocket. Requires an authenticated user with access to the incident.
    Returns the incident id and the online count."""
    # Scope to the incident — don't leak presence of a room the caller can't access.
    await get_accessible_incident(db, incident_id, user)
    return {"incident_id": str(incident_id), "online": warroom_manager.online_count(str(incident_id))}


# ─── WebSocket ────────────────────────────────────────────────────────────────

async def _ws_auth(websocket: WebSocket, db: AsyncSession) -> User | None:
    """Resolve user from the session cookie carried on the WS handshake."""
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


@router.websocket("/{incident_id}/warroom/ws")
async def warroom_ws(
    incident_id: uuid.UUID,
    websocket: WebSocket,
    db: AsyncSession = Depends(get_db),
):
    user = await _ws_auth(websocket, db)
    if not user:
        await websocket.close(code=4001)
        return

    # Incident-scope the socket: a valid session is necessary but not sufficient.
    # get_accessible_incident raises 404 for incidents the user can't see; map
    # that to a WS policy-violation close so a caller can't join another team's room.
    try:
        await get_accessible_incident(incident_id=incident_id, db=db, user=user)
    except HTTPException:
        await websocket.close(code=4003)
        return

    sid = str(incident_id)
    try:
        await warroom_manager.connect(sid, str(user.id), user.username, websocket)
        while True:
            # Messages are sent via REST → broadcast; WS is presence-only keep-alive.
            await websocket.receive_text()
    except WebSocketDisconnect:
        await warroom_manager.disconnect(sid, str(user.id))
