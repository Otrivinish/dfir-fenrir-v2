"""War Room: per-incident live chat (REST + WebSocket)."""
import base64
import binascii
import json
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, WebSocket, WebSocketDisconnect, status
from pydantic import BaseModel
from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from auth.deps import current_user, require_analyst
from auth.service import SESSION_COOKIE
from core.database import SessionLocal, get_db
from core.errors import ApiError, ApiErrorBody
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


def _encode_cursor(m: ChatMessage) -> str:
    """Opaque keyset cursor: the oldest message of the page (created_at at full precision + id)."""
    raw = json.dumps({"t": m.created_at.isoformat(), "i": str(m.id)})
    return base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")


def _decode_cursor(cursor: str) -> tuple[datetime, uuid.UUID]:
    try:
        data = json.loads(base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)).decode())
        t = datetime.fromisoformat(data["t"])
        return (t if t.tzinfo else t.replace(tzinfo=timezone.utc)), uuid.UUID(data["i"])
    except (ValueError, KeyError, TypeError, binascii.Error, UnicodeDecodeError):
        raise ApiError(status.HTTP_400_BAD_REQUEST, "invalid_cursor", "Invalid cursor")


@router.get("/{incident_id}/warroom/messages", summary="List war-room messages",
            responses={400: {"model": ApiErrorBody, "description": "invalid_cursor or invalid_before"}})
async def list_messages(
    incident_id: uuid.UUID,
    limit: int = Query(50, ge=1, le=200),
    cursor: str | None = Query(None, description="Opaque cursor from a previous page's next_cursor: "
                                                 "the next OLDER page"),
    before: str | None = Query(None, description="ISO 8601 timestamp: only messages created before it "
                                                 "(kept for older clients; prefer cursor)"),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(current_user),
):
    """List an incident's war-room messages, newest page first: the first page holds the
    newest `limit` messages (1-200, default 50), and `next_cursor` (null when there is none)
    fetches the next older page. Within a page, `items` are in chat order (oldest first), so a
    client appends live WebSocket messages after them and prepends older pages before them.
    `before` (ISO 8601) limits the list to messages created before that instant. Requires an
    authenticated user with access to the incident. Returns {items, next_cursor, online}
    (`online` = current WebSocket count). 400 code invalid_cursor / invalid_before on a
    malformed value."""
    await _get_incident(incident_id, db, user)
    q = select(ChatMessage).where(ChatMessage.incident_id == incident_id)
    if cursor:
        t, i = _decode_cursor(cursor)
        q = q.where(or_(ChatMessage.created_at < t, and_(ChatMessage.created_at == t, ChatMessage.id < i)))
    if before:
        try:
            b = datetime.fromisoformat(before.strip().replace("Z", "+00:00"))
        except ValueError:
            raise ApiError(status.HTTP_400_BAD_REQUEST, "invalid_before",
                           "before must be an ISO 8601 timestamp, e.g. 2026-10-04T10:00:00Z")
        q = q.where(ChatMessage.created_at < (b if b.tzinfo else b.replace(tzinfo=timezone.utc)))
    # R68: newest first (keyset on created_at, id), then flipped to chat order for the page.
    rows = (await db.execute(
        q.order_by(ChatMessage.created_at.desc(), ChatMessage.id.desc()).limit(limit + 1)
    )).scalars().all()
    page = list(reversed(rows[:limit]))
    return {
        "items": [_fmt(m) for m in page],
        "next_cursor": _encode_cursor(page[0]) if len(rows) > limit else None,
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
    analyst role and access to the incident. Allowed on a closed incident too: the
    war room is a communication record, not an investigative fact. Returns the created
    message; 422 if the body is empty."""
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
):
    # R62: a short-lived session for the auth and access checks only, closed before the receive
    # loop. A socket lives for hours; a session held that long pins a pool connection and an open
    # transaction whose locks block migrations. Messages are posted over REST, never on this socket.
    allowed = False
    async with SessionLocal() as db:
        user = await _ws_auth(websocket, db)
        if user:
            # Incident-scope the socket: a valid session is necessary but not sufficient.
            # get_accessible_incident raises 404 for incidents the user can't see; map
            # that to a WS policy-violation close so a caller can't join another team's room.
            try:
                await get_accessible_incident(incident_id=incident_id, db=db, user=user)
                allowed = True
            except HTTPException:
                pass
    if not user:
        await websocket.close(code=4001)
        return
    if not allowed:
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
