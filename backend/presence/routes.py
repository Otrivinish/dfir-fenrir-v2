"""Presence routes — who is currently viewing an incident page."""
import json
import uuid

from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from auth.deps import current_user
from auth.service import SESSION_COOKIE
from core.database import get_db
from core.redis_client import get_redis
from core.security import hash_token
from incidents.access import get_accessible_incident
from models import User
from presence.ws import presence_manager

router = APIRouter()


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


@router.get("/{incident_id}/presence/viewers", summary="List incident page viewers")
async def list_viewers(
    incident_id: uuid.UUID,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
):
    """REST fallback for the presence WebSocket: returns the list of users
    currently viewing this incident page, from the in-memory presence manager.
    Requires an authenticated user with access to the incident."""
    # Scope to the incident — don't leak viewer identities of a restricted room.
    await get_accessible_incident(db, incident_id, user)
    return {"viewers": presence_manager.viewers(str(incident_id))}


@router.websocket("/{incident_id}/presence/ws")
async def presence_ws(
    incident_id: uuid.UUID,
    websocket: WebSocket,
    db: AsyncSession = Depends(get_db),
):
    user = await _ws_auth(websocket, db)
    if not user:
        await websocket.close(code=4001)
        return

    # Incident-scope the socket — a valid session isn't enough to watch presence
    # of an incident the user can't access.
    from fastapi import HTTPException
    try:
        await get_accessible_incident(db=db, incident_id=incident_id, user=user)
    except HTTPException:
        await websocket.close(code=4003)
        return

    sid = str(incident_id)
    try:
        await presence_manager.connect(sid, str(user.id), user.username, websocket)
        while True:
            # Client sends a ping every 30 s to keep the connection alive.
            await websocket.receive_text()
    except WebSocketDisconnect:
        await presence_manager.disconnect(sid, str(user.id))
