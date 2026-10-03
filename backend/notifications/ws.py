"""Per-user WebSocket connection manager for push notifications."""
from fastapi import WebSocket


class NotificationManager:
    def __init__(self):
        # user_id (str) → every open socket of that user (each tab opens several:
        # bell, toasts, dashboard), so closing one never cuts the others off.
        self._connections: dict[str, set[WebSocket]] = {}

    async def connect(self, user_id: str, ws: WebSocket):
        await ws.accept()
        self._connections.setdefault(user_id, set()).add(ws)

    def disconnect(self, user_id: str, ws: WebSocket):
        """Forget this one socket; the user's other sockets stay."""
        sockets = self._connections.get(user_id)
        if sockets is None:
            return
        sockets.discard(ws)
        if not sockets:
            self._connections.pop(user_id, None)

    async def push(self, user_id: str, payload: dict):
        """Send to every open socket of the user; a socket that fails is dropped."""
        for ws in list(self._connections.get(user_id, ())):
            try:
                await ws.send_json(payload)
            except Exception:
                self.disconnect(user_id, ws)

    async def broadcast(self, payload: dict, exclude_user_id: str | None = None):
        for uid in list(self._connections):
            if uid != exclude_user_id:
                await self.push(uid, payload)


notification_manager = NotificationManager()
