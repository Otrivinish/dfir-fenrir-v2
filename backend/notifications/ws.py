"""Per-user WebSocket connection manager for push notifications."""
from fastapi import WebSocket


class NotificationManager:
    def __init__(self):
        # user_id (str) → WebSocket
        self._connections: dict[str, WebSocket] = {}

    async def connect(self, user_id: str, ws: WebSocket):
        await ws.accept()
        self._connections[user_id] = ws

    def disconnect(self, user_id: str):
        self._connections.pop(user_id, None)

    async def push(self, user_id: str, payload: dict):
        ws = self._connections.get(user_id)
        if ws:
            try:
                await ws.send_json(payload)
            except Exception:
                self._connections.pop(user_id, None)

    async def broadcast(self, payload: dict, exclude_user_id: str | None = None):
        dead = []
        for uid, ws in list(self._connections.items()):
            if uid == exclude_user_id:
                continue
            try:
                await ws.send_json(payload)
            except Exception:
                dead.append(uid)
        for uid in dead:
            self._connections.pop(uid, None)


notification_manager = NotificationManager()
