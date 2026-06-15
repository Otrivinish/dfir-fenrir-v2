"""Incident page presence manager — tracks who is currently viewing an incident."""
from fastapi import WebSocket


class PresenceManager:
    def __init__(self):
        # incident_id (str) → {user_id (str): username (str)}
        # WebSocket objects are NOT stored here; they live in the route handler.
        self._viewers: dict[str, dict[str, str]] = {}
        # incident_id → {user_id: WebSocket}  (separate from username map)
        self._sockets: dict[str, dict[str, WebSocket]] = {}

    def _user_list(self, incident_id: str) -> list[dict]:
        return [
            {"user_id": uid, "username": name}
            for uid, name in self._viewers.get(incident_id, {}).items()
        ]

    async def connect(self, incident_id: str, user_id: str, username: str, ws: WebSocket):
        await ws.accept()
        self._viewers.setdefault(incident_id, {})[user_id] = username
        self._sockets.setdefault(incident_id, {})[user_id] = ws
        await self._broadcast(incident_id)

    async def disconnect(self, incident_id: str, user_id: str):
        self._viewers.get(incident_id, {}).pop(user_id, None)
        self._sockets.get(incident_id, {}).pop(user_id, None)
        if not self._viewers.get(incident_id):
            self._viewers.pop(incident_id, None)
            self._sockets.pop(incident_id, None)
        else:
            await self._broadcast(incident_id)

    async def _broadcast(self, incident_id: str):
        payload = {"type": "presence", "viewers": self._user_list(incident_id)}
        dead: list[str] = []
        for uid, ws in list(self._sockets.get(incident_id, {}).items()):
            try:
                await ws.send_json(payload)
            except Exception:
                dead.append(uid)
        for uid in dead:
            self._viewers.get(incident_id, {}).pop(uid, None)
            self._sockets.get(incident_id, {}).pop(uid, None)

    def viewers(self, incident_id: str) -> list[dict]:
        return self._user_list(incident_id)


presence_manager = PresenceManager()
