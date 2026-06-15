"""War Room WebSocket connection manager — per-incident rooms."""
from fastapi import WebSocket


class WarRoomManager:
    def __init__(self):
        # incident_id (str) → {user_id (str): (WebSocket, username)}
        self._rooms: dict[str, dict[str, tuple]] = {}

    async def connect(self, incident_id: str, user_id: str, username: str, ws: WebSocket):
        await ws.accept()
        room = self._rooms.setdefault(incident_id, {})
        room[user_id] = (ws, username)
        await self._broadcast(incident_id, {
            "type": "presence",
            "online": len(room),
            "user": username,
            "action": "join",
        })

    async def disconnect(self, incident_id: str, user_id: str):
        room = self._rooms.get(incident_id, {})
        entry = room.pop(user_id, None)
        if not room:
            self._rooms.pop(incident_id, None)
        if entry:
            _, username = entry
            await self._broadcast(incident_id, {
                "type": "presence",
                "online": len(self._rooms.get(incident_id, {})),
                "user": username,
                "action": "leave",
            })

    async def broadcast_message(self, incident_id: str, payload: dict):
        await self._broadcast(incident_id, {"type": "message", **payload})

    async def _broadcast(self, incident_id: str, payload: dict):
        dead = []
        for uid, (ws, _) in list(self._rooms.get(incident_id, {}).items()):
            try:
                await ws.send_json(payload)
            except Exception:
                dead.append(uid)
        for uid in dead:
            self._rooms.get(incident_id, {}).pop(uid, None)

    def online_count(self, incident_id: str) -> int:
        return len(self._rooms.get(incident_id, {}))


warroom_manager = WarRoomManager()
