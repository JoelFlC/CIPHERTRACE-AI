"""WebSocket connection manager for real-time SOC alert broadcasting."""

from __future__ import annotations

from typing import Any

from fastapi import WebSocket


class ConnectionManager:
    """Thread-safe async WebSocket registry for live SOC dashboard streaming."""

    def __init__(self) -> None:
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict[str, Any]) -> None:
        """Broadcast JSON payload to all active WebSocket clients, pruning broken ones."""
        stale: list[WebSocket] = []
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception:
                stale.append(connection)
        for conn in stale:
            self.disconnect(conn)


ws_manager = ConnectionManager()
