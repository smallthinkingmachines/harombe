"""WebSocket-based web chat adapter.

Provides a WebSocket endpoint that can be used with any web frontend.
Messages are sent/received as JSON: {"text": "...", "user_id": "..."}

Usage:
    from fastapi import FastAPI
    from harombe.channels.web import WebChatAdapter

    app = FastAPI()
    adapter = WebChatAdapter(agent=agent)
    app.include_router(adapter.router)
"""

from __future__ import annotations

import contextlib
import json
import logging
from typing import TYPE_CHECKING

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from harombe.channels.base import ChannelMessage

if TYPE_CHECKING:
    from harombe.agent.loop import Agent

logger = logging.getLogger(__name__)


class WebChatAdapter:
    """WebSocket-based web chat adapter."""

    def __init__(self, agent: Agent, path: str = "/ws/chat") -> None:
        """Initialize WebSocket chat adapter.

        Args:
            agent: Harombe agent to handle messages
            path: WebSocket endpoint path
        """
        self.agent = agent
        self.path = path
        self.router = APIRouter()
        self._connections: dict[str, WebSocket] = {}

        self.router.add_api_websocket_route(path, self._websocket_handler)

    async def _websocket_handler(self, websocket: WebSocket) -> None:
        """Handle a WebSocket connection."""
        await websocket.accept()
        conn_id = str(id(websocket))
        self._connections[conn_id] = websocket
        logger.info("WebSocket client connected: %s", conn_id)

        try:
            while True:
                data = await websocket.receive_text()
                try:
                    payload = json.loads(data)
                    text = payload.get("text", "")
                    user_id = payload.get("user_id", conn_id)
                except (json.JSONDecodeError, AttributeError):
                    text = data
                    user_id = conn_id

                if not text.strip():
                    continue

                msg = ChannelMessage(
                    text=text.strip(),
                    user_id=user_id,
                    channel_id=conn_id,
                )

                logger.info("WebSocket message from %s: %s", user_id, text[:100])

                try:
                    response = await self.agent.run(msg.text)
                    await websocket.send_json({"text": response, "type": "response"})
                except Exception as e:
                    logger.error("Error processing WebSocket message: %s", e)
                    await websocket.send_json({"text": f"Error: {e}", "type": "error"})

        except WebSocketDisconnect:
            logger.info("WebSocket client disconnected: %s", conn_id)
        finally:
            self._connections.pop(conn_id, None)

    async def start(self) -> None:
        """No-op for WebSocket adapter (runs as part of FastAPI app)."""
        pass

    async def stop(self) -> None:
        """Close all WebSocket connections."""
        for _conn_id, ws in list(self._connections.items()):
            with contextlib.suppress(Exception):
                await ws.close()
        self._connections.clear()

    async def send_message(self, channel_id: str, text: str, thread_id: str | None = None) -> None:
        """Send a message to a specific WebSocket connection."""
        ws = self._connections.get(channel_id)
        if ws:
            await ws.send_json({"text": text, "type": "message"})
