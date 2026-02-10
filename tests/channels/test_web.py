"""Tests for WebSocket web chat adapter."""

import json
from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from harombe.channels.web import WebChatAdapter


@pytest.fixture
def web_adapter(mock_agent):
    """Create WebChatAdapter with mock agent."""
    return WebChatAdapter(agent=mock_agent)


@pytest.fixture
def app(web_adapter):
    """Create FastAPI app with web adapter router."""
    app = FastAPI()
    app.include_router(web_adapter.router)
    return app


@pytest.fixture
def client(app):
    """Create test client."""
    return TestClient(app)


class TestWebChatAdapter:
    def test_init(self, mock_agent):
        adapter = WebChatAdapter(agent=mock_agent)
        assert adapter.agent is mock_agent
        assert adapter.path == "/ws/chat"
        assert adapter._connections == {}

    def test_custom_path(self, mock_agent):
        adapter = WebChatAdapter(agent=mock_agent, path="/ws/custom")
        assert adapter.path == "/ws/custom"

    def test_websocket_json_message(self, client, mock_agent):
        """Test sending a JSON message via WebSocket."""
        with client.websocket_connect("/ws/chat") as ws:
            ws.send_text(json.dumps({"text": "hello", "user_id": "user-1"}))
            data = ws.receive_json()
            assert data["text"] == "Hello from the agent!"
            assert data["type"] == "response"

    def test_websocket_plain_text(self, client, mock_agent):
        """Test sending plain text (non-JSON) via WebSocket."""
        with client.websocket_connect("/ws/chat") as ws:
            ws.send_text("hello plain")
            data = ws.receive_json()
            assert data["text"] == "Hello from the agent!"
            assert data["type"] == "response"

    def test_websocket_empty_message_ignored(self, client, mock_agent):
        """Test that empty messages are ignored."""
        with client.websocket_connect("/ws/chat") as ws:
            ws.send_text(json.dumps({"text": "   ", "user_id": "u1"}))
            # Send a valid message after to confirm the connection still works
            ws.send_text(json.dumps({"text": "real message", "user_id": "u1"}))
            data = ws.receive_json()
            assert data["type"] == "response"

    def test_websocket_agent_error(self, client, mock_agent):
        """Test error handling when agent raises."""
        mock_agent.run = AsyncMock(side_effect=RuntimeError("agent crashed"))

        with client.websocket_connect("/ws/chat") as ws:
            ws.send_text(json.dumps({"text": "trigger error", "user_id": "u1"}))
            data = ws.receive_json()
            assert data["type"] == "error"
            assert "agent crashed" in data["text"]

    def test_websocket_invalid_json(self, client, mock_agent):
        """Test handling of invalid JSON input (treated as plain text)."""
        with client.websocket_connect("/ws/chat") as ws:
            ws.send_text("{invalid json")
            data = ws.receive_json()
            assert data["type"] == "response"

    @pytest.mark.asyncio
    async def test_start_noop(self, web_adapter):
        """Test start is a no-op."""
        await web_adapter.start()

    @pytest.mark.asyncio
    async def test_stop_clears_connections(self, web_adapter):
        """Test stop clears all connections."""
        mock_ws = AsyncMock()
        web_adapter._connections["conn1"] = mock_ws

        await web_adapter.stop()

        assert web_adapter._connections == {}
        mock_ws.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_message_to_existing_connection(self, web_adapter):
        """Test sending a message to an existing WebSocket connection."""
        mock_ws = AsyncMock()
        web_adapter._connections["conn1"] = mock_ws

        await web_adapter.send_message("conn1", "hello")

        mock_ws.send_json.assert_called_once_with({"text": "hello", "type": "message"})

    @pytest.mark.asyncio
    async def test_send_message_to_missing_connection(self, web_adapter):
        """Test sending to a non-existing connection does nothing."""
        await web_adapter.send_message("nonexistent", "hello")
