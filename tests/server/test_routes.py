"""Tests for Harombe server API routes."""

from unittest.mock import AsyncMock, MagicMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from harombe.config.schema import HarombeConfig
from harombe.server.routes import create_router


def _make_app(cluster_manager=None, agent_run_side_effect=None):
    """Create a FastAPI app with mocked LLM and agent."""
    mock_llm = MagicMock()
    mock_llm.complete = AsyncMock()

    with (
        patch("harombe.server.routes.create_llm_client", return_value=mock_llm),
        patch("harombe.server.routes.Agent") as mock_agent_cls,
        patch(
            "harombe.server.routes.get_enabled_tools",
            return_value=[],
        ),
    ):
        mock_agent = MagicMock()
        if agent_run_side_effect:
            exc = agent_run_side_effect

            async def _raise(*_args: object, **_kwargs: object) -> str:
                raise exc

            mock_agent.run = _raise
        else:
            mock_agent.run = AsyncMock(return_value="Hello from agent!")
        mock_agent_cls.return_value = mock_agent

        config = HarombeConfig()
        router = create_router(config, cluster_manager=cluster_manager)

    app = FastAPI()
    app.include_router(router)
    return app, mock_llm


def _make_simple_app(cluster_manager=None):
    """Create a FastAPI app returning only the app."""
    app, _llm = _make_app(cluster_manager=cluster_manager)
    return app


def test_health_endpoint():
    """GET /health returns healthy status with model name."""
    app = _make_simple_app()
    client = TestClient(app)

    response = client.get("/health")

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "model" in data
    assert "version" in data


def test_chat_endpoint():
    """POST /chat returns agent response."""
    app = _make_simple_app()
    client = TestClient(app)

    response = client.post("/chat", json={"message": "Hi"})

    assert response.status_code == 200
    data = response.json()
    assert data["response"] == "Hello from agent!"


def test_chat_endpoint_error():
    """POST /chat returns 500 when agent raises."""
    app, _llm = _make_app(agent_run_side_effect=RuntimeError("LLM down"))
    client = TestClient(app, raise_server_exceptions=False)

    response = client.post("/chat", json={"message": "Hi"})

    assert response.status_code == 500
    assert "LLM down" in response.json()["detail"]


def test_chat_stream_endpoint():
    """POST /chat/stream returns SSE events."""
    app = _make_simple_app()
    client = TestClient(app)

    response = client.post("/chat/stream", json={"message": "Hi"})

    assert response.status_code == 200
    # SSE responses are text/event-stream
    assert "text/event-stream" in response.headers["content-type"]
    body = response.text
    # Should contain at least the message and done events
    assert "Hello from agent!" in body
    assert "done" in body


def test_chat_stream_error():
    """POST /chat/stream yields error event on exception."""
    app, _llm = _make_app(agent_run_side_effect=ValueError("Stream failed"))
    client = TestClient(app)

    response = client.post("/chat/stream", json={"message": "Hi"})

    assert response.status_code == 200
    body = response.text
    assert "Stream failed" in body
    assert "error" in body


def test_complete_endpoint_no_tools():
    """POST /api/complete returns completion response."""
    from harombe.llm.client import CompletionResponse

    app, mock_llm = _make_app()
    mock_llm.complete = AsyncMock(
        return_value=CompletionResponse(content="Completed!", tool_calls=None)
    )
    client = TestClient(app)

    response = client.post(
        "/api/complete",
        json={
            "messages": [{"role": "user", "content": "Hello"}],
            "temperature": 0.5,
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert data["content"] == "Completed!"
    assert data["tool_calls"] is None


def test_complete_endpoint_with_tools():
    """POST /api/complete handles tool calls in response."""
    from harombe.llm.client import CompletionResponse, ToolCall

    app, mock_llm = _make_app()
    mock_llm.complete = AsyncMock(
        return_value=CompletionResponse(
            content="",
            tool_calls=[
                ToolCall(
                    id="call_1",
                    name="read_file",
                    arguments={"path": "test.py"},
                )
            ],
        )
    )
    client = TestClient(app)

    tool_def = {
        "function": {
            "name": "read_file",
            "description": "Read a file",
            "parameters": {
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "File path",
                    }
                }
            },
        }
    }

    response = client.post(
        "/api/complete",
        json={
            "messages": [{"role": "user", "content": "Read test.py"}],
            "tools": [tool_def],
            "temperature": 0.7,
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert data["tool_calls"] is not None
    assert len(data["tool_calls"]) == 1
    assert data["tool_calls"][0]["name"] == "read_file"
    assert data["tool_calls"][0]["id"] == "call_1"


def test_complete_endpoint_error():
    """POST /api/complete returns 500 on LLM error."""
    app, mock_llm = _make_app()
    mock_llm.complete = AsyncMock(side_effect=RuntimeError("LLM error"))
    client = TestClient(app, raise_server_exceptions=False)

    response = client.post(
        "/api/complete",
        json={
            "messages": [{"role": "user", "content": "Hello"}],
        },
    )

    assert response.status_code == 500
    assert "LLM error" in response.json()["detail"]


def test_metrics_no_cluster():
    """GET /metrics without cluster_manager returns 503."""
    app = _make_simple_app(cluster_manager=None)
    client = TestClient(app, raise_server_exceptions=False)

    response = client.get("/metrics")

    assert response.status_code == 503
    assert "Cluster manager not available" in (response.json()["detail"])


def test_metrics_with_cluster():
    """GET /metrics with cluster_manager returns metrics."""
    mock_cm = MagicMock()
    mock_cm.get_metrics.return_value = {
        "nodes": {"node-1": {"cpu": 0.5}},
        "cluster_summary": {"total_nodes": 1},
    }

    app = _make_simple_app(cluster_manager=mock_cm)
    client = TestClient(app)

    response = client.get("/metrics")

    assert response.status_code == 200
    data = response.json()
    assert "nodes" in data
    assert "cluster_summary" in data
    assert data["nodes"]["node-1"]["cpu"] == 0.5
    assert data["cluster_summary"]["total_nodes"] == 1
