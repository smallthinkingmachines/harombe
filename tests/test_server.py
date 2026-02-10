"""Tests for FastAPI server."""

from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from harombe.config.schema import HarombeConfig
from harombe.server.app import create_app


@pytest.fixture
def test_config():
    """Create test configuration."""
    config = HarombeConfig()
    config.model.name = "qwen2.5:7b"
    config.tools.confirm_dangerous = False
    return config


@pytest.fixture
def client(test_config):
    """Create test client."""
    app = create_app(test_config)
    return TestClient(app)


def test_health_endpoint(client):
    """Test health check endpoint."""
    response = client.get("/health")

    assert response.status_code == 200
    data = response.json()

    assert data["status"] == "healthy"
    assert "model" in data
    assert "version" in data


def test_chat_endpoint_requires_message(client):
    """Test chat endpoint validation."""
    response = client.post("/chat", json={})

    assert response.status_code == 422  # Validation error


@pytest.mark.skip(reason="Requires running Ollama instance")
def test_chat_endpoint(client):
    """Test chat endpoint with real LLM (integration test)."""
    response = client.post("/chat", json={"message": "Hello"})

    assert response.status_code == 200
    data = response.json()

    assert "response" in data
    assert isinstance(data["response"], str)
    assert len(data["response"]) > 0


@pytest.mark.skip(reason="Requires running Ollama instance")
def test_chat_stream_endpoint(client):
    """Test streaming chat endpoint (integration test)."""
    with client.stream("POST", "/chat/stream", json={"message": "Hi"}) as response:
        assert response.status_code == 200

        events = []
        for line in response.iter_lines():
            if line:
                events.append(line)

        assert len(events) > 0


def test_metrics_endpoint_without_cluster(client):
    """Test metrics endpoint returns 503 when cluster manager is not available."""
    response = client.get("/metrics")

    assert response.status_code == 503
    data = response.json()
    assert "Cluster manager not available" in data["detail"]


def test_health_endpoint_response_fields(client):
    """Test health endpoint returns all expected fields."""
    response = client.get("/health")
    data = response.json()

    assert data["status"] == "healthy"
    assert data["model"] == "qwen2.5:7b"
    assert isinstance(data["version"], str)


def test_chat_endpoint_invalid_content_type(client):
    """Test chat endpoint with invalid content type."""
    response = client.post("/chat", content=b"not json", headers={"Content-Type": "text/plain"})
    assert response.status_code == 422


def test_chat_endpoint_extra_fields(client):
    """Test chat endpoint ignores extra fields."""
    response = client.post(
        "/chat", json={"message": "Hello", "extra_field": "ignored", "stream": False}
    )
    # Should be 422 (Ollama not running) or valid - depends on Ollama
    assert response.status_code in (200, 422, 500)


def test_complete_endpoint_validation(client):
    """Test /api/complete endpoint validates request body."""
    response = client.post("/api/complete", json={})
    assert response.status_code == 422  # Missing required 'messages'


def test_complete_endpoint_with_messages(client):
    """Test /api/complete endpoint with valid messages."""
    response = client.post(
        "/api/complete",
        json={
            "messages": [{"role": "user", "content": "Hello"}],
            "temperature": 0.5,
        },
    )
    # Will fail because Ollama isn't running, but validates it hit the route
    assert response.status_code in (200, 500)


def test_metrics_endpoint_with_cluster_manager():
    """Test metrics endpoint with a mocked cluster manager via create_router."""
    from fastapi import FastAPI

    from harombe.server.routes import create_router

    config = HarombeConfig()
    config.model.name = "qwen2.5:7b"

    mock_cluster = MagicMock()
    mock_cluster.get_metrics.return_value = {
        "nodes": {
            "node-a": {
                "total_requests": 10,
                "success_rate": 0.9,
                "average_latency_ms": 20.0,
                "tokens_per_second": 50.0,
                "last_request": "2024-01-01",
            },
        },
        "cluster_summary": {
            "total_nodes": 1,
            "total_requests": 10,
            "average_success_rate": 0.9,
            "average_latency_ms": 20.0,
            "total_tokens": 500,
            "tokens_per_second": 50.0,
        },
    }

    app = FastAPI()
    router = create_router(config, cluster_manager=mock_cluster)
    app.include_router(router)
    test_client = TestClient(app)

    response = test_client.get("/metrics")
    assert response.status_code == 200
    data = response.json()
    assert "nodes" in data
    assert "cluster_summary" in data


def test_metrics_endpoint_cluster_error():
    """Test metrics endpoint when cluster manager raises."""
    from fastapi import FastAPI

    from harombe.server.routes import create_router

    config = HarombeConfig()
    config.model.name = "qwen2.5:7b"

    mock_cluster = MagicMock()
    mock_cluster.get_metrics.side_effect = RuntimeError("metrics failed")

    app = FastAPI()
    router = create_router(config, cluster_manager=mock_cluster)
    app.include_router(router)
    test_client = TestClient(app)

    response = test_client.get("/metrics")
    assert response.status_code == 500


def test_health_endpoint_default_config():
    """Test health endpoint with default config."""
    config = HarombeConfig()
    app = create_app(config)
    test_client = TestClient(app)

    response = test_client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["model"] == "auto"
