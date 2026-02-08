"""Tests for FastAPI server."""

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
