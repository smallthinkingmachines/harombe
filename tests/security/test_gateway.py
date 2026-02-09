"""Tests for MCP Gateway."""

from unittest.mock import AsyncMock, patch

import pytest
import respx
from fastapi.testclient import TestClient
from httpx import Response

from harombe.mcp.protocol import ContentItem, ErrorCode, MCPRequest, MCPResponse
from harombe.security.gateway import MCPClientPool, create_gateway


@pytest.fixture
def gateway():
    """Create gateway instance for testing."""
    return create_gateway(host="127.0.0.1", port=8100, version="0.1.0-test")


@pytest.fixture
def client(gateway):
    """Create test client."""
    return TestClient(gateway.app)


def test_gateway_health_check(client):
    """Test gateway health endpoint."""
    response = client.get("/health")

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["version"] == "0.1.0-test"
    assert "uptime" in data


def test_gateway_readiness_check_empty(client):
    """Test readiness check with no containers."""
    response = client.get("/ready")

    assert response.status_code == 200
    data = response.json()
    assert data["ready"] is False  # No containers registered yet
    assert data["containers_healthy"] == 0
    assert data["containers_total"] == 0


def test_mcp_request_success():
    """Test successful MCP request routing."""
    gateway = create_gateway()
    client = TestClient(gateway.app)

    # Mock container response
    mock_response = MCPResponse.success(
        request_id="req-123",
        content=[ContentItem(type="text", text="Hello from container")],
    )

    # Send request
    request = MCPRequest(
        id="req-123",
        method="tools/call",
        params={
            "name": "browser_navigate",
            "arguments": {"url": "https://example.com"},
        },
    )

    with patch.object(
        gateway.client_pool, "send_request", new_callable=AsyncMock, return_value=mock_response
    ):
        response = client.post("/mcp", json=request.model_dump(mode="json"))

        assert response.status_code == 200
        data = response.json()
        assert data["id"] == "req-123"
        assert data["result"] is not None
        assert data["result"]["content"][0]["text"] == "Hello from container"


@respx.mock
@pytest.mark.asyncio
async def test_mcp_request_tool_not_found():
    """Test MCP request with unknown tool."""
    gateway = create_gateway()
    client = TestClient(gateway.app)

    request = MCPRequest(
        id="req-456",
        method="tools/call",
        params={
            "name": "unknown_tool",
            "arguments": {},
        },
    )

    response = client.post("/mcp", json=request.model_dump(mode="json"))

    assert response.status_code == 200
    data = response.json()
    assert data["id"] == "req-456"
    assert data["error"] is not None
    assert data["error"]["code"] == ErrorCode.METHOD_NOT_FOUND.value
    assert "unknown_tool" in data["error"]["message"]


def test_mcp_request_invalid_method(client):
    """Test MCP request with invalid method."""
    request = MCPRequest(
        id="req-789",
        method="invalid/method",
        params={},
    )

    response = client.post("/mcp", json=request.model_dump(mode="json"))

    assert response.status_code == 200
    data = response.json()
    assert data["id"] == "req-789"
    assert data["error"] is not None
    assert data["error"]["code"] == ErrorCode.INVALID_PARAMS.value


def test_mcp_request_invalid_json(client):
    """Test MCP request with invalid JSON."""
    response = client.post("/mcp", json={"invalid": "not a valid MCP request"})

    assert response.status_code == 400
    data = response.json()
    assert data["error"] is not None
    assert data["error"]["code"] == ErrorCode.INVALID_REQUEST.value


@respx.mock
@pytest.mark.asyncio
async def test_mcp_request_container_timeout():
    """Test MCP request when container times out."""
    # Mock container timeout
    respx.post("http://web-search-container:3003/mcp").mock(side_effect=Exception("Timeout"))

    gateway = create_gateway()
    client = TestClient(gateway.app)

    request = MCPRequest(
        id="req-timeout",
        method="tools/call",
        params={
            "name": "web_search",
            "arguments": {"query": "test"},
        },
    )

    response = client.post("/mcp", json=request.model_dump(mode="json"))

    assert response.status_code == 200
    data = response.json()
    assert data["id"] == "req-timeout"
    assert data["error"] is not None
    assert data["error"]["code"] in {
        ErrorCode.CONTAINER_TIMEOUT.value,
        ErrorCode.INTERNAL_ERROR.value,
    }


@pytest.mark.asyncio
async def test_client_pool_get_client():
    """Test MCPClientPool get_client."""
    pool = MCPClientPool()

    client1 = await pool.get_client("test-container:3000")
    client2 = await pool.get_client("test-container:3000")

    # Should return same client instance
    assert client1 is client2

    # Different container should get different client
    client3 = await pool.get_client("other-container:3001")
    assert client3 is not client1

    await pool.close_all()


@pytest.mark.asyncio
async def test_client_pool_close_all():
    """Test MCPClientPool close_all."""
    pool = MCPClientPool()

    await pool.get_client("container1:3000")
    await pool.get_client("container2:3001")

    assert len(pool._clients) == 2

    await pool.close_all()

    assert len(pool._clients) == 0


@respx.mock
@pytest.mark.asyncio
async def test_client_pool_send_request_retry():
    """Test MCPClientPool retry logic."""
    # First attempt: 503 Service Unavailable
    # Second attempt: 200 OK
    container_response = MCPResponse.success(
        request_id="req-retry",
        content=[ContentItem(type="text", text="Success after retry")],
    )

    route = respx.post("http://retry-test-container:3000/mcp")
    route.side_effect = [
        Response(503, text="Service Unavailable"),
        Response(200, json=container_response.model_dump(mode="json")),
    ]

    pool = MCPClientPool(max_retries=3)

    request = MCPRequest(
        id="req-retry",
        method="tools/call",
        params={"name": "test_tool", "arguments": {}},
    )

    response = await pool.send_request("retry-test-container:3000", request)

    assert response.id == "req-retry"
    assert response.is_success()
    assert route.call_count == 2  # First failed, second succeeded

    await pool.close_all()


@respx.mock
@pytest.mark.asyncio
async def test_client_pool_health_check():
    """Test container health check."""
    # Mock healthy container
    respx.get("http://healthy-container:3000/health").mock(return_value=Response(200, json={}))

    # Mock unhealthy container
    respx.get("http://unhealthy-container:3001/health").mock(return_value=Response(503, json={}))

    pool = MCPClientPool()

    # Check health
    healthy = await pool.check_health("healthy-container:3000")
    unhealthy = await pool.check_health("unhealthy-container:3001")

    assert healthy is True
    assert unhealthy is False

    # Check status
    status = pool.get_health_status()
    assert status["healthy-container:3000"] == "healthy"
    assert status["unhealthy-container:3001"] == "unhealthy"

    await pool.close_all()


def test_gateway_routes_registered(gateway):
    """Test that gateway routes are properly registered."""
    routes = [route.path for route in gateway.app.routes]

    assert "/mcp" in routes
    assert "/health" in routes
    assert "/ready" in routes


def test_mcp_request_multiple_tools():
    """Test routing different tools to different containers."""
    gateway = create_gateway()
    client = TestClient(gateway.app)

    # Mock browser response
    browser_response = MCPResponse.success(
        request_id="req-browser",
        content=[ContentItem(type="text", text="Browser response")],
    )

    # Mock filesystem response
    fs_response = MCPResponse.success(
        request_id="req-filesystem",
        content=[ContentItem(type="text", text="Filesystem response")],
    )

    # Create a mock that returns different responses based on request
    async def mock_send_request(container: str, request: MCPRequest):
        if "browser" in request.params.get("name", ""):
            return browser_response
        elif "filesystem" in request.params.get("name", ""):
            return fs_response

    with patch.object(
        gateway.client_pool, "send_request", new_callable=AsyncMock, side_effect=mock_send_request
    ):
        # Browser request
        browser_req = MCPRequest(
            id="req-browser",
            method="tools/call",
            params={"name": "browser_navigate", "arguments": {"url": "https://example.com"}},
        )

        response1 = client.post("/mcp", json=browser_req.model_dump(mode="json"))
        assert response1.status_code == 200
        data1 = response1.json()
        assert "Browser response" in data1["result"]["content"][0]["text"]

        # Filesystem request
        fs_req = MCPRequest(
            id="req-filesystem",
            method="tools/call",
            params={"name": "filesystem_read", "arguments": {"path": "/test.txt"}},
        )

        response2 = client.post("/mcp", json=fs_req.model_dump(mode="json"))
        assert response2.status_code == 200
        data2 = response2.json()
        assert "Filesystem response" in data2["result"]["content"][0]["text"]
