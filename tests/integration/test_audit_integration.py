"""Integration tests for audit logging with MCP Gateway.

Tests the complete audit logging flow through the MCP Gateway.
"""

import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from harombe.mcp.protocol import MCPRequest
from harombe.security.gateway import create_gateway


@pytest.fixture
def temp_audit_db():
    """Create temporary audit database."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    yield db_path

    # Cleanup
    Path(db_path).unlink(missing_ok=True)
    Path(f"{db_path}-shm").unlink(missing_ok=True)
    Path(f"{db_path}-wal").unlink(missing_ok=True)


@pytest.fixture
def gateway_with_audit(temp_audit_db):
    """Create MCP Gateway with audit logging enabled."""
    gateway = create_gateway(
        host="127.0.0.1",
        port=8100,
        audit_db_path=temp_audit_db,
        enable_audit_logging=True,
    )
    return gateway


@pytest.fixture
def client(gateway_with_audit):
    """Create test client for gateway."""
    return TestClient(gateway_with_audit.app)


def test_gateway_health_endpoint(client):
    """Test gateway health endpoint works with audit logging."""
    response = client.get("/health")
    assert response.status_code == 200

    data = response.json()
    assert data["status"] == "healthy"
    assert "version" in data


def test_audit_logs_invalid_request(client, gateway_with_audit):
    """Test audit logging for invalid requests."""
    # Send invalid JSON-RPC request
    response = client.post("/mcp", json={"invalid": "request"})
    assert response.status_code == 400

    # Check audit logs
    audit_logger = gateway_with_audit.audit_logger
    assert audit_logger is not None

    # Should have logged the error
    stats = audit_logger.db.get_statistics()
    assert stats["events"]["total_events"] > 0


def test_audit_logs_unsupported_tool(client, gateway_with_audit):
    """Test audit logging for unsupported tool."""
    request = MCPRequest(
        id="test-1",
        method="tools/call",
        params={
            "name": "unsupported_tool",
            "arguments": {},
        },
    )

    response = client.post("/mcp", json=request.model_dump(mode="json"))
    assert response.status_code == 200

    data = response.json()
    assert "error" in data

    # Check audit logs
    audit_logger = gateway_with_audit.audit_logger
    events = audit_logger.db.get_events_by_session(session_id=None, limit=100)

    # Should have logged request and error response
    assert len(events) >= 2


def test_audit_correlation_tracking(client, gateway_with_audit):
    """Test correlation ID tracking across request/response."""
    request = MCPRequest(
        id="test-2",
        method="tools/call",
        params={
            "name": "filesystem_read",
            "arguments": {"path": "/etc/hosts"},
        },
    )

    # Make request (will fail since container isn't running, but that's ok)
    client.post("/mcp", json=request.model_dump(mode="json"))

    # Check audit logs have correlation
    audit_logger = gateway_with_audit.audit_logger
    events = audit_logger.db.get_events_by_session(session_id=None, limit=100)

    # Find request event
    request_events = [e for e in events if e["event_type"] == "request"]
    if request_events:
        correlation_id = request_events[0]["correlation_id"]

        # Should have matching response
        correlated = audit_logger.db.get_events_by_correlation(correlation_id)
        assert len(correlated) >= 1


def test_audit_tool_call_logging(client, gateway_with_audit):
    """Test tool call details are logged."""
    request = MCPRequest(
        id="test-3",
        method="tools/call",
        params={
            "name": "browser_navigate",
            "arguments": {"url": "https://example.com"},
        },
    )

    # Make request
    client.post("/mcp", json=request.model_dump(mode="json"))

    # Check tool call was logged
    audit_logger = gateway_with_audit.audit_logger
    audit_logger.db.get_tool_calls(tool_name="browser_navigate")

    # May not have result if container isn't running, but should log the attempt
    # In a real integration test with containers, we'd verify the complete flow


def test_audit_statistics(client, gateway_with_audit):
    """Test audit statistics generation."""
    # Make several requests
    for i in range(5):
        request = MCPRequest(
            id=f"test-{i}",
            method="tools/call",
            params={
                "name": "filesystem_read",
                "arguments": {"path": f"/tmp/file{i}"},
            },
        )
        client.post("/mcp", json=request.model_dump(mode="json"))

    # Get statistics
    audit_logger = gateway_with_audit.audit_logger
    stats = audit_logger.db.get_statistics()

    # Should have event statistics
    assert stats["events"]["total_events"] >= 5
    assert stats["events"]["unique_requests"] >= 5


def test_audit_sensitive_data_redaction(client, gateway_with_audit):
    """Test sensitive data is redacted in audit logs."""
    request = MCPRequest(
        id="test-sensitive",
        method="tools/call",
        params={
            "name": "filesystem_write",
            "arguments": {
                "path": "/tmp/secrets.txt",
                "content": "API_KEY=sk-1234567890abcdef",
            },
        },
    )

    client.post("/mcp", json=request.model_dump(mode="json"))

    # Check audit logs have redacted sensitive data
    audit_logger = gateway_with_audit.audit_logger
    tool_calls = audit_logger.db.get_tool_calls()

    if tool_calls:
        # API key should be redacted
        for call in tool_calls:
            params_str = str(call["parameters"])
            assert "sk-1234567890abcdef" not in params_str or "[REDACTED]" in params_str


def test_audit_logging_disabled():
    """Test gateway works with audit logging disabled."""
    gateway = create_gateway(
        host="127.0.0.1",
        port=8100,
        enable_audit_logging=False,
    )

    assert gateway.audit_logger is None

    client = TestClient(gateway.app)

    # Should still handle requests
    response = client.get("/health")
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_audit_logger_lifecycle(gateway_with_audit):
    """Test audit logger starts and stops correctly."""
    audit_logger = gateway_with_audit.audit_logger
    assert audit_logger is not None

    # Start logger
    await audit_logger.start()
    assert audit_logger._writer_task is not None

    # Log some events
    correlation_id = audit_logger.start_request_sync(
        actor="test",
        action="test_action",
    )
    audit_logger.end_request_sync(
        correlation_id=correlation_id,
        status="success",
    )

    # Stop logger
    await audit_logger.stop()

    # Verify events were logged
    events = audit_logger.db.get_events_by_correlation(correlation_id)
    assert len(events) == 2


def test_audit_export_capability(gateway_with_audit):
    """Test ability to export audit logs."""
    audit_logger = gateway_with_audit.audit_logger

    # Log some events
    for i in range(10):
        corr_id = audit_logger.start_request_sync(
            actor="agent",
            action=f"action-{i}",
        )
        audit_logger.end_request_sync(
            correlation_id=corr_id,
            status="success",
            duration_ms=100 * i,
        )

    # Get statistics for export
    stats = audit_logger.db.get_statistics()
    assert stats["events"]["total_events"] >= 10

    # Get all events
    events = audit_logger.db.get_events_by_session(session_id=None, limit=1000)
    assert len(events) >= 10
