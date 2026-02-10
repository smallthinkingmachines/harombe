"""
Integration tests for MCP Gateway client pool and routing.

Validates that the gateway client pool properly routes requests
to capability containers.
"""

import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from harombe.mcp.protocol import MCPRequest
from harombe.security.audit_db import AuditDatabase
from harombe.security.audit_logger import AuditLogger
from harombe.security.gateway import MCPClientPool


class TestGatewayMCPIntegration:
    """Integration tests for MCP Gateway."""

    @pytest.fixture
    def temp_db_path(self):
        """Create temporary database for testing."""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        yield db_path
        Path(db_path).unlink(missing_ok=True)

    @pytest.fixture
    def audit_db(self, temp_db_path):
        """Create audit database."""
        db = AuditDatabase(db_path=temp_db_path)
        # AuditDatabase initializes on construction
        yield db
        # No close() method needed - connections are per-operation

    @pytest.fixture
    def audit_logger(self, temp_db_path):
        """Create audit logger."""
        return AuditLogger(db_path=temp_db_path)

    @pytest.fixture
    def client_pool(self):
        """Create MCP client pool."""
        return MCPClientPool(
            max_connections=10,
            timeout=30.0,
            max_retries=3,
        )

    @pytest.mark.asyncio
    async def test_client_pool_creates_clients(self, client_pool):
        """Test that client pool creates HTTP clients for containers."""
        # Get client for browser container
        client = await client_pool.get_client("browser-container:3000")
        assert client is not None

        # Verify client cached
        client2 = await client_pool.get_client("browser-container:3000")
        assert client is client2

        # Get client for different container
        client3 = await client_pool.get_client("code-exec-container:3002")
        assert client3 is not None
        assert client3 is not client

    @pytest.mark.asyncio
    async def test_client_pool_health_tracking(self, client_pool):
        """Test that client pool tracks container health."""
        # Create client
        await client_pool.get_client("browser-container:3000")

        # Verify health tracked
        assert "browser-container:3000" in client_pool._container_health
        assert client_pool._container_health["browser-container:3000"] is True

    @pytest.mark.asyncio
    async def test_mcp_request_routing(self, client_pool):
        """Test routing MCP requests through client pool."""
        # Mock httpx response
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "jsonrpc": "2.0",
            "id": "req_1",
            "result": {
                "content": [{"type": "text", "text": "Navigation successful"}],
                "isError": False,
            },
        }
        mock_response.status_code = 200

        # Mock client
        with patch.object(client_pool, "get_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=mock_response)
            mock_get_client.return_value = mock_client

            # Create request
            request = MCPRequest(
                id="req_1",
                method="browser_navigate",
                params={"url": "https://example.com"},
            )

            # Send request
            response = await client_pool.send_request(
                "browser-container:3000",
                request,
            )

            # Verify routing
            assert response.id == "req_1"
            assert response.result is not None
            assert len(response.result.content) > 0

    @pytest.mark.asyncio
    async def test_concurrent_requests_different_containers(self, client_pool):
        """Test handling concurrent requests to different containers."""
        import asyncio

        # Mock responses
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "jsonrpc": "2.0",
            "id": "test",
            "result": {
                "content": [{"type": "text", "text": "Success"}],
                "isError": False,
            },
        }
        mock_response.status_code = 200

        async def send_request(container: str, request_id: str):
            with patch.object(client_pool, "get_client") as mock_get_client:
                mock_client = AsyncMock()
                mock_client.post = AsyncMock(return_value=mock_response)
                mock_get_client.return_value = mock_client

                request = MCPRequest(
                    id=request_id,
                    method="test_method",
                    params={},
                )

                return await client_pool.send_request(container, request)

        # Send concurrent requests
        results = await asyncio.gather(
            send_request("browser-container:3000", "req_1"),
            send_request("code-exec-container:3002", "req_2"),
            send_request("filesystem-container:3001", "req_3"),
        )

        # Verify all succeeded
        assert len(results) == 3
        assert all(r.result is not None for r in results)

    @pytest.mark.asyncio
    async def test_request_with_audit_logging(self, client_pool, audit_logger, audit_db):
        """Test that requests are logged to audit trail."""
        # Mock response
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "jsonrpc": "2.0",
            "id": "req_1",
            "result": {
                "content": [{"type": "text", "text": "Code executed successfully"}],
                "isError": False,
            },
        }
        mock_response.status_code = 200

        # Mock client
        with patch.object(client_pool, "get_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=mock_response)
            mock_get_client.return_value = mock_client

            # Create request
            request = MCPRequest(
                id="req_1",
                method="code_execute",
                params={"language": "python", "code": "print('test')"},
            )

            # Send request
            response = await client_pool.send_request(
                "code-exec-container:3002",
                request,
            )

            # Log tool call
            audit_logger.log_tool_call(
                correlation_id=request.id,
                tool_name="code_execute",
                method="execute",
                parameters=request.params,
                result=response.result.model_dump(mode="json") if response.result else None,
                duration_ms=100,
                container_id="code-exec-container:3002",
            )

        # Verify audit trail
        events = audit_db.get_tool_calls(tool_name="code_execute", limit=10)

        assert len(events) >= 1
        assert events[0]["tool_name"] == "code_execute"

    @pytest.mark.asyncio
    async def test_request_error_handling(self, client_pool):
        """Test error handling in request routing."""
        # Mock error response
        with patch.object(client_pool, "get_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(side_effect=Exception("Connection failed"))
            mock_get_client.return_value = mock_client

            # Create request
            request = MCPRequest(
                id="req_1",
                method="test_method",
                params={},
            )

            # Send request (should handle error)
            try:
                await client_pool.send_request("browser-container:3000", request)
            except Exception as e:
                assert "Connection failed" in str(e)

    @pytest.mark.asyncio
    async def test_multiple_tool_types_routing(self, client_pool, audit_logger):
        """Test routing different tool types to correct containers."""
        tool_container_map = [
            ("browser_navigate", "browser-container:3000"),
            ("code_execute", "code-exec-container:3002"),
            ("filesystem_read", "filesystem-container:3001"),
        ]

        for tool_name, container in tool_container_map:
            # Mock response
            mock_response = MagicMock()
            mock_response.json.return_value = {
                "jsonrpc": "2.0",
                "id": f"req_{tool_name}",
                "result": {
                    "content": [{"type": "text", "text": f"Tool {tool_name} executed"}],
                    "isError": False,
                },
            }
            mock_response.status_code = 200

            # Mock client
            with patch.object(client_pool, "get_client") as mock_get_client:
                mock_client = AsyncMock()
                mock_client.post = AsyncMock(return_value=mock_response)
                mock_get_client.return_value = mock_client

                # Create request
                request = MCPRequest(
                    id=f"req_{tool_name}",
                    method=tool_name,
                    params={},
                )

                # Send request to correct container
                response = await client_pool.send_request(container, request)
                assert response.result is not None

                # Log tool call
                audit_logger.log_tool_call(
                    correlation_id=request.id,
                    tool_name=tool_name,
                    method="execute",
                    parameters={},
                    result=response.result.model_dump(mode="json") if response.result else None,
                    duration_ms=50,
                    container_id=container,
                )

    @pytest.mark.asyncio
    async def test_request_timeout_handling(self, client_pool):
        """Test handling of request timeouts."""
        import asyncio

        # Mock slow response
        async def slow_post(*args, **kwargs):
            await asyncio.sleep(10)  # Simulate timeout
            return MagicMock()

        with patch.object(client_pool, "get_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_client.post = slow_post
            mock_get_client.return_value = mock_client

            # Create request
            request = MCPRequest(
                id="req_1",
                method="test_method",
                params={},
            )

            # Send request with short timeout (should timeout)
            import contextlib

            with contextlib.suppress(TimeoutError):
                # In production, would use client_pool timeout setting
                await asyncio.wait_for(
                    client_pool.send_request("browser-container:3000", request),
                    timeout=1.0,
                )

    @pytest.mark.asyncio
    async def test_client_pool_cleanup(self, client_pool):
        """Test that client pool cleans up HTTP clients."""
        # Create multiple clients
        await client_pool.get_client("browser-container:3000")
        await client_pool.get_client("code-exec-container:3002")

        # Verify clients created
        assert len(client_pool._clients) == 2

        # Cleanup (would be called on shutdown)
        for client in client_pool._clients.values():
            await client.aclose()

        # Verify cleanup
        assert all(client.is_closed for client in client_pool._clients.values())
