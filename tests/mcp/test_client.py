"""Tests for MCP client."""

import pytest

from harombe.mcp.client import MCPServerConnection


class TestMCPServerConnection:
    def test_init_stdio(self):
        conn = MCPServerConnection(
            name="test",
            transport="stdio",
            command="echo",
            args=["hello"],
        )
        assert conn.name == "test"
        assert conn.transport == "stdio"
        assert conn.command == "echo"
        assert conn.tools == {}

    def test_init_http(self):
        conn = MCPServerConnection(
            name="remote",
            transport="streamable-http",
            url="http://localhost:8200/mcp",
        )
        assert conn.name == "remote"
        assert conn.transport == "streamable-http"
        assert conn.url == "http://localhost:8200/mcp"

    @pytest.mark.asyncio
    async def test_connect_stdio_requires_command(self):
        conn = MCPServerConnection(name="test", transport="stdio")
        with pytest.raises(ValueError, match="requires 'command'"):
            await conn.connect()

    @pytest.mark.asyncio
    async def test_connect_http_requires_url(self):
        conn = MCPServerConnection(name="test", transport="streamable-http")
        with pytest.raises(ValueError, match="requires 'url'"):
            await conn.connect()

    @pytest.mark.asyncio
    async def test_connect_unknown_transport(self):
        conn = MCPServerConnection(name="test", transport="unknown")
        with pytest.raises(ValueError, match="Unknown transport"):
            await conn.connect()

    def test_tools_empty_before_connect(self):
        conn = MCPServerConnection(name="test", transport="stdio", command="echo")
        assert conn.tools == {}

    @pytest.mark.asyncio
    async def test_disconnect_when_not_connected(self):
        conn = MCPServerConnection(name="test", transport="stdio", command="echo")
        # Should not raise
        await conn.disconnect()
        assert conn.tools == {}
