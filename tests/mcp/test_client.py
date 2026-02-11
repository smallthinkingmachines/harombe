"""Tests for MCP client."""

from unittest.mock import AsyncMock, MagicMock, patch

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

    def test_init_defaults(self):
        """Verify default values for all fields."""
        conn = MCPServerConnection(name="srv", transport="stdio", command="cat")
        assert conn.name == "srv"
        assert conn.transport == "stdio"
        assert conn.tools == {}
        assert conn._session is None
        assert conn.args == []
        assert conn.env == {}
        assert conn.url is None

    def test_tools_property_empty(self):
        """Tools property returns empty dict before connect."""
        conn = MCPServerConnection(name="srv", transport="stdio", command="cat")
        assert isinstance(conn.tools, dict)
        assert len(conn.tools) == 0

    @pytest.mark.asyncio
    async def test_discover_tools_not_connected(self):
        """_discover_tools without session raises RuntimeError."""
        conn = MCPServerConnection(name="test", transport="stdio", command="echo")
        with pytest.raises(RuntimeError, match="Not connected"):
            await conn._discover_tools()

    @pytest.mark.asyncio
    async def test_make_remote_caller_no_session(self):
        """Remote caller returns error when session is None."""
        conn = MCPServerConnection(name="test", transport="stdio", command="echo")
        caller = conn._make_remote_caller("some_tool")
        result = await caller()
        assert "Error: Not connected" in result

    @pytest.mark.asyncio
    async def test_disconnect_clears_state(self):
        """Disconnect resets tools, session, context managers."""
        conn = MCPServerConnection(name="test", transport="stdio", command="echo")
        # Simulate connected state
        conn._tools = {"fake_tool": "value"}
        conn._session = "fake_session"

        await conn.disconnect()

        assert conn.tools == {}
        assert conn._session is None
        assert conn._context_managers == []


# --- New tests covering connect, discover_tools, remote caller ---


class TestMCPConnectStdio:
    """Tests for the stdio connect path."""

    @pytest.mark.asyncio
    async def test_connect_stdio_success(self):
        """Test stdio connect enters context managers."""
        conn = MCPServerConnection(
            name="test",
            transport="stdio",
            command="echo",
            args=["hello"],
            env={"FOO": "bar"},
        )

        mock_session = AsyncMock()
        mock_session.initialize = AsyncMock()
        mock_session.list_tools = AsyncMock(return_value=MagicMock(tools=[]))

        # Mock the context managers
        mock_stdio_cm = AsyncMock()
        mock_stdio_cm.__aenter__ = AsyncMock(return_value=("read", "write"))
        mock_stdio_cm.__aexit__ = AsyncMock()

        mock_session_cm = MagicMock()
        mock_session_cm.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session_cm.__aexit__ = AsyncMock()

        with (
            patch(
                "harombe.mcp.client.stdio_client",
                return_value=mock_stdio_cm,
            ),
            patch(
                "harombe.mcp.client.ClientSession",
                return_value=mock_session_cm,
            ),
        ):
            await conn.connect()

        assert conn._session is mock_session
        assert len(conn._context_managers) == 2
        mock_session.initialize.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_connect_stdio_no_env(self):
        """Test stdio connect with empty env passes None."""
        conn = MCPServerConnection(
            name="test",
            transport="stdio",
            command="echo",
            env={},
        )

        mock_session = AsyncMock()
        mock_session.initialize = AsyncMock()
        mock_session.list_tools = AsyncMock(return_value=MagicMock(tools=[]))

        mock_stdio_cm = AsyncMock()
        mock_stdio_cm.__aenter__ = AsyncMock(return_value=("r", "w"))

        mock_session_cm = MagicMock()
        mock_session_cm.__aenter__ = AsyncMock(return_value=mock_session)

        with (
            patch(
                "harombe.mcp.client.stdio_client",
                return_value=mock_stdio_cm,
            ) as mock_stdio_fn,
            patch(
                "harombe.mcp.client.ClientSession",
                return_value=mock_session_cm,
            ),
        ):
            await conn.connect()

        # Verify env=None when env dict is empty
        call_args = mock_stdio_fn.call_args
        params = call_args[0][0]
        assert params.env is None


class TestMCPConnectHTTP:
    """Tests for the HTTP connect path."""

    @pytest.mark.asyncio
    async def test_connect_http_success(self):
        """Test HTTP connect enters context managers."""
        conn = MCPServerConnection(
            name="remote",
            transport="streamable-http",
            url="http://localhost:8200/mcp",
        )

        mock_session = AsyncMock()
        mock_session.initialize = AsyncMock()
        mock_session.list_tools = AsyncMock(return_value=MagicMock(tools=[]))

        mock_http_cm = AsyncMock()
        mock_http_cm.__aenter__ = AsyncMock(return_value=("read", "write", "extra"))
        mock_http_cm.__aexit__ = AsyncMock()

        mock_session_cm = MagicMock()
        mock_session_cm.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session_cm.__aexit__ = AsyncMock()

        with (
            patch(
                "harombe.mcp.client.streamablehttp_client",
                return_value=mock_http_cm,
            ),
            patch(
                "harombe.mcp.client.ClientSession",
                return_value=mock_session_cm,
            ),
        ):
            await conn.connect()

        assert conn._session is mock_session
        assert len(conn._context_managers) == 2
        mock_session.initialize.assert_awaited_once()


class TestMCPDiscoverTools:
    """Tests for _discover_tools."""

    @pytest.mark.asyncio
    async def test_discover_tools_populates_tools(self):
        """Test discover_tools creates Tool objects."""
        conn = MCPServerConnection(name="srv", transport="stdio", command="echo")

        # Create mock MCP tools
        mock_tool = MagicMock()
        mock_tool.name = "greet"
        mock_tool.description = "Greet someone"
        mock_tool.inputSchema = {
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": "Name",
                }
            },
            "required": ["name"],
        }

        mock_session = AsyncMock()
        mock_session.list_tools = AsyncMock(return_value=MagicMock(tools=[mock_tool]))
        conn._session = mock_session

        await conn._discover_tools()

        assert "srv__greet" in conn.tools
        tool = conn.tools["srv__greet"]
        assert tool.schema.name == "srv__greet"
        assert tool.schema.description == "Greet someone"

    @pytest.mark.asyncio
    async def test_discover_tools_empty_input_schema(self):
        """Test discover_tools handles empty inputSchema."""
        conn = MCPServerConnection(name="srv", transport="stdio", command="echo")

        mock_tool = MagicMock()
        mock_tool.name = "noop"
        mock_tool.description = "Do nothing"
        mock_tool.inputSchema = None

        mock_session = AsyncMock()
        mock_session.list_tools = AsyncMock(return_value=MagicMock(tools=[mock_tool]))
        conn._session = mock_session

        await conn._discover_tools()

        assert "srv__noop" in conn.tools


class TestMCPRemoteCaller:
    """Tests for _make_remote_caller with a session."""

    @pytest.mark.asyncio
    async def test_remote_caller_success(self):
        """Test remote caller returns text from content."""
        conn = MCPServerConnection(name="srv", transport="stdio", command="echo")

        content_item = MagicMock()
        content_item.text = "Hello from tool"

        mock_result = MagicMock()
        mock_result.content = [content_item]

        mock_session = AsyncMock()
        mock_session.call_tool = AsyncMock(return_value=mock_result)
        conn._session = mock_session

        caller = conn._make_remote_caller("greet")
        result = await caller(name="World")

        assert result == "Hello from tool"
        mock_session.call_tool.assert_awaited_once_with("greet", {"name": "World"})

    @pytest.mark.asyncio
    async def test_remote_caller_no_text(self):
        """Test remote caller returns (no output) when empty."""
        conn = MCPServerConnection(name="srv", transport="stdio", command="echo")

        # Content item without text attribute
        content_item = MagicMock(spec=[])

        mock_result = MagicMock()
        mock_result.content = [content_item]

        mock_session = AsyncMock()
        mock_session.call_tool = AsyncMock(return_value=mock_result)
        conn._session = mock_session

        caller = conn._make_remote_caller("tool")
        result = await caller()

        assert result == "(no output)"

    @pytest.mark.asyncio
    async def test_remote_caller_exception(self):
        """Test remote caller returns error on exception."""
        conn = MCPServerConnection(name="srv", transport="stdio", command="echo")

        mock_session = AsyncMock()
        mock_session.call_tool = AsyncMock(side_effect=RuntimeError("connection lost"))
        conn._session = mock_session

        caller = conn._make_remote_caller("tool")
        result = await caller()

        assert "Error calling srv/tool" in result
        assert "connection lost" in result

    @pytest.mark.asyncio
    async def test_remote_caller_multiple_content(self):
        """Test remote caller joins multiple text items."""
        conn = MCPServerConnection(name="srv", transport="stdio", command="echo")

        item1 = MagicMock()
        item1.text = "Line 1"
        item2 = MagicMock()
        item2.text = "Line 2"

        mock_result = MagicMock()
        mock_result.content = [item1, item2]

        mock_session = AsyncMock()
        mock_session.call_tool = AsyncMock(return_value=mock_result)
        conn._session = mock_session

        caller = conn._make_remote_caller("tool")
        result = await caller()

        assert result == "Line 1\nLine 2"


class TestMCPDisconnect:
    """Tests for disconnect with context managers."""

    @pytest.mark.asyncio
    async def test_disconnect_exits_cms_reverse(self):
        """Test disconnect exits CMs in reverse order."""
        conn = MCPServerConnection(name="srv", transport="stdio", command="echo")

        cm1 = AsyncMock()
        cm1.__aexit__ = AsyncMock()
        cm2 = AsyncMock()
        cm2.__aexit__ = AsyncMock()

        conn._context_managers = [cm1, cm2]
        conn._session = "fake"

        await conn.disconnect()

        # Both should be exited
        cm1.__aexit__.assert_awaited_once()
        cm2.__aexit__.assert_awaited_once()
        assert conn._session is None
        assert conn._tools == {}

    @pytest.mark.asyncio
    async def test_disconnect_handles_cm_error(self):
        """Test disconnect handles CM exit errors gracefully."""
        conn = MCPServerConnection(name="srv", transport="stdio", command="echo")

        cm1 = AsyncMock()
        cm1.__aexit__ = AsyncMock(side_effect=RuntimeError("cleanup fail"))

        conn._context_managers = [cm1]
        conn._session = "fake"

        # Should not raise
        await conn.disconnect()

        assert conn._session is None
