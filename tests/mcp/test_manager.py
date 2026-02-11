"""Tests for the MCP Manager module."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

from harombe.mcp.manager import MCPManager


def _make_config(name: str = "test-server") -> MagicMock:
    """Create a mock ExternalMCPServerConfig."""
    config = MagicMock()
    config.name = name
    config.transport = "stdio"
    config.command = "node"
    config.args = ["server.js"]
    config.env = {}
    config.url = None
    return config


# -- init / add_server -----------------------------------------------------------


def test_manager_init():
    mgr = MCPManager()
    assert mgr.server_names == []
    assert mgr.get_all_tools() == {}


def test_add_server():
    mgr = MCPManager()
    with patch("harombe.mcp.manager.MCPServerConnection"):
        mgr.add_server(_make_config("alpha"))
        mgr.add_server(_make_config("beta"))
    assert sorted(mgr.server_names) == ["alpha", "beta"]


# -- connect_all -----------------------------------------------------------------


async def test_connect_all_success():
    mgr = MCPManager()
    mock_conn = AsyncMock()
    with patch("harombe.mcp.manager.MCPServerConnection", return_value=mock_conn):
        mgr.add_server(_make_config("srv1"))
        mgr.add_server(_make_config("srv2"))
    await mgr.connect_all()
    assert mock_conn.connect.await_count == 2


async def test_connect_all_partial_failure():
    mgr = MCPManager()
    good_conn = AsyncMock()
    bad_conn = AsyncMock()
    bad_conn.connect.side_effect = RuntimeError("boom")

    conns = [bad_conn, good_conn]
    with patch("harombe.mcp.manager.MCPServerConnection", side_effect=conns):
        mgr.add_server(_make_config("bad"))
        mgr.add_server(_make_config("good"))

    # Should not raise even though one server fails
    await mgr.connect_all()
    bad_conn.connect.assert_awaited_once()
    good_conn.connect.assert_awaited_once()


# -- disconnect_all --------------------------------------------------------------


async def test_disconnect_all():
    mgr = MCPManager()
    mock_conn = AsyncMock()
    with patch("harombe.mcp.manager.MCPServerConnection", return_value=mock_conn):
        mgr.add_server(_make_config("srv"))
    await mgr.disconnect_all()
    mock_conn.disconnect.assert_awaited_once()


# -- get_all_tools ---------------------------------------------------------------


def test_get_all_tools_merged():
    mgr = MCPManager()

    conn_a = MagicMock()
    conn_a.tools = {"tool_a": MagicMock()}
    conn_b = MagicMock()
    conn_b.tools = {"tool_b": MagicMock()}

    with patch("harombe.mcp.manager.MCPServerConnection", side_effect=[conn_a, conn_b]):
        mgr.add_server(_make_config("a"))
        mgr.add_server(_make_config("b"))

    merged = mgr.get_all_tools()
    assert "tool_a" in merged
    assert "tool_b" in merged


# -- get_server ------------------------------------------------------------------


def test_get_server_found_and_not_found():
    mgr = MCPManager()
    with patch("harombe.mcp.manager.MCPServerConnection") as mock_cls:
        mock_instance = MagicMock()
        mock_cls.return_value = mock_instance
        mgr.add_server(_make_config("myserver"))

    assert mgr.get_server("myserver") is mock_instance
    assert mgr.get_server("unknown") is None
