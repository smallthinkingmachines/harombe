"""MCP Manager orchestrating multiple server connections."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from harombe.mcp.client import MCPServerConnection

if TYPE_CHECKING:
    from harombe.config.schema import ExternalMCPServerConfig
    from harombe.tools.base import Tool

logger = logging.getLogger(__name__)


class MCPManager:
    """Orchestrates multiple MCPServerConnection instances.

    Manages lifecycle (connect/disconnect/reconnect) and provides
    a unified view of all tools from all connected servers.
    """

    def __init__(self) -> None:
        self._connections: dict[str, MCPServerConnection] = {}

    def add_server(self, config: ExternalMCPServerConfig) -> None:
        """Register a server for connection.

        Args:
            config: External MCP server configuration
        """
        self._connections[config.name] = MCPServerConnection(
            name=config.name,
            transport=config.transport,
            command=config.command,
            args=config.args,
            env=config.env,
            url=config.url,
        )

    async def connect_all(self) -> None:
        """Connect to all registered servers."""
        for name, conn in self._connections.items():
            try:
                await conn.connect()
                logger.info("Connected to MCP server '%s'", name)
            except Exception as e:
                logger.warning("Failed to connect to MCP server '%s': %s", name, e)

    async def disconnect_all(self) -> None:
        """Disconnect from all servers."""
        for name, conn in self._connections.items():
            try:
                await conn.disconnect()
            except Exception as e:
                logger.warning("Error disconnecting from '%s': %s", name, e)

    def get_all_tools(self) -> dict[str, Tool]:
        """Get merged tools from all connected servers.

        Returns:
            Dictionary mapping prefixed tool names to Tool instances
        """
        all_tools: dict[str, Tool] = {}
        for conn in self._connections.values():
            all_tools.update(conn.tools)
        return all_tools

    def get_server(self, name: str) -> MCPServerConnection | None:
        """Get a specific server connection.

        Args:
            name: Server name

        Returns:
            MCPServerConnection or None
        """
        return self._connections.get(name)

    @property
    def server_names(self) -> list[str]:
        """List all registered server names."""
        return list(self._connections.keys())
