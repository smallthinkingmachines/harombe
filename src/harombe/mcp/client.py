"""MCP Client for connecting to external MCP servers."""

from __future__ import annotations

import logging
from typing import Any

from harombe.mcp.converters import mcp_tool_to_harombe_schema
from harombe.tools.base import Tool, ToolFunction
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.client.streamable_http import streamablehttp_client

logger = logging.getLogger(__name__)


class MCPServerConnection:
    """Connection to a single external MCP server.

    Discovers tools from the remote server and wraps each as a Harombe Tool
    with an async closure that calls the remote server.
    """

    def __init__(
        self,
        name: str,
        transport: str = "stdio",
        command: str | None = None,
        args: list[str] | None = None,
        env: dict[str, str] | None = None,
        url: str | None = None,
    ):
        """Initialize connection config.

        Args:
            name: Server name (used as tool prefix)
            transport: Transport type ("stdio" or "streamable-http")
            command: Command for stdio transport
            args: Arguments for the command
            env: Environment variables for the server process
            url: URL for HTTP transport
        """
        self.name = name
        self.transport = transport
        self.command = command
        self.args = args or []
        self.env = env or {}
        self.url = url
        self._tools: dict[str, Tool] = {}
        self._session: ClientSession | None = None
        self._context_managers: list[Any] = []

    @property
    def tools(self) -> dict[str, Tool]:
        """Get discovered tools (available after connect)."""
        return self._tools

    async def connect(self) -> None:
        """Connect to the MCP server and discover tools."""
        if self.transport == "stdio":
            if not self.command:
                raise ValueError(f"Server {self.name}: stdio transport requires 'command'")
            await self._connect_stdio()
        elif self.transport == "streamable-http":
            if not self.url:
                raise ValueError(f"Server {self.name}: streamable-http transport requires 'url'")
            await self._connect_http()
        else:
            raise ValueError(f"Unknown transport: {self.transport}")

        await self._discover_tools()

    async def _connect_stdio(self) -> None:
        """Connect via stdio transport."""
        server_params = StdioServerParameters(
            command=self.command,
            args=self.args,
            env=self.env if self.env else None,
        )
        # Enter the context manager and store for cleanup
        cm = stdio_client(server_params)
        read_stream, write_stream = await cm.__aenter__()
        self._context_managers.append(cm)

        session_cm = ClientSession(read_stream, write_stream)
        self._session = await session_cm.__aenter__()
        self._context_managers.append(session_cm)

        await self._session.initialize()

    async def _connect_http(self) -> None:
        """Connect via HTTP transport."""
        cm = streamablehttp_client(self.url)
        read_stream, write_stream, _ = await cm.__aenter__()
        self._context_managers.append(cm)

        session_cm = ClientSession(read_stream, write_stream)
        self._session = await session_cm.__aenter__()
        self._context_managers.append(session_cm)

        await self._session.initialize()

    async def _discover_tools(self) -> None:
        """Discover tools from the connected server."""
        if not self._session:
            raise RuntimeError("Not connected")

        response = await self._session.list_tools()

        for mcp_tool in response.tools:
            # Prefix tool name to avoid collisions
            prefixed_name = f"{self.name}__{mcp_tool.name}"
            schema = mcp_tool_to_harombe_schema(
                name=prefixed_name,
                description=mcp_tool.description,
                input_schema=mcp_tool.inputSchema if mcp_tool.inputSchema else {},
            )

            # Create a closure that calls the remote tool
            fn = self._make_remote_caller(mcp_tool.name)

            self._tools[prefixed_name] = Tool(schema=schema, fn=fn)

        logger.info(
            "Discovered %d tools from MCP server '%s'",
            len(self._tools),
            self.name,
        )

    def _make_remote_caller(self, remote_tool_name: str) -> ToolFunction:
        """Create an async function that calls a remote MCP tool.

        Args:
            remote_tool_name: Original tool name on the remote server

        Returns:
            Async callable matching ToolFunction signature
        """
        session = self._session

        async def call_remote_tool(**kwargs: Any) -> str:
            if session is None:
                return f"Error: Not connected to MCP server '{self.name}'"
            try:
                result = await session.call_tool(remote_tool_name, kwargs)
                # Extract text from content items
                texts = []
                for content in result.content:
                    if hasattr(content, "text"):
                        texts.append(content.text)
                return "\n".join(texts) if texts else "(no output)"
            except Exception as e:
                return f"Error calling {self.name}/{remote_tool_name}: {e}"

        return call_remote_tool

    async def disconnect(self) -> None:
        """Disconnect from the MCP server."""
        # Exit context managers in reverse order
        for cm in reversed(self._context_managers):
            try:
                await cm.__aexit__(None, None, None)
            except Exception:
                logger.debug("Error closing context manager for %s", self.name)
        self._context_managers.clear()
        self._session = None
        self._tools.clear()
