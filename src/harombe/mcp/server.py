"""MCP Server exposing Harombe tools to external clients."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from mcp.server import Server
from mcp.types import TextContent
from mcp.types import Tool as MCPTool

from harombe.mcp.converters import harombe_tool_to_mcp_input_schema

if TYPE_CHECKING:
    from harombe.tools.base import Tool

logger = logging.getLogger(__name__)


def create_mcp_server(
    tools: dict[str, Tool],
    server_name: str = "harombe",
) -> Server:
    """Create an MCP Server that exposes Harombe tools.

    Args:
        tools: Dictionary mapping tool names to Tool instances
        server_name: Name for the MCP server

    Returns:
        Configured MCP Server instance
    """
    server = Server(server_name)

    @server.list_tools()
    async def list_tools() -> list[MCPTool]:
        """Return all registered tools in MCP format."""
        mcp_tools: list[MCPTool] = []
        for name, tool in tools.items():
            mcp_tools.append(
                MCPTool(
                    name=name,
                    description=tool.schema.description,
                    inputSchema=harombe_tool_to_mcp_input_schema(tool),
                )
            )
        return mcp_tools

    @server.call_tool()
    async def call_tool(name: str, arguments: dict[str, Any] | None) -> list[TextContent]:
        """Execute a tool and return the result."""
        if name not in tools:
            raise ValueError(f"Unknown tool: {name}")

        tool = tools[name]
        args = arguments or {}

        try:
            result = await tool.execute(**args)
            return [TextContent(type="text", text=result)]
        except Exception as e:
            logger.error("Tool %s failed: %s", name, e)
            return [TextContent(type="text", text=f"Error executing {name}: {e}")]

    return server
