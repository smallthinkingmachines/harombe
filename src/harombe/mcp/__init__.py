"""Model Context Protocol (MCP) support for Harombe.

Provides:
- MCP Server: Expose Harombe tools to external MCP clients (Claude Desktop, etc.)
- MCP Client: Connect to external MCP servers to expand the tool ecosystem
- MCP Manager: Orchestrate multiple external MCP server connections
"""

from harombe.mcp.client import MCPServerConnection
from harombe.mcp.manager import MCPManager
from harombe.mcp.server import create_mcp_server

__all__ = [
    "MCPManager",
    "MCPServerConnection",
    "create_mcp_server",
]
