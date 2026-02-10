"""MCP transport entry points for running the Harombe MCP server."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from mcp.server.stdio import stdio_server
from mcp.server.streamable_http import StreamableHTTPServerTransport

if TYPE_CHECKING:
    from mcp.server import Server

logger = logging.getLogger(__name__)


async def run_stdio_server(server: Server) -> None:
    """Run MCP server over stdio transport.

    Args:
        server: Configured MCP Server instance
    """
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


async def run_streamable_http_server(
    server: Server,
    host: str = "127.0.0.1",
    port: int = 8200,
) -> None:
    """Run MCP server over Streamable HTTP transport.

    Args:
        server: Configured MCP Server instance
        host: Bind host
        port: Bind port
    """
    try:
        import uvicorn
        from starlette.applications import Starlette
        from starlette.routing import Mount
    except ImportError as err:
        raise RuntimeError(
            "HTTP transport requires starlette and uvicorn. "
            "These are already in harombe's dependencies."
        ) from err

    transport = StreamableHTTPServerTransport("/mcp")

    async def handle_mcp(scope: Any, receive: Any, send: Any) -> None:
        async with transport.connect() as (read_stream, write_stream):
            await server.run(read_stream, write_stream, server.create_initialization_options())

    app = Starlette(
        routes=[Mount("/mcp", app=transport.handle_request)],
    )

    logger.info("Starting MCP HTTP server on %s:%d", host, port)
    config = uvicorn.Config(app, host=host, port=port, log_level="info")
    server_instance = uvicorn.Server(config)
    await server_instance.serve()
