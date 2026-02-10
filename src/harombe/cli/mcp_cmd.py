"""CLI commands for MCP server management."""

from __future__ import annotations

import asyncio
from pathlib import Path

from rich.console import Console

console = Console()


def serve_command(
    transport: str = "stdio",
    host: str = "127.0.0.1",
    port: int = 8200,
    config_path: str | None = None,
) -> None:
    """Start the MCP server exposing harombe tools.

    Args:
        transport: Transport type (stdio or http)
        host: Bind host for HTTP transport
        port: Bind port for HTTP transport
        config_path: Optional path to config file
    """
    from harombe.config.loader import load_config

    path = Path(config_path) if config_path else None
    try:
        config = load_config(path)
    except Exception as e:
        console.print(f"[red]Failed to load config: {e}[/red]")
        return

    # Import and register tools
    import harombe.tools.filesystem
    import harombe.tools.shell
    import harombe.tools.web_search  # noqa: F401
    from harombe.tools.registry import get_enabled_tools

    tools_list = get_enabled_tools(
        shell=config.tools.shell,
        filesystem=config.tools.filesystem,
        web_search=config.tools.web_search,
    )
    tools_dict = {t.schema.name: t for t in tools_list}

    from harombe.mcp.server import create_mcp_server

    server = create_mcp_server(tools_dict)

    if transport == "stdio":
        console.print("[cyan]Starting MCP server (stdio transport)...[/cyan]")
        from harombe.mcp.transports import run_stdio_server

        asyncio.run(run_stdio_server(server))
    elif transport in ("http", "streamable-http"):
        console.print(f"[cyan]Starting MCP server (HTTP) on {host}:{port}...[/cyan]")
        from harombe.mcp.transports import run_streamable_http_server

        asyncio.run(run_streamable_http_server(server, host=host, port=port))
    else:
        console.print(f"[red]Unknown transport: {transport}[/red]")
        console.print("Supported: stdio, http")
