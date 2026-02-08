"""Server management commands."""

from pathlib import Path
from typing import Optional

from rich.console import Console

console = Console()


def start_command(config_path: Optional[str] = None, detach: bool = False):
    """Start the Harombe API server.

    Args:
        config_path: Optional path to config file
        detach: Run server in background
    """
    # Import here to avoid circular imports
    import asyncio
    import uvicorn

    from harombe.config.loader import load_config
    from harombe.server.app import create_app

    # Load config
    path = Path(config_path) if config_path else None
    try:
        config = load_config(path)
    except Exception as e:
        console.print(f"[red]Failed to load config: {e}[/red]")
        console.print("Run [bold]harombe init[/bold] to create a config file.")
        return

    # Create app
    app = create_app(config)

    console.print(f"[green]Starting Harombe server on {config.server.host}:{config.server.port}[/green]")
    console.print(f"Model: {config.model.name}")
    console.print("\nPress Ctrl+C to stop")

    # Run server
    uvicorn.run(
        app,
        host=config.server.host,
        port=config.server.port,
        log_level="info",
    )


def stop_command():
    """Stop the Harombe API server."""
    console.print("[yellow]Server stop command not yet implemented[/yellow]")
    console.print("For now, use Ctrl+C to stop the server process")


def status_command():
    """Check Harombe server status."""
    console.print("[yellow]Server status command not yet implemented[/yellow]")
    console.print("Try: [bold]curl http://localhost:8000/health[/bold]")
