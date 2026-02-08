"""Main CLI application using Typer."""

import sys

import typer
from rich.console import Console

from harombe import __version__

# Create Typer app
app = typer.Typer(
    name="harombe",
    help="Harombe - Declarative self-hosted AI assistant platform",
    no_args_is_help=True,
)

console = Console()


@app.command()
def version():
    """Show Harombe version."""
    console.print(f"Harombe version {__version__}")


@app.command()
def init(
    force: bool = typer.Option(False, "--force", "-f", help="Overwrite existing config"),
):
    """Initialize Harombe configuration with hardware detection."""
    from harombe.cli.init_cmd import init_command

    init_command(force=force)


@app.command()
def chat(
    config_path: str = typer.Option(
        None,
        "--config",
        "-c",
        help="Path to config file (default: ~/.harombe/harombe.yaml)",
    ),
):
    """Start interactive chat session."""
    from harombe.cli.chat import chat_command

    chat_command(config_path=config_path)


@app.command()
def start(
    config_path: str = typer.Option(
        None,
        "--config",
        "-c",
        help="Path to config file",
    ),
    detach: bool = typer.Option(False, "--detach", "-d", help="Run server in background"),
):
    """Start Harombe API server."""
    from harombe.cli.server_cmd import start_command

    start_command(config_path=config_path, detach=detach)


@app.command()
def stop():
    """Stop Harombe API server."""
    from harombe.cli.server_cmd import stop_command

    stop_command()


@app.command()
def status():
    """Check Harombe server status."""
    from harombe.cli.server_cmd import status_command

    status_command()


def main():
    """Entry point for the CLI."""
    try:
        app()
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user[/yellow]")
        sys.exit(130)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


if __name__ == "__main__":
    main()
