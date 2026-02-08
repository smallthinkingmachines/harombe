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
    """Show harombe version."""
    console.print(f"harombe version {__version__}")


@app.command()
def init(
    force: bool = typer.Option(False, "--force", "-f", help="Overwrite existing config"),
    non_interactive: bool = typer.Option(
        False, "--non-interactive", "-y", help="Use defaults without prompting"
    ),
    model: str = typer.Option(None, "--model", "-m", help="Specify model name"),
):
    """Initialize harombe configuration with hardware detection."""
    from harombe.cli.init_cmd import init_command

    init_command(force=force, non_interactive=non_interactive, model=model)


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
    """Start harombe API server."""
    from harombe.cli.server_cmd import start_command

    start_command(config_path=config_path, detach=detach)


@app.command()
def stop():
    """Stop harombe API server."""
    from harombe.cli.server_cmd import stop_command

    stop_command()


@app.command()
def status():
    """Check harombe server status."""
    from harombe.cli.server_cmd import status_command

    status_command()


@app.command()
def doctor():
    """Run system health checks and diagnostics."""
    from harombe.cli.doctor import doctor_command

    doctor_command()


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
