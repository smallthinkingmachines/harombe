"""Server management commands."""

import os
import signal
import subprocess
import sys
from pathlib import Path

import httpx
from rich.console import Console

PID_FILE = Path.home() / ".harombe" / "server.pid"

console = Console()


def _write_pid(pid: int) -> None:
    """Write PID file."""
    PID_FILE.parent.mkdir(parents=True, exist_ok=True)
    PID_FILE.write_text(str(pid))


def _read_pid() -> int | None:
    """Read PID from file, return None if missing or stale."""
    if not PID_FILE.exists():
        return None
    try:
        pid = int(PID_FILE.read_text().strip())
        # Check if process is still alive
        os.kill(pid, 0)
        return pid
    except (ValueError, ProcessLookupError, PermissionError):
        PID_FILE.unlink(missing_ok=True)
        return None


def _remove_pid() -> None:
    """Remove PID file."""
    PID_FILE.unlink(missing_ok=True)


def start_command(config_path: str | None = None, detach: bool = False) -> None:
    """Start the harombe API server.

    Args:
        config_path: Optional path to config file
        detach: Run server in background
    """
    from harombe.config.loader import load_config

    # Check if already running
    existing_pid = _read_pid()
    if existing_pid:
        console.print(f"[yellow]Server already running (PID {existing_pid})[/yellow]")
        console.print("Run [bold]harombe stop[/bold] first.")
        return

    # Load config
    path = Path(config_path) if config_path else None
    try:
        config = load_config(path)
    except Exception as e:
        console.print(f"[red]Failed to load config: {e}[/red]")
        console.print("Run [bold]harombe init[/bold] to create a config file.")
        return

    if detach:
        # Fork to background
        cmd = [
            sys.executable,
            "-m",
            "uvicorn",
            "harombe.server.asgi:app",
            "--host",
            config.server.host,
            "--port",
            str(config.server.port),
            "--log-level",
            "info",
        ]
        log_path = Path.home() / ".harombe" / "server.log"
        log_file = log_path.open("a")
        proc = subprocess.Popen(
            cmd,
            stdout=log_file,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        _write_pid(proc.pid)
        console.print(f"[green]harombe server started in background (PID {proc.pid})[/green]")
        console.print(f"  http://{config.server.host}:{config.server.port}")
        console.print(f"  Log: {log_path}")
        console.print("\nRun [bold]harombe stop[/bold] to stop.")
    else:
        # Foreground mode — write our own PID so `harombe stop` works
        import uvicorn

        from harombe.server.app import create_app

        app = create_app(config)
        _write_pid(os.getpid())

        console.print(
            f"[green]Starting harombe server on "
            f"{config.server.host}:{config.server.port}[/green]"
        )
        console.print(f"Model: {config.model.name}")
        console.print("\nPress Ctrl+C to stop")

        try:
            uvicorn.run(
                app,
                host=config.server.host,
                port=config.server.port,
                log_level="info",
            )
        finally:
            _remove_pid()


def stop_command() -> None:
    """Stop the harombe API server."""
    pid = _read_pid()
    if pid is None:
        console.print("[yellow]No running harombe server found.[/yellow]")
        return

    try:
        os.kill(pid, signal.SIGTERM)
        console.print(f"[green]Stopped harombe server (PID {pid})[/green]")
    except ProcessLookupError:
        console.print("[yellow]Server process already exited.[/yellow]")
    finally:
        _remove_pid()


def status_command() -> None:
    """Check harombe server status."""
    from harombe.config.loader import load_config

    pid = _read_pid()

    # Try loading config for host/port
    try:
        config = load_config()
        host = config.server.host
        port = config.server.port
    except Exception:
        host = "127.0.0.1"
        port = 8000

    # Check if health endpoint responds
    try:
        resp = httpx.get(f"http://{host}:{port}/health", timeout=3.0)
        data = resp.json()
        console.print("[green]Server is running[/green]")
        if pid:
            console.print(f"  PID:     {pid}")
        console.print(f"  URL:     http://{host}:{port}")
        console.print(f"  Model:   {data.get('model', 'unknown')}")
        console.print(f"  Version: {data.get('version', 'unknown')}")
    except Exception:
        if pid:
            console.print(f"[yellow]PID {pid} exists but health check failed.[/yellow]")
        else:
            console.print("[yellow]Server is not running.[/yellow]")
            console.print("Start with: [bold]harombe start[/bold]")
