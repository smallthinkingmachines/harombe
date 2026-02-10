"""Main CLI application using Typer."""

import sys

import typer
from rich.console import Console

from harombe import __version__

# Create Typer app
app = typer.Typer(
    name="harombe",
    help="Harombe - Self-hosted agent framework for distributed AI workloads",
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


# Plugin commands
plugin_app = typer.Typer(help="Manage harombe plugins")
app.add_typer(plugin_app, name="plugin")


@plugin_app.command("list")
def plugin_list():
    """List all installed plugins."""
    from harombe.cli.plugin_cmd import list_plugins

    list_plugins()


@plugin_app.command("info")
def plugin_info(
    name: str = typer.Argument(..., help="Plugin name"),
):
    """Show detailed information about a plugin."""
    from harombe.cli.plugin_cmd import info_plugin

    info_plugin(name)


@plugin_app.command("enable")
def plugin_enable(
    name: str = typer.Argument(..., help="Plugin name"),
):
    """Enable a plugin."""
    from harombe.cli.plugin_cmd import enable_plugin

    enable_plugin(name)


@plugin_app.command("disable")
def plugin_disable(
    name: str = typer.Argument(..., help="Plugin name"),
):
    """Disable a plugin."""
    from harombe.cli.plugin_cmd import disable_plugin

    disable_plugin(name)


# MCP commands
mcp_app = typer.Typer(help="Model Context Protocol server and client management")
app.add_typer(mcp_app, name="mcp")


@mcp_app.command("serve")
def mcp_serve(
    transport: str = typer.Option(
        "stdio",
        "--transport",
        "-t",
        help="Transport type: stdio or http",
    ),
    host: str = typer.Option(
        "127.0.0.1",
        "--host",
        help="Bind host (HTTP transport only)",
    ),
    port: int = typer.Option(
        8200,
        "--port",
        "-p",
        help="Bind port (HTTP transport only)",
    ),
    config_path: str = typer.Option(
        None,
        "--config",
        "-c",
        help="Path to config file",
    ),
):
    """Start MCP server to expose harombe tools."""
    from harombe.cli.mcp_cmd import serve_command

    serve_command(transport=transport, host=host, port=port, config_path=config_path)


# Cluster management commands (Phase 1)
cluster_app = typer.Typer(help="Manage multi-machine cluster orchestration")
app.add_typer(cluster_app, name="cluster")


# Audit log commands (Phase 4.2)
audit_app = typer.Typer(help="Query and analyze security audit logs")
app.add_typer(audit_app, name="audit")


@cluster_app.command("init")
def cluster_init():
    """Generate cluster configuration template."""
    from harombe.cli.cluster_cmd import cluster_init_command

    cluster_init_command()


@cluster_app.command("status")
def cluster_status(
    config_path: str = typer.Option(
        None,
        "--config",
        "-c",
        help="Path to config file",
    ),
):
    """Show cluster status and node health."""
    from harombe.cli.cluster_cmd import cluster_status_command

    cluster_status_command(config_path=config_path)


@cluster_app.command("test")
def cluster_test(
    config_path: str = typer.Option(
        None,
        "--config",
        "-c",
        help="Path to config file",
    ),
):
    """Test connectivity to all cluster nodes."""
    from harombe.cli.cluster_cmd import cluster_test_command

    cluster_test_command(config_path=config_path)


@cluster_app.command("metrics")
def cluster_metrics(
    config_path: str = typer.Option(
        None,
        "--config",
        "-c",
        help="Path to config file",
    ),
    node: str = typer.Option(
        None,
        "--node",
        "-n",
        help="Show metrics for specific node only",
    ),
):
    """Show cluster performance metrics."""
    from harombe.cli.cluster_cmd import cluster_metrics_command

    cluster_metrics_command(config_path=config_path, node=node)


@audit_app.command("events")
def audit_events(
    db_path: str = typer.Option(
        "~/.harombe/audit.db",
        "--db",
        "-d",
        help="Path to audit database",
    ),
    session_id: str = typer.Option(
        None,
        "--session",
        "-s",
        help="Filter by session ID",
    ),
    correlation_id: str = typer.Option(
        None,
        "--correlation",
        "-c",
        help="Filter by correlation ID",
    ),
    limit: int = typer.Option(
        20,
        "--limit",
        "-n",
        help="Maximum number of events to show",
    ),
    output_format: str = typer.Option(
        "table",
        "--format",
        "-f",
        help="Output format (table, json, csv)",
    ),
):
    """Query audit events."""
    from harombe.cli.audit_cmd import query_events

    query_events(
        db_path=db_path,
        session_id=session_id,
        correlation_id=correlation_id,
        limit=limit,
        output_format=output_format,
    )


@audit_app.command("tools")
def audit_tools(
    db_path: str = typer.Option(
        "~/.harombe/audit.db",
        "--db",
        "-d",
        help="Path to audit database",
    ),
    tool_name: str = typer.Option(
        None,
        "--tool",
        "-t",
        help="Filter by tool name",
    ),
    hours: int = typer.Option(
        None,
        "--hours",
        "-h",
        help="Only show calls from last N hours",
    ),
    limit: int = typer.Option(
        20,
        "--limit",
        "-n",
        help="Maximum number of calls to show",
    ),
    output_format: str = typer.Option(
        "table",
        "--format",
        "-f",
        help="Output format (table, json, csv)",
    ),
):
    """Query tool execution logs."""
    from harombe.cli.audit_cmd import query_tools

    query_tools(
        db_path=db_path,
        tool_name=tool_name,
        hours=hours,
        limit=limit,
        output_format=output_format,
    )


@audit_app.command("security")
def audit_security(
    db_path: str = typer.Option(
        "~/.harombe/audit.db",
        "--db",
        "-d",
        help="Path to audit database",
    ),
    decision_type: str = typer.Option(
        None,
        "--type",
        "-t",
        help="Filter by decision type",
    ),
    decision: str = typer.Option(
        None,
        "--decision",
        help="Filter by decision outcome",
    ),
    limit: int = typer.Option(
        20,
        "--limit",
        "-n",
        help="Maximum number of decisions to show",
    ),
    output_format: str = typer.Option(
        "table",
        "--format",
        "-f",
        help="Output format (table, json, csv)",
    ),
):
    """Query security decisions."""
    from harombe.cli.audit_cmd import query_security

    query_security(
        db_path=db_path,
        decision_type=decision_type,
        decision=decision,
        limit=limit,
        output_format=output_format,
    )


@audit_app.command("stats")
def audit_stats(
    db_path: str = typer.Option(
        "~/.harombe/audit.db",
        "--db",
        "-d",
        help="Path to audit database",
    ),
    hours: int = typer.Option(
        None,
        "--hours",
        "-h",
        help="Only show stats from last N hours",
    ),
):
    """Show audit log statistics."""
    from harombe.cli.audit_cmd import stats

    stats(db_path=db_path, hours=hours)


@audit_app.command("export")
def audit_export(
    output_path: str = typer.Argument(
        ...,
        help="Output file path",
    ),
    db_path: str = typer.Option(
        "~/.harombe/audit.db",
        "--db",
        "-d",
        help="Path to audit database",
    ),
    hours: int = typer.Option(
        None,
        "--hours",
        "-h",
        help="Only export logs from last N hours",
    ),
    format: str = typer.Option(
        "json",
        "--format",
        "-f",
        help="Export format (json, csv)",
    ),
):
    """Export audit logs to file."""
    from pathlib import Path

    from harombe.cli.audit_cmd import export

    export(output_path=Path(output_path), db_path=db_path, hours=hours, format=format)


@app.command()
def voice(
    stt_model: str = typer.Option(
        "medium",
        "--stt-model",
        help="Whisper model size (tiny/base/small/medium/large-v3)",
    ),
    tts_engine: str = typer.Option(
        "piper",
        "--tts-engine",
        help="TTS engine (piper/coqui)",
    ),
    tts_model: str = typer.Option(
        "en_US-lessac-medium",
        "--tts-model",
        help="TTS model name",
    ),
):
    """Start interactive voice assistant (push-to-talk)."""
    import asyncio

    from harombe.cli.voice import voice_command

    asyncio.run(voice_command(stt_model=stt_model, tts_engine=tts_engine, tts_model=tts_model))


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
