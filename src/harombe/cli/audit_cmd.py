"""Audit log query CLI commands.

Provides commands to query and analyze audit logs for security analysis
and compliance reporting.
"""

import csv
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.table import Table

from harombe.security.audit_db import AuditDatabase, SecurityDecision

console = Console()


def _format_timestamp(ts: str | datetime) -> str:
    """Format timestamp for display.

    Args:
        ts: Timestamp string or datetime

    Returns:
        Formatted timestamp
    """
    if isinstance(ts, str):
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except ValueError:
            return ts
    else:
        dt = ts

    return dt.strftime("%Y-%m-%d %H:%M:%S")


def _format_duration(ms: int | None) -> str:
    """Format duration for display.

    Args:
        ms: Duration in milliseconds

    Returns:
        Formatted duration
    """
    if ms is None:
        return "N/A"
    if ms < 1000:
        return f"{ms}ms"
    return f"{ms/1000:.2f}s"


def query_events(
    db_path: str = typer.Option(
        "~/.harombe/audit.db",
        "--db",
        "-d",
        help="Path to audit database",
    ),
    session_id: str | None = typer.Option(
        None,
        "--session",
        "-s",
        help="Filter by session ID",
    ),
    correlation_id: str | None = typer.Option(
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
) -> None:
    """Query audit events."""
    try:
        db = AuditDatabase(db_path=db_path, retention_days=0)  # Don't cleanup

        # Get events
        if correlation_id:
            events = db.get_events_by_correlation(correlation_id)
        elif session_id:
            events = db.get_events_by_session(session_id, limit=limit)
        else:
            # Get recent events
            events = db.get_events_by_session(session_id or "", limit=limit)

        if not events:
            console.print("[yellow]No events found[/yellow]")
            return

        # Output format
        if output_format == "json":
            console.print_json(data=events)
        elif output_format == "csv":
            if events:
                writer = csv.DictWriter(console.file, fieldnames=events[0].keys())
                writer.writeheader()
                writer.writerows(events)
        else:  # table
            table = Table(title=f"Audit Events ({len(events)} records)")
            table.add_column("Timestamp", style="cyan")
            table.add_column("Type", style="magenta")
            table.add_column("Actor", style="green")
            table.add_column("Tool", style="yellow")
            table.add_column("Action", style="blue")
            table.add_column("Status", style="bold")
            table.add_column("Duration", justify="right")

            for event in events:
                status_color = "green" if event["status"] == "success" else "red"
                table.add_row(
                    _format_timestamp(event["timestamp"]),
                    event["event_type"],
                    event["actor"] or "N/A",
                    event["tool_name"] or "N/A",
                    event["action"],
                    f"[{status_color}]{event['status']}[/{status_color}]",
                    _format_duration(event.get("duration_ms")),
                )

            console.print(table)

    except Exception as e:
        console.print(f"[red]Error querying events: {e}[/red]")
        raise typer.Exit(1) from None


def query_tools(
    db_path: str = typer.Option(
        "~/.harombe/audit.db",
        "--db",
        "-d",
        help="Path to audit database",
    ),
    tool_name: str | None = typer.Option(
        None,
        "--tool",
        "-t",
        help="Filter by tool name",
    ),
    hours: int | None = typer.Option(
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
) -> None:
    """Query tool execution logs."""
    try:
        db = AuditDatabase(db_path=db_path, retention_days=0)

        # Calculate time range
        start_time = None
        end_time = None
        if hours:
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(hours=hours)

        # Get tool calls
        calls = db.get_tool_calls(
            tool_name=tool_name,
            start_time=start_time,
            end_time=end_time,
            limit=limit,
        )

        if not calls:
            console.print("[yellow]No tool calls found[/yellow]")
            return

        # Output format
        if output_format == "json":
            console.print_json(data=calls)
        elif output_format == "csv":
            if calls:
                writer = csv.DictWriter(console.file, fieldnames=calls[0].keys())
                writer.writeheader()
                writer.writerows(calls)
        else:  # table
            table = Table(title=f"Tool Calls ({len(calls)} records)")
            table.add_column("Timestamp", style="cyan")
            table.add_column("Tool", style="yellow")
            table.add_column("Method", style="blue")
            table.add_column("Status", style="bold")
            table.add_column("Duration", justify="right")
            table.add_column("Container", style="dim")

            for call in calls:
                status = "✓" if call.get("error") is None else "✗"
                status_color = "green" if call.get("error") is None else "red"

                table.add_row(
                    _format_timestamp(call["timestamp"]),
                    call["tool_name"],
                    call["method"],
                    f"[{status_color}]{status}[/{status_color}]",
                    _format_duration(call.get("duration_ms")),
                    call.get("container_id", "N/A"),
                )

            console.print(table)

    except Exception as e:
        console.print(f"[red]Error querying tool calls: {e}[/red]")
        raise typer.Exit(1) from None


def query_security(
    db_path: str = typer.Option(
        "~/.harombe/audit.db",
        "--db",
        "-d",
        help="Path to audit database",
    ),
    decision_type: str | None = typer.Option(
        None,
        "--type",
        "-t",
        help="Filter by decision type (authorization, egress, secret_scan, hitl)",
    ),
    decision: str | None = typer.Option(
        None,
        "--decision",
        help="Filter by decision (allow, deny, require_confirmation, redacted)",
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
) -> None:
    """Query security decisions."""
    try:
        db = AuditDatabase(db_path=db_path, retention_days=0)

        # Parse decision enum
        decision_enum = None
        if decision:
            try:
                decision_enum = SecurityDecision(decision)
            except ValueError:
                console.print(
                    f"[red]Invalid decision: {decision}. "
                    f"Must be one of: allow, deny, require_confirmation, redacted[/red]"
                )
                raise typer.Exit(1) from None

        # Get security decisions
        decisions = db.get_security_decisions(
            decision_type=decision_type,
            decision=decision_enum,
            limit=limit,
        )

        if not decisions:
            console.print("[yellow]No security decisions found[/yellow]")
            return

        # Output format
        if output_format == "json":
            console.print_json(data=decisions)
        elif output_format == "csv":
            if decisions:
                writer = csv.DictWriter(console.file, fieldnames=decisions[0].keys())
                writer.writeheader()
                writer.writerows(decisions)
        else:  # table
            table = Table(title=f"Security Decisions ({len(decisions)} records)")
            table.add_column("Timestamp", style="cyan")
            table.add_column("Type", style="magenta")
            table.add_column("Decision", style="bold")
            table.add_column("Tool", style="yellow")
            table.add_column("Actor", style="green")
            table.add_column("Reason", style="dim")

            for dec in decisions:
                decision_color = {
                    "allow": "green",
                    "deny": "red",
                    "require_confirmation": "yellow",
                    "redacted": "blue",
                }.get(dec["decision"], "white")

                table.add_row(
                    _format_timestamp(dec["timestamp"]),
                    dec["decision_type"],
                    f"[{decision_color}]{dec['decision']}[/{decision_color}]",
                    dec.get("tool_name", "N/A"),
                    dec["actor"],
                    dec["reason"][:50] + "..." if len(dec["reason"]) > 50 else dec["reason"],
                )

            console.print(table)

    except Exception as e:
        console.print(f"[red]Error querying security decisions: {e}[/red]")
        raise typer.Exit(1) from None


def stats(
    db_path: str = typer.Option(
        "~/.harombe/audit.db",
        "--db",
        "-d",
        help="Path to audit database",
    ),
    hours: int | None = typer.Option(
        None,
        "--hours",
        "-h",
        help="Only show stats from last N hours",
    ),
) -> None:
    """Show audit log statistics."""
    try:
        db = AuditDatabase(db_path=db_path, retention_days=0)

        # Calculate time range
        start_time = None
        end_time = None
        if hours:
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(hours=hours)

        # Get statistics
        statistics = db.get_statistics(start_time=start_time, end_time=end_time)

        # Display event statistics
        console.print("\n[bold cyan]Event Statistics[/bold cyan]")
        event_stats = statistics["events"]
        console.print(f"Total events: {event_stats['total_events']}")
        console.print(f"Unique sessions: {event_stats['unique_sessions']}")
        console.print(f"Unique requests: {event_stats['unique_requests']}")

        # Display tool statistics
        console.print("\n[bold cyan]Tool Usage[/bold cyan]")
        tool_stats = statistics["tools"]
        if tool_stats:
            table = Table()
            table.add_column("Tool", style="yellow")
            table.add_column("Calls", justify="right", style="cyan")
            table.add_column("Avg Duration", justify="right", style="green")

            for tool in tool_stats:
                avg_duration = tool.get("avg_duration_ms")
                table.add_row(
                    tool["tool_name"],
                    str(tool["call_count"]),
                    _format_duration(int(avg_duration) if avg_duration else None),
                )

            console.print(table)
        else:
            console.print("[dim]No tool calls recorded[/dim]")

        # Display security decision statistics
        console.print("\n[bold cyan]Security Decisions[/bold cyan]")
        decision_stats = statistics["security_decisions"]
        if decision_stats:
            table = Table()
            table.add_column("Decision", style="bold")
            table.add_column("Count", justify="right", style="cyan")

            for dec in decision_stats:
                decision_color = {
                    "allow": "green",
                    "deny": "red",
                    "require_confirmation": "yellow",
                    "redacted": "blue",
                }.get(dec["decision"], "white")

                table.add_row(
                    f"[{decision_color}]{dec['decision']}[/{decision_color}]",
                    str(dec["count"]),
                )

            console.print(table)
        else:
            console.print("[dim]No security decisions recorded[/dim]")

        console.print()

    except Exception as e:
        console.print(f"[red]Error generating statistics: {e}[/red]")
        raise typer.Exit(1) from None


def export(
    output_path: Path = typer.Argument(  # noqa: B008
        ...,
        help="Output file path (e.g., audit_export.json)",
    ),
    db_path: str = typer.Option(
        "~/.harombe/audit.db",
        "--db",
        "-d",
        help="Path to audit database",
    ),
    hours: int | None = typer.Option(
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
) -> None:
    """Export audit logs to file."""
    try:
        db = AuditDatabase(db_path=db_path, retention_days=0)

        # Calculate time range
        start_time = None
        end_time = None
        if hours:
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(hours=hours)

        # Collect all data
        events: list[dict[str, Any]] = []
        tool_calls = db.get_tool_calls(start_time=start_time, end_time=end_time, limit=100000)
        decisions = db.get_security_decisions(limit=100000)

        # Export based on format
        if format == "json":
            export_data = {
                "events": events,
                "tool_calls": tool_calls,
                "security_decisions": decisions,
                "exported_at": datetime.utcnow().isoformat(),
            }

            with open(output_path, "w") as f:
                json.dump(export_data, f, indent=2, default=str)

            console.print(
                f"[green]✓[/green] Exported {len(tool_calls)} tool calls and {len(decisions)} decisions to {output_path}"
            )

        elif format == "csv":
            # Export tool calls to CSV
            with open(output_path, "w", newline="") as f:
                if tool_calls:
                    writer = csv.DictWriter(f, fieldnames=tool_calls[0].keys())
                    writer.writeheader()
                    writer.writerows(tool_calls)

            console.print(
                f"[green]✓[/green] Exported {len(tool_calls)} tool calls to {output_path}"
            )

        else:
            console.print(f"[red]Invalid format: {format}. Use 'json' or 'csv'[/red]")
            raise typer.Exit(1) from None

    except Exception as e:
        console.print(f"[red]Error exporting audit logs: {e}[/red]")
        raise typer.Exit(1) from None
