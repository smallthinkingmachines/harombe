"""CLI commands for cluster management."""

import asyncio
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.table import Table

from harombe.config.loader import DEFAULT_CONFIG_PATH, load_config
from harombe.coordination.cluster import ClusterManager, NodeStatus

console = Console()


def cluster_init_command():
    """Generate cluster configuration template."""
    console.print("[bold]Initializing cluster configuration...[/bold]\n")

    template = """# Cluster configuration for multi-machine orchestration

cluster:
  coordinator:
    host: localhost  # Any always-on machine

  discovery:
    method: explicit  # 'explicit' or 'mdns'
    mdns_service: _harombe._tcp.local

  routing:
    prefer_local: true
    fallback_strategy: graceful  # 'graceful' or 'strict'
    load_balance: true

  nodes:
    # Example node configurations (customize for your hardware)

    # Tier 0: Fast/local nodes
    # - name: my-laptop
    #   host: localhost
    #   port: 8000
    #   model: qwen2.5:3b
    #   tier: 0
    #   enabled: true

    # Tier 1: Medium/balanced nodes
    # - name: workstation
    #   host: 192.168.1.100
    #   port: 8000
    #   model: qwen2.5:14b
    #   tier: 1
    #   enabled: true

    # Tier 2: Powerful nodes
    # - name: server
    #   host: server.local
    #   port: 8000
    #   model: qwen2.5:72b
    #   tier: 2
    #   enabled: true

    # Cloud/remote nodes (optional)
    # - name: cloud-gpu
    #   host: 203.0.113.42
    #   port: 8000
    #   model: qwen2.5:32b
    #   tier: 2
    #   auth_token: your-token-here
    #   enabled: true

# Tiers are user-controlled, not hardware-specific:
# - Tier 0 (fast): Low latency, simple queries
# - Tier 1 (medium): Balanced performance
# - Tier 2 (powerful): Complex queries, large context
"""

    console.print(template)
    console.print("\n[green]✓[/green] Cluster configuration template generated")
    console.print("\nAdd the cluster configuration to your harombe.yaml file")
    console.print(f"Config location: [cyan]{DEFAULT_CONFIG_PATH}[/cyan]")


async def _async_status(config_path: Optional[str] = None):
    """Async implementation of cluster status check."""
    if config_path:
        config = load_config(Path(config_path))
    else:
        config = load_config()

    if not config.cluster or not config.cluster.nodes:
        console.print("[yellow]No cluster configured[/yellow]")
        console.print("\nRun [cyan]harombe cluster init[/cyan] to generate a configuration template")
        return

    console.print("[bold]Checking cluster status...[/bold]\n")

    # Initialize cluster manager
    cluster = ClusterManager(config.cluster)

    # Perform health checks
    await cluster.check_all_health()

    # Create status table
    table = Table(title="Cluster Status")
    table.add_column("Name", style="cyan")
    table.add_column("Host", style="white")
    table.add_column("Tier", style="magenta")
    table.add_column("Model", style="blue")
    table.add_column("Status", style="white")
    table.add_column("Latency", style="yellow")
    table.add_column("Load", style="green")

    for node_name in cluster._nodes.keys():
        node = cluster._nodes[node_name]
        health = cluster._health[node_name]

        # Format status with color
        if health.status == NodeStatus.AVAILABLE:
            status = "[green]available[/green]"
        elif health.status == NodeStatus.DEGRADED:
            status = "[yellow]degraded[/yellow]"
        else:
            status = "[red]unavailable[/red]"

        # Format latency
        latency = f"{health.latency_ms:.1f}ms" if health.status == NodeStatus.AVAILABLE else "-"

        # Format load
        load = f"{health.load:.0%}" if health.status == NodeStatus.AVAILABLE else "-"

        table.add_row(
            node.name,
            f"{node.host}:{node.port}",
            str(node.tier),
            node.model,
            status,
            latency,
            load,
        )

    console.print(table)

    # Summary
    available = sum(
        1
        for h in cluster._health.values()
        if h.status == NodeStatus.AVAILABLE
    )
    total = len(cluster._nodes)

    console.print(f"\n[bold]Summary:[/bold] {available}/{total} nodes available")

    await cluster.close()


def cluster_status_command(config_path: Optional[str] = None):
    """Show cluster status and node health."""
    asyncio.run(_async_status(config_path))


async def _async_test(config_path: Optional[str] = None):
    """Async implementation of cluster test."""
    if config_path:
        config = load_config(Path(config_path))
    else:
        config = load_config()

    if not config.cluster or not config.cluster.nodes:
        console.print("[yellow]No cluster configured[/yellow]")
        return

    console.print("[bold]Testing all cluster nodes...[/bold]\n")

    cluster = ClusterManager(config.cluster)

    for node_name in cluster._nodes.keys():
        node = cluster._nodes[node_name]
        console.print(f"Testing [cyan]{node.name}[/cyan] ({node.host}:{node.port})... ", end="")

        health = await cluster.check_node_health(node_name)

        if health.status == NodeStatus.AVAILABLE:
            console.print(f"[green]✓[/green] OK ({health.latency_ms:.1f}ms)")
        else:
            console.print(f"[red]✗[/red] Failed")

    await cluster.close()


def cluster_test_command(config_path: Optional[str] = None):
    """Test connectivity to all cluster nodes."""
    asyncio.run(_async_test(config_path))
