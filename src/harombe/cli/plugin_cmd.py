"""CLI commands for plugin management."""

from __future__ import annotations

from rich.console import Console
from rich.table import Table

console = Console()


def list_plugins(plugin_dir: str = "~/.harombe/plugins") -> None:
    """List all discovered plugins."""
    from harombe.plugins.loader import PluginLoader

    loader = PluginLoader(plugin_dir=plugin_dir)
    plugins = loader.discover_all()

    if not plugins:
        console.print("[dim]No plugins found.[/dim]")
        console.print(f"Drop .py files in {plugin_dir} or install via pip.")
        return

    table = Table(title="Installed Plugins")
    table.add_column("Name", style="cyan")
    table.add_column("Version")
    table.add_column("Source")
    table.add_column("Tools", style="green")
    table.add_column("Status")

    for plugin in plugins:
        status = "[green]enabled[/green]" if plugin.enabled else "[red]disabled[/red]"
        if plugin.error:
            status = f"[red]error: {plugin.error[:40]}[/red]"
        table.add_row(
            plugin.manifest.name,
            plugin.manifest.version,
            plugin.source,
            ", ".join(plugin.tool_names) if plugin.tool_names else "-",
            status,
        )

    console.print(table)


def info_plugin(name: str, plugin_dir: str = "~/.harombe/plugins") -> None:
    """Show detailed info about a plugin."""
    from harombe.plugins.loader import PluginLoader

    loader = PluginLoader(plugin_dir=plugin_dir)
    loader.discover_all()

    plugin = loader.get_plugin(name)
    if not plugin:
        console.print(f"[red]Plugin '{name}' not found.[/red]")
        return

    m = plugin.manifest
    console.print(f"\n[bold cyan]{m.name}[/bold cyan] v{m.version}")
    if m.description:
        console.print(f"  {m.description}")
    if m.author:
        console.print(f"  Author: {m.author}")
    console.print(f"  Source: {plugin.source}")
    console.print(f"  Enabled: {plugin.enabled}")
    if plugin.tool_names:
        console.print(f"  Tools: {', '.join(plugin.tool_names)}")

    p = m.permissions
    console.print("  Permissions:")
    console.print(f"    Network: {p.network_domains or 'none'}")
    console.print(f"    Filesystem: {p.filesystem}")
    console.print(f"    Shell: {p.shell}")
    console.print(f"    Dangerous: {p.dangerous}")

    if plugin.error:
        console.print(f"  [red]Error: {plugin.error}[/red]")


def enable_plugin(name: str, plugin_dir: str = "~/.harombe/plugins") -> None:
    """Enable a plugin."""
    from harombe.plugins.loader import PluginLoader

    loader = PluginLoader(plugin_dir=plugin_dir)
    loader.discover_all()

    if loader.enable_plugin(name):
        console.print(f"[green]Plugin '{name}' enabled.[/green]")
    else:
        console.print(f"[red]Plugin '{name}' not found.[/red]")


def disable_plugin(name: str, plugin_dir: str = "~/.harombe/plugins") -> None:
    """Disable a plugin."""
    from harombe.plugins.loader import PluginLoader

    loader = PluginLoader(plugin_dir=plugin_dir)
    loader.discover_all()

    if loader.disable_plugin(name):
        console.print(f"[yellow]Plugin '{name}' disabled.[/yellow]")
    else:
        console.print(f"[red]Plugin '{name}' not found.[/red]")
