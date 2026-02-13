"""Interactive chat REPL command."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.prompt import Confirm, Prompt

from harombe.agent.loop import Agent
from harombe.config.loader import load_config
from harombe.privacy.router import PrivacyRouter, create_privacy_router
from harombe.tools.registry import get_enabled_tools_v2

if TYPE_CHECKING:
    from harombe.config.schema import HarombeConfig
    from harombe.llm.client import LLMClient
    from harombe.mcp.manager import MCPManager
    from harombe.tools.base import Tool

console = Console()
logger = logging.getLogger(__name__)


def chat_command(config_path: str | None = None) -> None:
    """Start interactive chat session.

    Args:
        config_path: Optional path to config file
    """
    # Load config
    path = Path(config_path) if config_path else None
    try:
        config = load_config(path)
    except Exception as e:
        console.print(f"[red]Failed to load config: {e}[/red]")
        console.print("Run [bold]harombe init[/bold] to create a config file.")
        return

    # Show welcome
    console.print(
        Panel.fit(
            f"[bold blue]harombe chat[/bold blue]\n"
            f"Model: {config.model.name}\n"
            f"Type /help for commands, /exit to quit",
            border_style="blue",
        )
    )

    # Run async chat loop
    asyncio.run(_async_chat(config))


async def _async_chat(config: HarombeConfig) -> None:
    """Async chat loop.

    Args:
        config: Harombe configuration
    """
    # Initialize LLM client (privacy router or plain Ollama depending on config)
    llm = create_privacy_router(config)

    # Load plugins if enabled
    if config.plugins.enabled:
        _load_plugins(config)

    # Get enabled tools (includes plugin tools, respects plugin overrides)
    tools = get_enabled_tools_v2(
        shell=config.tools.shell,
        filesystem=config.tools.filesystem,
        web_search=config.tools.web_search,
        plugins_config=config.plugins,
    )

    # Wire up delegation if enabled
    if config.delegation.enabled and config.agents:
        delegation_tool = _create_delegation(config, llm)  # type: ignore[arg-type]
        if delegation_tool:
            tools.append(delegation_tool)

    # Connect to MCP servers if configured
    mcp_manager = None
    if config.mcp.external_servers:
        mcp_manager = await _connect_mcp(config)

    # Create confirmation callback for dangerous tools
    def confirm_dangerous(tool_name: str, description: str, args: dict[str, Any]) -> bool:
        console.print(f"\n[yellow]⚠️  Dangerous operation:[/yellow] {tool_name}")
        console.print(f"[dim]{description}[/dim]")
        console.print(f"Arguments: {args}")
        return Confirm.ask("Execute this operation?", default=False)

    confirm_callback = confirm_dangerous if config.tools.confirm_dangerous else None

    # Create agent
    agent = Agent(
        llm=llm,  # type: ignore[arg-type]
        tools=tools,
        max_steps=config.agent.max_steps,
        system_prompt=config.agent.system_prompt,
        confirm_dangerous=config.tools.confirm_dangerous,
        confirm_callback=confirm_callback,
        mcp_manager=mcp_manager,
    )

    # Chat loop
    while True:
        try:
            # Get user input
            user_input = Prompt.ask("\n[bold cyan]You[/bold cyan]")

            if not user_input.strip():
                continue

            # Handle slash commands
            if user_input.startswith("/"):
                if _handle_slash_command(user_input, config, llm):  # type: ignore[arg-type]
                    break  # Exit if command returns True
                continue

            # Run agent
            with console.status("[bold green]Thinking...[/bold green]", spinner="dots"):
                response = await agent.run(user_input)

            # Display response
            console.print("\n[bold green]harombe[/bold green]")
            console.print(Markdown(response))

        except KeyboardInterrupt:
            console.print("\n[yellow]Interrupted[/yellow]")
            if Confirm.ask("Exit chat?", default=False):
                break
        except EOFError:
            break
        except Exception as e:
            console.print(f"\n[red]Error: {e}[/red]")

    console.print("\n[cyan]Goodbye![/cyan]")


def _load_plugins(config: HarombeConfig) -> None:
    """Load plugins based on configuration."""
    from harombe.plugins.loader import PluginLoader
    from harombe.plugins.sandbox import apply_plugin_permissions

    loader = PluginLoader(
        plugin_dir=config.plugins.plugin_dir,
        blocked=config.plugins.blocked,
    )
    plugins = loader.discover_all()

    for plugin in plugins:
        if plugin.enabled and not plugin.error:
            apply_plugin_permissions(plugin)
            # Tag tools with their plugin source
            for tool_name in plugin.tool_names:
                from harombe.tools.registry import _TOOL_SOURCES, _TOOLS

                _TOOL_SOURCES[tool_name] = plugin.manifest.name
                tool_obj = _TOOLS.get(tool_name)
                if tool_obj:
                    tool_obj.schema.source = plugin.manifest.name

    loaded = [p for p in plugins if p.enabled and not p.error]
    if loaded:
        total_tools = sum(len(p.tool_names) for p in loaded)
        logger.info("Loaded %d plugins with %d tools", len(loaded), total_tools)


def _create_delegation(config: HarombeConfig, llm: LLMClient) -> Tool | None:
    """Create delegation tool from config."""
    from harombe.agent.builder import build_agent_registry, create_root_delegation_context
    from harombe.tools.delegation import create_delegation_tool

    registry = build_agent_registry(config.agents)
    context = create_root_delegation_context(config)
    return create_delegation_tool(
        registry=registry,
        llm=llm,
        delegation_context=context,
        confirm_dangerous=config.tools.confirm_dangerous,
    )


async def _connect_mcp(config: HarombeConfig) -> MCPManager:
    """Connect to configured external MCP servers."""
    from harombe.mcp.manager import MCPManager

    manager = MCPManager()
    for server_config in config.mcp.external_servers:
        manager.add_server(server_config)

    try:
        await manager.connect_all()
    except Exception as e:
        logger.warning("MCP connection error: %s", e)

    return manager


def _handle_slash_command(
    command: str, config: HarombeConfig, llm: LLMClient | None = None
) -> bool:
    """Handle slash commands.

    Args:
        command: Command string starting with /
        config: Current configuration

    Returns:
        True if should exit chat loop
    """
    cmd = command.lower().strip()

    if cmd in ("/exit", "/quit", "/q"):
        return True

    elif cmd == "/help":
        console.print("\n[bold]Available commands:[/bold]")
        console.print("  /help      - Show this help")
        console.print("  /exit      - Exit chat")
        console.print("  /clear     - Clear screen")
        console.print("  /model     - Show current model")
        console.print("  /tools     - List enabled tools")
        console.print("  /config    - Show configuration")
        console.print("  /privacy   - Show privacy routing stats")

    elif cmd == "/clear":
        console.clear()

    elif cmd == "/model":
        console.print(f"\n[cyan]Current model:[/cyan] {config.model.name}")
        console.print(f"[cyan]Temperature:[/cyan] {config.model.temperature}")
        console.print(f"[cyan]Max steps:[/cyan] {config.agent.max_steps}")

    elif cmd == "/tools":
        console.print("\n[bold]Enabled tools:[/bold]")
        tools = get_enabled_tools_v2(
            shell=config.tools.shell,
            filesystem=config.tools.filesystem,
            web_search=config.tools.web_search,
            plugins_config=config.plugins,
        )
        for t in tools:
            source_tag = f" [dim]({t.schema.source})[/dim]" if t.schema.source != "builtin" else ""
            danger_tag = " [yellow]⚠[/yellow]" if t.schema.dangerous else ""
            console.print(
                f"  • {t.schema.name}{danger_tag} - {t.schema.description[:60]}{source_tag}"
            )

    elif cmd == "/config":
        console.print("\n[bold]Configuration:[/bold]")
        console.print(f"  Model: {config.model.name}")
        console.print(f"  Ollama: {config.ollama.host}")
        console.print(f"  Max steps: {config.agent.max_steps}")
        console.print(f"  Temperature: {config.model.temperature}")
        console.print(f"  Confirm dangerous: {config.tools.confirm_dangerous}")
        console.print(f"  Privacy mode: {config.privacy.mode}")

    elif cmd == "/privacy":
        console.print("\n[bold]Privacy routing:[/bold]")
        console.print(f"  Mode: {config.privacy.mode}")
        if isinstance(llm, PrivacyRouter):
            stats = llm.get_stats()
            console.print(f"  Total requests: {stats['total_requests']}")
            console.print(f"  Routed to local: {stats['local_count']}")
            console.print(f"  Routed to cloud: {stats['cloud_count']}")
            console.print(f"  Cloud (sanitized): {stats['cloud_sanitized_count']}")
        else:
            console.print("  Router: local-only (no cloud backend)")

    else:
        console.print(f"[red]Unknown command: {command}[/red]")
        console.print("Type /help for available commands")

    return False
