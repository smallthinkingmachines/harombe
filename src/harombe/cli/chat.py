"""Interactive chat REPL command."""

import asyncio
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.prompt import Confirm, Prompt

# Import tools to register them
from harombe.agent.loop import Agent
from harombe.config.loader import load_config
from harombe.privacy.router import PrivacyRouter, create_privacy_router
from harombe.tools.registry import get_enabled_tools

console = Console()


def chat_command(config_path: str | None = None):
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


async def _async_chat(config):
    """Async chat loop.

    Args:
        config: Harombe configuration
    """
    # Initialize LLM client (privacy router or plain Ollama depending on config)
    llm = create_privacy_router(config)

    # Get enabled tools
    tools = get_enabled_tools(
        shell=config.tools.shell,
        filesystem=config.tools.filesystem,
        web_search=config.tools.web_search,
    )

    # Create confirmation callback for dangerous tools
    def confirm_dangerous(tool_name: str, description: str, args: dict[str, Any]) -> bool:
        console.print(f"\n[yellow]⚠️  Dangerous operation:[/yellow] {tool_name}")
        console.print(f"[dim]{description}[/dim]")
        console.print(f"Arguments: {args}")
        return Confirm.ask("Execute this operation?", default=False)

    confirm_callback = confirm_dangerous if config.tools.confirm_dangerous else None

    # Create agent
    agent = Agent(
        llm=llm,
        tools=tools,
        max_steps=config.agent.max_steps,
        system_prompt=config.agent.system_prompt,
        confirm_dangerous=config.tools.confirm_dangerous,
        confirm_callback=confirm_callback,
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
                if _handle_slash_command(user_input, config, llm):
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
        except Exception as e:
            console.print(f"\n[red]Error: {e}[/red]")

    console.print("\n[cyan]Goodbye![/cyan]")


def _handle_slash_command(command: str, config, llm=None) -> bool:
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
        if config.tools.shell:
            console.print("  • shell - Execute shell commands")
        if config.tools.filesystem:
            console.print("  • read_file - Read file contents")
            console.print("  • write_file - Write to files")
        if config.tools.web_search:
            console.print("  • web_search - Search the web")

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
