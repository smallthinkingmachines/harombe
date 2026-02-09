"""Initialize command - hardware detection and config generation."""

import asyncio

import typer
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt

from harombe.config.loader import DEFAULT_CONFIG_PATH, save_config
from harombe.config.schema import HarombeConfig
from harombe.hardware.detect import (
    check_ollama_running,
    get_ollama_models,
    recommend_model,
)

console = Console()


def init_command(force: bool = False, non_interactive: bool = False, model: str | None = None):
    """Initialize harombe configuration.

    Args:
        force: Overwrite existing config if present
        non_interactive: Use defaults without prompting
        model: Optional model name to use
    """
    console.print(
        Panel.fit(
            "[bold blue]harombe initialization[/bold blue]\n"
            "Detecting hardware and configuring your AI assistant...",
            border_style="blue",
        )
    )

    # Check if config already exists
    if DEFAULT_CONFIG_PATH.exists() and not force:
        console.print(f"\n[yellow]Config already exists at {DEFAULT_CONFIG_PATH}[/yellow]")
        console.print(
            "Use [bold]--force[/bold] to overwrite, or [bold]harombe chat[/bold] to start using it."
        )
        raise typer.Exit(0)

    # Run async detection
    asyncio.run(_async_init(non_interactive=non_interactive, model_override=model))


async def _async_init(non_interactive: bool = False, model_override: str | None = None):
    """Async initialization logic.

    Args:
        non_interactive: Use defaults without prompting
        model_override: Optional model name to override detection
    """
    # 1. Detect hardware
    console.print("\n[cyan]Step 1:[/cyan] Detecting hardware...")
    recommended_model, reason = recommend_model()
    console.print(f"  {reason}")
    console.print(f"  [green]Recommended model:[/green] {recommended_model}")

    # Override if specified
    if model_override:
        recommended_model = model_override
        console.print(f"  [cyan]Using specified model:[/cyan] {recommended_model}")

    # 2. Check Ollama
    console.print("\n[cyan]Step 2:[/cyan] Checking Ollama...")
    ollama_running = await check_ollama_running()

    if not ollama_running:
        console.print("  [red]✗[/red] Ollama is not running or not installed")
        console.print("  [yellow]→[/yellow] Install from: https://ollama.ai")
        console.print("  [yellow]→[/yellow] Start with: [bold]ollama serve[/bold]")

        if non_interactive:
            console.print("\n[yellow]Continuing in non-interactive mode...[/yellow]")
        else:
            # Ask if user wants to continue anyway
            if not Confirm.ask("Continue with configuration anyway?", default=False):
                raise typer.Exit(1)
    else:
        console.print("  [green]✓[/green] Ollama is running")

        # Check available models
        models = await get_ollama_models()
        if models:
            console.print(f"  Available models: {', '.join(models[:5])}")

            # Check if recommended model is available
            if recommended_model not in models:
                console.print(
                    f"\n  [yellow]Recommended model '{recommended_model}' not found[/yellow]"
                )
                console.print(
                    f"  [yellow]→[/yellow] Pull with: [bold]ollama pull {recommended_model}[/bold]"
                )

                if not non_interactive and Confirm.ask(
                    f"Pull {recommended_model} now?", default=True
                ):
                    console.print("  (This may take several minutes)")
        else:
            console.print("  [yellow]No models found. You'll need to pull one:[/yellow]")
            console.print(f"  [bold]ollama pull {recommended_model}[/bold]")

    # 3. Create config
    console.print("\n[cyan]Step 3:[/cyan] Creating configuration...")

    config = HarombeConfig()
    config.model.name = recommended_model

    # Ask for customizations (skip in non-interactive mode)
    if not non_interactive and Confirm.ask("\nCustomize settings?", default=False):
        # Model name
        custom_model = Prompt.ask(
            "Model name",
            default=recommended_model,
        )
        config.model.name = custom_model

        # Temperature
        temp_str = Prompt.ask(
            "Temperature (0.0-2.0)",
            default=str(config.model.temperature),
        )
        try:
            config.model.temperature = float(temp_str)
        except ValueError:
            console.print("[yellow]Invalid temperature, using default[/yellow]")

        # Max steps
        steps_str = Prompt.ask(
            "Max agent steps",
            default=str(config.agent.max_steps),
        )
        try:
            config.agent.max_steps = int(steps_str)
        except ValueError:
            console.print("[yellow]Invalid max steps, using default[/yellow]")

    # Save config
    save_config(config)
    console.print(f"\n[green]✓ Configuration saved to {DEFAULT_CONFIG_PATH}[/green]")

    # 4. Next steps
    console.print("\n[bold cyan]Setup Complete![/bold cyan]")
    console.print("\nNext steps:")
    console.print("  1. Ensure Ollama is running: [bold]ollama serve[/bold]")
    console.print(f"  2. Pull the model: [bold]ollama pull {config.model.name}[/bold]")
    console.print("  3. Start chatting: [bold]harombe chat[/bold]")
    console.print("  4. Or start the API server: [bold]harombe start[/bold]")
