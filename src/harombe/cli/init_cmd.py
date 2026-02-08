"""Initialize command - hardware detection and config generation."""

import asyncio
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt

from harombe.config.loader import DEFAULT_CONFIG_PATH, load_config, save_config
from harombe.config.schema import HarombeConfig
from harombe.hardware.detect import (
    check_ollama_running,
    get_ollama_models,
    recommend_model,
)

console = Console()


def init_command(force: bool = False):
    """Initialize Harombe configuration.

    Args:
        force: Overwrite existing config if present
    """
    console.print(Panel.fit(
        "[bold blue]Harombe Initialization[/bold blue]\n"
        "Detecting hardware and configuring your AI assistant...",
        border_style="blue",
    ))

    # Check if config already exists
    if DEFAULT_CONFIG_PATH.exists() and not force:
        console.print(f"\n[yellow]Config already exists at {DEFAULT_CONFIG_PATH}[/yellow]")
        console.print("Use [bold]--force[/bold] to overwrite, or [bold]harombe chat[/bold] to start using it.")
        raise typer.Exit(0)

    # Run async detection
    asyncio.run(_async_init())


async def _async_init():
    """Async initialization logic."""
    # 1. Detect hardware
    console.print("\n[cyan]Step 1:[/cyan] Detecting hardware...")
    recommended_model, reason = recommend_model()
    console.print(f"  {reason}")
    console.print(f"  [green]Recommended model:[/green] {recommended_model}")

    # 2. Check Ollama
    console.print("\n[cyan]Step 2:[/cyan] Checking Ollama...")
    ollama_running = await check_ollama_running()

    if not ollama_running:
        console.print("  [yellow]Ollama is not running or not installed[/yellow]")
        console.print("  Install from: https://ollama.ai")
        console.print("  After installing, run: [bold]ollama serve[/bold]")

        # Ask if user wants to continue anyway
        if not Confirm.ask("Continue with configuration anyway?", default=False):
            raise typer.Exit(1)
    else:
        console.print("  [green]Ollama is running[/green]")

        # Check available models
        models = await get_ollama_models()
        if models:
            console.print(f"  Available models: {', '.join(models[:5])}")

            # Check if recommended model is available
            if recommended_model not in models:
                console.print(f"\n  [yellow]Recommended model '{recommended_model}' not found[/yellow]")
                if Confirm.ask(f"Pull {recommended_model} now?", default=True):
                    console.print(f"\n  Run: [bold]ollama pull {recommended_model}[/bold]")
                    console.print("  (This may take several minutes)")
        else:
            console.print("  [yellow]No models found. You'll need to pull one:[/yellow]")
            console.print(f"  [bold]ollama pull {recommended_model}[/bold]")

    # 3. Create config
    console.print("\n[cyan]Step 3:[/cyan] Creating configuration...")

    config = HarombeConfig()
    config.model.name = recommended_model

    # Ask for customizations
    if Confirm.ask("\nCustomize settings?", default=False):
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
    console.print(f"\n[green]Configuration saved to {DEFAULT_CONFIG_PATH}[/green]")

    # 4. Next steps
    console.print("\n[bold cyan]Setup Complete![/bold cyan]")
    console.print("\nNext steps:")
    console.print("  1. Ensure Ollama is running: [bold]ollama serve[/bold]")
    console.print(f"  2. Pull the model: [bold]ollama pull {config.model.name}[/bold]")
    console.print("  3. Start chatting: [bold]harombe chat[/bold]")
    console.print("  4. Or start the API server: [bold]harombe start[/bold]")
