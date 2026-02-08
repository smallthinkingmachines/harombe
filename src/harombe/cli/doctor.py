"""Doctor command - system health check."""

import asyncio
import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from harombe.config.loader import DEFAULT_CONFIG_PATH, load_config
from harombe.hardware.detect import (
    check_ollama_running,
    detect_gpu,
    get_ollama_models,
)

console = Console()


def doctor_command():
    """Run system health checks."""
    console.print(Panel.fit(
        "[bold blue]harombe system health check[/bold blue]\n"
        "Checking your installation...",
        border_style="blue",
    ))

    asyncio.run(_async_doctor())


async def _async_doctor():
    """Async doctor logic."""
    issues = []
    warnings = []

    # Create results table
    table = Table(title="System Health Check", show_header=True, header_style="bold cyan")
    table.add_column("Check", style="white", width=30)
    table.add_column("Status", width=10)
    table.add_column("Details", style="dim")

    # 1. Check Python version
    py_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    if sys.version_info >= (3, 11):
        table.add_row("Python Version", "[green]✓[/green]", f"{py_version}")
    else:
        table.add_row("Python Version", "[red]✗[/red]", f"{py_version} (need 3.11+)")
        issues.append("Python version too old. Upgrade to Python 3.11 or higher.")

    # 2. Check config file
    if DEFAULT_CONFIG_PATH.exists():
        try:
            config = load_config()
            table.add_row("Configuration", "[green]✓[/green]", f"{DEFAULT_CONFIG_PATH}")
        except Exception as e:
            table.add_row("Configuration", "[red]✗[/red]", f"Invalid: {e}")
            issues.append(f"Config file is invalid: {e}")
    else:
        table.add_row("Configuration", "[yellow]⚠[/yellow]", "Not found (using defaults)")
        warnings.append(f"No config file at {DEFAULT_CONFIG_PATH}. Run 'harombe init' to create one.")

    # 3. Check Ollama
    ollama_running = await check_ollama_running()
    if ollama_running:
        table.add_row("Ollama Server", "[green]✓[/green]", "Running at localhost:11434")

        # Check models
        models = await get_ollama_models()
        if models:
            model_list = ", ".join(models[:3])
            if len(models) > 3:
                model_list += f" (+{len(models) - 3} more)"
            table.add_row("Ollama Models", "[green]✓[/green]", model_list)
        else:
            table.add_row("Ollama Models", "[yellow]⚠[/yellow]", "No models found")
            warnings.append("No Ollama models installed. Run: ollama pull qwen2.5:7b")
    else:
        table.add_row("Ollama Server", "[red]✗[/red]", "Not running")
        issues.append("Ollama is not running. Start with: ollama serve")

    # 4. Check hardware
    gpu_type, vram_gb = detect_gpu()
    if gpu_type == "cpu":
        table.add_row("GPU Detection", "[yellow]⚠[/yellow]", "No GPU detected (CPU only)")
        warnings.append("No GPU detected. Performance will be slower on CPU.")
    else:
        gpu_name = gpu_type.replace("_", " ").title()
        table.add_row("GPU Detection", "[green]✓[/green]", f"{gpu_name} ({vram_gb:.1f}GB)")

    # 5. Check config model availability
    if DEFAULT_CONFIG_PATH.exists() and ollama_running:
        try:
            config = load_config()
            models = await get_ollama_models()
            if config.model.name in models:
                table.add_row("Configured Model", "[green]✓[/green]", f"{config.model.name} available")
            else:
                table.add_row("Configured Model", "[yellow]⚠[/yellow]", f"{config.model.name} not found")
                warnings.append(f"Model '{config.model.name}' not installed. Run: ollama pull {config.model.name}")
        except Exception:
            pass

    # Print table
    console.print("\n")
    console.print(table)

    # Print summary
    console.print("\n")
    if not issues and not warnings:
        console.print(Panel.fit(
            "[bold green]✓ All checks passed![/bold green]\n"
            "Your harombe installation is healthy.",
            border_style="green",
        ))
    else:
        if issues:
            console.print("[bold red]Issues Found:[/bold red]")
            for i, issue in enumerate(issues, 1):
                console.print(f"  {i}. {issue}")
            console.print()

        if warnings:
            console.print("[bold yellow]Warnings:[/bold yellow]")
            for i, warning in enumerate(warnings, 1):
                console.print(f"  {i}. {warning}")
            console.print()

        if issues:
            console.print("[yellow]Fix the issues above before using harombe.[/yellow]")
        else:
            console.print("[green]No critical issues. Warnings are optional improvements.[/green]")

    console.print("\nFor more help, visit: https://github.com/smallthinkingmachines/harombe/discussions")
