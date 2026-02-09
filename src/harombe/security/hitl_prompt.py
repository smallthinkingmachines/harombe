"""
HITL approval prompts for CLI and API interfaces.

Provides user-facing approval prompts with timeout handling.
"""

import asyncio

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm
from rich.table import Table

from .hitl import ApprovalDecision, ApprovalStatus, Operation, RiskLevel

console = Console()


class CLIApprovalPrompt:
    """CLI-based approval prompts."""

    def __init__(self, console: Console | None = None):
        """
        Initialize CLI approval prompt.

        Args:
            console: Rich console for output
        """
        self.console = console or Console()

    async def prompt(
        self,
        operation: Operation,
        risk_level: RiskLevel,
        timeout: int,
        user: str = "user",
    ) -> ApprovalDecision:
        """
        Prompt user for approval via CLI.

        Args:
            operation: The operation requiring approval
            risk_level: Risk level of the operation
            timeout: Timeout in seconds
            user: User being prompted

        Returns:
            Approval decision
        """
        # Display approval request
        self._display_approval_request(operation, risk_level, timeout)

        # Get user decision with timeout
        try:
            approved = await asyncio.wait_for(self._get_user_input(), timeout=timeout)

            if approved:
                return ApprovalDecision(
                    decision=ApprovalStatus.APPROVED,
                    user=user,
                    reason="Approved via CLI",
                )
            else:
                return ApprovalDecision(
                    decision=ApprovalStatus.DENIED,
                    user=user,
                    reason="Denied via CLI",
                )

        except TimeoutError:
            self.console.print(
                "\n[red]✗[/red] Request timed out. Operation denied.",
                style="bold",
            )
            return ApprovalDecision(
                decision=ApprovalStatus.TIMEOUT,
                user=user,
                reason=f"No response within {timeout} seconds",
                timeout_seconds=timeout,
            )

    def _display_approval_request(
        self, operation: Operation, risk_level: RiskLevel, timeout: int
    ) -> None:
        """Display approval request to user."""
        # Risk level styling
        risk_colors = {
            RiskLevel.LOW: "green",
            RiskLevel.MEDIUM: "yellow",
            RiskLevel.HIGH: "red",
            RiskLevel.CRITICAL: "bold red",
        }
        risk_color = risk_colors.get(risk_level, "yellow")

        # Risk descriptions
        risk_descriptions = {
            RiskLevel.LOW: "Read-only operation, safe to execute",
            RiskLevel.MEDIUM: "Modification with possible undo",
            RiskLevel.HIGH: "Destructive operation, hard to undo",
            RiskLevel.CRITICAL: "Irreversible operation, potential data loss",
        }
        risk_desc = risk_descriptions.get(risk_level, "Unknown risk level")

        # Create header
        header = f"[{risk_color}]{risk_level.value.upper()} RISK[/{risk_color}] - APPROVAL REQUIRED"

        # Create parameters table
        params_table = Table(show_header=False, box=None, padding=(0, 2))
        params_table.add_column("Key", style="cyan")
        params_table.add_column("Value", style="white")

        for key, value in operation.params.items():
            # Truncate long values
            value_str = str(value)
            if len(value_str) > 100:
                value_str = value_str[:97] + "..."
            params_table.add_row(key, value_str)

        # Create content
        content = f"""
[bold]Tool:[/bold] {operation.tool_name}

[bold]Parameters:[/bold]
{params_table}

[bold]Risk:[/bold] [{risk_color}]{risk_level.value.upper()}[/{risk_color}] - {risk_desc}

[bold yellow]Auto-deny in {timeout} seconds...[/bold yellow]
        """

        # Display panel
        panel = Panel(
            content.strip(),
            title=header,
            border_style=risk_color,
            padding=(1, 2),
        )

        self.console.print()
        self.console.print(panel)
        self.console.print()

    async def _get_user_input(self) -> bool:
        """Get user approval decision."""
        # Run blocking input in executor
        loop = asyncio.get_event_loop()
        approved = await loop.run_in_executor(
            None,
            lambda: Confirm.ask(
                "[bold]Approve this operation?[/bold]",
                default=False,
            ),
        )
        return approved


class APIApprovalPrompt:
    """API-based approval prompts (for web UI, etc.)."""

    def __init__(self):
        """Initialize API approval prompt."""
        self.pending_prompts = {}

    def create_prompt(
        self,
        approval_id: str,
        operation: Operation,
        risk_level: RiskLevel,
        timeout: int,
    ) -> dict:
        """
        Create API approval prompt data.

        Args:
            approval_id: Unique approval identifier
            operation: The operation requiring approval
            risk_level: Risk level of the operation
            timeout: Timeout in seconds

        Returns:
            Dict with prompt data for API clients
        """
        return {
            "approval_id": approval_id,
            "status": "pending",
            "operation": {
                "tool_name": operation.tool_name,
                "params": operation.params,
                "correlation_id": operation.correlation_id,
                "session_id": operation.session_id,
            },
            "risk_level": risk_level.value,
            "timeout": timeout,
            "created_at": operation.metadata.get("created_at"),
            "message": self._get_approval_message(operation, risk_level),
        }

    def _get_approval_message(self, operation: Operation, risk_level: RiskLevel) -> str:
        """Generate human-readable approval message."""
        messages = {
            RiskLevel.LOW: f"Allow {operation.tool_name} operation?",
            RiskLevel.MEDIUM: f"The agent wants to perform a medium-risk operation: {operation.tool_name}. This modification may be reversible. Approve?",
            RiskLevel.HIGH: f"⚠️ HIGH RISK: The agent wants to {operation.tool_name}. This operation is difficult to undo. Approve?",
            RiskLevel.CRITICAL: f"🚨 CRITICAL: The agent wants to {operation.tool_name}. This operation is IRREVERSIBLE and may result in DATA LOSS. Are you absolutely sure you want to approve?",
        }
        return messages.get(risk_level, f"Approve {operation.tool_name}?")


def create_prompt(
    mode: str = "cli", console: Console | None = None
) -> CLIApprovalPrompt | APIApprovalPrompt:
    """
    Create approval prompt for specified mode.

    Args:
        mode: "cli" or "api"
        console: Optional console for CLI mode

    Returns:
        Approval prompt instance
    """
    if mode == "cli":
        return CLIApprovalPrompt(console=console)
    elif mode == "api":
        return APIApprovalPrompt()
    else:
        raise ValueError(f"Unknown prompt mode: {mode}")
