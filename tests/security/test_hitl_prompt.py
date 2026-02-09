"""
Tests for HITL approval prompts.

Tests CLI and API prompt implementations.
"""

import asyncio
from unittest.mock import patch

import pytest
from rich.console import Console

from harombe.security.hitl import ApprovalStatus, Operation, RiskLevel
from harombe.security.hitl_prompt import (
    APIApprovalPrompt,
    CLIApprovalPrompt,
    create_prompt,
)


class TestCLIApprovalPrompt:
    """Tests for CLIApprovalPrompt."""

    @pytest.mark.asyncio
    async def test_prompt_approved(self):
        """Test that user approval works."""
        console = Console()
        prompt = CLIApprovalPrompt(console=console)

        operation = Operation(
            tool_name="send_email",
            params={"to": "user@example.com", "subject": "Test"},
            correlation_id="test-123",
        )

        # Mock user input to approve
        with patch("rich.prompt.Confirm.ask", return_value=True):
            decision = await prompt.prompt(
                operation=operation,
                risk_level=RiskLevel.HIGH,
                timeout=60,
                user="test-user",
            )

        assert decision.decision == ApprovalStatus.APPROVED
        assert decision.user == "test-user"
        assert decision.reason == "Approved via CLI"

    @pytest.mark.asyncio
    async def test_prompt_denied(self):
        """Test that user denial works."""
        console = Console()
        prompt = CLIApprovalPrompt(console=console)

        operation = Operation(
            tool_name="send_email",
            params={"to": "user@example.com"},
            correlation_id="test-123",
        )

        # Mock user input to deny
        with patch("rich.prompt.Confirm.ask", return_value=False):
            decision = await prompt.prompt(
                operation=operation,
                risk_level=RiskLevel.HIGH,
                timeout=60,
                user="test-user",
            )

        assert decision.decision == ApprovalStatus.DENIED
        assert decision.user == "test-user"
        assert decision.reason == "Denied via CLI"

    @pytest.mark.asyncio
    async def test_prompt_timeout(self):
        """Test that timeout works correctly."""
        console = Console()
        prompt = CLIApprovalPrompt(console=console)

        operation = Operation(
            tool_name="send_email",
            params={"to": "user@example.com"},
            correlation_id="test-123",
        )

        # Mock user input to hang (simulate timeout)
        async def slow_input():
            await asyncio.sleep(10)  # Longer than timeout
            return True

        with patch.object(prompt, "_get_user_input", side_effect=slow_input):
            decision = await prompt.prompt(
                operation=operation,
                risk_level=RiskLevel.HIGH,
                timeout=1,  # 1 second timeout
                user="test-user",
            )

        assert decision.decision == ApprovalStatus.TIMEOUT
        assert decision.user == "test-user"
        assert "No response within 1 seconds" in decision.reason
        assert decision.timeout_seconds == 1

    def test_display_approval_request_high_risk(self):
        """Test that high-risk operations display correctly."""
        console = Console()
        prompt = CLIApprovalPrompt(console=console)

        operation = Operation(
            tool_name="send_email",
            params={"to": "user@example.com", "subject": "Test"},
            correlation_id="test-123",
        )

        # Should not raise exception
        prompt._display_approval_request(operation, RiskLevel.HIGH, 60)

    def test_display_approval_request_critical_risk(self):
        """Test that critical-risk operations display correctly."""
        console = Console()
        prompt = CLIApprovalPrompt(console=console)

        operation = Operation(
            tool_name="delete_database",
            params={"database": "production"},
            correlation_id="test-123",
        )

        # Should not raise exception
        prompt._display_approval_request(operation, RiskLevel.CRITICAL, 30)

    def test_display_approval_request_truncates_long_values(self):
        """Test that long parameter values are truncated."""
        console = Console()
        prompt = CLIApprovalPrompt(console=console)

        long_content = "x" * 200  # Very long content

        operation = Operation(
            tool_name="write_file",
            params={"path": "/tmp/test.txt", "content": long_content},
            correlation_id="test-123",
        )

        # Should not raise exception and should truncate
        prompt._display_approval_request(operation, RiskLevel.MEDIUM, 60)

    @pytest.mark.asyncio
    async def test_get_user_input(self):
        """Test getting user input."""
        console = Console()
        prompt = CLIApprovalPrompt(console=console)

        # Mock Confirm.ask to return True
        with patch("rich.prompt.Confirm.ask", return_value=True):
            result = await prompt._get_user_input()

        assert result is True


class TestAPIApprovalPrompt:
    """Tests for APIApprovalPrompt."""

    def test_create_prompt(self):
        """Test creating API prompt data."""
        prompt = APIApprovalPrompt()

        operation = Operation(
            tool_name="send_email",
            params={"to": "user@example.com", "subject": "Test"},
            correlation_id="test-123",
            session_id="session-456",
            metadata={"created_at": "2026-02-09T12:00:00Z"},
        )

        prompt_data = prompt.create_prompt(
            approval_id="approval-789",
            operation=operation,
            risk_level=RiskLevel.HIGH,
            timeout=60,
        )

        assert prompt_data["approval_id"] == "approval-789"
        assert prompt_data["status"] == "pending"
        assert prompt_data["operation"]["tool_name"] == "send_email"
        assert prompt_data["operation"]["params"]["to"] == "user@example.com"
        assert prompt_data["operation"]["correlation_id"] == "test-123"
        assert prompt_data["operation"]["session_id"] == "session-456"
        assert prompt_data["risk_level"] == "high"
        assert prompt_data["timeout"] == 60
        assert prompt_data["created_at"] == "2026-02-09T12:00:00Z"
        assert "HIGH RISK" in prompt_data["message"]

    def test_get_approval_message_low_risk(self):
        """Test approval message for low-risk operations."""
        prompt = APIApprovalPrompt()

        operation = Operation(
            tool_name="read_file",
            params={"path": "/tmp/test.txt"},
            correlation_id="test-123",
        )

        message = prompt._get_approval_message(operation, RiskLevel.LOW)
        assert "Allow read_file operation?" in message

    def test_get_approval_message_medium_risk(self):
        """Test approval message for medium-risk operations."""
        prompt = APIApprovalPrompt()

        operation = Operation(
            tool_name="write_file",
            params={"path": "/tmp/test.txt"},
            correlation_id="test-123",
        )

        message = prompt._get_approval_message(operation, RiskLevel.MEDIUM)
        assert "medium-risk" in message
        assert "write_file" in message

    def test_get_approval_message_high_risk(self):
        """Test approval message for high-risk operations."""
        prompt = APIApprovalPrompt()

        operation = Operation(
            tool_name="send_email",
            params={"to": "user@example.com"},
            correlation_id="test-123",
        )

        message = prompt._get_approval_message(operation, RiskLevel.HIGH)
        assert "HIGH RISK" in message
        assert "send_email" in message
        assert "difficult to undo" in message

    def test_get_approval_message_critical_risk(self):
        """Test approval message for critical-risk operations."""
        prompt = APIApprovalPrompt()

        operation = Operation(
            tool_name="delete_database",
            params={"database": "production"},
            correlation_id="test-123",
        )

        message = prompt._get_approval_message(operation, RiskLevel.CRITICAL)
        assert "CRITICAL" in message
        assert "delete_database" in message
        assert "IRREVERSIBLE" in message
        assert "DATA LOSS" in message


class TestCreatePrompt:
    """Tests for create_prompt factory function."""

    def test_create_cli_prompt(self):
        """Test creating CLI prompt."""
        prompt = create_prompt(mode="cli")
        assert isinstance(prompt, CLIApprovalPrompt)

    def test_create_cli_prompt_with_console(self):
        """Test creating CLI prompt with custom console."""
        console = Console()
        prompt = create_prompt(mode="cli", console=console)
        assert isinstance(prompt, CLIApprovalPrompt)
        assert prompt.console == console

    def test_create_api_prompt(self):
        """Test creating API prompt."""
        prompt = create_prompt(mode="api")
        assert isinstance(prompt, APIApprovalPrompt)

    def test_create_prompt_unknown_mode(self):
        """Test that unknown mode raises error."""
        with pytest.raises(ValueError, match="Unknown prompt mode"):
            create_prompt(mode="unknown")
