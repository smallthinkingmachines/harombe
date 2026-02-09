"""
Tests for Human-in-the-Loop (HITL) Gates.

Tests risk classification, approval flows, timeouts, and decision handling.
"""

import asyncio
import contextlib

import pytest

from harombe.security.hitl import (
    ApprovalDecision,
    ApprovalStatus,
    HITLGate,
    HITLRule,
    Operation,
    PendingApproval,
    RiskClassifier,
    RiskLevel,
)


class TestRiskClassifier:
    """Tests for RiskClassifier."""

    def test_classify_critical_operations(self):
        """Test that critical operations are classified correctly."""
        classifier = RiskClassifier()

        operation = Operation(
            tool_name="delete_database",
            params={"database": "production"},
            correlation_id="test-123",
        )

        risk = classifier.classify(operation)
        assert risk == RiskLevel.CRITICAL

    def test_classify_high_risk_operations(self):
        """Test that high-risk operations are classified correctly."""
        classifier = RiskClassifier()

        operation = Operation(
            tool_name="send_email",
            params={"to": "user@example.com", "body": "Test"},
            correlation_id="test-123",
        )

        risk = classifier.classify(operation)
        assert risk == RiskLevel.HIGH

    def test_classify_medium_risk_operations(self):
        """Test that medium-risk operations are classified correctly."""
        classifier = RiskClassifier()

        operation = Operation(
            tool_name="write_file",
            params={"path": "/tmp/test.txt", "content": "Test"},
            correlation_id="test-123",
        )

        risk = classifier.classify(operation)
        assert risk == RiskLevel.MEDIUM

    def test_classify_low_risk_operations(self):
        """Test that low-risk operations are classified correctly."""
        classifier = RiskClassifier()

        operation = Operation(
            tool_name="read_file",
            params={"path": "/tmp/test.txt"},
            correlation_id="test-123",
        )

        risk = classifier.classify(operation)
        assert risk == RiskLevel.LOW

    def test_classify_unknown_operation_defaults_to_medium(self):
        """Test that unknown operations default to medium risk."""
        classifier = RiskClassifier()

        operation = Operation(
            tool_name="unknown_tool",
            params={},
            correlation_id="test-123",
        )

        risk = classifier.classify(operation)
        assert risk == RiskLevel.MEDIUM

    def test_custom_rules(self):
        """Test that custom rules can be added."""
        custom_rules = [
            HITLRule(
                tools=["custom_tool"],
                risk=RiskLevel.HIGH,
                description="Custom high-risk tool",
            )
        ]

        classifier = RiskClassifier(rules=custom_rules)

        operation = Operation(
            tool_name="custom_tool",
            params={},
            correlation_id="test-123",
        )

        risk = classifier.classify(operation)
        assert risk == RiskLevel.HIGH

    def test_requires_approval_for_high_risk(self):
        """Test that high-risk operations require approval."""
        classifier = RiskClassifier()

        operation = Operation(
            tool_name="send_email",
            params={"to": "user@example.com"},
            correlation_id="test-123",
        )

        assert classifier.requires_approval(operation) is True

    def test_no_approval_for_low_risk(self):
        """Test that low-risk operations don't require approval."""
        classifier = RiskClassifier()

        operation = Operation(
            tool_name="read_file",
            params={"path": "/tmp/test.txt"},
            correlation_id="test-123",
        )

        assert classifier.requires_approval(operation) is False

    def test_conditional_rules(self):
        """Test that conditional rules work correctly."""
        rules = [
            HITLRule(
                tools=["write_file"],
                risk=RiskLevel.CRITICAL,
                conditions=[{"param": "path", "matches": r"^/etc/.*"}],
                description="Critical for system files",
            ),
            HITLRule(
                tools=["write_file"],
                risk=RiskLevel.MEDIUM,
                description="Medium for other files",
            ),
        ]

        classifier = RiskClassifier(rules=rules)

        # System file - should be critical
        system_op = Operation(
            tool_name="write_file",
            params={"path": "/etc/hosts"},
            correlation_id="test-123",
        )
        assert classifier.classify(system_op) == RiskLevel.CRITICAL

        # Regular file - should be medium
        regular_op = Operation(
            tool_name="write_file",
            params={"path": "/tmp/test.txt"},
            correlation_id="test-123",
        )
        assert classifier.classify(regular_op) == RiskLevel.MEDIUM

    def test_get_timeout(self):
        """Test that timeout is retrieved correctly."""
        classifier = RiskClassifier()

        operation = Operation(
            tool_name="send_email",
            params={},
            correlation_id="test-123",
        )

        timeout = classifier.get_timeout(operation)
        assert timeout == 60  # Default for high-risk


class TestPendingApproval:
    """Tests for PendingApproval."""

    def test_pending_approval_creation(self):
        """Test that pending approval is created correctly."""
        operation = Operation(
            tool_name="send_email",
            params={"to": "user@example.com"},
            correlation_id="test-123",
        )

        pending = PendingApproval(
            approval_id="approval-123",
            operation=operation,
            risk_level=RiskLevel.HIGH,
            timeout=60,
        )

        assert pending.approval_id == "approval-123"
        assert pending.operation == operation
        assert pending.risk_level == RiskLevel.HIGH
        assert pending.timeout == 60
        assert pending.status == ApprovalStatus.PENDING
        assert pending.decision is None

    def test_is_expired(self):
        """Test expiration check."""
        operation = Operation(
            tool_name="send_email",
            params={},
            correlation_id="test-123",
        )

        pending = PendingApproval(
            approval_id="approval-123",
            operation=operation,
            risk_level=RiskLevel.HIGH,
            timeout=1,  # 1 second timeout
        )

        # Should not be expired immediately
        assert pending.is_expired() is False

        # Wait for expiration
        import time

        time.sleep(1.1)

        # Should now be expired
        assert pending.is_expired() is True

    @pytest.mark.asyncio
    async def test_wait_for_decision_timeout(self):
        """Test that waiting for decision times out correctly."""
        operation = Operation(
            tool_name="send_email",
            params={},
            correlation_id="test-123",
        )

        pending = PendingApproval(
            approval_id="approval-123",
            operation=operation,
            risk_level=RiskLevel.HIGH,
            timeout=1,  # 1 second timeout
        )

        # Wait for decision (should timeout)
        decision = await pending.wait_for_decision()

        assert decision.decision == ApprovalStatus.TIMEOUT
        assert decision.timeout_seconds == 1
        assert decision.approval_id == "approval-123"
        assert pending.status == ApprovalStatus.TIMEOUT

    @pytest.mark.asyncio
    async def test_set_decision(self):
        """Test that decision can be set."""
        operation = Operation(
            tool_name="send_email",
            params={},
            correlation_id="test-123",
        )

        pending = PendingApproval(
            approval_id="approval-123",
            operation=operation,
            risk_level=RiskLevel.HIGH,
            timeout=60,
        )

        # Set decision
        decision = ApprovalDecision(
            decision=ApprovalStatus.APPROVED,
            user="test-user",
            reason="Test approval",
            approval_id="approval-123",
        )

        pending.set_decision(decision)

        assert pending.decision == decision
        assert pending.status == ApprovalStatus.APPROVED


class TestHITLGate:
    """Tests for HITLGate."""

    @pytest.mark.asyncio
    async def test_auto_approve_low_risk(self):
        """Test that low-risk operations are auto-approved."""
        gate = HITLGate(auto_approve_low_risk=True)

        operation = Operation(
            tool_name="read_file",
            params={"path": "/tmp/test.txt"},
            correlation_id="test-123",
        )

        decision = await gate.check_approval(operation, user="test-user")

        assert decision.decision == ApprovalStatus.AUTO_APPROVED
        assert decision.user == "test-user"
        assert "Low risk" in decision.reason

    @pytest.mark.asyncio
    async def test_require_approval_for_high_risk(self):
        """Test that high-risk operations require approval."""
        gate = HITLGate()

        operation = Operation(
            tool_name="send_email",
            params={"to": "user@example.com"},
            correlation_id="test-123",
        )

        # Create task to check approval (will timeout)
        check_task = asyncio.create_task(gate.check_approval(operation, user="test-user"))

        # Wait a bit for pending approval to be created
        await asyncio.sleep(0.1)

        # Should have pending approval
        assert len(gate.pending_approvals) == 1

        # Cancel the task to avoid waiting for timeout
        check_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await check_task

    @pytest.mark.asyncio
    async def test_approve_operation(self):
        """Test that operation can be approved."""
        gate = HITLGate()

        operation = Operation(
            tool_name="send_email",
            params={"to": "user@example.com"},
            correlation_id="test-123",
        )

        # Start approval check in background
        check_task = asyncio.create_task(gate.check_approval(operation, user="test-user"))

        # Wait for pending approval to be created
        await asyncio.sleep(0.1)

        # Get approval ID
        approval_id = next(iter(gate.pending_approvals.keys()))

        # Approve the operation
        success = gate.approve(approval_id, user="admin", reason="Looks good")
        assert success is True

        # Wait for decision
        decision = await check_task

        assert decision.decision == ApprovalStatus.APPROVED
        assert decision.user == "admin"
        assert decision.reason == "Looks good"

    @pytest.mark.asyncio
    async def test_deny_operation(self):
        """Test that operation can be denied."""
        gate = HITLGate()

        operation = Operation(
            tool_name="send_email",
            params={"to": "user@example.com"},
            correlation_id="test-123",
        )

        # Start approval check in background
        check_task = asyncio.create_task(gate.check_approval(operation, user="test-user"))

        # Wait for pending approval to be created
        await asyncio.sleep(0.1)

        # Get approval ID
        approval_id = next(iter(gate.pending_approvals.keys()))

        # Deny the operation
        success = gate.deny(approval_id, user="admin", reason="Not safe")
        assert success is True

        # Wait for decision
        decision = await check_task

        assert decision.decision == ApprovalStatus.DENIED
        assert decision.user == "admin"
        assert decision.reason == "Not safe"

    @pytest.mark.asyncio
    async def test_timeout_denies(self):
        """Test that timeout results in denial."""
        gate = HITLGate()

        operation = Operation(
            tool_name="send_email",
            params={"to": "user@example.com"},
            correlation_id="test-123",
        )

        # Mock classifier to return short timeout
        gate.classifier.get_timeout = lambda op: 1

        # Check approval (will timeout after 1 second)
        decision = await gate.check_approval(operation, user="test-user")

        assert decision.decision == ApprovalStatus.TIMEOUT
        assert decision.timeout_seconds == 1

    @pytest.mark.asyncio
    async def test_prompt_callback(self):
        """Test that prompt callback is called."""
        gate = HITLGate()

        operation = Operation(
            tool_name="send_email",
            params={"to": "user@example.com"},
            correlation_id="test-123",
        )

        # Track if callback was called
        callback_called = False

        async def prompt_callback(op, risk, timeout):
            nonlocal callback_called
            callback_called = True
            return ApprovalDecision(
                decision=ApprovalStatus.APPROVED,
                user="test-user",
                reason="Callback approval",
            )

        # Check approval with callback
        decision = await gate.check_approval(
            operation,
            user="test-user",
            prompt_callback=prompt_callback,
        )

        assert callback_called is True
        assert decision.decision == ApprovalStatus.APPROVED
        assert decision.reason == "Callback approval"

    @pytest.mark.asyncio
    async def test_prompt_callback_error_denies(self):
        """Test that prompt callback error results in denial."""
        gate = HITLGate()

        operation = Operation(
            tool_name="send_email",
            params={"to": "user@example.com"},
            correlation_id="test-123",
        )

        async def failing_callback(op, risk, timeout):
            raise ValueError("Callback error")

        # Mock classifier to return short timeout for faster test
        gate.classifier.get_timeout = lambda op: 2

        # Check approval with failing callback
        decision = await gate.check_approval(
            operation,
            user="test-user",
            prompt_callback=failing_callback,
        )

        assert decision.decision == ApprovalStatus.DENIED
        assert "Error prompting user" in decision.reason

    def test_get_pending(self):
        """Test getting pending approval by ID."""
        gate = HITLGate()

        operation = Operation(
            tool_name="send_email",
            params={},
            correlation_id="test-123",
        )

        pending = PendingApproval(
            approval_id="approval-123",
            operation=operation,
            risk_level=RiskLevel.HIGH,
            timeout=60,
        )

        gate.pending_approvals["approval-123"] = pending

        retrieved = gate.get_pending("approval-123")
        assert retrieved == pending

        # Non-existent ID
        assert gate.get_pending("non-existent") is None

    def test_list_pending(self):
        """Test listing all pending approvals."""
        gate = HITLGate()

        operation1 = Operation(
            tool_name="send_email",
            params={},
            correlation_id="test-123",
        )

        operation2 = Operation(
            tool_name="delete_file",
            params={},
            correlation_id="test-456",
        )

        pending1 = PendingApproval(
            approval_id="approval-123",
            operation=operation1,
            risk_level=RiskLevel.HIGH,
            timeout=60,
        )

        pending2 = PendingApproval(
            approval_id="approval-456",
            operation=operation2,
            risk_level=RiskLevel.HIGH,
            timeout=60,
        )

        gate.pending_approvals["approval-123"] = pending1
        gate.pending_approvals["approval-456"] = pending2

        pending_list = gate.list_pending()
        assert len(pending_list) == 2
        assert pending1 in pending_list
        assert pending2 in pending_list

    def test_list_pending_cleans_expired(self):
        """Test that listing pending approvals cleans up expired ones."""
        gate = HITLGate()

        operation = Operation(
            tool_name="send_email",
            params={},
            correlation_id="test-123",
        )

        # Create expired pending approval
        pending = PendingApproval(
            approval_id="approval-123",
            operation=operation,
            risk_level=RiskLevel.HIGH,
            timeout=0,  # Already expired
        )

        gate.pending_approvals["approval-123"] = pending

        # List pending (should clean up expired)
        pending_list = gate.list_pending()
        assert len(pending_list) == 0
        assert "approval-123" not in gate.pending_approvals

    @pytest.mark.asyncio
    async def test_approval_cleanup(self):
        """Test that approved operations are cleaned up."""
        gate = HITLGate()

        operation = Operation(
            tool_name="send_email",
            params={"to": "user@example.com"},
            correlation_id="test-123",
        )

        # Start approval check
        check_task = asyncio.create_task(gate.check_approval(operation, user="test-user"))

        # Wait for pending approval
        await asyncio.sleep(0.1)

        approval_id = next(iter(gate.pending_approvals.keys()))

        # Approve
        gate.approve(approval_id, user="admin")

        # Wait for completion
        await check_task

        # Should be cleaned up
        assert approval_id not in gate.pending_approvals
