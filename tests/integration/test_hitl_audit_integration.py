"""
Integration tests for HITL gates and audit logging.

Validates that approval decisions are properly logged and
audit trail is complete for all HITL operations.
"""

import asyncio
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from harombe.security.audit_db import AuditDatabase, EventType, SecurityDecision
from harombe.security.audit_logger import AuditLogger
from harombe.security.hitl import (
    ApprovalDecision,
    ApprovalStatus,
    HITLGate,
    HITLRule,
    Operation,
    RiskLevel,
)


class TestHITLAuditIntegration:
    """Integration tests for HITL and audit logging."""

    @pytest.fixture
    def temp_db_path(self):
        """Create temporary database for testing."""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        yield db_path
        # Cleanup
        Path(db_path).unlink(missing_ok=True)

    @pytest.fixture
    async def audit_db(self, temp_db_path):
        """Create audit database."""
        db = AuditDatabase(db_path=temp_db_path)
        await db.initialize()
        yield db
        await db.close()

    @pytest.fixture
    def audit_logger(self, audit_db):
        """Create audit logger."""
        return AuditLogger(audit_db=audit_db)

    @pytest.fixture
    def hitl_rules(self):
        """Create test HITL rules."""
        return [
            HITLRule(
                tools=["test_tool"],
                risk=RiskLevel.HIGH,
                require_approval=True,
                timeout=60,
                description="Test operation",
            ),
            HITLRule(
                tools=["safe_tool"],
                risk=RiskLevel.LOW,
                require_approval=False,
                description="Safe operation",
            ),
        ]

    @pytest.fixture
    def hitl_gate(self, hitl_rules):
        """Create HITL gate with CLI prompt."""
        from harombe.security.hitl import RiskClassifier

        classifier = RiskClassifier(rules=hitl_rules)
        return HITLGate(classifier=classifier, auto_approve_low_risk=True, default_timeout=60)

    @pytest.mark.asyncio
    async def test_approved_operation_logged(self, hitl_gate, audit_logger, audit_db):
        """Test that approved operations are logged to audit trail."""
        # Mock approval
        with patch.object(hitl_gate.prompt, "request_approval") as mock_approve:
            mock_approve.return_value = ApprovalDecision(
                status=ApprovalStatus.APPROVED,
                reason="User approved",
                approved_by="test_user",
            )

            # Create operation
            operation = Operation(
                tool_name="test_tool",
                parameters={"param1": "value1"},
                context={"user": "test_user"},
            )

            # Request approval
            decision = await hitl_gate.request_approval(operation)

            # Log security decision
            await audit_logger.log_security_decision(
                tool_name=operation.tool_name,
                operation_type="approval_request",
                decision=SecurityDecision.APPROVED,
                risk_level="HIGH",
                reason=decision.reason,
                details={
                    "approved_by": decision.approved_by,
                    "parameters": operation.parameters,
                },
            )

        # Verify audit trail
        events = await audit_db.query_events(
            event_type=EventType.SECURITY_DECISION,
            limit=10,
        )

        assert len(events) == 1
        event = events[0]
        assert event.tool_name == "test_tool"
        assert event.decision == SecurityDecision.APPROVED
        assert event.risk_level == "HIGH"
        assert "User approved" in event.reason
        assert event.details["approved_by"] == "test_user"

    @pytest.mark.asyncio
    async def test_denied_operation_logged(self, hitl_gate, audit_logger, audit_db):
        """Test that denied operations are logged to audit trail."""
        # Mock denial
        with patch.object(hitl_gate.prompt, "request_approval") as mock_approve:
            mock_approve.return_value = ApprovalDecision(
                status=ApprovalStatus.DENIED,
                reason="User denied",
                approved_by="test_user",
            )

            # Create operation
            operation = Operation(
                tool_name="test_tool",
                parameters={"param1": "value1"},
                context={"user": "test_user"},
            )

            # Request approval
            decision = await hitl_gate.request_approval(operation)

            # Log security decision
            await audit_logger.log_security_decision(
                tool_name=operation.tool_name,
                operation_type="approval_request",
                decision=SecurityDecision.DENIED,
                risk_level="HIGH",
                reason=decision.reason,
                details={
                    "approved_by": decision.approved_by,
                    "parameters": operation.parameters,
                },
            )

        # Verify audit trail
        events = await audit_db.query_events(
            event_type=EventType.SECURITY_DECISION,
            limit=10,
        )

        assert len(events) == 1
        event = events[0]
        assert event.decision == SecurityDecision.DENIED
        assert "User denied" in event.reason

    @pytest.mark.asyncio
    async def test_timeout_operation_logged(self, hitl_gate, audit_logger, audit_db):
        """Test that timeout operations are logged to audit trail."""
        # Mock timeout
        with patch.object(hitl_gate.prompt, "request_approval") as mock_approve:
            mock_approve.return_value = ApprovalDecision(
                status=ApprovalStatus.TIMEOUT,
                reason="Approval timeout",
                approved_by=None,
            )

            # Create operation
            operation = Operation(
                tool_name="test_tool",
                parameters={"param1": "value1"},
                context={"user": "test_user"},
            )

            # Request approval
            decision = await hitl_gate.request_approval(operation)

            # Log security decision
            await audit_logger.log_security_decision(
                tool_name=operation.tool_name,
                operation_type="approval_request",
                decision=SecurityDecision.DENIED,  # Timeout = auto-deny
                risk_level="HIGH",
                reason=decision.reason,
                details={
                    "timeout": True,
                    "parameters": operation.parameters,
                },
            )

        # Verify audit trail
        events = await audit_db.query_events(
            event_type=EventType.SECURITY_DECISION,
            limit=10,
        )

        assert len(events) == 1
        event = events[0]
        assert event.decision == SecurityDecision.DENIED
        assert "timeout" in event.reason.lower()
        assert event.details["timeout"] is True

    @pytest.mark.asyncio
    async def test_auto_approved_operation_logged(self, hitl_gate, audit_logger, audit_db):
        """Test that auto-approved LOW risk operations are logged."""
        # Create LOW risk operation (auto-approved)
        operation = Operation(
            tool_name="safe_tool",
            parameters={"param1": "value1"},
            context={"user": "test_user"},
        )

        # Request approval (should auto-approve)
        decision = await hitl_gate.request_approval(operation)

        # Verify auto-approved
        assert decision.status == ApprovalStatus.APPROVED
        assert "auto-approved" in decision.reason.lower()

        # Log security decision
        await audit_logger.log_security_decision(
            tool_name=operation.tool_name,
            operation_type="approval_request",
            decision=SecurityDecision.APPROVED,
            risk_level="LOW",
            reason=decision.reason,
            details={
                "auto_approved": True,
                "parameters": operation.parameters,
            },
        )

        # Verify audit trail
        events = await audit_db.query_events(
            event_type=EventType.SECURITY_DECISION,
            limit=10,
        )

        assert len(events) == 1
        event = events[0]
        assert event.decision == SecurityDecision.APPROVED
        assert event.risk_level == "LOW"
        assert event.details["auto_approved"] is True

    @pytest.mark.asyncio
    async def test_multiple_operations_audit_trail(self, hitl_gate, audit_logger, audit_db):
        """Test that multiple operations create complete audit trail."""
        operations = [
            ("test_tool", "HIGH", ApprovalStatus.APPROVED),
            ("test_tool", "HIGH", ApprovalStatus.DENIED),
            ("safe_tool", "LOW", ApprovalStatus.APPROVED),  # Auto-approved
        ]

        for tool_name, risk, expected_status in operations:
            operation = Operation(
                tool_name=tool_name,
                parameters={"test": "data"},
                context={"user": "test_user"},
            )

            # Mock approval for HIGH risk operations
            if risk == "HIGH":
                with patch.object(hitl_gate.prompt, "request_approval") as mock:
                    mock.return_value = ApprovalDecision(
                        status=expected_status,
                        reason=f"User {expected_status.value}",
                        approved_by="test_user",
                    )
                    decision = await hitl_gate.request_approval(operation)
            else:
                decision = await hitl_gate.request_approval(operation)

            # Log decision
            await audit_logger.log_security_decision(
                tool_name=tool_name,
                operation_type="approval_request",
                decision=(
                    SecurityDecision.APPROVED
                    if decision.status == ApprovalStatus.APPROVED
                    else SecurityDecision.DENIED
                ),
                risk_level=risk,
                reason=decision.reason,
                details={"parameters": operation.parameters},
            )

        # Verify complete audit trail
        events = await audit_db.query_events(
            event_type=EventType.SECURITY_DECISION,
            limit=10,
        )

        assert len(events) == 3

        # Verify first operation (approved)
        assert events[0].decision == SecurityDecision.APPROVED
        assert events[0].risk_level == "HIGH"

        # Verify second operation (denied)
        assert events[1].decision == SecurityDecision.DENIED
        assert events[1].risk_level == "HIGH"

        # Verify third operation (auto-approved)
        assert events[2].decision == SecurityDecision.APPROVED
        assert events[2].risk_level == "LOW"

    @pytest.mark.asyncio
    async def test_concurrent_operations_audit_trail(self, hitl_gate, audit_logger, audit_db):
        """Test that concurrent operations are logged correctly."""

        async def approve_operation(tool_name: str, risk: str):
            operation = Operation(
                tool_name=tool_name,
                parameters={"test": "data"},
                context={"user": "test_user"},
            )

            # Mock approval
            with patch.object(hitl_gate.prompt, "request_approval") as mock:
                mock.return_value = ApprovalDecision(
                    status=ApprovalStatus.APPROVED,
                    reason="User approved",
                    approved_by="test_user",
                )
                decision = await hitl_gate.request_approval(operation)

            # Log decision
            await audit_logger.log_security_decision(
                tool_name=tool_name,
                operation_type="approval_request",
                decision=SecurityDecision.APPROVED,
                risk_level=risk,
                reason=decision.reason,
                details={"parameters": operation.parameters},
            )

        # Run concurrent operations
        await asyncio.gather(
            approve_operation("tool1", "HIGH"),
            approve_operation("tool2", "HIGH"),
            approve_operation("tool3", "HIGH"),
        )

        # Verify all operations logged
        events = await audit_db.query_events(
            event_type=EventType.SECURITY_DECISION,
            limit=10,
        )

        assert len(events) == 3
        tool_names = {e.tool_name for e in events}
        assert tool_names == {"tool1", "tool2", "tool3"}

    @pytest.mark.asyncio
    async def test_audit_query_by_tool_name(self, audit_logger, audit_db):
        """Test querying audit logs by tool name."""
        # Log multiple operations
        for i in range(5):
            await audit_logger.log_security_decision(
                tool_name=f"tool{i % 2}",  # tool0 or tool1
                operation_type="approval_request",
                decision=SecurityDecision.APPROVED,
                risk_level="HIGH",
                reason="Test",
                details={},
            )

        # Query for specific tool
        events = await audit_db.query_events(
            event_type=EventType.SECURITY_DECISION,
            tool_name="tool0",
            limit=10,
        )

        assert len(events) == 3  # Should have 3 tool0 events
        assert all(e.tool_name == "tool0" for e in events)

    @pytest.mark.asyncio
    async def test_audit_query_by_decision(self, audit_logger, audit_db):
        """Test querying audit logs by decision type."""
        # Log mixed decisions
        for decision in [
            SecurityDecision.APPROVED,
            SecurityDecision.DENIED,
            SecurityDecision.APPROVED,
        ]:
            await audit_logger.log_security_decision(
                tool_name="test_tool",
                operation_type="approval_request",
                decision=decision,
                risk_level="HIGH",
                reason="Test",
                details={},
            )

        # Query for approved only
        events = await audit_db.query_events(
            event_type=EventType.SECURITY_DECISION,
            decision=SecurityDecision.APPROVED,
            limit=10,
        )

        assert len(events) == 2
        assert all(e.decision == SecurityDecision.APPROVED for e in events)
