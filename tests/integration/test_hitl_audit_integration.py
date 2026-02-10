"""
Integration tests for HITL gates and audit logging.

Validates that approval decisions are properly logged and
audit trail is complete for all HITL operations.
"""

import asyncio
import tempfile
import uuid
from pathlib import Path

import pytest

from harombe.security.audit_db import AuditDatabase, SecurityDecision
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
    def audit_db(self, temp_db_path):
        """Create audit database."""
        db = AuditDatabase(db_path=temp_db_path)
        # AuditDatabase initializes on construction
        yield db
        # No close() method needed - connections are per-operation

    @pytest.fixture
    def audit_logger(self, temp_db_path):
        """Create audit logger."""
        return AuditLogger(db_path=temp_db_path)

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
        """Create HITL gate."""
        from harombe.security.hitl import RiskClassifier

        classifier = RiskClassifier(rules=hitl_rules)
        return HITLGate(classifier=classifier, auto_approve_low_risk=True, default_timeout=60)

    @pytest.mark.asyncio
    async def test_approved_operation_logged(self, hitl_gate, audit_logger, audit_db):
        """Test that approved operations are logged to audit trail."""
        # Create operation
        operation = Operation(
            tool_name="test_tool",
            params={"param1": "value1"},
            correlation_id="test_123",
        )

        # Mock prompt callback
        async def mock_prompt_callback(op, risk_level, timeout):
            return ApprovalDecision(
                decision=ApprovalStatus.APPROVED,
                reason="User approved",
                user="test_user",
            )

        # Request approval
        decision = await hitl_gate.check_approval(operation, prompt_callback=mock_prompt_callback)

        # Log security decision
        audit_logger.log_security_decision(
            correlation_id=str(uuid.uuid4()),
            decision_type="approval_request",
            decision=SecurityDecision.ALLOW,
            reason=decision.reason,
            actor="test_user",
            tool_name=operation.tool_name,
            context={
                "approved_by": decision.user,
                "parameters": operation.params,
                "risk_level": "HIGH",
            },
        )

        # Verify audit trail
        events = audit_db.get_security_decisions(limit=10)

        assert len(events) == 1
        event = events[0]
        assert event["tool_name"] == "test_tool"
        assert event["decision"] == SecurityDecision.ALLOW.value
        assert "User approved" in event["reason"]
        assert event["actor"] == "test_user"

    @pytest.mark.asyncio
    async def test_denied_operation_logged(self, hitl_gate, audit_logger, audit_db):
        """Test that denied operations are logged to audit trail."""
        # Create operation
        operation = Operation(
            tool_name="test_tool",
            params={"param1": "value1"},
            correlation_id="test_456",
        )

        # Mock prompt callback for denial
        async def mock_prompt_callback(op, risk_level, timeout):
            return ApprovalDecision(
                decision=ApprovalStatus.DENIED,
                reason="User denied",
                user="test_user",
            )

        # Request approval
        decision = await hitl_gate.check_approval(operation, prompt_callback=mock_prompt_callback)

        # Log security decision
        audit_logger.log_security_decision(
            correlation_id=str(uuid.uuid4()),
            decision_type="approval_request",
            decision=SecurityDecision.DENY,
            reason=decision.reason,
            actor="test_user",
            tool_name=operation.tool_name,
            context={
                "approved_by": decision.user,
                "parameters": operation.params,
                "risk_level": "HIGH",
            },
        )

        # Verify audit trail
        events = audit_db.get_security_decisions(limit=10)

        assert len(events) == 1
        event = events[0]
        assert event["decision"] == SecurityDecision.DENY.value
        assert "User denied" in event["reason"]

    @pytest.mark.asyncio
    async def test_timeout_operation_logged(self, hitl_gate, audit_logger, audit_db):
        """Test that timeout operations are logged to audit trail."""
        # Create operation
        operation = Operation(
            tool_name="test_tool",
            params={"param1": "value1"},
            correlation_id="test_789",
        )

        # Mock prompt callback for timeout
        async def mock_prompt_callback(op, risk_level, timeout):
            return ApprovalDecision(
                decision=ApprovalStatus.TIMEOUT,
                reason="Approval timeout",
                user=None,
            )

        # Request approval
        decision = await hitl_gate.check_approval(operation, prompt_callback=mock_prompt_callback)

        # Log security decision
        audit_logger.log_security_decision(
            correlation_id=str(uuid.uuid4()),
            decision_type="approval_request",
            decision=SecurityDecision.DENY,  # Timeout = auto-deny
            reason=decision.reason,
            actor="test_user",
            tool_name=operation.tool_name,
            context={
                "timeout": True,
                "parameters": operation.params,
                "risk_level": "HIGH",
            },
        )

        # Verify audit trail
        events = audit_db.get_security_decisions(limit=10)

        assert len(events) == 1
        event = events[0]
        assert event["decision"] == SecurityDecision.DENY.value
        assert "timeout" in event["reason"].lower()
        import json

        context = json.loads(event["context"])
        assert context["timeout"] is True

    @pytest.mark.asyncio
    async def test_auto_approved_operation_logged(self, hitl_gate, audit_logger, audit_db):
        """Test that auto-approved LOW risk operations are logged."""
        # Create LOW risk operation (auto-approved)
        operation = Operation(
            tool_name="safe_tool",
            params={"param1": "value1"},
            correlation_id="test_auto",
        )

        # Request approval (should auto-approve)
        decision = await hitl_gate.check_approval(operation)

        # Verify auto-approved
        assert decision.decision == ApprovalStatus.AUTO_APPROVED
        assert "auto" in decision.reason.lower() or "low risk" in decision.reason.lower()

        # Log security decision
        audit_logger.log_security_decision(
            correlation_id=str(uuid.uuid4()),
            decision_type="approval_request",
            decision=SecurityDecision.ALLOW,
            reason=decision.reason,
            actor="test_user",
            tool_name=operation.tool_name,
            context={
                "auto_approved": True,
                "parameters": operation.params,
                "risk_level": "LOW",
            },
        )

        # Verify audit trail
        events = audit_db.get_security_decisions(limit=10)

        assert len(events) == 1
        event = events[0]
        assert event["decision"] == SecurityDecision.ALLOW.value
        import json

        context = json.loads(event["context"])
        assert context["risk_level"] == "LOW"
        assert context["auto_approved"] is True

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
                params={"test": "data"},
                correlation_id=f"test_multi_{tool_name}",
            )

            # Mock approval for HIGH risk operations
            if risk == "HIGH":

                async def mock_prompt_callback(op, rl, to, _status=expected_status):
                    return ApprovalDecision(
                        decision=_status,
                        reason=f"User {_status.value}",
                        user="test_user",
                    )

                decision = await hitl_gate.check_approval(
                    operation, prompt_callback=mock_prompt_callback
                )
            else:
                decision = await hitl_gate.check_approval(operation)

            # Log decision
            audit_logger.log_security_decision(
                correlation_id=str(uuid.uuid4()),
                decision_type="approval_request",
                decision=(
                    SecurityDecision.ALLOW
                    if decision.decision in (ApprovalStatus.APPROVED, ApprovalStatus.AUTO_APPROVED)
                    else SecurityDecision.DENY
                ),
                reason=decision.reason,
                actor="test_user",
                tool_name=tool_name,
                context={"parameters": operation.params, "risk_level": risk},
            )

        # Verify complete audit trail
        events = audit_db.get_security_decisions(limit=10)

        assert len(events) == 3

        import json

        # Events are returned in reverse chronological order (newest first)
        # So we need to reverse to match insertion order
        events_reversed = list(reversed(events))

        # Verify first operation (approved)
        assert events_reversed[0]["decision"] == SecurityDecision.ALLOW.value
        context0 = json.loads(events_reversed[0]["context"])
        assert context0["risk_level"] == "HIGH"

        # Verify second operation (denied)
        assert events_reversed[1]["decision"] == SecurityDecision.DENY.value
        context1 = json.loads(events_reversed[1]["context"])
        assert context1["risk_level"] == "HIGH"

        # Verify third operation (auto-approved)
        assert events_reversed[2]["decision"] == SecurityDecision.ALLOW.value
        context2 = json.loads(events_reversed[2]["context"])
        assert context2["risk_level"] == "LOW"

    @pytest.mark.asyncio
    async def test_concurrent_operations_audit_trail(self, hitl_gate, audit_logger, audit_db):
        """Test that concurrent operations are logged correctly."""

        async def approve_operation(tool_name: str, risk: str):
            operation = Operation(
                tool_name=tool_name,
                params={"test": "data"},
                correlation_id=f"test_concurrent_{tool_name}",
            )

            # Mock approval callback
            async def mock_prompt_callback(op, rl, to):
                return ApprovalDecision(
                    decision=ApprovalStatus.APPROVED,
                    reason="User approved",
                    user="test_user",
                )

            decision = await hitl_gate.check_approval(
                operation, prompt_callback=mock_prompt_callback
            )

            # Log decision
            audit_logger.log_security_decision(
                correlation_id=str(uuid.uuid4()),
                decision_type="approval_request",
                decision=SecurityDecision.ALLOW,
                reason=decision.reason,
                actor="test_user",
                tool_name=tool_name,
                context={"parameters": operation.params, "risk_level": risk},
            )

        # Run concurrent operations
        await asyncio.gather(
            approve_operation("tool1", "HIGH"),
            approve_operation("tool2", "HIGH"),
            approve_operation("tool3", "HIGH"),
        )

        # Verify all operations logged
        events = audit_db.get_security_decisions(limit=10)

        assert len(events) == 3
        tool_names = {e["tool_name"] for e in events}
        assert tool_names == {"tool1", "tool2", "tool3"}

    @pytest.mark.asyncio
    async def test_audit_query_by_tool_name(self, audit_logger, audit_db):
        """Test querying audit logs by tool name."""
        # Log multiple operations
        for i in range(5):
            audit_logger.log_security_decision(
                correlation_id=str(uuid.uuid4()),
                decision_type="approval_request",
                decision=SecurityDecision.ALLOW,
                reason="Test",
                actor="test_user",
                tool_name=f"tool{i % 2}",  # tool0 or tool1
                context={"risk_level": "HIGH"},
            )

        # Query for all security decisions
        events = audit_db.get_security_decisions(limit=10)

        # Filter for specific tool
        tool0_events = [e for e in events if e["tool_name"] == "tool0"]
        assert len(tool0_events) == 3  # Should have 3 tool0 events
        assert all(e["tool_name"] == "tool0" for e in tool0_events)

    @pytest.mark.asyncio
    async def test_audit_query_by_decision(self, audit_logger, audit_db):
        """Test querying audit logs by decision type."""
        # Log mixed decisions
        for decision in [
            SecurityDecision.ALLOW,
            SecurityDecision.DENY,
            SecurityDecision.ALLOW,
        ]:
            audit_logger.log_security_decision(
                correlation_id=str(uuid.uuid4()),
                decision_type="approval_request",
                decision=decision,
                reason="Test",
                actor="test_user",
                tool_name="test_tool",
                context={"risk_level": "HIGH"},
            )

        # Query for approved only
        events = audit_db.get_security_decisions(decision=SecurityDecision.ALLOW, limit=10)

        assert len(events) == 2
        assert all(e["decision"] == SecurityDecision.ALLOW.value for e in events)
