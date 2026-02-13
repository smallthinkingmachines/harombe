"""
Human-in-the-Loop (HITL) Gates for Harombe Security Layer.

Provides approval mechanisms for potentially dangerous operations,
requiring explicit user confirmation before execution.

Phase 4.5 Implementation
"""

import asyncio
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4


class RiskLevel(StrEnum):
    """Risk classification for operations."""

    LOW = "low"  # Read-only operations, safe actions
    MEDIUM = "medium"  # Modifications with easy undo
    HIGH = "high"  # Destructive operations, hard to undo
    CRITICAL = "critical"  # Irreversible operations, data loss


class ApprovalStatus(StrEnum):
    """Status of approval request."""

    PENDING = "pending"  # Waiting for user decision
    APPROVED = "approved"  # User approved
    DENIED = "denied"  # User denied
    TIMEOUT = "timeout"  # Request timed out
    AUTO_APPROVED = "auto_approved"  # Auto-approved (low risk)


@dataclass
class Operation:
    """Represents an operation requiring approval."""

    tool_name: str
    params: dict[str, Any]
    correlation_id: str
    session_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ApprovalDecision:
    """Result of approval request."""

    decision: ApprovalStatus
    user: str | None = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC).replace(tzinfo=None))
    reason: str | None = None
    timeout_seconds: int | None = None
    approval_id: str | None = None


@dataclass
class HITLRule:
    """Rule for determining if approval is required."""

    tools: list[str]  # Tool names this rule applies to
    risk: RiskLevel
    require_approval: bool = True
    timeout: int = 60  # seconds
    conditions: list[dict[str, Any]] | None = None
    description: str | None = None


class RiskClassifier:
    """Classifies operations by risk level."""

    def __init__(self, rules: list[HITLRule] | None = None):
        """
        Initialize risk classifier.

        Args:
            rules: List of HITL rules for classification
        """
        self.rules = rules or self._default_rules()

    def _default_rules(self) -> list[HITLRule]:
        """Default risk classification rules."""
        return [
            # Critical operations
            HITLRule(
                tools=["delete_database", "drop_table", "format_disk"],
                risk=RiskLevel.CRITICAL,
                description="Irreversible data loss operations",
            ),
            # High risk operations
            HITLRule(
                tools=["send_email", "post_message", "delete_file", "execute_sql"],
                risk=RiskLevel.HIGH,
                timeout=60,
                description="Operations that are hard to undo",
            ),
            # Medium risk operations
            HITLRule(
                tools=["write_file", "modify_file", "create_resource"],
                risk=RiskLevel.MEDIUM,
                timeout=120,
                description="Modifications with possible undo",
            ),
            # Low risk operations (read-only)
            HITLRule(
                tools=["read_file", "list_files", "web_search", "get_data"],
                risk=RiskLevel.LOW,
                require_approval=False,
                description="Read-only operations",
            ),
        ]

    def classify(self, operation: Operation) -> RiskLevel:
        """
        Classify operation risk level.

        Args:
            operation: The operation to classify

        Returns:
            Risk level for the operation
        """
        # Check each rule
        for rule in self.rules:
            if operation.tool_name in rule.tools:
                # Check additional conditions if present
                if rule.conditions:
                    if self._check_conditions(operation, rule.conditions):
                        return rule.risk
                else:
                    return rule.risk

        # Default: medium risk for unknown operations
        return RiskLevel.MEDIUM

    def _check_conditions(self, operation: Operation, conditions: list[dict[str, Any]]) -> bool:
        """Check if operation meets all conditions."""
        for condition in conditions:
            param = condition.get("param")
            if param not in operation.params:
                return False

            value = operation.params[param]

            # Check different condition types
            if "equals" in condition and value != condition["equals"]:
                return False

            if "matches" in condition:
                import re

                if not re.match(condition["matches"], str(value)):
                    return False

            if "in" in condition and value not in condition["in"]:
                return False

        return True

    def requires_approval(self, operation: Operation) -> bool:
        """Check if operation requires approval."""
        for rule in self.rules:
            if operation.tool_name in rule.tools:
                if rule.conditions:
                    if self._check_conditions(operation, rule.conditions):
                        return rule.require_approval
                else:
                    return rule.require_approval

        # Default: require approval for unknown operations
        return True

    def get_timeout(self, operation: Operation) -> int:
        """Get timeout for operation."""
        for rule in self.rules:
            if operation.tool_name in rule.tools:
                if rule.conditions:
                    if self._check_conditions(operation, rule.conditions):
                        return rule.timeout
                else:
                    return rule.timeout

        # Default timeout
        return 60


class PendingApproval:
    """Represents a pending approval request."""

    def __init__(
        self,
        approval_id: str,
        operation: Operation,
        risk_level: RiskLevel,
        timeout: int,
    ):
        """
        Initialize pending approval.

        Args:
            approval_id: Unique approval identifier
            operation: The operation requiring approval
            risk_level: Risk level of the operation
            timeout: Timeout in seconds
        """
        self.approval_id = approval_id
        self.operation = operation
        self.risk_level = risk_level
        self.timeout = timeout
        self.created_at = time.time()
        self.status = ApprovalStatus.PENDING
        self.decision: ApprovalDecision | None = None
        self._future: asyncio.Future[Any] | None = None

    def is_expired(self) -> bool:
        """Check if approval request has expired."""
        return time.time() - self.created_at > self.timeout

    async def wait_for_decision(self) -> ApprovalDecision:
        """Wait for user decision or timeout."""
        if self._future is None:
            self._future = asyncio.Future()

        try:
            # Wait for decision or timeout
            return await asyncio.wait_for(self._future, timeout=self.timeout)
        except TimeoutError:
            # Timeout: auto-deny
            decision = ApprovalDecision(
                decision=ApprovalStatus.TIMEOUT,
                timestamp=datetime.now(UTC).replace(tzinfo=None),
                timeout_seconds=self.timeout,
                approval_id=self.approval_id,
            )
            self.status = ApprovalStatus.TIMEOUT
            self.decision = decision
            return decision

    def set_decision(self, decision: ApprovalDecision) -> None:
        """Set the approval decision."""
        self.decision = decision
        self.status = decision.decision

        if self._future and not self._future.done():
            self._future.set_result(decision)


class HITLGate:
    """Human-in-the-Loop gate for operation approval."""

    def __init__(
        self,
        classifier: RiskClassifier | None = None,
        auto_approve_low_risk: bool = True,
        default_timeout: int = 60,
    ):
        """
        Initialize HITL gate.

        Args:
            classifier: Risk classifier for operations
            auto_approve_low_risk: Auto-approve low-risk operations
            default_timeout: Default timeout in seconds
        """
        self.classifier = classifier or RiskClassifier()
        self.auto_approve_low_risk = auto_approve_low_risk
        self.default_timeout = default_timeout
        self.pending_approvals: dict[str, PendingApproval] = {}

    async def check_approval(
        self,
        operation: Operation,
        user: str | None = None,
        prompt_callback: Callable[..., Any] | None = None,
    ) -> ApprovalDecision:
        """
        Check if operation requires approval and get decision.

        Args:
            operation: The operation to check
            user: User requesting the operation
            prompt_callback: Optional callback to prompt user

        Returns:
            Approval decision
        """
        # Classify risk
        risk_level = self.classifier.classify(operation)

        # Auto-approve low-risk operations if configured
        if self.auto_approve_low_risk and risk_level == RiskLevel.LOW:
            return ApprovalDecision(
                decision=ApprovalStatus.AUTO_APPROVED,
                user=user,
                timestamp=datetime.now(UTC).replace(tzinfo=None),
                reason="Low risk operation",
            )

        # Check if approval required
        if not self.classifier.requires_approval(operation):
            return ApprovalDecision(
                decision=ApprovalStatus.AUTO_APPROVED,
                user=user,
                timestamp=datetime.now(UTC).replace(tzinfo=None),
                reason="Approval not required by policy",
            )

        # Get timeout for operation
        timeout = self.classifier.get_timeout(operation)

        # Create pending approval
        approval_id = str(uuid4())
        pending = PendingApproval(
            approval_id=approval_id,
            operation=operation,
            risk_level=risk_level,
            timeout=timeout,
        )

        self.pending_approvals[approval_id] = pending

        # Prompt user if callback provided
        prompt_task = None
        if prompt_callback:
            prompt_task = asyncio.create_task(self._prompt_user(pending, prompt_callback))

        # Wait for decision
        decision = await pending.wait_for_decision()

        # Cancel prompt task if still running
        if prompt_task and not prompt_task.done():
            prompt_task.cancel()

        # Clean up
        if approval_id in self.pending_approvals:
            del self.pending_approvals[approval_id]

        return decision

    async def _prompt_user(
        self, pending: PendingApproval, prompt_callback: Callable[..., Any]
    ) -> None:
        """Prompt user for approval."""
        try:
            decision = await prompt_callback(pending.operation, pending.risk_level, pending.timeout)
            pending.set_decision(decision)
        except Exception as e:
            # Error prompting: auto-deny
            pending.set_decision(
                ApprovalDecision(
                    decision=ApprovalStatus.DENIED,
                    timestamp=datetime.now(UTC).replace(tzinfo=None),
                    reason=f"Error prompting user: {e}",
                    approval_id=pending.approval_id,
                )
            )

    def approve(
        self,
        approval_id: str,
        user: str,
        reason: str | None = None,
    ) -> bool:
        """
        Approve a pending operation.

        Args:
            approval_id: Approval request ID
            user: User approving the operation
            reason: Optional reason for approval

        Returns:
            True if approval was successful
        """
        if approval_id not in self.pending_approvals:
            return False

        pending = self.pending_approvals[approval_id]

        if pending.is_expired():
            # Already expired
            return False

        decision = ApprovalDecision(
            decision=ApprovalStatus.APPROVED,
            user=user,
            timestamp=datetime.now(UTC).replace(tzinfo=None),
            reason=reason,
            approval_id=approval_id,
        )

        pending.set_decision(decision)
        return True

    def deny(
        self,
        approval_id: str,
        user: str,
        reason: str | None = None,
    ) -> bool:
        """
        Deny a pending operation.

        Args:
            approval_id: Approval request ID
            user: User denying the operation
            reason: Optional reason for denial

        Returns:
            True if denial was successful
        """
        if approval_id not in self.pending_approvals:
            return False

        pending = self.pending_approvals[approval_id]

        decision = ApprovalDecision(
            decision=ApprovalStatus.DENIED,
            user=user,
            timestamp=datetime.now(UTC).replace(tzinfo=None),
            reason=reason,
            approval_id=approval_id,
        )

        pending.set_decision(decision)
        return True

    def get_pending(self, approval_id: str) -> PendingApproval | None:
        """Get pending approval by ID."""
        return self.pending_approvals.get(approval_id)

    def list_pending(self) -> list[PendingApproval]:
        """List all pending approvals."""
        # Clean up expired approvals
        time.time()
        expired = [aid for aid, pending in self.pending_approvals.items() if pending.is_expired()]

        for aid in expired:
            del self.pending_approvals[aid]

        return list(self.pending_approvals.values())
