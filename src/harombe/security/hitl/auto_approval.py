"""Automated approval engine for low-risk HITL operations.

This module implements rule-based auto-approval logic that combines user trust
levels and historical risk scores to automatically approve low-risk operations
without human intervention.

Phase 5.2.3 Implementation
"""

import logging
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from .core import Operation
from .risk_scorer import HistoricalRiskScorer, RiskScore
from .trust import TrustLevel, TrustManager

logger = logging.getLogger(__name__)


class ApprovalAction(StrEnum):
    """Auto-approval action types."""

    AUTO_APPROVE = "auto_approve"
    REQUIRE_APPROVAL = "require_approval"


@dataclass
class AutoApprovalRule:
    """Rule for automatic approval decisions.

    Attributes:
        name: Rule identifier
        conditions: Conditions that must be met for rule to apply
        action: Action to take when rule matches
        reason: Human-readable explanation
        priority: Rule priority (higher = evaluated first)
    """

    name: str
    conditions: dict[str, Any]
    action: ApprovalAction
    reason: str
    priority: int = 0

    def matches(self, operation: Operation, trust: TrustLevel, risk: RiskScore) -> bool:
        """Check if rule conditions match the operation context.

        Args:
            operation: Operation being evaluated
            trust: User's trust level
            risk: Operation's risk score

        Returns:
            True if all conditions are met
        """
        # Check trust level condition
        if "trust_level" in self.conditions:
            required_trust = self.conditions["trust_level"]
            if trust != required_trust:
                return False

        # Check minimum trust level
        if "trust_level_min" in self.conditions:
            min_trust = self.conditions["trust_level_min"]
            trust_order = [
                TrustLevel.UNTRUSTED,
                TrustLevel.LOW,
                TrustLevel.MEDIUM,
                TrustLevel.HIGH,
            ]
            if trust_order.index(trust) < trust_order.index(min_trust):
                return False

        # Check maximum risk score
        if "risk_score_max" in self.conditions:
            max_risk = self.conditions["risk_score_max"]
            if risk.score > max_risk:
                return False

        # Check minimum risk score
        if "risk_score_min" in self.conditions:
            min_risk = self.conditions["risk_score_min"]
            if risk.score < min_risk:
                return False

        # Check tool name
        if "tool_name" in self.conditions:
            allowed_tools = self.conditions["tool_name"]
            if isinstance(allowed_tools, str):
                allowed_tools = [allowed_tools]
            if operation.tool_name not in allowed_tools:
                return False

        # Check excluded tools (rule matches if tool is in exclusion list)
        if "exclude_tools" in self.conditions:
            excluded = self.conditions["exclude_tools"]
            if isinstance(excluded, str):
                excluded = [excluded]
            if operation.tool_name not in excluded:
                return False

        # All conditions met
        return True


@dataclass
class AutoApprovalDecision:
    """Result of auto-approval evaluation.

    Attributes:
        should_auto_approve: Whether to auto-approve
        reason: Explanation for decision
        rule_name: Name of matching rule (if any)
        trust_level: User's trust level
        risk_score: Operation's risk score
    """

    should_auto_approve: bool
    reason: str
    rule_name: str | None
    trust_level: TrustLevel
    risk_score: float


class AutoApprovalEngine:
    """Automatically approve low-risk operations.

    Combines user trust levels and historical risk scores to make intelligent
    auto-approval decisions. Implements configurable rules that balance security
    with user experience.

    Default Rules:
    1. HIGH trust + risk <0.3 → auto-approve
    2. MEDIUM trust + risk <0.1 → auto-approve
    3. Any trust + risk >0.8 → require approval (safety override)
    4. LOW/UNTRUSTED trust → require approval

    Rules are evaluated in priority order (highest first).
    """

    def __init__(
        self,
        trust_manager: TrustManager,
        risk_scorer: HistoricalRiskScorer,
        custom_rules: list[AutoApprovalRule] | None = None,
    ):
        """Initialize auto-approval engine.

        Args:
            trust_manager: Trust manager instance
            risk_scorer: Risk scorer instance
            custom_rules: Optional custom rules (replaces defaults)
        """
        self.trust_manager = trust_manager
        self.risk_scorer = risk_scorer
        self.rules = custom_rules if custom_rules is not None else self._default_rules()
        # Sort rules by priority (highest first)
        self.rules.sort(key=lambda r: r.priority, reverse=True)

        # Statistics
        self.stats = {
            "total_evaluations": 0,
            "auto_approved": 0,
            "required_approval": 0,
            "by_rule": {},
        }

    async def should_auto_approve(
        self, operation: Operation, user_id: str, context: dict[str, Any] | None = None
    ) -> AutoApprovalDecision:
        """Determine if operation should be auto-approved.

        Args:
            operation: Operation to evaluate
            user_id: User identifier
            context: Additional context (optional)

        Returns:
            Auto-approval decision with explanation
        """
        self.stats["total_evaluations"] += 1

        # Get user trust level
        trust_level = await self.trust_manager.get_trust_level(user_id)

        # Get operation risk score
        risk_score = await self.risk_scorer.score_operation(operation, context)

        # Apply rules in priority order
        for rule in self.rules:
            if rule.matches(operation, trust_level, risk_score):
                # Rule matched - record stats
                rule_name = rule.name
                if rule_name not in self.stats["by_rule"]:
                    self.stats["by_rule"][rule_name] = 0
                self.stats["by_rule"][rule_name] += 1

                should_approve = rule.action == ApprovalAction.AUTO_APPROVE

                if should_approve:
                    self.stats["auto_approved"] += 1
                    logger.info(
                        f"Auto-approved {operation.tool_name} for {user_id} "
                        f"(trust={trust_level.value}, risk={risk_score.score:.2f}, "
                        f"rule={rule_name})"
                    )
                else:
                    self.stats["required_approval"] += 1
                    logger.debug(
                        f"Require approval for {operation.tool_name} for {user_id} "
                        f"(trust={trust_level.value}, risk={risk_score.score:.2f}, "
                        f"rule={rule_name})"
                    )

                return AutoApprovalDecision(
                    should_auto_approve=should_approve,
                    reason=rule.reason,
                    rule_name=rule_name,
                    trust_level=trust_level,
                    risk_score=risk_score.score,
                )

        # No rule matched - default to require approval
        self.stats["required_approval"] += 1
        logger.debug(
            f"No rule matched for {operation.tool_name} for {user_id} "
            f"(trust={trust_level.value}, risk={risk_score.score:.2f}) - "
            f"requiring approval"
        )

        return AutoApprovalDecision(
            should_auto_approve=False,
            reason="No matching auto-approval rule",
            rule_name=None,
            trust_level=trust_level,
            risk_score=risk_score.score,
        )

    def _default_rules(self) -> list[AutoApprovalRule]:
        """Load default auto-approval rules.

        Returns:
            List of default rules
        """
        return [
            # Safety override: Critical risk always requires approval
            AutoApprovalRule(
                name="critical_risk_block",
                conditions={"risk_score_min": 0.8},
                action=ApprovalAction.REQUIRE_APPROVAL,
                reason="Critical risk operation requires approval",
                priority=100,  # Highest priority
            ),
            # Dangerous tools always require approval
            AutoApprovalRule(
                name="dangerous_tools_block",
                conditions={
                    "exclude_tools": [
                        "delete_database",
                        "drop_table",
                        "format_disk",
                        "execute_sql",
                    ]
                },
                action=ApprovalAction.REQUIRE_APPROVAL,
                reason="Dangerous tool requires approval",
                priority=90,
            ),
            # High trust + low risk = auto-approve
            AutoApprovalRule(
                name="high_trust_low_risk",
                conditions={"trust_level": TrustLevel.HIGH, "risk_score_max": 0.3},
                action=ApprovalAction.AUTO_APPROVE,
                reason="High trust user, low risk operation",
                priority=50,
            ),
            # High trust + medium risk = auto-approve
            AutoApprovalRule(
                name="high_trust_medium_risk",
                conditions={"trust_level": TrustLevel.HIGH, "risk_score_max": 0.6},
                action=ApprovalAction.AUTO_APPROVE,
                reason="High trust user, acceptable risk",
                priority=45,
            ),
            # Medium trust + very low risk = auto-approve
            AutoApprovalRule(
                name="medium_trust_very_low_risk",
                conditions={"trust_level": TrustLevel.MEDIUM, "risk_score_max": 0.1},
                action=ApprovalAction.AUTO_APPROVE,
                reason="Medium trust user, very low risk operation",
                priority=40,
            ),
            # Low/Untrusted trust = require approval
            AutoApprovalRule(
                name="low_trust_block",
                conditions={"trust_level_min": TrustLevel.LOW},
                action=ApprovalAction.REQUIRE_APPROVAL,
                reason="Low trust user requires approval",
                priority=10,
            ),
        ]

    def add_rule(self, rule: AutoApprovalRule) -> None:
        """Add a custom auto-approval rule.

        Args:
            rule: Rule to add
        """
        self.rules.append(rule)
        # Re-sort by priority
        self.rules.sort(key=lambda r: r.priority, reverse=True)
        logger.info(f"Added auto-approval rule: {rule.name}")

    def remove_rule(self, rule_name: str) -> bool:
        """Remove an auto-approval rule by name.

        Args:
            rule_name: Name of rule to remove

        Returns:
            True if rule was found and removed
        """
        initial_count = len(self.rules)
        self.rules = [r for r in self.rules if r.name != rule_name]
        removed = len(self.rules) < initial_count

        if removed:
            logger.info(f"Removed auto-approval rule: {rule_name}")
        else:
            logger.warning(f"Rule not found: {rule_name}")

        return removed

    def get_rules(self) -> list[AutoApprovalRule]:
        """Get all active auto-approval rules.

        Returns:
            List of rules sorted by priority
        """
        return self.rules.copy()

    def get_statistics(self) -> dict[str, Any]:
        """Get auto-approval statistics.

        Returns:
            Dictionary with approval statistics
        """
        total = self.stats["total_evaluations"]
        auto_approved = self.stats["auto_approved"]
        required = self.stats["required_approval"]

        return {
            "total_evaluations": total,
            "auto_approved": auto_approved,
            "required_approval": required,
            "auto_approval_rate": auto_approved / total if total > 0 else 0.0,
            "by_rule": self.stats["by_rule"].copy(),
        }

    def reset_statistics(self) -> None:
        """Reset approval statistics."""
        self.stats = {
            "total_evaluations": 0,
            "auto_approved": 0,
            "required_approval": 0,
            "by_rule": {},
        }
        logger.info("Reset auto-approval statistics")
