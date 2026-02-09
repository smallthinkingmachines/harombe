"""Context-aware decision engine for HITL approval system.

This module implements the ContextAwareEngine that integrates auto-approval,
anomaly detection, and threat scoring into a unified decision-making system.

Phase 5.2.4 Implementation
"""

import logging
import time
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any

from ..ml.anomaly_detector import AnomalyDetector
from ..ml.models import ThreatLevel
from ..ml.threat_scoring import ThreatScorer
from .auto_approval import AutoApprovalEngine
from .core import Operation
from .risk_scorer import HistoricalRiskScorer
from .trust import TrustManager

logger = logging.getLogger(__name__)


class DecisionType(StrEnum):
    """Types of approval decisions."""

    AUTO_APPROVED = "auto_approved"
    REQUIRE_APPROVAL = "require_approval"
    BLOCKED = "blocked"


@dataclass
class ContextDecision:
    """Result of context-aware decision evaluation.

    Attributes:
        decision: Type of decision made
        reason: Human-readable explanation
        confidence: Confidence score (0-1)
        require_human: Whether human approval is required
        metadata: Additional context about decision
        latency_ms: Time taken to make decision
        components_evaluated: Components used in decision
    """

    decision: DecisionType
    reason: str
    confidence: float
    require_human: bool
    metadata: dict[str, Any]
    latency_ms: float
    components_evaluated: list[str]

    def __str__(self) -> str:
        """String representation of decision."""
        return (
            f"Decision: {self.decision.value}, "
            f"Reason: {self.reason}, "
            f"Confidence: {self.confidence:.2f}, "
            f"Latency: {self.latency_ms:.1f}ms"
        )


class ContextAwareEngine:
    """Context-aware decision engine for approval workflow.

    Integrates multiple components to make intelligent approval decisions:
    1. Auto-approval engine (trust + risk scoring)
    2. Anomaly detection (behavioral analysis)
    3. Threat scoring (security intelligence)

    Decision Flow:
    1. Check auto-approval (fast path for trusted low-risk ops)
    2. Detect anomalies (behavioral deviations)
    3. Score threats (security indicators)
    4. Make final decision with explanation

    The engine aims for <100ms decision latency while considering all
    available context factors.
    """

    def __init__(
        self,
        trust_manager: TrustManager,
        risk_scorer: HistoricalRiskScorer,
        anomaly_detector: AnomalyDetector | None = None,
        threat_scorer: ThreatScorer | None = None,
        enable_auto_approval: bool = True,
        enable_anomaly_detection: bool = True,
        enable_threat_scoring: bool = True,
    ):
        """Initialize context-aware engine.

        Args:
            trust_manager: Trust manager instance
            risk_scorer: Risk scorer instance
            anomaly_detector: Anomaly detector instance (optional)
            threat_scorer: Threat scorer instance (optional)
            enable_auto_approval: Enable auto-approval component
            enable_anomaly_detection: Enable anomaly detection component
            enable_threat_scoring: Enable threat scoring component
        """
        self.trust_manager = trust_manager
        self.risk_scorer = risk_scorer
        self.anomaly_detector = anomaly_detector
        self.threat_scorer = threat_scorer

        # Component toggles
        self.enable_auto_approval = enable_auto_approval
        self.enable_anomaly_detection = enable_anomaly_detection and anomaly_detector is not None
        self.enable_threat_scoring = enable_threat_scoring and threat_scorer is not None

        # Auto-approval engine (always created, can be disabled)
        self.auto_approval_engine = AutoApprovalEngine(trust_manager, risk_scorer)

        # Statistics
        self.stats = {
            "total_decisions": 0,
            "auto_approved": 0,
            "require_approval": 0,
            "blocked": 0,
            "avg_latency_ms": 0.0,
            "by_component": {},
        }

    async def evaluate(
        self,
        operation: Operation,
        user_id: str,
        context: dict[str, Any] | None = None,
    ) -> ContextDecision:
        """Evaluate operation and make approval decision.

        Args:
            operation: Operation to evaluate
            user_id: User identifier
            context: Additional context (optional)

        Returns:
            Context-aware decision with reasoning
        """
        start_time = time.perf_counter()
        components_evaluated = []
        context = context or {}

        self.stats["total_decisions"] += 1

        # Step 1: Try auto-approval (fast path)
        if self.enable_auto_approval:
            components_evaluated.append("auto_approval")
            auto_decision = await self.auto_approval_engine.should_auto_approve(
                operation, user_id, context
            )

            if auto_decision.should_auto_approve:
                latency_ms = (time.perf_counter() - start_time) * 1000
                self.stats["auto_approved"] += 1
                self._update_component_stats("auto_approval", latency_ms)

                logger.info(
                    f"Auto-approved {operation.tool_name} for {user_id} "
                    f"(rule: {auto_decision.rule_name}, latency: {latency_ms:.1f}ms)"
                )

                return ContextDecision(
                    decision=DecisionType.AUTO_APPROVED,
                    reason=auto_decision.reason,
                    confidence=0.95,
                    require_human=False,
                    metadata={
                        "rule_name": auto_decision.rule_name,
                        "trust_level": auto_decision.trust_level.value,
                        "risk_score": auto_decision.risk_score,
                    },
                    latency_ms=latency_ms,
                    components_evaluated=components_evaluated,
                )

        # Step 2: Check for anomalies
        anomaly_result = None
        if self.enable_anomaly_detection:
            components_evaluated.append("anomaly_detection")
            event = self._operation_to_event(operation, user_id, context)
            anomaly_result = self.anomaly_detector.detect(user_id, event)

            if anomaly_result.is_anomaly:
                latency_ms = (time.perf_counter() - start_time) * 1000
                self.stats["require_approval"] += 1
                self._update_component_stats("anomaly_detection", latency_ms)

                logger.warning(
                    f"Anomaly detected for {user_id}: {anomaly_result.explanation} "
                    f"(score: {anomaly_result.anomaly_score:.2f})"
                )

                return ContextDecision(
                    decision=DecisionType.REQUIRE_APPROVAL,
                    reason=f"Anomalous behavior detected: {anomaly_result.explanation}",
                    confidence=anomaly_result.anomaly_score,
                    require_human=True,
                    metadata={
                        "anomaly_score": anomaly_result.anomaly_score,
                        "threat_level": anomaly_result.threat_level.value,
                        "contributing_factors": anomaly_result.contributing_factors,
                    },
                    latency_ms=latency_ms,
                    components_evaluated=components_evaluated,
                )

        # Step 3: Score threat level
        threat_score = None
        if self.enable_threat_scoring:
            components_evaluated.append("threat_scoring")
            event = self._operation_to_event(operation, user_id, context)
            threat_score = await self.threat_scorer.score_event(user_id, event)

            # Block critical threats
            if threat_score.level == ThreatLevel.CRITICAL:
                latency_ms = (time.perf_counter() - start_time) * 1000
                self.stats["blocked"] += 1
                self._update_component_stats("threat_scoring", latency_ms)

                logger.error(
                    f"Critical threat detected for {user_id}: {threat_score.explanation} "
                    f"(score: {threat_score.total_score:.2f})"
                )

                return ContextDecision(
                    decision=DecisionType.BLOCKED,
                    reason=f"Critical threat detected: {threat_score.explanation}",
                    confidence=threat_score.total_score,
                    require_human=True,
                    metadata={
                        "threat_score": threat_score.total_score,
                        "threat_level": threat_score.level.value,
                        "components": threat_score.components,
                    },
                    latency_ms=latency_ms,
                    components_evaluated=components_evaluated,
                )

            # Require approval for high threats
            if threat_score.level == ThreatLevel.HIGH:
                latency_ms = (time.perf_counter() - start_time) * 1000
                self.stats["require_approval"] += 1
                self._update_component_stats("threat_scoring", latency_ms)

                logger.warning(
                    f"High threat detected for {user_id}: {threat_score.explanation} "
                    f"(score: {threat_score.total_score:.2f})"
                )

                return ContextDecision(
                    decision=DecisionType.REQUIRE_APPROVAL,
                    reason=f"High threat level: {threat_score.explanation}",
                    confidence=threat_score.total_score,
                    require_human=True,
                    metadata={
                        "threat_score": threat_score.total_score,
                        "threat_level": threat_score.level.value,
                        "components": threat_score.components,
                    },
                    latency_ms=latency_ms,
                    components_evaluated=components_evaluated,
                )

        # Step 4: Default to require approval
        # If we get here, no auto-approval and no blocking threats
        latency_ms = (time.perf_counter() - start_time) * 1000
        self.stats["require_approval"] += 1

        # Gather context for explanation
        metadata = {}
        reason_parts = []

        if anomaly_result:
            metadata["anomaly_score"] = anomaly_result.anomaly_score
            if anomaly_result.anomaly_score > 0.3:
                reason_parts.append(f"elevated anomaly score ({anomaly_result.anomaly_score:.2f})")

        if threat_score:
            metadata["threat_score"] = threat_score.total_score
            metadata["threat_level"] = threat_score.level.value
            if threat_score.level in [ThreatLevel.MEDIUM, ThreatLevel.LOW]:
                reason_parts.append(f"{threat_score.level.value} threat level")

        if reason_parts:
            reason = f"Standard approval required: {', '.join(reason_parts)}"
        else:
            reason = "Standard approval required"

        logger.debug(
            f"Require approval for {operation.tool_name} by {user_id}: {reason} "
            f"(latency: {latency_ms:.1f}ms)"
        )

        return ContextDecision(
            decision=DecisionType.REQUIRE_APPROVAL,
            reason=reason,
            confidence=0.5,
            require_human=True,
            metadata=metadata,
            latency_ms=latency_ms,
            components_evaluated=components_evaluated,
        )

    def _operation_to_event(
        self,
        operation: Operation,
        user_id: str,
        context: dict[str, Any],
    ) -> dict[str, Any]:
        """Convert operation to event dict for ML components.

        Args:
            operation: Operation to convert
            user_id: User identifier
            context: Additional context

        Returns:
            Event dictionary for ML components
        """
        return {
            "event_id": operation.correlation_id,
            "correlation_id": operation.correlation_id,
            "timestamp": datetime.now(),
            "event_type": "tool_invocation",
            "actor": user_id,
            "tool_name": operation.tool_name,
            "action": operation.tool_name,
            "status": "pending",
            "duration_ms": context.get("duration_ms"),
            "resource_count": len(operation.params) if operation.params else 0,
            "success": context.get("success", True),
            "metadata": operation.metadata or {},
            **context,  # Include additional context fields
        }

    def _update_component_stats(self, component: str, latency_ms: float) -> None:
        """Update statistics for a component.

        Args:
            component: Component name
            latency_ms: Latency in milliseconds
        """
        if component not in self.stats["by_component"]:
            self.stats["by_component"][component] = {
                "count": 0,
                "avg_latency_ms": 0.0,
            }

        stats = self.stats["by_component"][component]
        count = stats["count"]
        old_avg = stats["avg_latency_ms"]

        # Update running average
        stats["count"] = count + 1
        stats["avg_latency_ms"] = (old_avg * count + latency_ms) / (count + 1)

    def get_statistics(self) -> dict[str, Any]:
        """Get decision statistics.

        Returns:
            Dictionary with approval statistics
        """
        total = self.stats["total_decisions"]
        auto_approved = self.stats["auto_approved"]
        require_approval = self.stats["require_approval"]
        blocked = self.stats["blocked"]

        return {
            "total_decisions": total,
            "auto_approved": auto_approved,
            "require_approval": require_approval,
            "blocked": blocked,
            "auto_approval_rate": auto_approved / total if total > 0 else 0.0,
            "block_rate": blocked / total if total > 0 else 0.0,
            "by_component": self.stats["by_component"].copy(),
            "components_enabled": {
                "auto_approval": self.enable_auto_approval,
                "anomaly_detection": self.enable_anomaly_detection,
                "threat_scoring": self.enable_threat_scoring,
            },
        }

    def reset_statistics(self) -> None:
        """Reset decision statistics."""
        self.stats = {
            "total_decisions": 0,
            "auto_approved": 0,
            "require_approval": 0,
            "blocked": 0,
            "avg_latency_ms": 0.0,
            "by_component": {},
        }
        logger.info("Reset context-aware engine statistics")
