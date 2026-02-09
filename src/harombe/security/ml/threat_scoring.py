"""Real-time threat scoring engine."""

import logging
from datetime import datetime
from typing import Any

from ..audit_logger import AuditLogger
from .anomaly_detector import AnomalyDetector
from .models import ThreatLevel

logger = logging.getLogger(__name__)


class ThreatScore:
    """Threat score result."""

    def __init__(
        self,
        event: dict[str, Any],
        total_score: float,
        components: dict[str, float],
        level: ThreatLevel,
        explanation: str,
        timestamp: datetime,
    ):
        """Initialize threat score.

        Args:
            event: Original event
            total_score: Overall threat score (0-1)
            components: Individual component scores
            level: Threat level classification
            explanation: Human-readable explanation
            timestamp: When score was computed
        """
        self.event = event
        self.total_score = total_score
        self.components = components
        self.level = level
        self.explanation = explanation
        self.timestamp = timestamp

    def __repr__(self) -> str:
        return (
            f"ThreatScore(level={self.level.value}, "
            f"score={self.total_score:.2f}, "
            f"components={self.components})"
        )


class ThreatRuleEngine:
    """Rule-based threat detection engine."""

    def __init__(self):
        """Initialize rule engine."""
        self.rules = self._load_rules()

    async def evaluate(self, event: dict[str, Any]) -> float:
        """Evaluate event against threat rules.

        Args:
            event: Event to evaluate

        Returns:
            Rule-based threat score (0-1)
        """
        scores = []

        # Apply each rule
        for rule in self.rules:
            if rule["condition"](event):
                scores.append(rule["score"])
                logger.debug(f"Rule '{rule['name']}' triggered: {rule['description']}")

        # Return maximum score (most severe)
        return max(scores) if scores else 0.0

    def _load_rules(self) -> list[dict[str, Any]]:
        """Load threat detection rules.

        Returns:
            List of threat rules
        """
        return [
            # High-risk operations
            {
                "name": "privileged_operation",
                "description": "Operation requires elevated privileges",
                "condition": lambda e: e.get("tool_name")
                in [
                    "shell_execute",
                    "code_execution",
                    "file_delete",
                ],
                "score": 0.7,
            },
            # Multiple failures
            {
                "name": "repeated_failures",
                "description": "Multiple consecutive failures",
                "condition": lambda e: (
                    not e.get("success", True) and e.get("failure_count", 0) >= 3
                ),
                "score": 0.8,
            },
            # Unusual timing
            {
                "name": "after_hours_activity",
                "description": "Activity outside business hours",
                "condition": lambda e: (
                    e.get("timestamp", datetime.now()).hour < 6
                    or e.get("timestamp", datetime.now()).hour > 22
                ),
                "score": 0.4,
            },
            # Suspicious destinations
            {
                "name": "suspicious_domain",
                "description": "Connection to suspicious domain",
                "condition": lambda e: self._is_suspicious_domain(e.get("destination_domain", "")),
                "score": 0.9,
            },
            # Large data transfer
            {
                "name": "large_data_transfer",
                "description": "Unusually large data transfer",
                "condition": lambda e: e.get("bytes_sent", 0) > 100_000_000,  # 100MB
                "score": 0.6,
            },
            # Credential access
            {
                "name": "credential_access",
                "description": "Access to credentials or secrets",
                "condition": lambda e: e.get("event_type")
                in [
                    "secret_access",
                    "vault_read",
                ],
                "score": 0.5,
            },
            # Network policy violation
            {
                "name": "network_violation",
                "description": "Network policy violation detected",
                "condition": lambda e: e.get("network_violation", False),
                "score": 0.8,
            },
            # Browser automation
            {
                "name": "browser_automation",
                "description": "Browser automation detected",
                "condition": lambda e: e.get("tool_name") == "browser",
                "score": 0.3,
            },
        ]

    def _is_suspicious_domain(self, domain: str) -> bool:
        """Check if domain is suspicious.

        Args:
            domain: Domain name

        Returns:
            True if suspicious
        """
        if not domain:
            return False

        suspicious_tlds = [".xyz", ".tk", ".ml", ".ga", ".cf"]
        suspicious_keywords = ["pastebin", "temp", "anonymous", "leak"]

        # Check TLD
        for tld in suspicious_tlds:
            if domain.endswith(tld):
                return True

        # Check keywords
        return any(keyword in domain.lower() for keyword in suspicious_keywords)


class ThreatScorer:
    """Real-time threat scoring engine.

    Combines multiple threat detection methods:
    - ML-based anomaly detection (40% weight)
    - Rule-based scoring (30% weight)
    - Threat intelligence (30% weight)
    """

    def __init__(
        self,
        anomaly_detector: AnomalyDetector | None = None,
        audit_logger: AuditLogger | None = None,
    ):
        """Initialize threat scorer.

        Args:
            anomaly_detector: Anomaly detector instance
            audit_logger: Audit logger for threat alerts
        """
        self.anomaly_detector = anomaly_detector or AnomalyDetector()
        self.rule_engine = ThreatRuleEngine()
        self.audit_logger = audit_logger

        # Scoring weights
        self.weights = {
            "anomaly": 0.4,  # 40%
            "rules": 0.3,  # 30%
            "intel": 0.3,  # 30%
        }

    async def score_event(self, agent_id: str, event: dict[str, Any]) -> ThreatScore:
        """Score threat level of an event.

        Args:
            agent_id: Agent identifier
            event: Event to score

        Returns:
            Threat score with classification
        """
        scores = {}
        explanations = []

        # 1. ML anomaly score (0-1)
        anomaly_result = self.anomaly_detector.detect(agent_id, event)
        anomaly_score = anomaly_result.anomaly_score
        scores["anomaly"] = anomaly_score

        if anomaly_result.is_anomaly:
            explanations.append(f"Anomaly detected (score: {anomaly_score:.2f})")
            if anomaly_result.explanation:
                explanations.append(anomaly_result.explanation)

        # 2. Rule-based score (0-1)
        rule_score = await self.rule_engine.evaluate(event)
        scores["rules"] = rule_score

        if rule_score > 0.5:
            explanations.append(f"Rule-based threat detected (score: {rule_score:.2f})")

        # 3. Threat intel score (0-1)
        # For now, placeholder - will be implemented in Task 5.1.4
        intel_score = 0.0
        scores["intel"] = intel_score

        # Calculate weighted total score
        total_score = sum(scores[component] * self.weights[component] for component in scores)

        # Classify threat level
        level = self._score_to_level(total_score)

        # Generate explanation
        explanation = self._generate_explanation(total_score, scores, explanations, level)

        # Create threat score
        threat_score = ThreatScore(
            event=event,
            total_score=total_score,
            components=scores,
            level=level,
            explanation=explanation,
            timestamp=datetime.now(),
        )

        # Log high/critical threats
        if level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]:
            await self._log_threat(agent_id, threat_score)

        return threat_score

    def _score_to_level(self, score: float) -> ThreatLevel:
        """Convert score to threat level.

        Args:
            score: Threat score (0-1)

        Returns:
            Threat level classification
        """
        if score >= 0.8:
            return ThreatLevel.CRITICAL
        elif score >= 0.6:
            return ThreatLevel.HIGH
        elif score >= 0.4:
            return ThreatLevel.MEDIUM
        elif score >= 0.2:
            return ThreatLevel.LOW
        else:
            return ThreatLevel.NONE

    def _generate_explanation(
        self,
        total_score: float,
        component_scores: dict[str, float],
        explanations: list[str],
        level: ThreatLevel,
    ) -> str:
        """Generate human-readable explanation.

        Args:
            total_score: Overall score
            component_scores: Individual component scores
            explanations: List of explanation fragments
            level: Threat level

        Returns:
            Explanation string
        """
        # Format: "Threat Level: HIGH (score: 0.75)"
        parts = [f"Threat Level: {level.value.upper()} (score: {total_score:.2f})"]

        # Add component breakdown
        component_parts = []
        for name, score in component_scores.items():
            if score > 0.1:  # Only include significant scores
                component_parts.append(f"{name}={score:.2f}")

        if component_parts:
            parts.append(f"Components: {', '.join(component_parts)}")

        # Add specific explanations
        if explanations:
            parts.append("Reasons: " + "; ".join(explanations))

        return " | ".join(parts)

    async def _log_threat(self, agent_id: str, threat_score: ThreatScore) -> None:
        """Log threat alert to audit system.

        Args:
            agent_id: Agent identifier
            threat_score: Threat score result
        """
        if not self.audit_logger:
            return

        try:
            # Log security alert
            event_type = threat_score.event.get("event_type", "unknown")
            tool_name = threat_score.event.get("tool_name")

            logger.warning(
                f"Threat detected for {agent_id}: {threat_score.level.value.upper()} "
                f"(score: {threat_score.total_score:.2f}) - {event_type}"
            )

            # Log to audit system
            # Note: This would integrate with actual audit logger
            # For now, just log to standard logger
            logger.info(
                f"Audit log: agent_id={agent_id}, "
                f"level={threat_score.level.value}, "
                f"score={threat_score.total_score:.2f}, "
                f"event_type={event_type}, "
                f"tool={tool_name}"
            )

        except Exception as e:
            logger.error(f"Failed to log threat: {e}")

    def update_weights(self, weights: dict[str, float]) -> None:
        """Update scoring component weights.

        Args:
            weights: New weights for components

        Raises:
            ValueError: If weights don't sum to 1.0
        """
        if abs(sum(weights.values()) - 1.0) > 0.01:
            raise ValueError("Weights must sum to 1.0")

        self.weights = weights.copy()
        logger.info(f"Updated threat scoring weights: {self.weights}")
