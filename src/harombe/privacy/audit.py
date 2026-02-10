"""Privacy audit logger for routing decisions.

Wraps the existing AuditLogger to log privacy routing decisions
with appropriate redaction and correlation tracking.
"""

import logging
from typing import Any

from harombe.security.audit_logger import AuditLogger

from .models import PrivacyRoutingDecision, RoutingTarget, SensitivityLevel

logger = logging.getLogger(__name__)


class PrivacyAuditLogger:
    """Logs privacy routing decisions to the audit system."""

    def __init__(self, audit_logger: AuditLogger | None = None) -> None:
        """Initialize privacy audit logger.

        Args:
            audit_logger: Existing AuditLogger instance (creates one if None)
        """
        self._logger = audit_logger

    def log_routing_decision(self, decision: PrivacyRoutingDecision) -> None:
        """Log a routing decision to the audit system.

        Args:
            decision: The routing decision to log
        """
        if self._logger is None:
            logger.debug(
                "Privacy routing: target=%s mode=%s sensitivity=%s sanitized=%s entities=%d",
                decision.target,
                decision.mode,
                decision.sensitivity.level.name,
                decision.was_sanitized,
                decision.sanitized_entity_count,
            )
            return

        metadata: dict[str, Any] = {
            "query_hash": decision.query_hash,
            "sensitivity_level": decision.sensitivity.level.name,
            "target": decision.target.value,
            "mode": decision.mode.value,
            "was_sanitized": decision.was_sanitized,
            "sanitized_entity_count": decision.sanitized_entity_count,
            "reasoning": decision.reasoning,
            "confidence": decision.sensitivity.confidence,
            "entity_types": list({e.type for e in decision.sensitivity.detected_entities}),
        }

        correlation_id = self._logger.start_request(
            actor="privacy_router",
            action="routing_decision",
            metadata=metadata,
        )

        status = "success"
        if (
            decision.target == RoutingTarget.LOCAL
            and decision.sensitivity.level.value >= SensitivityLevel.CONFIDENTIAL.value
        ):
            status = "blocked_cloud"

        self._logger.end_request(
            correlation_id=correlation_id,
            status=status,
        )

    def log_sanitization_stats(
        self,
        entity_count: int,
        entity_types: list[str],
        query_hash: str,
    ) -> None:
        """Log sanitization statistics.

        Args:
            entity_count: Number of entities sanitized
            entity_types: Types of entities sanitized
            query_hash: Hash of the original query
        """
        if self._logger is None:
            logger.debug(
                "Sanitization: %d entities of types %s for query %s",
                entity_count,
                entity_types,
                query_hash,
            )
            return

        self._logger.start_request(
            actor="privacy_router",
            action="sanitization",
            metadata={
                "entity_count": entity_count,
                "entity_types": entity_types,
                "query_hash": query_hash,
            },
        )
