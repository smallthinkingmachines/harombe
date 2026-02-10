"""Tests for the privacy audit logger."""

from unittest.mock import MagicMock

from harombe.privacy.audit import PrivacyAuditLogger
from harombe.privacy.models import (
    PIIEntity,
    PrivacyRoutingDecision,
    RoutingMode,
    RoutingTarget,
    SensitivityLevel,
    SensitivityResult,
)


def _make_decision(
    level=SensitivityLevel.PUBLIC,
    target=RoutingTarget.CLOUD,
    mode=RoutingMode.HYBRID,
    was_sanitized=False,
    entity_count=0,
    entities=None,
):
    return PrivacyRoutingDecision(
        query_hash="abc123",
        sensitivity=SensitivityResult(
            level=level,
            reasons=["test reason"],
            detected_entities=entities or [],
            confidence=0.9,
        ),
        target=target,
        mode=mode,
        was_sanitized=was_sanitized,
        sanitized_entity_count=entity_count,
        reasoning="test reasoning",
    )


class TestPrivacyAuditLogger:
    def test_log_without_audit_logger(self):
        """Should not raise when no audit logger is provided."""
        logger = PrivacyAuditLogger()
        decision = _make_decision()
        logger.log_routing_decision(decision)  # Should not raise

    def test_log_with_audit_logger(self):
        mock_logger = MagicMock()
        mock_logger.start_request.return_value = "corr-123"

        logger = PrivacyAuditLogger(audit_logger=mock_logger)
        decision = _make_decision()
        logger.log_routing_decision(decision)

        mock_logger.start_request.assert_called_once()
        call_kwargs = mock_logger.start_request.call_args.kwargs
        assert call_kwargs["actor"] == "privacy_router"
        assert call_kwargs["action"] == "routing_decision"
        assert call_kwargs["metadata"]["target"] == "cloud"

        mock_logger.end_request.assert_called_once_with(
            correlation_id="corr-123",
            status="success",
        )

    def test_blocked_cloud_status(self):
        mock_logger = MagicMock()
        mock_logger.start_request.return_value = "corr-456"

        logger = PrivacyAuditLogger(audit_logger=mock_logger)
        decision = _make_decision(
            level=SensitivityLevel.CONFIDENTIAL,
            target=RoutingTarget.LOCAL,
        )
        logger.log_routing_decision(decision)

        mock_logger.end_request.assert_called_once_with(
            correlation_id="corr-456",
            status="blocked_cloud",
        )

    def test_log_sanitization_stats_without_logger(self):
        logger = PrivacyAuditLogger()
        logger.log_sanitization_stats(3, ["email", "phone"], "hash123")

    def test_log_sanitization_stats_with_logger(self):
        mock_logger = MagicMock()
        logger = PrivacyAuditLogger(audit_logger=mock_logger)
        logger.log_sanitization_stats(3, ["email", "phone"], "hash123")

        mock_logger.start_request.assert_called_once()
        metadata = mock_logger.start_request.call_args.kwargs["metadata"]
        assert metadata["entity_count"] == 3
        assert "email" in metadata["entity_types"]

    def test_entity_types_in_metadata(self):
        mock_logger = MagicMock()
        mock_logger.start_request.return_value = "corr-789"

        entities = [
            PIIEntity(type="email", value="a@b.com", start=0, end=7, confidence=0.9),
            PIIEntity(type="phone", value="555-1234", start=10, end=18, confidence=0.85),
        ]
        logger = PrivacyAuditLogger(audit_logger=mock_logger)
        decision = _make_decision(
            level=SensitivityLevel.INTERNAL,
            target=RoutingTarget.CLOUD_SANITIZED,
            was_sanitized=True,
            entity_count=2,
            entities=entities,
        )
        logger.log_routing_decision(decision)

        metadata = mock_logger.start_request.call_args.kwargs["metadata"]
        assert "email" in metadata["entity_types"]
        assert "phone" in metadata["entity_types"]
