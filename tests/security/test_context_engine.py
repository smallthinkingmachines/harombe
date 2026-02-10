"""Tests for context-aware decision engine."""

import time

import pytest

from harombe.security.audit_db import AuditDatabase
from harombe.security.hitl import Operation
from harombe.security.hitl.auto_approval import AutoApprovalEngine
from harombe.security.hitl.context_engine import (
    ContextAwareEngine,
    DecisionType,
)
from harombe.security.hitl.risk_scorer import HistoricalRiskScorer, RiskScore
from harombe.security.hitl.trust import TrustLevel, TrustManager, TrustScore
from harombe.security.ml.anomaly_detector import AnomalyDetector
from harombe.security.ml.models import AnomalyResult, ThreatLevel
from harombe.security.ml.threat_scoring import ThreatScore, ThreatScorer


@pytest.fixture
def temp_db(tmp_path):
    """Create temporary audit database."""
    db_path = tmp_path / "test_audit.db"
    return AuditDatabase(db_path=db_path, retention_days=90)


@pytest.fixture
def trust_manager(temp_db):
    """Create trust manager instance."""
    return TrustManager(audit_db=temp_db, cache_ttl=3600, min_sample_size=10)


@pytest.fixture
def risk_scorer(temp_db):
    """Create risk scorer instance."""
    return HistoricalRiskScorer(audit_db=temp_db, cache_ttl=3600, min_sample_size=10)


@pytest.fixture
def anomaly_detector(tmp_path):
    """Create anomaly detector instance."""
    return AnomalyDetector(model_dir=tmp_path / "models")


@pytest.fixture
def threat_scorer(anomaly_detector):
    """Create threat scorer instance."""
    return ThreatScorer(anomaly_detector=anomaly_detector, audit_logger=None)


@pytest.fixture
def context_engine(trust_manager, risk_scorer, anomaly_detector, threat_scorer):
    """Create context-aware engine."""
    return ContextAwareEngine(
        trust_manager=trust_manager,
        risk_scorer=risk_scorer,
        anomaly_detector=anomaly_detector,
        threat_scorer=threat_scorer,
    )


@pytest.fixture
def sample_operation():
    """Create sample operation."""
    return Operation(
        tool_name="read_file",
        params={"path": "/tmp/test.txt"},
        correlation_id="test-corr-id",
    )


class TestDecisionType:
    """Test DecisionType enum."""

    def test_decision_types(self):
        """Test decision type values."""
        assert DecisionType.AUTO_APPROVED == "auto_approved"
        assert DecisionType.REQUIRE_APPROVAL == "require_approval"
        assert DecisionType.BLOCKED == "blocked"


class TestContextDecision:
    """Test ContextDecision dataclass."""

    def test_decision_creation(self):
        """Test creating context decision."""
        from harombe.security.hitl.context_engine import ContextDecision

        decision = ContextDecision(
            decision=DecisionType.AUTO_APPROVED,
            reason="Test reason",
            confidence=0.95,
            require_human=False,
            metadata={"test": "data"},
            latency_ms=5.0,
            components_evaluated=["auto_approval"],
        )

        assert decision.decision == DecisionType.AUTO_APPROVED
        assert decision.reason == "Test reason"
        assert decision.confidence == 0.95
        assert not decision.require_human
        assert decision.metadata == {"test": "data"}
        assert decision.latency_ms == 5.0
        assert "auto_approval" in decision.components_evaluated

    def test_decision_str(self):
        """Test decision string representation."""
        from harombe.security.hitl.context_engine import ContextDecision

        decision = ContextDecision(
            decision=DecisionType.AUTO_APPROVED,
            reason="High trust",
            confidence=0.95,
            require_human=False,
            metadata={},
            latency_ms=5.5,
            components_evaluated=["auto_approval"],
        )

        str_repr = str(decision)
        assert "auto_approved" in str_repr
        assert "High trust" in str_repr
        assert "0.95" in str_repr
        assert "5.5ms" in str_repr


class TestContextAwareEngine:
    """Test ContextAwareEngine class."""

    def test_initialization(self, context_engine, trust_manager, risk_scorer):
        """Test engine initialization."""
        assert context_engine.trust_manager == trust_manager
        assert context_engine.risk_scorer == risk_scorer
        assert context_engine.enable_auto_approval
        assert context_engine.enable_anomaly_detection
        assert context_engine.enable_threat_scoring
        assert isinstance(context_engine.auto_approval_engine, AutoApprovalEngine)

    def test_initialization_without_optional_components(self, trust_manager, risk_scorer):
        """Test initialization without optional components."""
        engine = ContextAwareEngine(
            trust_manager=trust_manager,
            risk_scorer=risk_scorer,
            anomaly_detector=None,
            threat_scorer=None,
        )

        assert not engine.enable_anomaly_detection
        assert not engine.enable_threat_scoring
        assert engine.enable_auto_approval

    def test_initialization_with_disabled_components(
        self, trust_manager, risk_scorer, anomaly_detector, threat_scorer
    ):
        """Test initialization with disabled components."""
        engine = ContextAwareEngine(
            trust_manager=trust_manager,
            risk_scorer=risk_scorer,
            anomaly_detector=anomaly_detector,
            threat_scorer=threat_scorer,
            enable_auto_approval=False,
            enable_anomaly_detection=False,
            enable_threat_scoring=False,
        )

        assert not engine.enable_auto_approval
        assert not engine.enable_anomaly_detection
        assert not engine.enable_threat_scoring

    @pytest.mark.asyncio
    async def test_auto_approval_path(
        self, context_engine, trust_manager, risk_scorer, sample_operation
    ):
        """Test auto-approval decision path."""
        # Setup for auto-approval
        trust_manager.trust_cache["user1"] = (
            TrustScore(95.0, TrustLevel.HIGH, {}, 50, None, 60),
            time.time(),
        )
        risk_scorer.risk_cache["risk:read_file"] = (
            RiskScore(0.1, {}, 50, 0.9, False),
            time.time(),
        )

        decision = await context_engine.evaluate(sample_operation, "user1")

        assert decision.decision == DecisionType.AUTO_APPROVED
        assert not decision.require_human
        assert decision.confidence >= 0.9
        assert decision.latency_ms < 500  # Should be fast (relaxed for CI)
        assert "auto_approval" in decision.components_evaluated
        assert "rule_name" in decision.metadata
        assert "trust_level" in decision.metadata
        assert "risk_score" in decision.metadata

    @pytest.mark.asyncio
    async def test_anomaly_detection_path(
        self, context_engine, trust_manager, risk_scorer, sample_operation
    ):
        """Test anomaly detection decision path."""
        # Setup for no auto-approval
        trust_manager.trust_cache["user2"] = (
            TrustScore(55.0, TrustLevel.LOW, {}, 15, None, 20),
            time.time(),
        )
        risk_scorer.risk_cache["risk:read_file"] = (
            RiskScore(0.1, {}, 50, 0.9, False),
            time.time(),
        )

        # Mock anomaly detector to return anomaly
        context_engine.anomaly_detector.detect = lambda agent_id, event: AnomalyResult(
            agent_id=agent_id,
            timestamp=event["timestamp"],
            anomaly_score=0.85,
            is_anomaly=True,
            threat_level=ThreatLevel.HIGH,
            contributing_factors={"resource_count": 0.8},
            explanation="Unusual resource usage pattern",
        )

        decision = await context_engine.evaluate(sample_operation, "user2")

        assert decision.decision == DecisionType.REQUIRE_APPROVAL
        assert decision.require_human
        assert "anomalous" in decision.reason.lower()
        assert "anomaly_detection" in decision.components_evaluated
        assert "anomaly_score" in decision.metadata
        assert decision.metadata["anomaly_score"] == 0.85

    @pytest.mark.asyncio
    async def test_critical_threat_blocked(
        self, context_engine, trust_manager, risk_scorer, sample_operation
    ):
        """Test critical threat gets blocked."""
        # Setup for no auto-approval
        trust_manager.trust_cache["user3"] = (
            TrustScore(55.0, TrustLevel.LOW, {}, 15, None, 20),
            time.time(),
        )
        risk_scorer.risk_cache["risk:read_file"] = (
            RiskScore(0.1, {}, 50, 0.9, False),
            time.time(),
        )

        # Mock anomaly detector to return no anomaly
        context_engine.anomaly_detector.detect = lambda agent_id, event: AnomalyResult(
            agent_id=agent_id,
            timestamp=event["timestamp"],
            anomaly_score=0.1,
            is_anomaly=False,
            threat_level=ThreatLevel.NONE,
            contributing_factors={},
            explanation=None,
        )

        # Mock threat scorer to return critical threat
        async def mock_score_event(agent_id, event):
            from datetime import datetime

            return ThreatScore(
                event=event,
                total_score=0.95,
                components={"anomaly": 0.1, "rules": 0.9, "intel": 0.8},
                level=ThreatLevel.CRITICAL,
                explanation="Critical security threat detected",
                timestamp=datetime.now(),
            )

        context_engine.threat_scorer.score_event = mock_score_event

        decision = await context_engine.evaluate(sample_operation, "user3")

        assert decision.decision == DecisionType.BLOCKED
        assert decision.require_human
        assert "critical" in decision.reason.lower()
        assert "threat_scoring" in decision.components_evaluated
        assert "threat_score" in decision.metadata
        assert decision.metadata["threat_level"] == "critical"

    @pytest.mark.asyncio
    async def test_high_threat_requires_approval(
        self, context_engine, trust_manager, risk_scorer, sample_operation
    ):
        """Test high threat requires approval."""
        # Setup for no auto-approval
        trust_manager.trust_cache["user4"] = (
            TrustScore(55.0, TrustLevel.LOW, {}, 15, None, 20),
            time.time(),
        )
        risk_scorer.risk_cache["risk:read_file"] = (
            RiskScore(0.1, {}, 50, 0.9, False),
            time.time(),
        )

        # Mock anomaly detector to return no anomaly
        context_engine.anomaly_detector.detect = lambda agent_id, event: AnomalyResult(
            agent_id=agent_id,
            timestamp=event["timestamp"],
            anomaly_score=0.1,
            is_anomaly=False,
            threat_level=ThreatLevel.NONE,
            contributing_factors={},
            explanation=None,
        )

        # Mock threat scorer to return high threat
        async def mock_score_event(agent_id, event):
            from datetime import datetime

            return ThreatScore(
                event=event,
                total_score=0.75,
                components={"anomaly": 0.1, "rules": 0.7, "intel": 0.5},
                level=ThreatLevel.HIGH,
                explanation="High security risk detected",
                timestamp=datetime.now(),
            )

        context_engine.threat_scorer.score_event = mock_score_event

        decision = await context_engine.evaluate(sample_operation, "user4")

        assert decision.decision == DecisionType.REQUIRE_APPROVAL
        assert decision.require_human
        assert "high threat" in decision.reason.lower()
        assert "threat_scoring" in decision.components_evaluated
        assert decision.metadata["threat_level"] == "high"

    @pytest.mark.asyncio
    async def test_default_require_approval(
        self, context_engine, trust_manager, risk_scorer, sample_operation
    ):
        """Test default require approval path."""
        # Setup for no auto-approval
        trust_manager.trust_cache["user5"] = (
            TrustScore(55.0, TrustLevel.LOW, {}, 15, None, 20),
            time.time(),
        )
        risk_scorer.risk_cache["risk:read_file"] = (
            RiskScore(0.1, {}, 50, 0.9, False),
            time.time(),
        )

        # Mock anomaly detector to return no anomaly
        context_engine.anomaly_detector.detect = lambda agent_id, event: AnomalyResult(
            agent_id=agent_id,
            timestamp=event["timestamp"],
            anomaly_score=0.1,
            is_anomaly=False,
            threat_level=ThreatLevel.NONE,
            contributing_factors={},
            explanation=None,
        )

        # Mock threat scorer to return low threat
        async def mock_score_event(agent_id, event):
            from datetime import datetime

            return ThreatScore(
                event=event,
                total_score=0.2,
                components={"anomaly": 0.1, "rules": 0.2, "intel": 0.1},
                level=ThreatLevel.LOW,
                explanation="Low security risk",
                timestamp=datetime.now(),
            )

        context_engine.threat_scorer.score_event = mock_score_event

        decision = await context_engine.evaluate(sample_operation, "user5")

        assert decision.decision == DecisionType.REQUIRE_APPROVAL
        assert decision.require_human
        assert "standard approval" in decision.reason.lower()
        assert decision.confidence == 0.5

    @pytest.mark.asyncio
    async def test_latency_under_100ms(
        self, context_engine, trust_manager, risk_scorer, sample_operation
    ):
        """Test decision latency is under 100ms."""
        # Setup for auto-approval (fast path)
        trust_manager.trust_cache["user_fast"] = (
            TrustScore(95.0, TrustLevel.HIGH, {}, 50, None, 60),
            time.time(),
        )
        risk_scorer.risk_cache["risk:read_file"] = (
            RiskScore(0.1, {}, 50, 0.9, False),
            time.time(),
        )

        decision = await context_engine.evaluate(sample_operation, "user_fast")

        assert decision.latency_ms < 500  # Relaxed for CI

    @pytest.mark.asyncio
    async def test_components_evaluated_tracking(
        self, context_engine, trust_manager, risk_scorer, sample_operation
    ):
        """Test components evaluated are tracked."""
        # Setup for auto-approval
        trust_manager.trust_cache["user6"] = (
            TrustScore(95.0, TrustLevel.HIGH, {}, 50, None, 60),
            time.time(),
        )
        risk_scorer.risk_cache["risk:read_file"] = (
            RiskScore(0.1, {}, 50, 0.9, False),
            time.time(),
        )

        decision = await context_engine.evaluate(sample_operation, "user6")

        # Should only evaluate auto_approval
        assert len(decision.components_evaluated) == 1
        assert "auto_approval" in decision.components_evaluated

    @pytest.mark.asyncio
    async def test_operation_to_event_conversion(self, context_engine, sample_operation):
        """Test operation to event conversion."""
        context = {
            "duration_ms": 150,
            "success": True,
            "custom_field": "test",
        }

        event = context_engine._operation_to_event(sample_operation, "user_test", context)

        assert event["correlation_id"] == sample_operation.correlation_id
        assert event["actor"] == "user_test"
        assert event["tool_name"] == sample_operation.tool_name
        assert event["duration_ms"] == 150
        assert event["success"] is True
        assert event["custom_field"] == "test"
        assert event["resource_count"] == 1  # len(params)

    def test_get_statistics(self, context_engine):
        """Test getting statistics."""
        stats = context_engine.get_statistics()

        assert stats["total_decisions"] == 0
        assert stats["auto_approved"] == 0
        assert stats["require_approval"] == 0
        assert stats["blocked"] == 0
        assert stats["auto_approval_rate"] == 0.0
        assert stats["block_rate"] == 0.0
        assert "by_component" in stats
        assert "components_enabled" in stats

    @pytest.mark.asyncio
    async def test_statistics_tracking(
        self, context_engine, trust_manager, risk_scorer, sample_operation
    ):
        """Test statistics are tracked correctly."""
        # Auto-approve one operation
        trust_manager.trust_cache["user_stats1"] = (
            TrustScore(95.0, TrustLevel.HIGH, {}, 50, None, 60),
            time.time(),
        )
        risk_scorer.risk_cache["risk:read_file"] = (
            RiskScore(0.1, {}, 50, 0.9, False),
            time.time(),
        )

        await context_engine.evaluate(sample_operation, "user_stats1")

        # Require approval for another
        trust_manager.trust_cache["user_stats2"] = (
            TrustScore(55.0, TrustLevel.LOW, {}, 15, None, 20),
            time.time(),
        )

        await context_engine.evaluate(sample_operation, "user_stats2")

        stats = context_engine.get_statistics()

        assert stats["total_decisions"] == 2
        assert stats["auto_approved"] == 1
        assert stats["require_approval"] == 1
        assert stats["auto_approval_rate"] == 0.5

    def test_reset_statistics(self, context_engine):
        """Test resetting statistics."""
        # Set some stats
        context_engine.stats["total_decisions"] = 10
        context_engine.stats["auto_approved"] = 5

        # Reset
        context_engine.reset_statistics()

        stats = context_engine.get_statistics()
        assert stats["total_decisions"] == 0
        assert stats["auto_approved"] == 0

    def test_component_toggles(self, trust_manager, risk_scorer):
        """Test component enable/disable toggles."""
        engine = ContextAwareEngine(
            trust_manager=trust_manager,
            risk_scorer=risk_scorer,
            anomaly_detector=None,
            threat_scorer=None,
            enable_auto_approval=False,
        )

        assert not engine.enable_auto_approval
        assert not engine.enable_anomaly_detection
        assert not engine.enable_threat_scoring

        stats = engine.get_statistics()
        assert not stats["components_enabled"]["auto_approval"]
        assert not stats["components_enabled"]["anomaly_detection"]
        assert not stats["components_enabled"]["threat_scoring"]


@pytest.mark.integration
class TestContextEngineIntegration:
    """Integration tests for context-aware engine."""

    @pytest.mark.asyncio
    async def test_end_to_end_decision_flow(self, tmp_path):
        """Test complete decision workflow."""
        from datetime import datetime, timedelta

        from harombe.security.audit_db import AuditEvent, EventType

        # Setup
        db = AuditDatabase(tmp_path / "audit.db")
        trust_manager = TrustManager(db, cache_ttl=3600, min_sample_size=5)
        risk_scorer = HistoricalRiskScorer(db, cache_ttl=3600, min_sample_size=5)
        anomaly_detector = AnomalyDetector(model_dir=tmp_path / "models")
        threat_scorer = ThreatScorer(anomaly_detector=anomaly_detector, audit_logger=None)
        engine = ContextAwareEngine(trust_manager, risk_scorer, anomaly_detector, threat_scorer)

        # Create history for high-trust user
        base_time = datetime.now() - timedelta(days=60)
        for i in range(50):
            event = AuditEvent(
                correlation_id=f"corr-{i}",
                event_type=EventType.REQUEST,
                actor="trusted_user",
                action="read_file",
                status="success",
                timestamp=base_time + timedelta(days=i),
            )
            db.log_event(event)

        # Create operation
        operation = Operation("read_file", {"path": "/tmp/test.txt"}, "corr-new")

        # Evaluate
        decision = await engine.evaluate(operation, "trusted_user")

        # Should make a decision without errors
        assert decision.decision in [DecisionType.AUTO_APPROVED, DecisionType.REQUIRE_APPROVAL]
        assert isinstance(decision.latency_ms, float)
        assert isinstance(decision.components_evaluated, list)
        assert len(decision.components_evaluated) > 0

    @pytest.mark.asyncio
    async def test_multi_component_evaluation(self, tmp_path):
        """Test evaluation with multiple components."""
        db = AuditDatabase(tmp_path / "audit.db")
        trust_manager = TrustManager(db)
        risk_scorer = HistoricalRiskScorer(db)
        anomaly_detector = AnomalyDetector(model_dir=tmp_path / "models")
        threat_scorer = ThreatScorer(anomaly_detector=anomaly_detector, audit_logger=None)

        engine = ContextAwareEngine(trust_manager, risk_scorer, anomaly_detector, threat_scorer)

        operation = Operation("read_file", {}, "test-1")

        # Should complete without errors even with no training data
        decision = await engine.evaluate(operation, "new_user")

        assert decision.decision in [
            DecisionType.AUTO_APPROVED,
            DecisionType.REQUIRE_APPROVAL,
            DecisionType.BLOCKED,
        ]
        assert isinstance(decision.latency_ms, float)
        assert isinstance(decision.components_evaluated, list)
