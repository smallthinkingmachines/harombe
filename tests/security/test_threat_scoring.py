"""Tests for real-time threat scoring."""

import tempfile
from datetime import datetime
from pathlib import Path

import pytest

from harombe.security.ml.anomaly_detector import AnomalyDetector
from harombe.security.ml.models import ThreatLevel
from harombe.security.ml.threat_scoring import (
    ThreatRuleEngine,
    ThreatScore,
    ThreatScorer,
)


@pytest.fixture
def temp_model_dir():
    """Create temporary directory for models."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def trained_detector(temp_model_dir):
    """Create trained anomaly detector."""
    detector = AnomalyDetector(model_dir=temp_model_dir)

    # Train on normal events
    normal_events = []
    for _ in range(100):
        normal_events.append(
            {
                "timestamp": datetime.now(),
                "event_type": "tool_call",
                "resource_count": 3,
                "duration_ms": 200,
                "success": True,
            }
        )

    detector.train("agent-123", normal_events)
    return detector


@pytest.fixture
def rule_engine():
    """Create rule engine instance."""
    return ThreatRuleEngine()


@pytest.fixture
def threat_scorer(trained_detector):
    """Create threat scorer instance."""
    return ThreatScorer(anomaly_detector=trained_detector)


class TestThreatRuleEngine:
    """Test rule-based threat detection."""

    def test_initialization(self, rule_engine):
        """Test rule engine initialization."""
        assert rule_engine.rules is not None
        assert len(rule_engine.rules) > 0

    @pytest.mark.asyncio
    async def test_no_rules_triggered(self, rule_engine):
        """Test event that triggers no rules."""
        event = {
            "timestamp": datetime.now().replace(hour=14),  # Business hours
            "event_type": "api_call",
            "tool_name": "web_search",
            "success": True,
            "bytes_sent": 1000,
        }

        score = await rule_engine.evaluate(event)
        assert score == 0.0

    @pytest.mark.asyncio
    async def test_privileged_operation_rule(self, rule_engine):
        """Test privileged operation detection."""
        event = {
            "timestamp": datetime.now(),
            "event_type": "tool_call",
            "tool_name": "shell_execute",
            "success": True,
        }

        score = await rule_engine.evaluate(event)
        assert score >= 0.7  # High-risk operation

    @pytest.mark.asyncio
    async def test_repeated_failures_rule(self, rule_engine):
        """Test repeated failures detection."""
        event = {
            "timestamp": datetime.now(),
            "event_type": "api_call",
            "success": False,
            "failure_count": 5,
        }

        score = await rule_engine.evaluate(event)
        assert score >= 0.8  # Very high risk

    @pytest.mark.asyncio
    async def test_after_hours_rule(self, rule_engine):
        """Test after-hours activity detection."""
        event = {
            "timestamp": datetime.now().replace(hour=3),  # 3 AM
            "event_type": "api_call",
            "success": True,
        }

        score = await rule_engine.evaluate(event)
        assert score >= 0.4  # Medium risk

    @pytest.mark.asyncio
    async def test_suspicious_domain_rule(self, rule_engine):
        """Test suspicious domain detection."""
        event = {
            "timestamp": datetime.now(),
            "event_type": "network_request",
            "destination_domain": "malicious.xyz",
            "success": True,
        }

        score = await rule_engine.evaluate(event)
        assert score >= 0.9  # Critical risk

    @pytest.mark.asyncio
    async def test_large_data_transfer_rule(self, rule_engine):
        """Test large data transfer detection."""
        event = {
            "timestamp": datetime.now(),
            "event_type": "network_request",
            "bytes_sent": 150_000_000,  # 150MB
            "success": True,
        }

        score = await rule_engine.evaluate(event)
        assert score >= 0.6  # High risk

    @pytest.mark.asyncio
    async def test_credential_access_rule(self, rule_engine):
        """Test credential access detection."""
        event = {
            "timestamp": datetime.now(),
            "event_type": "secret_access",
            "success": True,
        }

        score = await rule_engine.evaluate(event)
        assert score >= 0.5  # Medium-high risk

    @pytest.mark.asyncio
    async def test_multiple_rules_triggered(self, rule_engine):
        """Test event that triggers multiple rules."""
        event = {
            "timestamp": datetime.now().replace(hour=2),  # After hours
            "event_type": "tool_call",
            "tool_name": "shell_execute",  # Privileged
            "success": True,
        }

        score = await rule_engine.evaluate(event)
        # Should return max score (privileged operation = 0.7)
        assert score >= 0.7

    @pytest.mark.asyncio
    async def test_suspicious_domain_detection(self, rule_engine):
        """Test various suspicious domain patterns."""
        suspicious_domains = [
            "evil.xyz",
            "pastebin.com",
            "anonymous-leak.com",
            "tempfiles.tk",
        ]

        for domain in suspicious_domains:
            assert rule_engine._is_suspicious_domain(domain)

    @pytest.mark.asyncio
    async def test_legitimate_domain_detection(self, rule_engine):
        """Test legitimate domains are not flagged."""
        legitimate_domains = [
            "api.anthropic.com",
            "github.com",
            "stackoverflow.com",
            "google.com",
        ]

        for domain in legitimate_domains:
            assert not rule_engine._is_suspicious_domain(domain)


class TestThreatScore:
    """Test ThreatScore model."""

    def test_threat_score_creation(self):
        """Test creating a threat score."""
        event = {"event_type": "test", "timestamp": datetime.now()}

        score = ThreatScore(
            event=event,
            total_score=0.75,
            components={"anomaly": 0.8, "rules": 0.7, "intel": 0.0},
            level=ThreatLevel.HIGH,
            explanation="Test threat",
            timestamp=datetime.now(),
        )

        assert score.total_score == 0.75
        assert score.level == ThreatLevel.HIGH
        assert "anomaly" in score.components

    def test_threat_score_repr(self):
        """Test ThreatScore string representation."""
        event = {"event_type": "test"}

        score = ThreatScore(
            event=event,
            total_score=0.5,
            components={},
            level=ThreatLevel.MEDIUM,
            explanation="Test",
            timestamp=datetime.now(),
        )

        repr_str = repr(score)
        assert "ThreatScore" in repr_str
        assert "medium" in repr_str  # lowercase in enum value
        assert "0.50" in repr_str


class TestThreatScorer:
    """Test integrated threat scoring."""

    def test_initialization(self, threat_scorer):
        """Test threat scorer initialization."""
        assert threat_scorer.anomaly_detector is not None
        assert threat_scorer.rule_engine is not None
        assert threat_scorer.weights is not None

    def test_default_weights(self, threat_scorer):
        """Test default weight distribution."""
        assert threat_scorer.weights["anomaly"] == 0.4
        assert threat_scorer.weights["rules"] == 0.3
        assert threat_scorer.weights["intel"] == 0.3
        assert sum(threat_scorer.weights.values()) == 1.0

    @pytest.mark.asyncio
    async def test_score_normal_event(self, threat_scorer):
        """Test scoring a normal event."""
        event = {
            "timestamp": datetime.now().replace(hour=14),
            "event_type": "api_call",
            "tool_name": "web_search",
            "resource_count": 3,
            "duration_ms": 200,
            "success": True,
        }

        score = await threat_scorer.score_event("agent-123", event)

        assert isinstance(score, ThreatScore)
        assert 0.0 <= score.total_score <= 1.0
        assert score.level in [ThreatLevel.NONE, ThreatLevel.LOW, ThreatLevel.MEDIUM]
        assert "anomaly" in score.components
        assert "rules" in score.components
        assert "intel" in score.components

    @pytest.mark.asyncio
    async def test_score_high_risk_event(self, threat_scorer):
        """Test scoring a high-risk event."""
        event = {
            "timestamp": datetime.now().replace(hour=3),  # After hours
            "event_type": "tool_call",
            "tool_name": "shell_execute",  # Privileged
            "resource_count": 100,  # Unusual
            "duration_ms": 5000,  # Long
            "success": False,  # Failed
            "failure_count": 5,
        }

        score = await threat_scorer.score_event("agent-123", event)

        assert isinstance(score, ThreatScore)
        assert score.total_score > 0.4  # Should be elevated (relaxed threshold)
        assert score.level in [
            ThreatLevel.MEDIUM,
            ThreatLevel.HIGH,
            ThreatLevel.CRITICAL,
        ]

    @pytest.mark.asyncio
    async def test_score_to_level_mapping(self, threat_scorer):
        """Test threat score to level conversion."""
        assert threat_scorer._score_to_level(0.9) == ThreatLevel.CRITICAL
        assert threat_scorer._score_to_level(0.75) == ThreatLevel.HIGH
        assert threat_scorer._score_to_level(0.5) == ThreatLevel.MEDIUM
        assert threat_scorer._score_to_level(0.3) == ThreatLevel.LOW
        assert threat_scorer._score_to_level(0.1) == ThreatLevel.NONE

    @pytest.mark.asyncio
    async def test_explanation_generation(self, threat_scorer):
        """Test threat explanation generation."""
        event = {
            "timestamp": datetime.now(),
            "event_type": "test",
            "resource_count": 3,
            "duration_ms": 200,
            "success": True,
        }

        score = await threat_scorer.score_event("agent-123", event)

        assert score.explanation is not None
        assert "Threat Level:" in score.explanation
        assert "score:" in score.explanation

    @pytest.mark.asyncio
    async def test_component_scores_present(self, threat_scorer):
        """Test all component scores are calculated."""
        event = {
            "timestamp": datetime.now(),
            "event_type": "test",
            "resource_count": 3,
            "duration_ms": 200,
            "success": True,
        }

        score = await threat_scorer.score_event("agent-123", event)

        assert "anomaly" in score.components
        assert "rules" in score.components
        assert "intel" in score.components
        assert all(0.0 <= s <= 1.0 for s in score.components.values())

    @pytest.mark.asyncio
    async def test_weighted_scoring(self, threat_scorer):
        """Test weighted score calculation."""
        # Create event that triggers rules but not anomaly
        event = {
            "timestamp": datetime.now(),
            "event_type": "tool_call",
            "tool_name": "shell_execute",  # High rule score
            "resource_count": 3,  # Normal
            "duration_ms": 200,  # Normal
            "success": True,
        }

        score = await threat_scorer.score_event("agent-123", event)

        # Rule score should be high (0.7+)
        assert score.components["rules"] >= 0.7

        # Total should be weighted average
        expected = (
            score.components["anomaly"] * 0.4
            + score.components["rules"] * 0.3
            + score.components["intel"] * 0.3
        )
        assert abs(score.total_score - expected) < 0.01

    def test_update_weights(self, threat_scorer):
        """Test updating scoring weights."""
        new_weights = {"anomaly": 0.5, "rules": 0.3, "intel": 0.2}

        threat_scorer.update_weights(new_weights)

        assert threat_scorer.weights == new_weights

    def test_update_weights_invalid_sum(self, threat_scorer):
        """Test updating weights with invalid sum."""
        invalid_weights = {"anomaly": 0.5, "rules": 0.3, "intel": 0.1}  # Sum = 0.9

        with pytest.raises(ValueError, match=r"must sum to 1\.0"):
            threat_scorer.update_weights(invalid_weights)

    @pytest.mark.asyncio
    async def test_no_agent_model(self, temp_model_dir):
        """Test scoring when no agent model exists."""
        detector = AnomalyDetector(model_dir=temp_model_dir)
        scorer = ThreatScorer(anomaly_detector=detector)

        event = {
            "timestamp": datetime.now(),
            "event_type": "test",
            "resource_count": 3,
            "duration_ms": 200,
            "success": True,
        }

        score = await scorer.score_event("unknown-agent", event)

        # Should still work, anomaly score will be 0
        assert isinstance(score, ThreatScore)
        assert score.components["anomaly"] == 0.0


@pytest.mark.integration
class TestThreatScoringIntegration:
    """Integration tests for threat scoring."""

    @pytest.mark.asyncio
    async def test_end_to_end_scoring(self, threat_scorer):
        """Test full threat scoring pipeline."""
        # Normal event
        normal_event = {
            "timestamp": datetime.now().replace(hour=10),
            "event_type": "api_call",
            "tool_name": "web_search",
            "resource_count": 2,
            "duration_ms": 150,
            "success": True,
        }

        normal_score = await threat_scorer.score_event("agent-123", normal_event)
        assert normal_score.level in [ThreatLevel.NONE, ThreatLevel.LOW]

        # Suspicious event
        suspicious_event = {
            "timestamp": datetime.now().replace(hour=3),
            "event_type": "tool_call",
            "tool_name": "code_execution",
            "resource_count": 50,
            "duration_ms": 5000,
            "success": False,
            "failure_count": 3,
            "destination_domain": "suspicious.xyz",
        }

        suspicious_score = await threat_scorer.score_event("agent-123", suspicious_event)
        assert suspicious_score.level in [
            ThreatLevel.MEDIUM,
            ThreatLevel.HIGH,
            ThreatLevel.CRITICAL,
        ]
        assert suspicious_score.total_score > normal_score.total_score

    @pytest.mark.asyncio
    async def test_multiple_agent_scoring(self, threat_scorer):
        """Test scoring events from multiple agents."""
        event = {
            "timestamp": datetime.now(),
            "event_type": "test",
            "resource_count": 3,
            "duration_ms": 200,
            "success": True,
        }

        # Score for different agents
        score1 = await threat_scorer.score_event("agent-1", event)
        score2 = await threat_scorer.score_event("agent-2", event)
        score3 = await threat_scorer.score_event("agent-3", event)

        # All should work independently
        assert isinstance(score1, ThreatScore)
        assert isinstance(score2, ThreatScore)
        assert isinstance(score3, ThreatScore)

    @pytest.mark.asyncio
    async def test_progressive_threat_escalation(self, threat_scorer):
        """Test threat scoring with progressively worse events."""
        base_event = {
            "timestamp": datetime.now().replace(hour=14),
            "event_type": "api_call",
            "resource_count": 3,
            "duration_ms": 200,
            "success": True,
        }

        # Baseline
        score1 = await threat_scorer.score_event("agent-123", base_event)

        # Add after-hours
        event2 = {**base_event, "timestamp": datetime.now().replace(hour=3)}
        score2 = await threat_scorer.score_event("agent-123", event2)

        # Add privileged operation
        event3 = {**event2, "tool_name": "shell_execute"}
        score3 = await threat_scorer.score_event("agent-123", event3)

        # Add failure
        event4 = {**event3, "success": False, "failure_count": 3}
        score4 = await threat_scorer.score_event("agent-123", event4)

        # Scores should progressively increase
        assert score1.total_score <= score2.total_score
        assert score2.total_score <= score3.total_score
        assert score3.total_score <= score4.total_score
