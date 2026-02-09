"""Tests for historical risk scoring."""

import time

import pytest

from harombe.security.audit_db import (
    AuditDatabase,
    SecurityDecisionRecord,
    ToolCallRecord,
)
from harombe.security.hitl import Operation
from harombe.security.hitl.risk_scorer import HistoricalRiskScorer, RiskScore


@pytest.fixture
def temp_db(tmp_path):
    """Create temporary audit database."""
    db_path = tmp_path / "test_audit.db"
    return AuditDatabase(db_path=db_path, retention_days=90)


@pytest.fixture
def risk_scorer(temp_db):
    """Create risk scorer instance."""
    return HistoricalRiskScorer(
        audit_db=temp_db,
        cache_ttl=3600,  # 1 hour for tests
        min_sample_size=10,
    )


@pytest.fixture
def sample_operation():
    """Create sample operation."""
    return Operation(
        tool_name="test_tool",
        params={"param1": "value1"},
        correlation_id="test-correlation-id",
        session_id="test-session-id",
    )


def create_tool_call(correlation_id: str, tool_name: str, result=None, error=None, duration_ms=100):
    """Helper to create tool call records."""
    return ToolCallRecord(
        correlation_id=correlation_id,
        tool_name=tool_name,
        method="test_method",
        parameters={"test": "param"},
        result=result if result is not None else {"success": True},
        error=error,
        duration_ms=duration_ms,
    )


def create_security_decision(
    correlation_id: str, tool_name: str, decision: str, actor="test_agent"
):
    """Helper to create security decision records."""
    return SecurityDecisionRecord(
        correlation_id=correlation_id,
        decision_type="hitl",
        decision=decision,
        reason="Test decision",
        actor=actor,
        context={"tool_name": tool_name},
        tool_name=tool_name,
    )


class TestRiskScore:
    """Test RiskScore dataclass."""

    def test_risk_score_creation(self):
        """Test creating risk score."""
        score = RiskScore(
            score=0.5,
            factors={"failure_rate": 0.2, "denial_rate": 0.3, "incident_rate": 0.1},
            sample_size=100,
            confidence=0.9,
        )

        assert score.score == 0.5
        assert score.factors["failure_rate"] == 0.2
        assert score.sample_size == 100
        assert score.confidence == 0.9
        assert not score.cached

    def test_risk_score_cached_flag(self):
        """Test cached flag."""
        score = RiskScore(
            score=0.5,
            factors={},
            sample_size=10,
            confidence=0.5,
            cached=True,
        )

        assert score.cached


class TestHistoricalRiskScorer:
    """Test HistoricalRiskScorer class."""

    def test_initialization(self, risk_scorer, temp_db):
        """Test risk scorer initialization."""
        assert risk_scorer.audit_db == temp_db
        assert risk_scorer.cache_ttl == 3600
        assert risk_scorer.min_sample_size == 10
        assert len(risk_scorer.risk_cache) == 0

    @pytest.mark.asyncio
    async def test_score_with_no_history(self, risk_scorer, sample_operation):
        """Test scoring operation with no historical data."""
        score = await risk_scorer.score_operation(sample_operation)

        # Should return neutral score with low confidence
        assert score.score == 0.5
        assert score.sample_size == 0
        assert score.confidence == 0.3
        assert not score.cached

    @pytest.mark.asyncio
    async def test_score_with_insufficient_samples(self, risk_scorer, sample_operation, temp_db):
        """Test scoring with insufficient sample size."""
        # Add 5 tool calls (below min_sample_size of 10)
        for i in range(5):
            temp_db.log_tool_call(create_tool_call(f"corr-{i}", "test_tool"))

        score = await risk_scorer.score_operation(sample_operation)

        # Should return neutral score with low confidence
        assert score.score == 0.5
        assert score.sample_size == 5
        assert score.confidence == 0.3

    @pytest.mark.asyncio
    async def test_score_with_all_successes(self, risk_scorer, sample_operation, temp_db):
        """Test scoring with all successful operations."""
        # Add 20 successful tool calls
        for i in range(20):
            temp_db.log_tool_call(create_tool_call(f"corr-{i}", "test_tool"))

        score = await risk_scorer.score_operation(sample_operation)

        # All successes = low risk
        assert score.score == 0.0
        assert score.factors["failure_rate"] == 0.0
        assert score.factors["denial_rate"] == 0.0
        assert score.factors["incident_rate"] == 0.0
        assert score.sample_size == 20
        assert score.confidence == 0.2  # 20/100

    @pytest.mark.asyncio
    async def test_score_with_failures(self, risk_scorer, sample_operation, temp_db):
        """Test scoring with operation failures."""
        # Add 10 successful and 10 failed operations
        for i in range(10):
            temp_db.log_tool_call(create_tool_call(f"corr-success-{i}", "test_tool"))

        for i in range(10):
            temp_db.log_tool_call(
                create_tool_call(f"corr-fail-{i}", "test_tool", error="Test error")
            )

        score = await risk_scorer.score_operation(sample_operation)

        # 50% failure rate * 0.3 weight = 0.15
        assert score.factors["failure_rate"] == 0.5
        assert score.score >= 0.1  # At least failure contribution
        assert score.sample_size == 20

    @pytest.mark.asyncio
    async def test_score_with_denials(self, risk_scorer, sample_operation, temp_db):
        """Test scoring with security denials."""
        # Add tool calls
        for i in range(20):
            temp_db.log_tool_call(create_tool_call(f"corr-{i}", "test_tool"))

        # Add security decisions with 50% denials
        for i in range(10):
            temp_db.log_security_decision(
                create_security_decision(
                    f"corr-{i}", "test_tool", "deny" if i % 2 == 0 else "allow"
                )
            )

        score = await risk_scorer.score_operation(sample_operation)

        # 50% denial rate * 0.4 weight = 0.20
        assert score.factors["denial_rate"] == 0.5
        assert score.score >= 0.2  # At least denial contribution

    @pytest.mark.asyncio
    async def test_score_with_security_incidents(self, risk_scorer, sample_operation, temp_db):
        """Test scoring with security-related errors."""
        # Add operations with security errors
        for i in range(20):
            if i < 5:
                # 5 security incidents
                temp_db.log_tool_call(
                    create_tool_call(f"corr-{i}", "test_tool", error="Security violation detected")
                )
            else:
                # 15 normal operations
                temp_db.log_tool_call(create_tool_call(f"corr-{i}", "test_tool"))

        score = await risk_scorer.score_operation(sample_operation)

        # 25% incident rate * 0.3 weight = 0.075
        # 25% failure rate * 0.3 weight = 0.075
        # Total ~= 0.15
        assert score.factors["incident_rate"] == 0.25
        assert score.factors["failure_rate"] == 0.25
        assert score.score >= 0.1

    @pytest.mark.asyncio
    async def test_weighted_score_calculation(self, risk_scorer, sample_operation, temp_db):
        """Test weighted risk score calculation."""
        # Create specific failure pattern
        # 20% failures, 40% denials, 10% incidents

        # 100 tool calls: 20 failures (2 with security errors)
        for i in range(100):
            error = None
            if i < 20:
                error = "Security error" if i < 2 else "Normal error"

            temp_db.log_tool_call(create_tool_call(f"corr-{i}", "test_tool", error=error))

        # 50 decisions: 20 denials (40%)
        for i in range(50):
            temp_db.log_security_decision(
                create_security_decision(f"corr-{i}", "test_tool", "deny" if i < 20 else "allow")
            )

        score = await risk_scorer.score_operation(sample_operation)

        # Expected: 0.2*0.3 + 0.4*0.4 + 0.02*0.3 = 0.06 + 0.16 + 0.006 = 0.226
        assert abs(score.score - 0.226) < 0.01
        assert score.confidence == 1.0  # 100 samples = full confidence

    @pytest.mark.asyncio
    async def test_caching_behavior(self, risk_scorer, sample_operation, temp_db):
        """Test risk score caching."""
        # Add some data
        for i in range(20):
            temp_db.log_tool_call(create_tool_call(f"corr-{i}", "test_tool"))

        # First call - should compute and cache
        score1 = await risk_scorer.score_operation(sample_operation)
        assert not score1.cached

        # Second call - should use cache
        score2 = await risk_scorer.score_operation(sample_operation)
        assert score2.cached
        assert score1.score == score2.score

    @pytest.mark.asyncio
    async def test_cache_expiration(self, risk_scorer, sample_operation, temp_db):
        """Test cache expiration."""
        # Set very short TTL
        risk_scorer.cache_ttl = 1  # 1 second

        # Add data
        for i in range(20):
            temp_db.log_tool_call(create_tool_call(f"corr-{i}", "test_tool"))

        # First call
        score1 = await risk_scorer.score_operation(sample_operation)
        assert not score1.cached

        # Wait for cache to expire
        time.sleep(1.1)

        # Should recompute
        score2 = await risk_scorer.score_operation(sample_operation)
        assert not score2.cached

    @pytest.mark.asyncio
    async def test_performance_under_10ms(self, risk_scorer, sample_operation, temp_db):
        """Test scoring latency is under 10ms (with caching)."""
        # Add historical data
        for i in range(100):
            temp_db.log_tool_call(create_tool_call(f"corr-{i}", "test_tool"))

        # First call to populate cache
        await risk_scorer.score_operation(sample_operation)

        # Measure cached lookup
        start = time.perf_counter()
        await risk_scorer.score_operation(sample_operation)
        elapsed_ms = (time.perf_counter() - start) * 1000

        # Cached lookup should be very fast
        assert elapsed_ms < 10.0

    def test_clear_cache_specific_tool(self, risk_scorer):
        """Test clearing cache for specific tool."""
        # Manually add cache entries
        risk_scorer.risk_cache["risk:tool1"] = (
            RiskScore(0.5, {}, 10, 0.5),
            time.time(),
        )
        risk_scorer.risk_cache["risk:tool2"] = (
            RiskScore(0.3, {}, 20, 0.7),
            time.time(),
        )

        # Clear only tool1
        risk_scorer.clear_cache("tool1")

        assert "risk:tool1" not in risk_scorer.risk_cache
        assert "risk:tool2" in risk_scorer.risk_cache

    def test_clear_cache_all(self, risk_scorer):
        """Test clearing all cache."""
        # Add cache entries
        risk_scorer.risk_cache["risk:tool1"] = (
            RiskScore(0.5, {}, 10, 0.5),
            time.time(),
        )
        risk_scorer.risk_cache["risk:tool2"] = (
            RiskScore(0.3, {}, 20, 0.7),
            time.time(),
        )

        # Clear all
        risk_scorer.clear_cache()

        assert len(risk_scorer.risk_cache) == 0

    def test_get_risk_statistics(self, risk_scorer):
        """Test getting risk statistics."""
        # Add some cache entries
        risk_scorer.risk_cache["risk:tool1"] = (
            RiskScore(0.5, {}, 10, 0.5),
            time.time(),
        )
        risk_scorer.risk_cache["risk:tool2"] = (
            RiskScore(0.3, {}, 20, 0.7),
            time.time(),
        )

        stats = risk_scorer.get_risk_statistics()

        assert stats["cache_size"] == 2
        assert stats["cache_ttl"] == 3600
        assert stats["min_sample_size"] == 10
        assert "tool1" in stats["cached_tools"]
        assert "tool2" in stats["cached_tools"]

    @pytest.mark.asyncio
    async def test_bulk_score_operations(self, risk_scorer, temp_db):
        """Test bulk scoring multiple operations."""
        # Add data for two tools
        for i in range(20):
            temp_db.log_tool_call(create_tool_call(f"corr-tool1-{i}", "tool1"))
            temp_db.log_tool_call(create_tool_call(f"corr-tool2-{i}", "tool2", error="Failed"))

        # Create operations
        ops = [
            Operation("tool1", {}, "corr-1"),
            Operation("tool1", {}, "corr-2"),
            Operation("tool2", {}, "corr-3"),
        ]

        # Bulk score
        results = await risk_scorer.bulk_score_operations(ops)

        assert "tool1" in results
        assert "tool2" in results
        assert results["tool1"].score == 0.0  # All successes
        assert results["tool2"].score > 0.0  # All failures

    def test_update_cache_on_incident(self, risk_scorer):
        """Test cache invalidation on incident."""
        # Add cache entry
        risk_scorer.risk_cache["risk:dangerous_tool"] = (
            RiskScore(0.2, {}, 50, 0.9),
            time.time(),
        )

        # Incident occurs
        risk_scorer.update_cache_on_incident("dangerous_tool")

        # Cache should be cleared
        assert "risk:dangerous_tool" not in risk_scorer.risk_cache

    @pytest.mark.asyncio
    async def test_different_tools_separate_scores(self, risk_scorer, temp_db):
        """Test that different tools get separate scores."""
        # Add data for two different tools
        for i in range(20):
            temp_db.log_tool_call(create_tool_call(f"corr-safe-{i}", "safe_tool"))

        for i in range(20):
            temp_db.log_tool_call(create_tool_call(f"corr-risky-{i}", "risky_tool", error="Failed"))

        # Score both
        safe_op = Operation("safe_tool", {}, "corr-1")
        risky_op = Operation("risky_tool", {}, "corr-2")

        safe_score = await risk_scorer.score_operation(safe_op)
        risky_score = await risk_scorer.score_operation(risky_op)

        # Safe tool should have lower risk
        assert safe_score.score < risky_score.score
        assert safe_score.score == 0.0
        assert risky_score.score > 0.2  # 100% failure * 0.3 weight = 0.3

    @pytest.mark.asyncio
    async def test_confidence_scales_with_sample_size(self, risk_scorer, temp_db):
        """Test that confidence increases with sample size."""
        # Add varying amounts of data
        for i in range(150):
            temp_db.log_tool_call(create_tool_call(f"corr-{i}", "test_tool"))

        op = Operation("test_tool", {}, "corr-1")
        score = await risk_scorer.score_operation(op)

        # 150 samples should give full confidence (capped at 1.0)
        assert score.sample_size == 150
        assert score.confidence == 1.0


@pytest.mark.integration
class TestRiskScorerIntegration:
    """Integration tests for risk scorer."""

    @pytest.mark.asyncio
    async def test_end_to_end_risk_scoring(self, tmp_path):
        """Test complete risk scoring workflow."""
        # Create database
        db = AuditDatabase(db_path=tmp_path / "audit.db")

        # Create scorer
        scorer = HistoricalRiskScorer(db, cache_ttl=3600, min_sample_size=5)

        # Simulate operations over time
        for day in range(7):
            for hour in range(24):
                # Safe operations
                for i in range(10):
                    db.log_tool_call(
                        ToolCallRecord(
                            correlation_id=f"safe-day{day}-hour{hour}-{i}",
                            tool_name="read_file",
                            method="read",
                            parameters={"path": "/tmp/test.txt"},
                            result={"content": "test"},
                            duration_ms=50,
                        )
                    )

                # Risky operations with failures
                for i in range(10):
                    error = "Permission denied" if i % 3 == 0 else None
                    result = {"deleted": True} if i % 3 != 0 else None
                    db.log_tool_call(
                        ToolCallRecord(
                            correlation_id=f"risky-day{day}-hour{hour}-{i}",
                            tool_name="delete_file",
                            method="delete",
                            parameters={"path": "/tmp/test.txt"},
                            error=error,
                            result=result,
                            duration_ms=100,
                        )
                    )

        # Score both operations
        safe_op = Operation("read_file", {"path": "/tmp/test.txt"}, "test-1")
        risky_op = Operation("delete_file", {"path": "/tmp/test.txt"}, "test-2")

        safe_score = await scorer.score_operation(safe_op)
        risky_score = await scorer.score_operation(risky_op)

        # Verify results
        assert safe_score.score == 0.0  # No failures
        assert risky_score.score > 0.0  # ~33% failure rate
        assert safe_score.confidence == 1.0  # Many samples
        assert risky_score.confidence == 1.0

        # Verify caching
        stats = scorer.get_risk_statistics()
        assert stats["cache_size"] == 2
