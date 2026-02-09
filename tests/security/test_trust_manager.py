"""Tests for user trust level management."""

import time
from datetime import datetime, timedelta

import pytest

from harombe.security.audit_db import (
    AuditDatabase,
    AuditEvent,
    EventType,
    SecurityDecision,
    SecurityDecisionRecord,
)
from harombe.security.hitl.trust import TrustLevel, TrustManager, TrustScore


@pytest.fixture
def temp_db(tmp_path):
    """Create temporary audit database."""
    db_path = tmp_path / "test_audit.db"
    return AuditDatabase(db_path=db_path, retention_days=90)


@pytest.fixture
def trust_manager(temp_db):
    """Create trust manager instance."""
    return TrustManager(
        audit_db=temp_db,
        cache_ttl=3600,  # 1 hour for tests
        min_sample_size=10,
    )


def create_audit_event(actor: str, event_type: str, status: str = "success", **kwargs):
    """Helper to create audit events."""
    return AuditEvent(
        correlation_id=f"corr-{time.time()}",
        event_type=EventType(event_type),
        actor=actor,
        action="test_action",
        status=status,
        **kwargs,
    )


def create_security_decision_record(actor: str, decision: str, **kwargs):
    """Helper to create security decision records."""
    return SecurityDecisionRecord(
        correlation_id=f"corr-{time.time()}",
        decision_type="hitl",
        decision=SecurityDecision(decision),
        reason="Test decision",
        actor=actor,
        **kwargs,
    )


class TestTrustLevel:
    """Test TrustLevel enum."""

    def test_trust_levels(self):
        """Test trust level values."""
        assert TrustLevel.HIGH == "high"
        assert TrustLevel.MEDIUM == "medium"
        assert TrustLevel.LOW == "low"
        assert TrustLevel.UNTRUSTED == "untrusted"

    def test_trust_level_ordering(self):
        """Test trust levels can be compared."""
        levels = [TrustLevel.HIGH, TrustLevel.MEDIUM, TrustLevel.LOW, TrustLevel.UNTRUSTED]
        assert len(levels) == 4
        assert len(set(levels)) == 4  # All unique


class TestTrustScore:
    """Test TrustScore dataclass."""

    def test_trust_score_creation(self):
        """Test creating trust score."""
        score = TrustScore(
            score=75.0,
            level=TrustLevel.MEDIUM,
            factors={"compliance": 0.9, "approval_success": 0.8, "tenure": 0.5},
            sample_size=100,
            last_updated=datetime.now(),
            days_active=45,
        )

        assert score.score == 75.0
        assert score.level == TrustLevel.MEDIUM
        assert score.factors["compliance"] == 0.9
        assert score.sample_size == 100
        assert score.days_active == 45


class TestTrustManager:
    """Test TrustManager class."""

    def test_initialization(self, trust_manager, temp_db):
        """Test trust manager initialization."""
        assert trust_manager.audit_db == temp_db
        assert trust_manager.cache_ttl == 3600
        assert trust_manager.min_sample_size == 10
        assert len(trust_manager.trust_cache) == 0

    @pytest.mark.asyncio
    async def test_new_user_neutral_score(self, trust_manager):
        """Test new user gets neutral score."""
        score = await trust_manager.get_trust_score("new_user")

        assert score.score == 50.0
        assert score.level == TrustLevel.LOW
        assert score.sample_size == 0
        assert score.days_active == 0

    @pytest.mark.asyncio
    async def test_insufficient_samples(self, trust_manager, temp_db):
        """Test user with insufficient samples."""
        # Add 5 events (below min_sample_size of 10)
        for _ in range(5):
            event = create_audit_event("test_user", "request")
            temp_db.log_event(event)

        score = await trust_manager.get_trust_score("test_user")

        assert score.score == 50.0
        assert score.level == TrustLevel.LOW
        assert score.sample_size == 5

    @pytest.mark.asyncio
    async def test_perfect_user_high_trust(self, trust_manager, temp_db):
        """Test user with perfect record gets HIGH trust."""
        # Add 100 successful events over 90 days
        base_time = datetime.now() - timedelta(days=90)

        for i in range(100):
            event = create_audit_event(
                "perfect_user",
                "request",
                status="success",
                timestamp=base_time + timedelta(days=i % 90),
            )
            temp_db.log_event(event)

        score = await trust_manager.get_trust_score("perfect_user")

        # Perfect compliance (100%), no denials (100%), 90+ days tenure (~100%)
        # Score = 0.4*1.0 + 0.3*1.0 + 0.3*~1.0 ≈ 99-100
        assert score.score >= 99.0
        assert score.level == TrustLevel.HIGH
        assert score.factors["compliance"] == 1.0
        assert score.factors["approval_success"] == 1.0
        assert score.factors["tenure"] >= 0.98  # ~89-90 days
        assert score.days_active >= 89

    @pytest.mark.asyncio
    async def test_user_with_violations_lower_trust(self, trust_manager, temp_db):
        """Test user with violations gets lower trust."""
        # Add 20 events: 15 successes, 5 errors (25% violation rate)
        for i in range(20):
            status = "error" if i < 5 else "success"
            event = create_audit_event("violator", "request", status=status)
            temp_db.log_event(event)

        score = await trust_manager.get_trust_score("violator")

        # Compliance = 75% (15/20), approval_success = 100%, tenure = 0%
        # Score = 0.4*0.75 + 0.3*1.0 + 0.3*0.0 = 0.6 * 100 = 60
        assert score.factors["compliance"] == 0.75
        assert abs(score.score - 60.0) < 0.01  # Floating point tolerance
        assert score.level == TrustLevel.LOW

    @pytest.mark.asyncio
    async def test_user_with_denials_medium_trust(self, trust_manager, temp_db):
        """Test user with some denials."""
        # Add events
        for _ in range(20):
            event = create_audit_event("denied_user", "request", status="success")
            temp_db.log_event(event)

        # Add security decisions: 3 denials, 7 allows (70% approval)
        for i in range(10):
            decision = create_security_decision_record("denied_user", "deny" if i < 3 else "allow")
            temp_db.log_security_decision(decision)

        score = await trust_manager.get_trust_score("denied_user")

        # Compliance = 100%, approval_success = 70%, tenure = 0%
        # Score = 0.4*1.0 + 0.3*0.7 + 0.3*0.0 = 0.61 * 100 = 61
        assert score.factors["compliance"] == 1.0
        assert score.factors["approval_success"] == 0.7
        assert 60 <= score.score <= 62
        assert score.level == TrustLevel.LOW

    @pytest.mark.asyncio
    async def test_tenure_factor(self, trust_manager, temp_db):
        """Test tenure affects trust score."""
        # Add 20 events over 45 days (half of 90 days max)
        base_time = datetime.now() - timedelta(days=45)

        for i in range(20):
            event = create_audit_event(
                "mid_tenure",
                "request",
                status="success",
                timestamp=base_time + timedelta(days=i * 2),
            )
            temp_db.log_event(event)

        score = await trust_manager.get_trust_score("mid_tenure")

        # Tenure should be ~0.5 (45 days / 90 days)
        assert 0.4 <= score.factors["tenure"] <= 0.6
        assert score.days_active >= 38  # ~40 days (20 events * 2 days apart)

    @pytest.mark.asyncio
    async def test_caching_behavior(self, trust_manager, temp_db):
        """Test trust score caching."""
        # Add events
        for _ in range(20):
            event = create_audit_event("cached_user", "request")
            temp_db.log_event(event)

        # First call - compute and cache
        score1 = await trust_manager.get_trust_score("cached_user")
        assert "cached_user" in trust_manager.trust_cache

        # Second call - use cache (should be instant)
        start = time.time()
        score2 = await trust_manager.get_trust_score("cached_user")
        elapsed = time.time() - start

        assert elapsed < 0.001  # <1ms for cache hit
        assert score1.score == score2.score
        assert score1.level == score2.level

    @pytest.mark.asyncio
    async def test_cache_expiration(self, trust_manager, temp_db):
        """Test cache expiration."""
        # Set very short TTL
        trust_manager.cache_ttl = 1  # 1 second

        # Add events
        for _ in range(20):
            event = create_audit_event("expiry_user", "request")
            temp_db.log_event(event)

        # First call
        score1 = await trust_manager.get_trust_score("expiry_user")

        # Wait for cache to expire
        time.sleep(1.1)

        # Should recompute
        score2 = await trust_manager.get_trust_score("expiry_user")

        # Scores should be same (same data)
        assert score1.score == score2.score

    @pytest.mark.asyncio
    async def test_get_trust_level_shortcut(self, trust_manager, temp_db):
        """Test getting just the trust level."""
        # Add events for high trust user
        base_time = datetime.now() - timedelta(days=100)
        for i in range(50):
            event = create_audit_event(
                "level_user",
                "request",
                timestamp=base_time + timedelta(days=i * 2),
            )
            temp_db.log_event(event)

        level = await trust_manager.get_trust_level("level_user")

        assert level == TrustLevel.HIGH

    def test_clear_cache_specific_user(self, trust_manager):
        """Test clearing cache for specific user."""
        # Manually add cache entries
        import time

        trust_manager.trust_cache["user1"] = (
            TrustScore(75.0, TrustLevel.MEDIUM, {}, 20, datetime.now(), 30),
            time.time(),
        )
        trust_manager.trust_cache["user2"] = (
            TrustScore(90.0, TrustLevel.HIGH, {}, 50, datetime.now(), 60),
            time.time(),
        )

        # Clear only user1
        trust_manager.clear_cache("user1")

        assert "user1" not in trust_manager.trust_cache
        assert "user2" in trust_manager.trust_cache

    def test_clear_cache_all(self, trust_manager):
        """Test clearing all cache."""
        import time

        # Add cache entries
        trust_manager.trust_cache["user1"] = (
            TrustScore(75.0, TrustLevel.MEDIUM, {}, 20, datetime.now(), 30),
            time.time(),
        )
        trust_manager.trust_cache["user2"] = (
            TrustScore(90.0, TrustLevel.HIGH, {}, 50, datetime.now(), 60),
            time.time(),
        )

        # Clear all
        trust_manager.clear_cache()

        assert len(trust_manager.trust_cache) == 0

    def test_update_trust_on_event(self, trust_manager):
        """Test cache invalidation on significant events."""
        import time

        # Add cache entry
        trust_manager.trust_cache["risky_user"] = (
            TrustScore(80.0, TrustLevel.HIGH, {}, 30, datetime.now(), 40),
            time.time(),
        )

        # Violation occurs
        trust_manager.update_trust_on_event("risky_user", "violation")

        # Cache should be cleared
        assert "risky_user" not in trust_manager.trust_cache

    def test_update_trust_on_incident(self, trust_manager):
        """Test cache invalidation on security incident."""
        import time

        trust_manager.trust_cache["incident_user"] = (
            TrustScore(75.0, TrustLevel.MEDIUM, {}, 25, datetime.now(), 35),
            time.time(),
        )

        # Security incident occurs
        trust_manager.update_trust_on_event("incident_user", "security_incident")

        # Cache should be cleared
        assert "incident_user" not in trust_manager.trust_cache

    def test_get_trust_statistics(self, trust_manager):
        """Test getting trust statistics."""
        import time

        # Add some cache entries
        trust_manager.trust_cache["high_user"] = (
            TrustScore(95.0, TrustLevel.HIGH, {}, 50, datetime.now(), 100),
            time.time(),
        )
        trust_manager.trust_cache["medium_user"] = (
            TrustScore(75.0, TrustLevel.MEDIUM, {}, 30, datetime.now(), 50),
            time.time(),
        )
        trust_manager.trust_cache["low_user"] = (
            TrustScore(55.0, TrustLevel.LOW, {}, 15, datetime.now(), 20),
            time.time(),
        )

        stats = trust_manager.get_trust_statistics()

        assert stats["cache_size"] == 3
        assert stats["cache_ttl_days"] == 3600 / 86400
        assert stats["min_sample_size"] == 10
        assert stats["trust_distribution"]["high"] == 1
        assert stats["trust_distribution"]["medium"] == 1
        assert stats["trust_distribution"]["low"] == 1
        assert stats["trust_distribution"]["untrusted"] == 0
        assert "high_user" in stats["cached_users"]

    @pytest.mark.asyncio
    async def test_bulk_get_trust_levels(self, trust_manager, temp_db):
        """Test getting trust levels for multiple users."""
        # Add events for multiple users
        for user in ["user1", "user2", "user3"]:
            base_time = datetime.now() - timedelta(days=60)
            for i in range(20):
                event = create_audit_event(
                    user,
                    "request",
                    timestamp=base_time + timedelta(days=i * 3),
                )
                temp_db.log_event(event)

        # Get trust levels in bulk
        levels = await trust_manager.bulk_get_trust_levels(["user1", "user2", "user3"])

        assert len(levels) == 3
        assert levels["user1"] == TrustLevel.MEDIUM
        assert levels["user2"] == TrustLevel.MEDIUM
        assert levels["user3"] == TrustLevel.MEDIUM

    @pytest.mark.asyncio
    async def test_trust_level_thresholds(self, trust_manager, temp_db):
        """Test trust level threshold boundaries."""
        # Test HIGH threshold (90+)
        base_time = datetime.now() - timedelta(days=100)
        for i in range(50):
            event = create_audit_event(
                "high_trust",
                "request",
                timestamp=base_time + timedelta(days=i * 2),
            )
            temp_db.log_event(event)

        high_score = await trust_manager.get_trust_score("high_trust")
        assert high_score.score >= 90
        assert high_score.level == TrustLevel.HIGH

    @pytest.mark.asyncio
    async def test_untrusted_user(self, trust_manager, temp_db):
        """Test user with very poor record gets UNTRUSTED."""
        # Add 20 events: 10 errors (50% violation rate)
        for i in range(20):
            status = "error" if i < 10 else "success"
            event = create_audit_event("bad_user", "request", status=status)
            temp_db.log_event(event)

        # Add denials: 8 out of 10
        for i in range(10):
            decision = create_security_decision_record("bad_user", "deny" if i < 8 else "allow")
            temp_db.log_security_decision(decision)

        score = await trust_manager.get_trust_score("bad_user")

        # Compliance = 50%, approval_success = 20%, tenure = 0%
        # Score = 0.4*0.5 + 0.3*0.2 + 0.3*0.0 = 0.26 * 100 = 26
        assert score.score < 50
        assert score.level == TrustLevel.UNTRUSTED


@pytest.mark.integration
class TestTrustManagerIntegration:
    """Integration tests for trust manager."""

    @pytest.mark.asyncio
    async def test_end_to_end_trust_workflow(self, tmp_path):
        """Test complete trust management workflow."""
        # Create database and manager
        db = AuditDatabase(db_path=tmp_path / "audit.db")
        manager = TrustManager(db, cache_ttl=3600, min_sample_size=5)

        # Simulate user activity over time
        base_time = datetime.now() - timedelta(days=120)

        # User 1: Exemplary user
        for i in range(100):
            event = create_audit_event(
                "exemplary",
                "request",
                status="success",
                timestamp=base_time + timedelta(days=i),
            )
            db.log_event(event)

        # User 2: Occasional violations
        for i in range(100):
            status = "error" if i % 10 == 0 else "success"  # 10% errors
            event = create_audit_event(
                "occasional",
                "request",
                status=status,
                timestamp=base_time + timedelta(days=i),
            )
            db.log_event(event)

        # User 3: New user
        for _ in range(3):
            event = create_audit_event("newbie", "request")
            db.log_event(event)

        # Get trust scores
        exemplary_score = await manager.get_trust_score("exemplary")
        occasional_score = await manager.get_trust_score("occasional")
        newbie_score = await manager.get_trust_score("newbie")

        # Verify results
        assert exemplary_score.level == TrustLevel.HIGH
        assert exemplary_score.score >= 90
        assert exemplary_score.days_active >= 99

        assert occasional_score.level in [TrustLevel.MEDIUM, TrustLevel.HIGH]
        assert occasional_score.score >= 70

        assert newbie_score.level == TrustLevel.LOW
        assert newbie_score.score == 50.0  # Neutral

        # Verify caching
        stats = manager.get_trust_statistics()
        assert stats["cache_size"] == 3

    @pytest.mark.asyncio
    async def test_trust_degradation_on_violations(self, tmp_path):
        """Test trust degrades with violations."""
        db = AuditDatabase(db_path=tmp_path / "audit.db")
        manager = TrustManager(db, cache_ttl=1, min_sample_size=5)

        # User starts with good behavior
        base_time = datetime.now() - timedelta(days=60)
        for i in range(50):
            event = create_audit_event(
                "degrading",
                "request",
                status="success",
                timestamp=base_time + timedelta(days=i),
            )
            db.log_event(event)

        # Get initial trust
        score1 = await manager.get_trust_score("degrading")
        assert score1.level in [TrustLevel.HIGH, TrustLevel.MEDIUM]

        # Wait for cache to expire
        time.sleep(1.1)

        # Add violations
        for _ in range(25):
            event = create_audit_event("degrading", "request", status="error")
            db.log_event(event)

        # Get updated trust
        manager.clear_cache("degrading")
        score2 = await manager.get_trust_score("degrading")

        # Trust should have degraded
        assert score2.score < score1.score
        assert score2.factors["compliance"] < score1.factors["compliance"]
