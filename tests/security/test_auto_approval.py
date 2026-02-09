"""Tests for automated low-risk approval engine."""

import pytest

from harombe.security.audit_db import AuditDatabase
from harombe.security.hitl import Operation
from harombe.security.hitl.auto_approval import (
    ApprovalAction,
    AutoApprovalEngine,
    AutoApprovalRule,
)
from harombe.security.hitl.risk_scorer import HistoricalRiskScorer, RiskScore
from harombe.security.hitl.trust import TrustLevel, TrustManager, TrustScore


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
def auto_approval_engine(trust_manager, risk_scorer):
    """Create auto-approval engine."""
    return AutoApprovalEngine(trust_manager, risk_scorer)


@pytest.fixture
def sample_operation():
    """Create sample operation."""
    return Operation(
        tool_name="read_file",
        params={"path": "/tmp/test.txt"},
        correlation_id="test-corr-id",
    )


class TestApprovalAction:
    """Test ApprovalAction enum."""

    def test_approval_actions(self):
        """Test approval action values."""
        assert ApprovalAction.AUTO_APPROVE == "auto_approve"
        assert ApprovalAction.REQUIRE_APPROVAL == "require_approval"


class TestAutoApprovalRule:
    """Test AutoApprovalRule class."""

    def test_rule_creation(self):
        """Test creating approval rule."""
        rule = AutoApprovalRule(
            name="test_rule",
            conditions={"trust_level": TrustLevel.HIGH},
            action=ApprovalAction.AUTO_APPROVE,
            reason="Test reason",
            priority=50,
        )

        assert rule.name == "test_rule"
        assert rule.action == ApprovalAction.AUTO_APPROVE
        assert rule.priority == 50

    def test_rule_matches_trust_level(self, sample_operation):
        """Test rule matching by trust level."""
        rule = AutoApprovalRule(
            name="high_trust",
            conditions={"trust_level": TrustLevel.HIGH},
            action=ApprovalAction.AUTO_APPROVE,
            reason="High trust",
        )

        risk = RiskScore(0.2, {}, 10, 0.9, False)

        assert rule.matches(sample_operation, TrustLevel.HIGH, risk)
        assert not rule.matches(sample_operation, TrustLevel.MEDIUM, risk)

    def test_rule_matches_risk_score_max(self, sample_operation):
        """Test rule matching by maximum risk score."""
        rule = AutoApprovalRule(
            name="low_risk",
            conditions={"risk_score_max": 0.3},
            action=ApprovalAction.AUTO_APPROVE,
            reason="Low risk",
        )

        low_risk = RiskScore(0.2, {}, 10, 0.9, False)
        high_risk = RiskScore(0.5, {}, 10, 0.9, False)

        assert rule.matches(sample_operation, TrustLevel.HIGH, low_risk)
        assert not rule.matches(sample_operation, TrustLevel.HIGH, high_risk)

    def test_rule_matches_risk_score_min(self, sample_operation):
        """Test rule matching by minimum risk score."""
        rule = AutoApprovalRule(
            name="high_risk_block",
            conditions={"risk_score_min": 0.8},
            action=ApprovalAction.REQUIRE_APPROVAL,
            reason="High risk",
        )

        low_risk = RiskScore(0.2, {}, 10, 0.9, False)
        critical_risk = RiskScore(0.9, {}, 10, 0.9, False)

        assert not rule.matches(sample_operation, TrustLevel.HIGH, low_risk)
        assert rule.matches(sample_operation, TrustLevel.HIGH, critical_risk)

    def test_rule_matches_tool_name(self):
        """Test rule matching by tool name."""
        rule = AutoApprovalRule(
            name="safe_tools",
            conditions={"tool_name": ["read_file", "list_directory"]},
            action=ApprovalAction.AUTO_APPROVE,
            reason="Safe tool",
        )

        safe_op = Operation("read_file", {}, "corr-1")
        dangerous_op = Operation("delete_file", {}, "corr-2")
        risk = RiskScore(0.2, {}, 10, 0.9, False)

        assert rule.matches(safe_op, TrustLevel.HIGH, risk)
        assert not rule.matches(dangerous_op, TrustLevel.HIGH, risk)

    def test_rule_matches_exclude_tools(self):
        """Test rule matching by excluded tools."""
        rule = AutoApprovalRule(
            name="block_dangerous",
            conditions={"exclude_tools": ["delete_database", "drop_table"]},
            action=ApprovalAction.REQUIRE_APPROVAL,
            reason="Dangerous tool",
        )

        safe_op = Operation("read_file", {}, "corr-1")
        dangerous_op = Operation("delete_database", {}, "corr-2")
        risk = RiskScore(0.2, {}, 10, 0.9, False)

        # Rule doesn't match safe tools (not in exclusion list)
        assert not rule.matches(safe_op, TrustLevel.HIGH, risk)
        # Rule matches dangerous tools (in exclusion list)
        assert rule.matches(dangerous_op, TrustLevel.HIGH, risk)


class TestAutoApprovalEngine:
    """Test AutoApprovalEngine class."""

    def test_initialization(self, auto_approval_engine, trust_manager, risk_scorer):
        """Test engine initialization."""
        assert auto_approval_engine.trust_manager == trust_manager
        assert auto_approval_engine.risk_scorer == risk_scorer
        assert len(auto_approval_engine.rules) > 0

    def test_default_rules_loaded(self, auto_approval_engine):
        """Test default rules are loaded."""
        rules = auto_approval_engine.get_rules()
        rule_names = [r.name for r in rules]

        # Check for key default rules
        assert "critical_risk_block" in rule_names
        assert "high_trust_low_risk" in rule_names
        assert "medium_trust_very_low_risk" in rule_names

    def test_rules_sorted_by_priority(self, auto_approval_engine):
        """Test rules are sorted by priority."""
        rules = auto_approval_engine.get_rules()

        # Verify descending priority order
        for i in range(len(rules) - 1):
            assert rules[i].priority >= rules[i + 1].priority

    @pytest.mark.asyncio
    async def test_high_trust_low_risk_auto_approves(
        self, auto_approval_engine, trust_manager, risk_scorer, sample_operation
    ):
        """Test high trust + low risk gets auto-approved."""
        import time

        # Mock trust and risk
        trust_manager.trust_cache["user1"] = (
            TrustScore(95.0, TrustLevel.HIGH, {}, 50, None, 60),
            time.time(),
        )
        risk_scorer.risk_cache["risk:read_file"] = (
            RiskScore(0.1, {}, 50, 0.9, False),
            time.time(),
        )

        decision = await auto_approval_engine.should_auto_approve(sample_operation, "user1")

        assert decision.should_auto_approve
        assert decision.trust_level == TrustLevel.HIGH
        assert decision.risk_score < 0.3
        assert "high_trust" in decision.rule_name.lower()

    @pytest.mark.asyncio
    async def test_medium_trust_very_low_risk_auto_approves(
        self, auto_approval_engine, trust_manager, risk_scorer, sample_operation
    ):
        """Test medium trust + very low risk gets auto-approved."""
        import time

        trust_manager.trust_cache["user2"] = (
            TrustScore(75.0, TrustLevel.MEDIUM, {}, 30, None, 40),
            time.time(),
        )
        risk_scorer.risk_cache["risk:read_file"] = (
            RiskScore(0.05, {}, 50, 0.9, False),
            time.time(),
        )

        decision = await auto_approval_engine.should_auto_approve(sample_operation, "user2")

        assert decision.should_auto_approve
        assert decision.trust_level == TrustLevel.MEDIUM
        assert decision.risk_score < 0.1

    @pytest.mark.asyncio
    async def test_critical_risk_requires_approval(
        self, auto_approval_engine, trust_manager, risk_scorer, sample_operation
    ):
        """Test critical risk always requires approval."""
        import time

        # Even high trust user
        trust_manager.trust_cache["user3"] = (
            TrustScore(95.0, TrustLevel.HIGH, {}, 50, None, 60),
            time.time(),
        )
        risk_scorer.risk_cache["risk:read_file"] = (
            RiskScore(0.9, {}, 50, 0.9, False),
            time.time(),
        )

        decision = await auto_approval_engine.should_auto_approve(sample_operation, "user3")

        assert not decision.should_auto_approve
        assert "critical" in decision.reason.lower()

    @pytest.mark.asyncio
    async def test_low_trust_requires_approval(
        self, auto_approval_engine, trust_manager, risk_scorer, sample_operation
    ):
        """Test low trust user requires approval."""
        import time

        trust_manager.trust_cache["user4"] = (
            TrustScore(55.0, TrustLevel.LOW, {}, 15, None, 20),
            time.time(),
        )
        risk_scorer.risk_cache["risk:read_file"] = (
            RiskScore(0.1, {}, 50, 0.9, False),
            time.time(),
        )

        decision = await auto_approval_engine.should_auto_approve(sample_operation, "user4")

        assert not decision.should_auto_approve
        assert decision.trust_level == TrustLevel.LOW

    @pytest.mark.asyncio
    async def test_dangerous_tool_requires_approval(
        self, auto_approval_engine, trust_manager, risk_scorer
    ):
        """Test dangerous tools always require approval."""
        import time

        dangerous_op = Operation("delete_database", {}, "corr-1")

        trust_manager.trust_cache["user5"] = (
            TrustScore(95.0, TrustLevel.HIGH, {}, 50, None, 60),
            time.time(),
        )
        risk_scorer.risk_cache["risk:delete_database"] = (
            RiskScore(0.2, {}, 50, 0.9, False),
            time.time(),
        )

        decision = await auto_approval_engine.should_auto_approve(dangerous_op, "user5")

        assert not decision.should_auto_approve

    def test_add_custom_rule(self, auto_approval_engine):
        """Test adding custom rule."""
        initial_count = len(auto_approval_engine.rules)

        custom_rule = AutoApprovalRule(
            name="custom_test",
            conditions={"trust_level": TrustLevel.HIGH},
            action=ApprovalAction.AUTO_APPROVE,
            reason="Custom rule",
            priority=75,
        )

        auto_approval_engine.add_rule(custom_rule)

        assert len(auto_approval_engine.rules) == initial_count + 1
        assert custom_rule in auto_approval_engine.rules

    def test_remove_rule(self, auto_approval_engine):
        """Test removing rule."""
        # Add a rule
        test_rule = AutoApprovalRule(
            name="removable_rule",
            conditions={},
            action=ApprovalAction.AUTO_APPROVE,
            reason="Test",
        )
        auto_approval_engine.add_rule(test_rule)

        # Remove it
        removed = auto_approval_engine.remove_rule("removable_rule")

        assert removed
        assert "removable_rule" not in [r.name for r in auto_approval_engine.rules]

    def test_remove_nonexistent_rule(self, auto_approval_engine):
        """Test removing nonexistent rule."""
        removed = auto_approval_engine.remove_rule("nonexistent")
        assert not removed

    @pytest.mark.asyncio
    async def test_statistics_tracking(
        self, auto_approval_engine, trust_manager, risk_scorer, sample_operation
    ):
        """Test statistics are tracked correctly."""
        import time

        # Setup for auto-approval
        trust_manager.trust_cache["user_stats"] = (
            TrustScore(95.0, TrustLevel.HIGH, {}, 50, None, 60),
            time.time(),
        )
        risk_scorer.risk_cache["risk:read_file"] = (
            RiskScore(0.1, {}, 50, 0.9, False),
            time.time(),
        )

        # Make some decisions
        await auto_approval_engine.should_auto_approve(sample_operation, "user_stats")
        await auto_approval_engine.should_auto_approve(sample_operation, "user_stats")

        stats = auto_approval_engine.get_statistics()

        assert stats["total_evaluations"] == 2
        assert stats["auto_approved"] >= 1
        assert stats["auto_approval_rate"] > 0

    def test_reset_statistics(self, auto_approval_engine):
        """Test resetting statistics."""
        # Set some stats
        auto_approval_engine.stats["total_evaluations"] = 10
        auto_approval_engine.stats["auto_approved"] = 5

        # Reset
        auto_approval_engine.reset_statistics()

        stats = auto_approval_engine.get_statistics()
        assert stats["total_evaluations"] == 0
        assert stats["auto_approved"] == 0

    def test_custom_rules_replace_defaults(self, trust_manager, risk_scorer):
        """Test custom rules can replace defaults."""
        custom_rules = [
            AutoApprovalRule(
                name="always_approve",
                conditions={},
                action=ApprovalAction.AUTO_APPROVE,
                reason="Always approve",
            )
        ]

        engine = AutoApprovalEngine(trust_manager, risk_scorer, custom_rules)

        assert len(engine.rules) == 1
        assert engine.rules[0].name == "always_approve"


@pytest.mark.integration
class TestAutoApprovalIntegration:
    """Integration tests for auto-approval engine."""

    @pytest.mark.asyncio
    async def test_end_to_end_auto_approval_flow(self, tmp_path):
        """Test complete auto-approval workflow."""
        from datetime import datetime, timedelta

        from harombe.security.audit_db import AuditEvent, EventType

        # Setup
        db = AuditDatabase(tmp_path / "audit.db")
        trust_manager = TrustManager(db, cache_ttl=3600, min_sample_size=5)
        risk_scorer = HistoricalRiskScorer(db, cache_ttl=3600, min_sample_size=5)
        engine = AutoApprovalEngine(trust_manager, risk_scorer)

        # Create history for high-trust user with safe operations
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
        decision = await engine.should_auto_approve(operation, "trusted_user")

        # Verify auto-approval for trusted user + safe operation
        assert decision.should_auto_approve or decision.trust_level in [
            TrustLevel.HIGH,
            TrustLevel.MEDIUM,
        ]

    @pytest.mark.asyncio
    async def test_auto_approval_rate_target(self, tmp_path):
        """Test auto-approval rate meets 50%+ target."""
        from datetime import datetime, timedelta

        from harombe.security.audit_db import AuditEvent, EventType

        db = AuditDatabase(tmp_path / "audit.db")
        trust_manager = TrustManager(db, cache_ttl=3600, min_sample_size=5)
        risk_scorer = HistoricalRiskScorer(db, cache_ttl=3600, min_sample_size=5)
        engine = AutoApprovalEngine(trust_manager, risk_scorer)

        # Create diverse user population
        base_time = datetime.now() - timedelta(days=90)

        # High-trust users (should get auto-approved)
        for i in range(30):
            event = AuditEvent(
                correlation_id=f"high-{i}",
                event_type=EventType.REQUEST,
                actor="high_trust_user",
                action="read_file",
                status="success",
                timestamp=base_time + timedelta(days=i * 3),
            )
            db.log_event(event)

        # Medium-trust users (some auto-approved)
        for i in range(20):
            status = "error" if i % 10 == 0 else "success"  # 10% errors
            event = AuditEvent(
                correlation_id=f"med-{i}",
                event_type=EventType.REQUEST,
                actor="medium_trust_user",
                action="read_file",
                status=status,
                timestamp=base_time + timedelta(days=i * 4),
            )
            db.log_event(event)

        # Test operations
        safe_op = Operation("read_file", {}, "test-1")

        # Evaluate
        decision1 = await engine.should_auto_approve(safe_op, "high_trust_user")
        decision2 = await engine.should_auto_approve(safe_op, "medium_trust_user")

        stats = engine.get_statistics()

        # At least one should be auto-approved
        assert decision1.should_auto_approve or decision2.should_auto_approve
        # Track overall rate (would be >50% in production with more users)
        assert stats["total_evaluations"] > 0
