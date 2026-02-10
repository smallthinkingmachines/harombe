"""Tests for real-time security dashboard."""

import tempfile
import time
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from harombe.security.audit_db import (
    AuditDatabase,
    AuditEvent,
    EventType,
    SecurityDecision,
    SecurityDecisionRecord,
    ToolCallRecord,
)
from harombe.security.dashboard import (
    DashboardMetrics,
    MetricsCache,
    MetricTrend,
    MetricValue,
    SecurityDashboard,
    TrendPoint,
)

# --- Fixtures ---


@pytest.fixture
def temp_db():
    """Create a temporary audit database."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    db = AuditDatabase(db_path=db_path, retention_days=90)
    yield db
    Path(db_path).unlink(missing_ok=True)
    Path(f"{db_path}-shm").unlink(missing_ok=True)
    Path(f"{db_path}-wal").unlink(missing_ok=True)


@pytest.fixture
def populated_db(temp_db):
    """Create a database with sample audit data."""
    # Add events (recent, within last hour)
    for i in range(15):
        event = AuditEvent(
            correlation_id=f"corr-{i}",
            session_id=f"sess-{i % 3}",
            event_type=EventType.REQUEST,
            actor=f"agent-{i % 4}",
            tool_name="filesystem",
            action="read_file",
            metadata={"path": f"/data/file_{i}.txt"},
            status="success",
        )
        temp_db.log_event(event)

    # Add error events
    for i in range(3):
        error = AuditEvent(
            correlation_id=f"corr-err-{i}",
            session_id="sess-0",
            event_type=EventType.ERROR,
            actor=f"agent-{i}",
            action="write_file",
            metadata={},
            status="error",
            error_message="Permission denied",
        )
        temp_db.log_event(error)

    # Add security decisions - allows
    for i in range(8):
        decision = SecurityDecisionRecord(
            correlation_id=f"corr-dec-{i}",
            session_id="sess-0",
            decision_type="authorization",
            decision=SecurityDecision.ALLOW,
            reason="Allowed",
            context={},
            actor=f"agent-{i % 2}",
        )
        temp_db.log_security_decision(decision)

    # Add security decisions - denials
    for i in range(2):
        decision = SecurityDecisionRecord(
            correlation_id=f"corr-deny-{i}",
            session_id="sess-0",
            decision_type="egress",
            decision=SecurityDecision.DENY,
            reason="Blocked",
            context={},
            actor="agent-0",
        )
        temp_db.log_security_decision(decision)

    # Add tool calls
    for i in range(10):
        tc = ToolCallRecord(
            correlation_id=f"corr-tool-{i}",
            session_id="sess-0",
            tool_name="filesystem",
            method="read",
            parameters={"path": f"/data/{i}"},
            result={"ok": True},
            duration_ms=50 + i * 5,
        )
        temp_db.log_tool_call(tc)

    # Add errored tool call
    err_tc = ToolCallRecord(
        correlation_id="corr-tool-err",
        session_id="sess-0",
        tool_name="filesystem",
        method="write",
        parameters={"path": "/etc/secret"},
        error="Denied",
        duration_ms=5,
    )
    temp_db.log_tool_call(err_tc)

    return temp_db


@pytest.fixture
def dashboard(populated_db):
    """Create a dashboard with populated data."""
    return SecurityDashboard(populated_db, cache_ttl_seconds=60.0)


@pytest.fixture
def empty_dashboard(temp_db):
    """Create a dashboard with empty database."""
    return SecurityDashboard(temp_db, cache_ttl_seconds=60.0)


# --- MetricValue Tests ---


class TestMetricValue:
    def test_basic_metric(self):
        m = MetricValue(name="events", value=42, unit="count", category="activity")
        assert m.name == "events"
        assert m.value == 42
        assert m.unit == "count"

    def test_metric_defaults(self):
        m = MetricValue(name="test", value=0)
        assert m.unit == ""
        assert m.category == "activity"
        assert m.description == ""


# --- DashboardMetrics Tests ---


class TestDashboardMetrics:
    def test_default_values(self):
        metrics = DashboardMetrics()
        assert metrics.events_last_hour == 0
        assert metrics.events_last_day == 0
        assert metrics.denial_rate == 0.0
        assert metrics.error_rate == 0.0

    def test_to_metric_list(self):
        metrics = DashboardMetrics(
            events_last_hour=100,
            events_last_day=2000,
            security_denials=5,
            error_events=10,
        )
        metric_list = metrics.to_metric_list()
        assert len(metric_list) == 12  # 12 metrics

        names = {m.name for m in metric_list}
        assert "events_last_hour" in names
        assert "events_last_day" in names
        assert "security_denials" in names
        assert "denial_rate" in names
        assert "error_rate" in names
        assert "avg_tool_duration_ms" in names

    def test_metric_categories(self):
        metrics = DashboardMetrics()
        metric_list = metrics.to_metric_list()

        categories = {m.category for m in metric_list}
        assert "activity" in categories
        assert "security" in categories
        assert "performance" in categories

    def test_all_metrics_have_descriptions(self):
        metrics = DashboardMetrics()
        for m in metrics.to_metric_list():
            assert m.description != "", f"Metric '{m.name}' has no description"


# --- MetricsCache Tests ---


class TestMetricsCache:
    def test_set_and_get(self):
        cache = MetricsCache(ttl_seconds=60.0)
        cache.set("key1", "value1")
        assert cache.get("key1") == "value1"

    def test_cache_miss(self):
        cache = MetricsCache(ttl_seconds=60.0)
        assert cache.get("nonexistent") is None

    def test_cache_expiry(self):
        cache = MetricsCache(ttl_seconds=0.01)  # 10ms TTL
        cache.set("key1", "value1")
        time.sleep(0.02)  # Wait for expiry
        assert cache.get("key1") is None

    def test_invalidate_specific(self):
        cache = MetricsCache(ttl_seconds=60.0)
        cache.set("key1", "value1")
        cache.set("key2", "value2")
        cache.invalidate("key1")
        assert cache.get("key1") is None
        assert cache.get("key2") == "value2"

    def test_invalidate_all(self):
        cache = MetricsCache(ttl_seconds=60.0)
        cache.set("key1", "value1")
        cache.set("key2", "value2")
        cache.invalidate()
        assert cache.get("key1") is None
        assert cache.get("key2") is None

    def test_cache_size(self):
        cache = MetricsCache(ttl_seconds=60.0)
        assert cache.size == 0
        cache.set("k1", "v1")
        cache.set("k2", "v2")
        assert cache.size == 2

    def test_cache_overwrite(self):
        cache = MetricsCache(ttl_seconds=60.0)
        cache.set("key", "old")
        cache.set("key", "new")
        assert cache.get("key") == "new"


# --- TrendPoint Tests ---


class TestTrendPoint:
    def test_basic_point(self):
        now = datetime.utcnow()
        point = TrendPoint(timestamp=now, value=42)
        assert point.value == 42


# --- MetricTrend Tests ---


class TestMetricTrend:
    def test_basic_trend(self):
        trend = MetricTrend(metric_name="events", period_hours=24)
        assert trend.metric_name == "events"
        assert len(trend.points) == 0

    def test_trend_with_points(self):
        now = datetime.utcnow()
        points = [TrendPoint(timestamp=now - timedelta(hours=i), value=i * 10) for i in range(24)]
        trend = MetricTrend(metric_name="events", points=points, period_hours=24)
        assert len(trend.points) == 24


# --- SecurityDashboard Tests ---


class TestSecurityDashboard:
    def test_init(self, dashboard):
        assert dashboard.stats["metrics_computed"] == 0
        assert dashboard.stats["cache_hits"] == 0

    def test_get_metrics(self, dashboard):
        metrics = dashboard.get_metrics()
        assert isinstance(metrics, DashboardMetrics)
        assert metrics.events_last_day >= 0

    def test_get_metrics_with_data(self, dashboard):
        metrics = dashboard.get_metrics()
        # Should have some data from populated_db
        assert metrics.events_last_day >= 15  # 15 request events + 3 errors
        assert metrics.error_events >= 3
        assert metrics.total_tool_calls >= 10

    def test_get_metrics_caching(self, dashboard):
        metrics1 = dashboard.get_metrics()
        metrics2 = dashboard.get_metrics()  # Should hit cache

        assert dashboard.stats["cache_misses"] == 1
        assert dashboard.stats["cache_hits"] == 1
        assert metrics1.events_last_day == metrics2.events_last_day

    def test_get_metrics_after_invalidation(self, dashboard):
        dashboard.get_metrics()
        dashboard.invalidate_cache()
        dashboard.get_metrics()  # Should recompute

        assert dashboard.stats["cache_misses"] == 2
        assert dashboard.stats["metrics_computed"] == 2

    def test_get_metrics_empty_db(self, empty_dashboard):
        metrics = empty_dashboard.get_metrics()
        assert metrics.events_last_hour == 0
        assert metrics.events_last_day == 0
        assert metrics.security_denials == 0
        assert metrics.denial_rate == 0.0
        assert metrics.error_rate == 0.0

    def test_security_decisions(self, dashboard):
        metrics = dashboard.get_metrics()
        assert metrics.security_denials >= 2
        assert metrics.security_allows >= 8
        assert metrics.denial_rate > 0

    def test_error_metrics(self, dashboard):
        metrics = dashboard.get_metrics()
        assert metrics.error_events >= 3
        assert metrics.error_rate > 0

    def test_tool_metrics(self, dashboard):
        metrics = dashboard.get_metrics()
        assert metrics.total_tool_calls >= 10
        assert metrics.tool_call_errors >= 1
        assert metrics.avg_tool_duration_ms > 0


class TestDashboardTrends:
    def test_get_events_trend(self, dashboard):
        trend = dashboard.get_trend("events", hours=4)
        assert trend.metric_name == "events"
        assert len(trend.points) == 4
        assert trend.period_hours == 4

    def test_get_denials_trend(self, dashboard):
        trend = dashboard.get_trend("denials", hours=4)
        assert trend.metric_name == "denials"
        assert len(trend.points) == 4

    def test_get_tool_calls_trend(self, dashboard):
        trend = dashboard.get_trend("tool_calls", hours=4)
        assert trend.metric_name == "tool_calls"

    def test_get_unknown_metric_trend(self, dashboard):
        trend = dashboard.get_trend("nonexistent", hours=4)
        # Should return zeros
        assert all(p.value == 0 for p in trend.points)

    def test_trend_caching(self, dashboard):
        dashboard.get_trend("events", hours=4)
        dashboard.get_trend("events", hours=4)  # Cache hit
        assert dashboard.stats["cache_hits"] >= 1


class TestDashboardSnapshot:
    def test_get_snapshot(self, dashboard):
        snapshot = dashboard.get_snapshot()
        assert "timestamp" in snapshot
        assert "metrics" in snapshot
        assert "summary" in snapshot
        assert snapshot["timestamp"].endswith("Z")

    def test_snapshot_metrics(self, dashboard):
        snapshot = dashboard.get_snapshot()
        metrics = snapshot["metrics"]
        assert "events_last_hour" in metrics
        assert "events_last_day" in metrics
        assert "denial_rate" in metrics

    def test_snapshot_summary(self, dashboard):
        snapshot = dashboard.get_snapshot()
        summary = snapshot["summary"]
        assert "total_events_24h" in summary
        assert "error_rate" in summary
        assert "denial_rate" in summary
        assert "active_sessions" in summary

    def test_snapshot_serializable(self, dashboard):
        """Snapshot should be JSON-serializable."""
        import json

        snapshot = dashboard.get_snapshot()
        json_str = json.dumps(snapshot)
        assert len(json_str) > 0


class TestDashboardStatistics:
    def test_stats_after_metrics(self, dashboard):
        dashboard.get_metrics()
        stats = dashboard.get_stats()
        assert stats["metrics_computed"] == 1
        assert stats["cache_misses"] == 1
        assert stats["avg_computation_ms"] > 0

    def test_stats_with_cache(self, dashboard):
        dashboard.get_metrics()
        dashboard.get_metrics()
        stats = dashboard.get_stats()
        assert stats["cache_hits"] == 1
        assert stats["cache_misses"] == 1


# --- Performance Tests ---


class TestDashboardPerformance:
    def test_metrics_computation_speed(self, dashboard):
        """Metrics should compute quickly."""
        dashboard.invalidate_cache()
        start = time.perf_counter()
        dashboard.get_metrics()
        elapsed_ms = (time.perf_counter() - start) * 1000
        # Should be well under 200ms for small datasets (relaxed for CI)
        assert elapsed_ms < 600, f"Metrics took {elapsed_ms:.1f}ms"

    def test_cached_metrics_speed(self, dashboard):
        """Cached metrics should be very fast."""
        dashboard.get_metrics()  # Populate cache

        start = time.perf_counter()
        for _i in range(100):
            dashboard.get_metrics()
        elapsed_ms = (time.perf_counter() - start) * 1000
        # 100 cached lookups should take <250ms (relaxed for CI)
        assert elapsed_ms < 250, f"100 cached lookups took {elapsed_ms:.1f}ms"


# --- Edge Cases ---


class TestEdgeCases:
    def test_dashboard_with_no_security_decisions(self, temp_db):
        # Add only events, no decisions
        event = AuditEvent(
            correlation_id="corr-1",
            event_type=EventType.REQUEST,
            actor="agent-1",
            action="test",
            status="success",
            metadata={},
        )
        temp_db.log_event(event)

        dashboard = SecurityDashboard(temp_db)
        metrics = dashboard.get_metrics()
        assert metrics.denial_rate == 0.0
        assert metrics.security_denials == 0

    def test_dashboard_all_errors(self, temp_db):
        for i in range(5):
            event = AuditEvent(
                correlation_id=f"corr-{i}",
                event_type=EventType.ERROR,
                actor="agent-bad",
                action="fail",
                status="error",
                metadata={},
            )
            temp_db.log_event(event)

        dashboard = SecurityDashboard(temp_db)
        metrics = dashboard.get_metrics()
        assert metrics.error_events >= 5
        assert metrics.error_rate > 0

    def test_cache_ttl_zero(self, populated_db):
        """Dashboard with 0 TTL always recomputes."""
        dashboard = SecurityDashboard(populated_db, cache_ttl_seconds=0.001)
        dashboard.get_metrics()
        time.sleep(0.01)
        dashboard.get_metrics()
        # Both should be cache misses
        assert dashboard.stats["metrics_computed"] >= 2
