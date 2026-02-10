"""Real-time security metrics dashboard.

This module provides a dashboard for monitoring security metrics
computed from the audit database. Supports caching, time-windowed
queries, and WebSocket-ready data for real-time updates.

Features:
- 10+ key security metrics
- Configurable cache TTL (default 60s)
- Time-windowed metric computation
- Activity, security, and performance metric categories
- Trend calculation (hourly buckets)
- WebSocket-ready metric snapshots
"""

import time
from datetime import datetime, timedelta
from typing import Any

from pydantic import BaseModel, Field

from .audit_db import AuditDatabase


class MetricValue(BaseModel):
    """A single metric value with metadata."""

    name: str
    value: float | int
    unit: str = ""  # "count", "ms", "percent", etc.
    category: str = "activity"  # "activity", "security", "performance"
    description: str = ""


class DashboardMetrics(BaseModel):
    """Complete set of dashboard metrics."""

    timestamp: datetime = Field(default_factory=datetime.utcnow)

    # Activity metrics
    events_last_hour: int = 0
    events_last_day: int = 0
    active_sessions: int = 0
    active_actors: int = 0

    # Security metrics
    security_denials: int = 0
    security_allows: int = 0
    error_events: int = 0
    tool_call_errors: int = 0

    # Performance metrics
    avg_tool_duration_ms: float = 0.0
    total_tool_calls: int = 0

    # Derived metrics
    denial_rate: float = 0.0
    error_rate: float = 0.0

    def to_metric_list(self) -> list[MetricValue]:
        """Convert to a list of MetricValue objects for API/WebSocket consumption."""
        return [
            MetricValue(
                name="events_last_hour",
                value=self.events_last_hour,
                unit="count",
                category="activity",
                description="Audit events in the last hour",
            ),
            MetricValue(
                name="events_last_day",
                value=self.events_last_day,
                unit="count",
                category="activity",
                description="Audit events in the last 24 hours",
            ),
            MetricValue(
                name="active_sessions",
                value=self.active_sessions,
                unit="count",
                category="activity",
                description="Unique sessions in the last hour",
            ),
            MetricValue(
                name="active_actors",
                value=self.active_actors,
                unit="count",
                category="activity",
                description="Unique actors in the last hour",
            ),
            MetricValue(
                name="security_denials",
                value=self.security_denials,
                unit="count",
                category="security",
                description="Security decision denials in the last 24 hours",
            ),
            MetricValue(
                name="security_allows",
                value=self.security_allows,
                unit="count",
                category="security",
                description="Security decision allows in the last 24 hours",
            ),
            MetricValue(
                name="denial_rate",
                value=self.denial_rate,
                unit="percent",
                category="security",
                description="Percentage of denied security decisions",
            ),
            MetricValue(
                name="error_events",
                value=self.error_events,
                unit="count",
                category="security",
                description="Error events in the last 24 hours",
            ),
            MetricValue(
                name="tool_call_errors",
                value=self.tool_call_errors,
                unit="count",
                category="security",
                description="Tool call errors in the last 24 hours",
            ),
            MetricValue(
                name="error_rate",
                value=self.error_rate,
                unit="percent",
                category="security",
                description="Percentage of events that are errors",
            ),
            MetricValue(
                name="avg_tool_duration_ms",
                value=self.avg_tool_duration_ms,
                unit="ms",
                category="performance",
                description="Average tool call duration",
            ),
            MetricValue(
                name="total_tool_calls",
                value=self.total_tool_calls,
                unit="count",
                category="performance",
                description="Total tool calls in the last 24 hours",
            ),
        ]


class TrendPoint(BaseModel):
    """A single point in a time series trend."""

    timestamp: datetime
    value: float | int


class MetricTrend(BaseModel):
    """A time series trend for a metric."""

    metric_name: str
    points: list[TrendPoint] = Field(default_factory=list)
    period_hours: int = 24


class MetricsCache:
    """Simple TTL-based metrics cache."""

    def __init__(self, ttl_seconds: float = 60.0):
        self.ttl_seconds = ttl_seconds
        self._cache: dict[str, tuple[float, Any]] = {}

    def get(self, key: str) -> Any | None:
        """Get a cached value if not expired."""
        if key in self._cache:
            timestamp, value = self._cache[key]
            if time.time() - timestamp < self.ttl_seconds:
                return value
            del self._cache[key]
        return None

    def set(self, key: str, value: Any) -> None:
        """Set a cached value."""
        self._cache[key] = (time.time(), value)

    def invalidate(self, key: str | None = None) -> None:
        """Invalidate a specific key or all keys."""
        if key is None:
            self._cache.clear()
        else:
            self._cache.pop(key, None)

    @property
    def size(self) -> int:
        """Number of cached items."""
        return len(self._cache)


class SecurityDashboard:
    """Real-time security metrics dashboard.

    Computes metrics from the AuditDatabase with caching for performance.
    Provides WebSocket-ready data snapshots and trend calculations.

    Usage:
        dashboard = SecurityDashboard(audit_db)

        # Get current metrics
        metrics = dashboard.get_metrics()

        # Get as list for API/WebSocket
        metric_list = metrics.to_metric_list()

        # Get trends
        trend = dashboard.get_trend("events", hours=24)
    """

    def __init__(
        self,
        audit_db: AuditDatabase,
        cache_ttl_seconds: float = 60.0,
    ):
        """Initialize dashboard.

        Args:
            audit_db: AuditDatabase instance
            cache_ttl_seconds: Metrics cache TTL in seconds
        """
        self.db = audit_db
        self.cache = MetricsCache(ttl_seconds=cache_ttl_seconds)
        self.stats: dict[str, Any] = {
            "metrics_computed": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "avg_computation_ms": 0.0,
        }

    def get_metrics(self) -> DashboardMetrics:
        """Get current security metrics.

        Uses cache if available, otherwise computes from database.

        Returns:
            DashboardMetrics with current values
        """
        cached = self.cache.get("current_metrics")
        if cached is not None:
            self.stats["cache_hits"] += 1
            return cached

        self.stats["cache_misses"] += 1
        start = time.perf_counter()

        metrics = self._compute_metrics()

        elapsed_ms = (time.perf_counter() - start) * 1000
        self.stats["metrics_computed"] += 1
        total = self.stats["metrics_computed"]
        prev_avg = self.stats["avg_computation_ms"]
        self.stats["avg_computation_ms"] = prev_avg + (elapsed_ms - prev_avg) / total

        self.cache.set("current_metrics", metrics)
        return metrics

    def _compute_metrics(self) -> DashboardMetrics:
        """Compute all dashboard metrics from the database."""
        now = datetime.utcnow()
        one_hour_ago = now - timedelta(hours=1)
        one_day_ago = now - timedelta(hours=24)

        # Get statistics from audit database
        hour_stats = self.db.get_statistics(start_time=one_hour_ago, end_time=now)
        day_stats = self.db.get_statistics(start_time=one_day_ago, end_time=now)

        # Activity metrics
        hour_events = hour_stats.get("events", {})
        day_events = day_stats.get("events", {})

        events_last_hour = hour_events.get("total_events", 0)
        events_last_day = day_events.get("total_events", 0)
        active_sessions = hour_events.get("unique_sessions", 0)
        active_actors = hour_events.get("unique_requests", 0)  # Approximation

        # Security decisions
        day_decisions = day_stats.get("security_decisions", [])
        security_denials = 0
        security_allows = 0
        for dec in day_decisions:
            if dec.get("decision") == "deny":
                security_denials += dec.get("count", 0)
            elif dec.get("decision") == "allow":
                security_allows += dec.get("count", 0)

        total_decisions = security_denials + security_allows
        denial_rate = (security_denials / total_decisions * 100) if total_decisions > 0 else 0.0

        # Error metrics (approximate from events)
        # Count error events by getting events list
        all_events = self.db.get_events_by_session(None, limit=10000)
        day_events_list = [
            e
            for e in all_events
            if _parse_timestamp(e.get("timestamp"))
            and _parse_timestamp(e.get("timestamp")) >= one_day_ago
        ]
        error_events = sum(1 for e in day_events_list if e.get("event_type") == "error")
        error_rate = (error_events / len(day_events_list) * 100) if day_events_list else 0.0

        # Tool call metrics
        day_tools = day_stats.get("tools", [])
        total_tool_calls = sum(t.get("call_count", 0) for t in day_tools)
        tool_call_errors = 0
        total_duration = 0.0
        for tool in day_tools:
            avg_dur = tool.get("avg_duration_ms")
            count = tool.get("call_count", 0)
            if avg_dur is not None and count > 0:
                total_duration += avg_dur * count

        avg_tool_duration_ms = (total_duration / total_tool_calls) if total_tool_calls > 0 else 0.0

        # Count errored tool calls
        tool_calls_list = self.db.get_tool_calls(start_time=one_day_ago, end_time=now, limit=10000)
        tool_call_errors = sum(1 for tc in tool_calls_list if tc.get("error"))

        return DashboardMetrics(
            events_last_hour=events_last_hour,
            events_last_day=events_last_day,
            active_sessions=active_sessions,
            active_actors=active_actors,
            security_denials=security_denials,
            security_allows=security_allows,
            denial_rate=round(denial_rate, 1),
            error_events=error_events,
            tool_call_errors=tool_call_errors,
            error_rate=round(error_rate, 1),
            avg_tool_duration_ms=round(avg_tool_duration_ms, 1),
            total_tool_calls=total_tool_calls,
        )

    def get_trend(self, metric_name: str, hours: int = 24) -> MetricTrend:
        """Get a time series trend for a metric.

        Args:
            metric_name: Name of the metric (e.g., "events", "errors")
            hours: Number of hours to include

        Returns:
            MetricTrend with hourly data points
        """
        cache_key = f"trend_{metric_name}_{hours}"
        cached = self.cache.get(cache_key)
        if cached is not None:
            self.stats["cache_hits"] += 1
            return cached

        self.stats["cache_misses"] += 1
        trend = self._compute_trend(metric_name, hours)
        self.cache.set(cache_key, trend)
        return trend

    def _compute_trend(self, metric_name: str, hours: int) -> MetricTrend:
        """Compute hourly trend for a metric."""
        now = datetime.utcnow()
        points: list[TrendPoint] = []

        for hour_offset in range(hours, 0, -1):
            start = now - timedelta(hours=hour_offset)
            end = now - timedelta(hours=hour_offset - 1)

            stats = self.db.get_statistics(start_time=start, end_time=end)

            if metric_name == "events":
                value = stats.get("events", {}).get("total_events", 0)
            elif metric_name == "errors":
                # Count error events for this hour
                events = self.db.get_events_by_session(None, limit=10000)
                value = sum(
                    1
                    for e in events
                    if e.get("event_type") == "error"
                    and _parse_timestamp(e.get("timestamp"))
                    and start <= _parse_timestamp(e.get("timestamp")) < end
                )
            elif metric_name == "denials":
                decisions = stats.get("security_decisions", [])
                value = sum(d.get("count", 0) for d in decisions if d.get("decision") == "deny")
            elif metric_name == "tool_calls":
                tools = stats.get("tools", [])
                value = sum(t.get("call_count", 0) for t in tools)
            else:
                value = 0

            points.append(TrendPoint(timestamp=start, value=value))

        return MetricTrend(
            metric_name=metric_name,
            points=points,
            period_hours=hours,
        )

    def get_snapshot(self) -> dict[str, Any]:
        """Get a WebSocket-ready snapshot of all dashboard data.

        Returns a dictionary suitable for JSON serialization and
        WebSocket transmission.

        Returns:
            Dictionary with metrics and metadata
        """
        metrics = self.get_metrics()
        metric_list = metrics.to_metric_list()

        return {
            "timestamp": metrics.timestamp.isoformat() + "Z",
            "metrics": {m.name: m.model_dump(mode="json") for m in metric_list},
            "summary": {
                "total_events_24h": metrics.events_last_day,
                "error_rate": metrics.error_rate,
                "denial_rate": metrics.denial_rate,
                "active_sessions": metrics.active_sessions,
            },
        }

    def invalidate_cache(self) -> None:
        """Force cache invalidation for next refresh."""
        self.cache.invalidate()

    def get_stats(self) -> dict[str, Any]:
        """Get dashboard statistics."""
        return dict(self.stats)


def _parse_timestamp(ts: Any) -> datetime | None:
    """Parse a timestamp from database row."""
    if ts is None:
        return None
    if isinstance(ts, datetime):
        return ts
    if isinstance(ts, str):
        try:
            return datetime.fromisoformat(ts)
        except ValueError:
            return None
    return None
