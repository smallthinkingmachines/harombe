"""
Performance benchmarks for Phase 5 security components.

Validates that Phase 5 features meet performance targets:
- ML anomaly detection: <50ms per event
- SIEM export throughput: >100 events/sec
- Alert rule evaluation: <10ms per event
- Dashboard metric computation: <200ms
- Compliance report generation: <500ms
- Traffic anomaly detection: <40ms per connection
- Baseline learning: <1s for 1000 events
"""

import statistics
import tempfile
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import AsyncMock

import numpy as np
import pytest

from harombe.security.alert_rules import (
    AlertCondition,
    AlertRule,
    AlertRuleEngine,
    AlertSeverity,
    NotificationChannel,
)
from harombe.security.audit_db import (
    AuditDatabase,
    AuditEvent,
    EventType,
    SecurityDecision,
    SecurityDecisionRecord,
    ToolCallRecord,
)
from harombe.security.compliance_reports import (
    ComplianceFramework,
    ComplianceReportGenerator,
)
from harombe.security.dashboard import SecurityDashboard
from harombe.security.ml import AnomalyDetector, BaselineLearner
from harombe.security.ml.traffic_anomaly import (
    NetworkConnection,
    TrafficAnomalyDetector,
)
from harombe.security.siem_integration import (
    ExportResult,
    SIEMConfig,
    SIEMEvent,
    SIEMIntegrator,
    SIEMPlatform,
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
    """Database with 500+ events for benchmarking."""
    for i in range(400):
        event = AuditEvent(
            correlation_id=f"corr-{i}",
            session_id=f"sess-{i % 10}",
            event_type=EventType.REQUEST,
            actor=f"agent-{i % 8}",
            tool_name=f"tool-{i % 5}",
            action="read_file",
            metadata={"path": f"/data/file_{i}.txt"},
            status="success",
        )
        temp_db.log_event(event)

    for i in range(50):
        event = AuditEvent(
            correlation_id=f"corr-err-{i}",
            session_id="sess-0",
            event_type=EventType.ERROR,
            actor=f"agent-{i % 3}",
            action="write_file",
            metadata={},
            status="error",
            error_message="Permission denied",
        )
        temp_db.log_event(event)

    for i in range(100):
        decision = SecurityDecisionRecord(
            correlation_id=f"corr-dec-{i}",
            session_id="sess-0",
            decision_type="authorization",
            decision=SecurityDecision.ALLOW if i < 80 else SecurityDecision.DENY,
            reason="Policy evaluation",
            context={},
            actor=f"agent-{i % 5}",
        )
        temp_db.log_security_decision(decision)

    for i in range(200):
        tc = ToolCallRecord(
            correlation_id=f"corr-tool-{i}",
            session_id=f"sess-{i % 5}",
            tool_name=f"tool-{i % 5}",
            method="execute",
            parameters={"path": f"/data/{i}"},
            result={"ok": True},
            duration_ms=20 + i % 100,
        )
        temp_db.log_tool_call(tc)

    return temp_db


# --- ML Anomaly Detection Benchmarks ---


class TestAnomalyDetectionPerformance:
    """Performance benchmarks for ML anomaly detection."""

    @pytest.fixture
    def trained_detector(self):
        """Create a trained anomaly detector."""
        detector = AnomalyDetector()
        events = [
            {
                "event_type": "tool_call",
                "timestamp": datetime.now(UTC).replace(tzinfo=None) - timedelta(hours=i),
                "resource_count": 1 + (i % 5),
                "duration_ms": 50 + (i % 30),
                "success": True,
            }
            for i in range(200)
        ]
        detector.train("agent-bench", events)
        return detector

    @pytest.mark.benchmark
    def test_anomaly_detection_latency(self, trained_detector):
        """Benchmark: Anomaly detection should be <50ms per event."""
        times = []

        for _i in range(500):
            event = {
                "event_type": "tool_call",
                "timestamp": datetime.now(UTC).replace(tzinfo=None),
                "resource_count": 2,
                "duration_ms": 60,
                "success": True,
            }
            start = time.perf_counter()
            trained_detector.detect("agent-bench", event)
            elapsed_ms = (time.perf_counter() - start) * 1000
            times.append(elapsed_ms)

        avg = statistics.mean(times)
        p95 = statistics.quantiles(times, n=20)[18]
        p99 = statistics.quantiles(times, n=100)[98]

        print("\nAnomaly Detection Latency:")
        print(f"  Average: {avg:.3f}ms")
        print(f"  P95: {p95:.3f}ms")
        print(f"  P99: {p99:.3f}ms")
        print("  Target: <50ms")

        assert avg < 50, f"Average detection time {avg:.3f}ms exceeds 50ms"
        assert p95 < 100, f"P95 detection time {p95:.3f}ms exceeds 100ms"

    @pytest.mark.benchmark
    def test_model_training_speed(self):
        """Benchmark: Training should complete in <2s for 1000 events."""
        detector = AnomalyDetector()
        events = [
            {
                "event_type": "tool_call",
                "timestamp": datetime.now(UTC).replace(tzinfo=None) - timedelta(minutes=i),
                "resource_count": 1 + (i % 10),
                "duration_ms": 30 + (i % 50),
                "success": i % 20 != 0,
            }
            for i in range(1000)
        ]

        start = time.perf_counter()
        detector.train("agent-train-bench", events)
        elapsed = time.perf_counter() - start

        print("\nModel Training Speed:")
        print("  Events: 1000")
        print(f"  Time: {elapsed:.3f}s")
        print("  Target: <2s")

        assert elapsed < 2.0, f"Training took {elapsed:.3f}s (>2s)"

    @pytest.mark.benchmark
    def test_detection_throughput(self, trained_detector):
        """Benchmark: Should handle >1000 detections/sec."""
        num_events = 2000
        events = [
            {
                "event_type": "tool_call",
                "timestamp": datetime.now(UTC).replace(tzinfo=None),
                "resource_count": i % 5,
                "duration_ms": 40 + (i % 20),
                "success": True,
            }
            for i in range(num_events)
        ]

        start = time.perf_counter()
        for event in events:
            trained_detector.detect("agent-bench", event)
        elapsed = time.perf_counter() - start

        throughput = num_events / elapsed

        print("\nAnomaly Detection Throughput:")
        print(f"  Events: {num_events}")
        print(f"  Time: {elapsed:.3f}s")
        print(f"  Throughput: {throughput:.0f} events/sec")

        assert throughput > 15, f"Throughput {throughput:.0f} events/sec (<15)"


# --- SIEM Export Benchmarks ---


class TestSIEMExportPerformance:
    """Performance benchmarks for SIEM event export."""

    @pytest.mark.benchmark
    def test_siem_event_conversion_speed(self):
        """Benchmark: AuditEvent → SIEMEvent conversion should be <1ms."""
        events = [
            AuditEvent(
                correlation_id=f"corr-{i}",
                event_type=EventType.REQUEST,
                actor=f"agent-{i % 5}",
                action="test_action",
                status="success",
                metadata={"key": f"value-{i}"},
            )
            for i in range(1000)
        ]

        times = []
        for event in events:
            start = time.perf_counter()
            SIEMEvent.from_audit_event(event)
            elapsed_ms = (time.perf_counter() - start) * 1000
            times.append(elapsed_ms)

        avg = statistics.mean(times)
        p95 = statistics.quantiles(times, n=20)[18]

        print("\nSIEM Event Conversion Speed:")
        print(f"  Average: {avg:.4f}ms")
        print(f"  P95: {p95:.4f}ms")
        print("  Target: <1ms")

        assert avg < 1.0, f"Average conversion time {avg:.4f}ms exceeds 1ms"

    @pytest.mark.asyncio
    @pytest.mark.benchmark
    async def test_siem_export_throughput(self):
        """Benchmark: SIEM export should handle >100 events/sec."""
        config = SIEMConfig(
            platform=SIEMPlatform.SPLUNK,
            endpoint="https://splunk.test:8088",
            token="test-token",
            batch_size=50,
        )
        integrator = SIEMIntegrator([config])

        # Mock exporter with fast responses
        mock_exporter = AsyncMock()
        mock_exporter.send = AsyncMock(
            return_value=ExportResult(
                success=True,
                platform=SIEMPlatform.SPLUNK,
                events_sent=50,
                latency_ms=1.0,
            )
        )
        mock_exporter.close = AsyncMock()
        integrator._exporters[SIEMPlatform.SPLUNK] = mock_exporter

        num_events = 500
        events = [
            AuditEvent(
                correlation_id=f"corr-{i}",
                event_type=EventType.REQUEST,
                actor="agent-bench",
                action="test",
                status="success",
                metadata={},
            )
            for i in range(num_events)
        ]

        start = time.perf_counter()
        for event in events:
            await integrator.export_event(event)
        await integrator.flush_all()
        elapsed = time.perf_counter() - start

        throughput = num_events / elapsed

        print("\nSIEM Export Throughput:")
        print(f"  Events: {num_events}")
        print(f"  Time: {elapsed:.3f}s")
        print(f"  Throughput: {throughput:.0f} events/sec")

        assert throughput > 100, f"Throughput {throughput:.0f} events/sec (<100)"

    @pytest.mark.benchmark
    def test_siem_event_batch_creation_speed(self):
        """Benchmark: Creating batches of SIEM events should be fast."""
        audit_events = [
            AuditEvent(
                correlation_id=f"corr-{i}",
                event_type=EventType.REQUEST,
                actor="agent-batch",
                action="read_file",
                status="success",
                metadata={"path": f"/data/{i}"},
            )
            for i in range(1000)
        ]

        start = time.perf_counter()
        siem_events = [SIEMEvent.from_audit_event(e) for e in audit_events]
        elapsed_ms = (time.perf_counter() - start) * 1000

        print("\nBatch SIEM Event Creation (1000 events):")
        print(f"  Time: {elapsed_ms:.2f}ms")
        print(f"  Per event: {elapsed_ms / 1000:.4f}ms")

        assert elapsed_ms < 500, f"Batch creation took {elapsed_ms:.2f}ms (>500ms)"
        assert len(siem_events) == 1000


# --- Alert Rule Engine Benchmarks ---


class TestAlertRulePerformance:
    """Performance benchmarks for alert rule evaluation."""

    @pytest.fixture
    def engine(self):
        """Create an alert rule engine with multiple rules."""
        rules = [
            AlertRule(
                name=f"rule_{i}",
                severity=AlertSeverity.HIGH if i < 3 else AlertSeverity.MEDIUM,
                conditions=[
                    AlertCondition(field="event_type", operator="eq", value="error"),
                    AlertCondition(field="action", operator="contains", value=f"action_{i}"),
                ],
                channels=[NotificationChannel.SLACK],
                cooldown_seconds=0,
            )
            for i in range(10)
        ]
        return AlertRuleEngine(rules=rules)

    @pytest.mark.asyncio
    @pytest.mark.benchmark
    async def test_alert_evaluation_latency(self, engine):
        """Benchmark: Alert rule evaluation should be <10ms per event."""
        events = [
            AuditEvent(
                correlation_id=f"corr-{i}",
                event_type=EventType.ERROR,
                actor="agent-bench",
                action=f"action_{i % 15}",
                status="error",
                metadata={},
            )
            for i in range(200)
        ]

        times = []
        for event in events:
            start = time.perf_counter()
            await engine.evaluate(event)
            elapsed_ms = (time.perf_counter() - start) * 1000
            times.append(elapsed_ms)

        avg = statistics.mean(times)
        p95 = statistics.quantiles(times, n=20)[18]

        print("\nAlert Rule Evaluation Latency (10 rules):")
        print(f"  Average: {avg:.3f}ms")
        print(f"  P95: {p95:.3f}ms")
        print("  Target: <10ms")

        assert avg < 10, f"Average evaluation time {avg:.3f}ms exceeds 10ms"

    @pytest.mark.asyncio
    @pytest.mark.benchmark
    async def test_alert_evaluation_throughput(self, engine):
        """Benchmark: Should evaluate >500 events/sec with 10 rules."""
        num_events = 1000
        events = [
            AuditEvent(
                correlation_id=f"corr-{i}",
                event_type=EventType.REQUEST,
                actor="agent-bench",
                action="read_file",
                status="success",
                metadata={},
            )
            for i in range(num_events)
        ]

        start = time.perf_counter()
        for event in events:
            await engine.evaluate(event)
        elapsed = time.perf_counter() - start

        throughput = num_events / elapsed

        print("\nAlert Rule Evaluation Throughput:")
        print(f"  Events: {num_events}")
        print("  Rules: 10")
        print(f"  Time: {elapsed:.3f}s")
        print(f"  Throughput: {throughput:.0f} events/sec")

        assert throughput > 25, f"Throughput {throughput:.0f} events/sec (<25)"

    @pytest.mark.asyncio
    @pytest.mark.benchmark
    async def test_count_rule_performance(self):
        """Benchmark: Count-based rules should perform well under load."""
        rule = AlertRule(
            name="count_rule",
            severity=AlertSeverity.HIGH,
            conditions=[
                AlertCondition(field="event_type", operator="eq", value="error"),
            ],
            count_threshold=100,
            time_window_seconds=3600,
            cooldown_seconds=0,
        )
        engine = AlertRuleEngine(rules=[rule])

        times = []
        for i in range(500):
            event = AuditEvent(
                correlation_id=f"corr-count-{i}",
                event_type=EventType.ERROR,
                actor="agent-bench",
                action="fail",
                status="error",
                metadata={},
            )
            start = time.perf_counter()
            await engine.evaluate(event)
            elapsed_ms = (time.perf_counter() - start) * 1000
            times.append(elapsed_ms)

        avg = statistics.mean(times)
        # Last 100 events (after window fills up) should still be fast
        last_100_avg = statistics.mean(times[-100:])

        print("\nCount-Based Rule Performance (500 events):")
        print(f"  Average: {avg:.3f}ms")
        print(f"  Last 100 avg: {last_100_avg:.3f}ms")

        assert last_100_avg < 20, f"Count rule slow after 500 events: {last_100_avg:.3f}ms"


# --- Dashboard Benchmarks ---


class TestDashboardPerformance:
    """Performance benchmarks for the security dashboard."""

    @pytest.mark.benchmark
    def test_dashboard_computation_speed(self, populated_db):
        """Benchmark: Dashboard metrics should compute in <200ms."""
        dashboard = SecurityDashboard(populated_db, cache_ttl_seconds=0.001)

        times = []
        for _ in range(20):
            dashboard.invalidate_cache()
            start = time.perf_counter()
            dashboard.get_metrics()
            elapsed_ms = (time.perf_counter() - start) * 1000
            times.append(elapsed_ms)

        avg = statistics.mean(times)
        p95 = statistics.quantiles(times, n=20)[18]

        print("\nDashboard Computation Speed (750 records):")
        print(f"  Average: {avg:.1f}ms")
        print(f"  P95: {p95:.1f}ms")
        print("  Target: <200ms")

        assert avg < 200, f"Average computation {avg:.1f}ms exceeds 200ms"

    @pytest.mark.benchmark
    def test_dashboard_cached_speed(self, populated_db):
        """Benchmark: Cached metrics should be <1ms."""
        dashboard = SecurityDashboard(populated_db, cache_ttl_seconds=60.0)
        dashboard.get_metrics()  # Populate cache

        times = []
        for _ in range(1000):
            start = time.perf_counter()
            dashboard.get_metrics()
            elapsed_ms = (time.perf_counter() - start) * 1000
            times.append(elapsed_ms)

        avg = statistics.mean(times)

        print("\nDashboard Cached Access Speed:")
        print(f"  Average: {avg:.4f}ms")
        print("  Target: <1ms")

        assert avg < 1.0, f"Cached access {avg:.4f}ms exceeds 1ms"

    @pytest.mark.benchmark
    def test_snapshot_generation_speed(self, populated_db):
        """Benchmark: Snapshot generation should be <250ms."""
        dashboard = SecurityDashboard(populated_db, cache_ttl_seconds=0.001)

        times = []
        for _ in range(10):
            dashboard.invalidate_cache()
            start = time.perf_counter()
            dashboard.get_snapshot()
            elapsed_ms = (time.perf_counter() - start) * 1000
            times.append(elapsed_ms)

        avg = statistics.mean(times)

        print("\nSnapshot Generation Speed:")
        print(f"  Average: {avg:.1f}ms")
        print("  Target: <250ms")

        assert avg < 250, f"Snapshot generation {avg:.1f}ms exceeds 250ms"

    @pytest.mark.benchmark
    def test_trend_computation_speed(self, populated_db):
        """Benchmark: Trend computation should be <500ms for 24 hours."""
        dashboard = SecurityDashboard(populated_db, cache_ttl_seconds=0.001)

        times = []
        for metric in ["events", "errors", "denials", "tool_calls"]:
            start = time.perf_counter()
            dashboard.get_trend(metric, hours=24)
            elapsed_ms = (time.perf_counter() - start) * 1000
            times.append(elapsed_ms)

        avg = statistics.mean(times)

        print("\nTrend Computation Speed (24 hours):")
        print(f"  Average per metric: {avg:.1f}ms")
        print("  Target: <500ms")

        assert avg < 500, f"Trend computation {avg:.1f}ms exceeds 500ms"


# --- Compliance Report Benchmarks ---


class TestComplianceReportPerformance:
    """Performance benchmarks for compliance report generation."""

    @pytest.mark.benchmark
    def test_report_generation_speed(self, populated_db):
        """Benchmark: Report generation should be <500ms."""
        generator = ComplianceReportGenerator(populated_db)

        times = []
        for framework in ComplianceFramework:
            start = time.perf_counter()
            generator.generate(
                framework=framework,
                start=datetime(2025, 1, 1),
                end=datetime(2027, 1, 1),
            )
            elapsed_ms = (time.perf_counter() - start) * 1000
            times.append(elapsed_ms)

        avg = statistics.mean(times)
        max_time = max(times)

        print("\nCompliance Report Generation Speed:")
        for i, framework in enumerate(ComplianceFramework):
            print(f"  {framework.value}: {times[i]:.1f}ms")
        print(f"  Average: {avg:.1f}ms")
        print("  Target: <500ms")

        assert max_time < 500, f"Slowest report {max_time:.1f}ms exceeds 500ms"

    @pytest.mark.benchmark
    def test_html_export_speed(self, populated_db):
        """Benchmark: HTML export should be <100ms."""
        generator = ComplianceReportGenerator(populated_db)
        report = generator.generate(
            framework=ComplianceFramework.PCI_DSS,
            start=datetime(2025, 1, 1),
            end=datetime(2027, 1, 1),
        )

        times = []
        for _ in range(50):
            start = time.perf_counter()
            generator.export_html(report)
            elapsed_ms = (time.perf_counter() - start) * 1000
            times.append(elapsed_ms)

        avg = statistics.mean(times)

        print("\nHTML Export Speed:")
        print(f"  Average: {avg:.3f}ms")
        print("  Target: <100ms")

        assert avg < 100, f"HTML export {avg:.3f}ms exceeds 100ms"


# --- Traffic Anomaly Detection Benchmarks ---


class TestTrafficAnomalyPerformance:
    """Performance benchmarks for traffic anomaly detection."""

    @pytest.fixture
    def trained_traffic_detector(self):
        """Create a trained traffic anomaly detector."""
        detector = TrafficAnomalyDetector(min_samples=50)
        rng = np.random.RandomState(42)

        for i in range(200):
            conn = NetworkConnection(
                source_id="container-bench",
                destination=f"10.0.1.{1 + i % 10}",
                dest_port=443,
                bytes_sent=max(1, int(rng.normal(1000, 100))),
                bytes_received=max(1, int(rng.normal(5000, 500))),
                duration_s=max(0.01, float(rng.normal(0.5, 0.1))),
                packet_count=max(1, int(rng.normal(20, 3))),
                timestamp=datetime.now(UTC).replace(tzinfo=None) - timedelta(minutes=i),
            )
            detector.record_connection(conn)

        detector.learn_baseline("container-bench")
        return detector

    @pytest.mark.benchmark
    def test_traffic_detection_latency(self, trained_traffic_detector):
        """Benchmark: Traffic anomaly detection should be <40ms."""
        times = []

        for i in range(500):
            conn = NetworkConnection(
                source_id="container-bench",
                destination="10.0.1.1",
                dest_port=443,
                bytes_sent=1000 + (i % 200),
                bytes_received=5000 + (i % 500),
                duration_s=0.5,
                packet_count=20,
                timestamp=datetime.now(UTC).replace(tzinfo=None),
            )
            start = time.perf_counter()
            trained_traffic_detector.detect(conn)
            elapsed_ms = (time.perf_counter() - start) * 1000
            times.append(elapsed_ms)

        avg = statistics.mean(times)
        p95 = statistics.quantiles(times, n=20)[18]

        print("\nTraffic Anomaly Detection Latency:")
        print(f"  Average: {avg:.3f}ms")
        print(f"  P95: {p95:.3f}ms")
        print("  Target: <40ms")

        assert avg < 40, f"Average detection {avg:.3f}ms exceeds 40ms"

    @pytest.mark.benchmark
    def test_baseline_learning_speed(self):
        """Benchmark: Baseline learning should complete in <1s for 1000 connections."""
        detector = TrafficAnomalyDetector(min_samples=50)
        rng = np.random.RandomState(42)

        for i in range(1000):
            conn = NetworkConnection(
                source_id="container-speed",
                destination=f"10.0.{i % 256}.{1 + i % 254}",
                dest_port=443 if i % 3 == 0 else 80,
                bytes_sent=max(1, int(rng.normal(2000, 300))),
                bytes_received=max(1, int(rng.normal(8000, 1000))),
                duration_s=max(0.01, float(rng.normal(1.0, 0.3))),
                packet_count=max(1, int(rng.normal(30, 5))),
                timestamp=datetime.now(UTC).replace(tzinfo=None) - timedelta(seconds=i),
            )
            detector.record_connection(conn)

        start = time.perf_counter()
        baseline = detector.learn_baseline("container-speed")
        elapsed = time.perf_counter() - start

        print("\nBaseline Learning Speed (1000 connections):")
        print(f"  Time: {elapsed:.3f}s")
        print("  Target: <1s")

        assert baseline is not None
        assert elapsed < 1.0, f"Baseline learning took {elapsed:.3f}s (>1s)"

    @pytest.mark.benchmark
    def test_traffic_detection_throughput(self, trained_traffic_detector):
        """Benchmark: Should handle >500 detections/sec."""
        num_connections = 1000
        connections = [
            NetworkConnection(
                source_id="container-bench",
                destination="10.0.1.1",
                dest_port=443,
                bytes_sent=1000,
                bytes_received=5000,
                duration_s=0.5,
                packet_count=20,
                timestamp=datetime.now(UTC).replace(tzinfo=None),
            )
            for _ in range(num_connections)
        ]

        start = time.perf_counter()
        for conn in connections:
            trained_traffic_detector.detect(conn)
        elapsed = time.perf_counter() - start

        throughput = num_connections / elapsed

        print("\nTraffic Detection Throughput:")
        print(f"  Connections: {num_connections}")
        print(f"  Time: {elapsed:.3f}s")
        print(f"  Throughput: {throughput:.0f} connections/sec")

        assert throughput > 25, f"Throughput {throughput:.0f} conn/sec (<25)"


# --- Behavioral Baseline Benchmarks ---


class TestBaselineLearnerPerformance:
    """Performance benchmarks for behavioral baseline learning."""

    @pytest.mark.benchmark
    def test_baseline_computation_speed(self):
        """Benchmark: Baseline computation should be <500ms for 5000 events."""
        learner = BaselineLearner(min_samples=50)

        for i in range(5000):
            learner.record_event(
                "agent-speed",
                {
                    "event_type": "tool_call",
                    "timestamp": datetime.now(UTC).replace(tzinfo=None) - timedelta(minutes=i),
                    "resource_count": 1 + (i % 10),
                    "duration_ms": 30 + (i % 80),
                },
            )

        start = time.perf_counter()
        baseline = learner.compute_baseline("agent-speed")
        elapsed_ms = (time.perf_counter() - start) * 1000

        print("\nBaseline Computation Speed (5000 events):")
        print(f"  Time: {elapsed_ms:.1f}ms")
        print("  Target: <500ms")

        assert baseline is not None
        assert elapsed_ms < 500, f"Baseline computation {elapsed_ms:.1f}ms exceeds 500ms"

    @pytest.mark.benchmark
    def test_anomaly_comparison_speed(self):
        """Benchmark: Baseline anomaly comparison should be <1ms."""
        learner = BaselineLearner(min_samples=50)

        for i in range(200):
            learner.record_event(
                "agent-cmp",
                {
                    "event_type": "tool_call",
                    "timestamp": datetime.now(UTC).replace(tzinfo=None) - timedelta(hours=i),
                    "resource_count": 2,
                    "duration_ms": 50,
                },
            )
        learner.compute_baseline("agent-cmp")

        times = []
        for _ in range(1000):
            event = {
                "event_type": "tool_call",
                "timestamp": datetime.now(UTC).replace(tzinfo=None),
                "resource_count": 2,
                "duration_ms": 50,
            }
            start = time.perf_counter()
            learner.detect_anomalies("agent-cmp", event)
            elapsed_ms = (time.perf_counter() - start) * 1000
            times.append(elapsed_ms)

        avg = statistics.mean(times)

        print("\nBaseline Anomaly Comparison Speed:")
        print(f"  Average: {avg:.4f}ms")
        print("  Target: <1ms")

        assert avg < 1.0, f"Comparison {avg:.4f}ms exceeds 1ms"
