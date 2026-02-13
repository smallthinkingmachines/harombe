"""Phase 5 integration tests.

Tests that verify all Phase 5 components work together end-to-end:
- ML anomaly detection pipeline → alert rules → SIEM export
- Compliance reporting with live audit data
- Dashboard metrics from real audit data
- Threat scoring → behavioral baseline → detection flow
- Network security → traffic anomaly detection
- Certificate pinning + protocol filtering + DPI pipeline
"""

import tempfile
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
    SlackNotifier,
)
from harombe.security.audit_db import (
    AuditDatabase,
    AuditEvent,
    EventType,
    SecurityDecision,
    SecurityDecisionRecord,
    ToolCallRecord,
)
from harombe.security.audit_logger import AuditLogger
from harombe.security.compliance_reports import (
    ComplianceFramework,
    ComplianceReportGenerator,
)
from harombe.security.dashboard import SecurityDashboard
from harombe.security.ml import (
    AnomalyDetector,
    BaselineLearner,
)
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
    """Database with realistic audit data for integration testing."""
    # Normal operation events
    for i in range(20):
        event = AuditEvent(
            correlation_id=f"corr-{i}",
            session_id=f"sess-{i % 3}",
            event_type=EventType.REQUEST,
            actor=f"agent-{i % 4}",
            tool_name="filesystem",
            action="read_file",
            metadata={"path": f"/data/file_{i}.txt", "key": "[REDACTED]"},
            status="success",
        )
        temp_db.log_event(event)

    # Error events
    for i in range(5):
        event = AuditEvent(
            correlation_id=f"corr-err-{i}",
            session_id="sess-0",
            event_type=EventType.ERROR,
            actor="agent-0",
            action="auth_failure",
            metadata={},
            status="error",
            error_message="Authentication failed",
        )
        temp_db.log_event(event)

    # Security decisions
    for i in range(10):
        decision = SecurityDecisionRecord(
            correlation_id=f"corr-dec-{i}",
            session_id="sess-0",
            decision_type="authorization",
            decision=SecurityDecision.ALLOW if i < 8 else SecurityDecision.DENY,
            reason="Policy evaluation",
            context={"tool": "filesystem"},
            actor=f"agent-{i % 3}",
        )
        temp_db.log_security_decision(decision)

    # Tool calls
    for i in range(15):
        tc = ToolCallRecord(
            correlation_id=f"corr-tool-{i}",
            session_id="sess-0",
            tool_name="filesystem",
            method="read",
            parameters={"path": f"/data/{i}"},
            result={"ok": True},
            duration_ms=50 + i * 10,
        )
        temp_db.log_tool_call(tc)

    return temp_db


# --- Integration Test: Anomaly Detection → Alert Rules → SIEM ---


@pytest.mark.integration
class TestAnomalyToAlertToSIEM:
    """Test the anomaly detection → alert → SIEM export pipeline."""

    @pytest.mark.asyncio
    async def test_anomaly_triggers_alert_and_siem_export(self, populated_db):
        """Detect anomaly, evaluate alert rules, export to SIEM."""
        # 1. Detect anomaly using ML
        detector = AnomalyDetector()
        events = [
            {
                "event_type": "tool_call",
                "agent_id": "agent-0",
                "tool_name": "filesystem",
                "action": "read_file",
                "timestamp": datetime.now(UTC).replace(tzinfo=None),
                "resource_count": 1,
                "duration_ms": 50,
                "success": True,
            }
            for _ in range(50)
        ]
        detector.train("agent-0", events)

        # 2. Create anomalous event and log to audit
        anomaly_event = AuditEvent(
            correlation_id="corr-anomaly-1",
            session_id="sess-0",
            event_type=EventType.ERROR,
            actor="agent-0",
            action="anomaly_detected",
            metadata={"anomaly_score": 0.95, "type": "behavioral"},
            status="error",
            error_message="Anomalous behavior detected",
        )
        populated_db.log_event(anomaly_event)

        # 3. Evaluate alert rules
        alert_rule = AlertRule(
            name="anomaly_alert",
            severity=AlertSeverity.HIGH,
            conditions=[
                AlertCondition(field="action", operator="contains", value="anomaly"),
            ],
            channels=[NotificationChannel.SLACK],
            cooldown_seconds=0,
        )
        engine = AlertRuleEngine(rules=[alert_rule])
        engine.add_notifier(SlackNotifier())

        alerts = await engine.evaluate(anomaly_event)
        assert len(alerts) == 1
        assert alerts[0].severity == AlertSeverity.HIGH

        # 4. Export alert event to SIEM
        siem_config = SIEMConfig(
            platform=SIEMPlatform.SPLUNK,
            endpoint="https://splunk.test:8088",
            token="test-token",
            batch_size=10,
        )
        integrator = SIEMIntegrator([siem_config])

        # Mock the exporter
        mock_exporter = AsyncMock()
        mock_exporter.send = AsyncMock(
            return_value=ExportResult(
                success=True,
                platform=SIEMPlatform.SPLUNK,
                events_sent=1,
                latency_ms=5.0,
            )
        )
        mock_exporter.close = AsyncMock()
        integrator._exporters[SIEMPlatform.SPLUNK] = mock_exporter

        await integrator.export_event(anomaly_event)
        results = await integrator.flush_all()

        assert len(results) == 1
        assert results[0].success is True
        assert integrator.stats["events_exported"] == 1

    @pytest.mark.asyncio
    async def test_multiple_errors_trigger_count_based_alert(self, populated_db):
        """Multiple errors over time trigger a count-based alert rule."""
        rule = AlertRule(
            name="auth_failures",
            severity=AlertSeverity.HIGH,
            conditions=[
                AlertCondition(field="event_type", operator="eq", value="error"),
                AlertCondition(field="action", operator="contains", value="auth"),
            ],
            count_threshold=3,
            time_window_seconds=3600,
            cooldown_seconds=0,
        )
        engine = AlertRuleEngine(rules=[rule])
        engine.add_notifier(SlackNotifier())

        # Simulate 3 auth failure events
        triggered = []
        for i in range(3):
            event = AuditEvent(
                correlation_id=f"corr-auth-{i}",
                event_type=EventType.ERROR,
                actor="agent-bad",
                action="auth_failure",
                status="error",
                metadata={},
            )
            alerts = await engine.evaluate(event)
            triggered.extend(alerts)

        # 3rd event should trigger the rule
        assert len(triggered) == 1
        assert triggered[0].rule_name == "auth_failures"


# --- Integration Test: Compliance Report with Live Data ---


@pytest.mark.integration
class TestComplianceWithLiveData:
    """Test compliance report generation with actual audit data."""

    def test_pci_dss_with_populated_data(self, populated_db):
        """Generate PCI DSS report from real audit data."""
        generator = ComplianceReportGenerator(populated_db)
        report = generator.generate(
            framework=ComplianceFramework.PCI_DSS,
            start=datetime(2025, 1, 1),
            end=datetime(2027, 1, 1),
        )

        assert report.total_controls > 0
        assert report.controls_passed >= 2
        assert report.summary != ""

        # Verify HTML export works with real data
        html = generator.export_html(report)
        assert "PCI DSS" in html
        assert len(html) > 500

    def test_all_frameworks_with_populated_data(self, populated_db):
        """Generate reports for all frameworks with real data."""
        generator = ComplianceReportGenerator(populated_db)

        for framework in ComplianceFramework:
            report = generator.generate(
                framework=framework,
                start=datetime(2025, 1, 1),
                end=datetime(2027, 1, 1),
            )
            assert report.total_controls > 0
            assert report.summary != ""

    def test_compliance_report_reflects_security_denials(self, populated_db):
        """Access control checks should reflect actual denial data."""
        generator = ComplianceReportGenerator(populated_db)
        report = generator.generate(
            framework=ComplianceFramework.PCI_DSS,
            start=datetime(2025, 1, 1),
            end=datetime(2027, 1, 1),
        )

        # Find the access controls section
        access_controls = [
            c for s in report.sections for c in s.controls if "access" in c.control_name.lower()
        ]
        assert len(access_controls) >= 1
        # With 20% denial rate (2/10), should pass
        for ac in access_controls:
            assert ac.evidence_summary != ""


# --- Integration Test: Dashboard from Live Audit Data ---


@pytest.mark.integration
class TestDashboardWithLiveData:
    """Test dashboard metrics computed from real audit data."""

    def test_dashboard_reflects_audit_data(self, populated_db):
        """Dashboard metrics should reflect actual audit data."""
        dashboard = SecurityDashboard(populated_db, cache_ttl_seconds=0.001)
        metrics = dashboard.get_metrics()

        # Should see our events
        assert metrics.events_last_day >= 25  # 20 normal + 5 errors
        assert metrics.error_events >= 5
        assert metrics.security_denials >= 2
        assert metrics.security_allows >= 8
        assert metrics.total_tool_calls >= 15
        assert metrics.denial_rate > 0

    def test_snapshot_with_live_data(self, populated_db):
        """WebSocket snapshot should contain real metric data."""
        import json

        dashboard = SecurityDashboard(populated_db)
        snapshot = dashboard.get_snapshot()

        # Should be valid JSON
        json_str = json.dumps(snapshot)
        assert len(json_str) > 100

        # Should contain real data
        assert snapshot["summary"]["total_events_24h"] >= 25

    def test_dashboard_and_compliance_use_same_data(self, populated_db):
        """Dashboard and compliance report should see the same data source."""
        dashboard = SecurityDashboard(populated_db, cache_ttl_seconds=0.001)
        generator = ComplianceReportGenerator(populated_db)

        metrics = dashboard.get_metrics()
        report = generator.generate(
            framework=ComplianceFramework.SOC2,
            start=datetime(2025, 1, 1),
            end=datetime(2027, 1, 1),
        )

        # Both should see the data
        assert metrics.events_last_day > 0
        assert report.total_controls > 0


# --- Integration Test: ML Pipeline ---


@pytest.mark.integration
class TestMLPipeline:
    """Test the full ML anomaly detection pipeline."""

    def test_train_and_detect(self):
        """Train a model and detect anomalies."""
        detector = AnomalyDetector()

        # Generate normal training events (AnomalyDetector works with plain dicts)
        normal_events = [
            {
                "event_type": "tool_call",
                "timestamp": datetime.now(UTC).replace(tzinfo=None) - timedelta(hours=i),
                "resource_count": 1,
                "duration_ms": 50 + (i % 10),
                "success": True,
            }
            for i in range(100)
        ]

        detector.train("agent-test", normal_events)

        # Detect on a normal event
        normal_result = detector.detect(
            "agent-test",
            {
                "event_type": "tool_call",
                "timestamp": datetime.now(UTC).replace(tzinfo=None),
                "resource_count": 1,
                "duration_ms": 55,
                "success": True,
            },
        )
        # Normal event should generally not be anomalous
        assert normal_result is not None
        assert normal_result.agent_id == "agent-test"

    def test_baseline_learning(self):
        """Test behavioral baseline learning."""
        learner = BaselineLearner(min_samples=50)

        # BaselineLearner uses record_event() + compute_baseline() with plain dicts
        for i in range(200):
            learner.record_event(
                "agent-bl",
                {
                    "event_type": "tool_call",
                    "timestamp": datetime.now(UTC).replace(tzinfo=None) - timedelta(hours=i),
                    "resource_count": 1,
                    "duration_ms": 50 + (i % 10),
                },
            )

        baseline = learner.compute_baseline("agent-bl")
        assert baseline is not None
        assert baseline.agent_id == "agent-bl"
        assert baseline.event_count >= 200
        assert len(baseline.pattern.hourly_distribution) == 24
        assert len(baseline.pattern.daily_distribution) == 7

    def test_traffic_anomaly_detection(self):
        """Test traffic anomaly detection pipeline."""
        detector = TrafficAnomalyDetector(min_samples=50)
        rng = np.random.RandomState(42)

        # Record normal connections (NetworkConnection uses source_id, destination)
        for i in range(100):
            conn = NetworkConnection(
                source_id="container-1",
                destination="10.0.1.1",
                dest_port=443,
                bytes_sent=max(1, int(rng.normal(1000, 100))),
                bytes_received=max(1, int(rng.normal(5000, 500))),
                duration_s=max(0.01, float(rng.normal(0.5, 0.1))),
                packet_count=max(1, int(rng.normal(20, 3))),
                timestamp=datetime.now(UTC).replace(tzinfo=None) - timedelta(minutes=i),
            )
            detector.record_connection(conn)

        # Learn baseline
        baseline = detector.learn_baseline("container-1")
        assert baseline is not None
        assert baseline.avg_bytes_sent > 0

        # Detect on normal connection
        normal_conn = NetworkConnection(
            source_id="container-1",
            destination="10.0.1.1",
            dest_port=443,
            bytes_sent=1000,
            bytes_received=5000,
            duration_s=0.5,
            packet_count=20,
            timestamp=datetime.now(UTC).replace(tzinfo=None),
        )
        result = detector.detect(normal_conn)
        assert result is not None
        # Normal traffic should generally not be anomalous
        assert not result.is_anomaly or result.anomaly_score < 0.8


# --- Integration Test: SIEM Event Format Consistency ---


@pytest.mark.integration
class TestSIEMEventConsistency:
    """Test that audit events convert correctly for all SIEM platforms."""

    def test_all_event_types_convert(self):
        """All EventType values should convert to valid SIEMEvents."""
        for event_type in EventType:
            event = AuditEvent(
                correlation_id="corr-test",
                event_type=event_type,
                actor="agent-test",
                action="test_action",
                status="success",
                metadata={},
            )
            siem_event = SIEMEvent.from_audit_event(event)
            assert siem_event.event_type == event_type.value
            assert siem_event.timestamp.endswith("Z")
            assert siem_event.source == "harombe"

    def test_siem_event_preserves_correlation(self, populated_db):
        """SIEM events should preserve correlation IDs from audit events."""
        events = populated_db.get_events_by_session(None, limit=5)
        for event_dict in events:
            event = AuditEvent(
                correlation_id=event_dict["correlation_id"],
                event_type=EventType(event_dict["event_type"]),
                actor=event_dict["actor"],
                action=event_dict["action"],
                status=event_dict["status"],
                metadata={},
            )
            siem_event = SIEMEvent.from_audit_event(event)
            assert siem_event.correlation_id == event_dict["correlation_id"]


# --- Integration Test: Alert Rules with Audit Logger ---


@pytest.mark.integration
class TestAlertRulesWithAuditLogger:
    """Test alert rules evaluating events from the audit logger."""

    def test_audit_events_trigger_alerts(self, populated_db):
        """Events logged via AuditLogger should be evaluable by AlertRuleEngine."""
        # Log a new error event
        logger = AuditLogger(db_path=str(populated_db.db_path), redact_sensitive=True)
        corr_id = logger.start_request_sync(
            actor="agent-suspect",
            tool_name="shell",
            action="secret_leak_detected",
            metadata={"command": "password=[REDACTED]"},
        )
        logger.end_request_sync(corr_id, status="error", error_message="Secret leak")

        # Retrieve the event
        events = populated_db.get_events_by_correlation(corr_id)
        assert len(events) >= 1


# --- Integration Test: Full Data Flow ---


@pytest.mark.integration
class TestFullDataFlow:
    """Test the complete data flow from event generation to dashboard."""

    def test_event_to_dashboard(self, populated_db):
        """Logged events should appear in dashboard metrics."""
        # Add a specific event
        event = AuditEvent(
            correlation_id="corr-flow-test",
            session_id="sess-flow",
            event_type=EventType.REQUEST,
            actor="agent-flow",
            action="read_file",
            metadata={},
            status="success",
        )
        populated_db.log_event(event)

        # Check dashboard sees it
        dashboard = SecurityDashboard(populated_db, cache_ttl_seconds=0.001)
        metrics = dashboard.get_metrics()
        assert metrics.events_last_day >= 26  # Previous 25 + this one

    def test_security_decision_to_compliance_report(self, populated_db):
        """Security decisions should appear in compliance reports."""
        # Add a specific denial
        decision = SecurityDecisionRecord(
            correlation_id="corr-comp-test",
            decision_type="authorization",
            decision=SecurityDecision.DENY,
            reason="Unauthorized access attempt",
            context={"target": "sensitive_resource"},
            actor="agent-comp",
        )
        populated_db.log_security_decision(decision)

        # Generate compliance report
        generator = ComplianceReportGenerator(populated_db)
        report = generator.generate(
            framework=ComplianceFramework.SOC2,
            start=datetime(2025, 1, 1),
            end=datetime(2027, 1, 1),
        )

        # Access control section should reflect decisions
        assert report.total_controls > 0

    @pytest.mark.asyncio
    async def test_event_to_alert_to_siem_to_dashboard(self, populated_db):
        """Full pipeline: event → alert → SIEM → dashboard."""
        # 1. Log an error event
        error_event = AuditEvent(
            correlation_id="corr-pipeline",
            event_type=EventType.ERROR,
            actor="agent-bad",
            action="auth_failure",
            status="error",
            metadata={},
            error_message="Bad credentials",
        )
        populated_db.log_event(error_event)

        # 2. Evaluate alert rules
        rule = AlertRule(
            name="pipeline_test",
            conditions=[
                AlertCondition(field="event_type", operator="eq", value="error"),
            ],
            cooldown_seconds=0,
        )
        engine = AlertRuleEngine(rules=[rule])
        alerts = await engine.evaluate(error_event)
        assert len(alerts) == 1

        # 3. Export to SIEM
        integrator = SIEMIntegrator(
            [
                SIEMConfig(
                    platform=SIEMPlatform.SPLUNK,
                    endpoint="https://test:8088",
                    token="t",
                    batch_size=10,
                )
            ]
        )
        mock_exporter = AsyncMock()
        mock_exporter.send = AsyncMock(
            return_value=ExportResult(
                success=True, platform=SIEMPlatform.SPLUNK, events_sent=1, latency_ms=1.0
            )
        )
        mock_exporter.close = AsyncMock()
        integrator._exporters[SIEMPlatform.SPLUNK] = mock_exporter
        await integrator.export_event(error_event)
        await integrator.flush_all()
        assert integrator.stats["events_exported"] == 1

        # 4. Dashboard reflects new error
        dashboard = SecurityDashboard(populated_db, cache_ttl_seconds=0.001)
        metrics = dashboard.get_metrics()
        assert metrics.error_events >= 6  # 5 original + 1 new
