"""Tests for compliance report generation."""

import json
import tempfile
import time
from datetime import datetime
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
from harombe.security.compliance_reports import (
    ComplianceFramework,
    ComplianceReport,
    ComplianceReportGenerator,
    ControlAssessment,
    ControlStatus,
    Finding,
    ReportSection,
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
    # Add some events
    for i in range(10):
        event = AuditEvent(
            correlation_id=f"corr-{i}",
            session_id="sess-001",
            event_type=EventType.REQUEST,
            actor=f"agent-{i % 3}",
            tool_name="filesystem",
            action="read_file",
            metadata={"path": f"/data/file_{i}.txt", "redacted": "[REDACTED]"},
            status="success",
        )
        temp_db.log_event(event)

    # Add an error event
    error_event = AuditEvent(
        correlation_id="corr-error",
        session_id="sess-001",
        event_type=EventType.ERROR,
        actor="agent-0",
        action="write_file",
        metadata={},
        status="error",
        error_message="Permission denied",
    )
    temp_db.log_event(error_event)

    # Add security decisions
    for i in range(5):
        decision = SecurityDecisionRecord(
            correlation_id=f"corr-dec-{i}",
            session_id="sess-001",
            decision_type="authorization",
            decision=SecurityDecision.ALLOW,
            reason="Allowed by policy",
            context={"tool": "filesystem", "action": "read"},
            actor=f"agent-{i % 2}",
        )
        temp_db.log_security_decision(decision)

    # Add a denial
    deny_decision = SecurityDecisionRecord(
        correlation_id="corr-deny",
        session_id="sess-001",
        decision_type="egress",
        decision=SecurityDecision.DENY,
        reason="Blocked by policy",
        context={"destination": "evil.com"},
        actor="agent-0",
    )
    temp_db.log_security_decision(deny_decision)

    # Add tool calls
    for i in range(8):
        tool_call = ToolCallRecord(
            correlation_id=f"corr-tool-{i}",
            session_id="sess-001",
            tool_name="filesystem",
            method="read",
            parameters={"path": f"/data/file_{i}.txt"},
            result={"content": "data"},
            duration_ms=50 + i * 10,
        )
        temp_db.log_tool_call(tool_call)

    # Add an errored tool call
    error_tool = ToolCallRecord(
        correlation_id="corr-tool-err",
        session_id="sess-001",
        tool_name="filesystem",
        method="write",
        parameters={"path": "/etc/passwd"},
        error="Permission denied",
        duration_ms=10,
    )
    temp_db.log_tool_call(error_tool)

    return temp_db


@pytest.fixture
def generator(populated_db):
    """Create a compliance report generator with populated data."""
    return ComplianceReportGenerator(populated_db)


@pytest.fixture
def empty_generator(temp_db):
    """Create a generator with empty database."""
    return ComplianceReportGenerator(temp_db)


# --- Enum Tests ---


class TestComplianceFramework:
    def test_values(self):
        assert ComplianceFramework.PCI_DSS == "pci_dss"
        assert ComplianceFramework.GDPR == "gdpr"
        assert ComplianceFramework.SOC2 == "soc2"


class TestControlStatus:
    def test_values(self):
        assert ControlStatus.PASS == "pass"
        assert ControlStatus.FAIL == "fail"
        assert ControlStatus.PARTIAL == "partial"
        assert ControlStatus.NOT_APPLICABLE == "not_applicable"


# --- Model Tests ---


class TestFinding:
    def test_basic_finding(self):
        finding = Finding(title="Test", description="Test finding")
        assert finding.severity == "info"
        assert finding.control_id == ""
        assert finding.recommendation == ""

    def test_finding_with_all_fields(self):
        finding = Finding(
            title="High Risk",
            description="Critical issue found",
            severity="critical",
            control_id="PCI-3.4",
            recommendation="Fix immediately",
            evidence={"count": 10},
        )
        assert finding.severity == "critical"
        assert finding.evidence["count"] == 10


class TestControlAssessment:
    def test_basic_assessment(self):
        assessment = ControlAssessment(
            control_id="PCI-3.4",
            control_name="Data protection",
        )
        assert assessment.status == ControlStatus.PASS
        assert len(assessment.findings) == 0

    def test_failed_assessment(self):
        assessment = ControlAssessment(
            control_id="PCI-10.1",
            control_name="Audit logging",
            status=ControlStatus.FAIL,
            findings=[Finding(title="No logs", description="No audit logs found")],
        )
        assert assessment.status == ControlStatus.FAIL
        assert len(assessment.findings) == 1


class TestReportSection:
    def test_basic_section(self):
        section = ReportSection(title="Test Section")
        assert len(section.controls) == 0
        assert section.description == ""


class TestComplianceReport:
    def test_basic_report(self):
        report = ComplianceReport(
            framework=ComplianceFramework.PCI_DSS,
            title="Test Report",
            period_start=datetime(2026, 1, 1),
            period_end=datetime(2026, 2, 1),
        )
        assert report.framework == ComplianceFramework.PCI_DSS
        assert report.overall_status == ControlStatus.PASS
        assert report.report_id.startswith("report-")

    def test_report_with_findings(self):
        report = ComplianceReport(
            framework=ComplianceFramework.GDPR,
            title="GDPR Report",
            period_start=datetime(2026, 1, 1),
            period_end=datetime(2026, 2, 1),
            findings=[Finding(title="Issue", description="Found issue")],
            controls_failed=1,
            overall_status=ControlStatus.FAIL,
        )
        assert len(report.findings) == 1
        assert report.overall_status == ControlStatus.FAIL


# --- PCI DSS Report Tests ---


class TestPCIDSSReport:
    def test_generate_pci_dss(self, generator):
        report = generator.generate(
            framework=ComplianceFramework.PCI_DSS,
            start=datetime(2025, 1, 1),
            end=datetime(2027, 1, 1),
        )
        assert report.framework == ComplianceFramework.PCI_DSS
        assert report.title == "PCI DSS Compliance Report"
        assert len(report.sections) == 3
        assert report.total_controls > 0

    def test_pci_dss_sections(self, generator):
        report = generator.generate(
            framework=ComplianceFramework.PCI_DSS,
            start=datetime(2025, 1, 1),
            end=datetime(2027, 1, 1),
        )
        section_titles = [s.title for s in report.sections]
        assert any("Requirement 3" in t for t in section_titles)
        assert any("Requirement 7" in t for t in section_titles)
        assert any("Requirement 10" in t for t in section_titles)

    def test_pci_dss_controls(self, generator):
        report = generator.generate(
            framework=ComplianceFramework.PCI_DSS,
            start=datetime(2025, 1, 1),
            end=datetime(2027, 1, 1),
        )
        all_controls = [c for s in report.sections for c in s.controls]
        control_ids = [c.control_id for c in all_controls]
        assert "PCI-3.4" in control_ids
        assert "PCI-7.1" in control_ids
        assert "PCI-10.1" in control_ids
        assert "PCI-10.5" in control_ids

    def test_pci_dss_with_populated_data(self, generator):
        report = generator.generate(
            framework=ComplianceFramework.PCI_DSS,
            start=datetime(2025, 1, 1),
            end=datetime(2027, 1, 1),
        )
        # With proper data, most controls should pass
        assert report.controls_passed >= 2

    def test_pci_dss_empty_db(self, empty_generator):
        report = empty_generator.generate(
            framework=ComplianceFramework.PCI_DSS,
            start=datetime(2025, 1, 1),
            end=datetime(2027, 1, 1),
        )
        # With empty db, audit logging check should fail
        assert report.total_controls > 0


# --- GDPR Report Tests ---


class TestGDPRReport:
    def test_generate_gdpr(self, generator):
        report = generator.generate(
            framework=ComplianceFramework.GDPR,
            start=datetime(2025, 1, 1),
            end=datetime(2027, 1, 1),
        )
        assert report.framework == ComplianceFramework.GDPR
        assert report.title == "GDPR Compliance Report"
        assert len(report.sections) == 4

    def test_gdpr_sections(self, generator):
        report = generator.generate(
            framework=ComplianceFramework.GDPR,
            start=datetime(2025, 1, 1),
            end=datetime(2027, 1, 1),
        )
        section_titles = [s.title for s in report.sections]
        assert any("Article 5" in t for t in section_titles)
        assert any("Article 25" in t for t in section_titles)
        assert any("Article 30" in t for t in section_titles)
        assert any("Article 32" in t for t in section_titles)

    def test_gdpr_controls(self, generator):
        report = generator.generate(
            framework=ComplianceFramework.GDPR,
            start=datetime(2025, 1, 1),
            end=datetime(2027, 1, 1),
        )
        all_controls = [c for s in report.sections for c in s.controls]
        control_ids = [c.control_id for c in all_controls]
        assert "GDPR-5.1f" in control_ids
        assert "GDPR-25.1" in control_ids
        assert "GDPR-30.1" in control_ids
        assert "GDPR-32.1" in control_ids


# --- SOC 2 Report Tests ---


class TestSOC2Report:
    def test_generate_soc2(self, generator):
        report = generator.generate(
            framework=ComplianceFramework.SOC2,
            start=datetime(2025, 1, 1),
            end=datetime(2027, 1, 1),
        )
        assert report.framework == ComplianceFramework.SOC2
        assert report.title == "SOC 2 Type II Compliance Report"
        assert len(report.sections) == 3

    def test_soc2_sections(self, generator):
        report = generator.generate(
            framework=ComplianceFramework.SOC2,
            start=datetime(2025, 1, 1),
            end=datetime(2027, 1, 1),
        )
        section_titles = [s.title for s in report.sections]
        assert any("CC6" in t for t in section_titles)
        assert any("CC7" in t for t in section_titles)
        assert any("CC8" in t for t in section_titles)

    def test_soc2_controls(self, generator):
        report = generator.generate(
            framework=ComplianceFramework.SOC2,
            start=datetime(2025, 1, 1),
            end=datetime(2027, 1, 1),
        )
        all_controls = [c for s in report.sections for c in s.controls]
        control_ids = [c.control_id for c in all_controls]
        assert "CC6.1" in control_ids
        assert "CC6.3" in control_ids
        assert "CC7.1" in control_ids
        assert "CC7.2" in control_ids
        assert "CC8.1" in control_ids


# --- Export Tests ---


class TestHTMLExport:
    def test_export_html(self, generator):
        report = generator.generate(
            framework=ComplianceFramework.PCI_DSS,
            start=datetime(2025, 1, 1),
            end=datetime(2027, 1, 1),
        )
        html = generator.export_html(report)
        assert "<!DOCTYPE html>" in html
        assert report.title in html
        assert "PCI" in html

    def test_html_contains_controls(self, generator):
        report = generator.generate(
            framework=ComplianceFramework.PCI_DSS,
            start=datetime(2025, 1, 1),
            end=datetime(2027, 1, 1),
        )
        html = generator.export_html(report)
        assert "PCI-3.4" in html
        assert "PCI-10.1" in html

    def test_html_contains_status(self, generator):
        report = generator.generate(
            framework=ComplianceFramework.PCI_DSS,
            start=datetime(2025, 1, 1),
            end=datetime(2027, 1, 1),
        )
        html = generator.export_html(report)
        assert "PASS" in html

    def test_html_contains_report_id(self, generator):
        report = generator.generate(
            framework=ComplianceFramework.PCI_DSS,
            start=datetime(2025, 1, 1),
            end=datetime(2027, 1, 1),
        )
        html = generator.export_html(report)
        assert report.report_id in html


class TestJSONExport:
    def test_export_json(self, generator):
        report = generator.generate(
            framework=ComplianceFramework.SOC2,
            start=datetime(2025, 1, 1),
            end=datetime(2027, 1, 1),
        )
        json_str = generator.export_json(report)
        data = json.loads(json_str)
        assert data["framework"] == "soc2"
        assert data["title"] == "SOC 2 Type II Compliance Report"

    def test_json_roundtrip(self, generator):
        report = generator.generate(
            framework=ComplianceFramework.GDPR,
            start=datetime(2025, 1, 1),
            end=datetime(2027, 1, 1),
        )
        json_str = generator.export_json(report)
        data = json.loads(json_str)
        assert data["framework"] == "gdpr"
        assert len(data["sections"]) == 4


# --- Statistics Tests ---


class TestReportStatistics:
    def test_stats_after_generation(self, generator):
        generator.generate(
            framework=ComplianceFramework.PCI_DSS,
            start=datetime(2025, 1, 1),
            end=datetime(2027, 1, 1),
        )
        stats = generator.get_stats()
        assert stats["reports_generated"] == 1
        assert stats["total_generation_time_ms"] > 0
        assert "pci_dss" in stats["per_framework"]

    def test_stats_multiple_reports(self, generator):
        for framework in [
            ComplianceFramework.PCI_DSS,
            ComplianceFramework.GDPR,
            ComplianceFramework.SOC2,
        ]:
            generator.generate(
                framework=framework,
                start=datetime(2025, 1, 1),
                end=datetime(2027, 1, 1),
            )
        stats = generator.get_stats()
        assert stats["reports_generated"] == 3
        assert len(stats["per_framework"]) == 3


# --- Summary/Status Tests ---


class TestReportSummary:
    def test_summary_generated(self, generator):
        report = generator.generate(
            framework=ComplianceFramework.PCI_DSS,
            start=datetime(2025, 1, 1),
            end=datetime(2027, 1, 1),
        )
        assert report.summary != ""
        assert "controls passed" in report.summary

    def test_controls_count(self, generator):
        report = generator.generate(
            framework=ComplianceFramework.SOC2,
            start=datetime(2025, 1, 1),
            end=datetime(2027, 1, 1),
        )
        assert report.total_controls == 5  # CC6.1, CC6.3, CC7.1, CC7.2, CC8.1
        assert (
            report.controls_passed + report.controls_failed + report.controls_partial
            == report.total_controls
        )

    def test_overall_status_pass(self, generator):
        report = generator.generate(
            framework=ComplianceFramework.PCI_DSS,
            start=datetime(2025, 1, 1),
            end=datetime(2027, 1, 1),
        )
        # With populated data, overall status should be PASS
        assert report.overall_status in (ControlStatus.PASS, ControlStatus.PARTIAL)

    def test_overall_status_fail_with_empty_db(self, empty_generator):
        report = empty_generator.generate(
            framework=ComplianceFramework.PCI_DSS,
            start=datetime(2025, 1, 1),
            end=datetime(2027, 1, 1),
        )
        # With empty db, audit logging check should fail
        assert report.controls_failed >= 1
        assert report.overall_status == ControlStatus.FAIL


# --- Performance Tests ---


class TestReportPerformance:
    def test_generation_performance(self, generator):
        """Report generation should be fast."""
        start = time.perf_counter()
        for _i in range(10):
            generator.generate(
                framework=ComplianceFramework.PCI_DSS,
                start=datetime(2025, 1, 1),
                end=datetime(2027, 1, 1),
            )
        elapsed_ms = (time.perf_counter() - start) * 1000
        # 10 reports should take <5000ms
        assert elapsed_ms < 5000, f"10 reports took {elapsed_ms:.1f}ms"


# --- Edge Cases ---


class TestEdgeCases:
    def test_invalid_framework(self, generator):
        with pytest.raises(ValueError, match="Unsupported framework"):
            generator.generate(
                framework="invalid",
                start=datetime(2025, 1, 1),
                end=datetime(2027, 1, 1),
            )

    def test_all_frameworks_generate(self, generator):
        for framework in ComplianceFramework:
            report = generator.generate(
                framework=framework,
                start=datetime(2025, 1, 1),
                end=datetime(2027, 1, 1),
            )
            assert report.total_controls > 0
            assert report.summary != ""

    def test_findings_collected(self, empty_generator):
        report = empty_generator.generate(
            framework=ComplianceFramework.PCI_DSS,
            start=datetime(2025, 1, 1),
            end=datetime(2027, 1, 1),
        )
        # Empty DB should produce at least one finding
        assert len(report.findings) >= 1
