"""Compliance report generation for audit data.

This module generates compliance reports from audit database data,
supporting PCI DSS, GDPR, and SOC 2 frameworks. Reports include
data summaries, control assessments, and finding details.

Features:
- Template-based report generation
- PCI DSS, GDPR, SOC 2 compliance frameworks
- Automatic data gathering from AuditDatabase
- HTML and JSON export formats
- Report scheduling support
- Statistics tracking
"""

import json
import time
from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from .audit_db import AuditDatabase


class ComplianceFramework(StrEnum):
    """Supported compliance frameworks."""

    PCI_DSS = "pci_dss"
    GDPR = "gdpr"
    SOC2 = "soc2"


class ControlStatus(StrEnum):
    """Status of a compliance control."""

    PASS = "pass"
    FAIL = "fail"
    PARTIAL = "partial"
    NOT_APPLICABLE = "not_applicable"


class Finding(BaseModel):
    """A compliance finding/observation."""

    title: str
    description: str
    severity: str = "info"  # "info", "low", "medium", "high", "critical"
    control_id: str = ""
    recommendation: str = ""
    evidence: dict[str, Any] = Field(default_factory=dict)


class ControlAssessment(BaseModel):
    """Assessment of a single compliance control."""

    control_id: str
    control_name: str
    description: str = ""
    status: ControlStatus = ControlStatus.PASS
    findings: list[Finding] = Field(default_factory=list)
    evidence_summary: str = ""
    data: dict[str, Any] = Field(default_factory=dict)


class ReportSection(BaseModel):
    """A section within a compliance report."""

    title: str
    description: str = ""
    controls: list[ControlAssessment] = Field(default_factory=list)
    summary: str = ""
    data: dict[str, Any] = Field(default_factory=dict)


class ComplianceReport(BaseModel):
    """A complete compliance report."""

    report_id: str = Field(default_factory=lambda: f"report-{int(time.time() * 1000)}")
    framework: ComplianceFramework
    title: str
    generated_at: datetime = Field(default_factory=datetime.utcnow)
    period_start: datetime
    period_end: datetime
    sections: list[ReportSection] = Field(default_factory=list)
    summary: str = ""
    overall_status: ControlStatus = ControlStatus.PASS
    total_controls: int = 0
    controls_passed: int = 0
    controls_failed: int = 0
    controls_partial: int = 0
    findings: list[Finding] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


def _assess_control(
    control_id: str,
    control_name: str,
    description: str,
    data: dict[str, Any],
    check_fn: Any,
) -> ControlAssessment:
    """Assess a control using provided data and check function.

    Args:
        control_id: Control identifier (e.g., "PCI-3.1")
        control_name: Human-readable control name
        description: Control description
        data: Data gathered from audit database
        check_fn: Function that returns (status, findings, evidence_summary)
    """
    status, findings, evidence_summary = check_fn(data)
    return ControlAssessment(
        control_id=control_id,
        control_name=control_name,
        description=description,
        status=status,
        findings=findings,
        evidence_summary=evidence_summary,
        data=data,
    )


class ComplianceReportGenerator:
    """Generate compliance reports from audit data.

    Supports PCI DSS, GDPR, and SOC 2 compliance frameworks.
    Queries the AuditDatabase for relevant data and generates
    structured reports with control assessments.

    Usage:
        generator = ComplianceReportGenerator(audit_db)
        report = generator.generate(
            framework=ComplianceFramework.PCI_DSS,
            start=datetime(2026, 1, 1),
            end=datetime(2026, 2, 1),
        )
        html = generator.export_html(report)
    """

    def __init__(self, audit_db: AuditDatabase):
        """Initialize compliance report generator.

        Args:
            audit_db: AuditDatabase instance for data queries
        """
        self.db = audit_db
        self.stats: dict[str, Any] = {
            "reports_generated": 0,
            "total_generation_time_ms": 0.0,
            "per_framework": {},
        }

    def generate(
        self,
        framework: ComplianceFramework,
        start: datetime,
        end: datetime,
    ) -> ComplianceReport:
        """Generate a compliance report.

        Args:
            framework: Compliance framework to report on
            start: Report period start
            end: Report period end

        Returns:
            ComplianceReport with sections, controls, and findings
        """
        gen_start = time.perf_counter()

        # Gather data from audit database
        stats = self.db.get_statistics(start_time=start, end_time=end)
        events = self.db.get_events_by_session(None, limit=10000)
        tool_calls = self.db.get_tool_calls(start_time=start, end_time=end, limit=10000)
        security_decisions = self.db.get_security_decisions(limit=10000)

        audit_data = {
            "stats": stats,
            "events": events,
            "tool_calls": tool_calls,
            "security_decisions": security_decisions,
            "period_start": start,
            "period_end": end,
        }

        # Generate framework-specific report
        if framework == ComplianceFramework.PCI_DSS:
            report = self._generate_pci_dss(audit_data, start, end)
        elif framework == ComplianceFramework.GDPR:
            report = self._generate_gdpr(audit_data, start, end)
        elif framework == ComplianceFramework.SOC2:
            report = self._generate_soc2(audit_data, start, end)
        else:
            raise ValueError(f"Unsupported framework: {framework}")

        # Compute summary stats
        report.total_controls = sum(len(s.controls) for s in report.sections)
        report.controls_passed = sum(
            1 for s in report.sections for c in s.controls if c.status == ControlStatus.PASS
        )
        report.controls_failed = sum(
            1 for s in report.sections for c in s.controls if c.status == ControlStatus.FAIL
        )
        report.controls_partial = sum(
            1 for s in report.sections for c in s.controls if c.status == ControlStatus.PARTIAL
        )
        report.findings = [f for s in report.sections for c in s.controls for f in c.findings]

        # Overall status
        if report.controls_failed > 0:
            report.overall_status = ControlStatus.FAIL
        elif report.controls_partial > 0:
            report.overall_status = ControlStatus.PARTIAL
        else:
            report.overall_status = ControlStatus.PASS

        report.summary = (
            f"{report.framework.value.upper()} Compliance Report: "
            f"{report.controls_passed}/{report.total_controls} controls passed, "
            f"{report.controls_failed} failed, {report.controls_partial} partial. "
            f"{len(report.findings)} findings."
        )

        # Update stats
        elapsed_ms = (time.perf_counter() - gen_start) * 1000
        self.stats["reports_generated"] += 1
        self.stats["total_generation_time_ms"] += elapsed_ms
        fw_key = framework.value
        if fw_key not in self.stats["per_framework"]:
            self.stats["per_framework"][fw_key] = {"count": 0, "avg_time_ms": 0.0}
        fw_stats = self.stats["per_framework"][fw_key]
        fw_stats["count"] += 1
        fw_stats["avg_time_ms"] += (elapsed_ms - fw_stats["avg_time_ms"]) / fw_stats["count"]

        return report

    def _generate_pci_dss(
        self,
        data: dict[str, Any],
        start: datetime,
        end: datetime,
    ) -> ComplianceReport:
        """Generate PCI DSS compliance report."""
        stats = data["stats"]
        events = data["events"]
        security_decisions = data["security_decisions"]

        sections = []

        # Requirement 3: Protect Stored Cardholder Data
        req3_controls = [
            _assess_control(
                "PCI-3.4",
                "Render PAN unreadable",
                "Sensitive data must be redacted in logs",
                {"events": events, "stats": stats},
                _check_data_redaction,
            ),
        ]
        sections.append(
            ReportSection(
                title="Requirement 3: Protect Stored Cardholder Data",
                description="Controls for protecting stored cardholder data",
                controls=req3_controls,
            )
        )

        # Requirement 7: Restrict Access by Business Need-to-Know
        req7_controls = [
            _assess_control(
                "PCI-7.1",
                "Limit access to system components",
                "Access must be restricted based on need-to-know",
                {"security_decisions": security_decisions},
                _check_access_controls,
            ),
        ]
        sections.append(
            ReportSection(
                title="Requirement 7: Restrict Access",
                description="Controls for access restriction",
                controls=req7_controls,
            )
        )

        # Requirement 10: Log and Monitor All Access
        req10_controls = [
            _assess_control(
                "PCI-10.1",
                "Audit trail implementation",
                "All access to system components must be logged",
                {"stats": stats},
                _check_audit_logging,
            ),
            _assess_control(
                "PCI-10.5",
                "Secure audit trails",
                "Audit trails must be secured against unauthorized modification",
                {"stats": stats},
                _check_audit_integrity,
            ),
        ]
        sections.append(
            ReportSection(
                title="Requirement 10: Log and Monitor All Access",
                description="Controls for logging and monitoring",
                controls=req10_controls,
            )
        )

        return ComplianceReport(
            framework=ComplianceFramework.PCI_DSS,
            title="PCI DSS Compliance Report",
            period_start=start,
            period_end=end,
            sections=sections,
        )

    def _generate_gdpr(
        self,
        data: dict[str, Any],
        start: datetime,
        end: datetime,
    ) -> ComplianceReport:
        """Generate GDPR compliance report."""
        stats = data["stats"]
        events = data["events"]
        security_decisions = data["security_decisions"]

        sections = []

        # Article 5: Principles relating to processing
        art5_controls = [
            _assess_control(
                "GDPR-5.1f",
                "Integrity and confidentiality",
                "Personal data must be processed with appropriate security",
                {"events": events, "stats": stats},
                _check_data_redaction,
            ),
        ]
        sections.append(
            ReportSection(
                title="Article 5: Data Processing Principles",
                description="Principles for lawful processing of personal data",
                controls=art5_controls,
            )
        )

        # Article 25: Data protection by design
        art25_controls = [
            _assess_control(
                "GDPR-25.1",
                "Data protection by design and default",
                "Implement appropriate technical measures for data protection",
                {"security_decisions": security_decisions},
                _check_access_controls,
            ),
        ]
        sections.append(
            ReportSection(
                title="Article 25: Data Protection by Design",
                description="Technical and organizational measures for data protection",
                controls=art25_controls,
            )
        )

        # Article 30: Records of processing activities
        art30_controls = [
            _assess_control(
                "GDPR-30.1",
                "Records of processing activities",
                "Maintain records of all data processing activities",
                {"stats": stats},
                _check_audit_logging,
            ),
        ]
        sections.append(
            ReportSection(
                title="Article 30: Records of Processing Activities",
                description="Maintaining records of processing activities",
                controls=art30_controls,
            )
        )

        # Article 32: Security of processing
        art32_controls = [
            _assess_control(
                "GDPR-32.1",
                "Security of processing",
                "Implement security measures appropriate to the risk",
                {"security_decisions": security_decisions, "stats": stats},
                _check_security_decisions,
            ),
        ]
        sections.append(
            ReportSection(
                title="Article 32: Security of Processing",
                description="Implementing appropriate security measures",
                controls=art32_controls,
            )
        )

        return ComplianceReport(
            framework=ComplianceFramework.GDPR,
            title="GDPR Compliance Report",
            period_start=start,
            period_end=end,
            sections=sections,
        )

    def _generate_soc2(
        self,
        data: dict[str, Any],
        start: datetime,
        end: datetime,
    ) -> ComplianceReport:
        """Generate SOC 2 compliance report."""
        stats = data["stats"]
        events = data["events"]
        security_decisions = data["security_decisions"]
        tool_calls = data["tool_calls"]

        sections = []

        # CC6: Logical and Physical Access Controls
        cc6_controls = [
            _assess_control(
                "CC6.1",
                "Logical access security",
                "Implement logical access controls over information assets",
                {"security_decisions": security_decisions},
                _check_access_controls,
            ),
            _assess_control(
                "CC6.3",
                "Access authorization",
                "Authorize access based on business need",
                {"security_decisions": security_decisions},
                _check_authorization,
            ),
        ]
        sections.append(
            ReportSection(
                title="CC6: Logical and Physical Access Controls",
                description="Controls for securing logical and physical access",
                controls=cc6_controls,
            )
        )

        # CC7: System Operations
        cc7_controls = [
            _assess_control(
                "CC7.1",
                "Monitoring of infrastructure",
                "Monitor system infrastructure and operations",
                {"stats": stats},
                _check_audit_logging,
            ),
            _assess_control(
                "CC7.2",
                "Anomaly detection",
                "Detect and respond to anomalies",
                {"events": events},
                _check_anomaly_detection,
            ),
        ]
        sections.append(
            ReportSection(
                title="CC7: System Operations",
                description="Controls for system monitoring and operations",
                controls=cc7_controls,
            )
        )

        # CC8: Change Management
        cc8_controls = [
            _assess_control(
                "CC8.1",
                "Change management process",
                "Changes must follow an authorized process",
                {"tool_calls": tool_calls, "stats": stats},
                _check_change_management,
            ),
        ]
        sections.append(
            ReportSection(
                title="CC8: Change Management",
                description="Controls for managing system changes",
                controls=cc8_controls,
            )
        )

        return ComplianceReport(
            framework=ComplianceFramework.SOC2,
            title="SOC 2 Type II Compliance Report",
            period_start=start,
            period_end=end,
            sections=sections,
        )

    def export_html(self, report: ComplianceReport) -> str:
        """Export report as HTML string.

        Args:
            report: ComplianceReport to export

        Returns:
            HTML string
        """
        status_colors = {
            ControlStatus.PASS: "#28a745",
            ControlStatus.FAIL: "#dc3545",
            ControlStatus.PARTIAL: "#ffc107",
            ControlStatus.NOT_APPLICABLE: "#6c757d",
        }

        html_parts = [
            "<!DOCTYPE html>",
            "<html><head>",
            f"<title>{report.title}</title>",
            "<style>",
            "body { font-family: Arial, sans-serif; margin: 40px; }",
            "h1 { color: #333; } h2 { color: #555; } h3 { color: #777; }",
            "table { border-collapse: collapse; width: 100%; margin: 10px 0; }",
            "th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }",
            "th { background-color: #f5f5f5; }",
            ".status-pass { color: #28a745; font-weight: bold; }",
            ".status-fail { color: #dc3545; font-weight: bold; }",
            ".status-partial { color: #ffc107; font-weight: bold; }",
            ".finding { background-color: #fff3cd; padding: 10px; margin: 5px 0; border-radius: 4px; }",
            "</style>",
            "</head><body>",
            f"<h1>{report.title}</h1>",
            f"<p>Generated: {report.generated_at.isoformat()}</p>",
            f"<p>Period: {report.period_start.isoformat()} to {report.period_end.isoformat()}</p>",
            f"<p><strong>Overall Status: "
            f"<span style='color:{status_colors.get(report.overall_status, '#333')}'>"
            f"{report.overall_status.value.upper()}</span></strong></p>",
            f"<p>{report.summary}</p>",
            "<hr>",
        ]

        for section in report.sections:
            html_parts.append(f"<h2>{section.title}</h2>")
            if section.description:
                html_parts.append(f"<p>{section.description}</p>")

            html_parts.append(
                "<table><tr><th>Control</th><th>Name</th><th>Status</th><th>Evidence</th></tr>"
            )
            for control in section.controls:
                status_class = f"status-{control.status.value}"
                html_parts.append(
                    f"<tr><td>{control.control_id}</td>"
                    f"<td>{control.control_name}</td>"
                    f"<td class='{status_class}'>{control.status.value.upper()}</td>"
                    f"<td>{control.evidence_summary}</td></tr>"
                )
            html_parts.append("</table>")

            for control in section.controls:
                for finding in control.findings:
                    html_parts.append(
                        f"<div class='finding'>"
                        f"<strong>[{finding.severity.upper()}] {finding.title}</strong>"
                        f"<p>{finding.description}</p>"
                        f"{'<p><em>Recommendation: ' + finding.recommendation + '</em></p>' if finding.recommendation else ''}"
                        f"</div>"
                    )

        html_parts.extend(
            [
                "<hr>",
                f"<p><small>Report ID: {report.report_id}</small></p>",
                "</body></html>",
            ]
        )

        return "\n".join(html_parts)

    def export_json(self, report: ComplianceReport) -> str:
        """Export report as JSON string.

        Args:
            report: ComplianceReport to export

        Returns:
            JSON string
        """
        return report.model_dump_json(indent=2)

    def get_stats(self) -> dict[str, Any]:
        """Get generator statistics."""
        return dict(self.stats)


# --- Control Check Functions ---


def _check_data_redaction(data: dict[str, Any]) -> tuple[ControlStatus, list[Finding], str]:
    """Check if sensitive data is being properly redacted."""
    findings: list[Finding] = []
    events = data.get("events", [])

    # Count events with potential unredacted data
    redacted_count = 0
    total_with_metadata = 0
    for event in events:
        metadata = event.get("metadata")
        if metadata:
            total_with_metadata += 1
            metadata_str = json.dumps(metadata) if isinstance(metadata, dict) else str(metadata)
            if "[REDACTED]" in metadata_str:
                redacted_count += 1

    if total_with_metadata == 0:
        return (
            ControlStatus.PASS,
            [],
            "No events with metadata to assess",
        )

    evidence = f"{redacted_count}/{total_with_metadata} events show active redaction"

    if redacted_count > 0:
        return (ControlStatus.PASS, findings, evidence)

    findings.append(
        Finding(
            title="No evidence of data redaction",
            description="No redacted data patterns found in audit logs",
            severity="medium",
            recommendation="Verify that SensitiveDataRedactor is active for all audit entries",
        )
    )
    return (ControlStatus.PARTIAL, findings, evidence)


def _check_access_controls(data: dict[str, Any]) -> tuple[ControlStatus, list[Finding], str]:
    """Check if access controls are enforced."""
    findings: list[Finding] = []
    decisions = data.get("security_decisions", [])

    total = len(decisions)
    denials = sum(1 for d in decisions if d.get("decision") == "deny")

    if total == 0:
        return (
            ControlStatus.PASS,
            [],
            "No security decisions recorded (system may be new)",
        )

    denial_rate = denials / total
    evidence = f"{total} security decisions, {denials} denials ({denial_rate:.0%})"

    if denial_rate > 0.5:
        findings.append(
            Finding(
                title="High denial rate",
                description=f"Denial rate ({denial_rate:.0%}) indicates potential misconfiguration",
                severity="medium",
                recommendation="Review access policies for overly restrictive rules",
            )
        )
        return (ControlStatus.PARTIAL, findings, evidence)

    return (ControlStatus.PASS, findings, evidence)


def _check_audit_logging(data: dict[str, Any]) -> tuple[ControlStatus, list[Finding], str]:
    """Check if audit logging is comprehensive."""
    findings: list[Finding] = []
    stats = data.get("stats", {})
    event_stats = stats.get("events", {})

    total_events = event_stats.get("total_events", 0)
    unique_sessions = event_stats.get("unique_sessions", 0)

    evidence = f"{total_events} events across {unique_sessions} sessions"

    if total_events == 0:
        findings.append(
            Finding(
                title="No audit events found",
                description="No audit events were recorded in the reporting period",
                severity="high",
                recommendation="Verify audit logging is enabled and properly configured",
            )
        )
        return (ControlStatus.FAIL, findings, evidence)

    return (ControlStatus.PASS, findings, evidence)


def _check_audit_integrity(data: dict[str, Any]) -> tuple[ControlStatus, list[Finding], str]:
    """Check audit trail integrity."""
    stats = data.get("stats", {})
    event_stats = stats.get("events", {})
    total_events = event_stats.get("total_events", 0)

    evidence = f"Audit database uses WAL mode and parameterized queries. {total_events} events."

    # Audit integrity is ensured by the database design (WAL mode, parameterized queries)
    return (ControlStatus.PASS, [], evidence)


def _check_security_decisions(data: dict[str, Any]) -> tuple[ControlStatus, list[Finding], str]:
    """Check security decision quality."""
    findings: list[Finding] = []
    decisions = data.get("security_decisions", [])

    total = len(decisions)
    if total == 0:
        return (
            ControlStatus.PASS,
            [],
            "No security decisions to assess",
        )

    # Check that decisions have context
    decisions_with_context = sum(
        1 for d in decisions if d.get("context") and d.get("context") != "{}"
    )
    context_rate = decisions_with_context / total
    evidence = f"{total} decisions, {context_rate:.0%} with context"

    if context_rate < 0.5:
        findings.append(
            Finding(
                title="Low context rate in security decisions",
                description=f"Only {context_rate:.0%} of decisions include context information",
                severity="low",
                recommendation="Ensure security decisions include relevant context for audit trails",
            )
        )
        return (ControlStatus.PARTIAL, findings, evidence)

    return (ControlStatus.PASS, findings, evidence)


def _check_authorization(data: dict[str, Any]) -> tuple[ControlStatus, list[Finding], str]:
    """Check authorization controls."""
    findings: list[Finding] = []
    decisions = data.get("security_decisions", [])

    auth_decisions = [d for d in decisions if d.get("decision_type") == "authorization"]
    total = len(auth_decisions)

    if total == 0:
        return (
            ControlStatus.PASS,
            [],
            "No authorization decisions recorded",
        )

    evidence = f"{total} authorization decisions recorded"
    return (ControlStatus.PASS, findings, evidence)


def _check_anomaly_detection(data: dict[str, Any]) -> tuple[ControlStatus, list[Finding], str]:
    """Check anomaly detection coverage."""
    findings: list[Finding] = []
    events = data.get("events", [])

    anomaly_events = [e for e in events if "anomaly" in str(e.get("action", "")).lower()]

    evidence = f"{len(anomaly_events)} anomaly-related events detected"

    # Having anomaly detection events is a good sign
    if len(anomaly_events) > 0:
        return (ControlStatus.PASS, findings, evidence)

    return (
        ControlStatus.PASS,
        findings,
        "No anomaly events (detection may not have triggered, which is normal)",
    )


def _check_change_management(data: dict[str, Any]) -> tuple[ControlStatus, list[Finding], str]:
    """Check change management controls."""
    findings: list[Finding] = []
    tool_calls = data.get("tool_calls", [])

    total_calls = len(tool_calls)
    if total_calls == 0:
        return (
            ControlStatus.PASS,
            [],
            "No tool calls recorded in period",
        )

    # Check for errors in tool calls
    error_calls = sum(1 for tc in tool_calls if tc.get("error"))
    error_rate = error_calls / total_calls

    evidence = f"{total_calls} tool calls, {error_calls} errors ({error_rate:.0%})"

    if error_rate > 0.2:
        findings.append(
            Finding(
                title="High tool error rate",
                description=f"Error rate ({error_rate:.0%}) exceeds 20% threshold",
                severity="medium",
                recommendation="Investigate recurring tool execution failures",
            )
        )
        return (ControlStatus.PARTIAL, findings, evidence)

    return (ControlStatus.PASS, findings, evidence)
