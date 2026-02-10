"""Security layer for harombe.

Provides:
- MCP Gateway for tool routing and security enforcement
- Docker container management
- Audit logging with sensitive data redaction
- Security decision tracking
- Credential vault integration (Vault, SOPS, env)
- Secret scanning and detection
- Secure environment variable injection
- Human-in-the-Loop (HITL) approval gates
"""

from .alert_rules import (
    Alert,
    AlertCondition,
    AlertRule,
    AlertRuleEngine,
    AlertSeverity,
    EmailNotifier,
    NotificationChannel,
    NotificationResult,
    Notifier,
    PagerDutyNotifier,
    SlackNotifier,
)
from .audit_db import (
    AuditDatabase,
    AuditEvent,
    EventType,
    SecurityDecision,
    SecurityDecisionRecord,
    ToolCallRecord,
)
from .audit_logger import AuditLogger, SensitiveDataRedactor
from .browser_manager import BrowserContainerManager, BrowserCredentials, BrowserSession
from .browser_risk import get_browser_hitl_rules, get_sensitive_domains, get_trusted_domains
from .compliance_reports import (
    ComplianceFramework,
    ComplianceReport,
    ComplianceReportGenerator,
    ControlAssessment,
    ControlStatus,
    Finding,
    ReportSection,
)
from .dashboard import (
    DashboardMetrics,
    MetricsCache,
    MetricTrend,
    MetricValue,
    SecurityDashboard,
    TrendPoint,
)
from .docker_manager import DockerManager
from .gateway import MCPGateway
from .hitl import (
    ApprovalDecision,
    ApprovalStatus,
    HITLGate,
    HITLRule,
    Operation,
    PendingApproval,
    RiskClassifier,
    RiskLevel,
)
from .hitl_prompt import APIApprovalPrompt, CLIApprovalPrompt, create_prompt
from .injection import DotEnvLoader, SecretInjector, SecretRotationScheduler, create_injector
from .network import (
    DNSResolver,
    EgressFilter,
    NetworkIsolationManager,
    NetworkMetrics,
    NetworkMonitor,
    NetworkPolicy,
)
from .protocol_filter import (
    FilterResult,
    HTTPValidator,
    Protocol,
    ProtocolFilter,
    ProtocolPolicy,
)
from .sandbox_manager import (
    ExecutionResult,
    FileResult,
    InstallResult,
    Sandbox,
    SandboxManager,
)
from .sandbox_risk import get_allowed_registries, get_sandbox_hitl_rules
from .secrets import SecretMatch, SecretScanner, SecretType
from .siem_integration import (
    DatadogExporter,
    ElasticsearchExporter,
    ExportResult,
    SIEMConfig,
    SIEMEvent,
    SIEMExporter,
    SIEMIntegrator,
    SIEMPlatform,
    SplunkExporter,
)
from .vault import (
    EnvVarBackend,
    HashiCorpVault,
    SOPSBackend,
    VaultBackend,
    create_vault_backend,
)

__all__ = [
    "APIApprovalPrompt",
    "Alert",
    "AlertCondition",
    "AlertRule",
    "AlertRuleEngine",
    "AlertSeverity",
    "ApprovalDecision",
    "ApprovalStatus",
    "AuditDatabase",
    "AuditEvent",
    "AuditLogger",
    "BrowserContainerManager",
    "BrowserCredentials",
    "BrowserSession",
    "CLIApprovalPrompt",
    "ComplianceFramework",
    "ComplianceReport",
    "ComplianceReportGenerator",
    "ControlAssessment",
    "ControlStatus",
    "DNSResolver",
    "DashboardMetrics",
    "DatadogExporter",
    "DockerManager",
    "DotEnvLoader",
    "EgressFilter",
    "ElasticsearchExporter",
    "EmailNotifier",
    "EnvVarBackend",
    "EventType",
    "ExecutionResult",
    "ExportResult",
    "FileResult",
    "FilterResult",
    "Finding",
    "HITLGate",
    "HITLRule",
    "HTTPValidator",
    "HashiCorpVault",
    "InstallResult",
    "MCPGateway",
    "MetricTrend",
    "MetricValue",
    "MetricsCache",
    "NetworkIsolationManager",
    "NetworkMetrics",
    "NetworkMonitor",
    "NetworkPolicy",
    "NotificationChannel",
    "NotificationResult",
    "Notifier",
    "Operation",
    "PagerDutyNotifier",
    "PendingApproval",
    "Protocol",
    "ProtocolFilter",
    "ProtocolPolicy",
    "ReportSection",
    "RiskClassifier",
    "RiskLevel",
    "SIEMConfig",
    "SIEMEvent",
    "SIEMExporter",
    "SIEMIntegrator",
    "SIEMPlatform",
    "SOPSBackend",
    "Sandbox",
    "SandboxManager",
    "SecretInjector",
    "SecretMatch",
    "SecretRotationScheduler",
    "SecretScanner",
    "SecretType",
    "SecurityDashboard",
    "SecurityDecision",
    "SecurityDecisionRecord",
    "SensitiveDataRedactor",
    "SlackNotifier",
    "SplunkExporter",
    "ToolCallRecord",
    "TrendPoint",
    "VaultBackend",
    "create_injector",
    "create_prompt",
    "create_vault_backend",
    "get_allowed_registries",
    "get_browser_hitl_rules",
    "get_sandbox_hitl_rules",
    "get_sensitive_domains",
    "get_trusted_domains",
]
