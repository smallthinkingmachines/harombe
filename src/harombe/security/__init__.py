"""Defense-in-depth security layer for harombe.

Implements the Capability-Container Pattern where every tool runs in its own
isolated container. The agent communicates through an MCP Gateway and never
directly touches raw credentials, host filesystems, or unrestricted networks.

Components:

- **MCP Gateway** (:class:`MCPGateway`) - Centralized routing and security enforcement
- **Container Management** (:class:`DockerManager`) - Container lifecycle with resource limits
- **Audit Logging** (:class:`AuditLogger`, :class:`AuditDatabase`) - Immutable event trail with redaction
- **Credential Vault** (:class:`HashiCorpVault`, :class:`SOPSBackend`, :class:`EnvVarBackend`) - Multi-backend secrets
- **Secret Scanning** (:class:`SecretScanner`) - Pattern and entropy-based credential detection
- **Network Isolation** (:class:`EgressFilter`, :class:`NetworkIsolationManager`) - Default-deny egress
- **HITL Gates** (:class:`HITLGate`, :class:`RiskClassifier`) - Risk-based approval workflows
- **Browser Container** (:class:`BrowserContainerManager`) - Pre-authenticated browser automation
- **Sandbox** (:class:`SandboxManager`) - gVisor-based code execution sandbox
- **Monitoring** (:class:`SecurityDashboard`, :class:`AlertRuleEngine`, :class:`SIEMIntegrator`) - Observability
- **Compliance** (:class:`ComplianceReportGenerator`) - SOC 2, GDPR, PCI DSS report generation
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
    AuditProofRecord,
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
from .zkp import (
    AuditClaim,
    AuditProofGenerator,
    AuditProofType,
    AuditProofVerifier,
    AuthorizationClaim,
    PedersenCommitment,
    PrivacyPreservingAuditLog,
    Proof,
    ProofType,
    RangeProof,
    SchnorrProof,
    VerificationResult,
    ZKPAuthorizationProvider,
    ZKPAuthorizationVerifier,
    ZKPContext,
    ZKPGateDecorator,
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
    "AuditClaim",
    "AuditDatabase",
    "AuditEvent",
    "AuditLogger",
    "AuditProofGenerator",
    "AuditProofRecord",
    "AuditProofType",
    "AuditProofVerifier",
    "AuthorizationClaim",
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
    "PedersenCommitment",
    "PendingApproval",
    "PrivacyPreservingAuditLog",
    "Proof",
    "ProofType",
    "Protocol",
    "ProtocolFilter",
    "ProtocolPolicy",
    "RangeProof",
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
    "SchnorrProof",
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
    "VerificationResult",
    "ZKPAuthorizationProvider",
    "ZKPAuthorizationVerifier",
    "ZKPContext",
    "ZKPGateDecorator",
    "create_injector",
    "create_prompt",
    "create_vault_backend",
    "get_allowed_registries",
    "get_browser_hitl_rules",
    "get_sandbox_hitl_rules",
    "get_sensitive_domains",
    "get_trusted_domains",
]
