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
from .secrets import SecretMatch, SecretScanner, SecretType
from .vault import (
    EnvVarBackend,
    HashiCorpVault,
    SOPSBackend,
    VaultBackend,
    create_vault_backend,
)

__all__ = [
    "APIApprovalPrompt",
    "ApprovalDecision",
    "ApprovalStatus",
    "AuditDatabase",
    "AuditEvent",
    "AuditLogger",
    "BrowserContainerManager",
    "BrowserCredentials",
    "BrowserSession",
    "CLIApprovalPrompt",
    "DNSResolver",
    "DockerManager",
    "DotEnvLoader",
    "EgressFilter",
    "EnvVarBackend",
    "EventType",
    "HITLGate",
    "HITLRule",
    "HashiCorpVault",
    "MCPGateway",
    "NetworkIsolationManager",
    "NetworkMetrics",
    "NetworkMonitor",
    "NetworkPolicy",
    "Operation",
    "PendingApproval",
    "RiskClassifier",
    "RiskLevel",
    "SOPSBackend",
    "SecretInjector",
    "SecretMatch",
    "SecretRotationScheduler",
    "SecretScanner",
    "SecretType",
    "SecurityDecision",
    "SecurityDecisionRecord",
    "SensitiveDataRedactor",
    "ToolCallRecord",
    "VaultBackend",
    "create_injector",
    "create_prompt",
    "create_vault_backend",
]
