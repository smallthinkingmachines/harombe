"""Security layer for harombe.

Provides:
- MCP Gateway for tool routing and security enforcement
- Docker container management
- Audit logging with sensitive data redaction
- Security decision tracking
- Credential vault integration (Vault, SOPS, env)
- Secret scanning and detection
- Secure environment variable injection
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
from .docker_manager import DockerManager
from .gateway import MCPGateway
from .injection import DotEnvLoader, SecretInjector, SecretRotationScheduler, create_injector
from .secrets import SecretMatch, SecretScanner, SecretType
from .vault import (
    EnvVarBackend,
    HashiCorpVault,
    SOPSBackend,
    VaultBackend,
    create_vault_backend,
)

__all__ = [
    "AuditDatabase",
    "AuditEvent",
    "AuditLogger",
    "DockerManager",
    "DotEnvLoader",
    "EnvVarBackend",
    "EventType",
    "HashiCorpVault",
    "MCPGateway",
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
    "create_vault_backend",
]
