"""Security layer for harombe.

Provides:
- MCP Gateway for tool routing and security enforcement
- Docker container management
- Audit logging with sensitive data redaction
- Security decision tracking
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

__all__ = [
    "AuditDatabase",
    "AuditEvent",
    "AuditLogger",
    "DockerManager",
    "EventType",
    "MCPGateway",
    "SecurityDecision",
    "SecurityDecisionRecord",
    "SensitiveDataRedactor",
    "ToolCallRecord",
]
