"""Audit logger for MCP Gateway operations.

This module provides structured logging with async writes, sensitive data redaction,
and correlation tracking. Integrates with AuditDatabase for persistent storage.

Features:
- Async writes (non-blocking)
- Request correlation tracking
- Sensitive data redaction
- Context propagation
- Thread-safe operations
"""

import asyncio
import contextlib
import hashlib
import re
import uuid
from typing import Any, ClassVar

from .audit_db import (
    AuditDatabase,
    AuditEvent,
    AuditProofRecord,
    EventType,
    SecurityDecision,
    SecurityDecisionRecord,
    ToolCallRecord,
)


class SensitiveDataRedactor:
    """Redact sensitive information from audit logs.

    Detects and redacts:
    - API keys and tokens
    - Passwords and secrets
    - Credit card numbers
    - Email addresses (optionally)
    - File paths with credentials
    """

    # Common patterns for sensitive data
    PATTERNS: ClassVar[dict[str, re.Pattern]] = {
        "api_key": re.compile(
            r"(?i)(api[_-]?key|apikey|access[_-]?token|secret[_-]?key|bearer)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{20,})",
            re.IGNORECASE,
        ),
        "password": re.compile(
            r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]?([^'\"\s]+)",
            re.IGNORECASE,
        ),
        "jwt": re.compile(r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+"),
        "credit_card": re.compile(r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b"),
        "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
        "private_key": re.compile(
            r"-----BEGIN (RSA |EC )?PRIVATE KEY-----[\s\S]+?-----END (RSA |EC )?PRIVATE KEY-----"
        ),
        "env_secret": re.compile(
            r"(?i)(secret|token|key|password)=['\"]?([a-zA-Z0-9_\-\.]+)",
            re.IGNORECASE,
        ),
    }

    REDACTED_PLACEHOLDER = "[REDACTED]"

    @classmethod
    def redact(cls, text: str, preserve_length: bool = False) -> str:
        """Redact sensitive data from text.

        Args:
            text: Text to redact
            preserve_length: If True, preserve original length with asterisks

        Returns:
            Redacted text
        """
        if not text:
            return text

        result = text

        # Apply all patterns
        for pattern_name, pattern in cls.PATTERNS.items():
            if pattern_name in ("api_key", "password", "env_secret"):
                # For key=value patterns, redact only the value
                result = pattern.sub(
                    lambda m: f"{m.group(1)}={cls._redact_value(m.group(2), preserve_length)}",
                    result,
                )
            else:
                # For standalone patterns, redact the entire match
                result = pattern.sub(
                    lambda m: cls._redact_value(m.group(0), preserve_length), result
                )

        return result

    @classmethod
    def _redact_value(cls, value: str, preserve_length: bool = False) -> str:
        """Redact a single value.

        Args:
            value: Value to redact
            preserve_length: If True, use asterisks to preserve length

        Returns:
            Redacted value
        """
        if preserve_length:
            return "*" * len(value)
        return cls.REDACTED_PLACEHOLDER

    @classmethod
    def redact_dict(cls, data: dict[str, Any]) -> dict[str, Any]:
        """Redact sensitive data from dictionary.

        Args:
            data: Dictionary to redact

        Returns:
            Redacted dictionary (new copy)
        """
        # Sensitive key patterns
        sensitive_keys = {
            "password",
            "passwd",
            "pwd",
            "secret",
            "token",
            "key",
            "api_key",
            "apikey",
            "access_token",
            "auth_token",
            "bearer",
            "private_key",
            "secret_key",
            "client_secret",
        }

        result = {}
        for key, value in data.items():
            # Check if key is sensitive
            key_lower = key.lower().replace("-", "_")
            is_sensitive_key = any(sens in key_lower for sens in sensitive_keys)

            if isinstance(value, str):
                if is_sensitive_key and value:
                    # Redact entire value if key is sensitive
                    result[key] = cls.REDACTED_PLACEHOLDER
                else:
                    # Otherwise redact patterns within value
                    result[key] = cls.redact(value)
            elif isinstance(value, dict):
                result[key] = cls.redact_dict(value)
            elif isinstance(value, list):
                result[key] = [
                    cls.redact_dict(item) if isinstance(item, dict) else item for item in value
                ]
            else:
                result[key] = value
        return result

    @classmethod
    def hash_sensitive(cls, value: str) -> str:
        """Create a hash of sensitive value for correlation.

        Useful for tracking the same credential without logging it.

        Args:
            value: Sensitive value to hash

        Returns:
            SHA256 hash (first 16 characters)
        """
        return hashlib.sha256(value.encode()).hexdigest()[:16]


class AuditLogger:
    """Async audit logger with sensitive data redaction.

    Provides non-blocking audit logging with automatic correlation tracking
    and sensitive data redaction. Integrates with AuditDatabase for storage.

    Usage:
        logger = AuditLogger(db_path="~/.harombe/audit.db")

        # Log a request
        correlation_id = logger.start_request(
            actor="agent-123",
            tool_name="filesystem",
            action="read_file",
            metadata={"path": "/etc/passwd"}
        )

        # Log the response
        logger.end_request(
            correlation_id=correlation_id,
            status="success",
            duration_ms=150
        )
    """

    def __init__(
        self,
        db_path: str = "~/.harombe/audit.db",
        retention_days: int = 90,
        redact_sensitive: bool = True,
        enable_zkp: bool = False,
    ):
        """Initialize audit logger.

        Args:
            db_path: Path to audit database
            retention_days: Number of days to retain logs
            redact_sensitive: If True, redact sensitive data
            enable_zkp: If True, enable ZKP audit proof generation
        """
        self.db = AuditDatabase(db_path=db_path, retention_days=retention_days)
        self.redact_sensitive = redact_sensitive
        self.enable_zkp = enable_zkp
        self._write_queue: asyncio.Queue[Any] = asyncio.Queue()
        self._writer_task: asyncio.Task | None = None
        self._proof_generator: Any | None = None
        self._proof_verifier: Any | None = None

    async def start(self) -> None:
        """Start async log writer."""
        if self._writer_task is None or self._writer_task.done():
            self._writer_task = asyncio.create_task(self._write_worker())

    async def stop(self) -> None:
        """Stop async log writer."""
        if self._writer_task and not self._writer_task.done():
            await self._write_queue.join()
            self._writer_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._writer_task

    async def _write_worker(self) -> None:
        """Background worker for async writes."""
        while True:
            try:
                item = await self._write_queue.get()
                if item is None:  # Shutdown signal
                    break

                # Write to database
                record_type, record = item
                if record_type == "event":
                    self.db.log_event(record)
                elif record_type == "tool_call":
                    self.db.log_tool_call(record)
                elif record_type == "decision":
                    self.db.log_security_decision(record)
                elif record_type == "proof":
                    self.db.log_audit_proof(record)

                self._write_queue.task_done()
            except Exception as e:
                # Log errors but don't crash the worker
                print(f"Audit write error: {e}")

    def _redact_if_needed(self, data: Any) -> Any:
        """Redact sensitive data if enabled.

        Args:
            data: Data to potentially redact

        Returns:
            Redacted data
        """
        if not self.redact_sensitive:
            return data

        if isinstance(data, str):
            return SensitiveDataRedactor.redact(data)
        elif isinstance(data, dict):
            return SensitiveDataRedactor.redact_dict(data)
        return data

    def start_request(
        self,
        actor: str,
        tool_name: str | None = None,
        action: str = "unknown",
        metadata: dict[str, Any] | None = None,
        session_id: str | None = None,
    ) -> str:
        """Log the start of a request.

        Args:
            actor: Agent or user identifier
            tool_name: Name of tool being called
            action: Action being performed
            metadata: Additional context
            session_id: Session identifier

        Returns:
            Correlation ID for this request
        """
        correlation_id = str(uuid.uuid4())

        # Redact metadata
        redacted_metadata = self._redact_if_needed(metadata or {})

        event = AuditEvent(
            correlation_id=correlation_id,
            session_id=session_id,
            event_type=EventType.REQUEST,
            actor=actor,
            tool_name=tool_name,
            action=action,
            metadata=redacted_metadata,
            status="pending",
        )

        # Queue for async write
        self._write_queue.put_nowait(("event", event))

        return correlation_id

    def end_request(
        self,
        correlation_id: str,
        status: str = "success",
        duration_ms: int | None = None,
        error_message: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Log the completion of a request.

        Args:
            correlation_id: Correlation ID from start_request
            status: "success", "error", or "timeout"
            duration_ms: Request duration in milliseconds
            error_message: Error message if status is "error"
            metadata: Additional response metadata
        """
        # Redact error message
        redacted_error = self._redact_if_needed(error_message) if error_message else None
        redacted_metadata = self._redact_if_needed(metadata or {})

        event = AuditEvent(
            correlation_id=correlation_id,
            event_type=EventType.RESPONSE,
            actor="system",
            action="response",
            metadata=redacted_metadata,
            duration_ms=duration_ms,
            status=status,
            error_message=redacted_error,
        )

        self._write_queue.put_nowait(("event", event))

    def log_tool_call(
        self,
        correlation_id: str,
        tool_name: str,
        method: str,
        parameters: dict[str, Any],
        result: dict[str, Any] | None = None,
        error: str | None = None,
        duration_ms: int | None = None,
        container_id: str | None = None,
        session_id: str | None = None,
    ) -> None:
        """Log a tool execution.

        Args:
            correlation_id: Request correlation ID
            tool_name: Name of tool
            method: Method/function called
            parameters: Tool parameters
            result: Tool result
            error: Error message if failed
            duration_ms: Execution duration
            container_id: Docker container ID
            session_id: Session identifier
        """
        # Redact sensitive data
        redacted_params = self._redact_if_needed(parameters)
        redacted_result = self._redact_if_needed(result) if result else None
        redacted_error = self._redact_if_needed(error) if error else None

        record = ToolCallRecord(
            correlation_id=correlation_id,
            session_id=session_id,
            tool_name=tool_name,
            method=method,
            parameters=redacted_params,
            result=redacted_result,
            error=redacted_error,
            duration_ms=duration_ms,
            container_id=container_id,
        )

        # Write directly to database (synchronous)
        self.db.log_tool_call(record)

    def log_security_decision(
        self,
        correlation_id: str,
        decision_type: str,
        decision: SecurityDecision,
        reason: str,
        actor: str,
        tool_name: str | None = None,
        context: dict[str, Any] | None = None,
        session_id: str | None = None,
    ) -> None:
        """Log a security decision.

        Args:
            correlation_id: Request correlation ID
            decision_type: Type of decision (authorization, egress, etc.)
            decision: Decision outcome
            reason: Reason for decision
            actor: Agent or user making the request
            tool_name: Tool involved in decision
            context: Additional context
            session_id: Session identifier
        """
        # Redact context
        redacted_context = self._redact_if_needed(context or {})

        record = SecurityDecisionRecord(
            correlation_id=correlation_id,
            session_id=session_id,
            decision_type=decision_type,
            decision=decision,
            reason=reason,
            context=redacted_context,
            tool_name=tool_name,
            actor=actor,
        )

        # Write directly to database (synchronous)
        self.db.log_security_decision(record)

    def log_error(
        self,
        correlation_id: str,
        actor: str,
        error_message: str,
        metadata: dict[str, Any] | None = None,
        session_id: str | None = None,
    ) -> None:
        """Log an error event.

        Args:
            correlation_id: Request correlation ID
            actor: Agent or user identifier
            error_message: Error description
            metadata: Additional context
            session_id: Session identifier
        """
        redacted_error = self._redact_if_needed(error_message)
        redacted_metadata = self._redact_if_needed(metadata or {})

        event = AuditEvent(
            correlation_id=correlation_id,
            session_id=session_id,
            event_type=EventType.ERROR,
            actor=actor,
            action="error",
            metadata=redacted_metadata,
            status="error",
            error_message=redacted_error,
        )

        self._write_queue.put_nowait(("event", event))

    def _get_proof_generator(self):
        """Lazily create and return the ZKP proof generator."""
        if self._proof_generator is None:
            from harombe.security.zkp.audit_proofs import AuditProofGenerator

            self._proof_generator = AuditProofGenerator()
        return self._proof_generator

    def _get_proof_verifier(self):
        """Lazily create and return the ZKP proof verifier."""
        if self._proof_verifier is None:
            from harombe.security.zkp.audit_proofs import AuditProofVerifier

            self._proof_verifier = AuditProofVerifier()
        return self._proof_verifier

    def generate_proof(
        self,
        proof_type: str,
        correlation_id: str | None = None,
        **kwargs: Any,
    ):
        """Generate a ZKP audit proof and persist it.

        Args:
            proof_type: Type of proof ("operation_count", "time_range",
                "policy_compliance", "resource_usage", "threshold_check")
            correlation_id: Optional correlation ID to link proof to audit events
            **kwargs: Proof-specific parameters

        Returns:
            AuditClaim if ZKP is enabled, None otherwise
        """
        if not self.enable_zkp:
            return None

        from harombe.security.zkp.audit_proofs import AuditClaim  # noqa: TC001

        generator = self._get_proof_generator()

        claim: AuditClaim | None = None
        if proof_type == "operation_count":
            claim = generator.prove_operation_count(
                actual_count=kwargs["actual_count"],
                claimed_min=kwargs["claimed_min"],
                claimed_max=kwargs["claimed_max"],
            )
        elif proof_type == "time_range":
            claim = generator.prove_time_range(
                timestamp=kwargs["timestamp"],
                range_start=kwargs["range_start"],
                range_end=kwargs["range_end"],
            )
        elif proof_type == "resource_usage":
            claim = generator.prove_resource_usage(
                actual_usage=kwargs["actual_usage"],
                limit=kwargs["limit"],
            )
        elif proof_type == "threshold_check":
            claim = generator.prove_threshold(
                value=kwargs["value"],
                threshold=kwargs["threshold"],
                above=kwargs.get("above", True),
            )

        if claim is not None:
            # Persist proof to database
            proof_record = AuditProofRecord(
                correlation_id=correlation_id,
                claim_type=claim.claim_type,
                description=claim.description,
                public_parameters=claim.public_parameters,
                proof_data=claim.proof_data,
            )
            self.db.log_audit_proof(proof_record)

        return claim

    def generate_proof_sync(
        self,
        proof_type: str,
        correlation_id: str | None = None,
        **kwargs: Any,
    ):
        """Synchronous version of generate_proof."""
        return self.generate_proof(proof_type, correlation_id, **kwargs)

    def verify_proof(self, claim) -> bool:
        """Verify a ZKP audit proof.

        Args:
            claim: AuditClaim to verify

        Returns:
            True if the proof is valid, False otherwise
        """
        if not self.enable_zkp:
            return False
        verifier = self._get_proof_verifier()
        return verifier.verify_claim(claim)

    # Synchronous methods for sync contexts
    def start_request_sync(
        self,
        actor: str,
        tool_name: str | None = None,
        action: str = "unknown",
        metadata: dict[str, Any] | None = None,
        session_id: str | None = None,
    ) -> str:
        """Synchronous version of start_request."""
        correlation_id = str(uuid.uuid4())
        redacted_metadata = self._redact_if_needed(metadata or {})

        event = AuditEvent(
            correlation_id=correlation_id,
            session_id=session_id,
            event_type=EventType.REQUEST,
            actor=actor,
            tool_name=tool_name,
            action=action,
            metadata=redacted_metadata,
            status="pending",
        )

        # Write synchronously
        self.db.log_event(event)
        return correlation_id

    def end_request_sync(
        self,
        correlation_id: str,
        status: str = "success",
        duration_ms: int | None = None,
        error_message: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Synchronous version of end_request."""
        redacted_error = self._redact_if_needed(error_message) if error_message else None
        redacted_metadata = self._redact_if_needed(metadata or {})

        event = AuditEvent(
            correlation_id=correlation_id,
            event_type=EventType.RESPONSE,
            actor="system",
            action="response",
            metadata=redacted_metadata,
            duration_ms=duration_ms,
            status=status,
            error_message=redacted_error,
        )

        self.db.log_event(event)
