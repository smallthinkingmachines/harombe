"""Audit database schema and operations.

This module provides SQLite-based audit logging for all MCP Gateway operations.
Audit logs capture requests, responses, tool calls, and security decisions for
compliance and security analysis.

Schema Design:
- audit_events: Core event log (request/response pairs)
- tool_calls: Tool execution details
- security_decisions: Authorization and security gate decisions
- audit_metadata: Session and correlation tracking

Retention Policy:
- Default: 90 days
- Configurable via harombe.yaml
- Automatic cleanup on startup
"""

import json
import sqlite3
import uuid
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


class EventType(StrEnum):
    """Audit event types."""

    REQUEST = "request"
    RESPONSE = "response"
    ERROR = "error"
    SECURITY_DECISION = "security_decision"
    TOOL_CALL = "tool_call"


class SecurityDecision(StrEnum):
    """Security decision outcomes."""

    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_CONFIRMATION = "require_confirmation"
    REDACTED = "redacted"


class AuditEvent(BaseModel):
    """Audit event record."""

    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    correlation_id: str  # Links request/response pairs
    session_id: str | None = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    event_type: EventType
    actor: str  # Agent/user identifier
    tool_name: str | None = None
    action: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    duration_ms: int | None = None
    status: str  # "success", "error", "pending"
    error_message: str | None = None


class ToolCallRecord(BaseModel):
    """Tool execution record."""

    call_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    correlation_id: str
    session_id: str | None = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    tool_name: str
    method: str
    parameters: dict[str, Any]
    result: dict[str, Any] | None = None
    error: str | None = None
    duration_ms: int | None = None
    container_id: str | None = None  # Docker container ID


class SecurityDecisionRecord(BaseModel):
    """Security decision record."""

    decision_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    correlation_id: str
    session_id: str | None = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    decision_type: str  # "authorization", "egress", "secret_scan", "hitl"
    decision: SecurityDecision
    reason: str
    context: dict[str, Any] = Field(default_factory=dict)
    tool_name: str | None = None
    actor: str


class AuditProofRecord(BaseModel):
    """ZKP audit proof record for persistent storage."""

    proof_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    correlation_id: str | None = None
    claim_type: str
    description: str = ""
    public_parameters: dict[str, Any] = Field(default_factory=dict)
    proof_data: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=datetime.utcnow)


class AuditDatabase:
    """SQLite-based audit log database.

    Thread-safe database operations for audit logging.
    Supports async writes, retention policies, and efficient queries.
    """

    SCHEMA_VERSION = 2

    def __init__(
        self,
        db_path: str | Path = "~/.harombe/audit.db",
        retention_days: int = 90,
    ):
        """Initialize audit database.

        Args:
            db_path: Path to SQLite database file
            retention_days: Number of days to retain audit logs
        """
        self.db_path = Path(db_path).expanduser()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.retention_days = retention_days
        self._initialize_schema()
        self._cleanup_old_records()

    def _get_connection(self) -> sqlite3.Connection:
        """Get database connection with optimized settings."""
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        # Enable WAL mode for better concurrency
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    def _initialize_schema(self) -> None:
        """Create database schema if not exists."""
        conn = self._get_connection()
        try:
            # Metadata table
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                """
            )

            # Check schema version
            cursor = conn.execute("SELECT value FROM audit_metadata WHERE key = 'schema_version'")
            row = cursor.fetchone()
            if row is None:
                conn.execute(
                    "INSERT INTO audit_metadata (key, value) VALUES ('schema_version', ?)",
                    (str(self.SCHEMA_VERSION),),
                )
                conn.commit()

            # Core audit events table
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_events (
                    event_id TEXT PRIMARY KEY,
                    correlation_id TEXT NOT NULL,
                    session_id TEXT,
                    timestamp TIMESTAMP NOT NULL,
                    event_type TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    tool_name TEXT,
                    action TEXT NOT NULL,
                    metadata TEXT,
                    duration_ms INTEGER,
                    status TEXT NOT NULL,
                    error_message TEXT
                )
                """
            )

            # Tool calls table
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS tool_calls (
                    call_id TEXT PRIMARY KEY,
                    correlation_id TEXT NOT NULL,
                    session_id TEXT,
                    timestamp TIMESTAMP NOT NULL,
                    tool_name TEXT NOT NULL,
                    method TEXT NOT NULL,
                    parameters TEXT NOT NULL,
                    result TEXT,
                    error TEXT,
                    duration_ms INTEGER,
                    container_id TEXT
                )
                """
            )

            # Security decisions table
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS security_decisions (
                    decision_id TEXT PRIMARY KEY,
                    correlation_id TEXT NOT NULL,
                    session_id TEXT,
                    timestamp TIMESTAMP NOT NULL,
                    decision_type TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    context TEXT,
                    tool_name TEXT,
                    actor TEXT NOT NULL
                )
                """
            )

            # Audit proofs table (ZKP)
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_proofs (
                    proof_id TEXT PRIMARY KEY,
                    correlation_id TEXT,
                    claim_type TEXT NOT NULL,
                    description TEXT,
                    public_parameters TEXT,
                    proof_data TEXT,
                    created_at TIMESTAMP NOT NULL
                )
                """
            )

            # Indexes for efficient queries
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_events_correlation
                ON audit_events(correlation_id)
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_events_session
                ON audit_events(session_id)
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_events_timestamp
                ON audit_events(timestamp)
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_events_tool
                ON audit_events(tool_name)
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_tools_correlation
                ON tool_calls(correlation_id)
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_tools_timestamp
                ON tool_calls(timestamp)
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_decisions_correlation
                ON security_decisions(correlation_id)
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_decisions_timestamp
                ON security_decisions(timestamp)
                """
            )

            # Audit proofs indexes
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_proofs_claim_type
                ON audit_proofs(claim_type)
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_proofs_created_at
                ON audit_proofs(created_at)
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_proofs_correlation_id
                ON audit_proofs(correlation_id)
                """
            )

            conn.commit()
        finally:
            conn.close()

    def _cleanup_old_records(self) -> None:
        """Delete records older than retention period."""
        if self.retention_days <= 0:
            return

        cutoff_date = datetime.now(UTC).replace(tzinfo=None) - timedelta(days=self.retention_days)
        conn = self._get_connection()
        try:
            # Clean up old events
            conn.execute("DELETE FROM audit_events WHERE timestamp < ?", (cutoff_date,))
            conn.execute("DELETE FROM tool_calls WHERE timestamp < ?", (cutoff_date,))
            conn.execute("DELETE FROM security_decisions WHERE timestamp < ?", (cutoff_date,))
            conn.execute("DELETE FROM audit_proofs WHERE created_at < ?", (cutoff_date,))
            conn.commit()

            # Vacuum to reclaim space
            conn.execute("VACUUM")
        finally:
            conn.close()

    def log_event(self, event: AuditEvent) -> None:
        """Log an audit event.

        Args:
            event: Audit event to log
        """
        conn = self._get_connection()
        try:
            conn.execute(
                """
                INSERT INTO audit_events (
                    event_id, correlation_id, session_id, timestamp,
                    event_type, actor, tool_name, action, metadata,
                    duration_ms, status, error_message
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.event_id,
                    event.correlation_id,
                    event.session_id,
                    event.timestamp,
                    event.event_type.value,
                    event.actor,
                    event.tool_name,
                    event.action,
                    json.dumps(event.metadata) if event.metadata else None,
                    event.duration_ms,
                    event.status,
                    event.error_message,
                ),
            )
            conn.commit()
        finally:
            conn.close()

    def log_tool_call(self, tool_call: ToolCallRecord) -> None:
        """Log a tool execution.

        Args:
            tool_call: Tool call record to log
        """
        conn = self._get_connection()
        try:
            conn.execute(
                """
                INSERT INTO tool_calls (
                    call_id, correlation_id, session_id, timestamp,
                    tool_name, method, parameters, result, error,
                    duration_ms, container_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    tool_call.call_id,
                    tool_call.correlation_id,
                    tool_call.session_id,
                    tool_call.timestamp,
                    tool_call.tool_name,
                    tool_call.method,
                    json.dumps(tool_call.parameters),
                    json.dumps(tool_call.result) if tool_call.result else None,
                    tool_call.error,
                    tool_call.duration_ms,
                    tool_call.container_id,
                ),
            )
            conn.commit()
        finally:
            conn.close()

    def log_security_decision(self, decision: SecurityDecisionRecord) -> None:
        """Log a security decision.

        Args:
            decision: Security decision record to log
        """
        conn = self._get_connection()
        try:
            conn.execute(
                """
                INSERT INTO security_decisions (
                    decision_id, correlation_id, session_id, timestamp,
                    decision_type, decision, reason, context, tool_name, actor
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    decision.decision_id,
                    decision.correlation_id,
                    decision.session_id,
                    decision.timestamp,
                    decision.decision_type,
                    decision.decision.value,
                    decision.reason,
                    json.dumps(decision.context) if decision.context else None,
                    decision.tool_name,
                    decision.actor,
                ),
            )
            conn.commit()
        finally:
            conn.close()

    def get_events_by_correlation(self, correlation_id: str) -> list[dict[str, Any]]:
        """Get all events for a correlation ID.

        Args:
            correlation_id: Correlation ID to query

        Returns:
            List of event dictionaries
        """
        conn = self._get_connection()
        try:
            cursor = conn.execute(
                """
                SELECT * FROM audit_events
                WHERE correlation_id = ?
                ORDER BY timestamp
                """,
                (correlation_id,),
            )
            return [dict(row) for row in cursor.fetchall()]
        finally:
            conn.close()

    def get_events_by_session(
        self,
        session_id: str | None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Get events for a session.

        Args:
            session_id: Session ID to query (None returns all events)
            limit: Maximum number of events to return
            offset: Number of events to skip

        Returns:
            List of event dictionaries
        """
        conn = self._get_connection()
        try:
            if session_id is None:
                cursor = conn.execute(
                    """
                    SELECT * FROM audit_events
                    ORDER BY timestamp DESC
                    LIMIT ? OFFSET ?
                    """,
                    (limit, offset),
                )
            else:
                cursor = conn.execute(
                    """
                    SELECT * FROM audit_events
                    WHERE session_id = ?
                    ORDER BY timestamp DESC
                    LIMIT ? OFFSET ?
                    """,
                    (session_id, limit, offset),
                )
            return [dict(row) for row in cursor.fetchall()]
        finally:
            conn.close()

    def get_tool_calls(
        self,
        tool_name: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Get tool call records.

        Args:
            tool_name: Filter by tool name (optional)
            start_time: Filter by start time (optional)
            end_time: Filter by end time (optional)
            limit: Maximum number of records to return

        Returns:
            List of tool call dictionaries
        """
        conn = self._get_connection()
        try:
            query = "SELECT * FROM tool_calls WHERE 1=1"
            params: list[Any] = []

            if tool_name:
                query += " AND tool_name = ?"
                params.append(tool_name)

            if start_time:
                query += " AND timestamp >= ?"
                params.append(start_time)

            if end_time:
                query += " AND timestamp <= ?"
                params.append(end_time)

            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)

            cursor = conn.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]
        finally:
            conn.close()

    def get_security_decisions(
        self,
        decision_type: str | None = None,
        decision: SecurityDecision | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Get security decision records.

        Args:
            decision_type: Filter by decision type (optional)
            decision: Filter by decision outcome (optional)
            start_time: Filter by start time (optional)
            end_time: Filter by end time (optional)
            limit: Maximum number of records to return

        Returns:
            List of security decision dictionaries
        """
        conn = self._get_connection()
        try:
            query = "SELECT * FROM security_decisions WHERE 1=1"
            params: list[Any] = []

            if decision_type:
                query += " AND decision_type = ?"
                params.append(decision_type)

            if decision:
                query += " AND decision = ?"
                params.append(decision.value)

            if start_time:
                query += " AND timestamp >= ?"
                params.append(start_time)

            if end_time:
                query += " AND timestamp <= ?"
                params.append(end_time)

            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)

            cursor = conn.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]
        finally:
            conn.close()

    def get_events_by_time_range(
        self,
        start_time: datetime,
        end_time: datetime,
        event_type: str | None = None,
        actor: str | None = None,
        limit: int = 10000,
    ) -> list[dict[str, Any]]:
        """Get audit events within a time range.

        Args:
            start_time: Start of time range
            end_time: End of time range
            event_type: Filter by event type (optional)
            actor: Filter by actor (optional)
            limit: Maximum number of records to return

        Returns:
            List of event dictionaries
        """
        conn = self._get_connection()
        try:
            query = "SELECT * FROM audit_events WHERE timestamp >= ? AND timestamp <= ?"
            params: list[Any] = [start_time, end_time]

            if event_type:
                query += " AND event_type = ?"
                params.append(event_type)

            if actor:
                query += " AND actor = ?"
                params.append(actor)

            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)

            cursor = conn.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]
        finally:
            conn.close()

    def log_audit_proof(self, proof: AuditProofRecord) -> None:
        """Log a ZKP audit proof.

        Args:
            proof: Audit proof record to log
        """
        conn = self._get_connection()
        try:
            conn.execute(
                """
                INSERT INTO audit_proofs (
                    proof_id, correlation_id, claim_type, description,
                    public_parameters, proof_data, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    proof.proof_id,
                    proof.correlation_id,
                    proof.claim_type,
                    proof.description,
                    json.dumps(proof.public_parameters) if proof.public_parameters else None,
                    json.dumps(proof.proof_data) if proof.proof_data else None,
                    proof.created_at,
                ),
            )
            conn.commit()
        finally:
            conn.close()

    def get_audit_proofs(
        self,
        claim_type: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        correlation_id: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Get ZKP audit proofs.

        Args:
            claim_type: Filter by claim type (optional)
            start_time: Filter by start time (optional)
            end_time: Filter by end time (optional)
            correlation_id: Filter by correlation ID (optional)
            limit: Maximum number of records to return

        Returns:
            List of audit proof dictionaries
        """
        conn = self._get_connection()
        try:
            query = "SELECT * FROM audit_proofs WHERE 1=1"
            params: list[Any] = []

            if claim_type:
                query += " AND claim_type = ?"
                params.append(claim_type)

            if start_time:
                query += " AND created_at >= ?"
                params.append(start_time)

            if end_time:
                query += " AND created_at <= ?"
                params.append(end_time)

            if correlation_id:
                query += " AND correlation_id = ?"
                params.append(correlation_id)

            query += " ORDER BY created_at DESC LIMIT ?"
            params.append(limit)

            cursor = conn.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]
        finally:
            conn.close()

    def get_statistics(
        self,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
    ) -> dict[str, Any]:
        """Get audit log statistics.

        Args:
            start_time: Start of time range (optional)
            end_time: End of time range (optional)

        Returns:
            Dictionary with statistics
        """
        conn = self._get_connection()
        try:
            time_filter = ""
            params: list[Any] = []

            if start_time:
                time_filter += " AND timestamp >= ?"
                params.append(start_time)

            if end_time:
                time_filter += " AND timestamp <= ?"
                params.append(end_time)

            # Event statistics
            cursor = conn.execute(
                f"""
                SELECT
                    COUNT(*) as total_events,
                    COUNT(DISTINCT session_id) as unique_sessions,
                    COUNT(DISTINCT correlation_id) as unique_requests
                FROM audit_events
                WHERE 1=1 {time_filter}
                """,
                params,
            )
            event_stats = dict(cursor.fetchone())

            # Tool call statistics
            cursor = conn.execute(
                f"""
                SELECT
                    tool_name,
                    COUNT(*) as call_count,
                    AVG(duration_ms) as avg_duration_ms
                FROM tool_calls
                WHERE 1=1 {time_filter}
                GROUP BY tool_name
                ORDER BY call_count DESC
                """,
                params,
            )
            tool_stats = [dict(row) for row in cursor.fetchall()]

            # Security decision statistics
            cursor = conn.execute(
                f"""
                SELECT
                    decision,
                    COUNT(*) as count
                FROM security_decisions
                WHERE 1=1 {time_filter}
                GROUP BY decision
                """,
                params,
            )
            decision_stats = [dict(row) for row in cursor.fetchall()]

            return {
                "events": event_stats,
                "tools": tool_stats,
                "security_decisions": decision_stats,
            }
        finally:
            conn.close()
