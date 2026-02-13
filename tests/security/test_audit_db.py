"""Tests for audit database."""

import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from harombe.security.audit_db import (
    AuditDatabase,
    AuditEvent,
    AuditProofRecord,
    EventType,
    SecurityDecision,
    SecurityDecisionRecord,
    ToolCallRecord,
)


@pytest.fixture
def temp_db():
    """Create temporary audit database."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    db = AuditDatabase(db_path=db_path, retention_days=0)  # Disable cleanup
    yield db

    # Cleanup
    Path(db_path).unlink(missing_ok=True)
    Path(f"{db_path}-shm").unlink(missing_ok=True)
    Path(f"{db_path}-wal").unlink(missing_ok=True)


def test_database_initialization(temp_db):
    """Test database schema initialization."""
    # Check tables exist
    conn = temp_db._get_connection()
    cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
    tables = [row[0] for row in cursor.fetchall()]
    conn.close()

    assert "audit_events" in tables
    assert "tool_calls" in tables
    assert "security_decisions" in tables
    assert "audit_metadata" in tables
    assert "audit_proofs" in tables


def test_log_event(temp_db):
    """Test logging audit events."""
    event = AuditEvent(
        correlation_id="test-123",
        session_id="session-1",
        event_type=EventType.REQUEST,
        actor="agent",
        tool_name="filesystem",
        action="read_file",
        metadata={"path": "/etc/passwd"},
        status="success",
        duration_ms=150,
    )

    temp_db.log_event(event)

    # Retrieve event
    events = temp_db.get_events_by_correlation("test-123")
    assert len(events) == 1
    assert events[0]["actor"] == "agent"
    assert events[0]["tool_name"] == "filesystem"
    assert events[0]["action"] == "read_file"
    assert events[0]["status"] == "success"


def test_log_tool_call(temp_db):
    """Test logging tool executions."""
    tool_call = ToolCallRecord(
        correlation_id="test-456",
        session_id="session-1",
        tool_name="browser",
        method="navigate",
        parameters={"url": "https://example.com"},
        result={"status": "ok"},
        duration_ms=500,
        container_id="browser-container:3000",
    )

    temp_db.log_tool_call(tool_call)

    # Retrieve tool calls
    calls = temp_db.get_tool_calls(tool_name="browser")
    assert len(calls) == 1
    assert calls[0]["method"] == "navigate"
    assert calls[0]["duration_ms"] == 500
    assert calls[0]["container_id"] == "browser-container:3000"


def test_log_security_decision(temp_db):
    """Test logging security decisions."""
    decision = SecurityDecisionRecord(
        correlation_id="test-789",
        session_id="session-1",
        decision_type="authorization",
        decision=SecurityDecision.ALLOW,
        reason="Tool is on allowlist",
        context={"tool": "filesystem", "action": "read"},
        tool_name="filesystem",
        actor="agent",
    )

    temp_db.log_security_decision(decision)

    # Retrieve decisions
    decisions = temp_db.get_security_decisions()
    assert len(decisions) == 1
    assert decisions[0]["decision_type"] == "authorization"
    assert decisions[0]["decision"] == "allow"
    assert decisions[0]["reason"] == "Tool is on allowlist"


def test_get_events_by_session(temp_db):
    """Test querying events by session ID."""
    # Log events for different sessions
    for i in range(5):
        event = AuditEvent(
            correlation_id=f"corr-{i}",
            session_id="session-1",
            event_type=EventType.REQUEST,
            actor="agent",
            action=f"action-{i}",
            status="success",
        )
        temp_db.log_event(event)

    for i in range(3):
        event = AuditEvent(
            correlation_id=f"corr-{i+5}",
            session_id="session-2",
            event_type=EventType.REQUEST,
            actor="agent",
            action=f"action-{i+5}",
            status="success",
        )
        temp_db.log_event(event)

    # Query session-1
    events = temp_db.get_events_by_session("session-1")
    assert len(events) == 5

    # Query session-2
    events = temp_db.get_events_by_session("session-2")
    assert len(events) == 3


def test_get_tool_calls_by_time_range(temp_db):
    """Test querying tool calls by time range."""
    now = datetime.now(UTC).replace(tzinfo=None)

    # Log calls at different times
    old_call = ToolCallRecord(
        correlation_id="old",
        tool_name="filesystem",
        method="read",
        parameters={},
        timestamp=now - timedelta(hours=5),
    )
    temp_db.log_tool_call(old_call)

    recent_call = ToolCallRecord(
        correlation_id="recent",
        tool_name="filesystem",
        method="write",
        parameters={},
        timestamp=now - timedelta(hours=1),
    )
    temp_db.log_tool_call(recent_call)

    # Query last 2 hours
    calls = temp_db.get_tool_calls(
        start_time=now - timedelta(hours=2),
        end_time=now,
    )
    assert len(calls) == 1
    assert calls[0]["method"] == "write"


def test_get_security_decisions_filtered(temp_db):
    """Test filtering security decisions."""
    # Log different decisions
    allow_decision = SecurityDecisionRecord(
        correlation_id="allow",
        decision_type="authorization",
        decision=SecurityDecision.ALLOW,
        reason="Allowed",
        actor="agent",
    )
    temp_db.log_security_decision(allow_decision)

    deny_decision = SecurityDecisionRecord(
        correlation_id="deny",
        decision_type="authorization",
        decision=SecurityDecision.DENY,
        reason="Denied",
        actor="agent",
    )
    temp_db.log_security_decision(deny_decision)

    # Filter by decision type
    decisions = temp_db.get_security_decisions(decision=SecurityDecision.ALLOW)
    assert len(decisions) == 1
    assert decisions[0]["decision"] == "allow"

    decisions = temp_db.get_security_decisions(decision=SecurityDecision.DENY)
    assert len(decisions) == 1
    assert decisions[0]["decision"] == "deny"


def test_get_statistics(temp_db):
    """Test generating statistics."""
    # Log various records
    for i in range(10):
        event = AuditEvent(
            correlation_id=f"corr-{i}",
            session_id=f"session-{i % 3}",
            event_type=EventType.REQUEST,
            actor="agent",
            action="test",
            status="success",
        )
        temp_db.log_event(event)

    for i in range(5):
        tool_call = ToolCallRecord(
            correlation_id=f"tool-{i}",
            tool_name="filesystem" if i % 2 == 0 else "browser",
            method="test",
            parameters={},
            duration_ms=100 * i,
        )
        temp_db.log_tool_call(tool_call)

    # Get statistics
    stats = temp_db.get_statistics()

    # Check event stats
    assert stats["events"]["total_events"] == 10
    assert stats["events"]["unique_sessions"] == 3
    assert stats["events"]["unique_requests"] == 10

    # Check tool stats
    assert len(stats["tools"]) == 2
    tool_names = [t["tool_name"] for t in stats["tools"]]
    assert "filesystem" in tool_names
    assert "browser" in tool_names


def test_retention_policy():
    """Test automatic cleanup of old records."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    # Create database with 1-day retention
    db = AuditDatabase(db_path=db_path, retention_days=1)

    # Log old event
    old_event = AuditEvent(
        correlation_id="old",
        event_type=EventType.REQUEST,
        actor="agent",
        action="test",
        status="success",
        timestamp=datetime.now(UTC).replace(tzinfo=None) - timedelta(days=2),
    )
    db.log_event(old_event)

    # Log recent event
    recent_event = AuditEvent(
        correlation_id="recent",
        event_type=EventType.REQUEST,
        actor="agent",
        action="test",
        status="success",
    )
    db.log_event(recent_event)

    # Cleanup should remove old event
    db._cleanup_old_records()

    # Only recent event should remain
    events = db.get_events_by_correlation("recent")
    assert len(events) == 1

    events = db.get_events_by_correlation("old")
    assert len(events) == 0

    # Cleanup
    Path(db_path).unlink(missing_ok=True)
    Path(f"{db_path}-shm").unlink(missing_ok=True)
    Path(f"{db_path}-wal").unlink(missing_ok=True)


def test_correlation_tracking(temp_db):
    """Test tracking request/response pairs via correlation ID."""
    correlation_id = "corr-123"

    # Log request
    request = AuditEvent(
        correlation_id=correlation_id,
        event_type=EventType.REQUEST,
        actor="agent",
        tool_name="filesystem",
        action="tools/call",
        status="pending",
    )
    temp_db.log_event(request)

    # Log response
    response = AuditEvent(
        correlation_id=correlation_id,
        event_type=EventType.RESPONSE,
        actor="system",
        action="response",
        status="success",
        duration_ms=250,
    )
    temp_db.log_event(response)

    # Retrieve all events for correlation
    events = temp_db.get_events_by_correlation(correlation_id)
    assert len(events) == 2
    assert events[0]["event_type"] == "request"
    assert events[1]["event_type"] == "response"
    assert events[1]["duration_ms"] == 250


def test_pagination(temp_db):
    """Test event pagination."""
    # Log many events
    for i in range(50):
        event = AuditEvent(
            correlation_id=f"corr-{i}",
            session_id="session-1",
            event_type=EventType.REQUEST,
            actor="agent",
            action=f"action-{i}",
            status="success",
        )
        temp_db.log_event(event)

    # Get first page
    page1 = temp_db.get_events_by_session("session-1", limit=20, offset=0)
    assert len(page1) == 20

    # Get second page
    page2 = temp_db.get_events_by_session("session-1", limit=20, offset=20)
    assert len(page2) == 20

    # Get third page
    page3 = temp_db.get_events_by_session("session-1", limit=20, offset=40)
    assert len(page3) == 10

    # Ensure no overlap
    page1_ids = {e["event_id"] for e in page1}
    page2_ids = {e["event_id"] for e in page2}
    assert len(page1_ids & page2_ids) == 0


def test_log_audit_proof(temp_db):
    """Test logging ZKP audit proofs."""
    proof = AuditProofRecord(
        correlation_id="corr-zkp-1",
        claim_type="operation_count",
        description="Operation count is in [1, 10]",
        public_parameters={"claimed_min": 1, "claimed_max": 10},
        proof_data={"commitment": "abc123", "blinding": 42},
    )

    temp_db.log_audit_proof(proof)

    # Retrieve proof
    proofs = temp_db.get_audit_proofs(claim_type="operation_count")
    assert len(proofs) == 1
    assert proofs[0]["correlation_id"] == "corr-zkp-1"
    assert proofs[0]["claim_type"] == "operation_count"
    assert proofs[0]["description"] == "Operation count is in [1, 10]"


def test_get_audit_proofs_filtered(temp_db):
    """Test filtered queries for audit proofs."""
    now = datetime.now(UTC).replace(tzinfo=None)

    # Log proofs with different claim types and times
    for i, claim_type in enumerate(["operation_count", "time_range", "operation_count"]):
        proof = AuditProofRecord(
            correlation_id=f"corr-{i}",
            claim_type=claim_type,
            description=f"Proof {i}",
            created_at=now - timedelta(hours=i),
        )
        temp_db.log_audit_proof(proof)

    # Filter by claim_type
    proofs = temp_db.get_audit_proofs(claim_type="operation_count")
    assert len(proofs) == 2

    proofs = temp_db.get_audit_proofs(claim_type="time_range")
    assert len(proofs) == 1

    # Filter by time range
    proofs = temp_db.get_audit_proofs(
        start_time=now - timedelta(hours=1, minutes=30),
        end_time=now,
    )
    assert len(proofs) == 2

    # Filter by correlation_id
    proofs = temp_db.get_audit_proofs(correlation_id="corr-0")
    assert len(proofs) == 1
    assert proofs[0]["correlation_id"] == "corr-0"


def test_get_events_by_time_range(temp_db):
    """Test querying events by time range."""
    now = datetime.now(UTC).replace(tzinfo=None)

    # Log events at different times
    for i in range(5):
        event = AuditEvent(
            correlation_id=f"corr-tr-{i}",
            event_type=EventType.REQUEST,
            actor="agent",
            action=f"action-{i}",
            status="success",
            timestamp=now - timedelta(hours=i),
        )
        temp_db.log_event(event)

    # Query last 2.5 hours — should get 3 events
    events = temp_db.get_events_by_time_range(
        start_time=now - timedelta(hours=2, minutes=30),
        end_time=now,
    )
    assert len(events) == 3

    # Query with event_type filter
    events = temp_db.get_events_by_time_range(
        start_time=now - timedelta(hours=10),
        end_time=now,
        event_type="request",
    )
    assert len(events) == 5

    # Query with actor filter
    events = temp_db.get_events_by_time_range(
        start_time=now - timedelta(hours=10),
        end_time=now,
        actor="nonexistent",
    )
    assert len(events) == 0


def test_get_security_decisions_by_time_range(temp_db):
    """Test time-range filtering on security decisions."""
    now = datetime.now(UTC).replace(tzinfo=None)

    # Log decisions at different times
    for i in range(4):
        decision = SecurityDecisionRecord(
            correlation_id=f"dec-tr-{i}",
            decision_type="authorization",
            decision=SecurityDecision.ALLOW,
            reason=f"Reason {i}",
            actor="agent",
            timestamp=now - timedelta(hours=i),
        )
        temp_db.log_security_decision(decision)

    # Query last 1.5 hours — should get 2 decisions
    decisions = temp_db.get_security_decisions(
        start_time=now - timedelta(hours=1, minutes=30),
        end_time=now,
    )
    assert len(decisions) == 2

    # All decisions
    decisions = temp_db.get_security_decisions()
    assert len(decisions) == 4
