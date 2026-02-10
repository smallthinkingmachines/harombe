"""Tests for CLI audit commands."""

import json
from datetime import datetime
from unittest.mock import patch

import pytest
import typer

from harombe.cli.audit_cmd import (
    _format_duration,
    _format_timestamp,
    export,
    query_events,
    query_security,
    query_tools,
    stats,
)


class TestFormatTimestamp:
    def test_iso_string(self):
        assert _format_timestamp("2024-01-15T10:30:00") == "2024-01-15 10:30:00"

    def test_iso_string_with_z(self):
        assert _format_timestamp("2024-01-15T10:30:00Z") == "2024-01-15 10:30:00"

    def test_datetime_object(self):
        dt = datetime(2024, 1, 15, 10, 30, 0)
        assert _format_timestamp(dt) == "2024-01-15 10:30:00"

    def test_invalid_string(self):
        assert _format_timestamp("not-a-date") == "not-a-date"


class TestFormatDuration:
    def test_none(self):
        assert _format_duration(None) == "N/A"

    def test_milliseconds(self):
        assert _format_duration(500) == "500ms"

    def test_seconds(self):
        assert _format_duration(1500) == "1.50s"

    def test_zero(self):
        assert _format_duration(0) == "0ms"


class TestQueryEvents:
    def test_query_events_table_format(self, tmp_path):
        db_path = str(tmp_path / "audit.db")
        events = [
            {
                "timestamp": "2024-01-15T10:30:00",
                "event_type": "request",
                "actor": "agent-1",
                "tool_name": "shell",
                "action": "execute",
                "status": "success",
                "duration_ms": 100,
            },
        ]

        with patch("harombe.cli.audit_cmd.AuditDatabase") as mock_db_cls:
            instance = mock_db_cls.return_value
            instance.get_events_by_session.return_value = events

            query_events(
                db_path=db_path,
                session_id=None,
                correlation_id=None,
                limit=20,
                output_format="table",
            )

    def test_query_events_json_format(self, tmp_path):
        db_path = str(tmp_path / "audit.db")
        events = [
            {
                "timestamp": "2024-01-15T10:30:00",
                "event_type": "request",
                "actor": "a",
                "tool_name": None,
                "action": "x",
                "status": "success",
            }
        ]

        with patch("harombe.cli.audit_cmd.AuditDatabase") as mock_db_cls:
            instance = mock_db_cls.return_value
            instance.get_events_by_session.return_value = events

            query_events(
                db_path=db_path,
                session_id=None,
                correlation_id=None,
                limit=20,
                output_format="json",
            )

    def test_query_events_csv_format(self, tmp_path):
        db_path = str(tmp_path / "audit.db")
        events = [
            {
                "timestamp": "2024-01-15",
                "event_type": "request",
                "actor": "a",
                "tool_name": None,
                "action": "x",
                "status": "success",
            }
        ]

        with patch("harombe.cli.audit_cmd.AuditDatabase") as mock_db_cls:
            instance = mock_db_cls.return_value
            instance.get_events_by_session.return_value = events

            query_events(
                db_path=db_path, session_id=None, correlation_id=None, limit=20, output_format="csv"
            )

    def test_query_events_empty(self, tmp_path):
        db_path = str(tmp_path / "audit.db")

        with patch("harombe.cli.audit_cmd.AuditDatabase") as mock_db_cls:
            instance = mock_db_cls.return_value
            instance.get_events_by_session.return_value = []

            query_events(
                db_path=db_path,
                session_id=None,
                correlation_id=None,
                limit=20,
                output_format="table",
            )

    def test_query_events_by_correlation(self, tmp_path):
        db_path = str(tmp_path / "audit.db")
        events = [
            {
                "timestamp": "2024-01-15",
                "event_type": "request",
                "actor": "a",
                "tool_name": None,
                "action": "x",
                "status": "success",
            }
        ]

        with patch("harombe.cli.audit_cmd.AuditDatabase") as mock_db_cls:
            instance = mock_db_cls.return_value
            instance.get_events_by_correlation.return_value = events

            query_events(
                db_path=db_path,
                session_id=None,
                correlation_id="corr-123",
                limit=20,
                output_format="table",
            )

            instance.get_events_by_correlation.assert_called_once_with("corr-123")

    def test_query_events_by_session(self, tmp_path):
        db_path = str(tmp_path / "audit.db")
        events = [
            {
                "timestamp": "2024-01-15",
                "event_type": "request",
                "actor": "a",
                "tool_name": None,
                "action": "x",
                "status": "success",
            }
        ]

        with patch("harombe.cli.audit_cmd.AuditDatabase") as mock_db_cls:
            instance = mock_db_cls.return_value
            instance.get_events_by_session.return_value = events

            query_events(
                db_path=db_path,
                session_id="sess-456",
                correlation_id=None,
                limit=10,
                output_format="table",
            )

            instance.get_events_by_session.assert_called_once_with("sess-456", limit=10)

    def test_query_events_error(self, tmp_path):
        db_path = str(tmp_path / "audit.db")

        with (
            patch("harombe.cli.audit_cmd.AuditDatabase", side_effect=Exception("db error")),
            pytest.raises(typer.Exit),
        ):
            query_events(
                db_path=db_path,
                session_id=None,
                correlation_id=None,
                limit=20,
                output_format="table",
            )

    def test_query_events_failed_status(self, tmp_path):
        db_path = str(tmp_path / "audit.db")
        events = [
            {
                "timestamp": "2024-01-15",
                "event_type": "error",
                "actor": "a",
                "tool_name": "shell",
                "action": "x",
                "status": "error",
                "duration_ms": None,
            }
        ]

        with patch("harombe.cli.audit_cmd.AuditDatabase") as mock_db_cls:
            instance = mock_db_cls.return_value
            instance.get_events_by_session.return_value = events

            query_events(
                db_path=db_path,
                session_id=None,
                correlation_id=None,
                limit=20,
                output_format="table",
            )


class TestQueryTools:
    def test_query_tools_table(self, tmp_path):
        db_path = str(tmp_path / "audit.db")
        calls = [
            {
                "timestamp": "2024-01-15T10:30:00",
                "tool_name": "shell",
                "method": "execute",
                "error": None,
                "duration_ms": 50,
                "container_id": "abc123",
            },
        ]

        with patch("harombe.cli.audit_cmd.AuditDatabase") as mock_db_cls:
            instance = mock_db_cls.return_value
            instance.get_tool_calls.return_value = calls

            query_tools(
                db_path=db_path, tool_name=None, hours=None, limit=20, output_format="table"
            )

    def test_query_tools_with_filter(self, tmp_path):
        db_path = str(tmp_path / "audit.db")

        with patch("harombe.cli.audit_cmd.AuditDatabase") as mock_db_cls:
            instance = mock_db_cls.return_value
            instance.get_tool_calls.return_value = []

            query_tools(
                db_path=db_path, tool_name="shell", hours=24, limit=10, output_format="table"
            )

    def test_query_tools_json(self, tmp_path):
        db_path = str(tmp_path / "audit.db")
        calls = [
            {
                "timestamp": "2024-01-15",
                "tool_name": "shell",
                "method": "exec",
                "error": None,
                "duration_ms": 50,
                "container_id": None,
            }
        ]

        with patch("harombe.cli.audit_cmd.AuditDatabase") as mock_db_cls:
            instance = mock_db_cls.return_value
            instance.get_tool_calls.return_value = calls

            query_tools(db_path=db_path, tool_name=None, hours=None, limit=20, output_format="json")

    def test_query_tools_csv(self, tmp_path):
        db_path = str(tmp_path / "audit.db")
        calls = [
            {
                "timestamp": "2024-01-15",
                "tool_name": "shell",
                "method": "exec",
                "error": None,
                "duration_ms": 50,
            }
        ]

        with patch("harombe.cli.audit_cmd.AuditDatabase") as mock_db_cls:
            instance = mock_db_cls.return_value
            instance.get_tool_calls.return_value = calls

            query_tools(db_path=db_path, tool_name=None, hours=None, limit=20, output_format="csv")

    def test_query_tools_with_error(self, tmp_path):
        db_path = str(tmp_path / "audit.db")
        calls = [
            {
                "timestamp": "2024-01-15",
                "tool_name": "shell",
                "method": "exec",
                "error": "timeout",
                "duration_ms": 30000,
                "container_id": None,
            }
        ]

        with patch("harombe.cli.audit_cmd.AuditDatabase") as mock_db_cls:
            instance = mock_db_cls.return_value
            instance.get_tool_calls.return_value = calls

            query_tools(
                db_path=db_path, tool_name=None, hours=None, limit=20, output_format="table"
            )

    def test_query_tools_error(self, tmp_path):
        db_path = str(tmp_path / "audit.db")

        with (
            patch("harombe.cli.audit_cmd.AuditDatabase", side_effect=Exception("db error")),
            pytest.raises(typer.Exit),
        ):
            query_tools(
                db_path=db_path, tool_name=None, hours=None, limit=20, output_format="table"
            )


class TestQuerySecurity:
    def test_query_security_table(self, tmp_path):
        db_path = str(tmp_path / "audit.db")
        decisions = [
            {
                "timestamp": "2024-01-15T10:30:00",
                "decision_type": "authorization",
                "decision": "allow",
                "tool_name": "shell",
                "actor": "agent-1",
                "reason": "Authorized by policy",
            },
        ]

        with patch("harombe.cli.audit_cmd.AuditDatabase") as mock_db_cls:
            instance = mock_db_cls.return_value
            instance.get_security_decisions.return_value = decisions

            query_security(
                db_path=db_path, decision_type=None, decision=None, limit=20, output_format="table"
            )

    def test_query_security_with_decision_filter(self, tmp_path):
        db_path = str(tmp_path / "audit.db")

        with patch("harombe.cli.audit_cmd.AuditDatabase") as mock_db_cls:
            instance = mock_db_cls.return_value
            instance.get_security_decisions.return_value = []

            query_security(
                db_path=db_path,
                decision_type="authorization",
                decision="deny",
                limit=20,
                output_format="table",
            )

    def test_query_security_invalid_decision(self, tmp_path):
        db_path = str(tmp_path / "audit.db")

        with patch("harombe.cli.audit_cmd.AuditDatabase"), pytest.raises(typer.Exit):
            query_security(
                db_path=db_path,
                decision_type=None,
                decision="invalid",
                limit=20,
                output_format="table",
            )

    def test_query_security_json(self, tmp_path):
        db_path = str(tmp_path / "audit.db")
        decisions = [
            {
                "timestamp": "2024-01-15",
                "decision_type": "auth",
                "decision": "deny",
                "tool_name": "shell",
                "actor": "a",
                "reason": "blocked",
            }
        ]

        with patch("harombe.cli.audit_cmd.AuditDatabase") as mock_db_cls:
            instance = mock_db_cls.return_value
            instance.get_security_decisions.return_value = decisions

            query_security(
                db_path=db_path, decision_type=None, decision=None, limit=20, output_format="json"
            )

    def test_query_security_long_reason(self, tmp_path):
        db_path = str(tmp_path / "audit.db")
        decisions = [
            {
                "timestamp": "2024-01-15",
                "decision_type": "auth",
                "decision": "deny",
                "tool_name": "shell",
                "actor": "a",
                "reason": "x" * 100,
            }
        ]

        with patch("harombe.cli.audit_cmd.AuditDatabase") as mock_db_cls:
            instance = mock_db_cls.return_value
            instance.get_security_decisions.return_value = decisions

            query_security(
                db_path=db_path, decision_type=None, decision=None, limit=20, output_format="table"
            )

    def test_query_security_all_decision_colors(self, tmp_path):
        """Test all decision types have proper color mapping."""
        db_path = str(tmp_path / "audit.db")
        decisions = [
            {
                "timestamp": "2024-01-15",
                "decision_type": "auth",
                "decision": "allow",
                "tool_name": None,
                "actor": "a",
                "reason": "ok",
            },
            {
                "timestamp": "2024-01-15",
                "decision_type": "auth",
                "decision": "deny",
                "tool_name": None,
                "actor": "a",
                "reason": "bad",
            },
            {
                "timestamp": "2024-01-15",
                "decision_type": "auth",
                "decision": "require_confirmation",
                "tool_name": None,
                "actor": "a",
                "reason": "maybe",
            },
            {
                "timestamp": "2024-01-15",
                "decision_type": "auth",
                "decision": "redacted",
                "tool_name": None,
                "actor": "a",
                "reason": "hidden",
            },
        ]

        with patch("harombe.cli.audit_cmd.AuditDatabase") as mock_db_cls:
            instance = mock_db_cls.return_value
            instance.get_security_decisions.return_value = decisions

            query_security(
                db_path=db_path, decision_type=None, decision=None, limit=20, output_format="table"
            )

    def test_query_security_error(self, tmp_path):
        db_path = str(tmp_path / "audit.db")

        with (
            patch("harombe.cli.audit_cmd.AuditDatabase", side_effect=Exception("db error")),
            pytest.raises(typer.Exit),
        ):
            query_security(
                db_path=db_path, decision_type=None, decision=None, limit=20, output_format="table"
            )


class TestStats:
    def test_stats_with_data(self, tmp_path):
        db_path = str(tmp_path / "audit.db")
        statistics = {
            "events": {"total_events": 100, "unique_sessions": 5, "unique_requests": 50},
            "tools": [
                {"tool_name": "shell", "call_count": 30, "avg_duration_ms": 150.5},
                {"tool_name": "filesystem", "call_count": 20, "avg_duration_ms": None},
            ],
            "security_decisions": [
                {"decision": "allow", "count": 40},
                {"decision": "deny", "count": 10},
            ],
        }

        with patch("harombe.cli.audit_cmd.AuditDatabase") as mock_db_cls:
            instance = mock_db_cls.return_value
            instance.get_statistics.return_value = statistics

            stats(db_path=db_path, hours=None)

    def test_stats_empty(self, tmp_path):
        db_path = str(tmp_path / "audit.db")
        statistics = {
            "events": {"total_events": 0, "unique_sessions": 0, "unique_requests": 0},
            "tools": [],
            "security_decisions": [],
        }

        with patch("harombe.cli.audit_cmd.AuditDatabase") as mock_db_cls:
            instance = mock_db_cls.return_value
            instance.get_statistics.return_value = statistics

            stats(db_path=db_path, hours=None)

    def test_stats_with_hours_filter(self, tmp_path):
        db_path = str(tmp_path / "audit.db")
        statistics = {
            "events": {"total_events": 10, "unique_sessions": 1, "unique_requests": 5},
            "tools": [],
            "security_decisions": [],
        }

        with patch("harombe.cli.audit_cmd.AuditDatabase") as mock_db_cls:
            instance = mock_db_cls.return_value
            instance.get_statistics.return_value = statistics

            stats(db_path=db_path, hours=24)

    def test_stats_error(self, tmp_path):
        db_path = str(tmp_path / "audit.db")

        with (
            patch("harombe.cli.audit_cmd.AuditDatabase", side_effect=Exception("db error")),
            pytest.raises(typer.Exit),
        ):
            stats(db_path=db_path, hours=None)


class TestExport:
    def test_export_json(self, tmp_path):
        db_path = str(tmp_path / "audit.db")
        output_path = tmp_path / "export.json"

        with patch("harombe.cli.audit_cmd.AuditDatabase") as mock_db_cls:
            instance = mock_db_cls.return_value
            instance.get_tool_calls.return_value = [{"tool": "shell", "method": "exec"}]
            instance.get_security_decisions.return_value = [{"decision": "allow"}]

            export(output_path=output_path, db_path=db_path, hours=None, format="json")

            assert output_path.exists()
            data = json.loads(output_path.read_text())
            assert "tool_calls" in data
            assert "security_decisions" in data
            assert "exported_at" in data

    def test_export_csv(self, tmp_path):
        db_path = str(tmp_path / "audit.db")
        output_path = tmp_path / "export.csv"

        with patch("harombe.cli.audit_cmd.AuditDatabase") as mock_db_cls:
            instance = mock_db_cls.return_value
            instance.get_tool_calls.return_value = [
                {"tool_name": "shell", "method": "exec", "timestamp": "2024-01-15"}
            ]
            instance.get_security_decisions.return_value = []

            export(output_path=output_path, db_path=db_path, hours=None, format="csv")

            assert output_path.exists()

    def test_export_csv_empty(self, tmp_path):
        db_path = str(tmp_path / "audit.db")
        output_path = tmp_path / "export.csv"

        with patch("harombe.cli.audit_cmd.AuditDatabase") as mock_db_cls:
            instance = mock_db_cls.return_value
            instance.get_tool_calls.return_value = []
            instance.get_security_decisions.return_value = []

            export(output_path=output_path, db_path=db_path, hours=None, format="csv")

    def test_export_invalid_format(self, tmp_path):
        db_path = str(tmp_path / "audit.db")
        output_path = tmp_path / "export.xml"

        with patch("harombe.cli.audit_cmd.AuditDatabase") as mock_db_cls:
            instance = mock_db_cls.return_value
            instance.get_tool_calls.return_value = []
            instance.get_security_decisions.return_value = []

            with pytest.raises(typer.Exit):
                export(output_path=output_path, db_path=db_path, hours=None, format="xml")

    def test_export_with_hours_filter(self, tmp_path):
        db_path = str(tmp_path / "audit.db")
        output_path = tmp_path / "export.json"

        with patch("harombe.cli.audit_cmd.AuditDatabase") as mock_db_cls:
            instance = mock_db_cls.return_value
            instance.get_tool_calls.return_value = []
            instance.get_security_decisions.return_value = []

            export(output_path=output_path, db_path=db_path, hours=48, format="json")

    def test_export_error(self, tmp_path):
        db_path = str(tmp_path / "audit.db")
        output_path = tmp_path / "export.json"

        with (
            patch("harombe.cli.audit_cmd.AuditDatabase", side_effect=Exception("db error")),
            pytest.raises(typer.Exit),
        ):
            export(output_path=output_path, db_path=db_path, hours=None, format="json")
