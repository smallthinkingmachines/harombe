"""Tests for automated alert rules engine."""

import time
from typing import Any

import pytest

from harombe.security.alert_rules import (
    Alert,
    AlertCondition,
    AlertRule,
    AlertRuleEngine,
    AlertSeverity,
    EmailNotifier,
    NotificationChannel,
    PagerDutyNotifier,
    SlackNotifier,
    _check_condition,
    _get_event_field,
    get_default_rules,
)
from harombe.security.audit_db import AuditEvent, EventType

# --- Helpers ---


def _make_event(
    event_type: EventType = EventType.REQUEST,
    actor: str = "agent-001",
    action: str = "read_file",
    status: str = "success",
    tool_name: str = "filesystem",
    correlation_id: str = "corr-123",
    error_message: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> AuditEvent:
    return AuditEvent(
        correlation_id=correlation_id,
        event_type=event_type,
        actor=actor,
        action=action,
        tool_name=tool_name,
        status=status,
        error_message=error_message,
        metadata=metadata or {},
    )


# --- AlertSeverity Tests ---


class TestAlertSeverity:
    def test_values(self):
        assert AlertSeverity.INFO == "info"
        assert AlertSeverity.LOW == "low"
        assert AlertSeverity.MEDIUM == "medium"
        assert AlertSeverity.HIGH == "high"
        assert AlertSeverity.CRITICAL == "critical"

    def test_from_string(self):
        assert AlertSeverity("critical") == AlertSeverity.CRITICAL


# --- NotificationChannel Tests ---


class TestNotificationChannel:
    def test_values(self):
        assert NotificationChannel.EMAIL == "email"
        assert NotificationChannel.SLACK == "slack"
        assert NotificationChannel.PAGERDUTY == "pagerduty"


# --- AlertCondition Tests ---


class TestAlertCondition:
    def test_eq_operator(self):
        event = _make_event(status="error")
        cond = AlertCondition(field="status", operator="eq", value="error")
        assert _check_condition(event, cond) is True

    def test_eq_operator_mismatch(self):
        event = _make_event(status="success")
        cond = AlertCondition(field="status", operator="eq", value="error")
        assert _check_condition(event, cond) is False

    def test_ne_operator(self):
        event = _make_event(status="success")
        cond = AlertCondition(field="status", operator="ne", value="error")
        assert _check_condition(event, cond) is True

    def test_contains_operator(self):
        event = _make_event(action="auth_failure")
        cond = AlertCondition(field="action", operator="contains", value="auth")
        assert _check_condition(event, cond) is True

    def test_contains_operator_not_found(self):
        event = _make_event(action="read_file")
        cond = AlertCondition(field="action", operator="contains", value="auth")
        assert _check_condition(event, cond) is False

    def test_in_operator(self):
        event = _make_event(status="error")
        cond = AlertCondition(field="status", operator="in", value=["error", "timeout"])
        assert _check_condition(event, cond) is True

    def test_in_operator_not_found(self):
        event = _make_event(status="success")
        cond = AlertCondition(field="status", operator="in", value=["error", "timeout"])
        assert _check_condition(event, cond) is False

    def test_gt_operator(self):
        event = _make_event()
        event.duration_ms = 5000
        cond = AlertCondition(field="duration_ms", operator="gt", value=1000)
        assert _check_condition(event, cond) is True

    def test_lt_operator(self):
        event = _make_event()
        event.duration_ms = 50
        cond = AlertCondition(field="duration_ms", operator="lt", value=100)
        assert _check_condition(event, cond) is True

    def test_gt_with_none(self):
        event = _make_event()  # duration_ms is None
        cond = AlertCondition(field="duration_ms", operator="gt", value=1000)
        assert _check_condition(event, cond) is False

    def test_enum_comparison(self):
        event = _make_event(event_type=EventType.ERROR)
        cond = AlertCondition(field="event_type", operator="eq", value="error")
        assert _check_condition(event, cond) is True

    def test_metadata_field(self):
        event = _make_event(metadata={"path": "/etc/passwd"})
        cond = AlertCondition(field="metadata.path", operator="eq", value="/etc/passwd")
        assert _check_condition(event, cond) is True

    def test_metadata_field_missing(self):
        event = _make_event(metadata={})
        cond = AlertCondition(field="metadata.path", operator="eq", value="/etc/passwd")
        assert _check_condition(event, cond) is False

    def test_unknown_operator(self):
        event = _make_event()
        cond = AlertCondition(field="status", operator="regex", value=".*")
        assert _check_condition(event, cond) is False


# --- AlertRule Tests ---


class TestAlertRule:
    def test_defaults(self):
        rule = AlertRule(name="test_rule")
        assert rule.severity == AlertSeverity.MEDIUM
        assert rule.enabled is True
        assert rule.cooldown_seconds == 300
        assert rule.count_threshold == 1
        assert rule.time_window_seconds == 3600
        assert NotificationChannel.SLACK in rule.channels

    def test_custom_rule(self):
        rule = AlertRule(
            name="custom",
            severity=AlertSeverity.CRITICAL,
            conditions=[AlertCondition(field="status", operator="eq", value="error")],
            channels=[NotificationChannel.EMAIL, NotificationChannel.PAGERDUTY],
            cooldown_seconds=0,
            count_threshold=5,
            time_window_seconds=1800,
        )
        assert rule.severity == AlertSeverity.CRITICAL
        assert len(rule.conditions) == 1
        assert len(rule.channels) == 2
        assert rule.cooldown_seconds == 0
        assert rule.count_threshold == 5


# --- Default Rules Tests ---


class TestDefaultRules:
    def test_default_rules_count(self):
        rules = get_default_rules()
        assert len(rules) >= 10

    def test_default_rules_have_names(self):
        rules = get_default_rules()
        names = [r.name for r in rules]
        assert "auth_failure_spike" in names
        assert "secret_rotation_failure" in names
        assert "high_risk_denied" in names
        assert "anomaly_detected" in names
        assert "secret_leak_detected" in names

    def test_default_rules_have_conditions(self):
        rules = get_default_rules()
        for rule in rules:
            assert len(rule.conditions) > 0, f"Rule '{rule.name}' has no conditions"

    def test_default_rules_all_enabled(self):
        rules = get_default_rules()
        for rule in rules:
            assert rule.enabled is True


# --- Alert Model Tests ---


class TestAlert:
    def test_alert_creation(self):
        alert = Alert(
            rule_name="test",
            severity=AlertSeverity.HIGH,
            message="Test alert",
            event={"action": "test"},
        )
        assert alert.rule_name == "test"
        assert alert.severity == AlertSeverity.HIGH
        assert alert.alert_id.startswith("alert-")

    def test_alert_with_channels(self):
        alert = Alert(
            rule_name="test",
            severity=AlertSeverity.MEDIUM,
            message="Test",
            event={},
            channels=[NotificationChannel.SLACK, NotificationChannel.EMAIL],
        )
        assert len(alert.channels) == 2


# --- Notifier Tests ---


class TestEmailNotifier:
    @pytest.mark.asyncio
    async def test_send_success(self):
        notifier = EmailNotifier(
            to_addresses=["security@example.com"],
        )
        alert = Alert(
            rule_name="test",
            severity=AlertSeverity.HIGH,
            message="Test alert",
            event={},
        )
        result = await notifier.send(alert)
        assert result.success is True
        assert result.channel == NotificationChannel.EMAIL
        assert result.latency_ms >= 0

    def test_default_config(self):
        notifier = EmailNotifier()
        assert notifier.smtp_host == "localhost"
        assert notifier.smtp_port == 587
        assert notifier.from_address == "alerts@harombe.local"


class TestSlackNotifier:
    @pytest.mark.asyncio
    async def test_send_success(self):
        notifier = SlackNotifier(webhook_url="https://hooks.slack.com/test")
        alert = Alert(
            rule_name="test",
            severity=AlertSeverity.CRITICAL,
            message="Critical alert",
            event={},
        )
        result = await notifier.send(alert)
        assert result.success is True
        assert result.channel == NotificationChannel.SLACK

    def test_default_config(self):
        notifier = SlackNotifier()
        assert notifier.channel_name == "#security-alerts"


class TestPagerDutyNotifier:
    @pytest.mark.asyncio
    async def test_send_high_severity(self):
        notifier = PagerDutyNotifier(
            routing_key="test-key",
            min_severity=AlertSeverity.HIGH,
        )
        alert = Alert(
            rule_name="test",
            severity=AlertSeverity.CRITICAL,
            message="Critical alert",
            event={},
        )
        result = await notifier.send(alert)
        assert result.success is True

    @pytest.mark.asyncio
    async def test_filters_low_severity(self):
        notifier = PagerDutyNotifier(
            routing_key="test-key",
            min_severity=AlertSeverity.HIGH,
        )
        alert = Alert(
            rule_name="test",
            severity=AlertSeverity.LOW,
            message="Low alert",
            event={},
        )
        result = await notifier.send(alert)
        # Still returns success but doesn't actually page
        assert result.success is True

    def test_severity_rank(self):
        notifier = PagerDutyNotifier()
        assert notifier._severity_rank(AlertSeverity.INFO) == 0
        assert notifier._severity_rank(AlertSeverity.LOW) == 1
        assert notifier._severity_rank(AlertSeverity.MEDIUM) == 2
        assert notifier._severity_rank(AlertSeverity.HIGH) == 3
        assert notifier._severity_rank(AlertSeverity.CRITICAL) == 4


# --- AlertRuleEngine Tests ---


class TestAlertRuleEngine:
    def test_init_default_rules(self):
        engine = AlertRuleEngine()
        assert len(engine.rules) >= 10
        assert engine.stats["events_evaluated"] == 0

    def test_init_custom_rules(self):
        rules = [
            AlertRule(
                name="custom",
                conditions=[
                    AlertCondition(field="status", operator="eq", value="error"),
                ],
            )
        ]
        engine = AlertRuleEngine(rules=rules)
        assert len(engine.rules) == 1

    def test_init_empty_rules(self):
        engine = AlertRuleEngine(rules=[])
        assert len(engine.rules) == 0

    def test_add_rule(self):
        engine = AlertRuleEngine(rules=[])
        engine.add_rule(
            AlertRule(
                name="new_rule",
                conditions=[
                    AlertCondition(field="status", operator="eq", value="error"),
                ],
            )
        )
        assert len(engine.rules) == 1
        assert "new_rule" in engine.stats["per_rule"]

    def test_remove_rule(self):
        rules = [
            AlertRule(
                name="keep",
                conditions=[
                    AlertCondition(field="status", operator="eq", value="error"),
                ],
            ),
            AlertRule(
                name="remove",
                conditions=[
                    AlertCondition(field="status", operator="eq", value="error"),
                ],
            ),
        ]
        engine = AlertRuleEngine(rules=rules)
        engine.remove_rule("remove")
        assert len(engine.rules) == 1
        assert engine.rules[0].name == "keep"

    def test_add_notifier(self):
        engine = AlertRuleEngine(rules=[])
        engine.add_notifier(SlackNotifier())
        assert NotificationChannel.SLACK in engine._notifiers

    def test_remove_notifier(self):
        engine = AlertRuleEngine(rules=[])
        engine.add_notifier(SlackNotifier())
        engine.remove_notifier(NotificationChannel.SLACK)
        assert NotificationChannel.SLACK not in engine._notifiers

    @pytest.mark.asyncio
    async def test_evaluate_matching_event(self):
        rule = AlertRule(
            name="error_rule",
            conditions=[AlertCondition(field="status", operator="eq", value="error")],
            cooldown_seconds=0,
        )
        engine = AlertRuleEngine(rules=[rule])
        engine.add_notifier(SlackNotifier())

        event = _make_event(status="error")
        alerts = await engine.evaluate(event)
        assert len(alerts) == 1
        assert alerts[0].rule_name == "error_rule"
        assert engine.stats["events_evaluated"] == 1
        assert engine.stats["alerts_generated"] == 1

    @pytest.mark.asyncio
    async def test_evaluate_non_matching_event(self):
        rule = AlertRule(
            name="error_rule",
            conditions=[AlertCondition(field="status", operator="eq", value="error")],
        )
        engine = AlertRuleEngine(rules=[rule])

        event = _make_event(status="success")
        alerts = await engine.evaluate(event)
        assert len(alerts) == 0
        assert engine.stats["events_evaluated"] == 1
        assert engine.stats["alerts_generated"] == 0

    @pytest.mark.asyncio
    async def test_evaluate_multiple_conditions(self):
        rule = AlertRule(
            name="multi_cond",
            conditions=[
                AlertCondition(field="status", operator="eq", value="error"),
                AlertCondition(field="action", operator="contains", value="auth"),
            ],
            cooldown_seconds=0,
        )
        engine = AlertRuleEngine(rules=[rule])

        # Both conditions match
        event = _make_event(status="error", action="auth_failure")
        alerts = await engine.evaluate(event)
        assert len(alerts) == 1

    @pytest.mark.asyncio
    async def test_evaluate_partial_conditions_no_match(self):
        rule = AlertRule(
            name="multi_cond",
            conditions=[
                AlertCondition(field="status", operator="eq", value="error"),
                AlertCondition(field="action", operator="contains", value="auth"),
            ],
        )
        engine = AlertRuleEngine(rules=[rule])

        # Only one condition matches
        event = _make_event(status="error", action="read_file")
        alerts = await engine.evaluate(event)
        assert len(alerts) == 0

    @pytest.mark.asyncio
    async def test_deduplication(self):
        rule = AlertRule(
            name="dedup_rule",
            conditions=[AlertCondition(field="status", operator="eq", value="error")],
            cooldown_seconds=300,
        )
        engine = AlertRuleEngine(rules=[rule])

        event = _make_event(status="error")
        alerts1 = await engine.evaluate(event)
        assert len(alerts1) == 1

        # Second evaluation should be deduplicated
        alerts2 = await engine.evaluate(event)
        assert len(alerts2) == 0
        assert engine.stats["alerts_deduplicated"] == 1

    @pytest.mark.asyncio
    async def test_no_dedup_when_cooldown_zero(self):
        rule = AlertRule(
            name="no_dedup",
            conditions=[AlertCondition(field="status", operator="eq", value="error")],
            cooldown_seconds=0,
        )
        engine = AlertRuleEngine(rules=[rule])

        event = _make_event(status="error")
        alerts1 = await engine.evaluate(event)
        assert len(alerts1) == 1

        alerts2 = await engine.evaluate(event)
        assert len(alerts2) == 1
        assert engine.stats["alerts_deduplicated"] == 0

    @pytest.mark.asyncio
    async def test_windowed_counting(self):
        rule = AlertRule(
            name="count_rule",
            conditions=[AlertCondition(field="status", operator="eq", value="error")],
            count_threshold=3,
            time_window_seconds=3600,
            cooldown_seconds=0,
        )
        engine = AlertRuleEngine(rules=[rule])

        event = _make_event(status="error")

        # First two events don't trigger (below threshold)
        alerts1 = await engine.evaluate(event)
        assert len(alerts1) == 0

        alerts2 = await engine.evaluate(event)
        assert len(alerts2) == 0

        # Third event triggers
        alerts3 = await engine.evaluate(event)
        assert len(alerts3) == 1

    @pytest.mark.asyncio
    async def test_disabled_rule_skipped(self):
        rule = AlertRule(
            name="disabled",
            conditions=[AlertCondition(field="status", operator="eq", value="error")],
            enabled=False,
        )
        engine = AlertRuleEngine(rules=[rule])

        event = _make_event(status="error")
        alerts = await engine.evaluate(event)
        assert len(alerts) == 0

    @pytest.mark.asyncio
    async def test_alert_sent_to_notifiers(self):
        rule = AlertRule(
            name="notify_rule",
            conditions=[AlertCondition(field="status", operator="eq", value="error")],
            channels=[NotificationChannel.SLACK, NotificationChannel.EMAIL],
            cooldown_seconds=0,
        )
        engine = AlertRuleEngine(rules=[rule])
        engine.add_notifier(SlackNotifier())
        engine.add_notifier(EmailNotifier())

        event = _make_event(status="error")
        await engine.evaluate(event)

        assert engine.stats["notifications_sent"] == 2

    @pytest.mark.asyncio
    async def test_missing_notifier_channel_skipped(self):
        rule = AlertRule(
            name="no_notifier",
            conditions=[AlertCondition(field="status", operator="eq", value="error")],
            channels=[NotificationChannel.PAGERDUTY],
            cooldown_seconds=0,
        )
        engine = AlertRuleEngine(rules=[rule])
        # No PagerDuty notifier registered

        event = _make_event(status="error")
        alerts = await engine.evaluate(event)
        assert len(alerts) == 1
        # Alert generated but no notification sent
        assert engine.stats["notifications_sent"] == 0

    @pytest.mark.asyncio
    async def test_empty_conditions_no_match(self):
        rule = AlertRule(name="empty", conditions=[])
        engine = AlertRuleEngine(rules=[rule])

        event = _make_event()
        alerts = await engine.evaluate(event)
        assert len(alerts) == 0

    @pytest.mark.asyncio
    async def test_alert_message_includes_context(self):
        rule = AlertRule(
            name="msg_rule",
            description="Error detected",
            conditions=[AlertCondition(field="status", operator="eq", value="error")],
            cooldown_seconds=0,
        )
        engine = AlertRuleEngine(rules=[rule])

        event = _make_event(
            status="error",
            actor="agent-bad",
            action="write_file",
            error_message="Permission denied",
        )
        alerts = await engine.evaluate(event)
        assert len(alerts) == 1
        assert "Error detected" in alerts[0].message
        assert "Permission denied" in alerts[0].message
        assert "agent-bad" in alerts[0].message

    def test_reset_windows(self):
        engine = AlertRuleEngine(rules=[])
        engine._event_windows["test"] = [1.0, 2.0, 3.0]
        engine.reset_windows()
        assert len(engine._event_windows) == 0

    def test_reset_dedup(self):
        engine = AlertRuleEngine(rules=[])
        engine._last_alert_time["test"] = time.time()
        engine.reset_dedup()
        assert len(engine._last_alert_time) == 0


# --- Statistics Tests ---


class TestAlertStatistics:
    @pytest.mark.asyncio
    async def test_stats_after_evaluation(self):
        rule = AlertRule(
            name="stat_rule",
            conditions=[AlertCondition(field="status", operator="eq", value="error")],
            cooldown_seconds=0,
        )
        engine = AlertRuleEngine(rules=[rule])
        engine.add_notifier(SlackNotifier())

        event = _make_event(status="error")
        await engine.evaluate(event)

        stats = engine.get_stats()
        assert stats["events_evaluated"] == 1
        assert stats["alerts_generated"] == 1
        assert stats["notifications_sent"] == 1

    @pytest.mark.asyncio
    async def test_per_rule_stats(self):
        rule = AlertRule(
            name="tracked_rule",
            conditions=[AlertCondition(field="status", operator="eq", value="error")],
            cooldown_seconds=0,
        )
        engine = AlertRuleEngine(rules=[rule])

        event = _make_event(status="error")
        await engine.evaluate(event)
        await engine.evaluate(event)

        stats = engine.get_stats()
        assert stats["per_rule"]["tracked_rule"]["matches"] == 2
        assert stats["per_rule"]["tracked_rule"]["alerts"] == 2


# --- Event Field Extraction Tests ---


class TestEventFieldExtraction:
    def test_simple_field(self):
        event = _make_event(actor="agent-007")
        assert _get_event_field(event, "actor") == "agent-007"

    def test_metadata_field(self):
        event = _make_event(metadata={"level": "high"})
        assert _get_event_field(event, "metadata.level") == "high"

    def test_missing_field(self):
        event = _make_event()
        assert _get_event_field(event, "nonexistent") is None

    def test_missing_metadata_key(self):
        event = _make_event(metadata={})
        assert _get_event_field(event, "metadata.missing") is None


# --- Performance Tests ---


class TestAlertPerformance:
    @pytest.mark.asyncio
    async def test_evaluation_performance(self):
        """Evaluating 1000 events should be fast."""
        rules = get_default_rules()
        # Disable cooldowns for performance test
        for rule in rules:
            rule.cooldown_seconds = 0
        engine = AlertRuleEngine(rules=rules)

        events = [_make_event(action=f"action_{i}") for i in range(1000)]
        start = time.perf_counter()
        for event in events:
            await engine.evaluate(event)
        elapsed_ms = (time.perf_counter() - start) * 1000

        # 1000 evaluations with 10 rules should take <2500ms (relaxed for CI)
        assert elapsed_ms < 2500, f"1000 evaluations took {elapsed_ms:.1f}ms"

    def test_condition_check_performance(self):
        """Condition checking should be fast."""
        event = _make_event()
        cond = AlertCondition(field="status", operator="eq", value="error")

        start = time.perf_counter()
        for _i in range(10000):
            _check_condition(event, cond)
        elapsed_ms = (time.perf_counter() - start) * 1000

        # 10000 checks should take <500ms (relaxed for CI)
        assert elapsed_ms < 500, f"10000 checks took {elapsed_ms:.1f}ms"


# --- Edge Cases ---


class TestEdgeCases:
    @pytest.mark.asyncio
    async def test_no_rules(self):
        engine = AlertRuleEngine(rules=[])
        event = _make_event()
        alerts = await engine.evaluate(event)
        assert len(alerts) == 0

    @pytest.mark.asyncio
    async def test_multiple_rules_match_same_event(self):
        rules = [
            AlertRule(
                name="rule_a",
                conditions=[AlertCondition(field="status", operator="eq", value="error")],
                cooldown_seconds=0,
            ),
            AlertRule(
                name="rule_b",
                conditions=[AlertCondition(field="status", operator="ne", value="success")],
                cooldown_seconds=0,
            ),
        ]
        engine = AlertRuleEngine(rules=rules)

        event = _make_event(status="error")
        alerts = await engine.evaluate(event)
        assert len(alerts) == 2
        rule_names = {a.rule_name for a in alerts}
        assert "rule_a" in rule_names
        assert "rule_b" in rule_names

    @pytest.mark.asyncio
    async def test_contains_on_non_string(self):
        event = _make_event()
        cond = AlertCondition(field="duration_ms", operator="contains", value="abc")
        assert _check_condition(event, cond) is False

    @pytest.mark.asyncio
    async def test_in_with_non_list(self):
        event = _make_event(status="error")
        cond = AlertCondition(field="status", operator="in", value="error")
        # value must be list for "in" operator
        assert _check_condition(event, cond) is False
