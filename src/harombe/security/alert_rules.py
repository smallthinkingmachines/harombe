"""Automated alert rules engine for audit events.

This module provides a rule-based alert engine that evaluates audit events
against configurable rules and dispatches notifications via multiple channels
(Email, Slack, PagerDuty).

Features:
- Configurable alert rules with field matching and conditions
- Multiple notification channels (Email, Slack, PagerDuty)
- Alert deduplication with configurable cooldown windows
- Severity-based routing (which channels get which severity)
- Windowed counting rules (e.g., "5 failures in 1 hour")
- Statistics tracking
"""

import time
from collections import defaultdict
from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from .audit_db import AuditEvent


class AlertSeverity(StrEnum):
    """Alert severity levels."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class NotificationChannel(StrEnum):
    """Supported notification channels."""

    EMAIL = "email"
    SLACK = "slack"
    PAGERDUTY = "pagerduty"


class AlertCondition(BaseModel):
    """A single condition that an event must match."""

    field: str  # Event field to check (e.g., "event_type", "status", "actor")
    operator: str = "eq"  # "eq", "ne", "contains", "in", "gt", "lt"
    value: Any = None  # Value to compare against


class AlertRule(BaseModel):
    """An alert rule definition."""

    name: str
    description: str = ""
    severity: AlertSeverity = AlertSeverity.MEDIUM
    conditions: list[AlertCondition] = Field(default_factory=list)
    enabled: bool = True
    channels: list[NotificationChannel] = Field(default_factory=lambda: [NotificationChannel.SLACK])
    cooldown_seconds: int = Field(default=300, ge=0)  # 5 min default dedup window
    # Windowed counting: require N matches in time_window_seconds
    count_threshold: int = Field(default=1, ge=1)  # How many matches to trigger
    time_window_seconds: int = Field(default=3600, ge=1)  # Window for counting


class Alert(BaseModel):
    """A generated alert."""

    alert_id: str = Field(default_factory=lambda: f"alert-{int(time.time() * 1000)}")
    rule_name: str
    severity: AlertSeverity
    message: str
    event: dict[str, Any]  # Serialized triggering event
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    channels: list[NotificationChannel] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class NotificationResult(BaseModel):
    """Result of sending a notification."""

    channel: NotificationChannel
    success: bool
    error: str | None = None
    latency_ms: float = 0.0


class Notifier:
    """Base class for notification channels."""

    channel: NotificationChannel = NotificationChannel.EMAIL

    async def send(self, alert: Alert) -> NotificationResult:
        """Send an alert notification. Override in subclasses."""
        raise NotImplementedError


class EmailNotifier(Notifier):
    """Send alerts via email."""

    channel = NotificationChannel.EMAIL

    def __init__(
        self,
        smtp_host: str = "localhost",
        smtp_port: int = 587,
        from_address: str = "alerts@harombe.local",
        to_addresses: list[str] | None = None,
    ):
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.from_address = from_address
        self.to_addresses = to_addresses or []

    async def send(self, alert: Alert) -> NotificationResult:
        """Send alert via email.

        In production, this would use aiosmtplib. For now, it formats the
        email payload and returns success (integration point for real SMTP).
        """
        start = time.perf_counter()
        try:
            # Build email payload (actual SMTP sending would go here)
            _payload = {
                "from": self.from_address,
                "to": self.to_addresses,
                "subject": f"[{alert.severity.upper()}] Harombe Alert: {alert.rule_name}",
                "body": alert.message,
            }
            elapsed_ms = (time.perf_counter() - start) * 1000
            return NotificationResult(
                channel=NotificationChannel.EMAIL,
                success=True,
                latency_ms=elapsed_ms,
            )
        except Exception as e:
            elapsed_ms = (time.perf_counter() - start) * 1000
            return NotificationResult(
                channel=NotificationChannel.EMAIL,
                success=False,
                error=str(e),
                latency_ms=elapsed_ms,
            )


class SlackNotifier(Notifier):
    """Send alerts via Slack webhook."""

    channel = NotificationChannel.SLACK

    def __init__(
        self,
        webhook_url: str = "",
        channel_name: str = "#security-alerts",
    ):
        self.webhook_url = webhook_url
        self.channel_name = channel_name

    async def send(self, alert: Alert) -> NotificationResult:
        """Send alert via Slack webhook.

        In production, this would POST to the webhook URL.
        """
        start = time.perf_counter()
        try:
            severity_emoji = {
                AlertSeverity.INFO: ":information_source:",
                AlertSeverity.LOW: ":white_circle:",
                AlertSeverity.MEDIUM: ":large_orange_circle:",
                AlertSeverity.HIGH: ":red_circle:",
                AlertSeverity.CRITICAL: ":rotating_light:",
            }
            _payload = {
                "channel": self.channel_name,
                "text": f"{severity_emoji.get(alert.severity, ':bell:')} *{alert.rule_name}*\n{alert.message}",
                "username": "Harombe Security",
            }
            elapsed_ms = (time.perf_counter() - start) * 1000
            return NotificationResult(
                channel=NotificationChannel.SLACK,
                success=True,
                latency_ms=elapsed_ms,
            )
        except Exception as e:
            elapsed_ms = (time.perf_counter() - start) * 1000
            return NotificationResult(
                channel=NotificationChannel.SLACK,
                success=False,
                error=str(e),
                latency_ms=elapsed_ms,
            )


class PagerDutyNotifier(Notifier):
    """Send alerts via PagerDuty Events API."""

    channel = NotificationChannel.PAGERDUTY

    def __init__(
        self,
        routing_key: str = "",
        min_severity: AlertSeverity = AlertSeverity.HIGH,
    ):
        self.routing_key = routing_key
        self.min_severity = min_severity

    def _severity_rank(self, severity: AlertSeverity) -> int:
        """Get numeric rank for severity comparison."""
        ranks = {
            AlertSeverity.INFO: 0,
            AlertSeverity.LOW: 1,
            AlertSeverity.MEDIUM: 2,
            AlertSeverity.HIGH: 3,
            AlertSeverity.CRITICAL: 4,
        }
        return ranks.get(severity, 0)

    async def send(self, alert: Alert) -> NotificationResult:
        """Send alert via PagerDuty.

        Only sends if alert severity meets minimum threshold.
        """
        start = time.perf_counter()

        # Check minimum severity
        if self._severity_rank(alert.severity) < self._severity_rank(self.min_severity):
            elapsed_ms = (time.perf_counter() - start) * 1000
            return NotificationResult(
                channel=NotificationChannel.PAGERDUTY,
                success=True,  # Not an error, just filtered
                latency_ms=elapsed_ms,
            )

        try:
            _severity_map = {
                AlertSeverity.INFO: "info",
                AlertSeverity.LOW: "info",
                AlertSeverity.MEDIUM: "warning",
                AlertSeverity.HIGH: "error",
                AlertSeverity.CRITICAL: "critical",
            }
            _payload = {
                "routing_key": self.routing_key,
                "event_action": "trigger",
                "payload": {
                    "summary": f"{alert.rule_name}: {alert.message}",
                    "severity": _severity_map.get(alert.severity, "info"),
                    "source": "harombe-security",
                },
            }
            elapsed_ms = (time.perf_counter() - start) * 1000
            return NotificationResult(
                channel=NotificationChannel.PAGERDUTY,
                success=True,
                latency_ms=elapsed_ms,
            )
        except Exception as e:
            elapsed_ms = (time.perf_counter() - start) * 1000
            return NotificationResult(
                channel=NotificationChannel.PAGERDUTY,
                success=False,
                error=str(e),
                latency_ms=elapsed_ms,
            )


def _get_event_field(event: AuditEvent, field: str) -> Any:
    """Extract a field value from an AuditEvent.

    Supports dot notation for metadata fields (e.g., "metadata.path").
    """
    if field.startswith("metadata."):
        key = field[len("metadata.") :]
        return event.metadata.get(key)
    return getattr(event, field, None)


def _check_condition(event: AuditEvent, condition: AlertCondition) -> bool:
    """Check if an event matches a condition."""
    actual = _get_event_field(event, condition.field)
    expected = condition.value

    if condition.operator == "eq":
        # Handle StrEnum comparison
        actual_str = actual.value if isinstance(actual, StrEnum) else actual
        return actual_str == expected
    elif condition.operator == "ne":
        actual_str = actual.value if isinstance(actual, StrEnum) else actual
        return actual_str != expected
    elif condition.operator == "contains":
        if isinstance(actual, str) and isinstance(expected, str):
            return expected in actual
        return False
    elif condition.operator == "in":
        if isinstance(expected, list):
            actual_str = actual.value if isinstance(actual, StrEnum) else actual
            return actual_str in expected
        return False
    elif condition.operator == "gt":
        if actual is not None and expected is not None:
            return actual > expected
        return False
    elif condition.operator == "lt":
        if actual is not None and expected is not None:
            return actual < expected
        return False
    return False


def get_default_rules() -> list[AlertRule]:
    """Get the default set of alert rules."""
    return [
        AlertRule(
            name="auth_failure_spike",
            description="Multiple authentication failures detected",
            severity=AlertSeverity.HIGH,
            conditions=[
                AlertCondition(field="event_type", operator="eq", value="error"),
                AlertCondition(field="action", operator="contains", value="auth"),
            ],
            count_threshold=5,
            time_window_seconds=3600,
            channels=[NotificationChannel.SLACK, NotificationChannel.PAGERDUTY],
        ),
        AlertRule(
            name="secret_rotation_failure",
            description="Secret rotation failed",
            severity=AlertSeverity.CRITICAL,
            conditions=[
                AlertCondition(field="action", operator="contains", value="rotation"),
                AlertCondition(field="status", operator="eq", value="error"),
            ],
            channels=[
                NotificationChannel.SLACK,
                NotificationChannel.EMAIL,
                NotificationChannel.PAGERDUTY,
            ],
        ),
        AlertRule(
            name="high_risk_denied",
            description="High-risk operation was denied",
            severity=AlertSeverity.MEDIUM,
            conditions=[
                AlertCondition(field="event_type", operator="eq", value="security_decision"),
                AlertCondition(field="status", operator="eq", value="denied"),
            ],
            channels=[NotificationChannel.SLACK],
        ),
        AlertRule(
            name="anomaly_detected",
            description="Behavioral anomaly detected",
            severity=AlertSeverity.HIGH,
            conditions=[
                AlertCondition(field="action", operator="contains", value="anomaly"),
            ],
            channels=[NotificationChannel.SLACK, NotificationChannel.PAGERDUTY],
        ),
        AlertRule(
            name="secret_leak_detected",
            description="Potential secret leak detected in output",
            severity=AlertSeverity.CRITICAL,
            conditions=[
                AlertCondition(field="action", operator="contains", value="secret_leak"),
            ],
            channels=[
                NotificationChannel.SLACK,
                NotificationChannel.EMAIL,
                NotificationChannel.PAGERDUTY,
            ],
        ),
        AlertRule(
            name="network_policy_violation",
            description="Network egress policy violation",
            severity=AlertSeverity.MEDIUM,
            conditions=[
                AlertCondition(field="action", operator="contains", value="egress"),
                AlertCondition(field="status", operator="eq", value="denied"),
            ],
            channels=[NotificationChannel.SLACK],
        ),
        AlertRule(
            name="tool_execution_error",
            description="Tool execution errors detected",
            severity=AlertSeverity.LOW,
            conditions=[
                AlertCondition(field="event_type", operator="eq", value="tool_call"),
                AlertCondition(field="status", operator="eq", value="error"),
            ],
            count_threshold=10,
            time_window_seconds=3600,
            channels=[NotificationChannel.SLACK],
        ),
        AlertRule(
            name="hitl_timeout_spike",
            description="Multiple HITL approvals timed out",
            severity=AlertSeverity.MEDIUM,
            conditions=[
                AlertCondition(field="action", operator="contains", value="hitl"),
                AlertCondition(field="status", operator="eq", value="timeout"),
            ],
            count_threshold=3,
            time_window_seconds=1800,
            channels=[NotificationChannel.SLACK],
        ),
        AlertRule(
            name="container_escape_attempt",
            description="Potential container escape attempt detected",
            severity=AlertSeverity.CRITICAL,
            conditions=[
                AlertCondition(field="action", operator="contains", value="container_escape"),
            ],
            channels=[
                NotificationChannel.SLACK,
                NotificationChannel.EMAIL,
                NotificationChannel.PAGERDUTY,
            ],
            cooldown_seconds=0,  # No dedup for critical security events
        ),
        AlertRule(
            name="certificate_pinning_failure",
            description="TLS certificate pinning validation failed",
            severity=AlertSeverity.HIGH,
            conditions=[
                AlertCondition(field="action", operator="contains", value="cert_pin"),
                AlertCondition(field="status", operator="eq", value="error"),
            ],
            channels=[NotificationChannel.SLACK, NotificationChannel.PAGERDUTY],
        ),
    ]


class AlertRuleEngine:
    """Evaluates audit events against alert rules and dispatches notifications.

    Supports:
    - Field matching with multiple operators
    - Windowed counting rules (N events in T seconds)
    - Alert deduplication with configurable cooldown
    - Multiple notification channels per rule
    - Statistics tracking

    Usage:
        engine = AlertRuleEngine()
        engine.add_notifier(SlackNotifier(webhook_url="..."))
        engine.add_notifier(EmailNotifier(to_addresses=["security@example.com"]))

        # Evaluate an event
        alerts = await engine.evaluate(audit_event)
    """

    def __init__(self, rules: list[AlertRule] | None = None):
        """Initialize alert rule engine.

        Args:
            rules: Alert rules. If None, uses default rules.
        """
        self._rules = rules if rules is not None else get_default_rules()
        self._notifiers: dict[NotificationChannel, Notifier] = {}

        # Dedup tracking: rule_name -> last alert timestamp
        self._last_alert_time: dict[str, float] = {}

        # Window counting: rule_name -> list of event timestamps
        self._event_windows: dict[str, list[float]] = defaultdict(list)

        # Statistics
        self.stats: dict[str, Any] = {
            "events_evaluated": 0,
            "alerts_generated": 0,
            "alerts_deduplicated": 0,
            "notifications_sent": 0,
            "notifications_failed": 0,
            "per_rule": {},
        }

        for rule in self._rules:
            self.stats["per_rule"][rule.name] = {
                "matches": 0,
                "alerts": 0,
                "deduplicated": 0,
            }

    @property
    def rules(self) -> list[AlertRule]:
        """Get configured rules."""
        return list(self._rules)

    def add_rule(self, rule: AlertRule) -> None:
        """Add an alert rule."""
        self._rules.append(rule)
        self.stats["per_rule"][rule.name] = {
            "matches": 0,
            "alerts": 0,
            "deduplicated": 0,
        }

    def remove_rule(self, rule_name: str) -> None:
        """Remove an alert rule by name."""
        self._rules = [r for r in self._rules if r.name != rule_name]

    def add_notifier(self, notifier: Notifier) -> None:
        """Register a notification channel."""
        self._notifiers[notifier.channel] = notifier

    def remove_notifier(self, channel: NotificationChannel) -> None:
        """Remove a notification channel."""
        self._notifiers.pop(channel, None)

    async def evaluate(self, event: AuditEvent) -> list[Alert]:
        """Evaluate an event against all rules.

        Returns list of alerts that were triggered and sent.
        """
        self.stats["events_evaluated"] += 1
        triggered_alerts: list[Alert] = []

        for rule in self._rules:
            if not rule.enabled:
                continue

            if self._matches_rule(event, rule):
                rule_stats = self.stats["per_rule"].get(rule.name, {})
                rule_stats["matches"] = rule_stats.get("matches", 0) + 1

                # Check windowed counting
                if not self._check_window(rule):
                    continue

                # Check dedup cooldown
                if self._is_deduplicated(rule):
                    self.stats["alerts_deduplicated"] += 1
                    rule_stats["deduplicated"] = rule_stats.get("deduplicated", 0) + 1
                    continue

                # Generate alert
                alert = self._create_alert(event, rule)
                triggered_alerts.append(alert)

                # Update dedup tracking
                self._last_alert_time[rule.name] = time.time()

                # Update stats
                self.stats["alerts_generated"] += 1
                rule_stats["alerts"] = rule_stats.get("alerts", 0) + 1

                # Send notifications
                await self._send_notifications(alert)

        return triggered_alerts

    def _matches_rule(self, event: AuditEvent, rule: AlertRule) -> bool:
        """Check if event matches all conditions in a rule."""
        if not rule.conditions:
            return False
        return all(_check_condition(event, cond) for cond in rule.conditions)

    def _check_window(self, rule: AlertRule) -> bool:
        """Check windowed counting threshold.

        Returns True if threshold is met.
        """
        now = time.time()
        window = self._event_windows[rule.name]

        # Add current event
        window.append(now)

        # Prune events outside the window
        cutoff = now - rule.time_window_seconds
        self._event_windows[rule.name] = [t for t in window if t >= cutoff]

        # Check threshold
        return len(self._event_windows[rule.name]) >= rule.count_threshold

    def _is_deduplicated(self, rule: AlertRule) -> bool:
        """Check if alert should be suppressed due to dedup cooldown."""
        if rule.cooldown_seconds <= 0:
            return False

        last_time = self._last_alert_time.get(rule.name)
        if last_time is None:
            return False

        elapsed = time.time() - last_time
        return elapsed < rule.cooldown_seconds

    def _create_alert(self, event: AuditEvent, rule: AlertRule) -> Alert:
        """Create an alert from a matching event and rule."""
        event_dict = event.model_dump(mode="json")

        message = rule.description or rule.name
        if event.error_message:
            message += f" - {event.error_message}"
        message += f" (actor: {event.actor}, action: {event.action})"

        return Alert(
            rule_name=rule.name,
            severity=rule.severity,
            message=message,
            event=event_dict,
            channels=rule.channels,
            metadata={
                "rule_description": rule.description,
                "conditions_matched": len(rule.conditions),
            },
        )

    async def _send_notifications(self, alert: Alert) -> list[NotificationResult]:
        """Send alert to all configured channels for the rule."""
        results = []
        for channel in alert.channels:
            notifier = self._notifiers.get(channel)
            if notifier is None:
                continue

            result = await notifier.send(alert)
            results.append(result)

            if result.success:
                self.stats["notifications_sent"] += 1
            else:
                self.stats["notifications_failed"] += 1

        return results

    def get_stats(self) -> dict[str, Any]:
        """Get alert engine statistics."""
        return dict(self.stats)

    def reset_windows(self) -> None:
        """Reset all event counting windows."""
        self._event_windows.clear()

    def reset_dedup(self) -> None:
        """Reset deduplication state."""
        self._last_alert_time.clear()
