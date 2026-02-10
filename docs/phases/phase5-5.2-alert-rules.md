# Task 5.5.2: Automated Alert Rules

**Status**: Complete
**Date**: 2026-02-09

## Summary

Implemented an automated alert rule engine that evaluates audit events against configurable rules and dispatches notifications via multiple channels (Email, Slack, PagerDuty). Supports windowed counting, alert deduplication, and severity-based routing.

## Components

### AlertSeverity (Enum)

Five levels: `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`

### AlertCondition (Pydantic Model)

Field-level matching with operators: `eq`, `ne`, `contains`, `in`, `gt`, `lt`
Supports dot notation for metadata fields (e.g., `metadata.path`).

### AlertRule (Pydantic Model)

| Field                 | Default    | Description                              |
| --------------------- | ---------- | ---------------------------------------- |
| `name`                | (required) | Unique rule name                         |
| `severity`            | `MEDIUM`   | Alert severity level                     |
| `conditions`          | `[]`       | List of AlertConditions (all must match) |
| `enabled`             | `True`     | Enable/disable rule                      |
| `channels`            | `[SLACK]`  | Notification channels                    |
| `cooldown_seconds`    | `300`      | Dedup window (0 = no dedup)              |
| `count_threshold`     | `1`        | Events needed to trigger                 |
| `time_window_seconds` | `3600`     | Window for counting                      |

### Notifiers

| Notifier            | Channel   | Config                            |
| ------------------- | --------- | --------------------------------- |
| `EmailNotifier`     | EMAIL     | SMTP host/port, from/to addresses |
| `SlackNotifier`     | SLACK     | Webhook URL, channel name         |
| `PagerDutyNotifier` | PAGERDUTY | Routing key, min_severity filter  |

### AlertRuleEngine (Main Class)

1. **evaluate(event)** - Check event against all rules
2. **Windowed counting** - Require N matches in T seconds
3. **Deduplication** - Suppress duplicate alerts within cooldown
4. **Multi-channel dispatch** - Send to registered notifiers
5. **Statistics tracking** - Per-rule and aggregate metrics

### Default Rules (10 built-in)

| Rule                          | Severity | Description                    |
| ----------------------------- | -------- | ------------------------------ |
| `auth_failure_spike`          | HIGH     | 5+ auth failures in 1 hour     |
| `secret_rotation_failure`     | CRITICAL | Secret rotation failed         |
| `high_risk_denied`            | MEDIUM   | High-risk operation denied     |
| `anomaly_detected`            | HIGH     | Behavioral anomaly detected    |
| `secret_leak_detected`        | CRITICAL | Secret leak in output          |
| `network_policy_violation`    | MEDIUM   | Egress policy violation        |
| `tool_execution_error`        | LOW      | 10+ tool errors in 1 hour      |
| `hitl_timeout_spike`          | MEDIUM   | 3+ HITL timeouts in 30 min     |
| `container_escape_attempt`    | CRITICAL | Container escape attempt       |
| `certificate_pinning_failure` | HIGH     | TLS cert pin validation failed |

## Files

| File                                  | Description                       |
| ------------------------------------- | --------------------------------- |
| `src/harombe/security/alert_rules.py` | Alert rules engine implementation |
| `tests/security/test_alert_rules.py`  | 65 tests (all passing)            |

## Test Coverage

- **65 tests** across 13 test classes
- AlertSeverity enum (2)
- NotificationChannel enum (1)
- AlertCondition operators (14)
- AlertRule model (2)
- Default rules (4)
- Alert model (2)
- EmailNotifier (2)
- SlackNotifier (2)
- PagerDutyNotifier (3)
- AlertRuleEngine (15)
- Statistics (2)
- Event field extraction (4)
- Performance (2)
- Edge cases (4)

### Performance

- 1000 evaluations (10 rules each): <500ms
- 10000 condition checks: <100ms

## Architecture

```
AuditEvent
    │
    ▼
AlertRuleEngine
    │
    ├─► evaluate(event)
    │   │
    │   ├─► For each enabled rule:
    │   │   ├── _matches_rule()     ── all conditions must match
    │   │   ├── _check_window()     ── windowed counting threshold
    │   │   ├── _is_deduplicated()  ── cooldown check
    │   │   └── _create_alert()     ── generate Alert object
    │   │
    │   └─► _send_notifications()
    │       ├── EmailNotifier.send()
    │       ├── SlackNotifier.send()
    │       └── PagerDutyNotifier.send()
    │
    ├─► add_rule() / remove_rule()
    ├─► add_notifier() / remove_notifier()
    └─► get_stats()
```

## Acceptance Criteria

- [x] Evaluates 10+ alert rules (10 default rules)
- [x] Sends alerts within 1 minute (<1ms per evaluation)
- [x] Supports multiple notification channels (Email, Slack, PagerDuty)
- [x] Alert deduplication with configurable cooldown
- [x] Rule DSL with field matching operators
