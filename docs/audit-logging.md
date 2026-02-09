# Audit Logging

**Phase 4.2 - Complete Audit Trail for Security and Compliance**

harombe's audit logging system provides a complete, tamper-evident record of all AI agent actions, tool executions, and security decisions. This enables security analysis, compliance reporting, and forensic investigation.

## Overview

Every interaction with the MCP Gateway is automatically logged to a SQLite database, creating an immutable audit trail that captures:

- **Audit Events** - Request/response pairs with timing and correlation tracking
- **Tool Calls** - Complete record of tool executions with parameters and results
- **Security Decisions** - Authorization, egress filtering, and HITL gate decisions
- **Sensitive Data Redaction** - Automatic removal of credentials, API keys, and secrets

## Architecture

```
┌─────────────────────────────┐
│  MCP Gateway                │
│  - Receives agent requests  │
│  - Routes to containers     │
└──────────┬──────────────────┘
           │
           ▼
┌─────────────────────────────┐
│  Audit Logger               │
│  - Correlation tracking     │
│  - Sensitive data redaction │
│  - Async writes             │
└──────────┬──────────────────┘
           │
           ▼
┌─────────────────────────────┐
│  Audit Database (SQLite)    │
│  - audit_events             │
│  - tool_calls               │
│  - security_decisions       │
│  - Indexed for fast queries │
└─────────────────────────────┘
```

## Database Schema

### audit_events

Core event log capturing all MCP Gateway requests and responses.

| Column         | Type      | Description                          |
| -------------- | --------- | ------------------------------------ |
| event_id       | TEXT      | Unique event identifier (UUID)       |
| correlation_id | TEXT      | Links request/response pairs         |
| session_id     | TEXT      | Agent session identifier (optional)  |
| timestamp      | TIMESTAMP | Event timestamp (UTC)                |
| event_type     | TEXT      | request, response, error             |
| actor          | TEXT      | Agent or user identifier             |
| tool_name      | TEXT      | Name of tool being called (optional) |
| action         | TEXT      | Action being performed               |
| metadata       | TEXT      | JSON metadata (redacted)             |
| duration_ms    | INTEGER   | Request duration in milliseconds     |
| status         | TEXT      | success, error, pending              |
| error_message  | TEXT      | Error description (redacted)         |

**Indexes:**

- `idx_events_correlation` - Fast correlation tracking
- `idx_events_session` - Session-based queries
- `idx_events_timestamp` - Time-range queries
- `idx_events_tool` - Tool-specific queries

### tool_calls

Detailed record of tool executions.

| Column         | Type      | Description                   |
| -------------- | --------- | ----------------------------- |
| call_id        | TEXT      | Unique call identifier (UUID) |
| correlation_id | TEXT      | Links to audit_events         |
| session_id     | TEXT      | Session identifier (optional) |
| timestamp      | TIMESTAMP | Call timestamp (UTC)          |
| tool_name      | TEXT      | Name of tool executed         |
| method         | TEXT      | Method/function called        |
| parameters     | TEXT      | JSON parameters (redacted)    |
| result         | TEXT      | JSON result (redacted)        |
| error          | TEXT      | Error message if failed       |
| duration_ms    | INTEGER   | Execution duration            |
| container_id   | TEXT      | Docker container identifier   |

**Indexes:**

- `idx_tools_correlation` - Link to events
- `idx_tools_timestamp` - Time-range queries

### security_decisions

Record of all security decisions (authorization, egress, secret scanning, HITL).

| Column         | Type      | Description                                 |
| -------------- | --------- | ------------------------------------------- |
| decision_id    | TEXT      | Unique decision identifier (UUID)           |
| correlation_id | TEXT      | Links to audit_events                       |
| session_id     | TEXT      | Session identifier (optional)               |
| timestamp      | TIMESTAMP | Decision timestamp (UTC)                    |
| decision_type  | TEXT      | authorization, egress, secret_scan, hitl    |
| decision       | TEXT      | allow, deny, require_confirmation, redacted |
| reason         | TEXT      | Explanation for decision                    |
| context        | TEXT      | JSON context (redacted)                     |
| tool_name      | TEXT      | Tool involved in decision (optional)        |
| actor          | TEXT      | Agent or user identifier                    |

**Indexes:**

- `idx_decisions_correlation` - Link to events
- `idx_decisions_timestamp` - Time-range queries

## Configuration

Enable audit logging in your `harombe.yaml`:

```yaml
security:
  audit:
    enabled: true
    db_path: ~/.harombe/audit.db
    retention_days: 90 # Auto-delete logs older than 90 days
    redact_sensitive: true # Redact credentials and secrets
```

## CLI Commands

### Query Events

View audit events with filtering and formatting options:

```bash
# Show recent events (default: 20)
harombe audit events

# Filter by session ID
harombe audit events --session session-abc123

# Filter by correlation ID (see entire request/response flow)
harombe audit events --correlation corr-456def

# Show more results
harombe audit events --limit 100

# Export to JSON
harombe audit events --format json > events.json

# Export to CSV
harombe audit events --format csv > events.csv
```

### Query Tool Calls

View tool execution logs:

```bash
# Show recent tool calls
harombe audit tools

# Filter by tool name
harombe audit tools --tool filesystem

# Show calls from last 24 hours
harombe audit tools --hours 24

# Show last 50 calls
harombe audit tools --limit 50

# Export to JSON
harombe audit tools --format json > tools.json
```

### Query Security Decisions

View authorization and security gate decisions:

```bash
# Show all security decisions
harombe audit security

# Filter by decision type
harombe audit security --type authorization
harombe audit security --type egress
harombe audit security --type secret_scan
harombe audit security --type hitl

# Filter by decision outcome
harombe audit security --decision allow
harombe audit security --decision deny
harombe audit security --decision require_confirmation

# Export decisions
harombe audit security --format json > decisions.json
```

### Statistics

View aggregate statistics:

```bash
# Show overall statistics
harombe audit stats

# Show stats for last 24 hours
harombe audit stats --hours 24
```

Output:

```
Event Statistics
Total events: 1,250
Unique sessions: 15
Unique requests: 625

Tool Usage
┌──────────────┬───────┬──────────────┐
│ Tool         │ Calls │ Avg Duration │
├──────────────┼───────┼──────────────┤
│ filesystem   │   450 │        125ms │
│ browser      │   300 │        850ms │
│ code_execute │   150 │      2,500ms │
│ web_search   │    75 │      1,200ms │
└──────────────┴───────┴──────────────┘

Security Decisions
┌─────────────────────┬───────┐
│ Decision            │ Count │
├─────────────────────┼───────┤
│ allow               │   580 │
│ deny                │    25 │
│ require_confirmation│    15 │
│ redacted            │     5 │
└─────────────────────┴───────┘
```

### Export Logs

Export complete audit trail to file:

```bash
# Export to JSON (includes all events, tool calls, and decisions)
harombe audit export audit_export.json

# Export only last 24 hours
harombe audit export audit_export.json --hours 24

# Export to CSV (tool calls only)
harombe audit export audit_export.csv --format csv
```

## Programmatic Usage

### Basic Audit Logging

```python
from harombe.security.audit_logger import AuditLogger
from harombe.security.audit_db import SecurityDecision

# Create audit logger
logger = AuditLogger(
    db_path="~/.harombe/audit.db",
    retention_days=90,
    redact_sensitive=True,
)

# Start async writer
await logger.start()

try:
    # Log request start
    correlation_id = logger.start_request_sync(
        actor="agent-abc123",
        tool_name="filesystem",
        action="tools/call",
        metadata={"method": "read_file", "path": "/etc/hosts"},
        session_id="session-1",
    )

    # Log tool execution
    logger.log_tool_call(
        correlation_id=correlation_id,
        tool_name="filesystem",
        method="read_file",
        parameters={"path": "/etc/hosts"},
        result={"content": "127.0.0.1 localhost"},
        duration_ms=50,
        session_id="session-1",
    )

    # Log security decision
    logger.log_security_decision(
        correlation_id=correlation_id,
        decision_type="authorization",
        decision=SecurityDecision.ALLOW,
        reason="Path is not sensitive",
        actor="agent-abc123",
        tool_name="filesystem",
        session_id="session-1",
    )

    # Log request completion
    logger.end_request_sync(
        correlation_id=correlation_id,
        status="success",
        duration_ms=100,
    )

finally:
    # Stop async writer
    await logger.stop()
```

### Query Audit Logs

```python
from harombe.security.audit_db import AuditDatabase
from datetime import datetime, timedelta

# Open audit database
db = AuditDatabase(db_path="~/.harombe/audit.db")

# Get events by correlation (complete request/response flow)
events = db.get_events_by_correlation("correlation-id-here")
for event in events:
    print(f"{event['timestamp']}: {event['action']} - {event['status']}")

# Get events by session
events = db.get_events_by_session("session-1", limit=50)

# Get tool calls for a specific tool
calls = db.get_tool_calls(tool_name="filesystem")
for call in calls:
    print(f"{call['method']}: {call['duration_ms']}ms")

# Get tool calls in time range
start_time = datetime.utcnow() - timedelta(hours=24)
calls = db.get_tool_calls(start_time=start_time)

# Get security decisions
decisions = db.get_security_decisions(decision_type="authorization")
for dec in decisions:
    print(f"{dec['decision']}: {dec['reason']}")

# Get statistics
stats = db.get_statistics()
print(f"Total events: {stats['events']['total_events']}")
print(f"Unique sessions: {stats['events']['unique_sessions']}")
```

## Sensitive Data Redaction

The audit logger automatically redacts sensitive information before logging:

### Redacted Patterns

- **API Keys**: `API_KEY=sk-abc123` → `API_KEY=[REDACTED]`
- **Passwords**: `password=secret` → `password=[REDACTED]`
- **JWT Tokens**: `eyJhbGc...` → `[REDACTED]`
- **Credit Cards**: `4532-1488-0343-6467` → `[REDACTED]`
- **Email Addresses**: `user@example.com` → `[REDACTED]`
- **Private Keys**: `-----BEGIN RSA PRIVATE KEY-----` → `[REDACTED]`
- **Environment Secrets**: `SECRET=value` → `SECRET=[REDACTED]`

### Custom Redaction

```python
from harombe.security.audit_logger import SensitiveDataRedactor

# Redact text
text = "API_KEY=sk-1234567890abcdef"
redacted = SensitiveDataRedactor.redact(text)
# Output: "API_KEY=[REDACTED]"

# Redact dictionary
data = {
    "username": "admin",
    "password": "secret123",
    "api_key": "sk-abc123",
}
redacted_data = SensitiveDataRedactor.redact_dict(data)
# Output: {"username": "admin", "password": "[REDACTED]", "api_key": "[REDACTED]"}

# Hash sensitive value for correlation (without logging it)
api_key_hash = SensitiveDataRedactor.hash_sensitive("sk-1234567890abcdef")
# Output: "a3f2c1b4d5e6f7g8"  (first 16 chars of SHA256)
```

## Retention Policy

Audit logs are automatically cleaned up based on the configured retention period:

```yaml
security:
  audit:
    retention_days: 90 # Delete logs older than 90 days
```

- Cleanup runs on database initialization (gateway startup)
- Uses `VACUUM` to reclaim disk space
- Set `retention_days: 0` to disable automatic cleanup

## Performance Considerations

### Async Writes

The audit logger uses async writes to avoid blocking MCP Gateway requests:

- Events are queued in memory
- Background worker writes to database
- Non-blocking for fast request handling

### Database Optimization

SQLite is configured for optimal concurrency:

- **WAL mode** - Write-Ahead Logging for better concurrency
- **Indexed queries** - Fast lookups by correlation, session, time, tool
- **Pagination support** - Efficient queries for large datasets

### Disk Space

Estimated storage requirements:

- **Events**: ~500 bytes per event
- **Tool calls**: ~1 KB per call
- **Decisions**: ~300 bytes per decision

Example:

- 10,000 tool calls/day = ~10 MB/day
- 90-day retention = ~900 MB

## Security Considerations

### Database Access Control

Protect the audit database file:

```bash
chmod 600 ~/.harombe/audit.db
chown harombe:harombe ~/.harombe/audit.db
```

### Tamper Detection

Consider using file integrity monitoring (FIM) tools:

```bash
# Monitor audit database for unauthorized changes
tripwire --check ~/.harombe/audit.db
```

### Backup and Archival

Regular backups for compliance:

```bash
# Daily backup
cp ~/.harombe/audit.db ~/.harombe/backups/audit-$(date +%Y%m%d).db

# Compress and archive
gzip ~/.harombe/backups/audit-*.db
```

### Export for SIEM

Integrate with Security Information and Event Management (SIEM) systems:

```bash
# Export to JSON for ingestion
harombe audit export /var/log/harombe/audit-$(date +%Y%m%d).json --hours 24

# Send to SIEM (example: Splunk)
/opt/splunkforwarder/bin/splunk add oneshot /var/log/harombe/audit-*.json
```

## Compliance Use Cases

### SOC 2 Type II

Audit logs support SOC 2 controls:

- **CC6.1** - Logical access controls
- **CC6.2** - System monitoring
- **CC7.2** - System operation detection
- **CC7.3** - Incident response

Query examples:

```bash
# Who accessed what data?
harombe audit tools --tool filesystem --limit 1000 > access_log.csv

# What security decisions were made?
harombe audit security > security_decisions.csv

# Failed operations (potential security incidents)
harombe audit events --format json | jq '.[] | select(.status=="error")'
```

### GDPR Data Subject Access Requests (DSAR)

Retrieve all activities for a specific user:

```python
# Get all events for a user
events = db.get_events_by_session(session_id="user-session-id")

# Get all tool calls by the user
calls = db.get_tool_calls()
user_calls = [c for c in calls if c.get('session_id') == 'user-session-id']

# Export to JSON for DSAR response
import json
with open('dsar_response.json', 'w') as f:
    json.dump({
        'events': events,
        'tool_calls': user_calls,
    }, f, indent=2)
```

### Forensic Investigation

Reconstruct agent behavior during security incident:

```bash
# 1. Find suspicious activity
harombe audit security --decision deny --limit 100

# 2. Get correlation ID from suspicious event
harombe audit events --session compromised-session --format json

# 3. Reconstruct complete request/response flow
harombe audit events --correlation <correlation-id>

# 4. See all tool calls in that flow
harombe audit tools --format json | jq '.[] | select(.correlation_id=="<correlation-id>")'

# 5. Export complete timeline
harombe audit export incident_timeline.json --hours 48
```

## Troubleshooting

### Database Locked

If you see "database is locked" errors:

```bash
# Check for other processes using the database
lsof ~/.harombe/audit.db

# Kill stale connections
kill -9 <pid>

# Verify WAL mode is enabled
sqlite3 ~/.harombe/audit.db "PRAGMA journal_mode;"
# Should output: wal
```

### Disk Space

Monitor disk usage:

```bash
# Check database size
du -h ~/.harombe/audit.db

# Check how many records
sqlite3 ~/.harombe/audit.db "SELECT COUNT(*) FROM audit_events;"

# Manual cleanup (careful!)
sqlite3 ~/.harombe/audit.db "DELETE FROM audit_events WHERE timestamp < datetime('now', '-90 days');"
sqlite3 ~/.harombe/audit.db "VACUUM;"
```

### Performance Issues

If queries are slow:

```sql
-- Check if indexes exist
SELECT name FROM sqlite_master WHERE type='index';

-- Rebuild indexes
REINDEX;

-- Analyze query performance
EXPLAIN QUERY PLAN SELECT * FROM audit_events WHERE correlation_id = 'xxx';

-- Consider archiving old data
-- Move records older than 1 year to archive database
```

## Next Steps

- **Phase 4.3** - Secret management with Vault integration
- **Phase 4.4** - Network isolation with egress filtering
- **Phase 4.5** - Human-in-the-loop (HITL) confirmation gates
- **Phase 4.6** - Browser container with pre-authenticated sessions
- **Phase 4.7** - Code execution sandbox with gVisor
- **Phase 4.8** - End-to-end security integration and testing

## References

- [SQLite WAL Mode](https://www.sqlite.org/wal.html)
- [SOC 2 Audit Logs Best Practices](https://www.vanta.com/resources/audit-logs-soc-2)
- [GDPR Article 15 - Right of Access](https://gdpr-info.eu/art-15-gdpr/)
