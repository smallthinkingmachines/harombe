# ADR-004: Use SQLite for Audit Logging

**Status**: Accepted
**Date**: 2026-02

## Context

Harombe needs an immutable audit trail for compliance and security monitoring. Every tool invocation, agent decision, and human approval must be recorded with timestamps and context. The options considered were:

1. **SQLite** — embedded relational database, zero external dependencies.
2. **PostgreSQL** — full-featured RDBMS, requires separate server process.
3. **File-based logging** — append-only log files (JSON lines or similar).
4. **External service** — cloud logging services (Datadog, CloudWatch, etc.).

The key requirements were: low write latency, ACID guarantees, zero external dependencies for local deployments, and queryable records.

## Decision

Use SQLite with WAL (Write-Ahead Logging) mode for audit logging.

## Consequences

**Positive:**

- Zero external dependencies; SQLite is included in Python's standard library.
- Less than 1ms write latency with WAL mode enabled.
- Single-file deployment makes backup and transfer straightforward.
- Full ACID guarantees ensure audit records are never partially written.
- SQL queries allow flexible analysis of audit data.

**Negative:**

- Single-writer limitation means only one process can write at a time (acceptable for per-agent logging where each agent has its own database).
- Not suitable for very high-throughput multi-agent scenarios where many agents write to the same audit log simultaneously.
- No built-in replication or clustering support.
