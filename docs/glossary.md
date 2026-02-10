# Glossary

Key terms used throughout the harombe documentation.

---

ADR
: Architecture Decision Record — a document that captures an important architectural decision along with its context and consequences. Used to maintain a decision log for the project.

Capability-Container Pattern
: Harombe's security isolation model where every tool runs in its own isolated container. The agent communicates through an MCP Gateway, never directly touching raw credentials, host filesystems, or unrestricted networks.

Circuit Breaker
: A fault tolerance pattern that prevents cascading failures in distributed systems. Has three states: Closed (normal), Open (failing, traffic blocked), Half-Open (testing recovery).

gVisor
: Google's application kernel that provides an additional layer of isolation between containers and the host OS. Intercepts syscalls at the kernel boundary, reducing the attack surface from 300+ to ~70 syscalls.

HITL
: Human-in-the-Loop — approval gates that require human confirmation before executing high-risk operations. Harombe classifies operations by risk level (LOW/MEDIUM/HIGH/CRITICAL) and routes accordingly.

MCP
: Model Context Protocol — a standardized JSON-RPC 2.0 protocol for communication between AI agents and tool servers. Developed by Anthropic for secure, structured tool execution.

mDNS
: Multicast DNS — a zero-configuration networking protocol for service discovery on local networks. Harombe uses mDNS to automatically discover other harombe nodes without manual configuration.

PII
: Personally Identifiable Information — data that could identify a specific individual. The Privacy Router detects and redacts PII before sending queries to cloud LLM providers.

RAG
: Retrieval-Augmented Generation — a technique where relevant context is retrieved from a knowledge store (vector database) and injected into the LLM prompt before generation, improving accuracy and grounding.

ReAct Loop
: Reasoning + Acting pattern for autonomous agents. The agent alternates between reasoning about what to do and executing actions (tool calls), repeating until the task is complete or a step limit is reached.

SOPS
: Secrets OPerationS — Mozilla's tool for encrypting secret files. Supports age and GPG encryption, and is version-control friendly (encrypted files can be stored in git).

WAL
: Write-Ahead Logging — an SQLite journaling mode that improves write performance by appending to a log file rather than modifying the database directly. Used by harombe's audit logger for <1ms write latency.
