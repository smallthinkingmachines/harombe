# ADR-003: Adopt Capability-Container Security Pattern

**Status**: Accepted
**Date**: 2026-02

## Context

Research in February 2026 revealed that MCP (Model Context Protocol) cannot enforce security at the protocol level alone. The protocol defines how agents communicate with tools, but it does not provide isolation, credential management, or access control enforcement. Without infrastructure-level enforcement, a compromised or misbehaving tool could access host resources, leak credentials, or interfere with other tools.

Harombe needed a security model that provides strong isolation guarantees independent of the protocol layer.

## Decision

Every tool runs in its own isolated Docker container. The agent communicates exclusively through an MCP Gateway and never directly touches raw credentials, host filesystems, or unrestricted networks. This is the Capability-Container Pattern:

- Each tool container receives only the specific capabilities it needs (filesystem mounts, network access, environment variables).
- The MCP Gateway mediates all communication, enforcing access policies and injecting credentials at runtime.
- Containers can optionally use gVisor for additional syscall-level isolation.

## Consequences

**Positive:**

- Strong isolation between tools prevents lateral movement if one tool is compromised.
- Credential management happens at the gateway level, so tools never see raw secrets.
- Full audit trail of all tool invocations and their results.
- Security enforcement is infrastructure-level, independent of tool implementation quality.

**Negative:**

- Container overhead adds latency to tool invocations (cold start and inter-process communication).
- Docker becomes a hard dependency for production security (development mode can run without it).
- Increased operational complexity for deployment and debugging.
