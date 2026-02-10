# Harombe Security Architecture Whitepaper

## Executive Summary

Harombe implements a defense-in-depth security architecture for AI agent tool execution. Unlike other open-source agent frameworks that rely on prompt-level safeguards or protocol-level trust, Harombe enforces security at the infrastructure layer using container isolation, network egress filtering, credential vaults, and human-in-the-loop approval gates.

**Key insight (Feb 2026 security research):** MCP (Model Context Protocol) cannot enforce security at the protocol level. An agent that can send arbitrary JSON-RPC messages can bypass any protocol-level restriction. All security must be enforced at the infrastructure layer.

## Threat Model

### Threats We Address

| Threat                                  | Mitigation                                                |
| --------------------------------------- | --------------------------------------------------------- |
| Agent executes malicious shell commands | Container isolation + HITL approval for dangerous tools   |
| Credential leakage via tool output      | Secret scanning + audit log redaction                     |
| Network exfiltration of sensitive data  | Per-container egress filtering with allowlists            |
| Prompt injection causing tool misuse    | Risk classification + HITL gates for high-risk operations |
| Unauthorized access to credentials      | Vault-based secret management, never in config files      |
| Lateral movement between tools          | Separate containers per capability, no shared filesystem  |
| Audit trail tampering                   | Append-only SQLite with WAL mode                          |

### Threats We Do Not Address (v0.1.0)

- Compromised host OS (assumes trusted host)
- Supply chain attacks on container images (planned for v2)
- Side-channel attacks on shared hardware
- Sophisticated evasion of content filters

## Architecture

```
┌─────────────────────────────────────────────────────┐
│  Agent Container                                     │
│  - ReAct loop + LLM                                 │
│  - Can ONLY communicate with MCP Gateway             │
│  - No direct network, filesystem, or credential access│
└───────────────┬─────────────────────────────────────┘
                │ JSON-RPC 2.0
                ▼
┌─────────────────────────────────────────────────────┐
│  MCP Gateway                                         │
│  - Authentication + authorization                    │
│  - Audit logging (every request/response)            │
│  - Secret scanning (block credential leakage)        │
│  - HITL gates (approval for dangerous operations)    │
│  - Request routing to capability containers          │
└──────┬──────────┬──────────┬───────────┬────────────┘
       │          │          │           │
       ▼          ▼          ▼           ▼
  ┌────────┐ ┌────────┐ ┌────────┐ ┌────────────┐
  │Browser │ │Files   │ │Code    │ │Web Search  │
  │Container│ │Container│ │Container│ │Container   │
  │        │ │        │ │        │ │            │
  │Pre-auth│ │Scoped  │ │gVisor  │ │Allowlisted │
  │cookies │ │volumes │ │sandbox │ │egress      │
  └────────┘ └────────┘ └────────┘ └────────────┘
```

## Security Layers

### 1. Container Isolation

Every tool capability runs in its own Docker container with:

- **Resource limits**: CPU, memory, PID caps
- **Non-root execution**: UID 1000
- **Capability dropping**: Minimal Linux capabilities
- **No shared filesystem**: Explicit volume mounts only

### 2. Network Egress Filtering

Each container has an independent network namespace with:

- **Default deny**: No outbound traffic unless explicitly allowed
- **Domain allowlists**: Wildcard support (e.g., `*.github.com`)
- **DNS filtering**: Queries logged and filtered
- **iptables rules**: Enforced at the kernel level

### 3. Credential Management

Secrets never appear in configuration files:

- **HashiCorp Vault**: Production-grade dynamic secrets
- **SOPS**: Encrypted files for team environments
- **Environment injection**: Secrets delivered at container startup, cleaned on stop
- **Secret scanning**: Detect credentials in tool output before returning to agent

### 4. Audit Logging

Every operation is logged to an append-only SQLite database:

- **Event types**: Requests, responses, tool calls, security decisions
- **Sensitive data redaction**: API keys, passwords, JWT tokens automatically scrubbed
- **Correlation IDs**: Track requests across the entire pipeline
- **Retention policies**: Configurable cleanup (default 90 days)
- **Performance**: WAL mode, <1ms writes

### 5. Human-in-the-Loop Gates

Risk-based approval system for dangerous operations:

- **Risk levels**: LOW, MEDIUM, HIGH, CRITICAL
- **Auto-deny on timeout**: 60s default, prevents unattended execution
- **CLI and API interfaces**: Rich terminal prompts or webhook notifications
- **Audit trail**: Every approval/denial decision logged

### 6. Browser Security

Pre-authenticated browser automation with:

- **Credential injection before agent access**: Agent never sees raw passwords
- **Accessibility-based interaction**: Structured semantic tree, not raw DOM
- **HttpOnly cookies**: Protected from script access
- **Password field protection**: Auto-deny typing into password/secret inputs
- **16 risk classification rules**: Covering navigation, form submission, downloads

## Comparison with Competitors

| Feature                  | Harombe            | CrewAI | LangGraph          | AutoGen | OpenClaw |
| ------------------------ | ------------------ | ------ | ------------------ | ------- | -------- |
| Container isolation      | Per-tool           | None   | None               | None    | None     |
| Network egress filtering | Per-container      | None   | None               | None    | None     |
| Credential vault         | Vault/SOPS/env     | None   | None               | None    | None     |
| Audit logging            | SQLite + redaction | None   | Langsmith (cloud)  | None    | None     |
| HITL approval gates      | Risk-based         | None   | Human-in-loop node | None    | None     |
| Secret scanning          | Pattern + entropy  | None   | None               | None    | None     |
| Browser pre-auth         | Cookie injection   | None   | None               | None    | None     |

## Configuration Example

```yaml
security:
  enabled: true
  isolation: docker

  gateway:
    host: 127.0.0.1
    port: 8100

  audit:
    enabled: true
    database: ~/.harombe/audit.db
    retention_days: 90
    redact_sensitive: true

  credentials:
    method: vault
    vault_addr: http://localhost:8200

  containers:
    browser:
      image: harombe/browser:latest
      egress_allow:
        - "*.github.com"
        - "*.google.com"
    filesystem:
      image: harombe/filesystem:latest
      egress_allow: []
      mounts:
        - /home/user/documents:ro

  hitl:
    enabled: true
    timeout: 60
```

## Limitations and Future Work

### Experimental Features (not production-validated)

- **Zero-knowledge proofs**: Protocol models implemented, not integrated end-to-end
- **Hardware security modules**: Software simulation only, requires TPM/SGX/SEV-SNP hardware
- **Compliance reporting**: Heuristic templates, not audit-grade

### Planned Improvements

- Container image signing and verification
- Runtime network enforcement (beyond declarative permissions)
- Plugin sandboxing with resource quotas
- Independent security audit engagement
