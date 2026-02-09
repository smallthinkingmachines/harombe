# Phase 4 Implementation Plan: Security Layer

**Status:** Planning
**Start Date:** TBD
**Target Completion:** TBD

## Executive Summary

Phase 4 implements the **Capability-Container Pattern** for securing AI agent tool execution. Every tool runs in an isolated container, with the agent communicating through an MCP Gateway that enforces security policies, manages credentials, and provides full audit trails.

**Key Insight from Feb 2026 Research:** MCP protocol alone cannot enforce security — all security must be enforced at the infrastructure layer through containers, network policies, and gateways.

---

## Goals

### Primary Objectives

1. **Prevent credential leakage** — Agent never sees raw credentials
2. **Isolate tool execution** — Each tool runs in its own container with resource limits
3. **Enforce egress control** — Per-tool network allowlists
4. **Enable audit & compliance** — Full trail of all agent decisions and tool calls
5. **Support HITL gates** — Human confirmation for destructive operations

### Non-Goals (Out of Scope)

- Multi-tenant hosting (single-user/team focus)
- Firecracker VMs (Docker + gVisor sufficient)
- Cloud credential management (focus on self-hosted)
- Advanced browser automation (basic pre-auth container only)

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────┐
│  Agent Container                                    │
│  - ReAct loop, LLM inference                        │
│  - Can ONLY talk to MCP Gateway                     │
│  - No direct network, filesystem, or credential     │
│    access                                           │
└──────────────────┬──────────────────────────────────┘
                   │ HTTP/JSON-RPC
                   ▼
┌─────────────────────────────────────────────────────┐
│  MCP Gateway (Security Enforcement Point)           │
│  - Request authentication & authorization           │
│  - Secret scanning (redact credentials)             │
│  - Audit logging (every request/response)           │
│  - HITL gates (confirm destructive actions)         │
│  - Route to appropriate capability container        │
└──┬────────┬─────────┬────────────┬──────────────────┘
   │        │         │            │
   ▼        ▼         ▼            ▼
┌────────┐ ┌───────┐ ┌─────────┐ ┌─────────────────┐
│Browser │ │Files  │ │Code Exec│ │Other MCP        │
│Container│ │Container│ │(gVisor)│ │Servers          │
│        │ │       │ │         │ │(containerized)  │
│Pre-auth│ │Scoped │ │Sandbox  │ │Per-tool         │
│cookies │ │volumes│ │Network  │ │isolation        │
│        │ │       │ │isolated │ │                 │
└────────┘ └───────┘ └─────────┘ └─────────────────┘
```

### Key Components

1. **MCP Gateway** — Central security hub, routes all MCP requests
2. **Agent Container** — Isolated agent process, no direct tool access
3. **Capability Containers** — Purpose-built containers per tool category
4. **Credential Vault** — HashiCorp Vault or SOPS for secrets
5. **Audit Database** — SQLite/Postgres for compliance logging

---

## Implementation Phases

### Phase 4.1: Foundation (Weeks 1-2)

**Goal:** Basic MCP Gateway with Docker container support

#### Tasks

1. **Design MCP Gateway Architecture**
   - Define JSON-RPC protocol for gateway ↔ containers
   - Design request/response flow
   - Error handling strategy
   - Timeout and retry policies

2. **Implement Basic MCP Gateway**
   - FastAPI server on port 8100
   - JSON-RPC request routing
   - Health check endpoints
   - Connection pooling for MCP servers

3. **Docker Container Management**
   - Docker Compose setup for multi-container deployment
   - Container lifecycle management (start/stop/restart)
   - Resource limits (CPU, memory, network)
   - Volume mounting strategies

4. **Configuration Schema**
   - Add `security` section to `harombe.yaml`
   - Container definitions (image, resources, mounts)
   - Network policies (egress allowlists)
   - HITL rules (which tools require confirmation)

**Deliverables:**

- `src/harombe/security/gateway.py` — MCP Gateway implementation
- `src/harombe/security/docker_manager.py` — Container lifecycle
- `docker/docker-compose.yml` — Multi-container setup
- `tests/security/test_gateway.py` — Gateway tests
- Updated config schema with security section

**Success Criteria:**

- Gateway can route requests to containerized MCP servers
- Containers start/stop cleanly
- Basic health monitoring works

---

### Phase 4.2: Audit Logging (Week 3)

**Goal:** Full audit trail of all agent actions

#### Tasks

1. **Audit Database Schema**
   - SQLite schema for audit logs
   - Tables: requests, responses, tool_calls, decisions
   - Indexes for efficient queries
   - Retention policies

2. **Audit Logger Implementation**
   - Structured logging format (JSON)
   - Async writes (don't block requests)
   - Request correlation IDs
   - Sensitive data redaction

3. **Audit Query Interface**
   - CLI commands to query audit logs
   - Filter by session, tool, time range
   - Export to CSV/JSON for compliance
   - Statistics and reports

4. **Tests and Documentation**
   - Unit tests for audit logger
   - Integration tests with gateway
   - Audit log schema documentation
   - Query examples

**Deliverables:**

- `src/harombe/security/audit.py` — Audit logger
- `src/harombe/security/audit_schema.py` — Database schema
- `src/harombe/cli/audit.py` — CLI commands
- `tests/security/test_audit.py` — Tests
- `docs/security-audit.md` — Documentation

**Success Criteria:**

- Every tool call logged with full context
- Logs queryable via CLI
- No performance impact on agent (<5ms overhead)

---

### Phase 4.3: Secret Management (Week 4)

**Goal:** Zero credentials in LLM context or logs

#### Tasks

1. **Credential Vault Integration**
   - HashiCorp Vault client implementation
   - SOPS file encryption support (alternative)
   - Secret injection at container startup
   - Time-limited tokens (auto-refresh)

2. **Secret Scanning**
   - Regex patterns for common secrets (API keys, tokens, passwords)
   - Entropy-based detection
   - Redaction in responses before reaching agent
   - Alert on credential leakage attempts

3. **Environment Variable Injection**
   - Secure .env file handling
   - Per-container environment isolation
   - No secrets in config files
   - Vault → Container environment pipeline

4. **Credential Rotation**
   - Automatic token refresh
   - Graceful rotation (no downtime)
   - Rotation schedules per credential type
   - Audit trail for rotation events

**Deliverables:**

- `src/harombe/security/vault.py` — Vault integration
- `src/harombe/security/secrets.py` — Secret scanning
- `src/harombe/security/injection.py` — Environment injection
- `tests/security/test_vault.py` — Tests
- `docs/security-credentials.md` — Documentation

**Success Criteria:**

- Credentials never in agent context
- Secrets detected and redacted in <10ms
- Vault tokens auto-refresh without disruption

---

### Phase 4.4: Network Isolation (Week 5)

**Goal:** Per-container egress allowlists

#### Tasks

1. **Docker Network Policies**
   - Custom Docker networks per container
   - Egress filtering via iptables
   - DNS allowlisting
   - Network telemetry (connections, bandwidth)

2. **Egress Configuration**
   - Per-tool allowlist in config
   - Domain → IP resolution
   - Wildcard and CIDR support
   - Dynamic policy updates (no restart)

3. **Monitoring and Alerts**
   - Log blocked connection attempts
   - Alert on suspicious patterns
   - Network usage metrics
   - Integration with audit log

4. **Testing and Validation**
   - Unit tests for policy enforcement
   - Integration tests with real containers
   - Performance benchmarks
   - Documentation with examples

**Deliverables:**

- `src/harombe/security/network.py` — Network policies
- `docker/firewall-rules.sh` — iptables setup
- `tests/security/test_network.py` — Tests
- `docs/security-network.md` — Documentation

**Success Criteria:**

- Containers can only reach allowlisted domains
- Blocked attempts logged
- <1ms latency overhead

---

### Phase 4.5: HITL Gates (Week 6)

**Goal:** Human confirmation for destructive operations

#### Tasks

1. **HITL Gate Framework**
   - Async confirmation prompt system
   - CLI and web confirmation interfaces
   - Timeout handling (auto-deny after 60s)
   - Queue management (multiple pending requests)

2. **Action Classification**
   - Regex-based action matching
   - Destructive action database
   - Per-tool risk levels
   - User-configurable rules

3. **Confirmation UI**
   - Rich CLI prompts with action details
   - Web UI for remote confirmation
   - Mobile push notifications (future)
   - Action preview and impact analysis

4. **Testing and Documentation**
   - Unit tests for gate logic
   - Integration tests with real tools
   - User documentation
   - Example configurations

**Deliverables:**

- `src/harombe/security/hitl.py` — HITL gate framework
- `src/harombe/cli/confirm.py` — CLI confirmation
- `tests/security/test_hitl.py` — Tests
- `docs/security-hitl.md` — Documentation

**Success Criteria:**

- Destructive actions blocked until confirmed
- <5s confirmation prompt display
- Clear action preview for user

---

### Phase 4.6: Browser Container (Week 7)

**Goal:** Pre-authenticated browser with accessibility APIs

#### Tasks

1. **Browser Container Setup**
   - Playwright/Puppeteer in Docker
   - Persistent profile storage
   - Cookie management (pre-auth)
   - Headless + headed modes

2. **Accessibility API Integration**
   - Extract structured elements (not raw DOM)
   - Action primitives (click, type, read)
   - Navigation and interaction
   - Screenshot capture

3. **Security Hardening**
   - HttpOnly cookies
   - Network isolation (egress allowlist)
   - No arbitrary JavaScript execution
   - Sandboxed rendering

4. **MCP Server Implementation**
   - Browser MCP server (JSON-RPC)
   - Tool schema definitions
   - Error handling and retries
   - Tests and documentation

**Deliverables:**

- `docker/browser/Dockerfile` — Browser container
- `src/harombe/mcp/servers/browser.py` — MCP server
- `tests/mcp/test_browser.py` — Tests
- `docs/security-browser.md` — Documentation

**Success Criteria:**

- Browser maintains auth across sessions
- Accessibility API extracts structured data
- No DOM/CDP access from agent

---

### Phase 4.7: Code Execution Sandbox (Week 8)

**Goal:** gVisor-based code execution

#### Tasks

1. **gVisor Setup**
   - Docker + gVisor runtime configuration
   - OCI runtime integration
   - Performance tuning
   - Compatibility testing

2. **Execution Environment**
   - Language runtime containers (Python, Node, etc.)
   - Package caching
   - Timeout enforcement
   - Output capture and streaming

3. **Security Controls**
   - No network access (unless allowlisted)
   - Read-only filesystem (except /tmp)
   - Resource limits (CPU, memory, disk)
   - Syscall filtering

4. **MCP Server Implementation**
   - Code execution MCP server
   - Language detection
   - Dependency management
   - Tests and documentation

**Deliverables:**

- `docker/code-exec/Dockerfile` — Code execution container
- `docker/gvisor-config.json` — gVisor runtime config
- `src/harombe/mcp/servers/code_exec.py` — MCP server
- `tests/mcp/test_code_exec.py` — Tests
- `docs/security-code-exec.md` — Documentation

**Success Criteria:**

- Code runs in gVisor sandbox
- No host system access
- Execution time <10s for simple scripts

---

### Phase 4.8: Integration & Polish (Week 9-10)

**Goal:** End-to-end security, testing, documentation

#### Tasks

1. **End-to-End Integration**
   - Agent → Gateway → Containers full flow
   - Multi-tool orchestration
   - Error recovery and retry logic
   - Performance optimization

2. **Security Testing**
   - Penetration testing
   - Credential leakage tests
   - Container escape attempts
   - Network isolation verification

3. **Documentation**
   - Security architecture guide
   - Deployment instructions
   - Configuration examples
   - Troubleshooting guide

4. **Examples and Demos**
   - Secure multi-tool agent example
   - Browser automation example
   - Code execution example
   - Audit log analysis example

**Deliverables:**

- `examples/10_secure_agent.py` — Full security example
- `docs/security-architecture.md` — Architecture guide
- `docs/security-deployment.md` — Deployment guide
- `docs/security-troubleshooting.md` — Troubleshooting
- Security audit report

**Success Criteria:**

- All security features work together
- No known vulnerabilities
- Clear documentation for deployment
- Performance acceptable (<100ms overhead)

---

## Configuration Schema

### harombe.yaml (Security Section)

```yaml
security:
  enabled: true
  isolation: docker # docker | gvisor

  gateway:
    host: 127.0.0.1
    port: 8100
    timeout: 30 # seconds
    max_retries: 3

  audit:
    enabled: true
    database: ~/.harombe/audit.db
    retention_days: 90
    log_level: INFO # DEBUG | INFO | WARN | ERROR

  credentials:
    method: vault # env | vault | sops
    vault_addr: http://localhost:8200
    vault_token: ~/.vault-token
    auto_refresh: true
    rotation_days: 30

  containers:
    # Browser container
    browser:
      image: harombe/browser:latest
      enabled: true
      resources:
        cpu_limit: "2"
        memory_limit: "2g"
      egress_allow:
        - "*.google.com"
        - "*.github.com"
      interaction_mode: accessibility # accessibility | dom | cdp
      confirm_actions:
        - "send_email"
        - "delete_*"
        - "post_*"

    # Filesystem container
    filesystem:
      image: harombe/filesystem:latest
      enabled: true
      resources:
        cpu_limit: "1"
        memory_limit: "512m"
      mounts:
        - "/home/user/documents:/workspace:ro"
        - "/home/user/projects:/projects:rw"
      egress_allow: [] # No network access

    # Code execution container
    code_exec:
      image: harombe/code-exec:latest
      enabled: true
      sandbox: gvisor
      resources:
        cpu_limit: "2"
        memory_limit: "1g"
      egress_allow: [] # No network unless specified
      timeout: 30 # seconds
      languages:
        - python
        - javascript
        - bash

    # Web search (external API)
    web_search:
      image: harombe/web-search:latest
      enabled: true
      resources:
        cpu_limit: "0.5"
        memory_limit: "256m"
      egress_allow:
        - "api.duckduckgo.com"

  hitl:
    enabled: true
    timeout: 60 # seconds before auto-deny
    notification:
      method: cli # cli | webhook | email
      webhook_url: null # For remote confirmation
```

---

## Directory Structure

```
harombe/
├── src/harombe/
│   ├── security/              # NEW: Security layer
│   │   ├── __init__.py
│   │   ├── gateway.py         # MCP Gateway server
│   │   ├── docker_manager.py  # Container lifecycle
│   │   ├── audit.py           # Audit logging
│   │   ├── audit_schema.py    # Database schema
│   │   ├── vault.py           # Credential vault
│   │   ├── secrets.py         # Secret scanning
│   │   ├── injection.py       # Env injection
│   │   ├── network.py         # Network policies
│   │   ├── hitl.py            # HITL gates
│   │   └── config.py          # Security config
│   │
│   ├── mcp/                   # NEW: MCP server implementations
│   │   ├── __init__.py
│   │   ├── protocol.py        # JSON-RPC protocol
│   │   ├── servers/
│   │   │   ├── __init__.py
│   │   │   ├── browser.py     # Browser automation
│   │   │   ├── filesystem.py  # File operations
│   │   │   ├── code_exec.py   # Code execution
│   │   │   └── web_search.py  # Web search
│   │   └── client.py          # MCP client
│   │
│   └── cli/
│       ├── audit.py           # NEW: Audit query commands
│       └── confirm.py         # NEW: HITL confirmation
│
├── docker/                    # NEW: Container definitions
│   ├── docker-compose.yml     # Multi-container orchestration
│   ├── agent/
│   │   └── Dockerfile         # Agent container
│   ├── gateway/
│   │   └── Dockerfile         # Gateway container
│   ├── browser/
│   │   ├── Dockerfile         # Browser container
│   │   └── entrypoint.sh
│   ├── filesystem/
│   │   └── Dockerfile
│   ├── code-exec/
│   │   ├── Dockerfile
│   │   └── gvisor-config.json
│   ├── web-search/
│   │   └── Dockerfile
│   └── firewall-rules.sh      # iptables setup
│
├── docs/
│   ├── phase4-implementation-plan.md  # This file
│   ├── security-architecture.md       # Architecture guide
│   ├── security-audit.md              # Audit logging guide
│   ├── security-credentials.md        # Credential management
│   ├── security-network.md            # Network isolation
│   ├── security-hitl.md               # HITL gates
│   ├── security-browser.md            # Browser container
│   ├── security-code-exec.md          # Code execution
│   ├── security-deployment.md         # Deployment guide
│   └── security-troubleshooting.md    # Troubleshooting
│
├── examples/
│   └── 10_secure_agent.py     # NEW: Secure multi-tool agent
│
└── tests/
    ├── security/              # NEW: Security tests
    │   ├── test_gateway.py
    │   ├── test_audit.py
    │   ├── test_vault.py
    │   ├── test_network.py
    │   └── test_hitl.py
    └── mcp/                   # NEW: MCP server tests
        ├── test_browser.py
        ├── test_filesystem.py
        ├── test_code_exec.py
        └── test_web_search.py
```

---

## Dependencies

### New Python Packages

```toml
[project.dependencies]
# Existing...

# Phase 4 additions
docker>=7.0            # Docker SDK for Python
hvac>=2.0             # HashiCorp Vault client (optional)
sops>=0.1             # SOPS encryption (optional)
playwright>=1.40      # Browser automation (optional)
```

### System Dependencies

- Docker Engine 24.0+
- gVisor runtime (for code execution)
- iptables (for network policies)
- HashiCorp Vault (optional, for credential management)

---

## Testing Strategy

### Unit Tests

- Gateway routing logic
- Audit logger
- Secret scanning
- Network policy enforcement
- HITL gate logic

### Integration Tests

- Agent → Gateway → Container flow
- Multi-tool orchestration
- Credential injection
- Network isolation verification
- Audit log accuracy

### Security Tests

- Credential leakage detection
- Container escape attempts
- Network bypass attempts
- Privilege escalation tests
- Secret scanning accuracy

### Performance Tests

- Gateway latency (<5ms overhead)
- Container startup time (<2s)
- Audit write performance (>1000 ops/s)
- Network policy latency (<1ms)

---

## Risks and Mitigations

### Risk 1: Performance Overhead

**Impact:** High
**Likelihood:** Medium

**Mitigation:**

- Benchmark early and often
- Async operations where possible
- Connection pooling
- Caching frequently used data

### Risk 2: Docker Complexity

**Impact:** Medium
**Likelihood:** High

**Mitigation:**

- Start with Docker Compose (simple)
- Comprehensive error handling
- Clear documentation
- Fallback to non-isolated mode for development

### Risk 3: gVisor Compatibility

**Impact:** Medium
**Likelihood:** Medium

**Mitigation:**

- Make gVisor optional (Docker-only mode)
- Test on multiple platforms
- Document known limitations
- Provide workarounds

### Risk 4: User Experience Degradation

**Impact:** High
**Likelihood:** Medium

**Mitigation:**

- HITL gates should be fast (<5s)
- Clear error messages
- Progressive disclosure (don't overwhelm)
- Sensible defaults (security without friction)

---

## Success Metrics

### Security

- ✅ Zero credentials in agent context
- ✅ All tool calls logged
- ✅ Network isolation enforced
- ✅ Destructive actions require confirmation
- ✅ No container escape vulnerabilities

### Performance

- ✅ <5ms gateway overhead
- ✅ <2s container startup
- ✅ <100ms end-to-end latency increase
- ✅ >1000 audit writes/second

### Usability

- ✅ Single command to enable security mode
- ✅ Clear error messages
- ✅ Works on macOS, Linux, Windows (WSL2)
- ✅ Comprehensive documentation
- ✅ Example configurations for common use cases

---

## Timeline

| Phase                     | Duration     | Start | End |
| ------------------------- | ------------ | ----- | --- |
| 4.1: Foundation           | 2 weeks      | TBD   | TBD |
| 4.2: Audit Logging        | 1 week       | TBD   | TBD |
| 4.3: Secret Management    | 1 week       | TBD   | TBD |
| 4.4: Network Isolation    | 1 week       | TBD   | TBD |
| 4.5: HITL Gates           | 1 week       | TBD   | TBD |
| 4.6: Browser Container    | 1 week       | TBD   | TBD |
| 4.7: Code Execution       | 1 week       | TBD   | TBD |
| 4.8: Integration & Polish | 2 weeks      | TBD   | TBD |
| **Total**                 | **10 weeks** | TBD   | TBD |

---

## Next Steps

1. **Review this plan** with stakeholders
2. **Set timeline** and assign resources
3. **Create tracking tasks** (GitHub issues or similar)
4. **Begin Phase 4.1** (Foundation)

---

## References

- [MCP Protocol Specification](https://spec.modelcontextprotocol.io/)
- [Docker Security Best Practices](https://docs.docker.com/engine/security/)
- [gVisor Security Model](https://gvisor.dev/docs/architecture_guide/security/)
- [HashiCorp Vault Documentation](https://www.vaultproject.io/docs)
- [OWASP AI Security Guidelines](https://owasp.org/www-project-ai-security-and-privacy-guide/)

---

**Document Version:** 1.0
**Last Updated:** 2026-02-09
**Author:** Harombe Team
