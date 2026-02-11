# Security Policy

## Reporting a Vulnerability

We take the security of harombe seriously. If you discover a security vulnerability, please help us by disclosing it responsibly.

**Please DO NOT report security vulnerabilities through public GitHub issues.**

Instead, please report security vulnerabilities by opening a **private security advisory** on GitHub:

1. Go to https://github.com/smallthinkingmachines/harombe/security/advisories
2. Click "New draft security advisory"
3. Provide a detailed description of the vulnerability including:
   - Type of vulnerability
   - Steps to reproduce
   - Potential impact
   - Any suggested fixes (optional)

We will respond to your report within 48 hours and work with you to understand and address the issue.

## Security Advisory Process

1. **Report received** - We acknowledge your report within 48 hours
2. **Investigation** - We investigate and validate the vulnerability
3. **Fix development** - We develop and test a fix (you may be invited to review)
4. **Release** - We release a patched version
5. **Disclosure** - We publicly disclose the vulnerability after users have had time to update

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

We recommend always using the latest version of harombe.

## Security Architecture

Harombe implements a comprehensive security layer (Phase 4) based on the **Capability-Container Pattern**. This architecture ensures AI agents cannot access unauthorized resources, leak credentials, or exfiltrate data.

### Current Status: Phase 4 Foundation Complete

**✅ Implemented (Phase 4.1-4.4):**

- **MCP Gateway** - Centralized gateway for all tool execution with request routing
- **Container Isolation** - Each tool runs in its own Docker container with resource limits
- **Audit Logging** - Comprehensive SQLite-based audit trail of all agent actions
- **Secret Management** - HashiCorp Vault, SOPS, and environment variable backends
- **Network Isolation** - Per-container egress filtering with iptables and DNS control

**✅ Implemented (Phase 4.5-4.8):**

- Human-in-the-loop (HITL) confirmation gates (Phase 4.5)
- Pre-authenticated browser container (Phase 4.6)
- Code execution sandbox with gVisor support (Phase 4.7)
- End-to-end integration testing (Phase 4.8)

### Key Security Principle

**Infrastructure-level enforcement:** Research (Feb 2026) revealed that MCP protocol alone cannot enforce security. All security must be implemented at the infrastructure layer through containers, network policies, and gateways.

### The Capability-Container Pattern

```
┌─────────────────────────────────────────────────┐
│  Agent Container (ReAct loop, LLM)              │
│  Can ONLY talk to MCP Gateway                   │
├─────────────────────────────────────────────────┤
│  MCP Gateway (auth, audit, secret-scanning)     │
├──────────┬──────────┬──────────┬────────────────┤
│ Browser  │ Files    │ Code     │ API MCP        │
│ Container│ Container│ Container│ Servers        │
│ (isolated│ (scoped  │ (sandboxed│ (containerized)│
│  network)│ volumes) │ gVisor)  │ w/ secrets)    │
└──────────┴──────────┴──────────┴────────────────┘
```

### Security Features

#### 1. Audit Logging

Every action is logged to a tamper-evident SQLite database:

- **What's logged:** All tool calls, security decisions, network connections
- **Sensitive data redaction:** API keys, passwords, tokens automatically removed
- **Compliance:** SOC 2 and GDPR query support
- **Retention policies:** Automatic cleanup based on configured retention

[→ Audit Logging Documentation](docs/audit-logging.md)

#### 2. Secret Management

Zero secrets in LLM context or configuration files:

- **Vault backends:** HashiCorp Vault (production), SOPS (teams), env vars (dev)
- **Secret scanning:** Detect and redact leaked credentials in real-time
- **Secure injection:** Secrets delivered to containers via environment variables
- **Automatic cleanup:** Secrets removed when containers stop

[→ Secret Management Documentation](docs/security-credentials.md)

#### 3. Network Isolation

Per-container network security with default-deny egress:

- **Docker network namespaces:** Complete container isolation
- **Egress filtering:** iptables rules with domain allowlists
- **DNS control:** Query filtering and validation
- **Monitoring:** All connection attempts logged and analyzed

[→ Network Isolation Documentation](docs/security-network.md)

#### 4. Container Isolation

Docker-based isolation with resource limits:

- **Separate namespaces:** Each tool in its own container
- **Resource limits:** CPU and memory caps per container
- **Non-root execution:** Containers run as unprivileged user (UID 1000)
- **Capability dropping:** Minimal Linux capabilities

[→ MCP Gateway Design](docs/mcp-gateway-design.md)

## Security Considerations

### Running Tools

harombe includes tools that can execute system commands and modify files. When using harombe:

- **Review tool calls** - The `confirm_dangerous` setting (enabled by default) requires approval before dangerous operations
- **Sandbox environments** - Consider running harombe in isolated environments (containers, VMs) when testing
- **Use security layer** - Enable Phase 4 security features for production use
- **API exposure** - If running the API server, ensure proper network isolation and authentication
- **Model trust** - Remember that the LLM's decisions are based on training data and prompts

### Configuration Security

- **Config files** - Keep `harombe.yaml` files secure, especially if they contain sensitive settings
- **Never store secrets in config** - Use vault backends (Vault, SOPS) instead of plaintext
- **Environment variables** - Only use for development; prefer Vault for production
- **File permissions** - Ensure proper file permissions on config files and data directories
  - Config files: `chmod 600 ~/.harombe/harombe.yaml`
  - Audit database: `chmod 600 ~/.harombe/audit.db`
  - Secret files: `chmod 400 /tmp/harombe-secrets/*.env`

## Security Best Practices

### General Security

1. **Keep dependencies updated** - Regularly update harombe and its dependencies
2. **Use confirmation mode** - Keep `tools.confirm_dangerous: true` in your config
3. **Review logs** - Monitor harombe logs for unexpected behavior
4. **Limit network access** - Run Ollama and harombe on localhost unless remote access is required
5. **Principle of least privilege** - Run harombe with minimal required permissions

### Phase 4 Security Layer

For production deployments, enable and configure the security layer:

1. **Enable container isolation** - Set `security.enabled: true` in config
2. **Configure egress filtering** - Define strict allowlists for each container
3. **Use Vault for secrets** - Never store credentials in config files
4. **Enable audit logging** - Track all agent actions for compliance
5. **Monitor security events** - Review blocked connections and failed operations
6. **Apply retention policies** - Configure appropriate audit log retention
7. **Test security policies** - Validate egress rules and secret management before production

### Quick Start Guide

To enable the security layer:

```bash
# 1. Install Docker
# Follow: https://docs.docker.com/get-docker/

# 2. Configure security in harombe.yaml
security:
  enabled: true
  isolation: docker

  credentials:
    provider: vault  # or sops, env

  audit:
    enabled: true
    db_path: ~/.harombe/audit.db

  containers:
    browser:
      egress_allow:
        - "*.example.com"

# 3. Start containers
cd docker
docker-compose up -d

# 4. Verify health
curl http://localhost:8100/health
```

See [docs/security-quickstart.md](docs/security-quickstart.md) for detailed setup instructions.

## Security Documentation

Comprehensive security documentation is available:

- **[Security Quick Start](docs/security-quickstart.md)** - Get the security layer running in 5 minutes
- **[Audit Logging](docs/audit-logging.md)** - Complete audit trail system with compliance support
- **[Secret Management](docs/security-credentials.md)** - Vault, SOPS, credential handling (100+ pages)
- **[Network Isolation](docs/security-network.md)** - Egress filtering and DNS control (80+ pages)
- **[MCP Gateway Design](docs/mcp-gateway-design.md)** - Gateway architecture and protocol
- **[Phase 4 Implementation Plan](docs/phase4-implementation-plan.md)** - Complete security roadmap

## Threat Model

### In Scope

Security measures protect against:

- **Credential leakage** - Secrets in LLM responses or logs
- **Data exfiltration** - Unauthorized network connections
- **Lateral movement** - Container escape or cross-container access
- **Supply chain attacks** - Malicious tool execution
- **Prompt injection** - Adversarial inputs attempting unauthorized actions

### Out of Scope

Current security layer does not protect against:

- **Model vulnerabilities** - LLM training data poisoning or backdoors
- **Physical access** - Host system compromise
- **Social engineering** - User being tricked into approving malicious operations
- **Zero-day exploits** - Unknown vulnerabilities in dependencies

For defense-in-depth, combine harombe security features with:

- System hardening (AppArmor, SELinux)
- Network firewalls
- Intrusion detection systems (IDS)
- Regular security audits

## Contact

For any security concerns that don't require a private advisory, you can reach the maintainers through:

- GitHub Discussions: https://github.com/smallthinkingmachines/harombe/discussions

Thank you for helping keep harombe and its users safe!
