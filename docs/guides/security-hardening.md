# Security Hardening Guide

Production deployment checklist for Harombe's security layer.

## Pre-Deployment Checklist

### 1. Enable Security Layer

```yaml
security:
  enabled: true
  isolation: docker
```

### 2. Configure Audit Logging

```yaml
security:
  audit:
    enabled: true
    database: /var/lib/harombe/audit.db # Use persistent storage
    retention_days: 365 # 1 year for compliance
    redact_sensitive: true
    log_level: INFO
```

**Verify:** `harombe audit stats` shows events being recorded.

### 3. Use Vault for Credentials (not env vars)

```yaml
security:
  credentials:
    method: vault
    vault_addr: http://vault.internal:8200
    auto_refresh: true
    rotation_days: 30
```

**Never** store API keys in `harombe.yaml` or environment variables in production.

### 4. Configure Network Egress

For each container, explicitly list allowed domains:

```yaml
security:
  containers:
    browser:
      egress_allow:
        - "*.github.com"
        - "docs.python.org"
      # Everything else is blocked
    filesystem:
      egress_allow: [] # No network access
    code_exec:
      egress_allow: [] # No network access
```

**Principle:** Default deny. Only allow what's needed.

### 5. Enable HITL Gates

```yaml
security:
  hitl:
    enabled: true
    timeout: 60 # Auto-deny after 60s
    notification_method: cli # or webhook for remote approval
```

### 6. Set Container Resource Limits

```yaml
security:
  containers:
    browser:
      resources:
        cpu_limit: "2"
        memory_limit: "2g"
        pids_limit: 100
    code_exec:
      resources:
        cpu_limit: "1"
        memory_limit: "512m"
        pids_limit: 50
```

### 7. Restrict Filesystem Mounts

Only mount what's needed, read-only when possible:

```yaml
security:
  containers:
    filesystem:
      mounts:
        - "/home/user/workspace:/workspace:ro" # Read-only
```

### 8. Review Tools Configuration

Disable tools you don't need:

```yaml
tools:
  shell: false # Disable unless required
  filesystem: true
  web_search: true
  confirm_dangerous: true # Always keep this enabled
```

## Network Security

### Firewall Rules

- Only expose harombe's API port (8000) to trusted networks
- Block direct access to the MCP Gateway port (8100) from outside
- Use SSH tunnels for remote cluster nodes

### TLS

Harombe doesn't provide TLS by default. Use a reverse proxy:

```nginx
server {
    listen 443 ssl;
    server_name harombe.internal;
    ssl_certificate /etc/ssl/harombe.crt;
    ssl_certificate_key /etc/ssl/harombe.key;

    location / {
        proxy_pass http://127.0.0.1:8000;
    }
}
```

## Monitoring

### Audit Log Queries

```bash
# Recent security decisions
harombe audit security --limit 50

# Tool calls in the last hour
harombe audit tools --hours 1

# Export for SIEM
harombe audit export audit-$(date +%Y%m%d).json --format json
```

### Health Checks

```bash
# Gateway health
curl http://localhost:8100/health

# Container readiness
curl http://localhost:8100/ready
```

## Incident Response

### If Credentials Are Leaked

1. Rotate affected credentials immediately: `harombe audit tools --tool vault_*`
2. Check audit logs for unauthorized access: `harombe audit security`
3. Review container egress logs for exfiltration attempts
4. Revoke and regenerate Vault tokens

### If a Container Is Compromised

1. Stop the affected container: `docker stop <container>`
2. Review audit logs for the container's session
3. Check network egress logs for suspicious connections
4. Rebuild from a clean image

## What NOT to Do

- Don't run harombe as root
- Don't expose port 8000 or 8100 to the internet without authentication
- Don't store secrets in `harombe.yaml` or environment variables
- Don't disable `confirm_dangerous` in production
- Don't use `egress_allow: ["*"]` — be explicit about allowed domains
- Don't skip audit log review — set up automated alerts for HIGH/CRITICAL events
