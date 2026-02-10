# Harombe Production Deployment Guide

**Version**: 1.0
**Date**: 2026-02-09
**Phase**: 4.8 - Security Layer Complete

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Infrastructure Setup](#infrastructure-setup)
4. [Security Configuration](#security-configuration)
5. [Deployment Steps](#deployment-steps)
6. [Post-Deployment Validation](#post-deployment-validation)
7. [Monitoring and Alerting](#monitoring-and-alerting)
8. [Rollback Procedures](#rollback-procedures)
9. [Performance Tuning](#performance-tuning)
10. [Troubleshooting](#troubleshooting)

## Overview

This guide covers deploying Harombe with the complete Phase 4 security layer, including:

- **Code Execution Sandboxing** (gVisor-based isolation)
- **Credential Management** (HashiCorp Vault integration)
- **Network Security** (egress filtering, allowlists)
- **Audit Logging** (immutable security event trails)
- **Human-in-the-Loop (HITL) Gates** (risk-based approvals)
- **Secret Scanning** (credential leak prevention)

### Architecture Summary

```
┌─────────────────────────────────────────────────────────┐
│                    API Gateway                          │
│              (FastAPI + Security Middleware)            │
└────────────────────┬────────────────────────────────────┘
                     │
         ┌───────────┴───────────┐
         │                       │
    ┌────▼─────┐          ┌─────▼──────┐
    │  Agent   │          │   HITL     │
    │  Runtime │          │  Gateway   │
    └────┬─────┘          └─────┬──────┘
         │                      │
         │                ┌─────▼──────┐
         │                │   Vault    │
         │                │ (Secrets)  │
         │                └────────────┘
         │
    ┌────▼─────────────────────────┐
    │   Sandbox Manager            │
    │   (Docker + gVisor)          │
    └──────────────────────────────┘
         │
    ┌────▼─────────────────────────┐
    │   Audit Logger               │
    │   (SQLite + WAL)             │
    └──────────────────────────────┘
```

## Prerequisites

### System Requirements

**Minimum Production Specs**:

- CPU: 4 cores (8+ recommended)
- RAM: 8GB (16GB+ recommended)
- Disk: 50GB SSD (100GB+ recommended)
- OS: Linux (Ubuntu 22.04+ or RHEL 8+)

**Software Dependencies**:

- Python 3.11, 3.12, or 3.13 (3.14+ not compatible with ChromaDB)
- Docker Engine 24.0+ or containerd 1.7+
- gVisor runtime (`runsc`)
- HashiCorp Vault 1.15+
- PostgreSQL 14+ (optional, for persistent storage)

### Network Requirements

**Inbound**:

- Port 8000: API Gateway (HTTPS recommended)
- Port 8200: Vault API (internal only)

**Outbound**:

- Port 443: HTTPS for external APIs (Anthropic, GitHub, etc.)
- Port 6333: ChromaDB (if external)
- DNS resolution for allowlisted domains

### Access Requirements

- Docker daemon access (for sandbox creation)
- Vault admin token (for initial setup)
- Anthropic API key (for Claude integration)
- GitHub OAuth app credentials (if using GitHub integration)

## Infrastructure Setup

### 1. Install Docker and gVisor

```bash
# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER

# Install gVisor
(
  set -e
  ARCH=$(uname -m)
  URL=https://storage.googleapis.com/gvisor/releases/release/latest/${ARCH}
  wget ${URL}/runsc ${URL}/runsc.sha512 \
    ${URL}/containerd-shim-runsc-v1 ${URL}/containerd-shim-runsc-v1.sha512
  sha512sum -c runsc.sha512 \
    -c containerd-shim-runsc-v1.sha512
  rm -f *.sha512
  chmod a+rx runsc containerd-shim-runsc-v1
  sudo mv runsc containerd-shim-runsc-v1 /usr/local/bin
)

# Configure Docker to use gVisor
sudo tee /etc/docker/daemon.json > /dev/null <<EOF
{
  "runtimes": {
    "runsc": {
      "path": "/usr/local/bin/runsc",
      "runtimeArgs": [
        "--platform=systrap"
      ]
    }
  }
}
EOF

sudo systemctl restart docker

# Verify gVisor installation
docker run --rm --runtime=runsc hello-world
```

### 2. Install and Configure HashiCorp Vault

```bash
# Install Vault
wget -O- https://apt.releases.hashicorp.com/gpg | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list
sudo apt update && sudo apt install vault

# Create Vault configuration
sudo mkdir -p /etc/vault.d
sudo tee /etc/vault.d/vault.hcl > /dev/null <<EOF
storage "file" {
  path = "/opt/vault/data"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = 1  # Use TLS in production!
}

api_addr = "http://127.0.0.1:8200"
cluster_addr = "https://127.0.0.1:8201"
ui = true
disable_mlock = false
EOF

# Start Vault
sudo mkdir -p /opt/vault/data
sudo chown -R vault:vault /opt/vault/data
sudo systemctl enable vault
sudo systemctl start vault

# Initialize Vault (SAVE THESE KEYS SECURELY!)
export VAULT_ADDR='http://127.0.0.1:8200'
vault operator init -key-shares=5 -key-threshold=3

# Unseal Vault (requires 3 of 5 keys)
vault operator unseal <key1>
vault operator unseal <key2>
vault operator unseal <key3>

# Login with root token
vault login <root_token>

# Enable KV secrets engine
vault secrets enable -version=2 kv
```

### 3. Setup Application Environment

```bash
# Clone repository
git clone https://github.com/smallthinkingmachines/harombe.git
cd harombe

# Create Python virtual environment
python3.12 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -e .
pip install -r requirements-dev.txt

# Create data directories
sudo mkdir -p /var/lib/harombe/{audit,sandboxes,memory}
sudo chown -R $USER:$USER /var/lib/harombe
```

## Security Configuration

### 1. Vault Secrets Setup

```bash
export VAULT_ADDR='http://127.0.0.1:8200'
export VAULT_TOKEN='<your_root_token>'

# Create secrets for Harombe
vault kv put kv/harombe/api \
  anthropic_api_key="<your_anthropic_key>" \
  github_token="<your_github_token>" \
  openai_api_key="<your_openai_key>"

# Create AppRole for Harombe
vault auth enable approle

vault write auth/approle/role/harombe \
  token_policies="harombe-policy" \
  token_ttl=1h \
  token_max_ttl=24h

# Create policy for Harombe
vault policy write harombe-policy - <<EOF
path "kv/data/harombe/*" {
  capabilities = ["read"]
}
path "kv/metadata/harombe/*" {
  capabilities = ["list"]
}
EOF

# Get RoleID and SecretID
vault read auth/approle/role/harombe/role-id
vault write -f auth/approle/role/harombe/secret-id
```

### 2. Environment Configuration

Create `.env.production`:

```bash
# Application
ENVIRONMENT=production
LOG_LEVEL=INFO
DEBUG=false

# Vault
VAULT_ADDR=http://127.0.0.1:8200
VAULT_ROLE_ID=<role_id_from_above>
VAULT_SECRET_ID=<secret_id_from_above>
VAULT_MOUNT_POINT=kv

# Audit Logging
AUDIT_DB_PATH=/var/lib/harombe/audit/harombe.db
AUDIT_RETENTION_DAYS=90

# Sandbox
SANDBOX_RUNTIME=runsc
SANDBOX_MEMORY_LIMIT=2g
SANDBOX_CPU_LIMIT=2.0
SANDBOX_TIMEOUT=300
SANDBOX_ROOT=/var/lib/harombe/sandboxes

# Network Security
EGRESS_MODE=allowlist
ALLOWED_DOMAINS=api.anthropic.com,api.openai.com,api.github.com
BLOCK_PRIVATE_IPS=true

# HITL
HITL_HIGH_RISK_TOOLS=execute_code,file_write,git_push
HITL_APPROVAL_TIMEOUT=300

# Memory/RAG
CHROMA_PERSIST_DIR=/var/lib/harombe/memory
EMBEDDING_MODEL=text-embedding-3-small
```

### 3. Docker Security Configuration

Create `docker-compose.yml`:

```yaml
version: "3.8"

services:
  harombe:
    build: .
    ports:
      - "8000:8000"
    volumes:
      - /var/lib/harombe:/var/lib/harombe
      - /var/run/docker.sock:/var/run/docker.sock
    environment:
      - ENVIRONMENT=production
    env_file:
      - .env.production
    security_opt:
      - no-new-privileges:true
      - seccomp:unconfined # Required for gVisor
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE
    restart: unless-stopped
    networks:
      - harombe-net

  vault:
    image: hashicorp/vault:1.15
    ports:
      - "8200:8200"
    volumes:
      - /opt/vault/data:/vault/data
      - /etc/vault.d:/vault/config
    cap_add:
      - IPC_LOCK
    restart: unless-stopped
    networks:
      - harombe-net

networks:
  harombe-net:
    driver: bridge
```

### 4. Security Checklist

Before deployment, verify:

- [ ] All secrets stored in Vault (no hardcoded credentials)
- [ ] gVisor runtime configured and tested
- [ ] Network egress allowlist configured
- [ ] Audit logging enabled with WAL mode
- [ ] Docker daemon socket mounted read-only (if possible)
- [ ] Container runs as non-root user
- [ ] Resource limits configured (CPU, memory, disk)
- [ ] TLS certificates configured for production
- [ ] Secret scanning enabled in CI/CD
- [ ] Vault auto-unseal configured (production)
- [ ] Backup procedures documented
- [ ] Incident response plan prepared

## Deployment Steps

### 1. Pre-Deployment Validation

```bash
# Run security validation tests
pytest tests/security/test_hardening_validation.py -v

# Run performance benchmarks
pytest tests/performance/test_performance_benchmarks.py -v -m benchmark

# Run integration tests
pytest tests/integration/test_phase4_integration.py -v

# Verify Docker + gVisor
docker run --rm --runtime=runsc python:3.12-slim python --version

# Verify Vault connectivity
export VAULT_ADDR='http://127.0.0.1:8200'
vault status
```

### 2. Initial Deployment

```bash
# Copy production configuration
cp .env.production .env

# Build Docker image
docker build -t harombe:latest .

# Start services
docker-compose up -d

# Wait for startup
sleep 10

# Check service health
curl http://localhost:8000/health
curl http://localhost:8200/v1/sys/health

# Initialize database
docker-compose exec harombe python -m harombe.cli db init

# Verify audit logging
docker-compose exec harombe python -m harombe.cli audit test
```

### 3. Load Testing (Optional)

```bash
# Install load testing tool
pip install locust

# Run load test
locust -f tests/load/locustfile.py --host=http://localhost:8000 --users=10 --spawn-rate=2
```

## Post-Deployment Validation

### Health Checks

```bash
# API health
curl http://localhost:8000/health
# Expected: {"status": "healthy", "timestamp": "..."}

# Vault health
curl http://localhost:8200/v1/sys/health
# Expected: {"initialized": true, "sealed": false}

# Sandbox creation test
curl -X POST http://localhost:8000/api/v1/sandbox/test \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"runtime": "runsc"}'
# Expected: {"sandbox_id": "...", "status": "running"}

# Audit log verification
sqlite3 /var/lib/harombe/audit/harombe.db "SELECT COUNT(*) FROM audit_events;"
# Expected: Non-zero count
```

### Security Validation

```bash
# Verify no credentials in logs
docker-compose logs | grep -iE "(password|token|key|secret)" || echo "No secrets found"

# Check gVisor isolation
docker inspect $(docker ps -q --filter ancestor=harombe:latest) | jq '.[0].HostConfig.Runtime'
# Expected: "runsc"

# Verify network restrictions
docker-compose exec harombe curl -I https://evil.com
# Expected: Timeout or connection refused

# Check audit trail integrity
docker-compose exec harombe python -m harombe.cli audit verify
# Expected: "Audit trail verified - no tampering detected"
```

### Performance Validation

```bash
# Check response times
curl -w "\nTime: %{time_total}s\n" http://localhost:8000/api/v1/health

# Monitor resource usage
docker stats harombe --no-stream

# Check audit log write latency
docker-compose exec harombe python -m harombe.cli audit benchmark
# Expected: <10ms average
```

## Monitoring and Alerting

### Metrics to Monitor

**Application Metrics**:

- Request latency (P50, P95, P99)
- Error rate (4xx, 5xx responses)
- Active sandbox count
- Audit log write latency
- HITL approval queue depth

**Infrastructure Metrics**:

- CPU usage (container and host)
- Memory usage (container and host)
- Disk usage (/var/lib/harombe)
- Docker daemon health
- Vault seal status

**Security Metrics**:

- Failed authentication attempts
- Secret scanner detections
- Network egress blocks
- Sandbox escape attempts
- Audit log tampering attempts

### Prometheus Configuration

```yaml
# prometheus.yml
scrape_configs:
  - job_name: "harombe"
    static_configs:
      - targets: ["localhost:8000"]
    metrics_path: "/metrics"

  - job_name: "vault"
    static_configs:
      - targets: ["localhost:8200"]
    metrics_path: "/v1/sys/metrics"
    params:
      format: ["prometheus"]
```

### Alert Rules

```yaml
# alerts.yml
groups:
  - name: harombe
    rules:
      - alert: HighErrorRate
        expr: rate(http_requests_total{status=~"5.."}[5m]) > 0.05
        for: 5m
        annotations:
          summary: "High error rate detected"

      - alert: SlowAuditWrites
        expr: histogram_quantile(0.95, rate(audit_write_duration_seconds_bucket[5m])) > 0.010
        for: 5m
        annotations:
          summary: "Audit log writes exceeding 10ms P95"

      - alert: VaultSealed
        expr: vault_core_unsealed == 0
        for: 1m
        annotations:
          summary: "Vault is sealed - manual intervention required"

      - alert: SandboxLeaks
        expr: rate(sandbox_creation_total[5m]) - rate(sandbox_cleanup_total[5m]) > 5
        for: 10m
        annotations:
          summary: "Sandbox cleanup not keeping pace with creation"
```

## Rollback Procedures

### Emergency Rollback

If critical issues arise:

```bash
# 1. Stop current deployment
docker-compose down

# 2. Restore previous version
docker tag harombe:previous harombe:latest

# 3. Restart with previous version
docker-compose up -d

# 4. Verify health
curl http://localhost:8000/health

# 5. Check audit logs for issues
docker-compose exec harombe python -m harombe.cli audit tail --lines=100
```

### Database Rollback

```bash
# Backup current audit database
cp /var/lib/harombe/audit/harombe.db \
   /var/lib/harombe/audit/harombe.db.backup.$(date +%Y%m%d_%H%M%S)

# Restore from backup
cp /var/lib/harombe/audit/backups/harombe.db.20260209_120000 \
   /var/lib/harombe/audit/harombe.db

# Restart services
docker-compose restart harombe
```

### Configuration Rollback

```bash
# Restore previous environment
cp .env.production.backup .env.production

# Reload configuration
docker-compose up -d --force-recreate
```

## Performance Tuning

### Application Tuning

**Worker Processes**:

```bash
# For CPU-bound workloads
WORKERS=$(($(nproc) * 2 + 1))
gunicorn harombe.api:app --workers=$WORKERS --worker-class=uvicorn.workers.UvicornWorker
```

**Connection Pooling**:

```python
# config/production.py
DB_POOL_SIZE = 20
DB_MAX_OVERFLOW = 10
HTTPX_POOL_LIMITS = httpx.Limits(max_connections=100, max_keepalive_connections=20)
```

**Memory Optimization**:

```bash
# Reduce memory footprint
CHROMA_ANONYMIZED_TELEMETRY=False
PYTHONHASHSEED=0
MALLOC_TRIM_THRESHOLD_=100000
```

### Docker Tuning

```yaml
# docker-compose.yml
services:
  harombe:
    deploy:
      resources:
        limits:
          cpus: "4.0"
          memory: 8G
        reservations:
          cpus: "2.0"
          memory: 4G
    ulimits:
      nofile:
        soft: 65536
        hard: 65536
```

### Vault Tuning

```hcl
# /etc/vault.d/vault.hcl
storage "file" {
  path = "/opt/vault/data"
  max_parallel = 128
}

listener "tcp" {
  address = "0.0.0.0:8200"
  tls_disable = 0
  tls_cert_file = "/etc/vault.d/tls/vault.crt"
  tls_key_file = "/etc/vault.d/tls/vault.key"
}
```

### Database Tuning

```bash
# SQLite audit database optimizations
sqlite3 /var/lib/harombe/audit/harombe.db <<EOF
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA cache_size = -64000;  # 64MB cache
PRAGMA temp_store = MEMORY;
PRAGMA mmap_size = 268435456;  # 256MB mmap
EOF
```

## Troubleshooting

### Common Issues

**1. Sandbox Creation Fails**

```bash
# Check Docker daemon
sudo systemctl status docker

# Verify gVisor runtime
docker run --rm --runtime=runsc hello-world

# Check logs
docker-compose logs harombe | grep -i sandbox

# Solution: Ensure Docker daemon has gVisor configured
```

**2. Vault Connection Timeout**

```bash
# Check Vault status
vault status

# Verify network connectivity
curl http://localhost:8200/v1/sys/health

# Check Vault logs
journalctl -u vault -f

# Solution: Unseal Vault if sealed
vault operator unseal
```

**3. High Audit Log Latency**

```bash
# Check database file size
ls -lh /var/lib/harombe/audit/harombe.db

# Check WAL mode
sqlite3 /var/lib/harombe/audit/harombe.db "PRAGMA journal_mode;"

# Vacuum database
sqlite3 /var/lib/harombe/audit/harombe.db "VACUUM;"

# Solution: Implement log rotation
```

**4. Memory Leak in Sandboxes**

```bash
# List all containers
docker ps -a

# Check for orphaned containers
docker ps -aq --filter "status=exited"

# Clean up orphaned containers
docker container prune -f

# Solution: Verify cleanup logic in SandboxManager
```

**5. Secret Scanner False Positives**

```bash
# Check scanner configuration
docker-compose exec harombe python -c "from harombe.security.secrets import SecretScanner; print(SecretScanner().patterns)"

# Adjust confidence threshold
# In .env.production:
SECRET_SCANNER_MIN_CONFIDENCE=0.85

# Solution: Tune regex patterns or confidence
```

### Debug Mode

```bash
# Enable debug logging
docker-compose exec harombe python -c "
import logging
logging.basicConfig(level=logging.DEBUG)
from harombe.security.audit import AuditLogger
logger = AuditLogger()
# Test operations...
"

# Or modify .env.production:
LOG_LEVEL=DEBUG
docker-compose restart harombe
```

### Log Analysis

```bash
# Tail application logs
docker-compose logs -f harombe

# Search for errors
docker-compose logs harombe | grep -i error

# Analyze audit trail
sqlite3 /var/lib/harombe/audit/harombe.db \
  "SELECT event_type, COUNT(*) FROM audit_events GROUP BY event_type;"

# Check network blocks
sqlite3 /var/lib/harombe/audit/harombe.db \
  "SELECT * FROM audit_events WHERE event_type='network_block' ORDER BY timestamp DESC LIMIT 10;"
```

## Compliance

### PCI DSS

- ✅ Requirement 8: Credentials stored in Vault, rotated regularly
- ✅ Requirement 10: Comprehensive audit logging with immutability
- ✅ Requirement 6: Secure code execution in isolated sandboxes
- ✅ Requirement 3: No plaintext secrets in logs or storage

### GDPR

- ✅ Article 32: Technical measures (encryption, access control, audit)
- ✅ Article 5: Purpose limitation (minimal data collection)
- ✅ Article 30: Records of processing (audit trail)

### SOC 2

- ✅ CC6.1: Logical access controls (Vault, HITL)
- ✅ CC6.6: Change management (audit logging)
- ✅ CC7.2: System monitoring (metrics, alerts)

## Support

### Documentation

- [Architecture Overview](./architecture/overview.md)
- [Security Architecture](./security-architecture.md)
- [API Reference](./api/index.md)
- [Phase 4.8 Integration Plan](./phases/phase4-8-integration-plan.md)

### Troubleshooting Resources

- GitHub Issues: https://github.com/smallthinkingmachines/harombe/issues
- Security Incidents: security@harombe.ai
- Production Support: support@harombe.ai

### Emergency Contacts

- **Critical Security Issues**: security-emergency@harombe.ai
- **Production Outage**: oncall@harombe.ai
- **Vault Admin**: vault-admin@harombe.ai

## Maintenance

### Regular Tasks

**Daily**:

- Monitor error rates and latencies
- Check Vault seal status
- Review security alerts

**Weekly**:

- Analyze audit logs for anomalies
- Review HITL approval patterns
- Check disk usage trends

**Monthly**:

- Rotate Vault tokens
- Update dependencies (security patches)
- Review and update network allowlists
- Vacuum audit database

**Quarterly**:

- Performance benchmark review
- Security posture assessment
- Disaster recovery drill
- Dependency vulnerability scan

### Backup Procedures

```bash
#!/bin/bash
# backup.sh - Daily backup script

DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/var/backups/harombe/$DATE"

mkdir -p "$BACKUP_DIR"

# Backup audit database
cp /var/lib/harombe/audit/harombe.db "$BACKUP_DIR/"

# Backup configuration
cp .env.production "$BACKUP_DIR/"
cp docker-compose.yml "$BACKUP_DIR/"

# Backup Vault (snapshot)
vault operator raft snapshot save "$BACKUP_DIR/vault.snap"

# Compress
tar -czf "/var/backups/harombe/harombe-backup-$DATE.tar.gz" "$BACKUP_DIR"

# Clean up old backups (keep 30 days)
find /var/backups/harombe -name "*.tar.gz" -mtime +30 -delete

echo "Backup completed: harombe-backup-$DATE.tar.gz"
```

## Conclusion

This deployment guide covers production deployment of Harombe with the complete Phase 4.8 security layer. Follow the security checklist carefully, and monitor all metrics post-deployment.

**Key Success Metrics**:

- Zero security incidents
- <50ms P95 API latency
- <10ms P95 audit write latency
- 99.9% uptime
- Complete audit trail coverage

For questions or issues, consult the troubleshooting section or contact support.

---

**Document Version**: 1.0
**Last Updated**: 2026-02-09
**Next Review**: 2026-03-09
