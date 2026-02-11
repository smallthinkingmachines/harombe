# Harombe Security Layer - Quick Start Guide

Get the Harombe security layer running in under 5 minutes.

## Prerequisites

- Docker and Docker Compose installed
- Python 3.11+ installed
- At least 6GB RAM available for containers

## Step 1: Install Harombe

```bash
# Clone repository
git clone https://github.com/smallthinkingmachines/harombe.git
cd harombe

# Install with Docker support
pip install -e ".[docker]"
```

## Step 2: Configure Security Layer

Create or edit `harombe.yaml`:

```yaml
security:
  enabled: true
  isolation: docker

  gateway:
    host: 127.0.0.1
    port: 8100

  containers:
    browser:
      image: harombe/browser:latest
      enabled: true

    filesystem:
      image: harombe/filesystem:latest
      enabled: true

    code_exec:
      image: harombe/code-exec:latest
      enabled: true

    web_search:
      image: harombe/web-search:latest
      enabled: true
```

## Step 3: Start Containers

```bash
cd docker

# Build containers
docker-compose build

# Start all services
docker-compose up -d

# Check status
docker-compose ps
```

All containers should show `healthy` status after 10-15 seconds.

## Step 4: Verify Installation

### Check Gateway Health

```bash
curl http://localhost:8100/health
```

Expected response:

```json
{
  "status": "healthy",
  "version": "0.1.0",
  "uptime": 42,
  "containers": {
    "browser-container:3000": "healthy",
    "filesystem-container:3001": "healthy",
    "code-exec-container:3002": "healthy",
    "web-search-container:3003": "healthy"
  }
}
```

### Check Readiness

```bash
curl http://localhost:8100/ready
```

Expected response:

```json
{
  "ready": true,
  "containers_healthy": 4,
  "containers_total": 4
}
```

### View Logs

```bash
# All containers
docker-compose logs -f

# Specific container
docker-compose logs -f gateway
```

## Step 5: Test MCP Request

Send a test JSON-RPC request:

```bash
curl -X POST http://localhost:8100/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": "test-1",
    "method": "tools/call",
    "params": {
      "name": "web_search",
      "arguments": {"query": "test"}
    }
  }'
```

**Note:** This requires MCP server containers to be running. The gateway will route the request to the appropriate container.

## Common Commands

### Docker Management

```bash
cd docker

# Start all containers
make up

# Stop all containers
make down

# View logs
make logs

# Restart all containers
make restart

# Rebuild and restart
make rebuild

# Check health
make health
```

### Individual Container Commands

```bash
# Open shell in gateway
make shell-gateway

# View browser logs
make logs-browser

# Rebuild filesystem container
make rebuild-filesystem
```

## Troubleshooting

### Containers Won't Start

**Check logs:**

```bash
docker-compose logs <container-name>
```

**Common issues:**

- Port 8100 already in use
- Insufficient memory (need 6GB+)
- Docker daemon not running

### Health Checks Failing

**Test health endpoint directly:**

```bash
docker exec harombe-gateway curl http://localhost:8100/health
```

**Increase health check timeout:**
Edit `docker-compose.yml` and adjust `healthcheck.timeout`.

### Gateway Not Responding

**Verify gateway is running:**

```bash
docker-compose ps gateway
```

**Check gateway logs:**

```bash
docker-compose logs gateway
```

**Test from inside container:**

```bash
docker exec harombe-gateway curl http://localhost:8100/health
```

## Next Steps

1. **Read the Architecture:** [Phase 4.1 Foundation](./security-phase4.1-foundation.md)
2. **Understand MCP Protocol:** [MCP Gateway Design](./mcp-gateway-design.md)
3. **Configure Security:** [Phase 4 Implementation Plan](./phases/phase4-implementation-plan.md)
4. **Review Security Features:** All six defense-in-depth layers are implemented (Phases 4.1-4.8)

## Stopping the Stack

```bash
cd docker

# Stop containers
docker-compose down

# Stop and remove volumes
docker-compose down -v

# Complete cleanup (removes images)
docker-compose down -v --rmi all
```

## Resource Usage

Typical resource consumption:

| Container  | CPU (idle) | Memory (idle) | Memory (peak) |
| ---------- | ---------- | ------------- | ------------- |
| Gateway    | <1%        | ~100 MB       | ~200 MB       |
| Browser    | <5%        | ~200 MB       | ~1.5 GB       |
| Filesystem | <1%        | ~50 MB        | ~300 MB       |
| Code Exec  | <1%        | ~80 MB        | ~800 MB       |
| Web Search | <1%        | ~40 MB        | ~150 MB       |
| **Total**  | ~10%       | ~470 MB       | ~3 GB         |

## Security Notes

### Production-Ready Features

✅ Container isolation with Docker
✅ Non-root execution (UID 1000)
✅ Capability dropping
✅ Network isolation (filesystem/code-exec)
✅ Resource limits per container
✅ Audit logging with SQLite (Phase 4.2)
✅ Secret management — Vault, SOPS, env vars (Phase 4.3)
✅ Network egress filtering — iptables, domain allowlists (Phase 4.4)
✅ HITL confirmation gates — risk-based approvals (Phase 4.5)
✅ Browser container with pre-authentication (Phase 4.6)

### Experimental Features

> These features are implemented but have **not been validated in production** or undergone independent security audit.

⚗️ Zero-knowledge proof support — Protocol models only, not integrated end-to-end
⚗️ Hardware security modules (TPM/SGX/SEV-SNP) — Software simulation; requires specific hardware
⚗️ Compliance reporting (SOC 2, GDPR) — Heuristic templates, not audit-grade
⚗️ Confidential compute — Design only, requires AMD SEV-SNP or Intel TDX hardware

### Implemented (Phases 4.7-4.8)

✅ Code execution sandbox with gVisor support (Phase 4.7)
✅ End-to-end security integration testing (Phase 4.8)

## Getting Help

- **Documentation:** [docs/](./index.md)
- **Issues:** https://github.com/smallthinkingmachines/harombe/issues
- **Docker Help:** `cd docker && make help`

## Current Status

All Phase 4 security layers are **implemented**:

- **Phase 4.1:** Foundation (container isolation, gateway)
- **Phase 4.2:** Audit logging
- **Phase 4.3:** Secret management
- **Phase 4.4:** Network isolation
- **Phase 4.5:** HITL gates
- **Phase 4.6:** Browser container
- **Phase 4.7:** Code execution sandbox with gVisor
- **Phase 4.8:** End-to-end integration testing

See the [Phase 4 Implementation Plan](./phases/phase4-implementation-plan.md) for details.
