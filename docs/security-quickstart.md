# Harombe Security Layer - Quick Start Guide

Get the Phase 4.1 security layer running in under 5 minutes.

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

**Note:** This will fail until MCP server implementations are complete (Phase 4.6-4.7), but you'll see the gateway correctly route the request.

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
4. **Wait for MCP Servers:** Browser/Filesystem/Code execution servers coming in Phase 4.6-4.7

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

### Current Security Features

✅ Container isolation with Docker
✅ Non-root execution (UID 1000)
✅ Capability dropping
✅ Network isolation (filesystem/code-exec)
✅ Resource limits per container

### Not Yet Implemented

⏳ Audit logging (Phase 4.2)
⏳ Secret scanning (Phase 4.3)
⏳ Network egress filtering (Phase 4.4)
⏳ HITL confirmation gates (Phase 4.5)

**Do NOT use in production until all security phases are complete.**

## Getting Help

- **Documentation:** [docs/](./index.md)
- **Issues:** https://github.com/smallthinkingmachines/harombe/issues
- **Docker Help:** `cd docker && make help`

## What's Next?

This is the **foundation** for the security layer. Complete MCP server implementations and additional security features are coming in:

- **Phase 4.2:** Audit logging
- **Phase 4.3:** Secret management
- **Phase 4.4:** Network isolation
- **Phase 4.5:** HITL gates
- **Phase 4.6:** Browser container
- **Phase 4.7:** Code execution container
- **Phase 4.8:** Full integration and testing

Track progress in [phase4-implementation-plan.md](./phases/phase4-implementation-plan.md).
