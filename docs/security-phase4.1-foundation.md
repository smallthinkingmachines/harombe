# Phase 4.1: Security Layer Foundation

**Status:** ✅ Complete
**Version:** 1.0
**Date:** 2026-02-08

## Overview

Phase 4.1 establishes the foundational security infrastructure for Harombe using the **Capability-Container Pattern**. This phase implements the MCP Gateway, Docker container management, and basic isolation without the full security features (audit logging, secret management, HITL gates) which come in later phases.

## Architecture

### High-Level Architecture

```
┌─────────────────────────────────────┐
│  Agent Container                     │
│  - ReAct loop                        │
│  - LLM inference                     │
│  - Tool decision making              │
└──────────────┬──────────────────────┘
               │ HTTP/JSON-RPC 2.0
               │ Port: 8100
               ▼
┌─────────────────────────────────────┐
│  MCP Gateway                         │
│  ┌─────────────────────────────┐   │
│  │ Request Handler              │   │
│  │ - Parse JSON-RPC 2.0         │   │
│  │ - Validate request           │   │
│  └──────────┬──────────────────┘   │
│             ▼                        │
│  ┌─────────────────────────────┐   │
│  │ Router                       │   │
│  │ - Map tool → container       │   │
│  │ - Health checking            │   │
│  └──────────┬──────────────────┘   │
│             ▼                        │
│  ┌─────────────────────────────┐   │
│  │ MCP Client Pool              │   │
│  │ - HTTP connections           │   │
│  │ - Connection pooling         │   │
│  │ - Retry logic                │   │
│  └──────────┬──────────────────┘   │
└─────────────┼──────────────────────┘
              │
    ┌─────────┼─────────┬─────────┐
    │         │         │         │
    ▼         ▼         ▼         ▼
┌────────┐ ┌───────┐ ┌──────┐ ┌──────┐
│Browser │ │Files  │ │Code  │ │Search│
│MCP     │ │MCP    │ │MCP   │ │MCP   │
│Server  │ │Server │ │Server│ │Server│
└────────┘ └───────┘ └──────┘ └──────┘
```

### Component Breakdown

#### 1. MCP Gateway (`src/harombe/security/gateway.py`)

**Purpose:** Central security enforcement point for all tool execution.

**Key Features:**

- JSON-RPC 2.0 request/response handling
- Tool → Container routing via `TOOL_ROUTES` table
- HTTP connection pooling with `httpx.AsyncClient`
- Retry logic with exponential backoff (3 attempts, 2^n seconds)
- Health monitoring for all containers
- FastAPI-based server on port 8100

**Endpoints:**

- `POST /mcp` - Main JSON-RPC endpoint for tool calls
- `GET /health` - Gateway health status with container statuses
- `GET /ready` - Readiness check (all containers healthy)

**Tool Routes:**

```python
TOOL_ROUTES = {
    "browser_navigate": "browser-container:3000",
    "browser_click": "browser-container:3000",
    "filesystem_read": "filesystem-container:3001",
    "filesystem_write": "filesystem-container:3001",
    "code_execute": "code-exec-container:3002",
    "web_search": "web-search-container:3003",
}
```

#### 2. MCP Protocol (`src/harombe/mcp/protocol.py`)

**Purpose:** JSON-RPC 2.0 data models for MCP communication.

**Key Models:**

- `MCPRequest` - JSON-RPC request with `id`, `method`, `params`
- `MCPResponse` - JSON-RPC response with `result` or `error`
- `MCPError` - Structured error with code and details
- `ContentItem` - Response content (text, image, resource)
- `ErrorCode` - Standard + Harombe-specific error codes

**Error Codes:**

- `-32700` to `-32603`: Standard JSON-RPC errors
- `-32000` to `-32006`: Harombe-specific (auth, container, secrets, rate limits)

#### 3. Docker Manager (`src/harombe/security/docker_manager.py`)

**Purpose:** Container lifecycle management for capability isolation.

**Key Features:**

- Container creation, start, stop, restart, removal
- Resource limits (CPU, memory, PIDs)
- Network creation and management
- Health monitoring
- Logs and stats retrieval
- Automatic cleanup

**Resource Limits:**

```python
ResourceLimits.from_mb(memory_mb=512, cpu_cores=0.5)
# → 512MB memory, 0.5 CPU cores, 100 PIDs
```

#### 4. Configuration Schema (`src/harombe/config/schema.py`)

**Purpose:** Pydantic models for `harombe.yaml` security section.

**Security Configuration:**

```yaml
security:
  enabled: true
  isolation: docker # or gvisor

  gateway:
    host: 127.0.0.1
    port: 8100
    timeout: 30
    max_retries: 3

  containers:
    browser:
      image: harombe/browser:latest
      resources:
        cpu_limit: "2"
        memory_limit: "2g"
      egress_allow:
        - "*.google.com"
```

## Implementation Details

### MCP Gateway Request Flow

1. **Request Reception**
   - Agent sends JSON-RPC 2.0 request to `POST /mcp`
   - FastAPI parses request body

2. **Request Validation**
   - Pydantic validates request against `MCPRequest` schema
   - Extract tool name from `params.name`

3. **Tool Routing**
   - Lookup tool in `TOOL_ROUTES` table
   - Return error if tool not found (`-32601 Method not found`)

4. **Container Request**
   - Get or create HTTP client from connection pool
   - Forward request to container with retry logic
   - Handle timeouts, connection errors, 5xx responses

5. **Response Handling**
   - Parse container response as `MCPResponse`
   - Return to agent
   - Log errors if any

### Docker Container Isolation

**Security Features Implemented:**

1. **Non-root Execution**
   - All containers run as user `harombe` (UID 1000)
   - Prevents privilege escalation

2. **Capability Dropping**
   - Drop all Linux capabilities by default
   - Add back only necessary capabilities (SETUID/SETGID for multi-user)

3. **Network Isolation**
   - Filesystem container: `network_mode: none`
   - Code execution container: `network_mode: none`
   - Browser/search: Restricted to `harombe-network`

4. **Resource Limits**
   - CPU quota enforcement (e.g., 2 cores max)
   - Memory limits (e.g., 2GB max)
   - PID limits (100 processes max)

5. **Security Options**
   - `no-new-privileges:true` - Blocks privilege escalation
   - `seccomp` profiles (where applicable)

### Connection Pooling

The gateway maintains persistent HTTP connections to containers:

```python
class MCPClientPool:
    _clients: dict[str, httpx.AsyncClient]

    async def get_client(self, container: str) -> httpx.AsyncClient:
        # Reuse existing client or create new one
        # Limits: 10 keepalive connections per container
```

**Benefits:**

- No reconnection overhead
- Connection reuse across requests
- Automatic cleanup on shutdown

### Retry Logic

Exponential backoff for transient failures:

```python
for attempt in range(max_retries):
    try:
        response = await client.post("/mcp", json=request)
        if response.status_code == 200:
            return response
        if response.status_code in {502, 503, 504}:
            wait_time = 2.0 ** attempt  # 1s, 2s, 4s
            await asyncio.sleep(wait_time)
            continue
    except httpx.TimeoutException:
        # Retry with backoff
```

## Deployment

### Docker Compose Setup

All components are orchestrated via `docker-compose.yml`:

```bash
cd docker
docker-compose build
docker-compose up -d
```

**Containers:**

- `harombe-gateway` - MCP Gateway (port 8100)
- `harombe-browser` - Browser automation (2 CPU, 2GB RAM)
- `harombe-filesystem` - File operations (1 CPU, 512MB, no network)
- `harombe-code-exec` - Code execution (2 CPU, 1GB, no network)
- `harombe-web-search` - Web search API (0.5 CPU, 256MB)

**Network:**

- `harombe-network` - Bridge network (172.20.0.0/16)

**Volumes:**

- `workspace` - Read-only workspace mount
- `projects` - Read-write projects mount

### Health Monitoring

All containers expose `/health` endpoints:

- **Interval:** 10 seconds
- **Timeout:** 5 seconds
- **Retries:** 3
- **Start Period:** 10-15 seconds

Health check failures trigger automatic restart.

### Resource Allocation

| Container  | CPU Limit | Memory Limit | Network Access       |
| ---------- | --------- | ------------ | -------------------- |
| Gateway    | Unlimited | Unlimited    | Full                 |
| Browser    | 2 cores   | 2 GB         | harombe-network only |
| Filesystem | 1 core    | 512 MB       | **None**             |
| Code Exec  | 2 cores   | 1 GB         | **None**             |
| Web Search | 0.5 cores | 256 MB       | harombe-network only |

## Testing

### Unit Tests

**Gateway Tests** (`tests/security/test_gateway.py`):

- Request routing and validation
- Error handling
- Retry logic
- Health checks
- Connection pooling
- **Coverage:** 81%

**Docker Manager Tests** (`tests/security/test_docker_manager.py`):

- Container lifecycle operations
- Resource limit configuration
- Error handling for missing containers
- **Coverage:** 45% (integration tests require Docker)

**Protocol Tests** (`tests/mcp/test_protocol.py`):

- Request/response serialization
- Error code validation
- Content item creation
- **Coverage:** 97%

**Configuration Tests** (`tests/config/test_security_config.py`):

- Schema validation
- Default values
- YAML round-trip serialization
- **Coverage:** 100%

### Integration Tests

**Phase 4 Integration** (`tests/integration/test_phase4_integration.py`):

- Docker network creation
- Container lifecycle with real Docker daemon
- Health monitoring
- Gateway → Container request flow
- Multi-container management

**Running Integration Tests:**

```bash
# Requires Docker daemon
pytest -m docker_integration

# Skip integration tests
pytest -m "not docker_integration"
```

## Configuration Example

Add to `harombe.yaml`:

```yaml
security:
  enabled: true
  isolation: docker

  gateway:
    host: 127.0.0.1
    port: 8100
    timeout: 30
    max_retries: 3

  audit:
    enabled: false # Phase 4.2

  credentials:
    method: env # env | vault | sops

  containers:
    browser:
      image: harombe/browser:latest
      enabled: true
      resources:
        cpu_limit: "2"
        memory_limit: "2g"
        pids_limit: 100
      egress_allow:
        - "*.google.com"
        - "*.github.com"

    filesystem:
      image: harombe/filesystem:latest
      enabled: true
      resources:
        cpu_limit: "1"
        memory_limit: "512m"
      egress_allow: [] # No network access
      mounts:
        - "/home/user/workspace:/workspace:ro"
        - "/home/user/projects:/projects:rw"

    code_exec:
      image: harombe/code-exec:latest
      enabled: true
      resources:
        cpu_limit: "2"
        memory_limit: "1g"
      egress_allow: []
      timeout: 30

    web_search:
      image: harombe/web-search:latest
      enabled: true
      resources:
        cpu_limit: "0.5"
        memory_limit: "256m"
      egress_allow:
        - "api.duckduckgo.com"

  hitl:
    enabled: false # Phase 4.5
    timeout: 60
```

## Limitations and Future Work

### Current Limitations

1. **No MCP Server Implementations**
   - Containers have placeholder health servers
   - Actual browser/filesystem/code-exec servers pending (Phases 4.6-4.7)

2. **No Audit Logging**
   - Request/response logging not implemented
   - Audit database schema pending (Phase 4.2)

3. **No Secret Management**
   - Credentials passed via environment variables
   - Vault integration pending (Phase 4.3)

4. **No Network Egress Filtering**
   - Egress allowlists configured but not enforced
   - iptables rules pending (Phase 4.4)

5. **No HITL Gates**
   - Human confirmation for dangerous actions not implemented
   - HITL framework pending (Phase 4.5)

### Future Phases

**Phase 4.2 (Audit Logging):**

- SQLite audit database
- Request/response logging
- Query interface
- Retention policies

**Phase 4.3 (Secret Management):**

- HashiCorp Vault integration
- Secret scanning and redaction
- Credential rotation
- Environment injection

**Phase 4.4 (Network Isolation):**

- Per-container egress allowlists
- iptables/nftables rules
- DNS filtering
- Network telemetry

**Phase 4.5 (HITL Gates):**

- Action classification
- Confirmation prompts (CLI/webhook)
- Timeout handling
- Queue management

**Phase 4.6 (Browser Container):**

- Selenium-based automation
- Accessibility tree interaction
- Screenshot capture
- Session management

**Phase 4.7 (Code Execution):**

- Python/JavaScript/Bash execution
- gVisor sandboxing
- Resource limits per execution
- Output capture

**Phase 4.8 (Integration):**

- End-to-end testing
- Performance optimization
- Security audit
- Documentation finalization

## Performance Targets

### Phase 4.1 Achieved

- **Latency Overhead:** <5ms (gateway processing)
- **Throughput:** Not yet measured (awaiting MCP server implementations)
- **Connection Pooling:** ✅ Implemented
- **Concurrent Requests:** ✅ FastAPI async support

### Phase 4.8 Targets

- **Gateway Overhead:** <5ms per request
- **Throughput:** >1000 requests/second
- **Container Startup:** <2 seconds
- **Health Check Latency:** <100ms

## Security Posture

### Implemented (Phase 4.1)

✅ **Container Isolation:** Docker containers with capability dropping
✅ **Non-root Execution:** All containers run as UID 1000
✅ **Network Isolation:** Filesystem/code-exec have no network access
✅ **Resource Limits:** CPU/memory/PID constraints per container
✅ **Request Validation:** JSON-RPC 2.0 schema validation
✅ **Error Handling:** Graceful degradation on container failures

### Pending (Later Phases)

⏳ **Audit Logging:** Complete request/response trail (Phase 4.2)
⏳ **Secret Scanning:** Credential leak detection (Phase 4.3)
⏳ **Egress Filtering:** Network allowlist enforcement (Phase 4.4)
⏳ **HITL Gates:** Human confirmation for destructive actions (Phase 4.5)
⏳ **gVisor Sandboxing:** Enhanced container isolation (Phase 4.7)

## Troubleshooting

### Gateway Not Starting

**Symptom:** `docker-compose up` fails for gateway container

**Solutions:**

1. Check logs: `docker-compose logs gateway`
2. Verify port 8100 is available: `lsof -i :8100`
3. Ensure harombe package is installed: `pip install -e .`

### Container Health Check Failing

**Symptom:** Container shows `unhealthy` status

**Solutions:**

1. Check container logs: `docker-compose logs <container>`
2. Verify health endpoint: `docker exec harombe-<container> curl localhost:<port>/health`
3. Increase health check timeout in `docker-compose.yml`

### Cannot Connect to Container

**Symptom:** Gateway returns "Container unavailable" error

**Solutions:**

1. Verify container is running: `docker-compose ps`
2. Check network: `docker network inspect harombe_harombe-network`
3. Test container directly: `curl http://localhost:<port>/health`

### Resource Limit Exceeded

**Symptom:** Container killed due to OOM or CPU throttling

**Solutions:**

1. Increase limits in `docker-compose.yml` under `deploy.resources`
2. Monitor usage: `docker stats`
3. Optimize container workload

## References

- [Phase 4 Implementation Plan](./phases/phase4-implementation-plan.md)
- [MCP Gateway Design](./mcp-gateway-design.md)
- [Docker README](https://github.com/smallthinkingmachines/harombe/blob/main/docker/README.md)
- [MCP Protocol Specification](https://spec.modelcontextprotocol.io/)

## Changelog

### 2026-02-08 - Phase 4.1 Complete

**Added:**

- MCP Gateway implementation
- Docker container manager
- MCP protocol models
- Security configuration schema
- Docker Compose orchestration
- Integration test framework
- Comprehensive documentation

**Status:** Phase 4.1 (Foundation) complete ✅
