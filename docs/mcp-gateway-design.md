# MCP Gateway Design Specification

**Version:** 1.0
**Status:** Draft
**Date:** 2026-02-09

## Overview

The MCP Gateway is the central security enforcement point in Harombe's architecture. It acts as a proxy between the agent and capability containers, providing authentication, authorization, audit logging, and request routing.

## Architecture

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
│  │ - Authenticate               │   │
│  └──────────┬──────────────────┘   │
│             ▼                        │
│  ┌─────────────────────────────┐   │
│  │ Router                       │   │
│  │ - Map tool → container       │   │
│  │ - Load balancing             │   │
│  │ - Health checking            │   │
│  └──────────┬──────────────────┘   │
│             ▼                        │
│  ┌─────────────────────────────┐   │
│  │ Security Layer               │   │
│  │ - Secret scanning            │   │
│  │ - HITL gates                 │   │
│  │ - Audit logging              │   │
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

## Protocol: JSON-RPC 2.0

The MCP Gateway uses JSON-RPC 2.0 for all communication.

### Request Format

```json
{
  "jsonrpc": "2.0",
  "id": "req-123e4567-e89b-12d3-a456-426614174000",
  "method": "tools/call",
  "params": {
    "name": "browser_navigate",
    "arguments": {
      "url": "https://example.com"
    }
  }
}
```

### Response Format (Success)

```json
{
  "jsonrpc": "2.0",
  "id": "req-123e4567-e89b-12d3-a456-426614174000",
  "result": {
    "content": [
      {
        "type": "text",
        "text": "Navigation successful. Page title: Example Domain"
      }
    ]
  }
}
```

### Response Format (Error)

```json
{
  "jsonrpc": "2.0",
  "id": "req-123e4567-e89b-12d3-a456-426614174000",
  "error": {
    "code": -32603,
    "message": "Internal error",
    "data": {
      "type": "ContainerError",
      "details": "Browser container not responding"
    }
  }
}
```

### Standard Error Codes

Following JSON-RPC 2.0 specification:

- `-32700`: Parse error (invalid JSON)
- `-32600`: Invalid Request (malformed request object)
- `-32601`: Method not found (tool does not exist)
- `-32602`: Invalid params (invalid arguments)
- `-32603`: Internal error (server-side error)
- `-32000 to -32099`: Application-defined errors

**Harombe-specific error codes:**

- `-32000`: Authentication failed
- `-32001`: Authorization denied (HITL rejected)
- `-32002`: Container unavailable
- `-32003`: Container timeout
- `-32004`: Secret detected (blocked)
- `-32005`: Rate limit exceeded
- `-32006`: Resource limit exceeded

## Request/Response Flow

### 1. Agent → Gateway

```
POST /mcp HTTP/1.1
Host: localhost:8100
Content-Type: application/json

{
  "jsonrpc": "2.0",
  "id": "req-123",
  "method": "tools/call",
  "params": {
    "name": "filesystem_read",
    "arguments": {
      "path": "/workspace/data.txt"
    }
  }
}
```

### 2. Gateway Processing

1. **Parse Request**: Validate JSON-RPC 2.0 format
2. **Authenticate**: Verify request origin (future: token validation)
3. **Route**: Determine target container based on tool name
4. **Security Check**:
   - Scan for secrets in arguments
   - Check HITL rules (if required, wait for confirmation)
5. **Audit Log**: Record request (timestamp, tool, arguments)
6. **Forward**: Send to capability container via HTTP

### 3. Gateway → Container

```
POST /mcp HTTP/1.1
Host: filesystem-container:3000
Content-Type: application/json

{
  "jsonrpc": "2.0",
  "id": "req-123",
  "method": "tools/call",
  "params": {
    "name": "filesystem_read",
    "arguments": {
      "path": "/workspace/data.txt"
    }
  }
}
```

### 4. Container → Gateway

```json
{
  "jsonrpc": "2.0",
  "id": "req-123",
  "result": {
    "content": [
      {
        "type": "text",
        "text": "File contents: Hello, World!"
      }
    ]
  }
}
```

### 5. Gateway Processing (Response)

1. **Receive Response**: Parse JSON-RPC response
2. **Secret Scan**: Check response for leaked credentials
3. **Audit Log**: Record response
4. **Return**: Forward to agent

### 6. Gateway → Agent

```json
{
  "jsonrpc": "2.0",
  "id": "req-123",
  "result": {
    "content": [
      {
        "type": "text",
        "text": "File contents: Hello, World!"
      }
    ]
  }
}
```

## Tool → Container Mapping

The gateway maintains a routing table:

```python
TOOL_ROUTES = {
    # Browser tools
    "browser_navigate": "browser-container:3000",
    "browser_click": "browser-container:3000",
    "browser_type": "browser-container:3000",
    "browser_read": "browser-container:3000",

    # Filesystem tools
    "filesystem_read": "filesystem-container:3001",
    "filesystem_write": "filesystem-container:3001",
    "filesystem_list": "filesystem-container:3001",

    # Code execution tools
    "code_execute": "code-exec-container:3002",

    # Web search tools
    "web_search": "web-search-container:3003",
}
```

Routing logic:

1. Extract tool name from `params.name`
2. Look up container endpoint
3. If not found, return error `-32601` (Method not found)
4. Forward request to container

## Connection Pooling

The gateway maintains persistent HTTP connections to capability containers:

```python
class MCPClientPool:
    def __init__(self):
        self._clients: dict[str, httpx.AsyncClient] = {}
        self._max_connections = 10
        self._timeout = 30.0

    async def get_client(self, container: str) -> httpx.AsyncClient:
        """Get or create HTTP client for container."""
        if container not in self._clients:
            self._clients[container] = httpx.AsyncClient(
                base_url=f"http://{container}",
                timeout=self._timeout,
                limits=httpx.Limits(
                    max_keepalive_connections=self._max_connections,
                    max_connections=self._max_connections,
                )
            )
        return self._clients[container]
```

## Error Handling

### Retry Strategy

```python
class RetryConfig:
    max_retries: int = 3
    backoff_factor: float = 2.0  # Exponential backoff
    retry_statuses: set[int] = {502, 503, 504}  # Bad Gateway, Service Unavailable, Gateway Timeout
    timeout: float = 30.0
```

Retry logic:

1. Send request to container
2. If timeout or retry-able error:
   - Wait `backoff_factor ^ attempt` seconds
   - Retry up to `max_retries` times
3. If all retries fail, return error `-32003` (Container timeout)

### Circuit Breaker

Prevent cascading failures:

```python
class CircuitBreaker:
    failure_threshold: int = 5
    timeout: int = 60  # seconds
    half_open_attempts: int = 1
```

States:

- **Closed**: Normal operation
- **Open**: Too many failures, reject immediately
- **Half-Open**: Testing if service recovered

## Health Checks

### Gateway Health

```
GET /health
Response: 200 OK
{
  "status": "healthy",
  "version": "0.1.0",
  "uptime": 3600
}
```

### Container Health

Gateway periodically checks container health:

```
GET /health (on each container)
Interval: 10 seconds
Timeout: 5 seconds
```

If container fails health check:

1. Mark as unhealthy
2. Stop routing requests
3. Attempt restart (via Docker manager)
4. If restart fails, alert and mark as unavailable

## Security Features (Phase 4.1 - Basic)

### Request Validation

- Validate JSON-RPC 2.0 format
- Check required fields (`jsonrpc`, `method`, `params`)
- Validate tool name against allowlist
- Validate argument types

### Basic Audit Logging

Log every request/response:

```python
@dataclass
class AuditEntry:
    timestamp: datetime
    request_id: str
    tool_name: str
    arguments: dict
    response_status: str  # "success" | "error"
    response_time_ms: float
    error_code: int | None = None
    error_message: str | None = None
```

Store in SQLite database (detailed audit in Phase 4.2).

## Configuration

```yaml
security:
  enabled: true

  gateway:
    host: 127.0.0.1
    port: 8100
    timeout: 30
    max_retries: 3
    connection_pool_size: 10

  containers:
    browser:
      endpoint: "browser-container:3000"
      enabled: true
      health_check_interval: 10

    filesystem:
      endpoint: "filesystem-container:3001"
      enabled: true

    code_exec:
      endpoint: "code-exec-container:3002"
      enabled: true

    web_search:
      endpoint: "web-search-container:3003"
      enabled: true
```

## API Endpoints

### Core Endpoints

#### POST /mcp

Main JSON-RPC endpoint for tool calls.

**Request:** JSON-RPC 2.0 request
**Response:** JSON-RPC 2.0 response
**Status Codes:** 200 (OK), 400 (Bad Request), 500 (Internal Error)

#### GET /health

Health check endpoint.

**Response:**

```json
{
  "status": "healthy",
  "version": "0.1.0",
  "uptime": 3600,
  "containers": {
    "browser": "healthy",
    "filesystem": "healthy",
    "code_exec": "healthy",
    "web_search": "healthy"
  }
}
```

#### GET /ready

Readiness check (all containers healthy).

**Response:**

```json
{
  "ready": true,
  "containers_healthy": 4,
  "containers_total": 4
}
```

### Admin Endpoints (Future)

- `GET /metrics` - Prometheus metrics
- `GET /audit` - Query audit logs
- `POST /containers/{name}/restart` - Restart container

## Performance Targets

- **Latency overhead**: <5ms (gateway processing)
- **Throughput**: >1000 requests/second
- **Connection pooling**: Reuse connections (no reconnect overhead)
- **Concurrent requests**: Support 100+ concurrent tool calls

## Implementation Notes

### Phase 4.1 Scope (MVP)

**Included:**

- Basic JSON-RPC 2.0 request/response handling
- Tool → container routing
- Connection pooling
- Health checks
- Basic error handling
- Simple audit logging (request/response only)

**Not Included (Future Phases):**

- Secret scanning (Phase 4.3)
- HITL gates (Phase 4.5)
- Detailed audit logging (Phase 4.2)
- Authentication/authorization (Phase 4.2)
- Network egress policies (Phase 4.4)

### Technology Stack

- **FastAPI**: Gateway server
- **httpx**: Async HTTP client for container communication
- **Pydantic**: Request/response validation
- **SQLite**: Basic audit logging
- **Docker SDK**: Container management (Phase 4.1)

## Testing Strategy

### Unit Tests

- JSON-RPC message parsing
- Routing logic
- Error handling
- Connection pooling

### Integration Tests

- Gateway ↔ Mock container
- Health check flow
- Retry logic
- Circuit breaker

### Load Tests

- 1000 requests/second throughput
- Concurrent request handling
- Connection pool efficiency

## Security Considerations

### Phase 4.1 (Basic Security)

- Input validation (prevent injection)
- Tool allowlist (only known tools)
- Container isolation (Docker networks)
- Basic audit trail

### Future Phases

- Secret scanning (Phase 4.3)
- HITL gates for destructive actions (Phase 4.5)
- Credential vault integration (Phase 4.3)
- Network egress filtering (Phase 4.4)

## Next Steps

1. Implement `src/harombe/mcp/protocol.py` (JSON-RPC models)
2. Implement `src/harombe/security/gateway.py` (FastAPI server)
3. Implement `src/harombe/security/docker_manager.py` (container lifecycle)
4. Create Docker Compose setup
5. Write integration tests

---

**Document Status:** Ready for implementation
**Approved By:** TBD
**Implementation Start:** 2026-02-09
