# Harombe Docker Setup

This directory contains Docker configurations for Harombe's security layer (Phase 4).

## Architecture

```
┌─────────────────────────────────────┐
│  Agent (Host Machine)               │
│  - ReAct loop                       │
│  - LLM inference                    │
└──────────────┬──────────────────────┘
               │ HTTP/JSON-RPC 2.0
               │ Port: 8100
               ▼
┌─────────────────────────────────────┐
│  MCP Gateway Container              │
│  - Request routing                  │
│  - Security enforcement             │
│  - Audit logging                    │
└──────────────┬──────────────────────┘
               │
    ┌──────────┼──────────┬──────────┐
    │          │          │          │
    ▼          ▼          ▼          ▼
┌────────┐ ┌───────┐ ┌──────┐ ┌──────┐
│Browser │ │Files  │ │Code  │ │Search│
│:3000   │ │:3001  │ │:3002 │ │:3003 │
└────────┘ └───────┘ └──────┘ └──────┘
```

## Containers

### Gateway Container

- **Image**: Built from `gateway/Dockerfile`
- **Port**: 8100
- **Purpose**: Central security enforcement point
- **Resources**: Default (no limits)
- **Network**: Full access to harombe-network

### Browser Container

- **Image**: Built from `browser/Dockerfile`
- **Port**: 3000 (internal)
- **Purpose**: Web automation with Selenium
- **Resources**: 2 CPU cores, 2GB RAM (limit)
- **Network**: Access to harombe-network
- **Security**: Dropped all capabilities except SETUID/SETGID

### Filesystem Container

- **Image**: Built from `filesystem/Dockerfile`
- **Port**: 3001 (internal)
- **Purpose**: File read/write operations
- **Resources**: 1 CPU core, 512MB RAM (limit)
- **Network**: No network access (network_mode: none)
- **Security**: Dropped all capabilities
- **Volumes**: `/workspace` (ro), `/projects` (rw)

### Code Execution Container

- **Image**: Built from `code-exec/Dockerfile`
- **Port**: 3002 (internal)
- **Purpose**: Sandboxed code execution (Python, JavaScript, Bash)
- **Resources**: 2 CPU cores, 1GB RAM (limit)
- **Network**: No network access (network_mode: none)
- **Security**: Dropped all capabilities except SETUID/SETGID

### Web Search Container

- **Image**: Built from `web-search/Dockerfile`
- **Port**: 3003 (internal)
- **Purpose**: DuckDuckGo search via API
- **Resources**: 0.5 CPU cores, 256MB RAM (limit)
- **Network**: Access to harombe-network
- **Security**: Dropped all capabilities

## Quick Start

### 1. Build all containers

```bash
cd docker
docker-compose build
```

### 2. Start the stack

```bash
docker-compose up -d
```

### 3. Check health status

```bash
docker-compose ps
```

All containers should show `healthy` status after startup period.

### 4. View logs

```bash
# All containers
docker-compose logs -f

# Specific container
docker-compose logs -f gateway
docker-compose logs -f browser
```

### 5. Stop the stack

```bash
docker-compose down
```

## Environment Variables

Create a `.env` file in the `docker/` directory:

```env
# Gateway configuration
GATEWAY_HOST=0.0.0.0
GATEWAY_PORT=8100
LOG_LEVEL=INFO

# Volume mounts
HAROMBE_WORKSPACE=/path/to/your/workspace
HAROMBE_PROJECTS=/path/to/your/projects
```

## Resource Limits

Default resource limits per container:

| Container  | CPU Limit | Memory Limit | Reservation |
| ---------- | --------- | ------------ | ----------- |
| Gateway    | Unlimited | Unlimited    | N/A         |
| Browser    | 2 cores   | 2 GB         | 512 MB      |
| Filesystem | 1 core    | 512 MB       | 128 MB      |
| Code Exec  | 2 cores   | 1 GB         | 256 MB      |
| Web Search | 0.5 cores | 256 MB       | 64 MB       |

Adjust in `docker-compose.yml` under `deploy.resources`.

## Network Isolation

Containers are isolated by default:

- **Gateway**: Full network access (needs to route requests)
- **Browser**: Access to harombe-network only
- **Filesystem**: **No network access** (network_mode: none)
- **Code Exec**: **No network access** (network_mode: none)
- **Web Search**: Access to harombe-network only

## Security Features

### Capability Dropping

All containers drop all Linux capabilities by default, adding back only what's necessary:

- Browser/Code Exec: `SETUID`, `SETGID` (for running as non-root)

### Read-only Filesystems

Containers run with minimal write access:

- `/workspace` is mounted read-only
- `/projects` is mounted read-write

### Non-root Users

All containers run as user `harombe` (UID 1000), not root.

### Security Options

- `no-new-privileges:true` - Prevents privilege escalation
- `seccomp` profiles (where applicable)

## Health Checks

Each container exposes a `/health` endpoint:

- **Interval**: 10 seconds
- **Timeout**: 5 seconds
- **Retries**: 3
- **Start Period**: 10-15 seconds

Health check failures trigger automatic container restart.

## Development

### Building a single container

```bash
docker-compose build gateway
docker-compose build browser
```

### Running without detach (see logs)

```bash
docker-compose up
```

### Rebuilding after code changes

```bash
docker-compose up --build
```

## Production Deployment

For production use:

1. **Use specific image tags** instead of `latest`
2. **Set resource limits** appropriate for your hardware
3. **Configure logging drivers** (e.g., `json-file` with rotation)
4. **Enable TLS** for gateway if exposing externally
5. **Use secrets management** (Docker Secrets, Vault)
6. **Set restart policies** (already set to `unless-stopped`)

## Troubleshooting

### Container won't start

```bash
docker-compose logs <container-name>
```

### Health check failing

```bash
docker exec harombe-<container> curl -f http://localhost:<port>/health
```

### Network issues

```bash
docker network inspect harombe_harombe-network
```

### Permission issues with volumes

Ensure mounted directories are owned by UID 1000 (harombe user):

```bash
sudo chown -R 1000:1000 /path/to/workspace
```

## Implementation Status

**Phase 4.1 (Foundation)**: ✅ Complete

- Docker Compose orchestration
- Container definitions
- Network configuration
- Resource limits
- Security options

**Phase 4.6 (Browser Container)**: ⏳ Pending

- Browser MCP server implementation
- Selenium automation
- Accessibility-based interaction

**Phase 4.7 (Code Execution)**: ⏳ Pending

- Code execution MCP server
- Multi-language support
- Sandbox enforcement

**Phase 4.8 (Integration)**: ⏳ Pending

- Full agent → gateway → container flow
- End-to-end testing
- Performance optimization

## Related Documentation

- [Phase 4 Implementation Plan](../docs/phase4-implementation-plan.md)
- [MCP Gateway Design](../docs/mcp-gateway-design.md)
- [Security Architecture](../docs/security-architecture.md) (coming in Phase 4.8)
