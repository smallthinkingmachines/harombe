# Reference Architecture: Multi-Node Cluster with Privacy Routing

A 2-3 node cluster that routes queries based on complexity and privacy sensitivity.

## Overview

This architecture distributes workload across multiple machines. Simple questions stay on a lightweight local node, complex analysis goes to a powerful server, and privacy-sensitive queries never leave the local network. The privacy router makes the routing decision transparent to users.

## Hardware Layout

| Node                | Hardware                   | Model           | Tier | Role                       |
| ------------------- | -------------------------- | --------------- | ---- | -------------------------- |
| Laptop              | MacBook M2, 16 GB          | `llama3.1:8b`   | 0    | Coordinator + fast queries |
| Server A            | Linux, 64 GB RAM, RTX 4090 | `llama3.1:70b`  | 2    | Complex analysis           |
| Server B (optional) | Linux, 32 GB RAM           | `codellama:34b` | 1    | Code tasks                 |

## Architecture

```
┌─────────────────────────────────────┐
│  Laptop (Coordinator, Tier 0)       │
│  harombe chat                       │
│  ┌─────────────┐  ┌──────────────┐  │
│  │Privacy Router│  │Cluster Router│  │
│  │ PII filter   │  │ Complexity   │  │
│  └──────┬──────┘  └──────┬───────┘  │
│         │                │          │
│  ┌──────▼──────┐         │          │
│  │ Ollama      │         │          │
│  │ llama3.1:8b │         │          │
│  └─────────────┘         │          │
└──────────────────────────┼──────────┘
                           │ LAN only
              ┌────────────┼────────────┐
              │            │            │
       ┌──────▼──────┐  ┌─▼───────────┐
       │  Server A   │  │  Server B   │
       │  Tier 2     │  │  Tier 1     │
       │  70b model  │  │  34b model  │
       └─────────────┘  └─────────────┘
```

## Setup

### 1. Configure the Coordinator (Laptop)

```yaml
# harombe.yaml (laptop)

model:
  name: llama3.1:8b

privacy:
  mode: hybrid
  pii_detection: true
  sensitivity_threshold: 0.5
  cloud_provider:
    # "cloud" here is Server A on LAN, not public cloud
    base_url: http://server-a.local:11434
    model: llama3.1:70b

cluster:
  enabled: true
  node_id: laptop
  tier: 0
  bind_host: "0.0.0.0"
  bind_port: 8000
  nodes:
    - id: server-a
      host: server-a.local
      port: 8000
      tier: 2
      capabilities:
        - reasoning
        - analysis
    - id: server-b
      host: server-b.local
      port: 8000
      tier: 1
      capabilities:
        - code

memory:
  enabled: true
  backend: sqlite
  embedding:
    model: nomic-embed-text
    provider: ollama

tools:
  shell: true
  filesystem: true
  web_search: true
  confirm_dangerous: true

security:
  hitl:
    enabled: true
```

### 2. Configure Server A

```yaml
# harombe.yaml (Server A)

model:
  name: llama3.1:70b

cluster:
  enabled: true
  node_id: server-a
  tier: 2
  bind_host: "0.0.0.0"
  bind_port: 8000

ollama:
  host: http://localhost:11434
```

### 3. Configure Server B

```yaml
# harombe.yaml (Server B)

model:
  name: codellama:34b

cluster:
  enabled: true
  node_id: server-b
  tier: 1
  bind_host: "0.0.0.0"
  bind_port: 8000

ollama:
  host: http://localhost:11434
```

### 4. Start Nodes

```bash
# On each machine:
harombe start
```

### 5. Chat from Coordinator

```bash
# On laptop:
harombe chat
```

## Query Routing Examples

| Query                            | Complexity | Privacy      | Routed To           |
| -------------------------------- | ---------- | ------------ | ------------------- |
| "What time is it?"               | Simple     | None         | Laptop (Tier 0)     |
| "Summarize this report"          | Medium     | None         | Server B (Tier 1)   |
| "Analyze codebase architecture"  | Complex    | None         | Server A (Tier 2)   |
| "Review employee records in HR/" | Complex    | PII detected | Laptop (local-only) |

## Privacy Routing Behavior

The privacy router intercepts queries before cluster routing:

1. **PII detected** (names, SSNs, medical data) → forced to local node, regardless of complexity
2. **Sensitivity above threshold** → local processing only
3. **Clean queries** → routed normally by complexity tier

This ensures sensitive data never leaves the coordinator machine, even in a cluster.

## Health and Failover

- Nodes send heartbeats every 30 seconds
- Circuit breaker opens after 3 consecutive failures
- If a tier is unavailable, the query falls back to the next available tier
- The coordinator can handle all queries locally if both servers go down

## Monitoring

```bash
# Check cluster status
harombe cluster status

# View routing statistics
harombe chat
You> /privacy
```
