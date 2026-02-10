# Multi-Node Cluster Setup Guide

Step-by-step guide for setting up a 2-3 node Harombe cluster.

## Overview

Harombe clusters route queries to different nodes based on task complexity. Simple questions go to fast/lightweight nodes, while complex analysis tasks go to powerful nodes with larger models.

## Prerequisites

On each machine:

- Python 3.11+
- [Ollama](https://ollama.ai) installed and running
- Network connectivity between all machines (port 8000 by default)

## Architecture

```
┌─────────────────────────────────┐
│  Coordinator (your laptop)      │
│  - Runs harombe chat            │
│  - Routes queries to nodes      │
│  - Handles failover             │
└───────┬──────────┬──────────────┘
        │          │
        ▼          ▼
┌──────────┐  ┌──────────┐
│  Node A  │  │  Node B  │
│  Tier 0  │  │  Tier 2  │
│  3b model│  │  72b model│
└──────────┘  └──────────┘
```

## Step 1: Set Up Worker Nodes

Repeat on each machine that will serve as a worker node.

### Install Harombe

```bash
pip install harombe
```

### Pull the model

Choose a model appropriate for this node's hardware:

```bash
# Lightweight node (4-8GB VRAM)
ollama pull qwen2.5:3b

# Medium node (16GB VRAM)
ollama pull qwen2.5:14b

# Powerful node (48GB+ VRAM)
ollama pull qwen2.5:72b
```

### Configure the node

Create `~/.harombe/harombe.yaml`:

```yaml
model:
  name: qwen2.5:14b # The model this node runs

server:
  host: 0.0.0.0 # Listen on all interfaces
  port: 8000

ollama:
  host: http://localhost:11434
```

### Start the node

```bash
harombe start
```

### Verify it's accessible

From another machine:

```bash
curl http://<node-ip>:8000/health
```

You should see:

```json
{ "status": "ok", "model": "qwen2.5:14b" }
```

## Step 2: Configure the Coordinator

On the machine where you'll run `harombe chat`, create `~/.harombe/harombe.yaml`:

```yaml
model:
  name: qwen2.5:7b # Local model (optional, for simple queries)
  temperature: 0.7

agent:
  max_steps: 10

tools:
  shell: true
  filesystem: true
  web_search: true
  confirm_dangerous: true

cluster:
  routing:
    prefer_local: true # Use lowest-latency node when possible
    fallback_strategy: graceful # Fall back to other tiers if preferred unavailable
    load_balance: true # Distribute across same-tier nodes

  nodes:
    - name: laptop
      host: localhost
      port: 8000
      model: qwen2.5:7b
      tier: 0 # Fast: simple queries

    - name: workstation
      host: 192.168.1.100
      port: 8000
      model: qwen2.5:14b
      tier: 1 # Medium: balanced workloads

    - name: server
      host: 192.168.1.200
      port: 8000
      model: qwen2.5:72b
      tier: 2 # Powerful: complex analysis
```

## Step 3: Verify the Cluster

```bash
# Check cluster status
harombe cluster status

# Test connectivity to all nodes
harombe cluster test

# View performance metrics
harombe cluster metrics
```

Expected output from `harombe cluster status`:

```
┏━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━┳━━━━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━┓
┃ Name        ┃ Host                    ┃ Tier ┃ Model         ┃ Status    ┃ Latency ┃
┡━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━╇━━━━━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━┩
│ laptop      │ localhost:8000          │ 0    │ qwen2.5:7b    │ available │ 1.2ms   │
│ workstation │ 192.168.1.100:8000      │ 1    │ qwen2.5:14b   │ available │ 5.3ms   │
│ server      │ 192.168.1.200:8000      │ 2    │ qwen2.5:72b   │ available │ 12.1ms  │
└─────────────┴─────────────────────────┴──────┴───────────────┴───────────┴─────────┘
```

## Step 4: Use the Cluster

```bash
harombe chat
```

The router automatically selects the best node:

- **"What is Python?"** → Tier 0 (laptop, fast response)
- **"Explain async/await in Python"** → Tier 1 (workstation, balanced)
- **"Refactor this code, write tests, and explain trade-offs"** → Tier 2 (server, powerful model)

## Tier Guidelines

| Tier | Use Case                                          | Typical Hardware     | Model Size |
| ---- | ------------------------------------------------- | -------------------- | ---------- |
| 0    | Simple queries, quick factual answers             | Laptop, Mac Mini     | 1-7B       |
| 1    | Moderate analysis, explanations                   | Desktop, workstation | 7-30B      |
| 2    | Complex reasoning, code generation, large context | Server, cloud GPU    | 30-72B+    |

Tiers are **user-defined** — assign based on your judgment.

## Fallback Behavior

When the preferred tier is unavailable:

- **Graceful** (default): Tries adjacent tiers. If tier 2 is down, tries tier 1, then tier 0.
- **Strict**: Only uses the recommended tier. Returns an error if unavailable.

## Troubleshooting

### Node shows "unavailable"

```bash
# Check if the node is running
curl http://<node-ip>:8000/health

# Check Ollama is running on the node
curl http://<node-ip>:11434/api/tags

# Check firewall/network
ping <node-ip>
```

### High latency

- Ensure nodes are on the same network (LAN preferred)
- Check for network congestion
- Use `harombe cluster metrics` to identify bottlenecks

### Circuit breaker open

After repeated failures, the circuit breaker prevents traffic to a failing node. It automatically tests recovery after 60 seconds. Check the node's health and restart if necessary.

## Security Considerations

- Cluster traffic is **unencrypted by default**. Use SSH tunnels or VPN for sensitive data.
- Set `auth_token` on remote nodes for basic authentication.
- Run nodes behind a firewall — don't expose port 8000 to the internet.
