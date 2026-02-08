# Phase 1: Multi-Machine Orchestration - Design Document

## Context

Building on Phase 0 MVP, we're adding multi-machine support for **heterogeneous hardware clusters**.

**Design Goal**: Enable users to orchestrate ANY mix of hardware:
- Consumer GPUs (NVIDIA RTX, AMD Radeon)
- Apple Silicon (Mac Mini, Mac Studio, MacBook)
- Enterprise GPUs (DGX, H100, A100)
- CPUs (as fallback)
- Cloud instances (as needed)

**Use Cases**:
- Personal AI across home/office machines
- Small team sharing GPU resources
- Academic research labs
- Enterprise on-prem deployments

## Key Insight

This is NOT about splitting one model across machines (model parallelism - too complex, high latency).

This is about **intelligent task routing** across a heterogeneous cluster:
- Different models for different tasks
- Graceful degradation when nodes unavailable
- Load balancing across available resources
- Zero manual intervention

## Architecture Vision

```
┌─────────────────────────────────────────────────────────────────────┐
│                        harombe Coordinator                          │
│                    (any always-on machine)                          │
├─────────────────────────────────────────────────────────────────────┤
│  • Receives user queries                                            │
│  • Analyzes task complexity                                         │
│  • Routes to appropriate node                                       │
│  • Aggregates responses                                             │
│  • Manages conversation state                                       │
└─────────────────────────────────────────────────────────────────────┘
                                  │
          ┌───────────────────────┼───────────────────────┐
          ▼                       ▼                       ▼
┌─────────────────┐   ┌─────────────────┐   ┌─────────────────┐
│   Tier 0: Fast  │   │  Tier 1: Medium │   │ Tier 2: Powerful│
│   (local/small) │   │  (balanced)     │   │  (large models) │
├─────────────────┤   ├─────────────────┤   ├─────────────────┤
│ Examples:       │   │ Examples:       │   │ Examples:       │
│ • MacBook 3B    │   │ • RTX 4090 14B  │   │ • DGX 72B       │
│ • CPU 1.5B      │   │ • Mac Studio 7B │   │ • A100 235B     │
│ • RPi (future)  │   │ • AMD 7900 14B  │   │ • Multi-GPU     │
└─────────────────┘   └─────────────────┘   └─────────────────┘

Tiers are LOGICAL, not hardware-specific.
User declares tier in config based on their hardware capabilities.
```

## Layered Architecture (from Notion)

Following the original architectural vision, Phase 1 adds the **Coordination Layer**:

```
┌─────────────────────────────────────────────────────────────────────┐
│  Layer 5: User Interface                                            │
│  • CLI (harombe chat, harombe cluster)                              │
│  • REST API (FastAPI)                                               │
│  • Web UI (future)                                                  │
└─────────────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────────────┐
│  Layer 4: Agent & Memory                                            │
│  • ReAct loop (Phase 0 ✓)                                           │
│  • Tool registry (Phase 0 ✓)                                        │
│  • Conversation state                                               │
│  • Long-term memory (Phase 2)                                       │
└─────────────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────────────┐
│  Layer 3: Coordination Layer ← PHASE 1 FOCUS                        │
│  • Cluster management                                               │
│  • Node discovery (mDNS + explicit)                                 │
│  • Task routing & load balancing                                    │
│  • Health monitoring                                                │
│  • Failure recovery                                                 │
└─────────────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────────────┐
│  Layer 2: Inference Abstraction                                     │
│  • LLM client protocol (Phase 0 ✓)                                  │
│  • Ollama adapter (Phase 0 ✓)                                       │
│  • Remote inference client (Phase 1)                                │
│  • Future: vLLM, llama.cpp, etc.                                    │
└─────────────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────────────┐
│  Layer 1: Hardware Abstraction                                      │
│  • GPU detection (Phase 0 ✓)                                        │
│  • Model recommendations (Phase 0 ✓)                                │
│  • Resource monitoring                                              │
│  • VRAM/memory tracking                                             │
└─────────────────────────────────────────────────────────────────────┘
```

## Design Principles

1. **Hardware-Agnostic**: Works with ANY hardware mix (Apple Silicon, NVIDIA, AMD, CPU)
2. **Graceful Degradation**: Automatic fallback when nodes unavailable
3. **Smart Routing**: Task complexity → appropriate tier
4. **Local-First**: Prefer lowest latency unless task demands power
5. **User-Controlled**: Users assign tiers based on their judgment
6. **Zero-Config Option**: mDNS auto-discovery for simple setups
7. **Explicit Config Option**: YAML for complex networks/cloud

## Core Components

### 1. Node Types

```python
@dataclass
class NodeCapability:
    """Hardware-agnostic node description."""
    name: str              # User-chosen: "office-mac", "bedroom-pc", "server1"
    host: str              # hostname or IP
    port: int
    model: str             # which model it's running (user configures)
    tier: int              # User declares: 0=fast, 1=medium, 2=powerful

    # Auto-detected (for informational purposes)
    hardware_type: str     # "apple_silicon", "nvidia", "amd", "cpu"
    vram_gb: float         # detected or user-specified

    # Runtime state
    available: bool
    load: float            # 0.0-1.0
    latency_ms: float      # network latency to coordinator
```

**Key Design Choice**:
- User ASSIGNS tier based on their judgment
- harombe doesn't dictate "this hardware = this tier"
- Flexible: RTX 4060 might be tier 1 for one user, tier 2 for another

### 2. Task Classification

```python
class TaskComplexity(Enum):
    SIMPLE = 0      # "What's 2+2?" → Mac Mini
    MEDIUM = 1      # "Summarize this paper" → Alienware
    COMPLEX = 2     # "Analyze 10 papers for patterns" → DGX
```

### 3. Routing Strategy

```python
async def route_query(query: str, context: ConversationContext) -> Node:
    """
    Decide which node should handle this query.

    Factors:
    - Query complexity (LLM classification or heuristics)
    - Context length (long context → bigger model)
    - Tool requirements (some tools only on certain nodes)
    - Node availability and load
    - User preferences (can force tier)
    """
    complexity = classify_task_complexity(query, context)

    if complexity == TaskComplexity.SIMPLE:
        return get_node(tier=0) or get_node(tier=1) or get_node(tier=2)
    elif complexity == TaskComplexity.MEDIUM:
        return get_node(tier=1) or get_node(tier=2) or get_node(tier=0)
    else:  # COMPLEX
        return get_node(tier=2) or get_node(tier=1) or get_node(tier=0)
```

### 4. Discovery Mechanism

**Option A: mDNS (Simple, local network)**
```yaml
# Auto-discover via mDNS
discovery:
  method: mdns
  service: _harombe._tcp.local
```

**Option B: Explicit Config (Flexible, works everywhere)**
```yaml
cluster:
  # Coordinator is any node that orchestrates
  coordinator:
    host: localhost  # or any always-on machine

  # Nodes: User defines their heterogeneous hardware
  nodes:
    # Example 1: User with Mac + Gaming PC + Server
    - name: my-macbook
      host: macbook.local
      tier: 0                    # Fast/local (user's choice)
      model: qwen2.5:3b

    - name: gaming-pc
      host: 192.168.1.100
      tier: 1                    # Medium (user's choice)
      model: qwen2.5:14b

    - name: server-closet
      host: server.home
      tier: 2                    # Powerful (user's choice)
      model: qwen2.5:72b

    # Example 2: All AMD GPUs
    - name: amd-workstation
      host: workstation.local
      tier: 1
      model: qwen2.5:14b

    # Example 3: Cloud fallback
    - name: vast-ai-instance
      host: 203.0.113.42
      tier: 2
      model: qwen2.5:72b
      auth: token-abc123        # optional auth

# Routing preferences
routing:
  prefer_local: true             # Try lowest latency first
  fallback_strategy: graceful    # tier2→tier1→tier0 if unavailable
  load_balance: true             # distribute across same-tier nodes
```

**Design Philosophy**:
- User knows their hardware best
- harombe provides the orchestration framework
- No assumptions about specific brands/models

### 5. Communication Protocol

**REST API extensions:**
```
POST /cluster/execute
{
    "query": "Analyze this paper...",
    "context": [...],
    "prefer_tier": 2,  // optional: force tier
    "timeout": 300
}

GET /cluster/status
{
    "nodes": [
        {"name": "macmini", "available": true, "load": 0.2},
        {"name": "alienware", "available": true, "load": 0.5},
        {"name": "dgx", "available": false}
    ]
}
```

## Phase 1 Implementation Plan

### New Modules (Layer 3: Coordination)

```
src/harombe/
├── coordination/              # NEW: Layer 3
│   ├── __init__.py
│   ├── cluster.py            # ClusterManager - orchestrates nodes
│   ├── discovery.py          # mDNS + explicit node discovery
│   ├── routing.py            # Task routing logic
│   ├── health.py             # Health checks & monitoring
│   └── balancer.py           # Load balancing across same-tier
├── llm/
│   ├── client.py             # Existing protocol
│   ├── ollama.py             # Existing local
│   └── remote.py             # NEW: Remote node client
├── config/
│   ├── schema.py             # EXTEND: Add cluster config
│   └── ...
```

### Phase 1.1: Foundation (Week 1)

**Goal**: Basic cluster config and node registration

- [ ] Extend config schema with cluster settings
  ```python
  class ClusterConfig:
      coordinator: str
      nodes: List[NodeConfig]
      routing: RoutingConfig
  ```

- [ ] Create `RemoteLLMClient` (Layer 2)
  - HTTP client to other harombe nodes
  - Same interface as `OllamaClient`
  - Transparent to agent layer

- [ ] Implement `ClusterManager` (Layer 3)
  - Node registry
  - Basic health checks (HTTP ping)
  - Manual tier selection

- [ ] CLI: `harombe cluster init`
  - Generate cluster config template
  - Detect current machine capabilities

**Test**: Two machines, explicit config, manual routing

### Phase 1.2: Discovery & Health (Week 2)

**Goal**: Auto-discovery and graceful degradation

- [ ] mDNS discovery (`discovery.py`)
  - Announce harombe nodes via mDNS
  - Discover peers on local network
  - Fallback to explicit config

- [ ] Health monitoring (`health.py`)
  - Periodic health checks
  - Latency measurement
  - Load reporting (active requests)

- [ ] Fallback chain
  - tier2 → tier1 → tier0 if unavailable
  - Retry logic
  - Circuit breaker pattern

**Test**: Three machines, one goes offline, verify fallback

### Phase 1.3: Smart Routing (Week 3)

**Goal**: Intelligent task → node mapping

- [ ] Task complexity classifier (`routing.py`)
  - Heuristics: query length, keywords
  - Context size consideration
  - Optional: Small LLM to classify

- [ ] Routing strategy
  ```python
  def select_node(query, context, user_pref) -> Node:
      complexity = classify(query, context)
      tier = map_complexity_to_tier(complexity, user_pref)
      nodes = get_available_nodes(tier)
      return load_balance(nodes)
  ```

- [ ] Load balancing (`balancer.py`)
  - Round-robin within tier
  - Weighted by current load
  - Latency-aware

**Test**: Run diverse queries, verify routing decisions

### Phase 1.4: Polish & UX (Week 4)

**Goal**: Production-ready cluster management

- [ ] CLI commands
  - `harombe cluster status` - show all nodes
  - `harombe cluster add <host>` - register node
  - `harombe cluster remove <name>` - deregister
  - `harombe cluster test` - health check all

- [ ] Chat improvements
  - Show which node is processing
  - Allow user override: `harombe chat --tier 2`
  - Fallback notification

- [ ] Monitoring
  - Request distribution stats
  - Node utilization
  - Error rates

- [ ] Documentation
  - Cluster setup guide
  - Network requirements
  - Troubleshooting

**Test**: Full workflow with heterogeneous hardware

## Your Specific Workflows

### Workflow 1: Quick Q&A
```
User: "What's the main finding in this abstract?"
→ Mac Mini (fast, local, simple)
→ Response in 2-3 seconds
```

### Workflow 2: Paper Analysis
```
User: "Analyze this 20-page paper, extract key methods"
→ Alienware (medium task, good balance)
→ Response in 30-60 seconds
```

### Workflow 3: Meta-Analysis
```
User: "Compare these 10 papers, find common patterns"
→ DGX Spark (complex, needs large context + reasoning)
→ Response in 2-5 minutes
```

### Workflow 4: Tool-Heavy Task
```
User: "Search for recent papers on X, analyze trends"
→ Mac Mini for web search (fast)
→ Alienware for analysis (balanced)
→ Coordinated multi-step workflow
```

## Success Metrics

1. **Performance**
   - 90% of simple queries stay on Mac Mini
   - <5s for simple, <60s for medium, <300s for complex
   - <10% routing mistakes (wrong tier)

2. **Reliability**
   - Graceful degradation when nodes offline
   - No lost queries due to routing failures
   - Auto-recovery when nodes come back

3. **User Experience**
   - Transparent routing (user doesn't need to think)
   - Option to force tier for power users
   - Clear feedback on which node is processing

## Questions to Answer

1. **What's your network setup?**
   - All machines on same LAN?
   - Any VLANs or complex routing?
   - Static IPs or DHCP?

2. **What's your Mac Mini spec?**
   - M2 or M3?
   - How much RAM?

3. **Alienware GPU?**
   - Which NVIDIA card?
   - VRAM amount?

4. **DGX Spark config?**
   - How many GPUs?
   - Already running Ollama from Baldwin?

5. **Primary use patterns?**
   - Mostly interactive chat?
   - Batch analysis jobs?
   - Mix of both?

## Technical Challenges

1. **Context Synchronization**
   - How to maintain conversation state across nodes?
   - Solution: Coordinator holds state, nodes are stateless

2. **Tool Execution Location**
   - Should tools run on coordinator or on inference node?
   - Solution: Tools on coordinator (file access, etc.)

3. **Partial Failures**
   - What if DGX dies mid-response?
   - Solution: Timeout + retry on lower tier

4. **Load Balancing**
   - Multiple users on same tier?
   - Solution: Track active requests, route to least loaded

## Next Steps

1. **Gather your hardware specs** (above questions)
2. **Design the config schema** for your cluster
3. **Build Phase 1.1** (foundation + basic routing)
4. **Test on your actual hardware** (Mac Mini + Alienware + DGX)
5. **Iterate based on real usage**

This is exciting - building for a REAL use case with REAL hardware!
