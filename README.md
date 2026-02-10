# harombe

**The full-stack agent framework that runs entirely on your hardware.**

> Manages the complete agent lifecycle — tool execution in containers, network-level security, voice I/O, persistent memory with semantic search, and multi-node cluster routing. `pip install harombe`. No cloud required.

[![CI](https://github.com/smallthinkingmachines/harombe/actions/workflows/ci.yml/badge.svg)](https://github.com/smallthinkingmachines/harombe/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)

## Quick Start

```bash
pip install harombe
harombe init          # detects hardware, writes config
ollama pull qwen2.5:7b
harombe chat          # autonomous agent with tools
```

Or use it as a library:

```python
import asyncio
from harombe.agent.loop import Agent
from harombe.llm.ollama import OllamaClient
from harombe.tools.registry import get_enabled_tools

async def main():
    llm = OllamaClient(model="qwen2.5:7b")
    tools = get_enabled_tools(shell=True, filesystem=True, web_search=True)
    agent = Agent(llm=llm, tools=tools, system_prompt="You are a helpful assistant.")
    response = await agent.run("Find all Python files in src/ and count them.")
    print(response)

asyncio.run(main())
```

See [`examples/`](examples/) for more.

## What is harombe?

Harombe manages the full stack for AI agents — hardware detection, tool execution (in containers), security (network-level), I/O (voice + CLI + API), memory (SQLite + vector search), and networking (multi-node clusters with service discovery). Think of it as an operating system for AI agents — as a `pip install`.

### Security

Harombe's security is infrastructure-level, not bolt-on:

- Every tool runs in its own Docker container with resource limits
- Per-container network egress filtering (iptables, DNS allowlists)
- Audit logging with automatic credential redaction
- Human-in-the-loop approval gates with risk classification
- Secret management via Vault/SOPS
- ZKP-based audit proofs (experimental)

### What harombe manages

| Responsibility    | What it does                                                                         |
| ----------------- | ------------------------------------------------------------------------------------ |
| **Execution**     | ReAct agent loop, tool calling (shell, filesystem, web search, browser, code exec)   |
| **Voice I/O**     | Whisper STT + Piper TTS, push-to-talk, VAD, WebSocket streaming                      |
| **Memory**        | SQLite conversations, ChromaDB vectors, cross-session semantic search                |
| **Security**      | Container isolation, network filtering, audit logging, HITL gates, anomaly detection |
| **Networking**    | Multi-node clusters, mDNS discovery, complexity-based routing, circuit breakers      |
| **Privacy**       | PII detection, data sanitization, local/hybrid/cloud routing modes                   |
| **Extensibility** | MCP server + client, container-isolated plugins with auto-generated MCP scaffolds    |

## Architecture

```
┌─────────────────────────────────────┐
│  Layer 6: Clients                   │  Voice, iOS, Web, CLI
├─────────────────────────────────────┤
│  Layer 5: Privacy Router            │  Hybrid local/cloud AI
│  PII detection, context sanitizer   │  local-only / hybrid / cloud
├─────────────────────────────────────┤
│  Layer 4: Agent & Memory            │  ReAct loop, tools, memory
├─────────────────────────────────────┤
│  Layer 3: Security                  │  Defense-in-depth
│  MCP Gateway, container isolation   │  Credential vault, audit log
│  Per-tool egress, secret scanning   │  HITL gates, browser pre-auth
├─────────────────────────────────────┤
│  Layer 2: Orchestration             │  Smart routing, health monitoring
│  Cluster config, mDNS discovery     │  Circuit breakers, metrics
├─────────────────────────────────────┤
│  Layer 1: Runtimes                  │  llama.cpp, Whisper, TTS, embeddings
└─────────────────────────────────────┘
```

Each layer only talks to its neighbors. Security (Layer 3) wraps every tool invocation — there is no path from the agent to a tool that bypasses the gateway. See [ARCHITECTURE.md](ARCHITECTURE.md) for full design documentation.

## Security Deep Dive

Harombe enforces the **Capability-Container Pattern**: agents never execute tools directly. Every tool call goes through the MCP Gateway, which routes it to an isolated Docker container.

```
Agent  ──→  MCP Gateway  ──→  [ Container: shell ]
                          ──→  [ Container: browser ]
                          ──→  [ Container: web_search ]
```

**Container Isolation** — Each tool runs in its own Docker container with CPU/memory limits, read-only filesystem mounts, and no host network access.

**Network Egress** — Per-container iptables rules and DNS allowlists. A web_search container can reach DuckDuckGo; a filesystem container can reach nothing.

**Audit Logging** — Every tool call, approval decision, and security event is logged to SQLite with automatic redaction of API keys, passwords, and tokens.

**HITL Gates** — Operations are risk-classified (LOW/MEDIUM/HIGH/CRITICAL). High-risk operations require explicit human approval with default-deny on timeout.

**Anomaly Detection** — Per-agent Isolation Forest models learn baseline behavior and flag deviations. Integrated with SIEM (Splunk, Elasticsearch, Datadog).

See [docs/security-quickstart.md](docs/security-quickstart.md) for setup instructions.

## Features

### Agent Core

ReAct agent loop with autonomous planning, tool calling, and multi-step execution. Tools: shell, read/write files, web search, browser automation. Configurable step limits and confirmation gates.

### Voice

Whisper STT (tiny to large-v3) + Piper TTS. Push-to-talk CLI (`harombe voice`), REST + WebSocket API, voice activity detection. Cross-platform audio I/O.

### Memory & RAG

SQLite conversation persistence with token-based context windowing. ChromaDB vector store with sentence-transformers embeddings (local, no API calls). Semantic search across sessions. RAG-enabled agents auto-inject relevant context.

### Distributed Clusters

Define nodes in YAML, route queries by complexity. mDNS auto-discovery, health monitoring, circuit breakers, load balancing. Works with any hardware mix: Apple Silicon, NVIDIA, AMD, CPU.

### MCP Protocol

JSON-RPC 2.0 MCP server and client. Gateway-mediated tool execution with per-tool container isolation. Compatible with the broader MCP ecosystem.

### Plugins

Container-isolated plugins with auto-generated MCP scaffolds. ZKP audit proofs, compliance reporting, and container-based extensions ship as built-in plugins. See [`src/harombe/plugins/`](src/harombe/plugins/) for examples.

### Privacy

PII detection and data sanitization. Three routing modes: local-only (nothing leaves your machine), hybrid (sensitive data stays local, general queries can use cloud), and cloud. Configurable per-agent.

## Examples

| #   | Example                                                        | Description                                |
| --- | -------------------------------------------------------------- | ------------------------------------------ |
| 01  | [`simple_agent.py`](examples/01_simple_agent.py)               | Basic single-node agent with all tools     |
| 02  | [`api_usage.py`](examples/02_api_usage.py)                     | Programmatic agent creation and tool usage |
| 03  | [`data_pipeline.py`](examples/03_data_pipeline.py)             | Data processing with autonomous agents     |
| 04  | [`code_review.py`](examples/04_code_review.py)                 | Automated code review workflows            |
| 05  | [`research_agent.py`](examples/05_research_agent.py)           | Research automation with web search        |
| 06  | [`memory_conversation.py`](examples/06_memory_conversation.py) | Persistent conversation history            |
| 07  | [`cluster_routing.py`](examples/07_cluster_routing.py)         | Task-based routing across nodes            |
| 08  | [`semantic_memory.py`](examples/08_semantic_memory.py)         | Semantic search and RAG                    |
| 09  | [`voice_assistant.py`](examples/09_voice_assistant.py)         | Voice-enabled assistant (STT + TTS)        |

## Configuration

Configuration lives at `~/.harombe/harombe.yaml`. Minimal example:

```yaml
model:
  name: qwen2.5:7b
  temperature: 0.7

tools:
  shell: true
  filesystem: true
  web_search: true
  confirm_dangerous: true

memory:
  enabled: true
  storage_path: ~/.harombe/memory.db
```

All fields have sensible defaults — you can run with no config at all. See [`harombe.yaml.example`](harombe.yaml.example) for the full reference.

## Status

| Production                        | Experimental              | Planned            |
| --------------------------------- | ------------------------- | ------------------ |
| ReAct agent loop                  | Hardware security modules | iOS/Web clients    |
| Tool execution (shell, fs, web)   | Distributed cryptography  | Multi-modal vision |
| Container isolation + egress      |                           |                    |
| Code execution sandbox            |                           |                    |
| ZKP audit proofs                  |                           |                    |
| Audit logging + secret management |                           |                    |
| HITL approval gates               |                           |                    |
| Conversation memory + RAG         |                           |                    |
| Voice (STT + TTS)                 |                           |                    |
| Multi-node clusters               |                           |                    |
| MCP server + client               |                           |                    |
| Privacy router + PII detection    |                           |                    |
| Anomaly detection + SIEM          |                           |                    |

2400+ tests. Python 3.11-3.13. CI on Ubuntu + macOS. See [docs/roadmap.md](docs/roadmap.md) for full phase history.

## Development

```bash
git clone https://github.com/smallthinkingmachines/harombe.git
cd harombe && pip install -e ".[dev]"
pytest
```

See [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) for detailed setup and [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) for contribution guidelines.

## License

Apache 2.0 — see [LICENSE](LICENSE).
