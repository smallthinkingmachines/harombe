# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2026-02-10

### Added

**Multi-Backend Inference Distribution**

- `OpenAICompatibleClient` base class for all OpenAI-compatible inference servers
- `VLLMClient`: vLLM inference server support (NVIDIA GPU, PagedAttention)
- `SGLangClient`: SGLang inference server support (NVIDIA GPU, RadixAttention)
- `LlamaCppClient`: llama.cpp server support (CPU/GPU, GGUF models)
- `create_llm_client()` factory function for config-driven backend selection
- `InferenceConfig` with per-backend config models (`VLLMConfig`, `SGLangConfig`, `LlamaCppConfig`)
- `backend` field on `NodeConfig` for per-node backend specification in clusters

### Changed

- `OllamaClient` now extends `OpenAICompatibleClient` (backward-compatible)
- `PrivacyRouter` uses `create_llm_client()` factory instead of hardcoded `OllamaClient`
- Server routes use `create_llm_client()` factory for backend-agnostic initialization
- `HarombeConfig` now includes `inference` field (defaults to Ollama for backward compatibility)

## [0.2.0] - 2026-02-10

### Added

**Security Hardening**

- Rotation audit logging: `SecretRotationManager._log_rotation()` now writes to `AuditLogger`
- Container restart after secret rotation: `SecretRotationScheduler` notifies container manager
- Policy-based automatic rotation: `check_and_rotate()` compares elapsed time against policy interval
- `set_container_manager()` method on `SecretRotationScheduler` for post-rotation container restarts

**ZKP Audit Proofs (Promoted to Production)**

- Integrated ZKP audit proofs into `AuditDatabase` with `audit_proofs` table and indexes
- Added `AuditProofRecord` model for persistent proof storage
- Added `log_audit_proof()` and `get_audit_proofs()` methods to `AuditDatabase`
- Added `enable_zkp` parameter to `AuditLogger` with `generate_proof()`, `generate_proof_sync()`, and `verify_proof()` methods
- Exported all ZKP symbols from `security.zkp` and `security` packages
- ZKP primitives (Schnorr proofs, Pedersen commitments, range proofs), audit proofs, and authorization are now production-ready

**Compliance Reporting (Expanded)**

- Fixed time-range filtering bug: compliance reports now correctly filter events and security decisions to the reporting period
- Added `get_events_by_time_range()` to `AuditDatabase` for time-scoped event queries
- Added `start_time`/`end_time` parameters to `get_security_decisions()` (backward-compatible)
- Expanded from 13 to 24 compliance controls: PCI DSS (8), GDPR (8), SOC 2 (8)
- New PCI DSS controls: encryption at rest (3.5), key management (3.6), incident response (12.10), network monitoring (11.4)
- New GDPR controls: data retention (5.1e), consent tracking (7.1), breach notification (33.1), data portability (20.1)
- New SOC 2 controls: availability monitoring (A1.2), data classification (CC6.5), incident response (CC7.4)

**Container-Isolated Plugins**

- `PluginContainerManager`: Build, start, stop, and health-check containerized plugins
- Docker-based plugin isolation with auto-generated Dockerfiles and FastAPI MCP scaffold
- Per-plugin network policies from `PluginPermissions.network_domains`
- Dynamic gateway route registration via `register_tool_route()` / `register_plugin_routes()`
- New manifest fields: `container_enabled`, `base_image`, `extra_pip_packages`, `resource_limits`
- `create_container_config_from_permissions()` bridges plugin permissions to container configs
- Loader integration: plugins with `container_enabled=True` start in containers instead of in-process

**MCP Server & Client**

- MCP Server: Expose harombe tools to external MCP clients (Claude Desktop, etc.) via stdio or HTTP transport
- MCP Client: Connect to external MCP servers (GitHub, filesystem, Slack, etc.) to expand tool ecosystem
- MCPManager: Orchestrate multiple external MCP server connections with unified tool discovery
- Schema converters between Harombe ToolSchema and MCP input schema formats
- CLI command: `harombe mcp serve [--transport stdio|http] [--port 8200]`
- MCPConfig in harombe.yaml with server and external_servers configuration
- Agent loop integration: MCP tools automatically merged into agent's tool set

**Multi-Agent Delegation**

- AgentRegistry: Named agent blueprints with configurable tools, system prompts, and models
- DelegationContext: Tracks delegation chain, enforces max depth, detects cycles
- Delegation tool: LLM-invocable tool for delegating tasks to specialized agents
- Agent builder: Create registry and root agent from YAML configuration
- Recursive delegation: Child agents can further delegate if depth allows
- Config: `delegation` section with `enabled` and `max_depth`, `agents` list with named agent configs

**Plugin System v1**

- PluginLoader: Discovers plugins from Python entry points (pip install) and local directory (~/.harombe/plugins/)
- PluginManifest: Metadata (name, version, description, permissions) for plugin introspection
- Permission model: Declarative permissions (dangerous flag, network domains, filesystem, shell)
- CLI commands: `harombe plugin list/info/enable/disable`
- PluginsConfig in harombe.yaml with per-plugin overrides and blocked list
- Broken plugins warn but don't crash startup
- Tool source tracking: `source` field on ToolSchema for provenance

**Channel Integrations**

- ChannelAdapter protocol: Receive message → agent.run() → send response
- SlackAdapter: Slack Bot using Bolt SDK with Socket Mode (mentions + DMs)
- DiscordAdapter: Discord Bot using discord.py (mentions + DMs, 2000 char chunking)
- WebChatAdapter: WebSocket-based web chat with JSON message protocol

**Cluster Validation**

- Multi-node integration tests using respx to simulate 2-3 nodes
- End-to-end routing tests: query → complexity classification → node selection
- Cluster setup guide (docs/guides/cluster-setup.md)

**Voice Pipeline Improvements**

- Voice Activity Detection (VAD): Energy-based speech boundary detection for hands-free operation
- Improved Whisper streaming: VAD-based utterance segmentation with 2s fallback (replaces 3s fixed buffer)
- Improved Piper TTS streaming: Sentence-level chunked synthesis for lower time-to-first-audio
- VoiceActivityDetector with configurable energy threshold, silence duration, and minimum speech duration

**Tool Registry**

- `get_enabled_tools_v2()`: Plugin-aware tool filtering with per-plugin enable/disable overrides
- `_TOOL_SOURCES` tracking for tool provenance (builtin vs plugin name)

**CLI Chat Integration**

- Plugin loading on startup with permission enforcement
- Delegation tool auto-wired when `delegation.enabled` and agents configured
- MCP external servers connected on startup
- `/tools` command now shows all tools (builtin + plugin) with source tags and danger indicators

**Reference Architectures**

- Secure Code Analysis: 3-agent delegation setup for automated code review
- Private Research Assistant: Single Apple Silicon Mac with local-only privacy
- Multi-Node Cluster: 2-3 node setup with privacy routing and complexity-based distribution

### Changed

**Documentation Clarification**

- Marked Phase 6 features (ZKP, hardware security, compliance reporting) as experimental in README.md
- Added Feature Status table to ARCHITECTURE.md clarifying production-ready vs experimental vs partial features
- Updated docs/security-quickstart.md to distinguish production-ready from experimental security features
- MCP status clarified as "partial (protocol models only)" pending server/client implementation
- Cluster routing clarified as "untested at scale" pending multi-node integration tests

## [0.1.1] - 2026-02-10

### Added

- PyPI publish workflow with OIDC trusted publishing (`.github/workflows/publish.yml`)
- Dynamic version single-sourcing via `importlib.metadata`
- Configurable CORS origins in `ServerConfig.cors_origins`
- TLS support via `ServerConfig.ssl_certfile` / `ssl_keyfile`, passed through to uvicorn
- Root `Dockerfile` with multi-stage build (builder + slim runtime)

### Changed

- Pinned upper bounds on all core dependencies to prevent breaking major-version upgrades
- CORS middleware now reads from config instead of hardcoded `["*"]`

## [0.1.0] - 2026-02-10

### Added

**Agent Framework**

- ReAct agent loop with autonomous multi-step task execution
- Extensible tool system (shell, filesystem, web search, browser)
- Hardware auto-detection and model recommendation
- Interactive CLI (`harombe chat`) and REST API (`harombe start`)

**Distributed Orchestration (Phase 1)**

- YAML-based cluster configuration across heterogeneous hardware
- Smart routing based on task complexity (tier-based)
- Health monitoring with circuit breakers and mDNS discovery
- Performance metrics collection and observability

**Memory & RAG (Phase 2)**

- SQLite-based conversation persistence with session management
- Token-based context windowing for long conversations
- Vector embeddings with sentence-transformers (local, privacy-first)
- ChromaDB vector store for semantic search
- RAG for context-aware agent responses

**Voice Interface (Phase 3)**

- Speech-to-text with Whisper (tiny to large-v3 models)
- Text-to-speech with Piper (fast) and Coqui (high-quality)
- Push-to-talk voice interface and voice API endpoints
- Real-time audio processing with cross-platform support

**Security Layer (Phase 4)**

- MCP Gateway with containerized tool isolation
- Audit logging with SQLite (WAL mode, <1ms writes, sensitive data redaction)
- Secret management (HashiCorp Vault, SOPS, environment variables)
- Per-container network egress filtering with domain allowlists
- Human-in-the-Loop approval gates with risk classification
- Browser container with pre-authentication and accessibility-based interaction
- Code execution sandbox design with gVisor

**Intelligence & Monitoring (Phase 5)**

- ML-based anomaly detection with Isolation Forest (per-agent models)
- Threat scoring and threat intelligence integration
- Trust manager with historical risk scoring and auto-approval
- Secret rotation with zero-downtime and emergency rotation
- Certificate pinning, deep packet inspection, protocol filtering
- SIEM integration (Splunk, Elasticsearch, Datadog)
- Alert rules engine and compliance report generation
- Security dashboard with metrics caching

**Privacy Router (Phase 5)**

- Hybrid local/cloud AI with configurable privacy boundary
- PII detection and redaction before cloud calls
- Context sanitization with sensitivity classification
- Three routing modes: local-only, hybrid, cloud-assisted

**Advanced Security (Phase 6)**

- Hardware security module integration
- Enhanced isolation mechanisms
- Zero-knowledge proof support
- Distributed cryptography primitives

**Multi-Model Collaboration**

- Hybrid local/cloud AI collaboration patterns
- Model routing based on task requirements
