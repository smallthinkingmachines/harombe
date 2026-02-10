# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
