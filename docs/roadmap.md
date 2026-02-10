# Roadmap

## Phase 0: Weekend MVP (Complete)

- Single-machine AI assistant with tool calling
- ReAct agent loop
- Hardware auto-detection
- Interactive CLI and REST API

## Phase 1: Multi-Machine Orchestration (Complete)

- **Phase 1.1** (Complete): Cluster foundation
  - Cluster configuration schema
  - Remote LLM client
  - Health monitoring and node selection
  - CLI commands for cluster management

- **Phase 1.2** (Complete): Discovery & Health
  - mDNS auto-discovery for local networks
  - Periodic health monitoring
  - Circuit breaker pattern
  - Retry logic with exponential backoff

- **Phase 1.3** (Complete): Smart Routing
  - Task complexity classification
  - Context-aware routing decisions
  - Automatic tier selection
  - Integration with agent loop

- **Phase 1.4** (Complete): Polish & Monitoring
  - Dynamic node management (add/remove nodes at runtime)
  - Performance metrics collection and tracking
  - REST API metrics endpoint
  - CLI metrics command

## Phase 2: Memory & Context (Complete)

- **Phase 2.1** (Complete): Conversation Memory
  - SQLite-based conversation persistence
  - Session management and lifecycle
  - Token-based context windowing
  - Multi-turn conversations with history recall
  - Optional memory (backward compatible)

- **Phase 2.2** (Complete): Semantic Search & RAG
  - Vector embeddings with sentence-transformers (privacy-first, local)
  - ChromaDB vector store for similarity search
  - Semantic search across conversation history
  - RAG (Retrieval-Augmented Generation) for context-aware responses
  - Cross-session knowledge retrieval

## Phase 3: Voice & Multi-Modal (Complete)

- Whisper STT integration (speech-to-text)
- TTS integration (Piper fast, Coqui high-quality)
- Voice client (push-to-talk)
- Voice API endpoints (REST + WebSocket)
- Real-time audio processing
- Cross-platform audio I/O (macOS, Linux, Windows)

## Phase 4: Security Layer (Foundation Complete)

**Phase 4.1-4.4 (Complete):** Core security infrastructure

- **MCP Protocol Base** - JSON-RPC 2.0 protocol implementation
- **Docker Container Manager** - Container lifecycle management with resource limits
- **MCP Gateway Server** - Centralized gateway for tool execution routing
- **Audit Logging System** - SQLite-based comprehensive audit trail
  - Event tracking (requests, responses, errors)
  - Tool call logging with parameters and results
  - Security decision logging
  - Sensitive data redaction (API keys, passwords, tokens)
- **Secret Management** - Multi-backend credential vault
  - HashiCorp Vault integration (production)
  - SOPS file encryption (small teams)
  - Environment variables (development)
  - Secret scanning and detection
  - Automatic secret injection into containers
- **Network Isolation** - Per-container egress filtering
  - Docker network isolation
  - iptables-based egress rules
  - Domain allowlists
  - DNS query filtering
  - Connection attempt logging

**Phase 4.5 (Complete):** Human-in-the-Loop Gates

- Risk-based classification (LOW/MEDIUM/HIGH/CRITICAL)
- Centralized approval management with timeout handling
- CLI approval prompts with rich console formatting
- API approval support with web-compatible data structures
- Gateway integration with HITL checks before tool execution
- Audit integration for all approval decisions
- Default-deny safety on timeout

**Phase 4.6 (Complete):** Browser Container with Pre-Authentication

- Playwright-based browser automation with session isolation
- Pre-authentication flow with credentials injected from vault backend
- Accessibility-based interaction (semantic tree instead of raw HTML/DOM)
- Six browser tools: navigate, click, type, read, screenshot, close_session
- Password field protection (auto-deny typing into password/secret fields)
- HITL integration with 16 risk classification rules
- Session management with timeout and action-count expiration

**Phase 4.7-4.8 (Planned):**

- Code execution sandbox with gVisor
- End-to-end security integration and testing

## Phase 5: Intelligence & Privacy (Complete)

- ML-based anomaly detection with Isolation Forest (per-agent models)
- Threat scoring, threat intelligence integration
- Trust manager with historical risk scoring and auto-approval
- Secret rotation with zero-downtime and emergency rotation
- Certificate pinning, deep packet inspection, protocol filtering
- SIEM integration (Splunk, Elasticsearch, Datadog)
- Alert rules engine, compliance reports, security dashboard
- Privacy Router: hybrid local/cloud AI with PII detection
- Multi-model collaboration patterns

## Phase 6: Advanced Security (Experimental)

> **Note:** Phase 6 features are implemented but **experimental**. They have not been validated in production environments and may require additional hardening before enterprise deployment.

- Hardware security module integration — _Software simulation only; requires specific hardware (TPM/SGX/SEV-SNP) for production use_
- Enhanced isolation mechanisms — _Designed but not validated at scale_
- Zero-knowledge proof support — Integrated with audit pipeline for privacy-preserving compliance proofs
- Distributed cryptography primitives — _Shamir secret sharing and MPC implemented; requires security audit_

## Documentation

- [Security Quick Start](security-quickstart.md)
- [Audit Logging](audit-logging.md)
- [Secret Management](security-credentials.md)
- [Network Isolation](security-network.md)
- [MCP Gateway Design](mcp-gateway-design.md)
- [HITL Gates Design](hitl-design.md)
- [Browser Container Usage](browser-usage.md)
- [Browser Container Design](browser-container-design.md)
