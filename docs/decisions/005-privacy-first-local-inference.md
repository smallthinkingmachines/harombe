# ADR-005: Default to Local-First Inference

**Status**: Accepted
**Date**: 2025-06

## Context

Users may run workloads that involve sensitive data, including proprietary code, internal documents, and personally identifiable information (PII). Cloud LLM APIs send data to third-party servers, creating potential data exposure risks. At the same time, some tasks benefit from larger cloud models that are not feasible to run locally.

Harombe needed a default inference strategy that protects user data while still allowing access to more capable models when appropriate.

## Decision

Default to Ollama for local inference, with optional cloud escalation via the Privacy Router. The Privacy Router detects PII and sensitive content, redacting it before forwarding queries to cloud providers when escalation is explicitly requested or configured.

## Consequences

**Positive:**

- No data leaves the user's infrastructure by default.
- Works fully offline with no internet connection required.
- Zero API costs for local inference.
- Users retain complete control over their data.
- Privacy Router provides a safety net when cloud escalation is used.

**Negative:**

- Requires local GPU or CPU resources, which may be limited on some machines.
- Local models are smaller and less capable than the largest cloud alternatives.
- Initial model download requires internet access and significant disk space.
- Inference speed depends on local hardware (can be slow without a GPU).
