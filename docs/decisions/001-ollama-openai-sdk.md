# ADR-001: Use OpenAI SDK Instead of Ollama's Python Package

**Status**: Accepted
**Date**: 2025-06

## Context

Harombe needs a client library for communicating with Ollama's local inference server. Two options exist:

1. **Ollama's Python package** (`ollama-python`) — a dedicated client for the Ollama API.
2. **OpenAI SDK** (`openai`) — the standard OpenAI client library. Ollama exposes an OpenAI-compatible `/v1` endpoint, making it usable with this SDK.

The choice affects how tightly coupled harombe is to a single inference backend and how easily other backends can be added in the future.

## Decision

Use the OpenAI SDK to communicate with Ollama via its OpenAI-compatible `/v1` endpoint.

## Consequences

**Positive:**

- Works with any OpenAI-compatible endpoint (vLLM, llama.cpp, cloud providers), not just Ollama.
- Provides a consistent tool calling interface across all backends.
- Makes it straightforward to add other backends without changing the client layer.
- The OpenAI SDK is widely used and well-maintained, with strong community support.

**Negative:**

- Does not expose some Ollama-specific features such as model management (`ollama pull`, `ollama list`).
- Requires Ollama to be configured with its OpenAI-compatible endpoint enabled (this is the default).
