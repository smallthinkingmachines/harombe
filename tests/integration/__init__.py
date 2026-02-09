"""Integration tests for Harombe.

Integration tests verify interactions between multiple components.
These tests may require external dependencies (Docker, Ollama, etc.)
and are typically slower than unit tests.

Test categories:
- Phase 4 Integration: MCP Gateway + Docker containers
- Cluster Integration: Multi-node coordination (Phase 1)
- Memory Integration: RAG + Vector store (Phase 2)
- Voice Integration: STT + TTS pipeline (Phase 3)

Run integration tests with markers:
    pytest -m docker_integration  # Requires Docker daemon
    pytest -m cluster_integration # Requires multiple nodes
    pytest tests/integration/     # All integration tests
"""
