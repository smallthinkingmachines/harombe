"""Harombe - Self-hosted agent framework for distributed AI workloads.

Harombe provides autonomous AI agents with distributed orchestration,
defense-in-depth security, and privacy-preserving inference routing.
It runs on your hardware with zero cloud dependencies.

Key modules:

- :mod:`harombe.agent` - ReAct agent loop for autonomous task execution
- :mod:`harombe.memory` - Conversation persistence and semantic search (RAG)
- :mod:`harombe.security` - MCP Gateway, audit logging, credential vault, network isolation, HITL
- :mod:`harombe.privacy` - Privacy router for hybrid local/cloud AI
- :mod:`harombe.tools` - Built-in tools (shell, filesystem, web search, browser)
- :mod:`harombe.voice` - Speech-to-text (Whisper) and text-to-speech (Piper, Coqui)
- :mod:`harombe.llm` - LLM client abstraction (Ollama, Anthropic, remote nodes)
- :mod:`harombe.coordination` - Cluster management, smart routing, health monitoring
"""

__version__ = "0.3.1"
