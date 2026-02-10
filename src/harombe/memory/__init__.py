"""Conversation memory system for harombe.

Provides SQLite-backed conversation persistence with session management,
token-based context windowing, and optional semantic search via vector
embeddings. When combined with ChromaDB and sentence-transformers, enables
Retrieval-Augmented Generation (RAG) for context-aware agent responses.

Components:

- :class:`MemoryManager` - High-level API for session and message management
- :class:`MemoryStorage` - SQLite storage backend with WAL mode
"""

from harombe.memory.manager import MemoryManager
from harombe.memory.storage import MemoryStorage

__all__ = ["MemoryManager", "MemoryStorage"]
