# Vector Store Architecture (Phase 2.2)

## Overview

The vector store system adds semantic search capabilities to harombe's conversation memory. This enables:

- **Semantic memory retrieval** - Find relevant past conversations by meaning, not just keywords
- **RAG (Retrieval-Augmented Generation)** - Inject relevant context from memory into agent prompts
- **Long-term knowledge** - Build up searchable knowledge across many conversations
- **Topic-based organization** - Group and retrieve conversations by semantic similarity

## Design Decisions

### 1. Embedding Model

**Choice: sentence-transformers (local) + optional Ollama/OpenAI**

**Rationale:**

- **Local-first philosophy**: Aligns with harombe's privacy-first approach
- **No API keys**: sentence-transformers runs entirely offline
- **Good performance**: Models like `all-MiniLM-L6-v2` (384-dim) balance quality and speed
- **Flexibility**: Support Ollama embeddings (nomic-embed-text) or OpenAI as alternatives

**Implementation:**

```python
# Abstract interface
class EmbeddingClient(Protocol):
    async def embed(self, texts: list[str]) -> list[list[float]]:
        """Generate embeddings for texts."""
        ...

# Implementations
- SentenceTransformerEmbedding (default, local)
- OllamaEmbedding (via Ollama API)
- OpenAIEmbedding (cloud fallback)
```

**Model selection:**

- Default: `all-MiniLM-L6-v2` (384 dimensions, 80MB, fast)
- Better quality: `all-mpnet-base-v2` (768 dimensions, 420MB)
- Multilingual: `paraphrase-multilingual-MiniLM-L12-v2`

### 2. Vector Store Backend

**Choice: ChromaDB**

**Rationale:**

- **Lightweight**: Embedded database, no server required (SQLite-backed)
- **Simple API**: Pythonic, minimal boilerplate
- **Metadata filtering**: Rich filtering alongside vector search
- **Active development**: Well-maintained, growing ecosystem
- **Good performance**: HNSW index, fast approximate search

**Alternatives considered:**

- FAISS: More performant but requires more setup, no metadata filtering
- pgvector: Requires PostgreSQL, overkill for local use
- Qdrant: Server-based, adds complexity
- Weaviate: Too heavyweight for embedded use case

**ChromaDB features we'll use:**

- Collections: Separate collection per session or global collection
- Metadata: Store session_id, timestamp, role, message_id
- Distance metrics: Cosine similarity (default for sentence embeddings)
- Persistence: Disk-backed for durability

### 3. Schema Design

**Embedding storage:**

```python
# ChromaDB document structure
{
    "id": "msg_<message_id>",           # Unique message ID
    "embedding": [0.1, 0.2, ...],       # 384-dim vector
    "document": "message content",       # Original text
    "metadata": {
        "session_id": "session-uuid",
        "message_id": 123,
        "role": "user" | "assistant",
        "timestamp": "2025-02-08T20:00:00",
        "tool_calls": [...],             # Optional
    }
}
```

**Collection strategy:**

Option A: **Single global collection** (chosen)

- Pros: Simple, enables cross-session search, easier to manage
- Cons: May grow large over time
- Mitigation: Metadata filtering by session_id

Option B: One collection per session

- Pros: Isolated, easier to delete
- Cons: Can't search across sessions, management overhead

### 4. Retrieval Strategies

**Similarity search:**

```python
# Basic semantic search
results = memory.search_similar(
    query="How do I configure memory?",
    top_k=5,
    session_id=None,  # Search across all sessions
)
```

**Hybrid search (semantic + keyword):**

```python
# Combine vector similarity with metadata filters
results = memory.search_hybrid(
    query="Python debugging tips",
    top_k=10,
    filters={"role": "assistant", "session_id": "abc123"},
    min_similarity=0.7,
)
```

**Temporal weighting:**

- Recent messages get boosted in ranking
- Configurable decay factor
- Prevents old irrelevant matches from dominating

**Re-ranking strategies:**

- MMR (Maximal Marginal Relevance): Diversify results
- Cross-encoder re-ranking: Optional second-stage scoring
- BM25 + vector fusion: Hybrid retrieval

### 5. Integration with Memory System

**Architecture:**

```
┌─────────────────────────────────────────┐
│         MemoryManager (existing)        │
│  ┌────────────────────────────────────┐ │
│  │  SQLite Storage (messages)         │ │
│  │  - Message content                 │ │
│  │  - Session metadata                │ │
│  │  - Tool calls                      │ │
│  └────────────────────────────────────┘ │
│                  │                      │
│                  │                      │
│  ┌────────────────────────────────────┐ │
│  │  VectorStore (new)                 │ │
│  │  - ChromaDB collection             │ │
│  │  - Embeddings                      │ │
│  │  - Semantic search                 │ │
│  └────────────────────────────────────┘ │
│                  │                      │
│                  │                      │
│  ┌────────────────────────────────────┐ │
│  │  EmbeddingService                  │ │
│  │  - sentence-transformers           │ │
│  │  - Batch processing                │ │
│  │  - Caching                         │ │
│  └────────────────────────────────────┘ │
└─────────────────────────────────────────┘
```

**Automatic embedding:**

- On `save_message()`: Automatically embed and store in vector DB
- Async background processing: Don't block message saves
- Batch embedding for efficiency

**Unified interface:**

```python
# MemoryManager gains new methods
memory.search_similar(query: str, top_k: int) -> list[Message]
memory.search_by_topic(topic: str, session_id: str) -> list[Message]
memory.get_relevant_context(query: str, max_tokens: int) -> list[Message]
```

### 6. RAG Integration

**Context injection strategy:**

1. **User query arrives** → Agent.run(query)
2. **Semantic search** → Find top-K similar past messages
3. **Context assembly** → Format retrieved messages
4. **Prompt injection** → Add to system prompt or user message
5. **LLM generation** → Agent proceeds with enriched context

**RAG prompt template:**

```
You are a helpful assistant with access to relevant conversation history.

RELEVANT CONTEXT FROM PAST CONVERSATIONS:
---
[User, 2024-02-01]: How do I configure memory?
[Assistant, 2024-02-01]: Memory is configured in harombe.yaml under the `memory` section...
---

Now answer the current user question, using the context above if relevant.

User: {current_query}
```

**Configuration:**

```yaml
memory:
  enabled: true
  storage_path: ~/.harombe/memory.db
  max_history_tokens: 4096

  # Vector store (Phase 2.2)
  vector_store:
    enabled: true
    backend: chromadb
    collection_name: harombe_conversations
    embedding_model: sentence-transformers/all-MiniLM-L6-v2

  # RAG settings
  rag:
    enabled: false # Opt-in for now
    top_k: 5
    min_similarity: 0.7
    include_context_in_prompt: true
    temporal_decay: 0.95 # Boost recent messages
```

### 7. Performance Considerations

**Embedding generation:**

- Batch size: 32 messages at once
- Cache embeddings: Don't re-embed identical text
- Async processing: Use asyncio for I/O-bound operations
- Model loading: Load once, keep in memory

**Vector search:**

- ChromaDB uses HNSW: O(log N) approximate search
- Index tuning: Adjust `hnsw:space`, `hnsw:M`, `hnsw:ef`
- Limit results: Default top_k=10, max=100

**Storage:**

- Embeddings: 384 dims \* 4 bytes = 1.5KB per message
- 10K messages = ~15MB embeddings + metadata
- ChromaDB uses DuckDB for metadata, SQLite for storage

**Scalability:**

- Up to 100K messages: Embedded ChromaDB fine
- Beyond 100K: Consider client-server ChromaDB
- Cleanup: Prune old embeddings same as messages

## Implementation Plan

### Phase 2.2 Tasks

1. **Embedding Service** (Task 11)
   - `src/harombe/embeddings/client.py` - Protocol
   - `src/harombe/embeddings/sentence_transformer.py` - Default impl
   - `src/harombe/embeddings/ollama.py` - Ollama embeddings
   - `tests/embeddings/` - Unit tests

2. **Vector Store** (Task 12)
   - `src/harombe/vector/store.py` - Protocol
   - `src/harombe/vector/chromadb.py` - ChromaDB impl
   - `tests/vector/` - Unit tests

3. **Memory Integration** (Task 13)
   - Update `MemoryManager` with vector methods
   - Auto-embed on save
   - Semantic search methods
   - Tests

4. **RAG Integration** (Task 14)
   - Extend Agent for RAG
   - Context injection logic
   - RAG configuration
   - Example

5. **Config & Docs** (Task 15)
   - Update config schema
   - README documentation
   - Example script
   - CLI commands

## Testing Strategy

**Unit tests:**

- Embedding generation (mocked models)
- Vector store operations (in-memory ChromaDB)
- Similarity search correctness

**Integration tests:**

- End-to-end: Save message → Embed → Search → Retrieve
- RAG flow: Query → Retrieve context → Generate response
- Multi-session search

**Performance tests:**

- Embedding speed: 100 messages/second target
- Search latency: <100ms for top-10 retrieval
- Memory usage: <500MB for 10K messages

## Migration Path

**Backward compatibility:**

- Vector store is optional (enabled: false by default)
- Existing memory system works unchanged
- Incremental adoption: Enable vector store on existing DBs

**Migration:**

```python
# Backfill embeddings for existing messages
memory = MemoryManager(...)
memory.backfill_embeddings(batch_size=100)
```

## Security & Privacy

**Data locality:**

- All embeddings generated locally (sentence-transformers)
- ChromaDB runs embedded, no external calls
- Optional: Use Ollama for embeddings (still local)

**Sensitive data:**

- Embeddings leak semantic information about content
- Store embeddings with same access controls as messages
- Future: Privacy-preserving embeddings (differential privacy)

## Future Enhancements

**Phase 2.3+:**

- Cross-encoder re-ranking for better precision
- Hybrid BM25 + vector search
- Semantic clustering (topic modeling)
- Knowledge graph integration
- Multi-modal embeddings (images, code)
- Federated search across multiple harombe instances

---

## References

- [sentence-transformers documentation](https://www.sbert.net/)
- [ChromaDB documentation](https://docs.trychroma.com/)
- [RAG best practices](https://www.pinecone.io/learn/retrieval-augmented-generation/)
