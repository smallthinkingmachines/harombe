# Conversation Memory System Design

## Table of Contents

- [Overview](#overview)
- [Goals](#goals)
- [Architecture](#architecture)
- [Memory Strategies](#memory-strategies)
- [Integration Points](#integration-points)
- [Implementation Plan](#implementation-plan)
- [Phase 2.2: Semantic Search & RAG](#phase-22-semantic-search--rag)

## Overview

The conversation memory system enables harombe agents to maintain context across sessions, remember past interactions, and provide continuity in multi-turn conversations.

## Goals

1. **Persistence** - Conversations survive application restarts
2. **Efficiency** - Fast retrieval without loading entire history
3. **Scalability** - Handle long conversations with token limits
4. **Simplicity** - SQLite backend, no external dependencies
5. **Extensibility** - Easy to swap backends (PostgreSQL, Redis) later

## Architecture

### Components

```
┌─────────────────────────────────────────────────┐
│                    Agent                        │
│  ┌─────────────────────────────────────────┐   │
│  │         Memory Manager                   │   │
│  │  - Session management                    │   │
│  │  - Message filtering                     │   │
│  │  - Context windowing                     │   │
│  │  - Summarization                         │   │
│  └──────────────┬──────────────────────────┘   │
│                 │                               │
│  ┌──────────────▼──────────────────────────┐   │
│  │         Storage Backend                  │   │
│  │  - SQLite database                       │   │
│  │  - CRUD operations                       │   │
│  │  - Indexing                              │   │
│  └─────────────────────────────────────────┘   │
└─────────────────────────────────────────────────┘
```

### Storage Schema (SQLite)

```sql
-- Sessions table
CREATE TABLE sessions (
    id TEXT PRIMARY KEY,              -- UUID
    created_at TIMESTAMP NOT NULL,    -- Session creation time
    updated_at TIMESTAMP NOT NULL,    -- Last activity
    metadata TEXT,                    -- JSON: user, tags, etc.
    system_prompt TEXT                -- System prompt used
);

-- Messages table
CREATE TABLE messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,         -- FK to sessions
    role TEXT NOT NULL,               -- user, assistant, system, tool
    content TEXT,                     -- Message content
    tool_calls TEXT,                  -- JSON: tool calls if any
    tool_call_id TEXT,                -- For tool responses
    name TEXT,                        -- Tool name for tool messages
    created_at TIMESTAMP NOT NULL,    -- Message timestamp
    FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
);

-- Indexes for performance
CREATE INDEX idx_messages_session ON messages(session_id);
CREATE INDEX idx_messages_created ON messages(created_at);
CREATE INDEX idx_sessions_updated ON sessions(updated_at);
```

### Memory Manager API

```python
class MemoryManager:
    """High-level memory management."""

    def create_session(self, system_prompt: str, metadata: dict) -> str:
        """Create a new conversation session. Returns session_id."""

    def load_session(self, session_id: str) -> list[Message]:
        """Load conversation history for a session."""

    def save_message(self, session_id: str, message: Message) -> None:
        """Save a message to the session."""

    def get_recent_messages(
        self,
        session_id: str,
        max_tokens: int = 4096
    ) -> list[Message]:
        """Get recent messages within token limit."""

    def list_sessions(self, limit: int = 10) -> list[dict]:
        """List recent sessions with metadata."""

    def delete_session(self, session_id: str) -> None:
        """Delete a session and all its messages."""

    def prune_old_sessions(self, days: int = 30) -> int:
        """Delete sessions older than N days. Returns count deleted."""
```

## Memory Strategies

### 1. Simple Windowing (Phase 2.1)

Load the most recent N messages that fit within token limit:

```python
def get_recent_messages(session_id, max_tokens):
    messages = load_messages(session_id, order='DESC', limit=100)

    result = []
    total_tokens = 0

    for msg in reversed(messages):  # Oldest to newest
        tokens = estimate_tokens(msg)
        if total_tokens + tokens > max_tokens:
            break
        result.append(msg)
        total_tokens += tokens

    return result
```

**Pros:** Simple, fast, predictable
**Cons:** May lose important context from earlier in conversation

### 2. Summarization (Future)

Summarize old messages to compress history:

```python
def get_context_with_summary(session_id, max_tokens):
    # Get all messages
    all_messages = load_messages(session_id)

    # If within limit, return as-is
    if estimate_tokens(all_messages) <= max_tokens:
        return all_messages

    # Otherwise, summarize old context
    old_msgs = all_messages[:-20]  # All but recent 20
    recent_msgs = all_messages[-20:]

    summary = summarize_conversation(old_msgs)

    return [
        Message(role="system", content=f"Previous context: {summary}"),
        *recent_msgs
    ]
```

**Pros:** Preserves important context, better continuity
**Cons:** More complex, requires LLM call, lossy compression

### 3. Hybrid (Future)

Combine summarization with selective important message retention:

- Keep system messages always
- Summarize routine exchanges
- Flag and retain important messages (user decisions, key facts)
- Keep recent N messages verbatim

## Integration Points

### Agent Class Modifications

```python
class Agent:
    def __init__(
        self,
        llm: LLMClient,
        tools: list[Tool],
        memory_manager: MemoryManager | None = None,
        session_id: str | None = None,
        ...
    ):
        self.memory = memory_manager
        self.session_id = session_id

        # Load history if session exists
        if self.memory and self.session_id:
            self.state = self._load_session_state()
        else:
            self.state = AgentState(system_prompt)

    async def run(self, query: str) -> str:
        # Add user message
        self.state.add_user_message(query)

        # Save to memory if enabled
        if self.memory:
            self.memory.save_message(
                self.session_id,
                self.state.messages[-1]
            )

        # ... ReAct loop ...

        # Save assistant response
        if self.memory:
            self.memory.save_message(
                self.session_id,
                self.state.messages[-1]
            )

        return response
```

### CLI Integration

New commands in `harombe chat`:

```
/sessions          List recent conversation sessions
/load <session>    Load and continue a previous session
/save              Force save current session
/history           Show conversation history for current session
/clear             Clear current session history (but keep in DB)
/forget            Delete current session from memory
```

### Configuration Schema

```yaml
memory:
  enabled: true # Enable conversation memory
  storage_path: ~/.harombe/memory.db # SQLite database location
  max_history_tokens: 4096 # Token limit for context
  auto_prune_days: 30 # Auto-delete old sessions
  strategy: simple # simple, summarization, hybrid
```

## Implementation Plan

### Phase 2.1: Basic Memory (Complete)

1. ✅ Design architecture (this document)
2. ✅ Implement SQLite storage backend
3. ✅ Implement simple windowing strategy
4. ✅ Integrate with Agent class
5. ✅ Add CLI commands
6. ✅ Add configuration
7. ✅ Write tests
8. ✅ Update documentation

### Phase 2.2: Semantic Search & RAG (Complete)

1. ✅ Design vector store architecture
2. ✅ Implement embedding service (sentence-transformers, Ollama)
3. ✅ Implement ChromaDB vector store
4. ✅ Integrate with MemoryManager (auto-embedding)
5. ✅ Add semantic search capabilities
6. ✅ Implement RAG for agent
7. ✅ Write comprehensive tests
8. ✅ Update documentation and examples

### Phase 2.3: Advanced Memory (Future)

1. Implement summarization strategy
2. Add message importance scoring
3. Implement hybrid strategy
4. Export/import sessions
5. Alternative backends (PostgreSQL, Redis)
6. Cloud storage adapters

## File Structure

```
src/harombe/memory/
├── __init__.py
├── storage.py          # SQLite backend implementation
├── manager.py          # MemoryManager class
├── strategies.py       # Windowing/summarization strategies
└── schema.py           # Pydantic models for session/message

tests/memory/
├── __init__.py
├── test_storage.py
├── test_manager.py
└── test_strategies.py
```

## Token Estimation

Simple heuristic for token counting:

```python
def estimate_tokens(message: Message) -> int:
    """Rough token estimate: ~4 chars per token."""
    text = message.content or ""

    # Add tool call overhead
    if message.tool_calls:
        for tc in message.tool_calls:
            text += json.dumps(tc.arguments)

    return len(text) // 4
```

For production, consider using `tiktoken` library for accurate counts.

## Error Handling

- **Session not found**: Create new session automatically
- **Database locked**: Retry with exponential backoff
- **Token limit exceeded**: Fall back to most recent messages only
- **Corrupted data**: Log error, continue without memory

## Testing Strategy

1. **Unit tests**: Storage CRUD operations
2. **Integration tests**: Agent + memory workflows
3. **Performance tests**: Large conversation history
4. **Concurrency tests**: Multiple agents sharing storage

## Security Considerations

1. **No encryption** in Phase 2.1 (local SQLite only)
2. **Future**: Add encryption at rest for sensitive conversations
3. **Access control**: Not needed for single-user local setup
4. **PII handling**: Covered in Phase 2.3 (Privacy Router)

## Migration Path

For users upgrading:

1. Memory is opt-in via config
2. Existing agents work without changes
3. No data migration needed (fresh start)
4. Old sessions can be imported via CLI tool (future)

---

## Phase 2.2: Semantic Search & RAG

### Overview

Phase 2.2 extends the memory system with semantic search capabilities using vector embeddings. This enables agents to find relevant context from past conversations even when the exact wording differs, powering Retrieval-Augmented Generation (RAG) for more intelligent, context-aware responses.

### Architecture Extension

```
┌───────────────────────────────────────────────────────────────────┐
│                           Agent with RAG                          │
│  ┌───────────────────────────────────────────────────────────┐   │
│  │              Memory Manager                                │   │
│  │  - Session management                                      │   │
│  │  - Message filtering & windowing                           │   │
│  │  - Semantic search (NEW)                                   │   │
│  │  - RAG context retrieval (NEW)                             │   │
│  └────────┬────────────────────────────┬─────────────────────┘   │
│           │                            │                          │
│  ┌────────▼─────────────────┐  ┌──────▼───────────────────────┐ │
│  │   Storage Backend        │  │   Vector Store (ChromaDB)    │ │
│  │   - SQLite database      │  │   - Embeddings storage       │ │
│  │   - Message CRUD         │  │   - Similarity search        │ │
│  └──────────────────────────┘  │   - HNSW indexing            │ │
│                                 └──────▲───────────────────────┘ │
│                                        │                          │
│                                 ┌──────┴───────────────────────┐ │
│                                 │   Embedding Client           │ │
│                                 │   - sentence-transformers    │ │
│                                 │   - Ollama (optional)        │ │
│                                 └──────────────────────────────┘ │
└───────────────────────────────────────────────────────────────────┘
```

### Components

#### 1. Embedding Client

Generates vector embeddings (numerical representations) for text:

```python
class EmbeddingClient(Protocol):
    async def embed(self, texts: list[str]) -> list[list[float]]:
        """Generate embeddings for multiple texts."""

    async def embed_single(self, text: str) -> list[float]:
        """Generate embedding for a single text."""

    @property
    def dimension(self) -> int:
        """Embedding dimension (e.g., 384 for all-MiniLM-L6-v2)."""
```

**Implementations:**

- **SentenceTransformerEmbedding** (default) - Local, privacy-first
  - Model: `sentence-transformers/all-MiniLM-L6-v2`
  - Dimension: 384
  - No API calls, runs locally on CPU or GPU

- **OllamaEmbedding** - Uses Ollama for embeddings
  - Leverages existing Ollama infrastructure
  - Larger models available (e.g., `nomic-embed-text`)

#### 2. Vector Store

Stores and searches embeddings using approximate nearest neighbor algorithms:

```python
class VectorStore(Protocol):
    def add(
        self,
        ids: list[str],
        embeddings: list[list[float]],
        documents: list[str],
        metadata: list[dict[str, Any]],
    ) -> None:
        """Add embeddings to the store."""

    def search(
        self,
        query_embedding: list[float],
        top_k: int = 10,
        where: dict[str, Any] | None = None,
    ) -> tuple[list[str], list[str], list[dict], list[float]]:
        """Search for similar embeddings. Returns (ids, docs, metadata, distances)."""
```

**Implementation: ChromaDBVectorStore**

- Lightweight, embedded database
- Uses HNSW (Hierarchical Navigable Small World) for fast search
- Cosine similarity for distance metric
- Supports metadata filtering (e.g., by session_id)
- Persistent or in-memory storage

#### 3. Enhanced Memory Manager

Extended with semantic search capabilities:

```python
class MemoryManager:
    def __init__(
        self,
        storage_path: Path,
        max_history_tokens: int = 4096,
        embedding_client: EmbeddingClient | None = None,
        vector_store: VectorStore | None = None,
    ):
        # Enable semantic search if both components provided
        self.semantic_search_enabled = (
            embedding_client is not None and vector_store is not None
        )

    def save_message(self, session_id: str, message: Message) -> int:
        """Save message to SQLite AND auto-embed to vector store."""
        message_id = self.storage.save_message(record)

        # Auto-embed if semantic search enabled
        if self.semantic_search_enabled and message.content:
            self._embed_message(message_id, session_id, message)

        return message_id

    async def search_similar(
        self,
        query: str,
        top_k: int = 5,
        session_id: str | None = None,
        min_similarity: float | None = None,
    ) -> list[Message]:
        """Search for semantically similar messages."""
        # Generate query embedding
        query_embedding = await self.embedding_client.embed_single(query)

        # Search vector store with optional session filter
        where = {"session_id": session_id} if session_id else None
        ids, docs, metadata, distances = self.vector_store.search(
            query_embedding=query_embedding,
            top_k=top_k,
            where=where,
        )

        # Filter by similarity threshold and convert to Messages
        results = []
        for doc, meta, distance in zip(docs, metadata, distances):
            similarity = 1.0 - distance  # Convert distance to similarity
            if min_similarity and similarity < min_similarity:
                continue
            results.append(Message(role=meta["role"], content=doc))

        return results

    async def get_relevant_context(
        self,
        query: str,
        max_tokens: int = 2048,
        session_id: str | None = None,
    ) -> list[Message]:
        """Get relevant context within token budget."""
        # Over-fetch candidates
        candidates = await self.search_similar(
            query=query,
            top_k=20,
            session_id=session_id,
        )

        # Filter by token budget
        results = []
        current_tokens = 0
        for msg in candidates:
            msg_tokens = estimate_tokens(msg)
            if current_tokens + msg_tokens > max_tokens:
                break
            results.append(msg)
            current_tokens += msg_tokens

        return results
```

#### 4. RAG-Enabled Agent

Agent retrieves relevant context before LLM calls:

```python
class Agent:
    def __init__(
        self,
        llm: LLMClient,
        tools: list[Tool],
        memory_manager: MemoryManager | None = None,
        session_id: str | None = None,
        enable_rag: bool = False,
        rag_top_k: int = 5,
        rag_min_similarity: float = 0.7,
    ):
        self.enable_rag = enable_rag
        self.rag_top_k = rag_top_k
        self.rag_min_similarity = rag_min_similarity

    async def run(self, user_message: str) -> str:
        # Load conversation history
        state = self._load_history()

        # Retrieve relevant context if RAG enabled
        rag_context = None
        if self.enable_rag and self.memory_manager:
            rag_context = await self._retrieve_rag_context(user_message)

        # Inject context into user message
        if rag_context:
            enhanced_message = self._format_message_with_context(
                user_message, rag_context
            )
            state.add_user_message(enhanced_message)
        else:
            state.add_user_message(user_message)

        # Save ORIGINAL message (without RAG context) to memory
        if self.memory_manager:
            self.memory_manager.save_message(
                self.session_id,
                Message(role="user", content=user_message),
            )

        # ... ReAct loop ...

    def _format_message_with_context(
        self,
        user_message: str,
        context: list[Message],
    ) -> str:
        """Format enhanced message with retrieved context."""
        lines = [
            "RELEVANT CONTEXT FROM PAST CONVERSATIONS:",
            "---",
        ]

        for msg in context:
            role = msg.role.upper()
            content = msg.content[:200]  # Truncate long messages
            if len(msg.content) > 200:
                content += "..."
            lines.append(f"[{role}]: {content}")

        lines.extend([
            "---",
            "",
            "Now answer the current user question using the context above if relevant.",
            "",
            f"USER QUESTION: {user_message}",
        ])

        return "\n".join(lines)
```

### Embedding Schema

Embeddings are stored with metadata for filtering and retrieval:

```python
{
    "id": "msg_12345",           # Unique identifier
    "embedding": [0.1, 0.2, ...], # 384-dim vector (for all-MiniLM)
    "document": "message text",   # Original text
    "metadata": {
        "session_id": "abc-123",  # Session identifier
        "message_id": 12345,      # Database message ID
        "role": "user",           # Message role
        "timestamp": 1234567890,  # Unix timestamp (optional)
    }
}
```

### Configuration

```yaml
memory:
  enabled: true
  storage_path: ~/.harombe/memory.db
  max_history_tokens: 4096

  # Vector store configuration
  vector_store:
    enabled: true
    backend: chromadb # Only chromadb supported now
    embedding_model: sentence-transformers/all-MiniLM-L6-v2 # Model to use
    embedding_provider: sentence-transformers # Local embeddings
    persist_directory: ~/.harombe/vectors # Storage directory (null = in-memory)
    collection_name: harombe_embeddings # Collection name

  # RAG configuration
  rag:
    enabled: true
    top_k: 5 # Number of similar messages to retrieve
    min_similarity: 0.7 # Similarity threshold (0.0-1.0)
```

### How It Works

1. **Message saved** → Automatically embedded and stored in vector database
2. **User query** → If RAG enabled, retrieve similar messages
3. **Context injection** → Format retrieved messages into prompt
4. **LLM call** → Agent generates response with enhanced context
5. **Response saved** → Stored in both SQLite and vector store

### Performance Characteristics

- **Embedding generation**: ~10-50ms per message (CPU), ~1-5ms (GPU)
- **Vector search**: Sub-millisecond for <10K messages, ~10ms for 100K+
- **Storage overhead**: ~1.5KB per message (384-dim float32 embedding)
- **Memory usage**: ChromaDB loads index into RAM (~2MB per 1K messages)

### Use Cases

1. **Cross-session knowledge**: "What did we discuss about Python last week?"
2. **Related topics**: Find messages about similar topics with different wording
3. **Context-aware responses**: Agent recalls relevant past information
4. **Knowledge base**: Search entire conversation history semantically
5. **Multi-agent memory**: Multiple agents sharing a knowledge pool

### Testing Strategy

1. **Unit tests**: Embedding clients, vector store operations
2. **Integration tests**: MemoryManager with semantic search
3. **Agent tests**: RAG functionality with mocked LLM
4. **Performance tests**: Large-scale embedding and retrieval
5. **Similarity tests**: Verify semantic matching works correctly

### Privacy & Security

- **Local embeddings** - sentence-transformers runs entirely offline
- **No API calls** - All processing happens on your hardware
- **Data isolation** - Vector store stored locally alongside SQLite
- **Optional encryption** - ChromaDB supports encryption at rest (future)

### Backward Compatibility

- Semantic search is **opt-in** via config
- All new parameters have defaults
- Existing code works without changes
- Memory can be enabled without semantic search
- Semantic search requires both `embedding_client` and `vector_store`

### Future Enhancements

1. **Alternative embeddings**: Support for OpenAI, Cohere, custom models
2. **Hybrid search**: Combine keyword and semantic search
3. **Metadata indexing**: Filter by date, user, tags, importance
4. **Automatic importance scoring**: Identify key messages for retention
5. **Multi-modal embeddings**: Support for images, audio (CLIP, etc.)
6. **Backfill optimization**: Batch embedding for large existing datasets
