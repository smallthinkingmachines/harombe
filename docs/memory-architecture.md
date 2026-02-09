# Conversation Memory System Design

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

### Phase 2.1: Basic Memory (Current)

1. ✅ Design architecture (this document)
2. Implement SQLite storage backend
3. Implement simple windowing strategy
4. Integrate with Agent class
5. Add CLI commands
6. Add configuration
7. Write tests
8. Update documentation

### Phase 2.2: Advanced Memory (Future)

1. Implement summarization strategy
2. Add message importance scoring
3. Implement hybrid strategy
4. Add memory search/query
5. Export/import sessions

### Phase 2.3: Alternative Backends (Future)

1. PostgreSQL adapter
2. Redis adapter
3. Cloud storage adapters

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
