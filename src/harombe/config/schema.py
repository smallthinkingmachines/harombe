"""Pydantic models for harombe.yaml configuration."""

from typing import Literal

from pydantic import BaseModel, Field


class ModelConfig(BaseModel):
    """LLM model configuration."""

    name: str = Field(
        default="auto",
        description="Model name or 'auto' for automatic selection based on available VRAM",
    )
    quantization: str = Field(default="Q4_K_M", description="Model quantization level")
    context_length: int = Field(default=8192, description="Maximum context window size", ge=1024)
    temperature: float = Field(default=0.7, description="Sampling temperature", ge=0.0, le=2.0)


class OllamaConfig(BaseModel):
    """Ollama server configuration."""

    host: str = Field(default="http://localhost:11434", description="Ollama server URL")
    timeout: int = Field(default=120, description="Request timeout in seconds", ge=1)


class AgentConfig(BaseModel):
    """Agent loop configuration."""

    max_steps: int = Field(default=10, description="Maximum agent reasoning steps", ge=1, le=50)
    system_prompt: str = Field(
        default=(
            "You are harombe, a helpful AI assistant. You have access to tools that let you "
            "interact with the system, search the web, and work with files. Use them to help "
            "the user accomplish their goals. Think step by step and be precise."
        ),
        description="System prompt for the agent",
    )


class ToolsConfig(BaseModel):
    """Tool availability configuration."""

    shell: bool = Field(default=True, description="Enable shell command execution tool")
    filesystem: bool = Field(default=True, description="Enable filesystem read/write tools")
    web_search: bool = Field(default=True, description="Enable web search tool")
    confirm_dangerous: bool = Field(
        default=True,
        description="Require user confirmation before executing dangerous operations",
    )


class ServerConfig(BaseModel):
    """API server configuration."""

    host: str = Field(default="127.0.0.1", description="Server bind address")
    port: int = Field(default=8000, description="Server port", ge=1, le=65535)


class NodeConfig(BaseModel):
    """Configuration for a single node in the cluster."""

    name: str = Field(description="User-chosen name for this node (e.g., 'office-mac', 'server1')")
    host: str = Field(description="Hostname or IP address")
    port: int = Field(default=8000, description="Port number", ge=1, le=65535)
    model: str = Field(description="Model running on this node")
    tier: int = Field(description="User-declared tier: 0=fast, 1=medium, 2=powerful", ge=0, le=2)

    # Optional fields
    auth_token: str | None = Field(
        default=None, description="Authentication token for remote nodes"
    )
    enabled: bool = Field(default=True, description="Whether this node is enabled")


class DiscoveryConfig(BaseModel):
    """Node discovery configuration."""

    method: Literal["mdns", "explicit"] = Field(
        default="explicit",
        description="Discovery method: 'mdns' for auto-discovery, 'explicit' for manual config",
    )
    mdns_service: str = Field(
        default="_harombe._tcp.local",
        description="mDNS service name for auto-discovery",
    )


class RoutingConfig(BaseModel):
    """Task routing configuration."""

    prefer_local: bool = Field(
        default=True,
        description="Prefer lowest latency nodes when available",
    )
    fallback_strategy: Literal["graceful", "strict"] = Field(
        default="graceful",
        description="Fallback behavior: 'graceful' tries other tiers, 'strict' fails if preferred tier unavailable",
    )
    load_balance: bool = Field(
        default=True,
        description="Distribute load across same-tier nodes",
    )


class CoordinatorConfig(BaseModel):
    """Coordinator configuration."""

    host: str = Field(
        default="localhost",
        description="Host for the coordinator (any always-on machine)",
    )


class VectorStoreConfig(BaseModel):
    """Vector store configuration for semantic search."""

    enabled: bool = Field(
        default=False,
        description="Enable semantic search with vector embeddings",
    )
    backend: Literal["chromadb"] = Field(
        default="chromadb",
        description="Vector store backend (currently only chromadb is supported)",
    )
    embedding_model: str = Field(
        default="sentence-transformers/all-MiniLM-L6-v2",
        description="Embedding model for semantic search (local sentence-transformers model)",
    )
    embedding_provider: Literal["sentence-transformers", "ollama"] = Field(
        default="sentence-transformers",
        description="Embedding provider: 'sentence-transformers' (local, privacy-first) or 'ollama'",
    )
    persist_directory: str | None = Field(
        default=None,
        description="Directory for persistent vector storage (None = in-memory)",
    )
    collection_name: str = Field(
        default="harombe_embeddings",
        description="Name of the vector store collection",
    )


class RAGConfig(BaseModel):
    """Retrieval-Augmented Generation configuration."""

    enabled: bool = Field(
        default=False,
        description="Enable RAG to inject relevant context from past conversations",
    )
    top_k: int = Field(
        default=5,
        description="Number of similar messages to retrieve for context",
        ge=1,
        le=20,
    )
    min_similarity: float = Field(
        default=0.7,
        description="Minimum similarity threshold for retrieval (0.0-1.0)",
        ge=0.0,
        le=1.0,
    )


class MemoryConfig(BaseModel):
    """Conversation memory configuration."""

    enabled: bool = Field(
        default=False,
        description="Enable conversation memory persistence",
    )
    storage_path: str = Field(
        default="~/.harombe/memory.db",
        description="Path to SQLite database for conversation storage",
    )
    max_history_tokens: int = Field(
        default=4096,
        description="Maximum tokens to load from conversation history",
        ge=512,
        le=128000,
    )
    vector_store: VectorStoreConfig = Field(
        default_factory=VectorStoreConfig,
        description="Vector store configuration for semantic search (Phase 2.2)",
    )
    rag: RAGConfig = Field(
        default_factory=RAGConfig,
        description="Retrieval-Augmented Generation configuration (Phase 2.2)",
    )


class ClusterConfig(BaseModel):
    """Cluster orchestration configuration."""

    coordinator: CoordinatorConfig = Field(default_factory=CoordinatorConfig)
    discovery: DiscoveryConfig = Field(default_factory=DiscoveryConfig)
    routing: RoutingConfig = Field(default_factory=RoutingConfig)
    nodes: list[NodeConfig] = Field(
        default_factory=list,
        description="List of nodes in the cluster",
    )


class STTConfig(BaseModel):
    """Speech-to-text configuration."""

    model: str = Field(
        default="base",
        description="Whisper model size (tiny, base, small, medium, large-v2, large-v3)",
    )
    language: str | None = Field(
        default=None,
        description="Language code (e.g., 'en', 'es') or None for auto-detection",
    )
    device: str = Field(
        default="auto",
        description="Device to run on: 'auto', 'cpu', 'cuda', or 'mps'",
    )
    compute_type: str = Field(
        default="default",
        description="Computation precision: 'default', 'int8', 'float16', 'float32'",
    )


class TTSConfig(BaseModel):
    """Text-to-speech configuration."""

    engine: str = Field(
        default="piper",
        description="TTS engine: 'piper' (fast) or 'coqui' (high-quality)",
    )
    model: str = Field(
        default="en_US-lessac-medium",
        description="TTS model/voice name",
    )
    speed: float = Field(
        default=1.0,
        description="Speech speed multiplier",
        ge=0.5,
        le=2.0,
    )
    device: str = Field(
        default="auto",
        description="Device to run on: 'auto', 'cpu', 'cuda', or 'mps'",
    )


class VoiceConfig(BaseModel):
    """Voice and multi-modal configuration."""

    enabled: bool = Field(
        default=False,
        description="Enable voice features (STT/TTS)",
    )
    stt: STTConfig = Field(
        default_factory=STTConfig,
        description="Speech-to-text configuration",
    )
    tts: TTSConfig = Field(
        default_factory=TTSConfig,
        description="Text-to-speech configuration",
    )


class HarombeConfig(BaseModel):
    """Root configuration schema for Harombe."""

    model: ModelConfig = Field(default_factory=ModelConfig)
    ollama: OllamaConfig = Field(default_factory=OllamaConfig)
    agent: AgentConfig = Field(default_factory=AgentConfig)
    tools: ToolsConfig = Field(default_factory=ToolsConfig)
    server: ServerConfig = Field(default_factory=ServerConfig)
    memory: MemoryConfig = Field(
        default_factory=MemoryConfig,
        description="Conversation memory configuration (Phase 2.1)",
    )
    cluster: ClusterConfig | None = Field(
        default=None,
        description="Cluster configuration for multi-machine orchestration (Phase 1)",
    )
    voice: VoiceConfig = Field(
        default_factory=VoiceConfig,
        description="Voice and multi-modal configuration (Phase 3)",
    )
