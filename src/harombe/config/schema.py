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


class VLLMConfig(BaseModel):
    """vLLM inference server configuration."""

    base_url: str = Field(default="http://localhost:8000", description="vLLM server URL")
    timeout: int = Field(default=120, description="Request timeout in seconds", ge=1)
    api_key: str | None = Field(default=None, description="API key (if vLLM auth enabled)")


class SGLangConfig(BaseModel):
    """SGLang inference server configuration."""

    base_url: str = Field(default="http://localhost:30000", description="SGLang server URL")
    timeout: int = Field(default=120, description="Request timeout in seconds", ge=1)
    api_key: str | None = Field(default=None, description="API key (if auth enabled)")


class LlamaCppConfig(BaseModel):
    """llama.cpp server configuration."""

    base_url: str = Field(default="http://localhost:8080", description="llama.cpp server URL")
    timeout: int = Field(default=120, description="Request timeout in seconds", ge=1)


class InferenceConfig(BaseModel):
    """Inference backend configuration."""

    backend: Literal["ollama", "vllm", "sglang", "llamacpp"] = Field(
        default="ollama",
        description="Inference backend to use",
    )
    ollama: OllamaConfig = Field(default_factory=OllamaConfig)
    vllm: VLLMConfig = Field(default_factory=VLLMConfig)
    sglang: SGLangConfig = Field(default_factory=SGLangConfig)
    llamacpp: LlamaCppConfig = Field(default_factory=LlamaCppConfig)


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
    cors_origins: list[str] = Field(
        default=["http://localhost:3000", "http://localhost:8000"],
        description="Allowed CORS origins (use ['*'] for development only)",
    )
    ssl_certfile: str | None = Field(default=None, description="Path to SSL certificate file")
    ssl_keyfile: str | None = Field(default=None, description="Path to SSL private key file")


class NodeConfig(BaseModel):
    """Configuration for a single node in the cluster."""

    name: str = Field(description="User-chosen name for this node (e.g., 'office-mac', 'server1')")
    host: str = Field(description="Hostname or IP address")
    port: int = Field(default=8000, description="Port number", ge=1, le=65535)
    model: str = Field(description="Model running on this node")
    tier: int = Field(description="User-declared tier: 0=fast, 1=medium, 2=powerful", ge=0, le=2)
    backend: Literal["ollama", "vllm", "sglang", "llamacpp"] = Field(
        default="ollama",
        description="Inference backend running on this node",
    )

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


class GatewayConfig(BaseModel):
    """MCP Gateway configuration."""

    host: str = Field(
        default="127.0.0.1",
        description="Gateway bind address",
    )
    port: int = Field(
        default=8100,
        description="Gateway port",
        ge=1,
        le=65535,
    )
    timeout: int = Field(
        default=30,
        description="Request timeout in seconds",
        ge=1,
    )
    max_retries: int = Field(
        default=3,
        description="Maximum retry attempts for container requests",
        ge=1,
        le=10,
    )


class AuditConfig(BaseModel):
    """Audit logging configuration."""

    enabled: bool = Field(
        default=True,
        description="Enable audit logging of all tool calls",
    )
    database: str = Field(
        default="~/.harombe/audit.db",
        description="Path to SQLite audit database",
    )
    retention_days: int = Field(
        default=90,
        description="Number of days to retain audit logs",
        ge=1,
    )
    redact_sensitive: bool = Field(
        default=True,
        description="Automatically redact sensitive data (API keys, passwords, tokens)",
    )
    log_level: Literal["DEBUG", "INFO", "WARN", "ERROR"] = Field(
        default="INFO",
        description="Audit logging verbosity level",
    )


class CredentialsConfig(BaseModel):
    """Credential management configuration."""

    method: Literal["env", "vault", "sops"] = Field(
        default="env",
        description="Credential storage method: 'env' (environment vars), 'vault' (HashiCorp Vault), 'sops' (encrypted files)",
    )
    vault_addr: str | None = Field(
        default=None,
        description="Vault server address (e.g., http://localhost:8200)",
    )
    vault_token: str = Field(
        default="~/.vault-token",
        description="Path to Vault token file",
    )
    auto_refresh: bool = Field(
        default=True,
        description="Automatically refresh credentials before expiry",
    )
    rotation_days: int = Field(
        default=30,
        description="Days between credential rotation",
        ge=1,
    )


class ContainerResourcesConfig(BaseModel):
    """Container resource limits configuration."""

    cpu_limit: str | None = Field(
        default=None,
        description="CPU limit (e.g., '2' for 2 cores, '0.5' for half a core)",
    )
    memory_limit: str | None = Field(
        default=None,
        description="Memory limit (e.g., '2g' for 2GB, '512m' for 512MB)",
    )
    pids_limit: int = Field(
        default=100,
        description="Maximum number of processes",
        ge=1,
    )


class ContainerConfig(BaseModel):
    """Configuration for a single capability container."""

    image: str = Field(
        description="Docker image name (e.g., 'harombe/browser:latest')",
    )
    enabled: bool = Field(
        default=True,
        description="Whether this container is enabled",
    )
    resources: ContainerResourcesConfig = Field(
        default_factory=ContainerResourcesConfig,
        description="Resource limits for this container",
    )
    egress_allow: list[str] = Field(
        default_factory=list,
        description="Allowed egress domains/IPs (empty list = no network access)",
    )
    mounts: list[str] = Field(
        default_factory=list,
        description="Volume mounts in format '/host/path:/container/path:mode' (mode: ro/rw)",
    )
    environment: dict[str, str] = Field(
        default_factory=dict,
        description="Environment variables for the container",
    )
    timeout: int | None = Field(
        default=None,
        description="Operation timeout in seconds (None = use gateway default)",
        ge=1,
    )
    confirm_actions: list[str] = Field(
        default_factory=list,
        description="Action patterns requiring HITL confirmation (e.g., 'delete_*', 'send_email')",
    )


class HITLConfig(BaseModel):
    """Human-In-The-Loop confirmation configuration."""

    enabled: bool = Field(
        default=True,
        description="Enable HITL gates for dangerous operations",
    )
    timeout: int = Field(
        default=60,
        description="Seconds to wait for user confirmation before auto-deny",
        ge=1,
    )
    notification_method: Literal["cli", "webhook", "email"] = Field(
        default="cli",
        description="How to notify user of pending confirmations",
    )
    webhook_url: str | None = Field(
        default=None,
        description="Webhook URL for remote confirmation notifications",
    )


class CloudLLMConfig(BaseModel):
    """Cloud LLM provider configuration for privacy router."""

    provider: Literal["anthropic"] = Field(
        default="anthropic",
        description="Cloud LLM provider",
    )
    model: str = Field(
        default="claude-sonnet-4-20250514",
        description="Cloud model name",
    )
    api_key_env: str = Field(
        default="ANTHROPIC_API_KEY",
        description="Environment variable name containing the API key",
    )
    max_tokens: int = Field(
        default=4096,
        description="Maximum tokens for cloud responses",
        ge=1,
    )
    timeout: int = Field(
        default=120,
        description="Request timeout in seconds",
        ge=1,
    )


class PrivacyConfig(BaseModel):
    """Privacy routing configuration (Phase 5)."""

    mode: Literal["local-only", "hybrid", "cloud-assisted"] = Field(
        default="local-only",
        description="Routing mode: 'local-only' (default, no cloud), 'hybrid' (cloud for public queries), 'cloud-assisted' (cloud with sanitization)",
    )
    cloud_llm: CloudLLMConfig = Field(
        default_factory=CloudLLMConfig,
        description="Cloud LLM provider configuration",
    )
    custom_patterns: dict[str, str] = Field(
        default_factory=dict,
        description="Additional PII regex patterns {name: pattern_string}",
    )
    custom_restricted_keywords: list[str] = Field(
        default_factory=list,
        description="Additional keywords that force local-only routing",
    )
    audit_routing: bool = Field(
        default=True,
        description="Log routing decisions to audit system",
    )
    reconstruct_responses: bool = Field(
        default=True,
        description="Restore original values in cloud responses after sanitization",
    )


class PatternsConfig(BaseModel):
    """Multi-model collaboration pattern configuration (Phase 6)."""

    enabled: bool = Field(
        default=False,
        description="Enable a collaboration pattern on top of the privacy router",
    )
    pattern: Literal[
        "none",
        "smart_escalation",
        "privacy_handshake",
        "data_minimization",
        "specialized_routing",
        "sliding_privacy",
        "debate",
    ] = Field(
        default="none",
        description="Which collaboration pattern to use",
    )
    confidence_threshold: float = Field(
        default=0.5,
        description="(smart_escalation) Minimum confidence to accept local answer",
        ge=0.0,
        le=1.0,
    )
    privacy_level: float = Field(
        default=0.5,
        description="(sliding_privacy) Privacy dial: 0.0 = all cloud, 1.0 = all local",
        ge=0.0,
        le=1.0,
    )
    cloud_threshold: Literal["medium", "complex"] = Field(
        default="complex",
        description="(specialized_routing) Minimum complexity to route to cloud",
    )
    include_contextual: bool = Field(
        default=True,
        description="(data_minimization) Include CONTEXTUAL sentences in addition to ESSENTIAL",
    )


class PluginOverrideConfig(BaseModel):
    """Per-plugin override configuration."""

    enabled: bool = Field(default=True, description="Whether this plugin is enabled")


class PluginsConfig(BaseModel):
    """Plugin system configuration."""

    enabled: bool = Field(
        default=True,
        description="Enable the plugin system",
    )
    plugin_dir: str = Field(
        default="~/.harombe/plugins",
        description="Directory to scan for local plugins (.py files)",
    )
    plugins: dict[str, PluginOverrideConfig] = Field(
        default_factory=dict,
        description="Per-plugin overrides keyed by plugin name",
    )
    blocked: list[str] = Field(
        default_factory=list,
        description="Plugin names to block from loading",
    )


class DelegationConfig(BaseModel):
    """Multi-agent delegation configuration."""

    enabled: bool = Field(
        default=False,
        description="Enable multi-agent delegation",
    )
    max_depth: int = Field(
        default=3,
        description="Maximum delegation chain depth",
        ge=1,
        le=10,
    )


class NamedAgentConfig(BaseModel):
    """Configuration for a named agent in the registry."""

    name: str = Field(description="Unique agent name")
    description: str = Field(
        default="",
        description="Description of this agent's capabilities (shown to LLM for routing)",
    )
    system_prompt: str = Field(
        default="You are a helpful AI assistant.",
        description="System prompt for this agent",
    )
    model: str | None = Field(
        default=None,
        description="Model override for this agent (None = use default)",
    )
    max_steps: int = Field(
        default=10,
        description="Maximum reasoning steps",
        ge=1,
        le=50,
    )
    tools: ToolsConfig = Field(
        default_factory=ToolsConfig,
        description="Tool configuration for this agent",
    )
    enable_rag: bool = Field(
        default=False,
        description="Enable RAG for this agent",
    )


class MCPServerConfig(BaseModel):
    """MCP server configuration for exposing tools."""

    enabled: bool = Field(
        default=False,
        description="Enable MCP server to expose harombe tools",
    )
    transport: Literal["stdio", "streamable-http"] = Field(
        default="stdio",
        description="MCP server transport type",
    )
    host: str = Field(
        default="127.0.0.1",
        description="Host for HTTP transport",
    )
    port: int = Field(
        default=8200,
        description="Port for HTTP transport",
        ge=1,
        le=65535,
    )


class ExternalMCPServerConfig(BaseModel):
    """Configuration for connecting to an external MCP server."""

    name: str = Field(description="Server name (used as tool prefix)")
    transport: Literal["stdio", "streamable-http"] = Field(
        default="stdio",
        description="Transport type for connecting",
    )
    command: str | None = Field(
        default=None,
        description="Command to start the server (for stdio transport)",
    )
    args: list[str] = Field(
        default_factory=list,
        description="Arguments for the command",
    )
    env: dict[str, str] = Field(
        default_factory=dict,
        description="Environment variables for the server process",
    )
    url: str | None = Field(
        default=None,
        description="URL for HTTP transport",
    )


class MCPConfig(BaseModel):
    """Model Context Protocol configuration."""

    server: MCPServerConfig = Field(
        default_factory=MCPServerConfig,
        description="MCP server configuration for exposing tools",
    )
    external_servers: list[ExternalMCPServerConfig] = Field(
        default_factory=list,
        description="External MCP servers to connect to",
    )


class SecurityConfig(BaseModel):
    """Security layer configuration (Phase 4)."""

    enabled: bool = Field(
        default=False,
        description="Enable security layer with capability containers",
    )
    isolation: Literal["docker", "gvisor"] = Field(
        default="docker",
        description="Container isolation technology: 'docker' (standard) or 'gvisor' (enhanced)",
    )
    gateway: GatewayConfig = Field(
        default_factory=GatewayConfig,
        description="MCP Gateway configuration",
    )
    audit: AuditConfig = Field(
        default_factory=AuditConfig,
        description="Audit logging configuration",
    )
    credentials: CredentialsConfig = Field(
        default_factory=CredentialsConfig,
        description="Credential management configuration",
    )
    containers: dict[str, ContainerConfig] = Field(
        default_factory=dict,
        description="Container configurations by name (e.g., 'browser', 'filesystem', 'code_exec', 'web_search')",
    )
    hitl: HITLConfig = Field(
        default_factory=HITLConfig,
        description="Human-In-The-Loop confirmation configuration",
    )


class HarombeConfig(BaseModel):
    """Root configuration schema for Harombe."""

    model: ModelConfig = Field(default_factory=ModelConfig)
    ollama: OllamaConfig = Field(default_factory=OllamaConfig)
    inference: InferenceConfig = Field(default_factory=InferenceConfig)
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
    plugins: PluginsConfig = Field(
        default_factory=PluginsConfig,
        description="Plugin system configuration",
    )
    delegation: DelegationConfig = Field(
        default_factory=DelegationConfig,
        description="Multi-agent delegation configuration",
    )
    agents: list[NamedAgentConfig] = Field(
        default_factory=list,
        description="Named agent configurations for delegation",
    )
    mcp: MCPConfig = Field(
        default_factory=MCPConfig,
        description="Model Context Protocol configuration",
    )
    security: SecurityConfig = Field(
        default_factory=SecurityConfig,
        description="Security layer with capability containers (Phase 4)",
    )
    privacy: PrivacyConfig = Field(
        default_factory=PrivacyConfig,
        description="Privacy routing for hybrid local/cloud AI (Phase 5)",
    )
    patterns: PatternsConfig = Field(
        default_factory=PatternsConfig,
        description="Multi-model collaboration patterns (Phase 6)",
    )
