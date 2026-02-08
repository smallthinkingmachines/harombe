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


class HarombeConfig(BaseModel):
    """Root configuration schema for Harombe."""

    model: ModelConfig = Field(default_factory=ModelConfig)
    ollama: OllamaConfig = Field(default_factory=OllamaConfig)
    agent: AgentConfig = Field(default_factory=AgentConfig)
    tools: ToolsConfig = Field(default_factory=ToolsConfig)
    server: ServerConfig = Field(default_factory=ServerConfig)
