"""Ollama LLM client using OpenAI SDK."""

from harombe.llm.openai_compat import OpenAICompatibleClient


class OllamaClient(OpenAICompatibleClient):
    """LLM client that wraps Ollama's OpenAI-compatible API."""

    def __init__(
        self,
        model: str,
        base_url: str = "http://localhost:11434/v1",
        timeout: int = 120,
        temperature: float = 0.7,
    ) -> None:
        """Initialize Ollama client.

        Args:
            model: Model name (e.g., "qwen2.5:7b")
            base_url: Ollama OpenAI-compatible endpoint
            timeout: Request timeout in seconds
            temperature: Default sampling temperature
        """
        super().__init__(
            model=model,
            base_url=base_url,
            api_key="ollama",  # Ollama doesn't use API keys but SDK requires one
            timeout=timeout,
            temperature=temperature,
        )
