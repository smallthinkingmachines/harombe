"""SGLang LLM client using OpenAI-compatible API."""

from harombe.llm.openai_compat import OpenAICompatibleClient


class SGLangClient(OpenAICompatibleClient):
    """LLM client for SGLang inference server.

    SGLang exposes an OpenAI-compatible ``/v1/chat/completions`` endpoint,
    so this is a thin wrapper that sets sensible defaults for SGLang.
    """

    def __init__(
        self,
        model: str,
        base_url: str = "http://localhost:30000/v1",
        api_key: str | None = None,
        timeout: int = 120,
        temperature: float = 0.7,
    ) -> None:
        """Initialize SGLang client.

        Args:
            model: Model name (e.g., "meta-llama/Llama-3.1-8B-Instruct")
            base_url: SGLang OpenAI-compatible endpoint
            api_key: API key (if auth is enabled)
            timeout: Request timeout in seconds
            temperature: Default sampling temperature
        """
        super().__init__(
            model=model,
            base_url=base_url,
            api_key=api_key or "none",
            timeout=timeout,
            temperature=temperature,
        )
