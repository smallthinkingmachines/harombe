"""llama.cpp server LLM client using OpenAI-compatible API."""

from harombe.llm.openai_compat import OpenAICompatibleClient


class LlamaCppClient(OpenAICompatibleClient):
    """LLM client for llama.cpp server (llama-server).

    llama.cpp's built-in HTTP server exposes an OpenAI-compatible
    ``/v1/chat/completions`` endpoint, so this is a thin wrapper that
    sets sensible defaults for llama.cpp.
    """

    def __init__(
        self,
        model: str = "default",
        base_url: str = "http://localhost:8080/v1",
        timeout: int = 120,
        temperature: float = 0.7,
    ) -> None:
        """Initialize llama.cpp client.

        Args:
            model: Model name (llama.cpp typically serves a single model;
                   ``"default"`` works when only one model is loaded).
            base_url: llama.cpp OpenAI-compatible endpoint
            timeout: Request timeout in seconds
            temperature: Default sampling temperature
        """
        super().__init__(
            model=model,
            base_url=base_url,
            api_key="none",  # llama.cpp doesn't use API keys
            timeout=timeout,
            temperature=temperature,
        )
