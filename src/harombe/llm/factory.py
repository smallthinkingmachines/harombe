"""Factory function for creating LLM clients from configuration."""

from __future__ import annotations

from typing import TYPE_CHECKING

from harombe.llm.llamacpp import LlamaCppClient
from harombe.llm.ollama import OllamaClient
from harombe.llm.sglang import SGLangClient
from harombe.llm.vllm import VLLMClient

if TYPE_CHECKING:
    from harombe.config.schema import HarombeConfig
    from harombe.llm.openai_compat import OpenAICompatibleClient


def create_llm_client(config: HarombeConfig) -> OpenAICompatibleClient:
    """Create an LLM client based on configuration.

    Reads ``config.inference.backend`` and returns the appropriate client
    instance, configured from the corresponding backend-specific section.

    Args:
        config: Harombe configuration.

    Returns:
        An LLM client for the configured backend.

    Raises:
        ValueError: If the backend is not recognised.
    """
    backend = config.inference.backend

    if backend == "ollama":
        return OllamaClient(
            model=config.model.name,
            base_url=config.ollama.host + "/v1",
            timeout=config.ollama.timeout,
            temperature=config.model.temperature,
        )
    elif backend == "vllm":
        return VLLMClient(
            model=config.model.name,
            base_url=config.inference.vllm.base_url + "/v1",
            api_key=config.inference.vllm.api_key,
            timeout=config.inference.vllm.timeout,
            temperature=config.model.temperature,
        )
    elif backend == "sglang":
        return SGLangClient(
            model=config.model.name,
            base_url=config.inference.sglang.base_url + "/v1",
            api_key=config.inference.sglang.api_key,
            timeout=config.inference.sglang.timeout,
            temperature=config.model.temperature,
        )
    elif backend == "llamacpp":
        return LlamaCppClient(
            model=config.model.name,
            base_url=config.inference.llamacpp.base_url + "/v1",
            timeout=config.inference.llamacpp.timeout,
            temperature=config.model.temperature,
        )
    else:
        raise ValueError(f"Unknown inference backend: {backend}")
