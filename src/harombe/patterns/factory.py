"""Factory for creating pattern-wrapped LLM clients from config.

Reads ``PatternsConfig`` from the harombe configuration, creates the
base local/cloud clients via ``create_privacy_router()``, then wraps
them in the selected collaboration pattern.
"""

import logging
from typing import Any

from harombe.privacy.router import create_privacy_router

from .registry import PatternRegistry

logger = logging.getLogger(__name__)


def create_pattern_client(config: Any) -> Any:
    """Create an LLM client wrapped in the configured collaboration pattern.

    If no pattern is configured (or pattern is "none"), returns the base
    privacy-routed client unchanged.

    Args:
        config: HarombeConfig instance

    Returns:
        An LLM client satisfying the LLMClient protocol
    """
    # Build the base client (OllamaClient or PrivacyRouter)
    base_client = create_privacy_router(config)

    patterns_config = getattr(config, "patterns", None)
    if patterns_config is None or not patterns_config.enabled:
        return base_client

    pattern_name = patterns_config.pattern
    if pattern_name == "none":
        return base_client

    # Ensure all patterns are registered by importing the module
    _ensure_patterns_loaded()

    try:
        pattern_cls = PatternRegistry.get(pattern_name)
    except KeyError:
        logger.warning(
            "Unknown pattern %r, falling back to base client. Available: %s",
            pattern_name,
            PatternRegistry.available(),
        )
        return base_client

    # Build kwargs from config
    kwargs = _build_pattern_kwargs(pattern_name, base_client, config)

    return pattern_cls(**kwargs)


def _ensure_patterns_loaded() -> None:
    """Import all pattern modules so their @register_pattern decorators fire."""
    # These imports trigger registration via the decorator
    import harombe.patterns.data_minimization
    import harombe.patterns.debate
    import harombe.patterns.privacy_handshake
    import harombe.patterns.sliding_privacy
    import harombe.patterns.smart_escalation
    import harombe.patterns.specialized_routing  # noqa: F401


def _build_pattern_kwargs(
    pattern_name: str,
    base_client: Any,
    config: Any,
) -> dict[str, Any]:
    """Build constructor kwargs for a pattern class.

    For patterns that need separate local/cloud clients, we create them
    from the config. For the base_client returned by create_privacy_router,
    we use it as the local_client and create a fresh cloud client if needed.
    """
    from harombe.llm.ollama import OllamaClient
    from harombe.privacy.router import PrivacyRouter

    patterns_config = config.patterns

    # Determine local and cloud clients
    local_client: Any
    cloud_client: Any
    if isinstance(base_client, PrivacyRouter):
        local_client = base_client.local_client
        cloud_client = base_client.cloud_client
    elif isinstance(base_client, OllamaClient):
        local_client = base_client
        # Try to create a cloud client
        cloud_client = _try_create_cloud_client(config)
        if cloud_client is None:
            logger.warning(
                "Pattern %r needs a cloud client but none available. "
                "Falling back to local-only.",
                pattern_name,
            )
            cloud_client = local_client  # both point to local
    else:
        local_client = base_client
        cloud_client = base_client

    kwargs: dict[str, Any] = {
        "local_client": local_client,
        "cloud_client": cloud_client,
    }

    # Pattern-specific kwargs
    if pattern_name == "smart_escalation":
        kwargs["confidence_threshold"] = patterns_config.confidence_threshold

    elif pattern_name == "sliding_privacy":
        kwargs["privacy_level"] = patterns_config.privacy_level

    elif pattern_name == "specialized_routing":
        from harombe.coordination.router import TaskComplexity

        threshold_map = {
            "medium": TaskComplexity.MEDIUM,
            "complex": TaskComplexity.COMPLEX,
        }
        kwargs["cloud_threshold"] = threshold_map.get(
            patterns_config.cloud_threshold, TaskComplexity.COMPLEX
        )

    elif pattern_name == "data_minimization":
        kwargs["include_contextual"] = patterns_config.include_contextual

    return kwargs


def _try_create_cloud_client(config: Any) -> Any:
    """Attempt to create a cloud client from config. Returns None on failure."""
    import os

    privacy_config = config.privacy
    api_key = os.environ.get(privacy_config.cloud_llm.api_key_env, "")
    if not api_key:
        return None

    from harombe.llm.anthropic import AnthropicClient

    return AnthropicClient(
        api_key=api_key,
        model=privacy_config.cloud_llm.model,
        max_tokens=privacy_config.cloud_llm.max_tokens,
        timeout=privacy_config.cloud_llm.timeout,
        temperature=config.model.temperature,
    )
