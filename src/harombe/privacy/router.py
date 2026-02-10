"""Privacy router that implements LLMClient protocol.

Routes queries to local or cloud LLM based on sensitivity classification.
From the Agent's perspective, this is just another LLM client.
"""

import logging
import os
from collections.abc import AsyncIterator
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from harombe.config.schema import HarombeConfig

from harombe.llm.anthropic import AnthropicClient
from harombe.llm.client import CompletionResponse, Message
from harombe.llm.ollama import OllamaClient

from .audit import PrivacyAuditLogger
from .classifier import SensitivityClassifier
from .models import (
    PrivacyRoutingDecision,
    RoutingMode,
    RoutingTarget,
    SensitivityLevel,
)
from .sanitizer import ContextSanitizer

logger = logging.getLogger(__name__)

# Routing rules: mode -> sensitivity_level -> target
ROUTING_RULES: dict[RoutingMode, dict[SensitivityLevel, RoutingTarget]] = {
    RoutingMode.LOCAL_ONLY: {
        SensitivityLevel.PUBLIC: RoutingTarget.LOCAL,
        SensitivityLevel.INTERNAL: RoutingTarget.LOCAL,
        SensitivityLevel.CONFIDENTIAL: RoutingTarget.LOCAL,
        SensitivityLevel.RESTRICTED: RoutingTarget.LOCAL,
    },
    RoutingMode.HYBRID: {
        SensitivityLevel.PUBLIC: RoutingTarget.CLOUD,
        SensitivityLevel.INTERNAL: RoutingTarget.CLOUD_SANITIZED,
        SensitivityLevel.CONFIDENTIAL: RoutingTarget.LOCAL,
        SensitivityLevel.RESTRICTED: RoutingTarget.LOCAL,
    },
    RoutingMode.CLOUD_ASSISTED: {
        SensitivityLevel.PUBLIC: RoutingTarget.CLOUD,
        SensitivityLevel.INTERNAL: RoutingTarget.CLOUD,
        SensitivityLevel.CONFIDENTIAL: RoutingTarget.CLOUD_SANITIZED,
        SensitivityLevel.RESTRICTED: RoutingTarget.LOCAL,
    },
}


class PrivacyRouter:
    """LLM client that routes queries based on privacy classification.

    Implements the LLMClient protocol so it can be used as a drop-in
    replacement for OllamaClient or any other LLM client.
    """

    def __init__(
        self,
        local_client: OllamaClient,
        cloud_client: AnthropicClient,
        mode: RoutingMode = RoutingMode.HYBRID,
        classifier: SensitivityClassifier | None = None,
        sanitizer: ContextSanitizer | None = None,
        audit_logger: PrivacyAuditLogger | None = None,
        reconstruct_responses: bool = True,
    ):
        """Initialize privacy router.

        Args:
            local_client: Local LLM client (Ollama)
            cloud_client: Cloud LLM client (Anthropic)
            mode: Routing mode
            classifier: Sensitivity classifier (creates default if None)
            sanitizer: Context sanitizer (creates default if None)
            audit_logger: Privacy audit logger (creates default if None)
            reconstruct_responses: Whether to restore original values in cloud responses
        """
        self.local_client = local_client
        self.cloud_client = cloud_client
        self.mode = mode
        self.classifier = classifier or SensitivityClassifier()
        self.sanitizer = sanitizer or ContextSanitizer()
        self.audit_logger = audit_logger or PrivacyAuditLogger()
        self.reconstruct_responses = reconstruct_responses

        # Stats
        self.routing_stats = {
            "local": 0,
            "cloud": 0,
            "cloud_sanitized": 0,
        }

    def _get_routing_target(self, sensitivity_level: SensitivityLevel) -> RoutingTarget:
        """Look up routing target from rules table.

        Args:
            sensitivity_level: Classified sensitivity level

        Returns:
            Routing target
        """
        return ROUTING_RULES[self.mode][sensitivity_level]

    def _extract_latest_query(self, messages: list[Message]) -> str:
        """Extract the latest user query from messages.

        Args:
            messages: Conversation messages

        Returns:
            Latest user message content
        """
        for msg in reversed(messages):
            if msg.role == "user" and msg.content:
                return msg.content
        return ""

    async def complete(
        self,
        messages: list[Message],
        tools: list[dict[str, Any]] | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> CompletionResponse:
        """Route and complete a request based on privacy classification.

        Args:
            messages: Conversation history
            tools: Available tools in OpenAI function format
            temperature: Sampling temperature override
            max_tokens: Maximum tokens to generate

        Returns:
            CompletionResponse from the appropriate backend
        """
        # 1. Extract latest user query
        query = self._extract_latest_query(messages)

        # 2. Classify sensitivity
        sensitivity = self.classifier.classify(query, messages)

        # 3. Determine routing target
        target = self._get_routing_target(sensitivity.level)

        # 4. Route to appropriate backend
        was_sanitized = False
        sanitized_entity_count = 0

        if target == RoutingTarget.LOCAL:
            response = await self.local_client.complete(messages, tools, temperature, max_tokens)

        elif target == RoutingTarget.CLOUD:
            response = await self.cloud_client.complete(messages, tools, temperature, max_tokens)

        elif target == RoutingTarget.CLOUD_SANITIZED:
            # Sanitize messages before sending to cloud
            sanitized_messages, san_map = self.sanitizer.sanitize_messages(
                messages, sensitivity.detected_entities
            )
            was_sanitized = True
            sanitized_entity_count = len(san_map.replacements)

            response = await self.cloud_client.complete(
                sanitized_messages, tools, temperature, max_tokens
            )

            # Reconstruct original values in response
            if self.reconstruct_responses and san_map.replacements:
                response = self.sanitizer.reconstruct_response(response, san_map)

        else:
            # Fallback to local
            response = await self.local_client.complete(messages, tools, temperature, max_tokens)

        # Update stats
        self.routing_stats[target.value] = self.routing_stats.get(target.value, 0) + 1

        # 5. Audit the decision
        reasoning = (
            f"Mode={self.mode.value}, "
            f"Sensitivity={sensitivity.level.name}, "
            f"Target={target.value}"
        )
        if sensitivity.reasons:
            reasoning += f", Reasons: {'; '.join(sensitivity.reasons[:3])}"

        decision = PrivacyRoutingDecision(
            query_hash=PrivacyRoutingDecision.hash_query(query),
            sensitivity=sensitivity,
            target=target,
            mode=self.mode,
            was_sanitized=was_sanitized,
            sanitized_entity_count=sanitized_entity_count,
            reasoning=reasoning,
        )
        self.audit_logger.log_routing_decision(decision)

        return response

    async def stream_complete(
        self,
        messages: list[Message],
        tools: list[dict[str, Any]] | None = None,
        temperature: float | None = None,
    ) -> AsyncIterator[str]:
        """Stream a completion with privacy routing.

        For stream mode, sanitization reconstruction is not supported
        (placeholders would need to be detected mid-stream). Falls back
        to local if sanitization would be needed.

        Args:
            messages: Conversation history
            tools: Available tools in OpenAI function format
            temperature: Sampling temperature override

        Yields:
            Content chunks as strings
        """
        query = self._extract_latest_query(messages)
        sensitivity = self.classifier.classify(query, messages)
        target = self._get_routing_target(sensitivity.level)

        # For streaming, sanitized cloud is downgraded to local
        # (can't reconstruct placeholders mid-stream)
        if target == RoutingTarget.CLOUD_SANITIZED:
            target = RoutingTarget.LOCAL

        if target == RoutingTarget.CLOUD:
            async for chunk in self.cloud_client.stream_complete(messages, tools, temperature):
                yield chunk
        else:
            async for chunk in self.local_client.stream_complete(messages, tools, temperature):
                yield chunk

    def get_stats(self) -> dict[str, Any]:
        """Get routing statistics.

        Returns:
            Dict with routing counts and current mode
        """
        total = sum(self.routing_stats.values())
        return {
            "mode": self.mode.value,
            "total_requests": total,
            "local_count": self.routing_stats.get("local", 0),
            "cloud_count": self.routing_stats.get("cloud", 0),
            "cloud_sanitized_count": self.routing_stats.get("cloud_sanitized", 0),
        }


def create_privacy_router(config: "HarombeConfig") -> OllamaClient | PrivacyRouter:
    """Factory function that creates the appropriate LLM client.

    If mode is "local-only" (the default), returns a raw OllamaClient
    with zero overhead. Otherwise wraps OllamaClient + AnthropicClient
    in a PrivacyRouter.

    Args:
        config: HarombeConfig instance

    Returns:
        An LLM client (OllamaClient or PrivacyRouter)
    """
    local_client = OllamaClient(
        model=config.model.name,
        base_url=config.ollama.host + "/v1",
        timeout=config.ollama.timeout,
        temperature=config.model.temperature,
    )

    privacy_config = config.privacy

    if privacy_config.mode == RoutingMode.LOCAL_ONLY:  # type: ignore[comparison-overlap]
        return local_client

    # Get API key from environment
    api_key_env = privacy_config.cloud_llm.api_key_env
    api_key = os.environ.get(api_key_env, "")
    if not api_key:
        logger.warning(
            "Cloud LLM API key not found in %s, falling back to local-only mode",
            api_key_env,
        )
        return local_client

    cloud_client = AnthropicClient(
        api_key=api_key,
        model=privacy_config.cloud_llm.model,
        max_tokens=privacy_config.cloud_llm.max_tokens,
        timeout=privacy_config.cloud_llm.timeout,
        temperature=config.model.temperature,
    )

    classifier = SensitivityClassifier(
        custom_patterns=privacy_config.custom_patterns or None,
        custom_restricted_keywords=privacy_config.custom_restricted_keywords or None,
    )

    audit_logger = None
    if privacy_config.audit_routing and config.security.audit.enabled:
        from harombe.security.audit_logger import AuditLogger

        audit_logger = PrivacyAuditLogger(
            AuditLogger(
                db_path=config.security.audit.database,
                retention_days=config.security.audit.retention_days,
                redact_sensitive=config.security.audit.redact_sensitive,
            )
        )
    else:
        audit_logger = PrivacyAuditLogger()

    return PrivacyRouter(
        local_client=local_client,
        cloud_client=cloud_client,
        mode=RoutingMode(privacy_config.mode),
        classifier=classifier,
        audit_logger=audit_logger,
        reconstruct_responses=privacy_config.reconstruct_responses,
    )
