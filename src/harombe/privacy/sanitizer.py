"""Context sanitizer for privacy-preserving cloud routing.

Replaces detected PII/credentials with typed placeholders before sending
to cloud LLM, and reconstructs responses by restoring original values.
"""

from typing import ClassVar

from harombe.llm.client import CompletionResponse, Message

from .models import PIIEntity, SanitizationMap


class ContextSanitizer:
    """Sanitizes messages by replacing sensitive entities with placeholders."""

    # Placeholder format: [TYPE_N] e.g. [EMAIL_1], [SSN_2]
    TYPE_LABELS: ClassVar[dict[str, str]] = {
        "email": "EMAIL",
        "ssn": "SSN",
        "phone": "PHONE",
        "ip_address": "IP",
        "credit_card": "CARD",
        "date_of_birth": "DOB",
        "address": "ADDR",
    }

    def __init__(self) -> None:
        self._value_to_placeholder: dict[str, str] = {}
        self._type_counters: dict[str, int] = {}

    def _get_placeholder(self, entity: PIIEntity) -> str:
        """Get or create a consistent placeholder for an entity value.

        Same value always maps to the same placeholder within a session.

        Args:
            entity: The PII entity to create a placeholder for

        Returns:
            Placeholder string like "[EMAIL_1]"
        """
        if entity.value in self._value_to_placeholder:
            return self._value_to_placeholder[entity.value]

        # Determine type label
        base_type = entity.type.split(":")[-1]  # Handle "credential:api_key" -> "api_key"
        label = self.TYPE_LABELS.get(base_type, base_type.upper())

        # Increment counter for this type
        self._type_counters[label] = self._type_counters.get(label, 0) + 1
        placeholder = f"[{label}_{self._type_counters[label]}]"

        self._value_to_placeholder[entity.value] = placeholder
        return placeholder

    def sanitize_messages(
        self,
        messages: list[Message],
        entities: list[PIIEntity],
    ) -> tuple[list[Message], SanitizationMap]:
        """Sanitize a list of messages by replacing detected entities.

        Args:
            messages: Conversation messages to sanitize
            entities: PII entities detected by the classifier

        Returns:
            Tuple of (sanitized messages, sanitization map for reconstruction)
        """
        san_map = SanitizationMap()

        # Build placeholder map from entities
        for entity in entities:
            placeholder = self._get_placeholder(entity)
            san_map.add(placeholder, entity.value)

        # Sanitize each message
        sanitized = []
        for msg in messages:
            new_content = self._replace_entities(msg.content, san_map)
            sanitized.append(
                Message(
                    role=msg.role,
                    content=new_content,
                    tool_calls=msg.tool_calls,
                    tool_call_id=msg.tool_call_id,
                    name=msg.name,
                )
            )

        return sanitized, san_map

    def _replace_entities(self, text: str, san_map: SanitizationMap) -> str:
        """Replace all known entity values in text with placeholders.

        Args:
            text: Text to sanitize
            san_map: Mapping of placeholders to original values

        Returns:
            Sanitized text
        """
        result = text
        # Sort by value length descending to avoid partial replacements
        for placeholder, original in sorted(
            san_map.replacements.items(),
            key=lambda item: len(item[1]),
            reverse=True,
        ):
            result = result.replace(original, placeholder)
        return result

    def reconstruct_response(
        self,
        response: CompletionResponse,
        san_map: SanitizationMap,
    ) -> CompletionResponse:
        """Restore original values in a cloud LLM response.

        Args:
            response: Cloud LLM response with placeholders
            san_map: Sanitization map from sanitize_messages()

        Returns:
            Response with placeholders replaced by original values
        """
        content = response.content
        for placeholder, original in san_map.replacements.items():
            content = content.replace(placeholder, original)

        return CompletionResponse(
            content=content,
            tool_calls=response.tool_calls,
            finish_reason=response.finish_reason,
        )

    def reset(self) -> None:
        """Reset placeholder state for a new conversation."""
        self._value_to_placeholder.clear()
        self._type_counters.clear()
