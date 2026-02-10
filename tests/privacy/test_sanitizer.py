"""Tests for the context sanitizer."""

import pytest

from harombe.llm.client import CompletionResponse, Message
from harombe.privacy.models import PIIEntity
from harombe.privacy.sanitizer import ContextSanitizer


@pytest.fixture
def sanitizer():
    return ContextSanitizer()


class TestContextSanitizer:
    def test_sanitize_email(self, sanitizer):
        entities = [
            PIIEntity(type="email", value="john@example.com", start=0, end=16, confidence=0.9)
        ]
        messages = [Message(role="user", content="john@example.com needs help")]
        sanitized, san_map = sanitizer.sanitize_messages(messages, entities)

        assert "john@example.com" not in sanitized[0].content
        assert "[EMAIL_1]" in sanitized[0].content
        assert san_map.replacements["[EMAIL_1]"] == "john@example.com"

    def test_consistent_placeholders(self, sanitizer):
        entities = [
            PIIEntity(type="email", value="john@example.com", start=0, end=16, confidence=0.9),
            PIIEntity(type="email", value="john@example.com", start=30, end=46, confidence=0.9),
        ]
        messages = [Message(role="user", content="john@example.com said to email john@example.com")]
        sanitized, san_map = sanitizer.sanitize_messages(messages, entities)

        # Same value should get same placeholder
        assert sanitized[0].content.count("[EMAIL_1]") == 2
        assert len(san_map.replacements) == 1

    def test_different_values_get_different_placeholders(self, sanitizer):
        entities = [
            PIIEntity(type="email", value="a@example.com", start=0, end=13, confidence=0.9),
            PIIEntity(type="email", value="b@example.com", start=20, end=33, confidence=0.9),
        ]
        messages = [Message(role="user", content="a@example.com and b@example.com")]
        sanitized, san_map = sanitizer.sanitize_messages(messages, entities)

        assert "[EMAIL_1]" in sanitized[0].content
        assert "[EMAIL_2]" in sanitized[0].content
        assert len(san_map.replacements) == 2

    def test_multiple_entity_types(self, sanitizer):
        entities = [
            PIIEntity(type="email", value="john@example.com", start=0, end=16, confidence=0.9),
            PIIEntity(type="phone", value="555-123-4567", start=20, end=32, confidence=0.9),
            PIIEntity(type="ssn", value="123-45-6789", start=40, end=51, confidence=0.9),
        ]
        messages = [
            Message(
                role="user",
                content="john@example.com at 555-123-4567 has SSN 123-45-6789",
            )
        ]
        sanitized, _san_map = sanitizer.sanitize_messages(messages, entities)

        assert "[EMAIL_1]" in sanitized[0].content
        assert "[PHONE_1]" in sanitized[0].content
        assert "[SSN_1]" in sanitized[0].content

    def test_credential_type_handling(self, sanitizer):
        entities = [
            PIIEntity(
                type="credential:api_key",
                value="sk-1234567890",
                start=0,
                end=12,
                confidence=0.95,
            )
        ]
        messages = [Message(role="user", content="sk-1234567890 is my key")]
        sanitized, _san_map = sanitizer.sanitize_messages(messages, entities)

        assert "sk-1234567890" not in sanitized[0].content
        assert "[API_KEY_1]" in sanitized[0].content

    def test_sanitize_multiple_messages(self, sanitizer):
        entities = [
            PIIEntity(type="email", value="john@example.com", start=0, end=16, confidence=0.9),
        ]
        messages = [
            Message(role="user", content="Contact john@example.com"),
            Message(role="assistant", content="I'll email john@example.com"),
            Message(role="user", content="Also cc john@example.com"),
        ]
        sanitized, _san_map = sanitizer.sanitize_messages(messages, entities)

        for msg in sanitized:
            assert "john@example.com" not in msg.content

    def test_reconstruct_response(self, sanitizer):
        entities = [
            PIIEntity(type="email", value="john@example.com", start=0, end=16, confidence=0.9),
        ]
        messages = [Message(role="user", content="john@example.com")]
        _, san_map = sanitizer.sanitize_messages(messages, entities)

        cloud_response = CompletionResponse(
            content="I will contact [EMAIL_1] right away.",
        )
        reconstructed = sanitizer.reconstruct_response(cloud_response, san_map)

        assert "john@example.com" in reconstructed.content
        assert "[EMAIL_1]" not in reconstructed.content

    def test_reconstruct_preserves_tool_calls(self, sanitizer):
        from harombe.llm.client import ToolCall

        entities = [
            PIIEntity(type="email", value="test@test.com", start=0, end=13, confidence=0.9),
        ]
        messages = [Message(role="user", content="test@test.com")]
        _, san_map = sanitizer.sanitize_messages(messages, entities)

        tool_calls = [ToolCall(id="1", name="send_email", arguments={"to": "someone"})]
        response = CompletionResponse(
            content="Sending to [EMAIL_1]",
            tool_calls=tool_calls,
            finish_reason="tool_calls",
        )
        reconstructed = sanitizer.reconstruct_response(response, san_map)

        assert reconstructed.tool_calls == tool_calls
        assert reconstructed.finish_reason == "tool_calls"

    def test_preserves_message_metadata(self, sanitizer):
        entities = [
            PIIEntity(type="email", value="x@y.com", start=0, end=7, confidence=0.9),
        ]
        messages = [
            Message(
                role="tool",
                content="x@y.com",
                tool_call_id="tc_1",
                name="lookup",
            )
        ]
        sanitized, _ = sanitizer.sanitize_messages(messages, entities)

        assert sanitized[0].role == "tool"
        assert sanitized[0].tool_call_id == "tc_1"
        assert sanitized[0].name == "lookup"

    def test_reset(self, sanitizer):
        entities = [
            PIIEntity(type="email", value="a@b.com", start=0, end=7, confidence=0.9),
        ]
        messages = [Message(role="user", content="a@b.com")]
        sanitizer.sanitize_messages(messages, entities)

        sanitizer.reset()

        # After reset, same value gets [EMAIL_1] again (counter reset)
        sanitized, _san_map = sanitizer.sanitize_messages(messages, entities)
        assert "[EMAIL_1]" in sanitized[0].content

    def test_empty_entities(self, sanitizer):
        messages = [Message(role="user", content="Hello world")]
        sanitized, san_map = sanitizer.sanitize_messages(messages, [])

        assert sanitized[0].content == "Hello world"
        assert len(san_map.replacements) == 0

    def test_longer_values_replaced_first(self, sanitizer):
        """Ensure longer values are replaced before shorter ones to avoid partial matches."""
        entities = [
            PIIEntity(type="email", value="john@example.com", start=0, end=16, confidence=0.9),
            PIIEntity(type="email", value="john@example", start=0, end=12, confidence=0.8),
        ]
        messages = [Message(role="user", content="Contact john@example.com")]
        sanitized, _san_map = sanitizer.sanitize_messages(messages, entities)

        # The longer value should be replaced cleanly
        assert "john@example.com" not in sanitized[0].content
