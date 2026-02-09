"""Utility functions for memory management."""

import json

from harombe.llm.client import Message


def estimate_tokens(message: Message) -> int:
    """Estimate token count for a message.

    Uses a simple heuristic: ~4 characters per token.
    For more accurate counting, consider using tiktoken library.

    Args:
        message: Message to estimate tokens for

    Returns:
        Estimated token count
    """
    text = message.content or ""

    # Add tool call overhead
    if message.tool_calls:
        for tc in message.tool_calls:
            # Serialize tool call arguments
            text += json.dumps(tc.arguments)

    # Add tool result overhead for tool messages
    if message.role == "tool" and message.content:
        # Tool results can be large, count them
        text += message.content

    # Rough estimate: 4 chars per token
    return len(text) // 4


def estimate_total_tokens(messages: list[Message]) -> int:
    """Estimate total token count for a list of messages.

    Args:
        messages: List of messages

    Returns:
        Total estimated token count
    """
    return sum(estimate_tokens(msg) for msg in messages)
