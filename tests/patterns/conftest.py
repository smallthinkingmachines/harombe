"""Shared fixtures for pattern tests."""

from unittest.mock import AsyncMock

import pytest

from harombe.llm.client import CompletionResponse


@pytest.fixture
def mock_local():
    """AsyncMock local LLM client returning 'local response'."""
    client = AsyncMock()
    client.complete = AsyncMock(return_value=CompletionResponse(content="local response"))
    client.stream_complete = AsyncMock()
    return client


@pytest.fixture
def mock_cloud():
    """AsyncMock cloud LLM client returning 'cloud response'."""
    client = AsyncMock()
    client.complete = AsyncMock(return_value=CompletionResponse(content="cloud response"))
    client.stream_complete = AsyncMock()
    return client
