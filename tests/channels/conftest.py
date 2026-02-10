"""Shared fixtures for channel tests."""

from unittest.mock import AsyncMock

import pytest


@pytest.fixture
def mock_agent():
    """Create a mock agent that returns a fixed response."""
    agent = AsyncMock()
    agent.run = AsyncMock(return_value="Hello from the agent!")
    return agent
