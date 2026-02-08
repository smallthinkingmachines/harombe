"""Pytest configuration and shared fixtures."""

import pytest

from harombe.config.schema import HarombeConfig


@pytest.fixture
def default_config() -> HarombeConfig:
    """Provide a default configuration for tests."""
    return HarombeConfig()


@pytest.fixture
def custom_config() -> HarombeConfig:
    """Provide a custom configuration for tests."""
    config = HarombeConfig()
    config.model.name = "qwen2.5:7b"
    config.agent.max_steps = 5
    config.tools.confirm_dangerous = False
    return config
