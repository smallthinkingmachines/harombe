"""Tests for configuration loading and validation."""

from pathlib import Path
from tempfile import TemporaryDirectory

import pytest
import yaml

from harombe.config.loader import ConfigError, load_config, save_config
from harombe.config.schema import HarombeConfig


def test_default_config():
    """Test that default config has expected values."""
    config = HarombeConfig()

    assert config.model.name == "auto"
    assert config.model.quantization == "Q4_K_M"
    assert config.model.context_length == 8192
    assert config.model.temperature == 0.7

    assert config.ollama.host == "http://localhost:11434"
    assert config.ollama.timeout == 120

    assert config.agent.max_steps == 10
    assert "harombe" in config.agent.system_prompt

    assert config.tools.shell is True
    assert config.tools.filesystem is True
    assert config.tools.web_search is True
    assert config.tools.confirm_dangerous is True

    assert config.server.host == "127.0.0.1"
    assert config.server.port == 8000


def test_load_config_nonexistent_returns_defaults():
    """Test that loading a nonexistent config returns defaults."""
    with TemporaryDirectory() as tmpdir:
        config_path = Path(tmpdir) / "nonexistent.yaml"
        config = load_config(config_path)

        assert config.model.name == "auto"
        assert config.agent.max_steps == 10


def test_load_config_empty_file_returns_defaults():
    """Test that an empty config file returns defaults."""
    with TemporaryDirectory() as tmpdir:
        config_path = Path(tmpdir) / "empty.yaml"
        config_path.write_text("")

        config = load_config(config_path)
        assert config.model.name == "auto"


def test_load_config_partial_override():
    """Test that partial config overrides only specified values."""
    with TemporaryDirectory() as tmpdir:
        config_path = Path(tmpdir) / "partial.yaml"

        partial_config = {"model": {"name": "qwen2.5:7b", "temperature": 0.5}}

        with open(config_path, "w") as f:
            yaml.safe_dump(partial_config, f)

        config = load_config(config_path)

        # Overridden values
        assert config.model.name == "qwen2.5:7b"
        assert config.model.temperature == 0.5

        # Default values
        assert config.model.quantization == "Q4_K_M"
        assert config.agent.max_steps == 10


def test_load_config_invalid_yaml():
    """Test that invalid YAML raises ConfigError."""
    with TemporaryDirectory() as tmpdir:
        config_path = Path(tmpdir) / "invalid.yaml"
        config_path.write_text("{ invalid yaml: [")

        with pytest.raises(ConfigError, match="Invalid YAML"):
            load_config(config_path)


def test_load_config_validation_error():
    """Test that invalid values raise ConfigError."""
    with TemporaryDirectory() as tmpdir:
        config_path = Path(tmpdir) / "invalid_values.yaml"

        invalid_config = {"model": {"temperature": 5.0}}  # temperature > 2.0

        with open(config_path, "w") as f:
            yaml.safe_dump(invalid_config, f)

        with pytest.raises(ConfigError, match="validation failed"):
            load_config(config_path)


def test_save_and_load_config():
    """Test saving and loading config roundtrip."""
    with TemporaryDirectory() as tmpdir:
        config_path = Path(tmpdir) / "test.yaml"

        # Create custom config
        original = HarombeConfig()
        original.model.name = "qwen2.5:14b"
        original.model.temperature = 0.9
        original.agent.max_steps = 15

        # Save
        save_config(original, config_path)

        # Load
        loaded = load_config(config_path)

        assert loaded.model.name == "qwen2.5:14b"
        assert loaded.model.temperature == 0.9
        assert loaded.agent.max_steps == 15


def test_save_config_creates_directory():
    """Test that save_config creates parent directory if needed."""
    with TemporaryDirectory() as tmpdir:
        config_path = Path(tmpdir) / "nested" / "dir" / "config.yaml"

        config = HarombeConfig()
        save_config(config, config_path)

        assert config_path.exists()
        assert config_path.parent.is_dir()
