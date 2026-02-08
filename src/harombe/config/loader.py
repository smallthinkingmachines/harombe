"""Configuration loading and validation."""

from pathlib import Path
from typing import Optional, Union

import yaml
from pydantic import ValidationError

from harombe.config.schema import HarombeConfig


DEFAULT_CONFIG_PATH = Path.home() / ".harombe" / "harombe.yaml"


class ConfigError(Exception):
    """Configuration loading or validation error."""


def load_config(path: Optional[Path] = None) -> HarombeConfig:
    """Load and validate Harombe configuration from YAML file.

    Args:
        path: Path to config file. If None, tries default location.
              If file doesn't exist, returns default config.

    Returns:
        Validated configuration object

    Raises:
        ConfigError: If config file exists but is invalid
    """
    if path is None:
        path = DEFAULT_CONFIG_PATH

    # Zero-config mode: if file doesn't exist, use all defaults
    if not path.exists():
        return HarombeConfig()

    try:
        with open(path, "r") as f:
            config_data = yaml.safe_load(f)

        # Handle empty file
        if config_data is None:
            return HarombeConfig()

        return HarombeConfig(**config_data)

    except yaml.YAMLError as e:
        raise ConfigError(f"Invalid YAML in {path}: {e}") from e
    except ValidationError as e:
        raise ConfigError(f"Configuration validation failed: {e}") from e
    except Exception as e:
        raise ConfigError(f"Failed to load config from {path}: {e}") from e


def save_config(config: HarombeConfig, path: Optional[Union[str, Path]] = None) -> None:
    """Save configuration to YAML file.

    Args:
        config: Configuration object to save
        path: Destination path (string or Path object). If None, uses default location.
    """
    if path is None:
        path = DEFAULT_CONFIG_PATH
    elif isinstance(path, str):
        path = Path(path)

    # Ensure directory exists
    path.parent.mkdir(parents=True, exist_ok=True)

    # Convert to dict and write YAML
    config_dict = config.model_dump()

    with open(path, "w") as f:
        yaml.safe_dump(config_dict, f, default_flow_style=False, sort_keys=False)
