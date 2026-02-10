"""Plugin manifest and metadata models."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class PluginPermissions:
    """Declared permissions for a plugin.

    V1 is primarily declarative — sets dangerous flag and HITL rules.
    Container isolation available for V2 runtime enforcement.
    """

    network_domains: list[str] = field(default_factory=list)
    filesystem: bool = False
    shell: bool = False
    dangerous: bool = False
    container_enabled: bool = False
    resource_limits: dict[str, Any] | None = None


@dataclass
class PluginManifest:
    """Plugin metadata."""

    name: str
    version: str = "0.0.0"
    description: str = ""
    author: str = ""
    permissions: PluginPermissions = field(default_factory=PluginPermissions)
    container_enabled: bool = False
    base_image: str = "python:3.12-slim"
    extra_pip_packages: list[str] = field(default_factory=list)


@dataclass
class LoadedPlugin:
    """A plugin that has been discovered and loaded."""

    manifest: PluginManifest
    source: str  # "entrypoint", "directory", or "file"
    tool_names: list[str] = field(default_factory=list)
    enabled: bool = True
    error: str | None = None
