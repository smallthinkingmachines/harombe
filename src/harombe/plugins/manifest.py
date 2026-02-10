"""Plugin manifest and metadata models."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class PluginPermissions:
    """Declared permissions for a plugin.

    V1 is primarily declarative — sets dangerous flag and HITL rules.
    Runtime enforcement planned for V2.
    """

    network_domains: list[str] = field(default_factory=list)
    filesystem: bool = False
    shell: bool = False
    dangerous: bool = False


@dataclass
class PluginManifest:
    """Plugin metadata."""

    name: str
    version: str = "0.0.0"
    description: str = ""
    author: str = ""
    permissions: PluginPermissions = field(default_factory=PluginPermissions)


@dataclass
class LoadedPlugin:
    """A plugin that has been discovered and loaded."""

    manifest: PluginManifest
    source: str  # "entrypoint", "directory", or "file"
    tool_names: list[str] = field(default_factory=list)
    enabled: bool = True
    error: str | None = None
