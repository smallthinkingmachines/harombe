"""Plugin system for Harombe.

Enables community tool contributions with minimal friction.
Plugins use the same @tool decorator as built-in tools.
"""

from harombe.plugins.container import (
    PluginContainerConfig,
    PluginContainerManager,
    RunningPluginContainer,
)
from harombe.plugins.loader import PluginLoader
from harombe.plugins.manifest import LoadedPlugin, PluginManifest, PluginPermissions
from harombe.plugins.sandbox import create_container_config_from_permissions

__all__ = [
    "LoadedPlugin",
    "PluginContainerConfig",
    "PluginContainerManager",
    "PluginLoader",
    "PluginManifest",
    "PluginPermissions",
    "RunningPluginContainer",
    "create_container_config_from_permissions",
]
