"""Plugin system for Harombe.

Enables community tool contributions with minimal friction.
Plugins use the same @tool decorator as built-in tools.
"""

from harombe.plugins.loader import PluginLoader
from harombe.plugins.manifest import LoadedPlugin, PluginManifest, PluginPermissions

__all__ = [
    "LoadedPlugin",
    "PluginLoader",
    "PluginManifest",
    "PluginPermissions",
]
