"""Plugin discovery and loading system.

Discovers plugins from:
1. Python entry points (harombe.plugins group) — installed via pip
2. Local directory (~/.harombe/plugins/) — drop-in .py files

Uses _TOOLS dict diffing to capture which tools a plugin registers.
"""

from __future__ import annotations

import importlib
import importlib.util
import logging
import sys
from pathlib import Path
from typing import Any

from harombe.plugins.manifest import LoadedPlugin, PluginManifest, PluginPermissions
from harombe.tools.registry import _TOOLS

logger = logging.getLogger(__name__)


class PluginLoader:
    """Discovers and loads plugins from entry points and local directory."""

    def __init__(
        self,
        plugin_dir: str = "~/.harombe/plugins",
        blocked: list[str] | None = None,
    ) -> None:
        self.plugin_dir = Path(plugin_dir).expanduser()
        self.blocked = set(blocked or [])
        self._plugins: dict[str, LoadedPlugin] = {}
        self._container_manager = None

    def set_container_manager(self, manager: Any) -> None:
        """Set the container manager for container-isolated plugins.

        Args:
            manager: PluginContainerManager instance
        """
        self._container_manager = manager

    @property
    def plugins(self) -> dict[str, LoadedPlugin]:
        """Get all discovered plugins."""
        return self._plugins

    def discover_all(self) -> list[LoadedPlugin]:
        """Discover and load plugins from all sources.

        Returns:
            List of loaded plugins
        """
        self._discover_entry_points()
        self._discover_directory()
        return list(self._plugins.values())

    def _discover_entry_points(self) -> None:
        """Discover plugins from Python entry points."""
        try:
            if sys.version_info >= (3, 12):
                from importlib.metadata import entry_points

                eps: Any = entry_points(group="harombe.plugins")
            else:
                from importlib.metadata import entry_points

                all_eps = entry_points()
                eps: Any = all_eps.get("harombe.plugins", [])
        except Exception:
            logger.debug("No entry points found for harombe.plugins")
            return

        for ep in eps:
            if ep.name in self.blocked:
                logger.info("Plugin '%s' is blocked, skipping", ep.name)
                continue

            self._load_entry_point(ep)

    def _load_entry_point(self, ep: Any) -> None:
        """Load a single entry point plugin."""
        # Snapshot current tools
        before = set(_TOOLS.keys())

        try:
            module = ep.load()

            # Get metadata from module
            meta = getattr(module, "PLUGIN_META", {})
            manifest = PluginManifest(
                name=meta.get("name", ep.name),
                version=meta.get("version", "0.0.0"),
                description=meta.get("description", ""),
                author=meta.get("author", ""),
                permissions=_parse_permissions(meta.get("permissions", {})),
            )

            # Detect new tools registered by the plugin
            after = set(_TOOLS.keys())
            new_tools = list(after - before)

            plugin = LoadedPlugin(
                manifest=manifest,
                source="entrypoint",
                tool_names=new_tools,
                enabled=True,
            )
            self._plugins[manifest.name] = plugin
            logger.info(
                "Loaded plugin '%s' (entrypoint) with %d tools",
                manifest.name,
                len(new_tools),
            )

        except Exception as e:
            logger.warning("Failed to load plugin '%s': %s", ep.name, e)
            self._plugins[ep.name] = LoadedPlugin(
                manifest=PluginManifest(name=ep.name),
                source="entrypoint",
                enabled=False,
                error=str(e),
            )

    def _discover_directory(self) -> None:
        """Discover plugins from the local plugin directory."""
        if not self.plugin_dir.exists():
            return

        # Single .py files
        for py_file in sorted(self.plugin_dir.glob("*.py")):
            if py_file.name.startswith("_"):
                continue

            plugin_name = py_file.stem
            if plugin_name in self.blocked:
                logger.info("Plugin '%s' is blocked, skipping", plugin_name)
                continue

            self._load_file_plugin(py_file, plugin_name)

        # Subdirectories with plugin.toml
        for subdir in sorted(self.plugin_dir.iterdir()):
            if not subdir.is_dir() or subdir.name.startswith("_"):
                continue

            toml_path = subdir / "plugin.toml"
            init_path = subdir / "__init__.py"
            if not (toml_path.exists() or init_path.exists()):
                continue

            if subdir.name in self.blocked:
                logger.info("Plugin '%s' is blocked, skipping", subdir.name)
                continue

            self._load_dir_plugin(subdir)

    def _load_file_plugin(self, path: Path, name: str) -> None:
        """Load a single .py file plugin."""
        before = set(_TOOLS.keys())

        try:
            # Quick check: read PLUGIN_META to see if container_enabled
            # We still need to exec the module to get the meta first for
            # non-container plugins. For container plugins, we parse meta
            # but skip exec_module and delegate to container manager.
            spec = importlib.util.spec_from_file_location(f"harombe_plugin_{name}", path)
            if spec is None or spec.loader is None:
                raise ImportError(f"Cannot create module spec for {path}")

            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            meta = getattr(module, "PLUGIN_META", {})
            manifest = PluginManifest(
                name=meta.get("name", name),
                version=meta.get("version", "0.0.0"),
                description=meta.get("description", ""),
                author=meta.get("author", ""),
                permissions=_parse_permissions(meta.get("permissions", {})),
                container_enabled=meta.get("container_enabled", False),
                base_image=meta.get("base_image", "python:3.12-slim"),
                extra_pip_packages=meta.get("extra_pip_packages", []),
            )

            # Check if this plugin should run in a container
            if manifest.container_enabled and self._container_manager:
                plugin = self._start_container_plugin(manifest, str(path))
                self._plugins[manifest.name] = plugin
                return

            after = set(_TOOLS.keys())
            new_tools = list(after - before)

            plugin = LoadedPlugin(
                manifest=manifest,
                source="file",
                tool_names=new_tools,
                enabled=True,
            )
            self._plugins[manifest.name] = plugin
            logger.info(
                "Loaded plugin '%s' (file) with %d tools",
                manifest.name,
                len(new_tools),
            )

        except Exception as e:
            logger.warning("Failed to load plugin '%s' from %s: %s", name, path, e)
            self._plugins[name] = LoadedPlugin(
                manifest=PluginManifest(name=name),
                source="file",
                enabled=False,
                error=str(e),
            )

    def _load_dir_plugin(self, path: Path) -> None:
        """Load a directory-based plugin."""
        name = path.name
        before = set(_TOOLS.keys())

        try:
            # Add parent to sys.path temporarily
            parent = str(path.parent)
            if parent not in sys.path:
                sys.path.insert(0, parent)

            module = importlib.import_module(name)

            meta = getattr(module, "PLUGIN_META", {})
            manifest = PluginManifest(
                name=meta.get("name", name),
                version=meta.get("version", "0.0.0"),
                description=meta.get("description", ""),
                author=meta.get("author", ""),
                permissions=_parse_permissions(meta.get("permissions", {})),
                container_enabled=meta.get("container_enabled", False),
                base_image=meta.get("base_image", "python:3.12-slim"),
                extra_pip_packages=meta.get("extra_pip_packages", []),
            )

            # Check if this plugin should run in a container
            if manifest.container_enabled and self._container_manager:
                plugin = self._start_container_plugin(manifest, str(path))
                self._plugins[manifest.name] = plugin
                return

            after = set(_TOOLS.keys())
            new_tools = list(after - before)

            plugin = LoadedPlugin(
                manifest=manifest,
                source="directory",
                tool_names=new_tools,
                enabled=True,
            )
            self._plugins[manifest.name] = plugin
            logger.info(
                "Loaded plugin '%s' (directory) with %d tools",
                manifest.name,
                len(new_tools),
            )

        except Exception as e:
            logger.warning("Failed to load plugin '%s' from %s: %s", name, path, e)
            self._plugins[name] = LoadedPlugin(
                manifest=PluginManifest(name=name),
                source="directory",
                enabled=False,
                error=str(e),
            )

    def get_plugin(self, name: str) -> LoadedPlugin | None:
        """Get a plugin by name."""
        return self._plugins.get(name)

    def enable_plugin(self, name: str) -> bool:
        """Enable a plugin."""
        plugin = self._plugins.get(name)
        if plugin:
            plugin.enabled = True
            return True
        return False

    def disable_plugin(self, name: str) -> bool:
        """Disable a plugin."""
        plugin = self._plugins.get(name)
        if plugin:
            plugin.enabled = False
            return True
        return False

    def _start_container_plugin(self, manifest: PluginManifest, plugin_path: str) -> LoadedPlugin:
        """Start a plugin in a container and return the LoadedPlugin.

        Args:
            manifest: Plugin manifest
            plugin_path: Path to the plugin source

        Returns:
            LoadedPlugin with source="container"
        """
        import asyncio

        from harombe.plugins.container import PluginContainerConfig

        config = PluginContainerConfig(
            plugin_name=manifest.name,
            plugin_path=plugin_path,
            base_image=manifest.base_image,
            memory_mb=manifest.permissions.resource_limits.get("memory_mb", 256)
            if manifest.permissions.resource_limits
            else 256,
            cpu_cores=manifest.permissions.resource_limits.get("cpu_cores", 0.5)
            if manifest.permissions.resource_limits
            else 0.5,
            network_domains=manifest.permissions.network_domains,
            extra_pip_packages=manifest.extra_pip_packages,
        )

        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # We're inside an async context; store reference to track the task
                if self._container_manager is not None:
                    task = asyncio.ensure_future(self._container_manager.start_plugin(config))
                    task.add_done_callback(lambda t: t.result() if not t.cancelled() else None)
            else:
                if self._container_manager is not None:
                    loop.run_until_complete(self._container_manager.start_plugin(config))
        except RuntimeError:
            # No event loop; create one
            if self._container_manager is not None:
                asyncio.run(self._container_manager.start_plugin(config))

        plugin = LoadedPlugin(
            manifest=manifest,
            source="container",
            enabled=True,
        )

        logger.info(
            "Loaded plugin '%s' (container) with base image '%s'",
            manifest.name,
            manifest.base_image,
        )
        return plugin


def _parse_permissions(data: dict[str, Any]) -> PluginPermissions:
    """Parse permissions dict into PluginPermissions."""
    return PluginPermissions(
        network_domains=data.get("network_domains", []),
        filesystem=data.get("filesystem", False),
        shell=data.get("shell", False),
        dangerous=data.get("dangerous", False),
        container_enabled=data.get("container_enabled", False),
        resource_limits=data.get("resource_limits"),
    )
