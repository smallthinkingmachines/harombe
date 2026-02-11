"""Tests for plugin discovery and loading."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from harombe.plugins.loader import PluginLoader, _parse_permissions
from harombe.plugins.manifest import PluginPermissions
from harombe.tools.registry import _TOOLS


@pytest.fixture(autouse=True)
def _clean_tools():
    """Clean tool registry between tests."""
    before = dict(_TOOLS)
    yield
    _TOOLS.clear()
    _TOOLS.update(before)


class TestPluginLoader:
    def test_init(self, tmp_path: Path):
        loader = PluginLoader(plugin_dir=str(tmp_path))
        assert loader.plugins == {}

    def test_init_blocked_set(self, tmp_path: Path):
        loader = PluginLoader(plugin_dir=str(tmp_path), blocked=["bad", "evil"])
        assert loader.blocked == {"bad", "evil"}
        assert loader.plugin_dir == tmp_path

    def test_init_expands_user(self):
        loader = PluginLoader(plugin_dir="~/my_plugins")
        assert "~" not in str(loader.plugin_dir)
        assert loader.plugin_dir == Path("~/my_plugins").expanduser()

    def test_empty_directory(self, tmp_path: Path):
        loader = PluginLoader(plugin_dir=str(tmp_path))
        plugins = loader.discover_all()
        assert plugins == []

    def test_nonexistent_directory(self, tmp_path: Path):
        loader = PluginLoader(plugin_dir=str(tmp_path / "nonexistent"))
        plugins = loader.discover_all()
        assert plugins == []

    def test_load_simple_file_plugin(self, tmp_path: Path):
        # Create a simple plugin file
        plugin_file = tmp_path / "hello_plugin.py"
        plugin_file.write_text('''
PLUGIN_META = {
    "name": "hello",
    "version": "1.0.0",
    "description": "A hello world plugin",
}

from harombe.tools.registry import tool

@tool(description="Say hello")
async def hello_world(name: str = "World") -> str:
    """Say hello to someone.

    name: Name to greet
    """
    return f"Hello, {name}!"
''')

        loader = PluginLoader(plugin_dir=str(tmp_path))
        plugins = loader.discover_all()

        assert len(plugins) == 1
        plugin = plugins[0]
        assert plugin.manifest.name == "hello"
        assert plugin.manifest.version == "1.0.0"
        assert plugin.source == "file"
        assert plugin.enabled is True
        assert "hello_world" in plugin.tool_names

    def test_blocked_plugin_skipped(self, tmp_path: Path):
        plugin_file = tmp_path / "blocked.py"
        plugin_file.write_text("PLUGIN_META = {'name': 'blocked'}")

        loader = PluginLoader(plugin_dir=str(tmp_path), blocked=["blocked"])
        plugins = loader.discover_all()
        assert len(plugins) == 0

    def test_broken_plugin_reports_error(self, tmp_path: Path):
        plugin_file = tmp_path / "broken.py"
        plugin_file.write_text("raise RuntimeError('intentional error')")

        loader = PluginLoader(plugin_dir=str(tmp_path))
        plugins = loader.discover_all()

        assert len(plugins) == 1
        plugin = plugins[0]
        assert plugin.enabled is False
        assert plugin.error is not None
        assert "intentional error" in plugin.error

    def test_underscore_files_ignored(self, tmp_path: Path):
        (tmp_path / "_internal.py").write_text("PLUGIN_META = {'name': 'internal'}")
        (tmp_path / "__init__.py").write_text("")

        loader = PluginLoader(plugin_dir=str(tmp_path))
        plugins = loader.discover_all()
        assert len(plugins) == 0

    def test_enable_disable_plugin(self, tmp_path: Path):
        plugin_file = tmp_path / "toggle.py"
        plugin_file.write_text("PLUGIN_META = {'name': 'toggle'}")

        loader = PluginLoader(plugin_dir=str(tmp_path))
        loader.discover_all()

        assert loader.get_plugin("toggle").enabled is True

        loader.disable_plugin("toggle")
        assert loader.get_plugin("toggle").enabled is False

        loader.enable_plugin("toggle")
        assert loader.get_plugin("toggle").enabled is True

    def test_enable_nonexistent_returns_false(self):
        loader = PluginLoader(plugin_dir="/nonexistent")
        assert loader.enable_plugin("nope") is False

    def test_disable_nonexistent_returns_false(self):
        loader = PluginLoader(plugin_dir="/nonexistent")
        assert loader.disable_plugin("nope") is False

    def test_get_nonexistent_plugin(self):
        loader = PluginLoader(plugin_dir="/nonexistent")
        assert loader.get_plugin("nope") is None

    def test_plugin_without_meta(self, tmp_path: Path):
        plugin_file = tmp_path / "nometa.py"
        plugin_file.write_text("# No PLUGIN_META, just code\nx = 1")

        loader = PluginLoader(plugin_dir=str(tmp_path))
        plugins = loader.discover_all()

        assert len(plugins) == 1
        assert plugins[0].manifest.name == "nometa"
        assert plugins[0].enabled is True

    def test_discover_dir_plugin(self, tmp_path: Path):
        """Directory plugin with __init__.py containing PLUGIN_META."""
        subdir = tmp_path / "my_dir_plugin"
        subdir.mkdir()
        (subdir / "__init__.py").write_text(
            'PLUGIN_META = {"name": "dir_plugin", "version": "2.0.0",'
            ' "description": "Dir plugin"}\n'
        )

        loader = PluginLoader(plugin_dir=str(tmp_path))
        plugins = loader.discover_all()

        dir_plugins = [p for p in plugins if p.source == "directory"]
        assert len(dir_plugins) == 1
        assert dir_plugins[0].manifest.name == "dir_plugin"
        assert dir_plugins[0].manifest.version == "2.0.0"
        assert dir_plugins[0].enabled is True

    def test_discover_dir_plugin_with_toml(self, tmp_path: Path):
        """Directory plugin discovered via plugin.toml presence."""
        subdir = tmp_path / "toml_plugin"
        subdir.mkdir()
        (subdir / "plugin.toml").write_text('[plugin]\nname = "toml_plugin"\n')
        (subdir / "__init__.py").write_text(
            'PLUGIN_META = {"name": "toml_plugin", "version": "1.0.0",' ' "description": "Toml"}\n'
        )

        loader = PluginLoader(plugin_dir=str(tmp_path))
        plugins = loader.discover_all()

        dir_plugins = [p for p in plugins if p.source == "directory"]
        assert len(dir_plugins) == 1
        assert dir_plugins[0].manifest.name == "toml_plugin"

    def test_discover_dir_plugin_skips_underscore(self, tmp_path: Path):
        """Directories starting with _ are skipped."""
        subdir = tmp_path / "_private_plugin"
        subdir.mkdir()
        (subdir / "__init__.py").write_text(
            'PLUGIN_META = {"name": "private", "version": "1.0.0"}\n'
        )

        loader = PluginLoader(plugin_dir=str(tmp_path))
        plugins = loader.discover_all()
        dir_plugins = [p for p in plugins if p.manifest.name == "private"]
        assert len(dir_plugins) == 0

    def test_discover_dir_plugin_blocked(self, tmp_path: Path):
        """Blocked directory plugins are skipped."""
        subdir = tmp_path / "blocked_dir"
        subdir.mkdir()
        (subdir / "__init__.py").write_text(
            'PLUGIN_META = {"name": "blocked_dir", "version": "1.0.0"}\n'
        )

        loader = PluginLoader(plugin_dir=str(tmp_path), blocked=["blocked_dir"])
        plugins = loader.discover_all()
        dir_plugins = [p for p in plugins if p.manifest.name == "blocked_dir"]
        assert len(dir_plugins) == 0

    def test_discover_dir_plugin_error(self, tmp_path: Path):
        """Directory plugin with import error is loaded as disabled."""
        subdir = tmp_path / "bad_dir"
        subdir.mkdir()
        (subdir / "__init__.py").write_text("raise ImportError('bad dep')\n")

        loader = PluginLoader(plugin_dir=str(tmp_path))
        plugins = loader.discover_all()

        dir_plugins = [p for p in plugins if p.source == "directory"]
        assert len(dir_plugins) == 1
        assert dir_plugins[0].enabled is False
        assert dir_plugins[0].error is not None

    def test_discover_dir_without_init_or_toml_skipped(self, tmp_path: Path):
        """Directories without __init__.py or plugin.toml are skipped."""
        subdir = tmp_path / "plain_dir"
        subdir.mkdir()
        (subdir / "some_file.py").write_text("x = 1\n")

        loader = PluginLoader(plugin_dir=str(tmp_path))
        plugins = loader.discover_all()
        assert len(plugins) == 0

    def test_set_container_manager(self, tmp_path: Path):
        loader = PluginLoader(plugin_dir=str(tmp_path))
        assert loader._container_manager is None

        mock_manager = MagicMock()
        loader.set_container_manager(mock_manager)
        assert loader._container_manager is mock_manager

    def test_discover_entry_points(self, tmp_path: Path):
        """Entry point discovery calls importlib.metadata.entry_points."""
        mock_ep = MagicMock()
        mock_ep.name = "ep_plugin"
        mock_module = MagicMock()
        mock_module.PLUGIN_META = {
            "name": "ep_plugin",
            "version": "1.0.0",
            "description": "Entry point plugin",
        }
        mock_ep.load.return_value = mock_module

        with patch(
            "harombe.plugins.loader.importlib.metadata.entry_points",
            return_value=[mock_ep],
        ):
            loader = PluginLoader(plugin_dir=str(tmp_path))
            plugins = loader.discover_all()

        ep_plugins = [p for p in plugins if p.source == "entrypoint"]
        assert len(ep_plugins) == 1
        assert ep_plugins[0].manifest.name == "ep_plugin"
        assert ep_plugins[0].enabled is True

    def test_discover_entry_points_blocked(self, tmp_path: Path):
        """Blocked entry point plugins are skipped."""
        mock_ep = MagicMock()
        mock_ep.name = "blocked_ep"

        with patch(
            "harombe.plugins.loader.importlib.metadata.entry_points",
            return_value=[mock_ep],
        ):
            loader = PluginLoader(plugin_dir=str(tmp_path), blocked=["blocked_ep"])
            plugins = loader.discover_all()

        ep_plugins = [p for p in plugins if p.source == "entrypoint"]
        assert len(ep_plugins) == 0

    def test_discover_entry_points_load_error(self, tmp_path: Path):
        """Entry point that fails to load is recorded with error."""
        mock_ep = MagicMock()
        mock_ep.name = "bad_ep"
        mock_ep.load.side_effect = ImportError("missing dependency")

        with patch(
            "harombe.plugins.loader.importlib.metadata.entry_points",
            return_value=[mock_ep],
        ):
            loader = PluginLoader(plugin_dir=str(tmp_path))
            plugins = loader.discover_all()

        ep_plugins = [p for p in plugins if p.source == "entrypoint"]
        assert len(ep_plugins) == 1
        assert ep_plugins[0].enabled is False
        assert "missing dependency" in ep_plugins[0].error

    def test_discover_entry_points_exception(self, tmp_path: Path):
        """entry_points() itself raises, discovery continues gracefully."""
        with patch(
            "harombe.plugins.loader.importlib.metadata.entry_points",
            side_effect=Exception("metadata error"),
        ):
            loader = PluginLoader(plugin_dir=str(tmp_path))
            plugins = loader.discover_all()

        assert plugins == []

    def test_container_plugin_delegates_to_manager(self, tmp_path: Path):
        """File plugin with container_enabled delegates to container manager."""
        plugin_file = tmp_path / "container_plug.py"
        plugin_file.write_text(
            "PLUGIN_META = {\n"
            '    "name": "container_plug",\n'
            '    "version": "1.0.0",\n'
            '    "container_enabled": True,\n'
            '    "base_image": "python:3.13-slim",\n'
            "}\n"
        )

        mock_manager = MagicMock()
        # start_plugin is async, mock it as a coroutine
        mock_manager.start_plugin = MagicMock()

        loader = PluginLoader(plugin_dir=str(tmp_path))
        loader.set_container_manager(mock_manager)

        with patch.object(loader, "_start_container_plugin") as mock_start:
            mock_start.return_value = MagicMock(
                manifest=MagicMock(name="container_plug"),
                source="container",
                enabled=True,
            )
            loader.discover_all()
            mock_start.assert_called_once()


class TestParsePermissions:
    def test_empty_dict(self):
        p = _parse_permissions({})
        assert p.dangerous is False
        assert p.filesystem is False

    def test_full_permissions(self):
        p = _parse_permissions(
            {
                "network_domains": ["api.example.com"],
                "filesystem": True,
                "shell": True,
                "dangerous": True,
            }
        )
        assert p.network_domains == ["api.example.com"]
        assert p.filesystem is True
        assert p.shell is True
        assert p.dangerous is True

    def test_container_enabled(self):
        p = _parse_permissions({"container_enabled": True})
        assert p.container_enabled is True

    def test_resource_limits(self):
        p = _parse_permissions({"resource_limits": {"memory_mb": 512, "cpu_cores": 2.0}})
        assert p.resource_limits == {"memory_mb": 512, "cpu_cores": 2.0}

    def test_returns_plugin_permissions_type(self):
        p = _parse_permissions({})
        assert isinstance(p, PluginPermissions)

    def test_partial_permissions(self):
        p = _parse_permissions({"filesystem": True})
        assert p.filesystem is True
        assert p.shell is False
        assert p.dangerous is False
        assert p.network_domains == []
