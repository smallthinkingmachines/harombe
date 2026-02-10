"""Tests for plugin discovery and loading."""

from pathlib import Path

import pytest

from harombe.plugins.loader import PluginLoader, _parse_permissions
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
