"""Tests for CLI plugin commands."""

from unittest.mock import patch

from harombe.cli.plugin_cmd import (
    disable_plugin,
    enable_plugin,
    info_plugin,
    list_plugins,
)
from harombe.plugins.manifest import LoadedPlugin, PluginManifest, PluginPermissions


def _make_plugin(
    name: str = "test-plugin",
    version: str = "1.0.0",
    enabled: bool = True,
    error: str | None = None,
    tool_names: list[str] | None = None,
    source: str = "file",
) -> LoadedPlugin:
    """Create a test LoadedPlugin."""
    return LoadedPlugin(
        manifest=PluginManifest(
            name=name,
            version=version,
            description=f"A {name} plugin",
            author="test-author",
            permissions=PluginPermissions(
                network_domains=["example.com"],
                filesystem=True,
                shell=False,
                dangerous=False,
            ),
        ),
        source=source,
        tool_names=tool_names or ["tool_a", "tool_b"],
        enabled=enabled,
        error=error,
    )


def test_list_plugins_with_plugins():
    """Test listing plugins when plugins exist."""
    plugins = [_make_plugin("alpha"), _make_plugin("beta")]

    with patch("harombe.plugins.loader.PluginLoader") as mock_loader_cls:
        loader = mock_loader_cls.return_value
        loader.discover_all.return_value = plugins

        list_plugins(plugin_dir="/tmp/plugins")


def test_list_plugins_empty():
    """Test listing plugins when no plugins found."""
    with patch("harombe.plugins.loader.PluginLoader") as mock_loader_cls:
        loader = mock_loader_cls.return_value
        loader.discover_all.return_value = []

        list_plugins()


def test_list_plugins_with_error():
    """Test listing plugins when a plugin has an error."""
    plugins = [
        _make_plugin("good"),
        _make_plugin("broken", enabled=False, error="Import failed: module not found"),
    ]

    with patch("harombe.plugins.loader.PluginLoader") as mock_loader_cls:
        loader = mock_loader_cls.return_value
        loader.discover_all.return_value = plugins

        list_plugins()


def test_list_plugins_no_tools():
    """Test listing plugins with a plugin that has no tools."""
    plugins = [_make_plugin("empty", tool_names=[])]

    with patch("harombe.plugins.loader.PluginLoader") as mock_loader_cls:
        loader = mock_loader_cls.return_value
        loader.discover_all.return_value = plugins

        list_plugins()


def test_info_plugin_found():
    """Test info for an existing plugin."""
    plugin = _make_plugin("my-plugin")

    with patch("harombe.plugins.loader.PluginLoader") as mock_loader_cls:
        loader = mock_loader_cls.return_value
        loader.discover_all.return_value = None
        loader.get_plugin.return_value = plugin

        info_plugin("my-plugin")


def test_info_plugin_not_found():
    """Test info for a non-existing plugin."""
    with patch("harombe.plugins.loader.PluginLoader") as mock_loader_cls:
        loader = mock_loader_cls.return_value
        loader.discover_all.return_value = None
        loader.get_plugin.return_value = None

        info_plugin("nonexistent")


def test_info_plugin_with_error():
    """Test info for a plugin with an error."""
    plugin = _make_plugin("errored", enabled=False, error="Failed to load")

    with patch("harombe.plugins.loader.PluginLoader") as mock_loader_cls:
        loader = mock_loader_cls.return_value
        loader.discover_all.return_value = None
        loader.get_plugin.return_value = plugin

        info_plugin("errored")


def test_enable_plugin_success():
    """Test enabling a plugin."""
    with patch("harombe.plugins.loader.PluginLoader") as mock_loader_cls:
        loader = mock_loader_cls.return_value
        loader.discover_all.return_value = None
        loader.enable_plugin.return_value = True

        enable_plugin("my-plugin")

        loader.enable_plugin.assert_called_once_with("my-plugin")


def test_enable_plugin_not_found():
    """Test enabling a non-existing plugin."""
    with patch("harombe.plugins.loader.PluginLoader") as mock_loader_cls:
        loader = mock_loader_cls.return_value
        loader.discover_all.return_value = None
        loader.enable_plugin.return_value = False

        enable_plugin("nonexistent")


def test_disable_plugin_success():
    """Test disabling a plugin."""
    with patch("harombe.plugins.loader.PluginLoader") as mock_loader_cls:
        loader = mock_loader_cls.return_value
        loader.discover_all.return_value = None
        loader.disable_plugin.return_value = True

        disable_plugin("my-plugin")

        loader.disable_plugin.assert_called_once_with("my-plugin")


def test_disable_plugin_not_found():
    """Test disabling a non-existing plugin."""
    with patch("harombe.plugins.loader.PluginLoader") as mock_loader_cls:
        loader = mock_loader_cls.return_value
        loader.discover_all.return_value = None
        loader.disable_plugin.return_value = False

        disable_plugin("nonexistent")
