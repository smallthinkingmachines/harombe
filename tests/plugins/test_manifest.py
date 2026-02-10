"""Tests for plugin manifest models."""

from harombe.plugins.manifest import LoadedPlugin, PluginManifest, PluginPermissions


class TestPluginPermissions:
    def test_defaults(self):
        p = PluginPermissions()
        assert p.network_domains == []
        assert p.filesystem is False
        assert p.shell is False
        assert p.dangerous is False

    def test_custom_permissions(self):
        p = PluginPermissions(
            network_domains=["api.github.com"],
            filesystem=True,
            dangerous=True,
        )
        assert p.network_domains == ["api.github.com"]
        assert p.filesystem is True
        assert p.dangerous is True


class TestPluginManifest:
    def test_defaults(self):
        m = PluginManifest(name="test-plugin")
        assert m.name == "test-plugin"
        assert m.version == "0.0.0"
        assert m.description == ""
        assert m.author == ""
        assert m.permissions.dangerous is False

    def test_full_manifest(self):
        m = PluginManifest(
            name="github-tools",
            version="1.2.0",
            description="GitHub integration tools",
            author="harombe-community",
            permissions=PluginPermissions(
                network_domains=["api.github.com"],
                dangerous=False,
            ),
        )
        assert m.name == "github-tools"
        assert m.version == "1.2.0"


class TestLoadedPlugin:
    def test_defaults(self):
        lp = LoadedPlugin(
            manifest=PluginManifest(name="test"),
            source="file",
        )
        assert lp.tool_names == []
        assert lp.enabled is True
        assert lp.error is None

    def test_with_error(self):
        lp = LoadedPlugin(
            manifest=PluginManifest(name="broken"),
            source="entrypoint",
            enabled=False,
            error="ImportError: no module named 'foo'",
        )
        assert lp.enabled is False
        assert "ImportError" in lp.error

    def test_with_tools(self):
        lp = LoadedPlugin(
            manifest=PluginManifest(name="multi-tool"),
            source="directory",
            tool_names=["tool_a", "tool_b", "tool_c"],
        )
        assert len(lp.tool_names) == 3
