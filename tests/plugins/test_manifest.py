"""Tests for plugin manifest models."""

from harombe.plugins.manifest import LoadedPlugin, PluginManifest, PluginPermissions


class TestPluginPermissions:
    def test_defaults(self):
        p = PluginPermissions()
        assert p.network_domains == []
        assert p.filesystem is False
        assert p.shell is False
        assert p.dangerous is False
        assert p.container_enabled is False
        assert p.resource_limits is None

    def test_custom_permissions(self):
        p = PluginPermissions(
            network_domains=["api.github.com"],
            filesystem=True,
            dangerous=True,
        )
        assert p.network_domains == ["api.github.com"]
        assert p.filesystem is True
        assert p.dangerous is True

    def test_container_permissions(self):
        p = PluginPermissions(
            container_enabled=True,
            resource_limits={"memory_mb": 512, "cpu_cores": 1.0, "pids_limit": 100},
            network_domains=["api.example.com"],
        )
        assert p.container_enabled is True
        assert p.resource_limits["memory_mb"] == 512
        assert p.resource_limits["cpu_cores"] == 1.0
        assert p.resource_limits["pids_limit"] == 100


class TestPluginManifest:
    def test_defaults(self):
        m = PluginManifest(name="test-plugin")
        assert m.name == "test-plugin"
        assert m.version == "0.0.0"
        assert m.description == ""
        assert m.author == ""
        assert m.permissions.dangerous is False
        assert m.container_enabled is False
        assert m.base_image == "python:3.12-slim"
        assert m.extra_pip_packages == []

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

    def test_container_manifest(self):
        m = PluginManifest(
            name="sandboxed-plugin",
            version="2.0.0",
            container_enabled=True,
            base_image="python:3.13-slim",
            extra_pip_packages=["requests", "beautifulsoup4"],
            permissions=PluginPermissions(
                container_enabled=True,
                resource_limits={"memory_mb": 512},
                network_domains=["api.example.com"],
            ),
        )
        assert m.container_enabled is True
        assert m.base_image == "python:3.13-slim"
        assert len(m.extra_pip_packages) == 2
        assert "requests" in m.extra_pip_packages
        assert m.permissions.container_enabled is True


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
