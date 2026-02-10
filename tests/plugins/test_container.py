"""Tests for container-based plugin isolation."""

import pytest

from harombe.plugins.container import (
    BASE_PORT,
    MAX_CONTAINERS,
    PluginContainerConfig,
    PluginContainerManager,
    RunningPluginContainer,
)
from harombe.plugins.manifest import LoadedPlugin, PluginManifest, PluginPermissions
from harombe.plugins.sandbox import create_container_config_from_permissions


class TestPluginContainerConfig:
    def test_defaults(self):
        config = PluginContainerConfig(
            plugin_name="test-plugin",
            plugin_path="/path/to/plugin.py",
        )
        assert config.plugin_name == "test-plugin"
        assert config.plugin_path == "/path/to/plugin.py"
        assert config.base_image == "python:3.12-slim"
        assert config.memory_mb == 256
        assert config.cpu_cores == 0.5
        assert config.pids_limit == 50
        assert config.network_domains == []
        assert config.port is None
        assert config.extra_pip_packages == []

    def test_custom_config(self):
        config = PluginContainerConfig(
            plugin_name="heavy-plugin",
            plugin_path="/path/to/plugin/",
            base_image="python:3.13-slim",
            memory_mb=1024,
            cpu_cores=2.0,
            pids_limit=200,
            network_domains=["api.example.com", "cdn.example.com"],
            port=4000,
            extra_pip_packages=["numpy", "pandas"],
        )
        assert config.memory_mb == 1024
        assert config.cpu_cores == 2.0
        assert config.pids_limit == 200
        assert len(config.network_domains) == 2
        assert config.port == 4000
        assert len(config.extra_pip_packages) == 2


class TestRunningPluginContainer:
    def test_creation(self):
        running = RunningPluginContainer(
            name="test-plugin",
            container_id="abc123",
            host="localhost:3100",
            port=3100,
        )
        assert running.name == "test-plugin"
        assert running.container_id == "abc123"
        assert running.host == "localhost:3100"
        assert running.port == 3100
        assert running.tool_names == []

    def test_with_tools(self):
        running = RunningPluginContainer(
            name="multi-tool",
            container_id="def456",
            host="localhost:3101",
            port=3101,
            tool_names=["tool_a", "tool_b"],
        )
        assert len(running.tool_names) == 2


class TestPluginContainerManager:
    def test_port_allocation(self):
        manager = PluginContainerManager()
        port1 = manager._allocate_port()
        port2 = manager._allocate_port()
        assert port1 == BASE_PORT
        assert port2 == BASE_PORT + 1

    def test_port_allocation_exhaustion(self):
        manager = PluginContainerManager()
        # Exhaust all ports
        for _ in range(MAX_CONTAINERS):
            manager._allocate_port()
        with pytest.raises(RuntimeError, match="Maximum number"):
            manager._allocate_port()

    def test_generate_dockerfile_basic(self):
        manager = PluginContainerManager()
        config = PluginContainerConfig(
            plugin_name="test",
            plugin_path="/path/to/plugin.py",
            port=3100,
        )
        dockerfile = manager._generate_dockerfile(config)
        assert "FROM python:3.12-slim" in dockerfile
        assert "EXPOSE 3100" in dockerfile
        assert "COPY plugin/" in dockerfile
        assert "COPY scaffold.py" in dockerfile
        assert "CMD" in dockerfile

    def test_generate_dockerfile_with_packages(self):
        manager = PluginContainerManager()
        config = PluginContainerConfig(
            plugin_name="test",
            plugin_path="/path/to/plugin.py",
            port=3100,
            extra_pip_packages=["requests", "beautifulsoup4"],
        )
        dockerfile = manager._generate_dockerfile(config)
        assert "pip install --no-cache-dir requests beautifulsoup4" in dockerfile

    def test_generate_scaffold(self):
        manager = PluginContainerManager()
        scaffold = manager._generate_scaffold("my-plugin", 3100)
        assert "my-plugin" in scaffold
        assert "FastAPI" in scaffold
        assert "/health" in scaffold
        assert "/mcp" in scaffold
        assert "tools/list" in scaffold
        assert "tools/call" in scaffold
        assert "__tool_meta__" in scaffold
        assert "3100" in scaffold

    def test_route_lookup_missing(self):
        manager = PluginContainerManager()
        assert manager.get_tool_route("nonexistent") is None

    def test_route_lookup_existing(self):
        manager = PluginContainerManager()
        manager._running["my-plugin"] = RunningPluginContainer(
            name="my-plugin",
            container_id="abc",
            host="localhost:3100",
            port=3100,
        )
        assert manager.get_tool_route("my-plugin") == "localhost:3100"

    def test_get_all_routes(self):
        manager = PluginContainerManager()
        manager._running["plugin-a"] = RunningPluginContainer(
            name="plugin-a",
            container_id="a1",
            host="localhost:3100",
            port=3100,
        )
        manager._running["plugin-b"] = RunningPluginContainer(
            name="plugin-b",
            container_id="b1",
            host="localhost:3101",
            port=3101,
        )
        routes = manager.get_all_routes()
        assert len(routes) == 2
        assert routes["plugin-a"] == "localhost:3100"
        assert routes["plugin-b"] == "localhost:3101"

    def test_get_all_routes_empty(self):
        manager = PluginContainerManager()
        assert manager.get_all_routes() == {}

    @pytest.mark.asyncio
    async def test_health_check_missing_plugin(self):
        manager = PluginContainerManager()
        result = await manager.health_check("nonexistent")
        assert result is False

    @pytest.mark.asyncio
    async def test_start_plugin_no_docker(self):
        manager = PluginContainerManager(docker_manager=None)
        config = PluginContainerConfig(
            plugin_name="test",
            plugin_path="/path/to/plugin.py",
        )
        with pytest.raises(RuntimeError, match="Docker manager not available"):
            await manager.start_plugin(config)

    @pytest.mark.asyncio
    async def test_build_image_no_docker(self):
        manager = PluginContainerManager(docker_manager=None)
        config = PluginContainerConfig(
            plugin_name="test",
            plugin_path="/path/to/plugin.py",
        )
        with pytest.raises(RuntimeError, match="Docker manager not available"):
            await manager.build_image(config)


class TestCreateContainerConfigFromPermissions:
    def test_returns_none_when_not_container_enabled(self):
        plugin = LoadedPlugin(
            manifest=PluginManifest(
                name="basic-plugin",
                permissions=PluginPermissions(container_enabled=False),
            ),
            source="file",
        )
        result = create_container_config_from_permissions(plugin)
        assert result is None

    def test_creates_config_and_policy(self):
        plugin = LoadedPlugin(
            manifest=PluginManifest(
                name="sandboxed",
                base_image="python:3.13-slim",
                permissions=PluginPermissions(
                    container_enabled=True,
                    resource_limits={
                        "memory_mb": 512,
                        "cpu_cores": 1.0,
                        "pids_limit": 100,
                    },
                    network_domains=["api.example.com"],
                ),
            ),
            source="file",
        )
        result = create_container_config_from_permissions(plugin)
        assert result is not None
        container_config, network_policy = result

        assert container_config.name == "harombe-plugin-sandboxed"
        assert container_config.image == "python:3.13-slim"
        assert container_config.port == 3100

        assert network_policy.allowed_domains == ["api.example.com"]
        assert network_policy.block_by_default is True

    def test_default_resource_limits(self):
        plugin = LoadedPlugin(
            manifest=PluginManifest(
                name="defaults",
                permissions=PluginPermissions(
                    container_enabled=True,
                ),
            ),
            source="file",
        )
        result = create_container_config_from_permissions(plugin)
        assert result is not None
        container_config, _ = result
        # Should use defaults (256 MB, 0.5 CPU, 50 PIDs)
        assert container_config.resource_limits is not None


@pytest.mark.docker
class TestContainerIntegration:
    """Integration tests requiring Docker daemon.

    Skipped in CI via pytest -m "not docker".
    """

    def test_build_and_start_plugin(self):
        """Build and start a real plugin container."""
        try:
            import docker

            client = docker.from_env()
            client.ping()
        except Exception:
            pytest.skip("Docker daemon not available")

        import asyncio
        import tempfile
        from pathlib import Path

        # Create a minimal plugin file
        with tempfile.TemporaryDirectory() as tmpdir:
            plugin_file = Path(tmpdir) / "hello_plugin.py"
            plugin_file.write_text(
                'def hello(name: str = "world") -> str:\n'
                '    """Say hello."""\n'
                '    return f"Hello, {name}!"\n'
                "\n"
                "hello.__tool_meta__ = {\n"
                '    "name": "hello",\n'
                '    "description": "Say hello",\n'
                '    "parameters": {"type": "object", "properties": '
                '{"name": {"type": "string"}}},\n'
                "}\n"
            )

            from harombe.security.docker_manager import DockerManager

            docker_mgr = DockerManager()
            manager = PluginContainerManager(docker_manager=docker_mgr)

            config = PluginContainerConfig(
                plugin_name="hello-test",
                plugin_path=str(plugin_file),
            )

            try:
                running = asyncio.get_event_loop().run_until_complete(manager.start_plugin(config))
                assert running.name == "hello-test"
                assert running.port >= BASE_PORT
            finally:
                asyncio.get_event_loop().run_until_complete(manager.cleanup_all())
