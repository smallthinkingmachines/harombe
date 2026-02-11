"""Tests for container-based plugin isolation."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

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
    def test_init(self):
        manager = PluginContainerManager()
        assert manager._docker is None
        assert manager._running == {}
        assert manager._next_port == BASE_PORT

    def test_init_with_docker(self):
        mock_docker = MagicMock()
        manager = PluginContainerManager(docker_manager=mock_docker)
        assert manager._docker is mock_docker

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

    def test_port_allocation_max_boundary(self):
        manager = PluginContainerManager()
        manager._next_port = BASE_PORT + MAX_CONTAINERS
        with pytest.raises(RuntimeError):
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

    def test_generate_dockerfile_no_packages(self):
        manager = PluginContainerManager()
        config = PluginContainerConfig(
            plugin_name="test",
            plugin_path="/path/to/plugin.py",
            port=3100,
        )
        dockerfile = manager._generate_dockerfile(config)
        # Should not have extra pip install line (beyond fastapi/uvicorn)
        lines = dockerfile.strip().split("\n")
        pip_lines = [line for line in lines if "pip install" in line]
        # Only the fastapi uvicorn install
        assert any("fastapi" in line for line in pip_lines)

    def test_generate_dockerfile_custom_base_image(self):
        manager = PluginContainerManager()
        config = PluginContainerConfig(
            plugin_name="test",
            plugin_path="/path/to/plugin.py",
            port=3200,
            base_image="python:3.13-slim",
        )
        dockerfile = manager._generate_dockerfile(config)
        assert "FROM python:3.13-slim" in dockerfile
        assert "EXPOSE 3200" in dockerfile

    def test_generate_dockerfile_default_port(self):
        manager = PluginContainerManager()
        config = PluginContainerConfig(
            plugin_name="test",
            plugin_path="/path/to/plugin.py",
        )
        dockerfile = manager._generate_dockerfile(config)
        assert f"EXPOSE {BASE_PORT}" in dockerfile

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

    def test_generate_scaffold_different_port(self):
        manager = PluginContainerManager()
        scaffold = manager._generate_scaffold("other-plugin", 4500)
        assert "other-plugin" in scaffold
        assert "4500" in scaffold

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
    async def test_health_check_success(self):
        manager = PluginContainerManager()
        manager._running["healthy"] = RunningPluginContainer(
            name="healthy",
            container_id="h1",
            host="localhost:3100",
            port=3100,
        )
        mock_response = MagicMock()
        mock_response.status_code = 200

        mock_client = AsyncMock()
        mock_client.get.return_value = mock_response
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        mock_httpx = MagicMock()
        mock_httpx.AsyncClient.return_value = mock_client

        with patch.dict("sys.modules", {"httpx": mock_httpx}):
            result = await manager.health_check("healthy")

        assert result is True
        mock_client.get.assert_called_once_with("http://localhost:3100/health", timeout=5.0)

    @pytest.mark.asyncio
    async def test_health_check_failure(self):
        manager = PluginContainerManager()
        manager._running["sick"] = RunningPluginContainer(
            name="sick",
            container_id="s1",
            host="localhost:3100",
            port=3100,
        )
        mock_client = AsyncMock()
        mock_client.get.side_effect = ConnectionError("refused")
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        mock_httpx = MagicMock()
        mock_httpx.AsyncClient.return_value = mock_client

        with patch.dict("sys.modules", {"httpx": mock_httpx}):
            result = await manager.health_check("sick")

        assert result is False

    @pytest.mark.asyncio
    async def test_health_check_non_200(self):
        manager = PluginContainerManager()
        manager._running["bad"] = RunningPluginContainer(
            name="bad",
            container_id="b1",
            host="localhost:3100",
            port=3100,
        )
        mock_response = MagicMock()
        mock_response.status_code = 500

        mock_client = AsyncMock()
        mock_client.get.return_value = mock_response
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        mock_httpx = MagicMock()
        mock_httpx.AsyncClient.return_value = mock_client

        with patch.dict("sys.modules", {"httpx": mock_httpx}):
            result = await manager.health_check("bad")

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

    @pytest.mark.asyncio
    async def test_stop_plugin_no_docker(self):
        """stop_plugin with no docker returns early without error."""
        manager = PluginContainerManager(docker_manager=None)
        manager._running["orphan"] = RunningPluginContainer(
            name="orphan",
            container_id="o1",
            host="localhost:3100",
            port=3100,
        )
        # With docker=None, stop_plugin returns immediately (no-op)
        await manager.stop_plugin("orphan")
        # The plugin remains in _running since docker was None
        assert "orphan" in manager._running

    @pytest.mark.asyncio
    async def test_stop_plugin_with_docker(self):
        """stop_plugin calls docker stop and remove."""
        mock_docker = AsyncMock()
        manager = PluginContainerManager(docker_manager=mock_docker)
        manager._running["stopper"] = RunningPluginContainer(
            name="stopper",
            container_id="st1",
            host="localhost:3100",
            port=3100,
        )
        await manager.stop_plugin("stopper")
        mock_docker.stop_container.assert_awaited_once_with("harombe-plugin-stopper")
        mock_docker.remove_container.assert_awaited_once_with("harombe-plugin-stopper", force=True)
        assert "stopper" not in manager._running

    @pytest.mark.asyncio
    async def test_stop_plugin_docker_error(self):
        """stop_plugin handles docker errors gracefully."""
        mock_docker = AsyncMock()
        mock_docker.stop_container.side_effect = ValueError("not found")
        manager = PluginContainerManager(docker_manager=mock_docker)
        manager._running["bad_stop"] = RunningPluginContainer(
            name="bad_stop",
            container_id="bs1",
            host="localhost:3100",
            port=3100,
        )
        # Should not raise
        await manager.stop_plugin("bad_stop")
        assert "bad_stop" not in manager._running

    @pytest.mark.asyncio
    async def test_cleanup_all(self):
        """cleanup_all stops all running containers."""
        mock_docker = AsyncMock()
        manager = PluginContainerManager(docker_manager=mock_docker)
        manager._running["a"] = RunningPluginContainer(
            name="a", container_id="a1", host="localhost:3100", port=3100
        )
        manager._running["b"] = RunningPluginContainer(
            name="b", container_id="b1", host="localhost:3101", port=3101
        )
        await manager.cleanup_all()
        assert manager._running == {}
        assert mock_docker.stop_container.await_count == 2

    @pytest.mark.asyncio
    async def test_cleanup_all_empty(self):
        """cleanup_all on empty manager is a no-op."""
        manager = PluginContainerManager()
        await manager.cleanup_all()
        assert manager._running == {}

    @pytest.mark.asyncio
    async def test_build_image_with_docker(self, tmp_path):
        """build_image builds a Docker image using the docker manager."""
        plugin_file = tmp_path / "test_plugin.py"
        plugin_file.write_text("x = 1\n")

        mock_client = MagicMock()
        mock_client.images.build.return_value = (MagicMock(), [])

        mock_docker = MagicMock()
        mock_docker._get_client.return_value = mock_client

        manager = PluginContainerManager(docker_manager=mock_docker)
        config = PluginContainerConfig(
            plugin_name="build-test",
            plugin_path=str(plugin_file),
        )
        image_tag = await manager.build_image(config)
        assert image_tag == "harombe-plugin-build-test:latest"
        mock_client.images.build.assert_called_once()

    @pytest.mark.asyncio
    async def test_start_plugin_with_docker(self, tmp_path):
        """start_plugin builds image and starts container."""
        plugin_file = tmp_path / "start_plugin.py"
        plugin_file.write_text("x = 1\n")

        mock_client = MagicMock()
        mock_client.images.build.return_value = (MagicMock(), [])

        mock_docker = AsyncMock()
        mock_docker._get_client = MagicMock(return_value=mock_client)
        mock_docker.create_container.return_value = "container-id-123"

        manager = PluginContainerManager(docker_manager=mock_docker)
        config = PluginContainerConfig(
            plugin_name="start-test",
            plugin_path=str(plugin_file),
        )
        running = await manager.start_plugin(config)
        assert running.name == "start-test"
        assert running.container_id == "container-id-123"
        assert running.port >= BASE_PORT
        assert "start-test" in manager._running

    @pytest.mark.asyncio
    async def test_start_plugin_with_network_domains(self, tmp_path):
        """start_plugin with network_domains logs domain info."""
        plugin_file = tmp_path / "net_plugin.py"
        plugin_file.write_text("x = 1\n")

        mock_client = MagicMock()
        mock_client.images.build.return_value = (MagicMock(), [])

        mock_docker = AsyncMock()
        mock_docker._get_client = MagicMock(return_value=mock_client)
        mock_docker.create_container.return_value = "net-container-id"

        manager = PluginContainerManager(docker_manager=mock_docker)
        config = PluginContainerConfig(
            plugin_name="net-test",
            plugin_path=str(plugin_file),
            network_domains=["api.example.com"],
        )
        running = await manager.start_plugin(config)
        assert running.name == "net-test"


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
