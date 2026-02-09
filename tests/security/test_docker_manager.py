"""Tests for Docker Container Manager."""

import pytest

from harombe.security.docker_manager import (
    ContainerConfig,
    ContainerStatus,
    DockerManager,
    ResourceLimits,
)


def test_resource_limits_from_mb():
    """Test creating resource limits from human-readable values."""
    limits = ResourceLimits.from_mb(memory_mb=512, cpu_cores=0.5, pids_limit=50)

    assert limits.memory_limit == 512 * 1024 * 1024
    assert limits.cpu_quota == 50000  # 0.5 cores * 100000
    assert limits.pids_limit == 50


def test_resource_limits_to_docker_params():
    """Test converting resource limits to Docker params."""
    limits = ResourceLimits(
        cpu_quota=50000,
        cpu_period=100000,
        memory_limit=536870912,  # 512 MB
        pids_limit=100,
    )

    params = limits.to_docker_params()

    assert params["cpu_quota"] == 50000
    assert params["cpu_period"] == 100000
    assert params["mem_limit"] == 536870912
    assert params["pids_limit"] == 100


def test_resource_limits_optional():
    """Test resource limits with optional values."""
    limits = ResourceLimits(pids_limit=100)

    params = limits.to_docker_params()

    assert "cpu_quota" not in params
    assert "mem_limit" not in params
    assert params["pids_limit"] == 100


def test_container_config_basic():
    """Test basic container configuration."""
    config = ContainerConfig(
        name="test-container",
        image="harombe/test:latest",
        port=3000,
    )

    assert config.name == "test-container"
    assert config.image == "harombe/test:latest"
    assert config.port == 3000
    assert config.network == "harombe-network"
    assert config.auto_remove is False


def test_container_config_with_resources():
    """Test container config with resource limits."""
    limits = ResourceLimits.from_mb(memory_mb=256, cpu_cores=0.25)

    config = ContainerConfig(
        name="browser-container",
        image="harombe/browser:latest",
        port=3000,
        host_port=8001,
        resource_limits=limits,
    )

    assert config.resource_limits.memory_limit == 256 * 1024 * 1024
    assert config.resource_limits.cpu_quota == 25000
    assert config.host_port == 8001


def test_container_config_with_environment():
    """Test container config with environment variables."""
    config = ContainerConfig(
        name="code-exec-container",
        image="harombe/code-exec:latest",
        port=3002,
        environment={
            "PYTHONPATH": "/app",
            "LOG_LEVEL": "INFO",
        },
    )

    assert config.environment["PYTHONPATH"] == "/app"
    assert config.environment["LOG_LEVEL"] == "INFO"


def test_container_config_with_volumes():
    """Test container config with volume mounts."""
    config = ContainerConfig(
        name="filesystem-container",
        image="harombe/filesystem:latest",
        port=3001,
        volumes={
            "/host/workspace": {"bind": "/workspace", "mode": "rw"},
        },
    )

    assert "/host/workspace" in config.volumes
    assert config.volumes["/host/workspace"]["bind"] == "/workspace"


def test_container_status_enum():
    """Test ContainerStatus enum values."""
    assert ContainerStatus.CREATED == "created"
    assert ContainerStatus.RUNNING == "running"
    assert ContainerStatus.PAUSED == "paused"
    assert ContainerStatus.RESTARTING == "restarting"
    assert ContainerStatus.EXITED == "exited"
    assert ContainerStatus.DEAD == "dead"
    assert ContainerStatus.UNKNOWN == "unknown"


@pytest.mark.asyncio
async def test_docker_manager_init():
    """Test DockerManager initialization."""
    manager = DockerManager()

    assert manager._docker is None
    assert manager._containers == {}


@pytest.mark.asyncio
@pytest.mark.skipif(True, reason="Requires Docker daemon - integration test")
async def test_docker_manager_get_client():
    """Test getting Docker client (requires Docker daemon)."""
    manager = DockerManager()

    try:
        client = manager._get_client()
        assert client is not None

        # Verify connection
        client.ping()

        manager.close()
    except ImportError:
        pytest.skip("Docker SDK not installed")
    except Exception:
        pytest.skip("Docker daemon not available")


@pytest.mark.asyncio
@pytest.mark.skipif(True, reason="Requires Docker daemon - integration test")
async def test_create_network():
    """Test creating Docker network (requires Docker daemon)."""
    manager = DockerManager()

    try:
        await manager.create_network("test-harombe-network")

        # Network should exist
        client = manager._get_client()
        networks = client.networks.list(names=["test-harombe-network"])
        assert len(networks) == 1

        # Cleanup
        networks[0].remove()
        manager.close()
    except Exception:
        pytest.skip("Docker daemon not available")


@pytest.mark.asyncio
@pytest.mark.skipif(True, reason="Requires Docker daemon - integration test")
async def test_create_and_start_container():
    """Test creating and starting a container (requires Docker daemon)."""
    manager = DockerManager()

    try:
        # Create network first
        await manager.create_network("test-network")

        # Create container config
        config = ContainerConfig(
            name="test-container",
            image="python:3.11-slim",  # Small image for testing
            port=8000,
            network="test-network",
        )

        # Create and start container
        container_id = await manager.create_container(config)
        assert container_id is not None

        await manager.start_container("test-container")

        # Check status
        status = await manager.get_status("test-container")
        assert status == ContainerStatus.RUNNING

        # Cleanup
        await manager.stop_container("test-container")
        await manager.remove_container("test-container")

        client = manager._get_client()
        networks = client.networks.list(names=["test-network"])
        if networks:
            networks[0].remove()

        manager.close()
    except Exception:
        pytest.skip("Docker daemon not available or image pull failed")


@pytest.mark.asyncio
@pytest.mark.skipif(True, reason="Requires Docker daemon - integration test")
async def test_container_lifecycle():
    """Test full container lifecycle (requires Docker daemon)."""
    manager = DockerManager()

    try:
        await manager.create_network("test-network")

        config = ContainerConfig(
            name="lifecycle-test",
            image="python:3.11-slim",
            port=8000,
            network="test-network",
        )

        # Create
        await manager.create_container(config)
        status = await manager.get_status("lifecycle-test")
        assert status == ContainerStatus.CREATED

        # Start
        await manager.start_container("lifecycle-test")
        status = await manager.get_status("lifecycle-test")
        assert status == ContainerStatus.RUNNING

        # Stop
        await manager.stop_container("lifecycle-test")
        status = await manager.get_status("lifecycle-test")
        assert status == ContainerStatus.EXITED

        # Restart (will start again)
        await manager.start_container("lifecycle-test")
        await manager.restart_container("lifecycle-test")
        status = await manager.get_status("lifecycle-test")
        assert status == ContainerStatus.RUNNING

        # Remove
        await manager.stop_container("lifecycle-test")
        await manager.remove_container("lifecycle-test")

        # Should be gone
        assert "lifecycle-test" not in manager._containers

        # Cleanup network
        client = manager._get_client()
        networks = client.networks.list(names=["test-network"])
        if networks:
            networks[0].remove()

        manager.close()
    except Exception:
        pytest.skip("Docker daemon not available")


@pytest.mark.asyncio
async def test_get_status_not_found():
    """Test getting status for non-existent container."""
    manager = DockerManager()

    with pytest.raises(ValueError, match="Container 'nonexistent' not found"):
        await manager.get_status("nonexistent")


@pytest.mark.asyncio
async def test_start_container_not_found():
    """Test starting non-existent container."""
    manager = DockerManager()

    with pytest.raises(ValueError, match="Container 'nonexistent' not found"):
        await manager.start_container("nonexistent")


@pytest.mark.asyncio
async def test_stop_container_not_found():
    """Test stopping non-existent container."""
    manager = DockerManager()

    with pytest.raises(ValueError, match="Container 'nonexistent' not found"):
        await manager.stop_container("nonexistent")


@pytest.mark.asyncio
async def test_restart_container_not_found():
    """Test restarting non-existent container."""
    manager = DockerManager()

    with pytest.raises(ValueError, match="Container 'nonexistent' not found"):
        await manager.restart_container("nonexistent")


@pytest.mark.asyncio
async def test_remove_container_not_found():
    """Test removing non-existent container."""
    manager = DockerManager()

    with pytest.raises(ValueError, match="Container 'nonexistent' not found"):
        await manager.remove_container("nonexistent")


@pytest.mark.asyncio
async def test_get_logs_not_found():
    """Test getting logs for non-existent container."""
    manager = DockerManager()

    with pytest.raises(ValueError, match="Container 'nonexistent' not found"):
        await manager.get_logs("nonexistent")


@pytest.mark.asyncio
async def test_get_stats_not_found():
    """Test getting stats for non-existent container."""
    manager = DockerManager()

    with pytest.raises(ValueError, match="Container 'nonexistent' not found"):
        await manager.get_stats("nonexistent")


@pytest.mark.asyncio
async def test_list_containers_empty():
    """Test listing containers when none exist."""
    manager = DockerManager()

    containers = await manager.list_containers()
    assert containers == []


@pytest.mark.asyncio
async def test_cleanup_all_empty():
    """Test cleanup with no containers."""
    manager = DockerManager()

    await manager.cleanup_all()  # Should not raise


def test_docker_manager_close():
    """Test closing Docker manager."""
    manager = DockerManager()

    # Close without initializing client
    manager.close()  # Should not raise

    # Note: Testing with actual client requires Docker daemon
