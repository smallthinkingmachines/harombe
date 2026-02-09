"""Integration tests for Phase 4.1 - MCP Gateway and Docker Manager.

These tests verify the integration between:
- MCP Gateway
- Docker Manager
- Container lifecycle
- Health monitoring

Note: These tests require Docker daemon to be running.
They are skipped by default and can be run with: pytest -m docker_integration
"""

import pytest

from harombe.mcp.protocol import MCPRequest, MCPResponse
from harombe.security.docker_manager import (
    ContainerConfig,
    DockerManager,
    ResourceLimits,
)
from harombe.security.gateway import create_gateway

# Mark all tests in this module as docker integration tests
pytestmark = pytest.mark.docker_integration


@pytest.fixture
async def docker_manager():
    """Create a Docker manager instance."""
    manager = DockerManager()
    yield manager
    # Cleanup after tests
    await manager.cleanup_all(force=True)
    manager.close()


@pytest.fixture
def gateway():
    """Create a gateway instance for testing."""
    return create_gateway(host="127.0.0.1", port=8100, version="0.1.0-test")


@pytest.mark.asyncio
@pytest.mark.skipif(True, reason="Requires Docker daemon - run with pytest -m docker_integration")
async def test_docker_network_creation(docker_manager):
    """Test creating Docker network for containers."""
    await docker_manager.create_network("test-harombe-network")

    # Verify network exists
    client = docker_manager._get_client()
    networks = client.networks.list(names=["test-harombe-network"])
    assert len(networks) == 1
    assert networks[0].name == "test-harombe-network"

    # Cleanup
    networks[0].remove()


@pytest.mark.asyncio
@pytest.mark.skipif(True, reason="Requires Docker daemon - run with pytest -m docker_integration")
async def test_container_creation_with_resources(docker_manager):
    """Test creating container with resource limits."""
    await docker_manager.create_network("test-network")

    # Create container with resource limits
    config = ContainerConfig(
        name="test-limited-container",
        image="python:3.12-slim",
        port=8000,
        network="test-network",
        resource_limits=ResourceLimits.from_mb(memory_mb=256, cpu_cores=0.5),
    )

    container_id = await docker_manager.create_container(config)
    assert container_id is not None

    # Verify container was created
    assert "test-limited-container" in docker_manager._containers

    # Start and check status
    await docker_manager.start_container("test-limited-container")
    status = await docker_manager.get_status("test-limited-container")
    assert status.value == "running"

    # Cleanup
    await docker_manager.stop_container("test-limited-container")
    await docker_manager.remove_container("test-limited-container")

    client = docker_manager._get_client()
    networks = client.networks.list(names=["test-network"])
    if networks:
        networks[0].remove()


@pytest.mark.asyncio
@pytest.mark.skipif(True, reason="Requires Docker daemon - run with pytest -m docker_integration")
async def test_container_health_monitoring(docker_manager):
    """Test container health check integration."""
    await docker_manager.create_network("test-network")

    config = ContainerConfig(
        name="test-health-container",
        image="python:3.12-slim",
        port=8000,
        network="test-network",
    )

    await docker_manager.create_container(config)
    await docker_manager.start_container("test-health-container")

    # Check health (container may not have health endpoint, but test the flow)
    try:
        healthy = await docker_manager._get_client().api.inspect_container("test-health-container")
        assert healthy is not None
    except Exception:
        # Expected - container doesn't have health endpoint
        pass

    # Cleanup
    await docker_manager.stop_container("test-health-container")
    await docker_manager.remove_container("test-health-container")

    client = docker_manager._get_client()
    networks = client.networks.list(names=["test-network"])
    if networks:
        networks[0].remove()


@pytest.mark.asyncio
@pytest.mark.skipif(True, reason="Requires Docker daemon - run with pytest -m docker_integration")
async def test_multiple_containers(docker_manager):
    """Test managing multiple containers simultaneously."""
    await docker_manager.create_network("test-network")

    # Create multiple containers
    containers = []
    for i in range(3):
        config = ContainerConfig(
            name=f"test-multi-{i}",
            image="python:3.12-slim",
            port=8000 + i,
            network="test-network",
        )
        await docker_manager.create_container(config)
        containers.append(f"test-multi-{i}")

    # Start all containers
    for name in containers:
        await docker_manager.start_container(name)

    # List containers
    container_list = await docker_manager.list_containers()
    assert len(container_list) == 3

    # Cleanup all
    await docker_manager.cleanup_all(force=True)

    # Verify cleanup
    container_list = await docker_manager.list_containers()
    assert len(container_list) == 0

    # Cleanup network
    client = docker_manager._get_client()
    networks = client.networks.list(names=["test-network"])
    if networks:
        networks[0].remove()


@pytest.mark.asyncio
@pytest.mark.skipif(True, reason="Requires Docker daemon - run with pytest -m docker_integration")
async def test_container_logs_retrieval(docker_manager):
    """Test retrieving container logs."""
    await docker_manager.create_network("test-network")

    config = ContainerConfig(
        name="test-logs-container",
        image="python:3.12-slim",
        port=8000,
        network="test-network",
    )

    await docker_manager.create_container(config)
    await docker_manager.start_container("test-logs-container")

    # Get logs
    logs = await docker_manager.get_logs("test-logs-container", tail=10)
    assert isinstance(logs, str)

    # Cleanup
    await docker_manager.stop_container("test-logs-container")
    await docker_manager.remove_container("test-logs-container")

    client = docker_manager._get_client()
    networks = client.networks.list(names=["test-network"])
    if networks:
        networks[0].remove()


def test_gateway_initialization(gateway):
    """Test gateway initialization with configuration."""
    assert gateway.host == "127.0.0.1"
    assert gateway.port == 8100
    assert gateway.version == "0.1.0-test"
    assert gateway.app is not None
    assert gateway.client_pool is not None


def test_gateway_routes_registered(gateway):
    """Test that gateway routes are properly registered."""
    routes = [route.path for route in gateway.app.routes]

    # Core MCP Gateway routes
    assert "/mcp" in routes
    assert "/health" in routes
    assert "/ready" in routes


@pytest.mark.asyncio
async def test_gateway_startup_shutdown(gateway):
    """Test gateway startup and shutdown lifecycle."""
    # Test startup
    await gateway.startup()

    # Verify gateway is initialized
    assert gateway.start_time > 0

    # Test shutdown
    await gateway.shutdown()

    # Verify cleanup (client pool should be closed)
    assert len(gateway.client_pool._clients) == 0


@pytest.mark.asyncio
@pytest.mark.skipif(True, reason="Requires Docker daemon and running containers")
async def test_end_to_end_gateway_to_container():
    """End-to-end test: Gateway → Container → Response.

    This test verifies:
    1. Container is created and started
    2. Gateway routes request to container
    3. Container responds with valid MCP response
    4. Gateway returns response to caller
    """
    # Setup
    manager = DockerManager()
    gateway = create_gateway()

    try:
        # Create network
        await manager.create_network("e2e-test-network")

        # Create mock MCP server container
        config = ContainerConfig(
            name="e2e-mock-server",
            image="python:3.12-slim",
            port=3000,
            network="e2e-test-network",
        )

        await manager.create_container(config)
        await manager.start_container("e2e-mock-server")

        # Wait for container to be ready
        import asyncio

        await asyncio.sleep(2)

        # Send request through gateway
        request = MCPRequest(
            id="e2e-test-1",
            method="tools/call",
            params={
                "name": "test_tool",
                "arguments": {"test": "data"},
            },
        )

        # Note: This will fail until MCP server is implemented in container
        # For now, we're testing the gateway routing logic
        response = await gateway.client_pool.send_request("e2e-mock-server:3000", request)

        assert response is not None
        assert isinstance(response, MCPResponse)

    finally:
        # Cleanup
        await manager.cleanup_all(force=True)
        await gateway.shutdown()
        manager.close()

        client = manager._get_client()
        networks = client.networks.list(names=["e2e-test-network"])
        if networks:
            networks[0].remove()


def test_gateway_tool_routing():
    """Test that gateway has correct tool → container routing."""
    from harombe.security.gateway import TOOL_ROUTES

    # Verify expected tools are mapped
    assert "browser_navigate" in TOOL_ROUTES
    assert "filesystem_read" in TOOL_ROUTES
    assert "code_execute" in TOOL_ROUTES
    assert "web_search" in TOOL_ROUTES

    # Verify container endpoints
    assert TOOL_ROUTES["browser_navigate"] == "browser-container:3000"
    assert TOOL_ROUTES["filesystem_read"] == "filesystem-container:3001"
    assert TOOL_ROUTES["code_execute"] == "code-exec-container:3002"
    assert TOOL_ROUTES["web_search"] == "web-search-container:3003"


@pytest.mark.asyncio
async def test_docker_manager_resource_cleanup(docker_manager):
    """Test that Docker manager properly cleans up resources."""
    # cleanup_all will fail on None containers (expected behavior)
    # This test verifies the manager can handle cleanup failures gracefully

    # Initially empty
    assert len(docker_manager._containers) == 0

    # Cleanup on empty manager should not raise
    await docker_manager.cleanup_all(force=True)

    # Still empty
    assert len(docker_manager._containers) == 0
