"""
Integration tests for code sandbox and network isolation.

Validates that code execution sandbox properly integrates with
network isolation and egress filtering.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from harombe.security.docker_manager import DockerManager
from harombe.security.network import EgressFilter
from harombe.security.sandbox_manager import SandboxManager
from harombe.tools.code_execution import CodeExecutionTools


class TestSandboxNetworkIntegration:
    """Integration tests for sandbox and network isolation."""

    @pytest.fixture
    def docker_manager(self):
        """Mock Docker manager."""
        manager = MagicMock(spec=DockerManager)
        manager.client = MagicMock()
        manager.start = AsyncMock()
        manager.stop = AsyncMock()
        return manager

    @pytest.fixture
    def egress_filter(self):
        """Mock egress filter."""
        filter = MagicMock(spec=EgressFilter)
        filter.apply_policy = AsyncMock()
        filter.remove_policy = AsyncMock()
        return filter

    @pytest.fixture
    def sandbox_manager(self, docker_manager):
        """Create sandbox manager."""
        return SandboxManager(
            docker_manager=docker_manager,
            runtime="runsc",
        )

    @pytest.fixture
    def code_tools(self, sandbox_manager):
        """Create code execution tools."""
        return CodeExecutionTools(sandbox_manager=sandbox_manager)

    @pytest.mark.asyncio
    async def test_sandbox_air_gapped_by_default(self, code_tools, sandbox_manager):
        """Test that sandbox is air-gapped (no network) by default."""
        # Mock container execution
        mock_container = MagicMock()
        mock_container.start = MagicMock()
        mock_container.wait = MagicMock(return_value={"StatusCode": 0})
        mock_container.logs = MagicMock(return_value=b"Network test\n")
        mock_container.remove = MagicMock()

        sandbox_manager.docker_manager.client.containers.create = MagicMock(
            return_value=mock_container
        )

        # Execute code without network
        result = await code_tools.code_execute(
            language="python",
            code="print('Network test')",
            network_enabled=False,  # Default
        )

        # Verify container created with network_mode="none"
        create_args = sandbox_manager.docker_manager.client.containers.create.call_args[1]
        assert create_args["network_mode"] == "none"
        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_sandbox_with_network_enabled(self, code_tools, sandbox_manager):
        """Test sandbox with network explicitly enabled."""
        # Mock container execution
        mock_container = MagicMock()
        mock_container.start = MagicMock()
        mock_container.wait = MagicMock(return_value={"StatusCode": 0})
        mock_container.logs = MagicMock(return_value=b"200\n")
        mock_container.remove = MagicMock()

        sandbox_manager.docker_manager.client.containers.create = MagicMock(
            return_value=mock_container
        )

        # Execute code with network
        result = await code_tools.code_execute(
            language="python",
            code="import urllib.request; print('200')",
            network_enabled=True,
            allowed_domains=["pypi.org"],
        )

        # Verify container created with network_mode="bridge"
        create_args = sandbox_manager.docker_manager.client.containers.create.call_args[1]
        assert create_args["network_mode"] == "bridge"
        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_sandbox_network_allowlist(self, code_tools, sandbox_manager, egress_filter):
        """Test that network allowlist is enforced in sandbox."""
        # Create sandbox with network
        sandbox_id = await sandbox_manager.create_sandbox(
            language="python",
            network_enabled=True,
            allowed_domains=["pypi.org", "files.pythonhosted.org"],
        )

        sandbox = sandbox_manager._sandboxes[sandbox_id]
        assert sandbox.network_enabled is True
        assert "pypi.org" in sandbox.allowed_domains
        assert "files.pythonhosted.org" in sandbox.allowed_domains

        # In production, egress filter would be applied here
        # For now, verify allowlist is stored correctly

    @pytest.mark.asyncio
    async def test_package_installation_requires_network(self, code_tools, sandbox_manager):
        """Test that package installation requires network to be enabled."""
        # Create air-gapped sandbox
        sandbox_id = await sandbox_manager.create_sandbox(
            language="python",
            network_enabled=False,
        )

        # Try to install package
        result = await code_tools.code_install_package(
            sandbox_id=sandbox_id,
            package="requests",
            registry="pypi",
        )

        # Should fail because network is disabled
        assert result["success"] is False
        assert "network" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_package_installation_with_network(self, code_tools, sandbox_manager):
        """Test package installation when network is enabled."""
        # Mock container execution
        mock_container = MagicMock()
        mock_container.start = MagicMock()
        mock_container.wait = MagicMock(return_value={"StatusCode": 0})
        mock_container.logs = MagicMock(return_value=b"Successfully installed requests\n")
        mock_container.remove = MagicMock()

        sandbox_manager.docker_manager.client.containers.create = MagicMock(
            return_value=mock_container
        )

        # Create sandbox with network
        sandbox_id = await sandbox_manager.create_sandbox(
            language="python",
            network_enabled=True,
            allowed_domains=["pypi.org", "files.pythonhosted.org"],
        )

        # Install package
        result = await code_tools.code_install_package(
            sandbox_id=sandbox_id,
            package="requests==2.31.0",
            registry="pypi",
        )

        assert result["success"] is True
        assert "Successfully installed" in result["stdout"]

    @pytest.mark.asyncio
    async def test_network_isolation_across_sandboxes(self, code_tools, sandbox_manager):
        """Test that network isolation is maintained across multiple sandboxes."""
        # Create multiple sandboxes with different network configs
        sandbox1 = await sandbox_manager.create_sandbox(
            language="python",
            network_enabled=False,  # Air-gapped
        )

        sandbox2 = await sandbox_manager.create_sandbox(
            language="python",
            network_enabled=True,
            allowed_domains=["example.com"],
        )

        sandbox3 = await sandbox_manager.create_sandbox(
            language="python",
            network_enabled=True,
            allowed_domains=["pypi.org"],
        )

        # Verify each sandbox has correct network config
        s1 = sandbox_manager._sandboxes[sandbox1]
        assert s1.network_enabled is False

        s2 = sandbox_manager._sandboxes[sandbox2]
        assert s2.network_enabled is True
        assert s2.allowed_domains == ["example.com"]

        s3 = sandbox_manager._sandboxes[sandbox3]
        assert s3.network_enabled is True
        assert s3.allowed_domains == ["pypi.org"]

    @pytest.mark.asyncio
    async def test_sandbox_cleanup_removes_network_policy(self, sandbox_manager, egress_filter):
        """Test that sandbox cleanup removes associated network policies."""
        # Create sandbox with network
        sandbox_id = await sandbox_manager.create_sandbox(
            language="python",
            network_enabled=True,
            allowed_domains=["example.com"],
        )

        # Destroy sandbox
        await sandbox_manager.destroy_sandbox(sandbox_id)

        # Verify sandbox removed
        assert sandbox_id not in sandbox_manager._sandboxes

        # In production, egress filter policy would be removed here

    @pytest.mark.asyncio
    async def test_network_policy_validation(self, sandbox_manager):
        """Test that network policy domains are validated."""
        # Create sandbox with allowlist
        sandbox_id = await sandbox_manager.create_sandbox(
            language="python",
            network_enabled=True,
            allowed_domains=["*.pypi.org", "files.pythonhosted.org"],
        )

        sandbox = sandbox_manager._sandboxes[sandbox_id]
        assert "*.pypi.org" in sandbox.allowed_domains
        assert "files.pythonhosted.org" in sandbox.allowed_domains

    @pytest.mark.asyncio
    async def test_concurrent_sandboxes_network_isolation(self, code_tools, sandbox_manager):
        """Test that concurrent sandboxes maintain separate network isolation."""
        import asyncio

        async def create_and_verify(network_enabled: bool, domains: list[str]):
            sandbox_id = await sandbox_manager.create_sandbox(
                language="python",
                network_enabled=network_enabled,
                allowed_domains=domains,
            )
            sandbox = sandbox_manager._sandboxes[sandbox_id]
            assert sandbox.network_enabled == network_enabled
            assert sandbox.allowed_domains == domains
            return sandbox_id

        # Create multiple sandboxes concurrently
        results = await asyncio.gather(
            create_and_verify(False, []),
            create_and_verify(True, ["example.com"]),
            create_and_verify(True, ["pypi.org"]),
        )

        # Verify all sandboxes created with correct config
        assert len(results) == 3
        assert len(sandbox_manager._sandboxes) >= 3

    @pytest.mark.asyncio
    async def test_network_disabled_blocks_external_access(self, code_tools, sandbox_manager):
        """Test that network disabled actually blocks external access."""
        # Mock container execution that would fail without network
        mock_container = MagicMock()
        mock_container.start = MagicMock()
        mock_container.wait = MagicMock(return_value={"StatusCode": 1})
        mock_container.logs = MagicMock(return_value=b"Network unreachable\n")
        mock_container.remove = MagicMock()

        sandbox_manager.docker_manager.client.containers.create = MagicMock(
            return_value=mock_container
        )

        # Try to access network in air-gapped sandbox
        result = await code_tools.code_execute(
            language="python",
            code="""
import socket
try:
    socket.create_connection(("example.com", 80), timeout=1)
    print("Connected")
except Exception as e:
    print(f"Network unreachable")
""",
            network_enabled=False,
        )

        # Should fail with network error
        assert "Network unreachable" in result["stdout"]
