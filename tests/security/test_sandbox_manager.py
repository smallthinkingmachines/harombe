"""
Tests for gVisor sandbox manager.

Tests sandbox lifecycle, code execution, and resource management.
"""

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from harombe.security.docker_manager import DockerManager
from harombe.security.sandbox_manager import (
    SandboxManager,
)


class TestSandboxManager:
    """Tests for SandboxManager."""

    @pytest.fixture
    def docker_manager(self):
        """Mock Docker manager."""
        manager = MagicMock(spec=DockerManager)
        manager.client = MagicMock()
        manager.start = AsyncMock()
        manager.stop = AsyncMock()
        return manager

    @pytest.fixture
    def sandbox_manager(self, docker_manager):
        """Create sandbox manager."""
        return SandboxManager(
            docker_manager=docker_manager,
            runtime="runsc",
            max_memory_mb=512,
            max_cpu_cores=0.5,
            max_disk_mb=1024,
            max_execution_time=30,
        )

    @pytest.mark.asyncio
    async def test_start_stop(self, sandbox_manager, docker_manager):
        """Test starting and stopping sandbox manager."""
        await sandbox_manager.start()
        docker_manager.start.assert_called_once()

        await sandbox_manager.stop()
        docker_manager.stop.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_sandbox_python(self, sandbox_manager):
        """Test creating Python sandbox."""
        sandbox_id = await sandbox_manager.create_sandbox(language="python")

        assert sandbox_id.startswith("sandbox-")
        assert sandbox_id in sandbox_manager._sandboxes

        sandbox = sandbox_manager._sandboxes[sandbox_id]
        assert sandbox.language == "python"
        assert sandbox.network_enabled is False
        assert sandbox.execution_count == 0

    @pytest.mark.asyncio
    async def test_create_sandbox_with_network(self, sandbox_manager):
        """Test creating sandbox with network enabled."""
        sandbox_id = await sandbox_manager.create_sandbox(
            language="python",
            network_enabled=True,
            allowed_domains=["pypi.org"],
        )

        sandbox = sandbox_manager._sandboxes[sandbox_id]
        assert sandbox.network_enabled is True
        assert sandbox.allowed_domains == ["pypi.org"]

    @pytest.mark.asyncio
    async def test_create_sandbox_custom_id(self, sandbox_manager):
        """Test creating sandbox with custom ID."""
        sandbox_id = await sandbox_manager.create_sandbox(
            language="python",
            sandbox_id="my-sandbox",
        )

        assert sandbox_id == "my-sandbox"
        assert "my-sandbox" in sandbox_manager._sandboxes

    @pytest.mark.asyncio
    async def test_create_sandbox_unsupported_language(self, sandbox_manager):
        """Test creating sandbox with unsupported language."""
        with pytest.raises(ValueError, match="Unsupported language"):
            await sandbox_manager.create_sandbox(language="ruby")

    @pytest.mark.asyncio
    async def test_create_sandbox_docker_not_started(self, sandbox_manager):
        """Test creating sandbox when Docker not started."""
        sandbox_manager.docker_manager.client = None

        with pytest.raises(RuntimeError, match="Docker manager not started"):
            await sandbox_manager.create_sandbox(language="python")

    @pytest.mark.asyncio
    async def test_execute_code_success(self, sandbox_manager):
        """Test successful code execution."""
        sandbox_id = await sandbox_manager.create_sandbox(language="python")

        # Mock container execution
        mock_container = MagicMock()
        mock_container.start = MagicMock()
        mock_container.wait = MagicMock(return_value={"StatusCode": 0})
        mock_container.logs = MagicMock(return_value=b"Hello, World!\n")
        mock_container.remove = MagicMock()

        sandbox_manager.docker_manager.client.containers.create = MagicMock(
            return_value=mock_container
        )

        result = await sandbox_manager.execute_code(
            sandbox_id=sandbox_id,
            code="print('Hello, World!')",
        )

        assert result.success is True
        assert result.stdout == "Hello, World!\n"
        assert result.exit_code == 0
        assert result.execution_time > 0

    @pytest.mark.asyncio
    async def test_execute_code_failure(self, sandbox_manager):
        """Test code execution with non-zero exit code."""
        sandbox_id = await sandbox_manager.create_sandbox(language="python")

        # Mock container execution
        mock_container = MagicMock()
        mock_container.start = MagicMock()
        mock_container.wait = MagicMock(return_value={"StatusCode": 1})
        mock_container.logs = MagicMock(return_value=b"Error: something failed\n")
        mock_container.remove = MagicMock()

        sandbox_manager.docker_manager.client.containers.create = MagicMock(
            return_value=mock_container
        )

        result = await sandbox_manager.execute_code(
            sandbox_id=sandbox_id,
            code="import sys; sys.exit(1)",
        )

        assert result.success is False
        assert "Error" in result.stdout
        assert result.exit_code == 1

    @pytest.mark.asyncio
    async def test_execute_code_timeout(self, sandbox_manager):
        """Test code execution timeout."""

        sandbox_id = await sandbox_manager.create_sandbox(language="python")

        # Mock container that times out
        mock_container = MagicMock()

        def start_side_effect():
            # Simulate long-running start
            import time

            time.sleep(10)

        mock_container.start = MagicMock(side_effect=start_side_effect)
        mock_container.kill = MagicMock()
        mock_container.remove = MagicMock()

        sandbox_manager.docker_manager.client.containers.create = MagicMock(
            return_value=mock_container
        )

        result = await sandbox_manager.execute_code(
            sandbox_id=sandbox_id,
            code="import time; time.sleep(1000)",
            timeout=1,  # Short timeout
        )

        assert result.success is False
        assert "timeout" in result.stderr.lower()
        assert result.exit_code == -1
        assert result.error == "TimeoutError"

    @pytest.mark.asyncio
    async def test_execute_code_output_truncation(self, sandbox_manager):
        """Test output truncation when too large."""
        sandbox_manager.max_output_bytes = 100  # Small limit

        sandbox_id = await sandbox_manager.create_sandbox(language="python")

        # Mock container with large output
        mock_container = MagicMock()
        mock_container.start = MagicMock()
        mock_container.wait = MagicMock(return_value={"StatusCode": 0})
        mock_container.logs = MagicMock(return_value=b"x" * 1000)  # 1000 bytes
        mock_container.remove = MagicMock()

        sandbox_manager.docker_manager.client.containers.create = MagicMock(
            return_value=mock_container
        )

        result = await sandbox_manager.execute_code(
            sandbox_id=sandbox_id,
            code="print('x' * 1000)",
        )

        assert len(result.stdout) <= 100 + len("\n[OUTPUT TRUNCATED]")
        assert "[OUTPUT TRUNCATED]" in result.stdout

    @pytest.mark.asyncio
    async def test_execute_code_sandbox_not_found(self, sandbox_manager):
        """Test executing code in non-existent sandbox."""
        with pytest.raises(ValueError, match="Sandbox not found"):
            await sandbox_manager.execute_code(
                sandbox_id="nonexistent",
                code="print('hello')",
            )

    @pytest.mark.asyncio
    async def test_install_package_success(self, sandbox_manager):
        """Test successful package installation."""
        sandbox_id = await sandbox_manager.create_sandbox(
            language="python",
            network_enabled=True,
        )

        # Mock container execution
        mock_container = MagicMock()
        mock_container.start = MagicMock()
        mock_container.wait = MagicMock(return_value={"StatusCode": 0})
        mock_container.logs = MagicMock(return_value=b"Successfully installed requests\n")
        mock_container.remove = MagicMock()

        sandbox_manager.docker_manager.client.containers.create = MagicMock(
            return_value=mock_container
        )

        result = await sandbox_manager.install_package(
            sandbox_id=sandbox_id,
            package="requests==2.31.0",
            registry="pypi",
        )

        assert result.success is True
        assert result.package == "requests==2.31.0"
        assert result.registry == "pypi"

    @pytest.mark.asyncio
    async def test_install_package_network_disabled(self, sandbox_manager):
        """Test package installation when network disabled."""
        sandbox_id = await sandbox_manager.create_sandbox(
            language="python",
            network_enabled=False,
        )

        result = await sandbox_manager.install_package(
            sandbox_id=sandbox_id,
            package="requests",
            registry="pypi",
        )

        assert result.success is False
        assert result.error == "NetworkDisabled"
        assert "Network access required" in result.stderr

    @pytest.mark.asyncio
    async def test_install_package_unsupported_language(self, sandbox_manager):
        """Test package installation for unsupported language."""
        sandbox_id = await sandbox_manager.create_sandbox(
            language="shell",
            network_enabled=True,
        )

        result = await sandbox_manager.install_package(
            sandbox_id=sandbox_id,
            package="some-package",
            registry="npm",
        )

        assert result.success is False
        assert result.error == "UnsupportedLanguage"

    @pytest.mark.asyncio
    async def test_write_file(self, sandbox_manager):
        """Test writing file to sandbox workspace."""
        sandbox_id = await sandbox_manager.create_sandbox(language="python")

        result = await sandbox_manager.write_file(
            sandbox_id=sandbox_id,
            file_path="config.json",
            content='{"key": "value"}',
        )

        assert result.success is True
        assert result.path == "config.json"

        # Verify file was written
        sandbox = sandbox_manager._sandboxes[sandbox_id]
        file_path = Path(sandbox.workspace_path) / "config.json"
        assert file_path.exists()
        assert file_path.read_text() == '{"key": "value"}'

    @pytest.mark.asyncio
    async def test_write_file_with_subdirectory(self, sandbox_manager):
        """Test writing file to subdirectory."""
        sandbox_id = await sandbox_manager.create_sandbox(language="python")

        result = await sandbox_manager.write_file(
            sandbox_id=sandbox_id,
            file_path="data/output.txt",
            content="Hello",
        )

        assert result.success is True

        # Verify file and directory created
        sandbox = sandbox_manager._sandboxes[sandbox_id]
        file_path = Path(sandbox.workspace_path) / "data" / "output.txt"
        assert file_path.exists()
        assert file_path.read_text() == "Hello"

    @pytest.mark.asyncio
    async def test_write_file_directory_traversal(self, sandbox_manager):
        """Test that directory traversal is blocked."""
        sandbox_id = await sandbox_manager.create_sandbox(language="python")

        result = await sandbox_manager.write_file(
            sandbox_id=sandbox_id,
            file_path="../../../etc/passwd",
            content="malicious",
        )

        assert result.success is False
        assert "Invalid path" in result.error

    @pytest.mark.asyncio
    async def test_read_file(self, sandbox_manager):
        """Test reading file from sandbox workspace."""
        sandbox_id = await sandbox_manager.create_sandbox(language="python")

        # Write file first
        await sandbox_manager.write_file(
            sandbox_id=sandbox_id,
            file_path="test.txt",
            content="Hello, World!",
        )

        # Read file
        result = await sandbox_manager.read_file(
            sandbox_id=sandbox_id,
            file_path="test.txt",
        )

        assert result.success is True
        assert result.content == "Hello, World!"

    @pytest.mark.asyncio
    async def test_read_file_not_found(self, sandbox_manager):
        """Test reading non-existent file."""
        sandbox_id = await sandbox_manager.create_sandbox(language="python")

        result = await sandbox_manager.read_file(
            sandbox_id=sandbox_id,
            file_path="nonexistent.txt",
        )

        assert result.success is False
        assert "not found" in result.error.lower()

    @pytest.mark.asyncio
    async def test_list_files(self, sandbox_manager):
        """Test listing files in sandbox workspace."""
        sandbox_id = await sandbox_manager.create_sandbox(language="python")

        # Write some files
        await sandbox_manager.write_file(sandbox_id, "file1.txt", "content1")
        await sandbox_manager.write_file(sandbox_id, "file2.txt", "content2")
        await sandbox_manager.write_file(sandbox_id, "data/file3.txt", "content3")

        # List files
        result = await sandbox_manager.list_files(sandbox_id, path=".")

        assert result.success is True
        assert "file1.txt" in result.files
        assert "file2.txt" in result.files
        assert "data" in result.files

    @pytest.mark.asyncio
    async def test_list_files_not_directory(self, sandbox_manager):
        """Test listing files on a file (not directory)."""
        sandbox_id = await sandbox_manager.create_sandbox(language="python")

        # Write a file
        await sandbox_manager.write_file(sandbox_id, "test.txt", "content")

        # Try to list it
        result = await sandbox_manager.list_files(sandbox_id, path="test.txt")

        assert result.success is False
        assert "Not a directory" in result.error

    @pytest.mark.asyncio
    async def test_destroy_sandbox(self, sandbox_manager):
        """Test destroying sandbox and cleanup."""
        sandbox_id = await sandbox_manager.create_sandbox(language="python")

        # Write a file
        await sandbox_manager.write_file(sandbox_id, "test.txt", "content")

        # Get workspace path
        sandbox = sandbox_manager._sandboxes[sandbox_id]
        workspace_path = Path(sandbox.workspace_path)
        assert workspace_path.exists()

        # Destroy sandbox
        await sandbox_manager.destroy_sandbox(sandbox_id)

        # Verify cleanup
        assert sandbox_id not in sandbox_manager._sandboxes
        assert not workspace_path.exists()

    @pytest.mark.asyncio
    async def test_destroy_sandbox_not_found(self, sandbox_manager):
        """Test destroying non-existent sandbox."""
        with pytest.raises(ValueError, match="Sandbox not found"):
            await sandbox_manager.destroy_sandbox("nonexistent")

    @pytest.mark.asyncio
    async def test_stop_cleanup_all_sandboxes(self, sandbox_manager):
        """Test that stop() cleans up all sandboxes."""
        # Create multiple sandboxes
        await sandbox_manager.create_sandbox(language="python")
        await sandbox_manager.create_sandbox(language="javascript")

        assert len(sandbox_manager._sandboxes) == 2

        # Stop manager
        await sandbox_manager.stop()

        # Verify all sandboxes destroyed
        assert len(sandbox_manager._sandboxes) == 0

    def test_get_code_filename(self, sandbox_manager):
        """Test getting code filename for languages."""
        assert sandbox_manager._get_code_filename("python") == "script.py"
        assert sandbox_manager._get_code_filename("javascript") == "script.js"
        assert sandbox_manager._get_code_filename("shell") == "script.sh"

    def test_get_execution_command(self, sandbox_manager):
        """Test getting execution command for languages."""
        assert sandbox_manager._get_execution_command("python", "script.py") == [
            "python",
            "script.py",
        ]
        assert sandbox_manager._get_execution_command("javascript", "script.js") == [
            "node",
            "script.js",
        ]
        assert sandbox_manager._get_execution_command("shell", "script.sh") == [
            "bash",
            "script.sh",
        ]

    def test_get_install_command(self, sandbox_manager):
        """Test getting package install command."""
        # Python + PyPI
        cmd = sandbox_manager._get_install_command("python", "requests", "pypi")
        assert cmd == ["pip", "install", "--target=/workspace/.packages", "requests"]

        # JavaScript + npm
        cmd = sandbox_manager._get_install_command("javascript", "axios", "npm")
        assert cmd == ["npm", "install", "--prefix=/workspace", "axios"]

        # Unsupported
        cmd = sandbox_manager._get_install_command("shell", "pkg", "other")
        assert cmd is None

    def test_sanitize_path(self, sandbox_manager):
        """Test path sanitization."""
        # Valid paths
        assert sandbox_manager._sanitize_path("file.txt") == "file.txt"
        assert sandbox_manager._sanitize_path("data/file.txt") == "data/file.txt"
        assert sandbox_manager._sanitize_path("/file.txt") == "file.txt"

        # Invalid paths
        with pytest.raises(ValueError, match="Invalid path"):
            sandbox_manager._sanitize_path("../etc/passwd")

        with pytest.raises(ValueError, match="Invalid path"):
            sandbox_manager._sanitize_path("data/../../etc/passwd")
