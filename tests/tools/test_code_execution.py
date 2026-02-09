"""
Tests for code execution tools.

Tests MCP-compatible code execution tools with sandbox integration.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from harombe.security.sandbox_manager import (
    ExecutionResult,
    FileResult,
    InstallResult,
    SandboxManager,
)
from harombe.tools.code_execution import CodeExecutionTools


class TestCodeExecutionTools:
    """Tests for CodeExecutionTools."""

    @pytest.fixture
    def sandbox_manager(self):
        """Mock sandbox manager."""
        manager = MagicMock(spec=SandboxManager)
        manager.create_sandbox = AsyncMock(return_value="sandbox-123")
        manager._get_sandbox = MagicMock()
        return manager

    @pytest.fixture
    def code_tools(self, sandbox_manager):
        """Create code execution tools."""
        return CodeExecutionTools(sandbox_manager=sandbox_manager)

    @pytest.mark.asyncio
    async def test_code_execute_creates_new_sandbox(self, code_tools, sandbox_manager):
        """Test that code_execute creates new sandbox if not provided."""
        sandbox_manager.execute_code = AsyncMock(
            return_value=ExecutionResult(
                success=True,
                stdout="Hello, World!\n",
                stderr="",
                exit_code=0,
                execution_time=0.5,
            )
        )

        result = await code_tools.code_execute(
            language="python",
            code="print('Hello, World!')",
        )

        # Should create new sandbox
        sandbox_manager.create_sandbox.assert_called_once_with(
            language="python",
            network_enabled=False,
            allowed_domains=[],
        )

        # Should execute code
        sandbox_manager.execute_code.assert_called_once()

        assert result["success"] is True
        assert result["sandbox_id"] == "sandbox-123"
        assert result["stdout"] == "Hello, World!\n"
        assert result["exit_code"] == 0

    @pytest.mark.asyncio
    async def test_code_execute_uses_existing_sandbox(self, code_tools, sandbox_manager):
        """Test that code_execute uses existing sandbox."""
        sandbox_manager.execute_code = AsyncMock(
            return_value=ExecutionResult(
                success=True,
                stdout="Result\n",
                stderr="",
                exit_code=0,
                execution_time=0.3,
            )
        )

        result = await code_tools.code_execute(
            language="python",
            code="print('Result')",
            sandbox_id="existing-sandbox",
        )

        # Should NOT create new sandbox
        sandbox_manager.create_sandbox.assert_not_called()

        # Should verify sandbox exists
        sandbox_manager._get_sandbox.assert_called_once_with("existing-sandbox")

        # Should execute code
        sandbox_manager.execute_code.assert_called_once()

        assert result["success"] is True
        assert result["sandbox_id"] == "existing-sandbox"

    @pytest.mark.asyncio
    async def test_code_execute_with_network(self, code_tools, sandbox_manager):
        """Test code execution with network enabled."""
        sandbox_manager.execute_code = AsyncMock(
            return_value=ExecutionResult(
                success=True,
                stdout="200\n",
                stderr="",
                exit_code=0,
                execution_time=1.2,
            )
        )

        result = await code_tools.code_execute(
            language="python",
            code="import requests; print(requests.get('https://pypi.org').status_code)",
            network_enabled=True,
            allowed_domains=["pypi.org"],
        )

        # Should create sandbox with network enabled
        sandbox_manager.create_sandbox.assert_called_once_with(
            language="python",
            network_enabled=True,
            allowed_domains=["pypi.org"],
        )

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_code_execute_with_timeout(self, code_tools, sandbox_manager):
        """Test code execution with custom timeout."""
        sandbox_manager.execute_code = AsyncMock(
            return_value=ExecutionResult(
                success=True,
                stdout="",
                stderr="",
                exit_code=0,
                execution_time=5.0,
            )
        )

        await code_tools.code_execute(
            language="python",
            code="import time; time.sleep(5)",
            timeout=60,
        )

        # Should pass timeout to execute_code
        call_args = sandbox_manager.execute_code.call_args
        assert call_args[1]["timeout"] == 60

    @pytest.mark.asyncio
    async def test_code_execute_failure(self, code_tools, sandbox_manager):
        """Test code execution with non-zero exit code."""
        sandbox_manager.execute_code = AsyncMock(
            return_value=ExecutionResult(
                success=False,
                stdout="",
                stderr="Error: division by zero\n",
                exit_code=1,
                execution_time=0.1,
                error="RuntimeError",
            )
        )

        result = await code_tools.code_execute(
            language="python",
            code="1/0",
        )

        assert result["success"] is False
        assert result["exit_code"] == 1
        assert "division by zero" in result["stderr"]
        assert result["error"] == "RuntimeError"

    @pytest.mark.asyncio
    async def test_code_execute_error_handling(self, code_tools, sandbox_manager):
        """Test error handling in code_execute."""
        sandbox_manager.create_sandbox = AsyncMock(side_effect=ValueError("Invalid language"))

        result = await code_tools.code_execute(
            language="invalid",
            code="print('hello')",
        )

        assert result["success"] is False
        assert "Invalid language" in result["error"]
        assert result["error_type"] == "ValueError"

    @pytest.mark.asyncio
    async def test_code_install_package_success(self, code_tools, sandbox_manager):
        """Test successful package installation."""
        sandbox_manager.install_package = AsyncMock(
            return_value=InstallResult(
                success=True,
                package="requests==2.31.0",
                registry="pypi",
                stdout="Successfully installed requests-2.31.0\n",
                stderr="",
            )
        )

        result = await code_tools.code_install_package(
            sandbox_id="sandbox-123",
            package="requests==2.31.0",
            registry="pypi",
        )

        sandbox_manager.install_package.assert_called_once_with(
            sandbox_id="sandbox-123",
            package="requests==2.31.0",
            registry="pypi",
        )

        assert result["success"] is True
        assert result["package"] == "requests==2.31.0"
        assert result["registry"] == "pypi"
        assert "Successfully installed" in result["stdout"]

    @pytest.mark.asyncio
    async def test_code_install_package_network_disabled(self, code_tools, sandbox_manager):
        """Test package installation when network disabled."""
        sandbox_manager.install_package = AsyncMock(
            return_value=InstallResult(
                success=False,
                package="requests",
                registry="pypi",
                stdout="",
                stderr="Network access required",
                error="NetworkDisabled",
            )
        )

        result = await code_tools.code_install_package(
            sandbox_id="sandbox-123",
            package="requests",
        )

        assert result["success"] is False
        assert result["error"] == "NetworkDisabled"
        assert "Network access required" in result["stderr"]

    @pytest.mark.asyncio
    async def test_code_write_file_success(self, code_tools, sandbox_manager):
        """Test writing file to sandbox."""
        sandbox_manager.write_file = AsyncMock(
            return_value=FileResult(
                success=True,
                path="config.json",
            )
        )

        result = await code_tools.code_write_file(
            sandbox_id="sandbox-123",
            file_path="config.json",
            content='{"key": "value"}',
        )

        sandbox_manager.write_file.assert_called_once_with(
            sandbox_id="sandbox-123",
            file_path="config.json",
            content='{"key": "value"}',
        )

        assert result["success"] is True
        assert result["file_path"] == "config.json"

    @pytest.mark.asyncio
    async def test_code_write_file_directory_traversal(self, code_tools, sandbox_manager):
        """Test that directory traversal is blocked."""
        sandbox_manager.write_file = AsyncMock(
            return_value=FileResult(
                success=False,
                path="../../../etc/passwd",
                error="Invalid path",
            )
        )

        result = await code_tools.code_write_file(
            sandbox_id="sandbox-123",
            file_path="../../../etc/passwd",
            content="malicious",
        )

        assert result["success"] is False
        assert "Invalid path" in result["error"]

    @pytest.mark.asyncio
    async def test_code_read_file_success(self, code_tools, sandbox_manager):
        """Test reading file from sandbox."""
        sandbox_manager.read_file = AsyncMock(
            return_value=FileResult(
                success=True,
                path="output.txt",
                content="Hello, World!\n",
            )
        )

        result = await code_tools.code_read_file(
            sandbox_id="sandbox-123",
            file_path="output.txt",
        )

        sandbox_manager.read_file.assert_called_once_with(
            sandbox_id="sandbox-123",
            file_path="output.txt",
        )

        assert result["success"] is True
        assert result["content"] == "Hello, World!\n"

    @pytest.mark.asyncio
    async def test_code_read_file_not_found(self, code_tools, sandbox_manager):
        """Test reading non-existent file."""
        sandbox_manager.read_file = AsyncMock(
            return_value=FileResult(
                success=False,
                path="nonexistent.txt",
                error="File not found: nonexistent.txt",
            )
        )

        result = await code_tools.code_read_file(
            sandbox_id="sandbox-123",
            file_path="nonexistent.txt",
        )

        assert result["success"] is False
        assert "not found" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_code_list_files_success(self, code_tools, sandbox_manager):
        """Test listing files in sandbox."""
        sandbox_manager.list_files = AsyncMock(
            return_value=FileResult(
                success=True,
                path=".",
                files=["script.py", "output.txt", "data"],
            )
        )

        result = await code_tools.code_list_files(
            sandbox_id="sandbox-123",
            path=".",
        )

        sandbox_manager.list_files.assert_called_once_with(
            sandbox_id="sandbox-123",
            path=".",
        )

        assert result["success"] is True
        assert len(result["files"]) == 3
        assert "script.py" in result["files"]

    @pytest.mark.asyncio
    async def test_code_list_files_subdirectory(self, code_tools, sandbox_manager):
        """Test listing files in subdirectory."""
        sandbox_manager.list_files = AsyncMock(
            return_value=FileResult(
                success=True,
                path="data",
                files=["data/file1.json", "data/file2.json"],
            )
        )

        result = await code_tools.code_list_files(
            sandbox_id="sandbox-123",
            path="data",
        )

        assert result["success"] is True
        assert len(result["files"]) == 2

    @pytest.mark.asyncio
    async def test_code_destroy_sandbox_success(self, code_tools, sandbox_manager):
        """Test destroying sandbox."""
        sandbox_manager.destroy_sandbox = AsyncMock()

        result = await code_tools.code_destroy_sandbox(
            sandbox_id="sandbox-123",
        )

        sandbox_manager.destroy_sandbox.assert_called_once_with("sandbox-123")

        assert result["success"] is True
        assert result["sandbox_id"] == "sandbox-123"
        assert "destroyed successfully" in result["message"].lower()

    @pytest.mark.asyncio
    async def test_code_destroy_sandbox_not_found(self, code_tools, sandbox_manager):
        """Test destroying non-existent sandbox."""
        sandbox_manager.destroy_sandbox = AsyncMock(
            side_effect=ValueError("Sandbox not found: nonexistent")
        )

        result = await code_tools.code_destroy_sandbox(
            sandbox_id="nonexistent",
        )

        assert result["success"] is False
        assert "Sandbox not found" in result["error"]
        assert result["error_type"] == "ValueError"

    @pytest.mark.asyncio
    async def test_all_tools_handle_exceptions(self, code_tools, sandbox_manager):
        """Test that all tools handle exceptions gracefully."""
        # Simulate various exceptions
        sandbox_manager.execute_code = AsyncMock(side_effect=RuntimeError("Execution error"))
        sandbox_manager.install_package = AsyncMock(side_effect=RuntimeError("Install error"))
        sandbox_manager.write_file = AsyncMock(side_effect=RuntimeError("Write error"))
        sandbox_manager.read_file = AsyncMock(side_effect=RuntimeError("Read error"))
        sandbox_manager.list_files = AsyncMock(side_effect=RuntimeError("List error"))
        sandbox_manager.destroy_sandbox = AsyncMock(side_effect=RuntimeError("Destroy error"))

        # Test all tools
        result1 = await code_tools.code_execute("python", "print('hi')")
        assert result1["success"] is False
        assert "Execution error" in result1["error"]

        result2 = await code_tools.code_install_package("sandbox-123", "requests")
        assert result2["success"] is False
        assert "Install error" in result2["error"]

        result3 = await code_tools.code_write_file("sandbox-123", "test.txt", "content")
        assert result3["success"] is False
        assert "Write error" in result3["error"]

        result4 = await code_tools.code_read_file("sandbox-123", "test.txt")
        assert result4["success"] is False
        assert "Read error" in result4["error"]

        result5 = await code_tools.code_list_files("sandbox-123", ".")
        assert result5["success"] is False
        assert "List error" in result5["error"]

        result6 = await code_tools.code_destroy_sandbox("sandbox-123")
        assert result6["success"] is False
        assert "Destroy error" in result6["error"]
