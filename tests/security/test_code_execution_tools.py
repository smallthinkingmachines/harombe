"""
Tests for CodeExecutionTools.

Tests the MCP tool layer that wraps SandboxManager, covering
all six tools: code_execute, code_install_package, code_write_file,
code_read_file, code_list_files, code_destroy_sandbox.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from harombe.security.docker_manager import DockerManager
from harombe.security.sandbox_manager import (
    SandboxManager,
)
from harombe.tools.code_execution import CodeExecutionTools


class TestCodeExecute:
    """Tests for code_execute tool."""

    @pytest.fixture
    def docker_manager(self):
        manager = MagicMock(spec=DockerManager)
        manager.client = MagicMock()
        manager.start = AsyncMock()
        manager.stop = AsyncMock()
        return manager

    @pytest.fixture
    def sandbox_manager(self, docker_manager):
        return SandboxManager(docker_manager=docker_manager, runtime="runsc")

    @pytest.fixture
    def tools(self, sandbox_manager):
        return CodeExecutionTools(sandbox_manager=sandbox_manager)

    @pytest.mark.asyncio
    async def test_creates_sandbox_and_executes(self, tools, sandbox_manager):
        """Test that code_execute creates a sandbox when no ID is given."""
        mock_container = MagicMock()
        mock_container.start = MagicMock()
        mock_container.wait = MagicMock(return_value={"StatusCode": 0})
        mock_container.logs = MagicMock(return_value=b"42\n")
        mock_container.remove = MagicMock()

        sandbox_manager.docker_manager.client.containers.create = MagicMock(
            return_value=mock_container
        )

        result = await tools.code_execute(language="python", code="print(42)")

        assert result["success"] is True
        assert result["stdout"] == "42\n"
        assert result["exit_code"] == 0
        assert "sandbox_id" in result

    @pytest.mark.asyncio
    async def test_reuses_existing_sandbox(self, tools, sandbox_manager):
        """Test that code_execute reuses an existing sandbox."""
        sandbox_id = await sandbox_manager.create_sandbox(language="python")

        mock_container = MagicMock()
        mock_container.start = MagicMock()
        mock_container.wait = MagicMock(return_value={"StatusCode": 0})
        mock_container.logs = MagicMock(return_value=b"ok\n")
        mock_container.remove = MagicMock()

        sandbox_manager.docker_manager.client.containers.create = MagicMock(
            return_value=mock_container
        )

        result = await tools.code_execute(
            language="python",
            code="print('ok')",
            sandbox_id=sandbox_id,
        )

        assert result["success"] is True
        assert result["sandbox_id"] == sandbox_id

    @pytest.mark.asyncio
    async def test_nonexistent_sandbox_returns_error(self, tools):
        """Test that passing a bad sandbox_id returns an error dict."""
        result = await tools.code_execute(
            language="python",
            code="print(1)",
            sandbox_id="does-not-exist",
        )

        assert result["success"] is False
        assert "error" in result

    @pytest.mark.asyncio
    async def test_execution_failure_returns_stderr(self, tools, sandbox_manager):
        """Test that a non-zero exit code is reported."""
        mock_container = MagicMock()
        mock_container.start = MagicMock()
        mock_container.wait = MagicMock(return_value={"StatusCode": 1})
        mock_container.logs = MagicMock(return_value=b"NameError: name 'x' is not defined\n")
        mock_container.remove = MagicMock()

        sandbox_manager.docker_manager.client.containers.create = MagicMock(
            return_value=mock_container
        )

        result = await tools.code_execute(language="python", code="print(x)")

        assert result["success"] is False
        assert result["exit_code"] == 1

    @pytest.mark.asyncio
    async def test_network_enabled_passed_through(self, tools, sandbox_manager):
        """Test that network_enabled flag reaches the sandbox."""
        mock_container = MagicMock()
        mock_container.start = MagicMock()
        mock_container.wait = MagicMock(return_value={"StatusCode": 0})
        mock_container.logs = MagicMock(return_value=b"ok\n")
        mock_container.remove = MagicMock()

        sandbox_manager.docker_manager.client.containers.create = MagicMock(
            return_value=mock_container
        )

        result = await tools.code_execute(
            language="python",
            code="print('ok')",
            network_enabled=True,
            allowed_domains=["pypi.org"],
        )

        assert result["success"] is True
        sandbox_id = result["sandbox_id"]
        sandbox = sandbox_manager._sandboxes[sandbox_id]
        assert sandbox.network_enabled is True
        assert "pypi.org" in sandbox.allowed_domains


class TestCodeInstallPackage:
    """Tests for code_install_package tool."""

    @pytest.fixture
    def docker_manager(self):
        manager = MagicMock(spec=DockerManager)
        manager.client = MagicMock()
        return manager

    @pytest.fixture
    def sandbox_manager(self, docker_manager):
        return SandboxManager(docker_manager=docker_manager, runtime="runsc")

    @pytest.fixture
    def tools(self, sandbox_manager):
        return CodeExecutionTools(sandbox_manager=sandbox_manager)

    @pytest.mark.asyncio
    async def test_install_success(self, tools, sandbox_manager):
        """Test successful package installation."""
        sandbox_id = await sandbox_manager.create_sandbox(language="python", network_enabled=True)

        mock_container = MagicMock()
        mock_container.start = MagicMock()
        mock_container.wait = MagicMock(return_value={"StatusCode": 0})
        mock_container.logs = MagicMock(return_value=b"Successfully installed requests\n")
        mock_container.remove = MagicMock()

        sandbox_manager.docker_manager.client.containers.create = MagicMock(
            return_value=mock_container
        )

        result = await tools.code_install_package(
            sandbox_id=sandbox_id, package="requests", registry="pypi"
        )

        assert result["success"] is True
        assert result["package"] == "requests"

    @pytest.mark.asyncio
    async def test_install_no_network_fails(self, tools, sandbox_manager):
        """Test that installation fails without network."""
        sandbox_id = await sandbox_manager.create_sandbox(language="python", network_enabled=False)

        result = await tools.code_install_package(
            sandbox_id=sandbox_id, package="requests", registry="pypi"
        )

        assert result["success"] is False
        assert "error" in result

    @pytest.mark.asyncio
    async def test_install_bad_sandbox_returns_error(self, tools):
        """Test that a bad sandbox_id returns an error dict."""
        result = await tools.code_install_package(sandbox_id="missing", package="requests")

        assert result["success"] is False
        assert "error" in result


class TestCodeFileOperations:
    """Tests for code_write_file, code_read_file, code_list_files."""

    @pytest.fixture
    def docker_manager(self):
        manager = MagicMock(spec=DockerManager)
        manager.client = MagicMock()
        return manager

    @pytest.fixture
    def sandbox_manager(self, docker_manager):
        return SandboxManager(docker_manager=docker_manager, runtime="runsc")

    @pytest.fixture
    def tools(self, sandbox_manager):
        return CodeExecutionTools(sandbox_manager=sandbox_manager)

    @pytest.mark.asyncio
    async def test_write_and_read_file(self, tools, sandbox_manager):
        """Test writing then reading a file."""
        sandbox_id = await sandbox_manager.create_sandbox(language="python")

        write_result = await tools.code_write_file(
            sandbox_id=sandbox_id, file_path="data.json", content='{"key": "value"}'
        )
        assert write_result["success"] is True

        read_result = await tools.code_read_file(sandbox_id=sandbox_id, file_path="data.json")
        assert read_result["success"] is True
        assert read_result["content"] == '{"key": "value"}'

    @pytest.mark.asyncio
    async def test_read_nonexistent_file(self, tools, sandbox_manager):
        """Test reading a file that doesn't exist."""
        sandbox_id = await sandbox_manager.create_sandbox(language="python")

        result = await tools.code_read_file(sandbox_id=sandbox_id, file_path="missing.txt")

        assert result["success"] is False
        assert "error" in result

    @pytest.mark.asyncio
    async def test_list_files(self, tools, sandbox_manager):
        """Test listing files in workspace."""
        sandbox_id = await sandbox_manager.create_sandbox(language="python")

        await tools.code_write_file(sandbox_id=sandbox_id, file_path="a.txt", content="a")
        await tools.code_write_file(sandbox_id=sandbox_id, file_path="b.txt", content="b")

        result = await tools.code_list_files(sandbox_id=sandbox_id, path=".")

        assert result["success"] is True
        assert "a.txt" in result["files"]
        assert "b.txt" in result["files"]

    @pytest.mark.asyncio
    async def test_write_file_bad_sandbox(self, tools):
        """Test writing to a non-existent sandbox."""
        result = await tools.code_write_file(sandbox_id="missing", file_path="f.txt", content="x")
        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_directory_traversal_blocked(self, tools, sandbox_manager):
        """Test that directory traversal is blocked at the tool layer."""
        sandbox_id = await sandbox_manager.create_sandbox(language="python")

        result = await tools.code_write_file(
            sandbox_id=sandbox_id, file_path="../../etc/passwd", content="bad"
        )
        assert result["success"] is False


class TestCodeDestroySandbox:
    """Tests for code_destroy_sandbox tool."""

    @pytest.fixture
    def docker_manager(self):
        manager = MagicMock(spec=DockerManager)
        manager.client = MagicMock()
        return manager

    @pytest.fixture
    def sandbox_manager(self, docker_manager):
        return SandboxManager(docker_manager=docker_manager, runtime="runsc")

    @pytest.fixture
    def tools(self, sandbox_manager):
        return CodeExecutionTools(sandbox_manager=sandbox_manager)

    @pytest.mark.asyncio
    async def test_destroy_success(self, tools, sandbox_manager):
        """Test successful sandbox destruction."""
        sandbox_id = await sandbox_manager.create_sandbox(language="python")
        assert sandbox_id in sandbox_manager._sandboxes

        result = await tools.code_destroy_sandbox(sandbox_id=sandbox_id)

        assert result["success"] is True
        assert sandbox_id not in sandbox_manager._sandboxes

    @pytest.mark.asyncio
    async def test_destroy_nonexistent(self, tools):
        """Test destroying a sandbox that doesn't exist."""
        result = await tools.code_destroy_sandbox(sandbox_id="missing")
        assert result["success"] is False
        assert "error" in result


class TestSandboxHITLRules:
    """Tests for sandbox HITL risk classification rules."""

    def test_rules_are_defined(self):
        """Test that sandbox HITL rules exist and are structured correctly."""
        from harombe.security.sandbox_risk import get_sandbox_hitl_rules

        rules = get_sandbox_hitl_rules()

        assert len(rules) >= 8
        tool_names = {tool for rule in rules for tool in rule.tools}
        assert "code_execute" in tool_names
        assert "code_install_package" in tool_names
        assert "code_write_file" in tool_names
        assert "code_read_file" in tool_names
        assert "code_list_files" in tool_names
        assert "code_destroy_sandbox" in tool_names

    def test_code_execute_with_network_is_critical(self):
        """Test that code execution with network is classified as CRITICAL."""
        from harombe.security.hitl import RiskLevel
        from harombe.security.sandbox_risk import get_sandbox_hitl_rules

        rules = get_sandbox_hitl_rules()
        network_rules = [
            r
            for r in rules
            if "code_execute" in r.tools
            and r.conditions
            and any(c.get("param") == "network_enabled" for c in r.conditions)
        ]

        assert len(network_rules) == 1
        assert network_rules[0].risk == RiskLevel.CRITICAL

    def test_dangerous_patterns_are_critical(self):
        """Test that dangerous code patterns are classified as CRITICAL."""
        from harombe.security.hitl import RiskLevel
        from harombe.security.sandbox_risk import get_sandbox_hitl_rules

        rules = get_sandbox_hitl_rules()
        pattern_rules = [
            r
            for r in rules
            if "code_execute" in r.tools
            and r.conditions
            and any(c.get("param") == "code" for c in r.conditions)
        ]

        assert len(pattern_rules) == 1
        assert pattern_rules[0].risk == RiskLevel.CRITICAL

    def test_sandbox_destroy_is_low_risk(self):
        """Test that sandbox cleanup is LOW risk and auto-approved."""
        from harombe.security.hitl import RiskLevel
        from harombe.security.sandbox_risk import get_sandbox_hitl_rules

        rules = get_sandbox_hitl_rules()
        destroy_rules = [r for r in rules if "code_destroy_sandbox" in r.tools]

        assert len(destroy_rules) == 1
        assert destroy_rules[0].risk == RiskLevel.LOW
        assert destroy_rules[0].require_approval is False

    def test_allowed_registries(self):
        """Test that allowed registries are correctly defined."""
        from harombe.security.sandbox_risk import get_allowed_registries

        registries = get_allowed_registries()

        assert "pypi" in registries["python"]
        assert "npm" in registries["javascript"]
        assert registries["shell"] == []


class TestGatewayRoutes:
    """Tests for gateway tool route registration."""

    def test_sandbox_tools_are_routed(self):
        """Test that all sandbox tools have gateway routes."""
        from harombe.security.gateway import _tool_routes

        expected = [
            "code_execute",
            "code_install_package",
            "code_write_file",
            "code_read_file",
            "code_list_files",
            "code_destroy_sandbox",
        ]

        for tool_name in expected:
            assert tool_name in _tool_routes, f"Missing gateway route for {tool_name}"
            assert "code-exec" in _tool_routes[tool_name]
