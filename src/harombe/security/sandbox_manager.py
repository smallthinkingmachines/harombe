"""
gVisor-based code execution sandbox manager for Phase 4.7.

Provides secure code execution with:
- gVisor application kernel isolation
- Air-gapped by default (network disabled)
- Resource constraints (CPU, memory, disk, time)
- Multi-language support (Python, Node.js, shell)
- Optional package installation from allowlisted registries
"""

import asyncio
import logging
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from harombe.security.docker_manager import DockerManager

logger = logging.getLogger(__name__)


@dataclass
class ExecutionResult:
    """Result of code execution in sandbox."""

    success: bool
    stdout: str
    stderr: str
    exit_code: int
    execution_time: float
    error: str | None = None


@dataclass
class InstallResult:
    """Result of package installation."""

    success: bool
    package: str
    registry: str
    stdout: str
    stderr: str
    error: str | None = None


@dataclass
class FileResult:
    """Result of file operations."""

    success: bool
    path: str
    content: str | None = None
    files: list[str] | None = None
    error: str | None = None


@dataclass
class Sandbox:
    """Represents a gVisor sandbox instance."""

    sandbox_id: str
    language: str
    container_id: str | None = None
    network_enabled: bool = False
    allowed_domains: list[str] = field(default_factory=list)
    workspace_path: str | None = None
    created_at: float = field(default_factory=time.time)
    execution_count: int = 0


class SandboxManager:
    """Manages gVisor sandbox lifecycle and code execution."""

    def __init__(
        self,
        docker_manager: DockerManager,
        runtime: str | None = None,
        max_memory_mb: int = 512,
        max_cpu_cores: float = 0.5,
        max_disk_mb: int = 1024,
        max_execution_time: int = 30,
        max_output_bytes: int = 1_048_576,
    ):
        """Initialize sandbox manager.

        Args:
            docker_manager: Docker manager instance
            runtime: Container runtime. None = auto-detect based on engine
                     (Docker → "runsc" for gVisor, Podman → "crun")
            max_memory_mb: Maximum memory per sandbox (MB)
            max_cpu_cores: Maximum CPU cores per sandbox
            max_disk_mb: Maximum disk space per sandbox (MB)
            max_execution_time: Maximum execution time per run (seconds)
            max_output_bytes: Maximum output size (bytes)
        """
        self.docker_manager = docker_manager

        # Auto-detect runtime based on container engine
        if runtime is not None:
            self.runtime = runtime
        else:
            engine_info = docker_manager.engine_info
            if engine_info and engine_info.name == "podman":
                self.runtime = "crun"
                if not engine_info.supports_gvisor:
                    logger.info(
                        "Podman detected — using '%s' runtime (gVisor not available)",
                        self.runtime,
                    )
            else:
                self.runtime = "runsc"
        self.max_memory_mb = max_memory_mb
        self.max_cpu_cores = max_cpu_cores
        self.max_disk_mb = max_disk_mb
        self.max_execution_time = max_execution_time
        self.max_output_bytes = max_output_bytes

        # Active sandboxes
        self._sandboxes: dict[str, Sandbox] = {}

        # Language-specific images
        self._images = {
            "python": "python:3.11-slim",
            "javascript": "node:20-slim",
            "shell": "bash:5.2",
        }

    async def start(self) -> None:
        """Start the sandbox manager."""
        await self.docker_manager.start()
        logger.info("SandboxManager started with runtime=%s", self.runtime)

    async def stop(self) -> None:
        """Stop the sandbox manager and cleanup all sandboxes."""
        # Destroy all active sandboxes
        sandbox_ids = list(self._sandboxes.keys())
        for sandbox_id in sandbox_ids:
            try:
                await self.destroy_sandbox(sandbox_id)
            except Exception as e:
                logger.error(f"Error destroying sandbox {sandbox_id}: {e}")

        await self.docker_manager.stop()
        logger.info("SandboxManager stopped")

    async def create_sandbox(
        self,
        language: str,
        sandbox_id: str | None = None,
        network_enabled: bool = False,
        allowed_domains: list[str] | None = None,
    ) -> str:
        """Create a new gVisor sandbox.

        Args:
            language: Programming language (python, javascript, shell)
            sandbox_id: Optional sandbox ID (generated if not provided)
            network_enabled: Enable network access
            allowed_domains: Allowlisted domains (when network enabled)

        Returns:
            Sandbox ID

        Raises:
            ValueError: If language not supported or Docker not started
        """
        if language not in self._images:
            raise ValueError(
                f"Unsupported language: {language}. " f"Supported: {list(self._images.keys())}"
            )

        if not self.docker_manager.client:
            raise RuntimeError("Docker manager not started")

        # Generate sandbox ID
        if sandbox_id is None:
            sandbox_id = f"sandbox-{uuid.uuid4().hex[:8]}"

        # Create temporary workspace
        workspace_path = f"/tmp/harombe-sandbox-{sandbox_id}"
        Path(workspace_path).mkdir(parents=True, exist_ok=True)

        # Create sandbox instance
        sandbox = Sandbox(
            sandbox_id=sandbox_id,
            language=language,
            network_enabled=network_enabled,
            allowed_domains=allowed_domains or [],
            workspace_path=workspace_path,
        )

        self._sandboxes[sandbox_id] = sandbox

        logger.info(
            f"Created sandbox {sandbox_id} for {language} " f"(network_enabled={network_enabled})"
        )

        return sandbox_id

    async def execute_code(
        self,
        sandbox_id: str,
        code: str,
        timeout: int | None = None,
        max_memory_mb: int | None = None,
    ) -> ExecutionResult:
        """Execute code in sandbox.

        Args:
            sandbox_id: Sandbox ID
            code: Code to execute
            timeout: Execution timeout (uses default if not provided)
            max_memory_mb: Memory limit (uses default if not provided)

        Returns:
            Execution result with stdout, stderr, exit_code

        Raises:
            ValueError: If sandbox not found
        """
        sandbox = self._get_sandbox(sandbox_id)

        timeout = timeout or self.max_execution_time
        max_memory_mb = max_memory_mb or self.max_memory_mb

        # Write code to workspace
        assert sandbox.workspace_path is not None, "Sandbox workspace not initialized"
        code_file = self._get_code_filename(sandbox.language)
        code_path = Path(sandbox.workspace_path) / code_file
        code_path.write_text(code)

        # Get execution command
        command = self._get_execution_command(sandbox.language, code_file)

        # Create container configuration
        container_config = {
            "image": self._images[sandbox.language],
            "runtime": self.runtime,
            "command": command,
            "network_mode": "none" if not sandbox.network_enabled else "bridge",
            "mem_limit": f"{max_memory_mb}m",
            "cpu_period": 100000,
            "cpu_quota": int(self.max_cpu_cores * 100000),
            "volumes": {
                sandbox.workspace_path: {
                    "bind": "/workspace",
                    "mode": "rw",
                }
            },
            "working_dir": "/workspace",
            "remove": True,
            "detach": False,
        }

        start_time = time.time()

        try:
            # Run container
            result = await self._run_container(container_config, timeout)

            execution_time = time.time() - start_time

            # Truncate output if too large
            stdout = result["stdout"][: self.max_output_bytes]
            stderr = result["stderr"][: self.max_output_bytes]

            if len(result["stdout"]) > self.max_output_bytes:
                stdout += "\n[OUTPUT TRUNCATED]"
            if len(result["stderr"]) > self.max_output_bytes:
                stderr += "\n[OUTPUT TRUNCATED]"

            sandbox.execution_count += 1

            logger.info(
                f"Executed code in sandbox {sandbox_id} "
                f"(exit_code={result['exit_code']}, time={execution_time:.2f}s)"
            )

            return ExecutionResult(
                success=result["exit_code"] == 0,
                stdout=stdout,
                stderr=stderr,
                exit_code=result["exit_code"],
                execution_time=execution_time,
            )

        except TimeoutError:
            execution_time = time.time() - start_time
            logger.warning(f"Code execution timeout in sandbox {sandbox_id}")
            return ExecutionResult(
                success=False,
                stdout="",
                stderr=f"Execution timeout after {timeout}s",
                exit_code=-1,
                execution_time=execution_time,
                error="TimeoutError",
            )
        except Exception as e:
            execution_time = time.time() - start_time
            logger.error(f"Code execution error in sandbox {sandbox_id}: {e}")
            return ExecutionResult(
                success=False,
                stdout="",
                stderr=str(e),
                exit_code=-1,
                execution_time=execution_time,
                error=type(e).__name__,
            )

    async def install_package(
        self,
        sandbox_id: str,
        package: str,
        registry: str = "pypi",
    ) -> InstallResult:
        """Install package in sandbox.

        Args:
            sandbox_id: Sandbox ID
            package: Package name (with optional version)
            registry: Registry name (pypi, npm)

        Returns:
            Installation result

        Raises:
            ValueError: If sandbox not found or registry not supported
        """
        sandbox = self._get_sandbox(sandbox_id)

        if not sandbox.network_enabled:
            return InstallResult(
                success=False,
                package=package,
                registry=registry,
                stdout="",
                stderr="Network access required for package installation",
                error="NetworkDisabled",
            )

        # Get install command
        install_cmd = self._get_install_command(sandbox.language, package, registry)

        if not install_cmd:
            return InstallResult(
                success=False,
                package=package,
                registry=registry,
                stdout="",
                stderr=f"Package installation not supported for {sandbox.language}",
                error="UnsupportedLanguage",
            )

        # Create container configuration
        assert sandbox.workspace_path is not None, "Sandbox workspace not initialized"
        container_config = {
            "image": self._images[sandbox.language],
            "runtime": self.runtime,
            "command": install_cmd,
            "network_mode": "bridge",  # Network required
            "mem_limit": f"{self.max_memory_mb}m",
            "volumes": {
                sandbox.workspace_path: {
                    "bind": "/workspace",
                    "mode": "rw",
                }
            },
            "working_dir": "/workspace",
            "remove": True,
            "detach": False,
        }

        try:
            result = await self._run_container(container_config, timeout=300)

            logger.info(
                f"Installed package {package} from {registry} "
                f"in sandbox {sandbox_id} (exit_code={result['exit_code']})"
            )

            return InstallResult(
                success=result["exit_code"] == 0,
                package=package,
                registry=registry,
                stdout=result["stdout"],
                stderr=result["stderr"],
            )

        except Exception as e:
            logger.error(f"Package installation error in sandbox {sandbox_id}: {e}")
            return InstallResult(
                success=False,
                package=package,
                registry=registry,
                stdout="",
                stderr=str(e),
                error=type(e).__name__,
            )

    async def write_file(
        self,
        sandbox_id: str,
        file_path: str,
        content: str,
    ) -> FileResult:
        """Write file to sandbox workspace.

        Args:
            sandbox_id: Sandbox ID
            file_path: File path (relative to /workspace)
            content: File content

        Returns:
            Write result
        """
        sandbox = self._get_sandbox(sandbox_id)

        try:
            # Ensure path is relative and within workspace
            assert sandbox.workspace_path is not None, "Sandbox workspace not initialized"
            clean_path = self._sanitize_path(file_path)
            full_path = Path(sandbox.workspace_path) / clean_path

            # Create parent directories
            full_path.parent.mkdir(parents=True, exist_ok=True)

            # Write file
            full_path.write_text(content)

            logger.info(f"Wrote file {file_path} in sandbox {sandbox_id}")

            return FileResult(
                success=True,
                path=file_path,
            )

        except Exception as e:
            logger.error(f"Write file error in sandbox {sandbox_id}: {e}")
            return FileResult(
                success=False,
                path=file_path,
                error=str(e),
            )

    async def read_file(
        self,
        sandbox_id: str,
        file_path: str,
    ) -> FileResult:
        """Read file from sandbox workspace.

        Args:
            sandbox_id: Sandbox ID
            file_path: File path (relative to /workspace)

        Returns:
            Read result with file content
        """
        sandbox = self._get_sandbox(sandbox_id)

        try:
            # Ensure path is relative and within workspace
            assert sandbox.workspace_path is not None, "Sandbox workspace not initialized"
            clean_path = self._sanitize_path(file_path)
            full_path = Path(sandbox.workspace_path) / clean_path

            # Read file
            content = full_path.read_text()

            logger.info(f"Read file {file_path} from sandbox {sandbox_id}")

            return FileResult(
                success=True,
                path=file_path,
                content=content,
            )

        except FileNotFoundError:
            return FileResult(
                success=False,
                path=file_path,
                error=f"File not found: {file_path}",
            )
        except Exception as e:
            logger.error(f"Read file error in sandbox {sandbox_id}: {e}")
            return FileResult(
                success=False,
                path=file_path,
                error=str(e),
            )

    async def list_files(
        self,
        sandbox_id: str,
        path: str = ".",
    ) -> FileResult:
        """List files in sandbox workspace.

        Args:
            sandbox_id: Sandbox ID
            path: Directory path (relative to /workspace)

        Returns:
            List result with file names
        """
        sandbox = self._get_sandbox(sandbox_id)

        try:
            # Ensure path is relative and within workspace
            assert sandbox.workspace_path is not None, "Sandbox workspace not initialized"
            clean_path = self._sanitize_path(path)
            full_path = Path(sandbox.workspace_path) / clean_path

            # List files
            if full_path.is_dir():
                files = [
                    str(p.relative_to(Path(sandbox.workspace_path))) for p in full_path.iterdir()
                ]
            else:
                return FileResult(
                    success=False,
                    path=path,
                    error=f"Not a directory: {path}",
                )

            logger.info(f"Listed files in {path} from sandbox {sandbox_id}")

            return FileResult(
                success=True,
                path=path,
                files=sorted(files),
            )

        except Exception as e:
            logger.error(f"List files error in sandbox {sandbox_id}: {e}")
            return FileResult(
                success=False,
                path=path,
                error=str(e),
            )

    async def destroy_sandbox(self, sandbox_id: str) -> None:
        """Destroy sandbox and cleanup resources.

        Args:
            sandbox_id: Sandbox ID

        Raises:
            ValueError: If sandbox not found
        """
        sandbox = self._get_sandbox(sandbox_id)

        # Cleanup workspace
        try:
            import shutil

            if sandbox.workspace_path and Path(sandbox.workspace_path).exists():
                shutil.rmtree(sandbox.workspace_path)
        except Exception as e:
            logger.warning(f"Error cleaning workspace for {sandbox_id}: {e}")

        # Remove from active sandboxes
        del self._sandboxes[sandbox_id]

        logger.info(f"Destroyed sandbox {sandbox_id}")

    def _get_sandbox(self, sandbox_id: str) -> Sandbox:
        """Get sandbox by ID.

        Args:
            sandbox_id: Sandbox ID

        Returns:
            Sandbox instance

        Raises:
            ValueError: If sandbox not found
        """
        if sandbox_id not in self._sandboxes:
            raise ValueError(f"Sandbox not found: {sandbox_id}")
        return self._sandboxes[sandbox_id]

    def _get_code_filename(self, language: str) -> str:
        """Get code filename for language."""
        filenames = {
            "python": "script.py",
            "javascript": "script.js",
            "shell": "script.sh",
        }
        return filenames[language]

    def _get_execution_command(self, language: str, code_file: str) -> list[str]:
        """Get execution command for language."""
        commands = {
            "python": ["python", code_file],
            "javascript": ["node", code_file],
            "shell": ["bash", code_file],
        }
        return commands[language]

    def _get_install_command(self, language: str, package: str, registry: str) -> list[str] | None:
        """Get package install command.

        Args:
            language: Programming language
            package: Package name
            registry: Registry name

        Returns:
            Install command or None if not supported
        """
        if language == "python" and registry == "pypi":
            return ["pip", "install", "--target=/workspace/.packages", package]
        elif language == "javascript" and registry == "npm":
            return ["npm", "install", "--prefix=/workspace", package]
        return None

    def _sanitize_path(self, path: str) -> str:
        """Sanitize file path to prevent directory traversal.

        Args:
            path: Input path

        Returns:
            Sanitized path

        Raises:
            ValueError: If path attempts directory traversal
        """
        # Remove leading slash
        clean_path = path.lstrip("/")

        # Check for directory traversal
        if ".." in clean_path or clean_path.startswith("/"):
            raise ValueError(f"Invalid path: {path}")

        return clean_path

    async def _run_container(self, config: dict[str, Any], timeout: int) -> dict[str, Any]:
        """Run container and capture output.

        Args:
            config: Container configuration
            timeout: Execution timeout (seconds)

        Returns:
            Result with stdout, stderr, exit_code
        """
        if not self.docker_manager.client:
            raise RuntimeError("Docker manager not started")

        # Create container
        container = await asyncio.to_thread(self.docker_manager.client.containers.create, **config)

        try:
            # Start container with timeout
            await asyncio.wait_for(
                asyncio.to_thread(container.start),
                timeout=timeout,
            )

            # Wait for completion
            result = await asyncio.wait_for(
                asyncio.to_thread(container.wait),
                timeout=timeout,
            )

            # Get logs
            logs = await asyncio.to_thread(container.logs, stdout=True, stderr=True)
            output = logs.decode("utf-8", errors="replace")

            # Parse stdout/stderr (simplified - both in output)
            return {
                "stdout": output,
                "stderr": "",
                "exit_code": result["StatusCode"],
            }

        except TimeoutError:
            # Kill container on timeout
            import contextlib

            with contextlib.suppress(Exception):
                await asyncio.to_thread(container.kill)
            raise

        finally:
            # Cleanup container
            import contextlib

            with contextlib.suppress(Exception):
                await asyncio.to_thread(container.remove, force=True)
