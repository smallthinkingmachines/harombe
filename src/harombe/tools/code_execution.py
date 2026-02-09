"""
Code execution tools for Phase 4.7.

Provides MCP-compatible tools for executing code in gVisor sandboxes with:
- Multi-language support (Python, JavaScript, shell)
- Air-gapped execution by default
- Optional package installation from allowlisted registries
- File operations within isolated workspace
"""

import logging
from typing import Any

from harombe.security.sandbox_manager import SandboxManager

logger = logging.getLogger(__name__)


class CodeExecutionTools:
    """Code execution tools with gVisor sandbox."""

    def __init__(self, sandbox_manager: SandboxManager):
        """Initialize code execution tools.

        Args:
            sandbox_manager: Sandbox manager instance
        """
        self.sandbox_manager = sandbox_manager

    async def code_execute(
        self,
        language: str,
        code: str,
        sandbox_id: str | None = None,
        timeout: int = 30,
        network_enabled: bool = False,
        allowed_domains: list[str] | None = None,
    ) -> dict[str, Any]:
        """Execute code in isolated gVisor sandbox.

        Args:
            language: Programming language (python, javascript, shell)
            code: Code to execute
            sandbox_id: Optional existing sandbox ID (creates new if not provided)
            timeout: Execution timeout in seconds
            network_enabled: Enable network access (requires HITL approval)
            allowed_domains: Allowlisted domains when network enabled

        Returns:
            Execution result with stdout, stderr, exit_code
        """
        try:
            # Create sandbox if needed
            if sandbox_id is None:
                sandbox_id = await self.sandbox_manager.create_sandbox(
                    language=language,
                    network_enabled=network_enabled,
                    allowed_domains=allowed_domains or [],
                )
                logger.info(f"Created sandbox {sandbox_id} for {language}")
            else:
                # Verify sandbox exists
                self.sandbox_manager._get_sandbox(sandbox_id)

            # Execute code
            result = await self.sandbox_manager.execute_code(
                sandbox_id=sandbox_id,
                code=code,
                timeout=timeout,
            )

            return {
                "success": result.success,
                "sandbox_id": sandbox_id,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "exit_code": result.exit_code,
                "execution_time": result.execution_time,
                "error": result.error,
            }

        except Exception as e:
            logger.error(f"code_execute failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "error_type": type(e).__name__,
            }

    async def code_install_package(
        self,
        sandbox_id: str,
        package: str,
        registry: str = "pypi",
    ) -> dict[str, Any]:
        """Install package in sandbox from allowlisted registry.

        Args:
            sandbox_id: Sandbox ID
            package: Package name with optional version (e.g., "requests==2.31.0")
            registry: Registry name (pypi, npm)

        Returns:
            Installation result
        """
        try:
            result = await self.sandbox_manager.install_package(
                sandbox_id=sandbox_id,
                package=package,
                registry=registry,
            )

            return {
                "success": result.success,
                "sandbox_id": sandbox_id,
                "package": result.package,
                "registry": result.registry,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "error": result.error,
            }

        except Exception as e:
            logger.error(f"code_install_package failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "error_type": type(e).__name__,
            }

    async def code_write_file(
        self,
        sandbox_id: str,
        file_path: str,
        content: str,
    ) -> dict[str, Any]:
        """Write file to sandbox workspace.

        Args:
            sandbox_id: Sandbox ID
            file_path: File path relative to /workspace
            content: File content

        Returns:
            Write result
        """
        try:
            result = await self.sandbox_manager.write_file(
                sandbox_id=sandbox_id,
                file_path=file_path,
                content=content,
            )

            return {
                "success": result.success,
                "sandbox_id": sandbox_id,
                "file_path": result.path,
                "error": result.error,
            }

        except Exception as e:
            logger.error(f"code_write_file failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "error_type": type(e).__name__,
            }

    async def code_read_file(
        self,
        sandbox_id: str,
        file_path: str,
    ) -> dict[str, Any]:
        """Read file from sandbox workspace.

        Args:
            sandbox_id: Sandbox ID
            file_path: File path relative to /workspace

        Returns:
            Read result with file content
        """
        try:
            result = await self.sandbox_manager.read_file(
                sandbox_id=sandbox_id,
                file_path=file_path,
            )

            return {
                "success": result.success,
                "sandbox_id": sandbox_id,
                "file_path": result.path,
                "content": result.content,
                "error": result.error,
            }

        except Exception as e:
            logger.error(f"code_read_file failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "error_type": type(e).__name__,
            }

    async def code_list_files(
        self,
        sandbox_id: str,
        path: str = ".",
    ) -> dict[str, Any]:
        """List files in sandbox workspace.

        Args:
            sandbox_id: Sandbox ID
            path: Directory path relative to /workspace

        Returns:
            List result with file names
        """
        try:
            result = await self.sandbox_manager.list_files(
                sandbox_id=sandbox_id,
                path=path,
            )

            return {
                "success": result.success,
                "sandbox_id": sandbox_id,
                "path": result.path,
                "files": result.files,
                "error": result.error,
            }

        except Exception as e:
            logger.error(f"code_list_files failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "error_type": type(e).__name__,
            }

    async def code_destroy_sandbox(
        self,
        sandbox_id: str,
    ) -> dict[str, Any]:
        """Destroy sandbox and cleanup resources.

        Args:
            sandbox_id: Sandbox ID

        Returns:
            Destroy result
        """
        try:
            await self.sandbox_manager.destroy_sandbox(sandbox_id)

            return {
                "success": True,
                "sandbox_id": sandbox_id,
                "message": "Sandbox destroyed successfully",
            }

        except Exception as e:
            logger.error(f"code_destroy_sandbox failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "error_type": type(e).__name__,
            }
