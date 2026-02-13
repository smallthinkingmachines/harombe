"""Container-based plugin isolation.

Provides Docker-based isolation for plugins, building custom images
with a FastAPI MCP scaffold and managing container lifecycle.
"""

from __future__ import annotations

import logging
import textwrap
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from harombe.security.docker_manager import DockerManager

logger = logging.getLogger(__name__)

BASE_PORT = 3100
MAX_CONTAINERS = 50


@dataclass
class PluginContainerConfig:
    """Configuration for a containerized plugin."""

    plugin_name: str
    plugin_path: str
    base_image: str = "python:3.12-slim"
    memory_mb: int = 256
    cpu_cores: float = 0.5
    pids_limit: int = 50
    network_domains: list[str] = field(default_factory=list)
    port: int | None = None
    extra_pip_packages: list[str] = field(default_factory=list)


@dataclass
class RunningPluginContainer:
    """Runtime state of a running plugin container."""

    name: str
    container_id: str
    host: str
    port: int
    tool_names: list[str] = field(default_factory=list)


class PluginContainerManager:
    """Manages containerized plugin lifecycle.

    Builds Docker images with auto-generated FastAPI MCP scaffolds,
    starts containers, applies network policies, and provides
    route information for gateway registration.
    """

    def __init__(self, docker_manager: DockerManager | None = None) -> None:
        self._docker = docker_manager
        self._running: dict[str, RunningPluginContainer] = {}
        self._next_port = BASE_PORT

    def _allocate_port(self) -> int:
        """Allocate the next available port."""
        if self._next_port >= BASE_PORT + MAX_CONTAINERS:
            msg = f"Maximum number of plugin containers ({MAX_CONTAINERS}) reached"
            raise RuntimeError(msg)
        port = self._next_port
        self._next_port += 1
        return port

    def _generate_dockerfile(self, config: PluginContainerConfig) -> str:
        """Generate a Dockerfile for a plugin.

        Args:
            config: Plugin container configuration

        Returns:
            Dockerfile content as a string
        """
        pip_install = ""
        if config.extra_pip_packages:
            packages = " ".join(config.extra_pip_packages)
            pip_install = f"RUN pip install --no-cache-dir {packages}"

        port = config.port or BASE_PORT

        return textwrap.dedent(f"""\
            FROM {config.base_image}

            WORKDIR /app

            RUN pip install --no-cache-dir fastapi uvicorn

            {pip_install}

            COPY plugin/ /app/plugin/
            COPY scaffold.py /app/scaffold.py

            EXPOSE {port}

            CMD ["python", "scaffold.py"]
        """)

    def _generate_scaffold(self, plugin_name: str, port: int) -> str:
        """Generate a FastAPI MCP server scaffold for a plugin.

        The scaffold discovers functions decorated with ``__tool_meta__``
        and exposes them via ``POST /mcp`` (tools/call, tools/list)
        and ``GET /health``.

        Args:
            plugin_name: Name of the plugin
            port: Port to listen on

        Returns:
            Python source code for the scaffold
        """
        return textwrap.dedent(f"""\
            \"\"\"Auto-generated MCP scaffold for plugin '{plugin_name}'.\"\"\"

            import importlib
            import json
            import sys
            import types
            import uuid
            from pathlib import Path

            from fastapi import FastAPI
            from fastapi.responses import JSONResponse

            app = FastAPI(title="{plugin_name} MCP Server")

            # Discover tools from the plugin module
            _tools: dict[str, dict] = {{}}


            def _discover_tools():
                plugin_dir = Path("/app/plugin")
                for py_file in plugin_dir.glob("*.py"):
                    if py_file.name.startswith("_"):
                        continue
                    mod_name = f"plugin.{{py_file.stem}}"
                    spec = importlib.util.spec_from_file_location(mod_name, py_file)
                    if spec is None or spec.loader is None:
                        continue
                    module = importlib.util.module_from_spec(spec)
                    sys.modules[mod_name] = module
                    spec.loader.exec_module(module)

                    for attr_name in dir(module):
                        obj = getattr(module, attr_name)
                        if callable(obj) and hasattr(obj, "__tool_meta__"):
                            meta = obj.__tool_meta__
                            _tools[meta.get("name", attr_name)] = {{
                                "function": obj,
                                "description": meta.get("description", ""),
                                "parameters": meta.get("parameters", {{}}),
                            }}


            _discover_tools()


            @app.get("/health")
            async def health():
                return {{"status": "healthy", "plugin": "{plugin_name}", "tools": list(_tools.keys())}}


            @app.post("/mcp")
            async def mcp_handler(request: dict):
                method = request.get("method", "")
                params = request.get("params", {{}})
                req_id = request.get("id", str(uuid.uuid4()))

                if method == "tools/list":
                    tool_list = [
                        {{"name": name, "description": info["description"], "inputSchema": info["parameters"]}}
                        for name, info in _tools.items()
                    ]
                    return JSONResponse(content={{"jsonrpc": "2.0", "id": req_id, "result": {{"tools": tool_list}}}})

                if method == "tools/call":
                    tool_name = params.get("name", "")
                    arguments = params.get("arguments", {{}})
                    tool = _tools.get(tool_name)
                    if tool is None:
                        return JSONResponse(
                            content={{"jsonrpc": "2.0", "id": req_id, "error": {{"code": -32601, "message": f"Tool '{{tool_name}}' not found"}}}},
                            status_code=404,
                        )
                    try:
                        result = tool["function"](**arguments)
                        return JSONResponse(content={{"jsonrpc": "2.0", "id": req_id, "result": {{"content": [{{"type": "text", "text": str(result)}}]}}}})
                    except Exception as e:
                        return JSONResponse(
                            content={{"jsonrpc": "2.0", "id": req_id, "error": {{"code": -32000, "message": str(e)}}}},
                            status_code=500,
                        )

                return JSONResponse(
                    content={{"jsonrpc": "2.0", "id": req_id, "error": {{"code": -32601, "message": f"Method '{{method}}' not supported"}}}},
                    status_code=400,
                )


            if __name__ == "__main__":
                import uvicorn
                uvicorn.run(app, host="0.0.0.0", port={port})
        """)

    async def build_image(self, config: PluginContainerConfig) -> str:
        """Build a Docker image for a plugin.

        Args:
            config: Plugin container configuration

        Returns:
            Image tag

        Raises:
            RuntimeError: If Docker manager is not available
        """
        if self._docker is None:
            msg = "Docker manager not available"
            raise RuntimeError(msg)

        image_tag = f"harombe-plugin-{config.plugin_name}:latest"
        dockerfile = self._generate_dockerfile(config)

        logger.info("Building image %s for plugin '%s'", image_tag, config.plugin_name)

        # Build via Docker SDK
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as build_dir:
            build_path = Path(build_dir)

            # Write Dockerfile
            (build_path / "Dockerfile").write_text(dockerfile)

            # Write scaffold
            port = config.port or self._allocate_port()
            config.port = port
            scaffold = self._generate_scaffold(config.plugin_name, port)
            (build_path / "scaffold.py").write_text(scaffold)

            # Copy plugin code
            plugin_dir = build_path / "plugin"
            plugin_dir.mkdir()
            plugin_path = Path(config.plugin_path)
            if plugin_path.is_file():
                import shutil

                shutil.copy2(plugin_path, plugin_dir / plugin_path.name)
            elif plugin_path.is_dir():
                import shutil

                shutil.copytree(plugin_path, plugin_dir, dirs_exist_ok=True)

            # Build image via the container manager's client
            client = self._docker.client
            client.images.build(path=str(build_path), tag=image_tag, rm=True)

        logger.info("Built image %s", image_tag)
        return image_tag

    async def start_plugin(self, config: PluginContainerConfig) -> RunningPluginContainer:
        """Build image and start a plugin container.

        Args:
            config: Plugin container configuration

        Returns:
            RunningPluginContainer with runtime info

        Raises:
            RuntimeError: If Docker manager is not available
        """
        if self._docker is None:
            msg = "Docker manager not available"
            raise RuntimeError(msg)

        if config.port is None:
            config.port = self._allocate_port()

        image_tag = await self.build_image(config)

        from harombe.security.docker_manager import ContainerConfig, ResourceLimits

        container_name = f"harombe-plugin-{config.plugin_name}"
        resource_limits = ResourceLimits.from_mb(
            memory_mb=config.memory_mb,
            cpu_cores=config.cpu_cores,
            pids_limit=config.pids_limit,
        )

        container_config = ContainerConfig(
            name=container_name,
            image=image_tag,
            port=config.port,
            resource_limits=resource_limits,
        )

        container_id = await self._docker.create_container(container_config)
        await self._docker.start_container(container_name)

        # Apply network policy if domains are specified
        if config.network_domains:
            logger.info(
                "Network policy for '%s': allow %s",
                config.plugin_name,
                config.network_domains,
            )

        running = RunningPluginContainer(
            name=config.plugin_name,
            container_id=container_id,
            host=f"localhost:{config.port}",
            port=config.port,
        )
        self._running[config.plugin_name] = running

        logger.info(
            "Started plugin container '%s' on port %d",
            config.plugin_name,
            config.port,
        )
        return running

    async def stop_plugin(self, plugin_name: str) -> None:
        """Stop and remove a plugin container.

        Args:
            plugin_name: Name of the plugin to stop
        """
        if self._docker is None:
            return

        container_name = f"harombe-plugin-{plugin_name}"
        try:
            await self._docker.stop_container(container_name)
            await self._docker.remove_container(container_name, force=True)
        except (ValueError, Exception) as e:
            logger.warning("Error stopping plugin '%s': %s", plugin_name, e)

        self._running.pop(plugin_name, None)
        logger.info("Stopped plugin container '%s'", plugin_name)

    async def health_check(self, plugin_name: str) -> bool:
        """Check if a plugin container is healthy.

        Args:
            plugin_name: Name of the plugin

        Returns:
            True if healthy
        """
        running = self._running.get(plugin_name)
        if running is None:
            return False

        try:
            import httpx

            async with httpx.AsyncClient() as client:
                resp = await client.get(f"http://{running.host}/health", timeout=5.0)
                return resp.status_code == 200
        except Exception:
            return False

    def get_tool_route(self, plugin_name: str) -> str | None:
        """Get the container endpoint for a plugin.

        Args:
            plugin_name: Name of the plugin

        Returns:
            Container endpoint string or None
        """
        running = self._running.get(plugin_name)
        if running is None:
            return None
        return running.host

    def get_all_routes(self) -> dict[str, str]:
        """Get all plugin tool routes for gateway registration.

        Returns:
            Dict mapping plugin name to container endpoint
        """
        return {name: rc.host for name, rc in self._running.items()}

    async def cleanup_all(self) -> None:
        """Stop all running plugin containers."""
        plugin_names = list(self._running.keys())
        for name in plugin_names:
            await self.stop_plugin(name)
        logger.info("Cleaned up all plugin containers")
