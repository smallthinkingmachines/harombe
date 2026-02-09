"""Docker Container Manager for MCP capability containers.

Manages the lifecycle of isolated capability containers, including:
- Container creation and deletion
- Start/stop/restart operations
- Resource limits (CPU, memory, network)
- Health monitoring
- Volume mounting
"""

import logging
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

logger = logging.getLogger(__name__)


class ContainerStatus(StrEnum):
    """Container lifecycle states."""

    CREATED = "created"
    RUNNING = "running"
    PAUSED = "paused"
    RESTARTING = "restarting"
    EXITED = "exited"
    DEAD = "dead"
    UNKNOWN = "unknown"


@dataclass
class ResourceLimits:
    """Resource constraints for a container."""

    cpu_quota: int | None = None  # CPU quota in microseconds per period (100ms)
    cpu_period: int = 100000  # CPU period in microseconds (default 100ms)
    memory_limit: int | None = None  # Memory limit in bytes
    memory_reservation: int | None = None  # Soft memory limit in bytes
    pids_limit: int = 100  # Max number of processes
    network_bandwidth: int | None = None  # Network bandwidth limit (not directly supported)

    def to_docker_params(self) -> dict[str, Any]:
        """Convert to Docker SDK parameters."""
        params = {}

        if self.cpu_quota is not None:
            params["cpu_quota"] = self.cpu_quota
            params["cpu_period"] = self.cpu_period

        if self.memory_limit is not None:
            params["mem_limit"] = self.memory_limit

        if self.memory_reservation is not None:
            params["mem_reservation"] = self.memory_reservation

        params["pids_limit"] = self.pids_limit

        return params

    @classmethod
    def from_mb(
        cls,
        memory_mb: int | None = None,
        cpu_cores: float | None = None,
        pids_limit: int = 100,
    ) -> "ResourceLimits":
        """Create resource limits from human-readable values.

        Args:
            memory_mb: Memory limit in megabytes
            cpu_cores: CPU cores (e.g., 0.5 for half a core)
            pids_limit: Maximum number of processes

        Returns:
            ResourceLimits instance
        """
        memory_limit = memory_mb * 1024 * 1024 if memory_mb else None
        cpu_quota = int(cpu_cores * 100000) if cpu_cores else None

        return cls(
            cpu_quota=cpu_quota,
            memory_limit=memory_limit,
            pids_limit=pids_limit,
        )


@dataclass
class ContainerConfig:
    """Configuration for a capability container."""

    name: str  # Container name (e.g., "browser-container")
    image: str  # Docker image (e.g., "harombe/browser:latest")
    port: int  # Internal port (e.g., 3000)
    host_port: int | None = None  # Host port mapping (None = use internal port)
    environment: dict[str, str] | None = None  # Environment variables
    volumes: dict[str, dict[str, str]] | None = None  # Volume mounts
    network: str = "harombe-network"  # Docker network
    resource_limits: ResourceLimits | None = None  # Resource constraints
    auto_remove: bool = False  # Remove container when stopped
    restart_policy: dict[str, Any] | None = None  # Restart policy


class DockerManager:
    """Manages Docker containers for MCP capability isolation."""

    def __init__(self) -> None:
        """Initialize Docker manager."""
        self._docker: Any = None  # docker.DockerClient
        self._containers: dict[str, Any] = {}  # name -> container object

    def _get_client(self) -> Any:
        """Get or create Docker client.

        Returns:
            Docker client instance

        Raises:
            ImportError: If docker package not installed
            Exception: If Docker daemon not available
        """
        if self._docker is None:
            try:
                import docker

                self._docker = docker.from_env()
                logger.info("Connected to Docker daemon")
            except ImportError as e:
                msg = "Docker SDK not installed. " "Install with: pip install 'harombe[docker]'"
                raise ImportError(msg) from e
            except Exception as e:
                logger.error(f"Failed to connect to Docker daemon: {e}")
                raise

        return self._docker

    async def create_network(self, network_name: str = "harombe-network") -> None:
        """Create Docker network for capability containers.

        Args:
            network_name: Name of the Docker network

        Raises:
            Exception: If network creation fails
        """
        client = self._get_client()

        try:
            # Check if network already exists
            networks = client.networks.list(names=[network_name])
            if networks:
                logger.info(f"Docker network '{network_name}' already exists")
                return

            # Create new network
            client.networks.create(
                name=network_name,
                driver="bridge",
                check_duplicate=True,
            )
            logger.info(f"Created Docker network '{network_name}'")
        except Exception as e:
            logger.error(f"Failed to create network '{network_name}': {e}")
            raise

    async def create_container(self, config: ContainerConfig) -> str:
        """Create a new container.

        Args:
            config: Container configuration

        Returns:
            Container ID

        Raises:
            Exception: If container creation fails
        """
        client = self._get_client()

        try:
            # Check if container already exists
            if config.name in self._containers:
                logger.warning(f"Container '{config.name}' already exists")
                return self._containers[config.name].id

            # Prepare port mapping
            ports = {}
            if config.host_port:
                ports[f"{config.port}/tcp"] = config.host_port
            else:
                ports[f"{config.port}/tcp"] = config.port

            # Prepare host config (resource limits)
            host_config = {}
            if config.resource_limits:
                host_config.update(config.resource_limits.to_docker_params())

            # Prepare restart policy
            restart_policy = config.restart_policy or {"Name": "unless-stopped"}

            # Create container
            container = client.containers.create(
                image=config.image,
                name=config.name,
                ports=ports,
                environment=config.environment or {},
                volumes=config.volumes or {},
                network=config.network,
                detach=True,
                auto_remove=config.auto_remove,
                restart_policy=restart_policy,
                **host_config,
            )

            self._containers[config.name] = container
            logger.info(f"Created container '{config.name}' (id={container.short_id})")

            return container.id

        except Exception as e:
            logger.error(f"Failed to create container '{config.name}': {e}")
            raise

    async def start_container(self, name: str) -> None:
        """Start a container.

        Args:
            name: Container name

        Raises:
            ValueError: If container not found
            Exception: If start fails
        """
        if name not in self._containers:
            msg = f"Container '{name}' not found"
            raise ValueError(msg)

        try:
            container = self._containers[name]
            container.start()
            logger.info(f"Started container '{name}'")
        except Exception as e:
            logger.error(f"Failed to start container '{name}': {e}")
            raise

    async def stop_container(self, name: str, timeout: int = 10) -> None:
        """Stop a container.

        Args:
            name: Container name
            timeout: Seconds to wait before killing

        Raises:
            ValueError: If container not found
            Exception: If stop fails
        """
        if name not in self._containers:
            msg = f"Container '{name}' not found"
            raise ValueError(msg)

        try:
            container = self._containers[name]
            container.stop(timeout=timeout)
            logger.info(f"Stopped container '{name}'")
        except Exception as e:
            logger.error(f"Failed to stop container '{name}': {e}")
            raise

    async def restart_container(self, name: str, timeout: int = 10) -> None:
        """Restart a container.

        Args:
            name: Container name
            timeout: Seconds to wait before killing

        Raises:
            ValueError: If container not found
            Exception: If restart fails
        """
        if name not in self._containers:
            msg = f"Container '{name}' not found"
            raise ValueError(msg)

        try:
            container = self._containers[name]
            container.restart(timeout=timeout)
            logger.info(f"Restarted container '{name}'")
        except Exception as e:
            logger.error(f"Failed to restart container '{name}': {e}")
            raise

    async def remove_container(self, name: str, force: bool = False) -> None:
        """Remove a container.

        Args:
            name: Container name
            force: Force removal even if running

        Raises:
            ValueError: If container not found
            Exception: If removal fails
        """
        if name not in self._containers:
            msg = f"Container '{name}' not found"
            raise ValueError(msg)

        try:
            container = self._containers[name]
            container.remove(force=force)
            del self._containers[name]
            logger.info(f"Removed container '{name}'")
        except Exception as e:
            logger.error(f"Failed to remove container '{name}': {e}")
            raise

    async def get_status(self, name: str) -> ContainerStatus:
        """Get container status.

        Args:
            name: Container name

        Returns:
            Container status

        Raises:
            ValueError: If container not found
        """
        if name not in self._containers:
            msg = f"Container '{name}' not found"
            raise ValueError(msg)

        try:
            container = self._containers[name]
            container.reload()  # Refresh status
            status = container.status.lower()

            # Map Docker status to our enum
            if status in {"created", "running", "paused", "restarting", "exited", "dead"}:
                return ContainerStatus(status)

            return ContainerStatus.UNKNOWN

        except Exception as e:
            logger.error(f"Failed to get status for '{name}': {e}")
            return ContainerStatus.UNKNOWN

    async def get_logs(self, name: str, tail: int = 100) -> str:
        """Get container logs.

        Args:
            name: Container name
            tail: Number of lines to return

        Returns:
            Container logs

        Raises:
            ValueError: If container not found
        """
        if name not in self._containers:
            msg = f"Container '{name}' not found"
            raise ValueError(msg)

        try:
            container = self._containers[name]
            logs = container.logs(tail=tail).decode("utf-8")
            return logs
        except Exception as e:
            logger.error(f"Failed to get logs for '{name}': {e}")
            return f"Error retrieving logs: {e}"

    async def get_stats(self, name: str) -> dict[str, Any]:
        """Get container resource usage statistics.

        Args:
            name: Container name

        Returns:
            Stats dict with CPU, memory, network usage

        Raises:
            ValueError: If container not found
        """
        if name not in self._containers:
            msg = f"Container '{name}' not found"
            raise ValueError(msg)

        try:
            container = self._containers[name]
            stats = container.stats(stream=False)
            return stats
        except Exception as e:
            logger.error(f"Failed to get stats for '{name}': {e}")
            return {}

    async def list_containers(self) -> list[dict[str, Any]]:
        """List all managed containers.

        Returns:
            List of container info dicts
        """
        containers = []

        for name, container in self._containers.items():
            try:
                container.reload()
                containers.append(
                    {
                        "name": name,
                        "id": container.short_id,
                        "status": container.status,
                        "image": container.image.tags[0] if container.image.tags else "unknown",
                    }
                )
            except Exception as e:
                logger.warning(f"Failed to get info for '{name}': {e}")

        return containers

    async def cleanup_all(self, force: bool = False) -> None:
        """Stop and remove all managed containers.

        Args:
            force: Force removal even if running
        """
        container_names = list(self._containers.keys())

        for name in container_names:
            try:
                await self.remove_container(name, force=force)
            except Exception as e:
                logger.error(f"Failed to cleanup container '{name}': {e}")

        logger.info("Cleaned up all containers")

    def close(self) -> None:
        """Close Docker client connection."""
        if self._docker:
            self._docker.close()
            logger.info("Closed Docker client")
