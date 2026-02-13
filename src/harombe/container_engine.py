"""Container engine detection and client factory.

Supports both Docker and Podman via the docker Python SDK.
Podman provides a Docker-compatible API socket, so we use the same
``docker`` package for both engines — just pointed at the right socket.

Detection order:
1. Explicit ``engine`` parameter or config override (harombe.yaml security.container_engine)
2. CONTAINER_HOST / DOCKER_HOST environment variable
3. Docker default socket (/var/run/docker.sock)
4. Podman user socket (~/.local/share/containers/podman/machine/*/podman.sock,
   or /run/user/<uid>/podman/podman.sock, or /run/podman/podman.sock)
"""

import logging
import os
import platform
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class EngineInfo:
    """Information about the detected container engine."""

    name: str  # "docker" or "podman"
    supports_gvisor: bool
    network_backend: str  # "bridge" (Docker) or "netavark" (Podman)


def _find_podman_socket() -> str | None:
    """Find the Podman API socket path.

    Returns:
        Socket URI (unix://<path>) or None if not found.
    """
    candidates: list[Path] = []

    system = platform.system()

    if system == "Darwin":
        # macOS: Podman machine socket
        home = Path.home()
        podman_machine_dir = home / ".local/share/containers/podman/machine"
        if podman_machine_dir.exists():
            for machine_dir in podman_machine_dir.iterdir():
                sock = machine_dir / "podman.sock"
                if sock.exists():
                    candidates.append(sock)
        # Also check the standard macOS location
        run_dir = home / ".local/share/containers/podman/machine/podman.sock"
        candidates.append(run_dir)
        # Podman 5+ uses this path on macOS
        candidates.append(home / ".local/share/containers/podman/machine/qemu/podman.sock")

    # Linux: rootless user socket
    uid = os.getuid() if hasattr(os, "getuid") else None
    if uid is not None:
        candidates.append(Path(f"/run/user/{uid}/podman/podman.sock"))

    # Linux: rootful socket
    candidates.append(Path("/run/podman/podman.sock"))

    for sock in candidates:
        if sock.exists():
            logger.debug("Found Podman socket: %s", sock)
            return f"unix://{sock}"

    return None


def _detect_engine(client: Any) -> EngineInfo:
    """Detect whether a docker client is connected to Docker or Podman.

    Args:
        client: A docker.DockerClient instance.

    Returns:
        EngineInfo describing the engine.
    """
    try:
        version_info = client.version()
    except Exception:
        # If we can't get version info, assume Docker
        return EngineInfo(name="docker", supports_gvisor=True, network_backend="bridge")

    # Podman reports components with "Podman" in the name
    components = version_info.get("Components", [])
    for component in components:
        if "podman" in component.get("Name", "").lower():
            return EngineInfo(
                name="podman",
                supports_gvisor=False,
                network_backend="netavark",
            )

    # Also check the "Platform" or "Server" fields
    platform_name = version_info.get("Platform", {}).get("Name", "")
    if "podman" in platform_name.lower():
        return EngineInfo(
            name="podman",
            supports_gvisor=False,
            network_backend="netavark",
        )

    return EngineInfo(name="docker", supports_gvisor=True, network_backend="bridge")


def get_container_client(
    engine: str | None = None,
) -> tuple[Any, EngineInfo]:
    """Get a container client and engine info.

    Args:
        engine: Explicit engine choice: "docker", "podman", or "auto"/None
                for auto-detection.

    Returns:
        Tuple of (DockerClient, EngineInfo).

    Raises:
        ImportError: If the ``docker`` package is not installed.
        ConnectionError: If no container engine is reachable.
    """
    try:
        import docker
    except ImportError as e:
        msg = (
            "Docker SDK not installed. "
            "Install with: pip install 'harombe[docker]'  (works with both Docker and Podman)"
        )
        raise ImportError(msg) from e

    # Normalize engine param
    if engine in (None, "auto"):
        engine = None  # auto-detect

    # 1. Explicit engine choice
    if engine == "podman":
        return _connect_podman(docker)
    if engine == "docker":
        return _connect_docker(docker)

    # 2. Check environment variables (CONTAINER_HOST takes precedence)
    container_host = os.environ.get("CONTAINER_HOST") or os.environ.get("DOCKER_HOST")
    if container_host:
        client = docker.DockerClient(base_url=container_host)  # type: ignore[attr-defined]
        info = _detect_engine(client)
        logger.info(
            "Connected to %s via environment variable (%s)",
            info.name,
            container_host,
        )
        return client, info

    # 3. Try Docker default
    try:
        client = docker.from_env()  # type: ignore[attr-defined]
        client.ping()
        info = _detect_engine(client)
        logger.info("Connected to %s (default socket)", info.name)
        return client, info
    except Exception:
        logger.debug("Docker default socket not available, trying Podman")

    # 4. Try Podman socket
    return _connect_podman(docker)


def _connect_docker(docker_module: Any) -> tuple[Any, EngineInfo]:
    """Connect to Docker using the default method.

    Raises:
        ConnectionError: If Docker is not reachable.
    """
    try:
        client = docker_module.from_env()
        client.ping()
    except Exception as e:
        msg = f"Failed to connect to Docker daemon: {e}"
        raise ConnectionError(msg) from e

    info = _detect_engine(client)
    logger.info("Connected to Docker daemon")
    return client, info


def _connect_podman(docker_module: Any) -> tuple[Any, EngineInfo]:
    """Connect to Podman via its API socket.

    Raises:
        ConnectionError: If Podman socket is not found or not reachable.
    """
    socket_uri = _find_podman_socket()
    if socket_uri is None:
        msg = (
            "No container engine found. Install Docker or Podman, "
            "or set CONTAINER_HOST / DOCKER_HOST environment variable."
        )
        raise ConnectionError(msg)

    try:
        client = docker_module.DockerClient(base_url=socket_uri)
        client.ping()
    except Exception as e:
        msg = f"Failed to connect to Podman at {socket_uri}: {e}"
        raise ConnectionError(msg) from e

    info = EngineInfo(name="podman", supports_gvisor=False, network_backend="netavark")
    logger.info("Connected to Podman at %s", socket_uri)
    return client, info
