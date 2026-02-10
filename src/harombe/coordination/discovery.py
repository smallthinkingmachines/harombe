"""mDNS service discovery for automatic node registration."""

import asyncio
import socket
from collections.abc import Callable
from typing import Any

from zeroconf import ServiceBrowser, ServiceInfo, Zeroconf
from zeroconf.asyncio import AsyncServiceInfo, AsyncZeroconf

from harombe.config.schema import NodeConfig


class HarombeServiceListener:
    """Listener for harombe service announcements via mDNS."""

    def __init__(self, on_service_discovered: Callable[[NodeConfig], None]):
        """
        Initialize listener.

        Args:
            on_service_discovered: Callback when a new harombe service is found
        """
        self.on_service_discovered = on_service_discovered
        self.discovered_services: set[str] = set()
        self._tasks: set[Any] = set()

    def add_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        """Called when a service is discovered."""
        task = asyncio.create_task(self._async_add_service(zc, type_, name))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _async_add_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        """Async handler for service discovery."""
        if name in self.discovered_services:
            return

        info = AsyncServiceInfo(type_, name)
        await info.async_request(zc, 3000)

        if info.addresses:
            # Get first IPv4 address
            address = socket.inet_ntoa(info.addresses[0])
            port = info.port or 8000

            # Parse properties for node metadata
            properties = {}
            if info.properties:
                properties = {
                    k.decode("utf-8"): v.decode("utf-8") if v is not None else ""
                    for k, v in info.properties.items()
                }

            node_name = properties.get("name", name.split(".")[0])
            model = properties.get("model", "unknown")
            tier = int(properties.get("tier", "0"))

            node = NodeConfig(
                name=node_name,
                host=address,
                port=port,
                model=model,
                tier=tier,
            )

            self.discovered_services.add(name)
            self.on_service_discovered(node)

    def remove_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        """Called when a service goes away."""
        self.discovered_services.discard(name)

    def update_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        """Called when service information is updated."""
        pass


class ServiceDiscovery:
    """Manages mDNS service discovery and announcement."""

    def __init__(
        self,
        service_type: str = "_harombe._tcp.local.",
        on_service_discovered: Callable[[NodeConfig], None] | None = None,
    ):
        """
        Initialize service discovery.

        Args:
            service_type: mDNS service type
            on_service_discovered: Callback for discovered services
        """
        self.service_type = service_type
        self.on_service_discovered = on_service_discovered
        self.azeroconf: AsyncZeroconf | None = None
        self.browser: ServiceBrowser | None = None
        self.registered_service: ServiceInfo | None = None

    async def start_discovery(self) -> None:
        """Start discovering harombe services on the network."""
        if not self.on_service_discovered:
            raise ValueError("on_service_discovered callback required for discovery")

        self.azeroconf = AsyncZeroconf()
        listener = HarombeServiceListener(self.on_service_discovered)

        self.browser = ServiceBrowser(
            self.azeroconf.zeroconf,
            self.service_type,
            listener,  # type: ignore[arg-type]
        )

    async def announce_service(
        self,
        name: str,
        port: int,
        model: str,
        tier: int,
    ) -> None:
        """
        Announce this harombe instance as a service.

        Args:
            name: Node name
            port: Service port
            model: Model running on this node
            tier: Node tier (0-2)
        """
        if not self.azeroconf:
            self.azeroconf = AsyncZeroconf()

        # Get local IP address
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)

        # Create service info
        service_name = f"{name}.{self.service_type}"
        info = ServiceInfo(
            self.service_type,
            service_name,
            addresses=[socket.inet_aton(local_ip)],
            port=port,
            properties={
                b"name": name.encode("utf-8"),
                b"model": model.encode("utf-8"),
                b"tier": str(tier).encode("utf-8"),
            },
            server=f"{hostname}.local.",
        )

        await self.azeroconf.async_register_service(info)
        self.registered_service = info

    async def stop(self) -> None:
        """Stop discovery and unregister service."""
        if self.browser:
            self.browser.cancel()
            self.browser = None

        if self.registered_service and self.azeroconf:
            await self.azeroconf.async_unregister_service(self.registered_service)
            self.registered_service = None

        if self.azeroconf:
            await self.azeroconf.async_close()
            self.azeroconf = None

    async def __aenter__(self) -> "ServiceDiscovery":
        return self

    async def __aexit__(
        self, exc_type: type[BaseException] | None, exc_val: BaseException | None, exc_tb: Any
    ) -> None:
        await self.stop()
