"""Tests for mDNS service discovery."""

import socket
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from harombe.config.schema import NodeConfig
from harombe.coordination.discovery import HarombeServiceListener, ServiceDiscovery


class TestHarombeServiceListener:
    def test_init(self):
        callback = MagicMock()
        listener = HarombeServiceListener(on_service_discovered=callback)
        assert listener.on_service_discovered is callback
        assert listener.discovered_services == set()

    @pytest.mark.asyncio
    async def test_async_add_service_with_address(self):
        """Test adding a service with valid address info."""
        discovered = []

        def callback(node: NodeConfig):
            discovered.append(node)

        listener = HarombeServiceListener(on_service_discovered=callback)

        mock_info = AsyncMock()
        mock_info.addresses = [socket.inet_aton("192.168.1.50")]
        mock_info.port = 8000
        mock_info.properties = {
            b"name": b"test-node",
            b"model": b"qwen2.5:7b",
            b"tier": b"1",
        }
        mock_info.async_request = AsyncMock()

        with patch("harombe.coordination.discovery.AsyncServiceInfo", return_value=mock_info):
            mock_zc = MagicMock()
            await listener._async_add_service(
                mock_zc, "_harombe._tcp.local.", "test._harombe._tcp.local."
            )

        assert len(discovered) == 1
        node = discovered[0]
        assert node.name == "test-node"
        assert node.host == "192.168.1.50"
        assert node.port == 8000
        assert node.model == "qwen2.5:7b"
        assert node.tier == 1

    @pytest.mark.asyncio
    async def test_async_add_service_no_address(self):
        """Test that services without addresses are ignored."""
        callback = MagicMock()
        listener = HarombeServiceListener(on_service_discovered=callback)

        mock_info = AsyncMock()
        mock_info.addresses = []
        mock_info.async_request = AsyncMock()

        with patch("harombe.coordination.discovery.AsyncServiceInfo", return_value=mock_info):
            mock_zc = MagicMock()
            await listener._async_add_service(
                mock_zc, "_harombe._tcp.local.", "test._harombe._tcp.local."
            )

        callback.assert_not_called()

    @pytest.mark.asyncio
    async def test_async_add_service_duplicate_ignored(self):
        """Test that duplicate services are ignored."""
        discovered = []

        def callback(node: NodeConfig):
            discovered.append(node)

        listener = HarombeServiceListener(on_service_discovered=callback)
        listener.discovered_services.add("test._harombe._tcp.local.")

        mock_zc = MagicMock()
        await listener._async_add_service(
            mock_zc, "_harombe._tcp.local.", "test._harombe._tcp.local."
        )

        assert len(discovered) == 0

    @pytest.mark.asyncio
    async def test_async_add_service_default_values(self):
        """Test defaults when properties are missing."""
        discovered = []

        def callback(node: NodeConfig):
            discovered.append(node)

        listener = HarombeServiceListener(on_service_discovered=callback)

        mock_info = AsyncMock()
        mock_info.addresses = [socket.inet_aton("10.0.0.1")]
        mock_info.port = None  # Should default to 8000
        mock_info.properties = {}
        mock_info.async_request = AsyncMock()

        with patch("harombe.coordination.discovery.AsyncServiceInfo", return_value=mock_info):
            mock_zc = MagicMock()
            await listener._async_add_service(
                mock_zc, "_harombe._tcp.local.", "mynode._harombe._tcp.local."
            )

        assert len(discovered) == 1
        node = discovered[0]
        assert node.port == 8000
        assert node.model == "unknown"
        assert node.tier == 0

    def test_remove_service(self):
        """Test service removal."""
        listener = HarombeServiceListener(on_service_discovered=MagicMock())
        listener.discovered_services.add("test-service")

        listener.remove_service(MagicMock(), "_type", "test-service")

        assert "test-service" not in listener.discovered_services

    def test_update_service(self):
        """Test service update is a no-op."""
        listener = HarombeServiceListener(on_service_discovered=MagicMock())
        # Should not raise
        listener.update_service(MagicMock(), "_type", "test-service")


class TestServiceDiscovery:
    def test_init_defaults(self):
        sd = ServiceDiscovery()
        assert sd.service_type == "_harombe._tcp.local."
        assert sd.azeroconf is None
        assert sd.browser is None
        assert sd.registered_service is None

    def test_init_custom_service_type(self):
        sd = ServiceDiscovery(service_type="_custom._tcp.local.")
        assert sd.service_type == "_custom._tcp.local."

    @pytest.mark.asyncio
    async def test_start_discovery_requires_callback(self):
        """Test that start_discovery raises without callback."""
        sd = ServiceDiscovery(on_service_discovered=None)

        with pytest.raises(ValueError, match="callback required"):
            await sd.start_discovery()

    @pytest.mark.asyncio
    async def test_start_discovery_with_callback(self):
        """Test start_discovery initializes zeroconf and browser."""
        callback = MagicMock()
        sd = ServiceDiscovery(on_service_discovered=callback)

        with patch("harombe.coordination.discovery.AsyncZeroconf") as mock_azc_cls:
            mock_azc = mock_azc_cls.return_value
            mock_azc.zeroconf = MagicMock()

            with patch("harombe.coordination.discovery.ServiceBrowser") as mock_browser_cls:
                await sd.start_discovery()

                assert sd.azeroconf is mock_azc
                mock_browser_cls.assert_called_once()

    @pytest.mark.asyncio
    async def test_announce_service(self):
        """Test announcing a service on the network."""
        sd = ServiceDiscovery()

        with patch("harombe.coordination.discovery.AsyncZeroconf") as mock_azc_cls:
            mock_azc = mock_azc_cls.return_value
            mock_azc.async_register_service = AsyncMock()

            with patch("harombe.coordination.discovery.socket") as mock_socket:
                mock_socket.gethostname.return_value = "test-host"
                mock_socket.gethostbyname.return_value = "192.168.1.1"
                mock_socket.inet_aton.return_value = b"\xc0\xa8\x01\x01"

                await sd.announce_service(
                    name="my-node",
                    port=8000,
                    model="qwen2.5:7b",
                    tier=1,
                )

                mock_azc.async_register_service.assert_called_once()
                assert sd.registered_service is not None

    @pytest.mark.asyncio
    async def test_stop_cleans_up(self):
        """Test that stop cleans up all resources."""
        sd = ServiceDiscovery()
        sd.browser = MagicMock()
        sd.browser.cancel = MagicMock()
        sd.azeroconf = AsyncMock()
        sd.azeroconf.async_unregister_service = AsyncMock()
        sd.azeroconf.async_close = AsyncMock()
        sd.registered_service = MagicMock()

        await sd.stop()

        assert sd.browser is None
        assert sd.registered_service is None
        assert sd.azeroconf is None

    @pytest.mark.asyncio
    async def test_stop_no_browser(self):
        """Test stop when browser is None."""
        sd = ServiceDiscovery()
        await sd.stop()  # Should not raise

    @pytest.mark.asyncio
    async def test_context_manager(self):
        """Test async context manager."""
        sd = ServiceDiscovery()

        async with sd as s:
            assert s is sd

        # stop() should have been called

    @pytest.mark.asyncio
    async def test_announce_creates_azeroconf_if_needed(self):
        """Test that announce creates azeroconf if not already present."""
        sd = ServiceDiscovery()
        assert sd.azeroconf is None

        with patch("harombe.coordination.discovery.AsyncZeroconf") as mock_azc_cls:
            mock_azc = mock_azc_cls.return_value
            mock_azc.async_register_service = AsyncMock()

            with patch("harombe.coordination.discovery.socket") as mock_socket:
                mock_socket.gethostname.return_value = "test-host"
                mock_socket.gethostbyname.return_value = "192.168.1.1"
                mock_socket.inet_aton.return_value = b"\xc0\xa8\x01\x01"

                await sd.announce_service("node", 8000, "model", 0)

                assert sd.azeroconf is not None
