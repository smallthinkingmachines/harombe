"""Tests for CLI cluster commands."""

from unittest.mock import AsyncMock, patch

import pytest

from harombe.cli.cluster_cmd import (
    _async_metrics,
    _async_status,
    _async_test,
    cluster_init_command,
)
from harombe.config.schema import (
    ClusterConfig,
    HarombeConfig,
    NodeConfig,
)
from harombe.coordination.cluster import NodeHealth, NodeStatus


def _make_cluster_config() -> ClusterConfig:
    """Create a cluster config with two nodes."""
    return ClusterConfig(
        nodes=[
            NodeConfig(name="node-a", host="192.168.1.10", port=8000, model="qwen2.5:7b", tier=0),
            NodeConfig(name="node-b", host="192.168.1.20", port=8000, model="qwen2.5:14b", tier=1),
        ],
    )


def _make_health(name: str, status: NodeStatus, latency: float = 10.0) -> NodeHealth:
    """Create a NodeHealth instance."""
    from datetime import datetime

    return NodeHealth(
        name=name,
        status=status,
        load=0.3,
        latency_ms=latency,
        last_check=datetime.utcnow(),
    )


def test_cluster_init_command():
    """Test cluster init prints template."""
    # Should not raise
    cluster_init_command()


@pytest.mark.asyncio
async def test_async_status_no_cluster():
    """Test status when no cluster is configured."""
    config = HarombeConfig()  # No cluster configured

    with patch("harombe.cli.cluster_cmd.load_config", return_value=config):
        await _async_status()


@pytest.mark.asyncio
async def test_async_status_with_nodes():
    """Test status with cluster nodes."""
    cluster_config = _make_cluster_config()
    config = HarombeConfig()
    config.cluster = cluster_config

    nodes_dict = {n.name: n for n in cluster_config.nodes}
    health_dict = {
        "node-a": _make_health("node-a", NodeStatus.AVAILABLE),
        "node-b": _make_health("node-b", NodeStatus.UNAVAILABLE, latency=0.0),
    }

    with (
        patch("harombe.cli.cluster_cmd.load_config", return_value=config),
        patch("harombe.cli.cluster_cmd.ClusterManager") as mock_cluster_cls,
    ):
        instance = mock_cluster_cls.return_value
        instance._nodes = nodes_dict
        instance._health = health_dict
        instance.check_all_health = AsyncMock()
        instance.close = AsyncMock()

        await _async_status()

        instance.check_all_health.assert_called_once()
        instance.close.assert_called_once()


@pytest.mark.asyncio
async def test_async_status_degraded_node():
    """Test status with a degraded node."""
    cluster_config = _make_cluster_config()
    config = HarombeConfig()
    config.cluster = cluster_config

    nodes_dict = {n.name: n for n in cluster_config.nodes}
    health_dict = {
        "node-a": _make_health("node-a", NodeStatus.AVAILABLE),
        "node-b": _make_health("node-b", NodeStatus.DEGRADED, latency=150.0),
    }

    with (
        patch("harombe.cli.cluster_cmd.load_config", return_value=config),
        patch("harombe.cli.cluster_cmd.ClusterManager") as mock_cluster_cls,
    ):
        instance = mock_cluster_cls.return_value
        instance._nodes = nodes_dict
        instance._health = health_dict
        instance.check_all_health = AsyncMock()
        instance.close = AsyncMock()

        await _async_status()


@pytest.mark.asyncio
async def test_async_status_with_config_path(tmp_path):
    """Test status with a custom config path."""
    config = HarombeConfig()

    with patch("harombe.cli.cluster_cmd.load_config", return_value=config) as mock_load:
        await _async_status(config_path=str(tmp_path / "cluster.yaml"))

        mock_load.assert_called_once()


@pytest.mark.asyncio
async def test_async_test_no_cluster():
    """Test cluster test when no cluster configured."""
    config = HarombeConfig()

    with patch("harombe.cli.cluster_cmd.load_config", return_value=config):
        await _async_test()


@pytest.mark.asyncio
async def test_async_test_with_nodes():
    """Test cluster test with available nodes."""
    cluster_config = _make_cluster_config()
    config = HarombeConfig()
    config.cluster = cluster_config

    nodes_dict = {n.name: n for n in cluster_config.nodes}

    with (
        patch("harombe.cli.cluster_cmd.load_config", return_value=config),
        patch("harombe.cli.cluster_cmd.ClusterManager") as mock_cluster_cls,
    ):
        instance = mock_cluster_cls.return_value
        instance._nodes = nodes_dict
        instance.check_node_health = AsyncMock(
            side_effect=[
                _make_health("node-a", NodeStatus.AVAILABLE),
                _make_health("node-b", NodeStatus.UNAVAILABLE),
            ]
        )
        instance.close = AsyncMock()

        await _async_test()

        assert instance.check_node_health.call_count == 2
        instance.close.assert_called_once()


@pytest.mark.asyncio
async def test_async_metrics_no_cluster():
    """Test metrics when no cluster configured."""
    config = HarombeConfig()

    with patch("harombe.cli.cluster_cmd.load_config", return_value=config):
        await _async_metrics()


@pytest.mark.asyncio
async def test_async_metrics_all_nodes():
    """Test metrics for all nodes."""
    cluster_config = _make_cluster_config()
    config = HarombeConfig()
    config.cluster = cluster_config

    metrics_data = {
        "nodes": {
            "node-a": {
                "total_requests": 100,
                "success_rate": 0.95,
                "average_latency_ms": 12.5,
                "tokens_per_second": 45.0,
                "last_request": "2024-01-01T12:00:00",
            },
        },
        "cluster_summary": {
            "total_nodes": 1,
            "total_requests": 100,
            "average_success_rate": 0.95,
            "average_latency_ms": 12.5,
            "total_tokens": 4500,
            "tokens_per_second": 45.0,
        },
    }

    with (
        patch("harombe.cli.cluster_cmd.load_config", return_value=config),
        patch("harombe.cli.cluster_cmd.ClusterManager") as mock_cluster_cls,
    ):
        instance = mock_cluster_cls.return_value
        instance.get_metrics.return_value = metrics_data
        instance.close = AsyncMock()

        await _async_metrics()

        instance.close.assert_called_once()


@pytest.mark.asyncio
async def test_async_metrics_no_data():
    """Test metrics when no data available yet."""
    cluster_config = _make_cluster_config()
    config = HarombeConfig()
    config.cluster = cluster_config

    with (
        patch("harombe.cli.cluster_cmd.load_config", return_value=config),
        patch("harombe.cli.cluster_cmd.ClusterManager") as mock_cluster_cls,
    ):
        instance = mock_cluster_cls.return_value
        instance.get_metrics.return_value = {"nodes": {}}
        instance.close = AsyncMock()

        await _async_metrics()


@pytest.mark.asyncio
async def test_async_metrics_specific_node():
    """Test metrics for a specific node."""
    cluster_config = _make_cluster_config()
    config = HarombeConfig()
    config.cluster = cluster_config

    node_metrics = {
        "total_requests": 50,
        "success_rate": 0.98,
        "average_latency_ms": 8.0,
        "tokens_per_second": 60.0,
        "last_request": "2024-01-01T12:30:00",
    }

    with (
        patch("harombe.cli.cluster_cmd.load_config", return_value=config),
        patch("harombe.cli.cluster_cmd.ClusterManager") as mock_cluster_cls,
    ):
        instance = mock_cluster_cls.return_value
        instance.get_metrics.return_value = node_metrics
        instance.close = AsyncMock()

        await _async_metrics(node="node-a")


@pytest.mark.asyncio
async def test_async_metrics_specific_node_no_data():
    """Test metrics for a specific node with no data."""
    cluster_config = _make_cluster_config()
    config = HarombeConfig()
    config.cluster = cluster_config

    with (
        patch("harombe.cli.cluster_cmd.load_config", return_value=config),
        patch("harombe.cli.cluster_cmd.ClusterManager") as mock_cluster_cls,
    ):
        instance = mock_cluster_cls.return_value
        instance.get_metrics.return_value = {}
        instance.close = AsyncMock()

        await _async_metrics(node="node-nonexistent")


@pytest.mark.asyncio
async def test_async_metrics_node_never_requested():
    """Test metrics for a node that has never been requested."""
    cluster_config = _make_cluster_config()
    config = HarombeConfig()
    config.cluster = cluster_config

    node_metrics = {
        "total_requests": 0,
        "success_rate": 0.0,
        "average_latency_ms": 0.0,
        "tokens_per_second": 0.0,
        "last_request": None,
    }

    with (
        patch("harombe.cli.cluster_cmd.load_config", return_value=config),
        patch("harombe.cli.cluster_cmd.ClusterManager") as mock_cluster_cls,
    ):
        instance = mock_cluster_cls.return_value
        instance.get_metrics.return_value = node_metrics
        instance.close = AsyncMock()

        await _async_metrics(node="node-a")
