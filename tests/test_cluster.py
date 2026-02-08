"""Tests for cluster management."""

import pytest

from harombe.config.schema import ClusterConfig, NodeConfig, RoutingConfig
from harombe.coordination.cluster import ClusterManager, NodeStatus


@pytest.fixture
def sample_nodes():
    """Sample node configurations for testing."""
    return [
        NodeConfig(
            name="node0",
            host="localhost",
            port=8000,
            model="qwen2.5:3b",
            tier=0,
        ),
        NodeConfig(
            name="node1",
            host="192.168.1.100",
            port=8001,
            model="qwen2.5:14b",
            tier=1,
        ),
        NodeConfig(
            name="node2",
            host="192.168.1.101",
            port=8002,
            model="qwen2.5:72b",
            tier=2,
        ),
    ]


@pytest.fixture
def cluster_config(sample_nodes):
    """Sample cluster configuration."""
    return ClusterConfig(nodes=sample_nodes)


def test_cluster_manager_initialization(cluster_config):
    """Test cluster manager initializes with config."""
    manager = ClusterManager(cluster_config)

    assert len(manager._nodes) == 3
    assert "node0" in manager._nodes
    assert "node1" in manager._nodes
    assert "node2" in manager._nodes

    # All nodes should have health records
    assert len(manager._health) == 3
    for health in manager._health.values():
        assert health.status == NodeStatus.UNAVAILABLE  # Not checked yet


def test_get_nodes_by_tier(cluster_config):
    """Test filtering nodes by tier."""
    manager = ClusterManager(cluster_config)

    tier0 = manager.get_nodes_by_tier(0, available_only=False)
    tier1 = manager.get_nodes_by_tier(1, available_only=False)
    tier2 = manager.get_nodes_by_tier(2, available_only=False)

    assert len(tier0) == 1
    assert tier0[0].name == "node0"

    assert len(tier1) == 1
    assert tier1[0].name == "node1"

    assert len(tier2) == 1
    assert tier2[0].name == "node2"


def test_get_nodes_by_tier_available_only(cluster_config):
    """Test filtering nodes by tier with availability check."""
    manager = ClusterManager(cluster_config)

    # No nodes are available yet (no health checks performed)
    tier0 = manager.get_nodes_by_tier(0, available_only=True)
    assert len(tier0) == 0

    # Mark node0 as available
    manager._health["node0"].status = NodeStatus.AVAILABLE

    tier0 = manager.get_nodes_by_tier(0, available_only=True)
    assert len(tier0) == 1
    assert tier0[0].name == "node0"


@pytest.mark.asyncio
async def test_register_unregister_node(cluster_config):
    """Test dynamic node registration and removal."""
    manager = ClusterManager(cluster_config)

    initial_count = len(manager._nodes)

    # Add a new node
    new_node = NodeConfig(
        name="node3",
        host="192.168.1.102",
        port=8003,
        model="qwen2.5:32b",
        tier=2,
    )
    manager.register_node(new_node)

    assert len(manager._nodes) == initial_count + 1
    assert "node3" in manager._nodes

    # Remove the node
    await manager.unregister_node("node3")

    assert len(manager._nodes) == initial_count
    assert "node3" not in manager._nodes


def test_select_node_preferred_tier(cluster_config):
    """Test node selection prefers specified tier."""
    manager = ClusterManager(cluster_config)

    # Mark all nodes as available
    for health in manager._health.values():
        health.status = NodeStatus.AVAILABLE

    # Select from each tier
    node0 = manager.select_node(tier=0, fallback=False)
    node1 = manager.select_node(tier=1, fallback=False)
    node2 = manager.select_node(tier=2, fallback=False)

    assert node0.tier == 0
    assert node1.tier == 1
    assert node2.tier == 2


def test_select_node_fallback_graceful(cluster_config):
    """Test graceful fallback when preferred tier unavailable."""
    # Enable graceful fallback
    cluster_config.routing.fallback_strategy = "graceful"
    manager = ClusterManager(cluster_config)

    # Only tier 1 is available
    manager._health["node1"].status = NodeStatus.AVAILABLE

    # Request tier 2 (unavailable), should fallback to tier 1
    node = manager.select_node(tier=2, fallback=True)
    assert node is not None
    assert node.tier == 1

    # Request tier 0 (unavailable), should fallback to tier 1
    node = manager.select_node(tier=0, fallback=True)
    assert node is not None
    assert node.tier == 1


def test_select_node_fallback_strict(cluster_config):
    """Test strict mode returns None when preferred tier unavailable."""
    # Enable strict mode
    cluster_config.routing.fallback_strategy = "strict"
    manager = ClusterManager(cluster_config)

    # Only tier 1 is available
    manager._health["node1"].status = NodeStatus.AVAILABLE

    # Request tier 2 (unavailable) with strict mode
    node = manager.select_node(tier=2, fallback=False)
    assert node is None


def test_select_node_load_balancing():
    """Test load balancing selects least loaded node."""
    # Create two nodes in same tier
    nodes = [
        NodeConfig(
            name="node1a",
            host="192.168.1.100",
            port=8001,
            model="qwen2.5:14b",
            tier=1,
        ),
        NodeConfig(
            name="node1b",
            host="192.168.1.101",
            port=8002,
            model="qwen2.5:14b",
            tier=1,
        ),
    ]

    config = ClusterConfig(
        nodes=nodes,
        routing=RoutingConfig(load_balance=True),
    )
    manager = ClusterManager(config)

    # Mark both as available
    manager._health["node1a"].status = NodeStatus.AVAILABLE
    manager._health["node1a"].load = 0.8

    manager._health["node1b"].status = NodeStatus.AVAILABLE
    manager._health["node1b"].load = 0.3

    # Should select less loaded node
    node = manager.select_node(tier=1)
    assert node.name == "node1b"


def test_select_node_prefer_local():
    """Test prefer_local selects lowest latency node."""
    # Create two nodes in same tier
    nodes = [
        NodeConfig(
            name="node1a",
            host="192.168.1.100",
            port=8001,
            model="qwen2.5:14b",
            tier=1,
        ),
        NodeConfig(
            name="node1b",
            host="192.168.1.101",
            port=8002,
            model="qwen2.5:14b",
            tier=1,
        ),
    ]

    config = ClusterConfig(
        nodes=nodes,
        routing=RoutingConfig(prefer_local=True, load_balance=False),
    )
    manager = ClusterManager(config)

    # Mark both as available
    manager._health["node1a"].status = NodeStatus.AVAILABLE
    manager._health["node1a"].latency_ms = 50.0

    manager._health["node1b"].status = NodeStatus.AVAILABLE
    manager._health["node1b"].latency_ms = 10.0

    # Should select lower latency node
    node = manager.select_node(tier=1)
    assert node.name == "node1b"


def test_disabled_nodes_not_registered():
    """Test that disabled nodes are not registered."""
    nodes = [
        NodeConfig(
            name="enabled",
            host="localhost",
            port=8000,
            model="qwen2.5:3b",
            tier=0,
            enabled=True,
        ),
        NodeConfig(
            name="disabled",
            host="localhost",
            port=8001,
            model="qwen2.5:3b",
            tier=0,
            enabled=False,
        ),
    ]

    config = ClusterConfig(nodes=nodes)
    manager = ClusterManager(config)

    assert len(manager._nodes) == 1
    assert "enabled" in manager._nodes
    assert "disabled" not in manager._nodes


@pytest.mark.asyncio
async def test_cluster_manager_close(cluster_config):
    """Test cluster manager cleanup."""
    manager = ClusterManager(cluster_config)

    # Should close without errors
    await manager.close()
