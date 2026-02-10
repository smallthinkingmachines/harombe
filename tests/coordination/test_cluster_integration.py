"""Integration tests for multi-node cluster orchestration.

Uses respx to mock HTTP endpoints simulating 2-3 nodes with different tiers.
"""

import pytest
import respx
from httpx import Response

from harombe.config.schema import (
    ClusterConfig,
    DiscoveryConfig,
    NodeConfig,
    RoutingConfig,
)
from harombe.coordination.cluster import ClusterManager, NodeStatus


def _make_cluster_config(nodes: list[NodeConfig] | None = None) -> ClusterConfig:
    """Create a test cluster config."""
    if nodes is None:
        nodes = [
            NodeConfig(name="fast", host="fast.local", port=8000, model="qwen:3b", tier=0),
            NodeConfig(name="medium", host="medium.local", port=8000, model="qwen:14b", tier=1),
            NodeConfig(name="powerful", host="powerful.local", port=8000, model="qwen:72b", tier=2),
        ]
    return ClusterConfig(
        discovery=DiscoveryConfig(method="explicit"),
        routing=RoutingConfig(
            prefer_local=True,
            fallback_strategy="graceful",
            load_balance=True,
        ),
        nodes=nodes,
    )


class TestClusterManagerRegistration:
    def test_registers_all_enabled_nodes(self):
        config = _make_cluster_config()
        manager = ClusterManager(config)
        nodes = manager.list_nodes()
        assert len(nodes) == 3

    def test_skips_disabled_nodes(self):
        nodes = [
            NodeConfig(name="active", host="a.local", port=8000, model="m", tier=0),
            NodeConfig(
                name="inactive", host="b.local", port=8000, model="m", tier=1, enabled=False
            ),
        ]
        config = _make_cluster_config(nodes)
        manager = ClusterManager(config)
        assert len(manager.list_nodes()) == 1
        assert manager.list_nodes()[0]["name"] == "active"

    def test_get_node_by_name(self):
        config = _make_cluster_config()
        manager = ClusterManager(config)
        node = manager.get_node_by_name("medium")
        assert node is not None
        assert node.tier == 1

    def test_get_nonexistent_node(self):
        config = _make_cluster_config()
        manager = ClusterManager(config)
        assert manager.get_node_by_name("nonexistent") is None


class TestClusterManagerHealthCheck:
    @pytest.mark.asyncio
    @respx.mock
    async def test_health_check_marks_available(self):
        respx.get("http://fast.local:8000/health").mock(
            return_value=Response(200, json={"status": "ok"})
        )

        config = _make_cluster_config(
            [NodeConfig(name="fast", host="fast.local", port=8000, model="m", tier=0)]
        )
        manager = ClusterManager(config)
        health = await manager.check_node_health("fast", max_retries=1)
        assert health.status == NodeStatus.AVAILABLE
        assert health.latency_ms > 0

    @pytest.mark.asyncio
    @respx.mock
    async def test_health_check_marks_unavailable(self):
        respx.get("http://fast.local:8000/health").mock(side_effect=ConnectionError)

        config = _make_cluster_config(
            [NodeConfig(name="fast", host="fast.local", port=8000, model="m", tier=0)]
        )
        manager = ClusterManager(config)
        health = await manager.check_node_health("fast", max_retries=1)
        assert health.status == NodeStatus.UNAVAILABLE

    @pytest.mark.asyncio
    @respx.mock
    async def test_check_all_health(self):
        respx.get("http://fast.local:8000/health").mock(
            return_value=Response(200, json={"status": "ok"})
        )
        respx.get("http://medium.local:8000/health").mock(
            return_value=Response(200, json={"status": "ok"})
        )
        respx.get("http://powerful.local:8000/health").mock(side_effect=ConnectionError)

        config = _make_cluster_config()
        manager = ClusterManager(config)
        results = await manager.check_all_health()

        assert results["fast"].status == NodeStatus.AVAILABLE
        assert results["medium"].status == NodeStatus.AVAILABLE
        assert results["powerful"].status == NodeStatus.UNAVAILABLE


class TestClusterManagerNodeSelection:
    @pytest.mark.asyncio
    @respx.mock
    async def test_select_from_correct_tier(self):
        for host in ["fast.local", "medium.local", "powerful.local"]:
            respx.get(f"http://{host}:8000/health").mock(
                return_value=Response(200, json={"status": "ok"})
            )

        config = _make_cluster_config()
        manager = ClusterManager(config)
        await manager.check_all_health()

        node = manager.select_node(tier=2)
        assert node is not None
        assert node.name == "powerful"

    @pytest.mark.asyncio
    @respx.mock
    async def test_fallback_when_tier_unavailable(self):
        respx.get("http://fast.local:8000/health").mock(
            return_value=Response(200, json={"status": "ok"})
        )
        respx.get("http://medium.local:8000/health").mock(side_effect=ConnectionError)
        respx.get("http://powerful.local:8000/health").mock(side_effect=ConnectionError)

        config = _make_cluster_config()
        manager = ClusterManager(config)
        await manager.check_all_health()

        # Tier 2 unavailable, should fallback
        node = manager.select_node(tier=2, fallback=True)
        assert node is not None
        assert node.name == "fast"

    @pytest.mark.asyncio
    @respx.mock
    async def test_no_fallback_strict(self):
        respx.get("http://fast.local:8000/health").mock(
            return_value=Response(200, json={"status": "ok"})
        )
        respx.get("http://medium.local:8000/health").mock(side_effect=ConnectionError)
        respx.get("http://powerful.local:8000/health").mock(side_effect=ConnectionError)

        config = _make_cluster_config()
        config.routing.fallback_strategy = "strict"
        manager = ClusterManager(config)
        await manager.check_all_health()

        # Tier 2 unavailable, strict = no fallback
        node = manager.select_node(tier=2, fallback=True)
        assert node is None

    @pytest.mark.asyncio
    @respx.mock
    async def test_smart_routing_simple_query(self):
        for host in ["fast.local", "medium.local", "powerful.local"]:
            respx.get(f"http://{host}:8000/health").mock(
                return_value=Response(200, json={"status": "ok"})
            )

        config = _make_cluster_config()
        manager = ClusterManager(config)
        await manager.check_all_health()

        node, decision = manager.select_node_smart("What time is it?")
        assert node is not None
        assert decision.recommended_tier == 0
        assert node.tier == 0

    @pytest.mark.asyncio
    @respx.mock
    async def test_smart_routing_non_simple_query(self):
        for host in ["fast.local", "medium.local", "powerful.local"]:
            respx.get(f"http://{host}:8000/health").mock(
                return_value=Response(200, json={"status": "ok"})
            )

        config = _make_cluster_config()
        manager = ClusterManager(config)
        await manager.check_all_health()

        node, decision = manager.select_node_smart(
            "Analyze this code, refactor it to use async/await, "
            "implement comprehensive error handling, and write unit tests"
        )
        assert node is not None
        assert decision.recommended_tier >= 1


class TestClusterManagerDynamicNodes:
    @pytest.mark.asyncio
    @respx.mock
    async def test_add_node(self):
        config = _make_cluster_config(nodes=[])
        manager = ClusterManager(config)
        assert len(manager.list_nodes()) == 0

        new_node = NodeConfig(name="new", host="new.local", port=8000, model="m", tier=0)
        respx.get("http://new.local:8000/health").mock(
            return_value=Response(200, json={"status": "ok"})
        )
        await manager.add_node(new_node)
        assert len(manager.list_nodes()) == 1

    @pytest.mark.asyncio
    async def test_add_duplicate_node_raises(self):
        config = _make_cluster_config()
        manager = ClusterManager(config)
        with pytest.raises(ValueError, match="already exists"):
            await manager.add_node(NodeConfig(name="fast", host="x", port=8000, model="m", tier=0))

    @pytest.mark.asyncio
    async def test_remove_node(self):
        config = _make_cluster_config()
        manager = ClusterManager(config)
        assert len(manager.list_nodes()) == 3

        await manager.remove_node("medium")
        assert len(manager.list_nodes()) == 2
        assert manager.get_node_by_name("medium") is None

    @pytest.mark.asyncio
    async def test_remove_nonexistent_node_raises(self):
        config = _make_cluster_config()
        manager = ClusterManager(config)
        with pytest.raises(ValueError, match="not found"):
            await manager.remove_node("nonexistent")


class TestClusterManagerLifecycle:
    @pytest.mark.asyncio
    async def test_close(self):
        config = _make_cluster_config(
            [NodeConfig(name="fast", host="fast.local", port=8000, model="m", tier=0)]
        )
        manager = ClusterManager(config)
        await manager.close()

    @pytest.mark.asyncio
    async def test_context_manager(self):
        config = _make_cluster_config(
            [NodeConfig(name="fast", host="fast.local", port=8000, model="m", tier=0)]
        )
        async with ClusterManager(config) as manager:
            assert len(manager.list_nodes()) == 1
