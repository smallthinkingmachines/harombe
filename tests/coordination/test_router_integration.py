"""End-to-end routing tests: query → classification → node selection → response."""

import pytest
import respx
from httpx import Response

from harombe.config.schema import (
    ClusterConfig,
    DiscoveryConfig,
    NodeConfig,
    RoutingConfig,
)
from harombe.coordination.cluster import ClusterManager
from harombe.coordination.router import ComplexityClassifier, Router, TaskComplexity


class TestComplexityClassification:
    def setup_method(self):
        self.classifier = ComplexityClassifier()

    def test_simple_questions(self):
        simple_queries = [
            "What is Python?",
            "List the planets",
            "When was Python released?",
            "Show me the time",
        ]
        for query in simple_queries:
            result = self.classifier.classify_query(query)
            assert result in (
                TaskComplexity.SIMPLE,
                TaskComplexity.MEDIUM,
            ), f"Expected SIMPLE or MEDIUM for: {query!r}, got {result}"

    def test_complex_queries(self):
        complex_queries = [
            "Design a distributed system architecture, explain the tradeoffs, and optimize for high availability",
            "```python\ndef process_data(items):\n    return [x*2 for x in items]\n```\nRefactor this to use async/await",
        ]
        for query in complex_queries:
            result = self.classifier.classify_query(query)
            assert result in (
                TaskComplexity.MEDIUM,
                TaskComplexity.COMPLEX,
            ), f"Expected MEDIUM or COMPLEX for: {query[:50]!r}..., got {result}"

    def test_code_block_query_at_least_medium(self):
        query = "```python\nclass AuthService:\n    def authenticate(self, token):\n        pass\n```\nRefactor this and implement comprehensive tests"
        result = self.classifier.classify_query(query)
        assert result in (TaskComplexity.MEDIUM, TaskComplexity.COMPLEX)

    def test_medium_queries(self):
        medium_queries = [
            "Explain how Python's garbage collector works and compare it with Java's approach",
            "Debug this function that's returning incorrect values for edge cases",
        ]
        for query in medium_queries:
            result = self.classifier.classify_query(query)
            assert result in (
                TaskComplexity.MEDIUM,
                TaskComplexity.COMPLEX,
            ), f"Expected MEDIUM or COMPLEX for: {query[:50]!r}..., got {result}"


class TestRouterDecisions:
    def setup_method(self):
        self.router = Router()

    def test_simple_query_tier_0(self):
        decision = self.router.analyze_routing("Hello")
        assert decision.recommended_tier == 0
        assert decision.estimated_tokens > 0

    def test_complex_query_at_least_tier_1(self):
        decision = self.router.analyze_routing(
            "Analyze and refactor this authentication code to implement OAuth2 with PKCE, "
            "write comprehensive tests, and explain the security implications"
        )
        assert decision.recommended_tier >= 1

    def test_large_context_bumps_tier(self):
        from harombe.llm.client import Message

        # Create large context
        messages = [
            Message(role="user", content="x " * 2000),
            Message(role="assistant", content="y " * 2000),
        ]
        decision = self.router.analyze_routing("simple question", context=messages)
        assert decision.recommended_tier >= 1


class TestEndToEndRouting:
    """Full routing pipeline: query → classify → select node → verify."""

    @pytest.mark.asyncio
    @respx.mock
    async def test_simple_query_routes_to_fast_node(self):
        """Simple query should route to tier 0 (fast) node."""
        for host in ["fast.local", "medium.local", "powerful.local"]:
            respx.get(f"http://{host}:8000/health").mock(
                return_value=Response(200, json={"status": "ok"})
            )

        config = ClusterConfig(
            discovery=DiscoveryConfig(method="explicit"),
            routing=RoutingConfig(prefer_local=True, fallback_strategy="graceful"),
            nodes=[
                NodeConfig(name="fast", host="fast.local", port=8000, model="qwen:3b", tier=0),
                NodeConfig(name="medium", host="medium.local", port=8000, model="qwen:14b", tier=1),
                NodeConfig(
                    name="powerful", host="powerful.local", port=8000, model="qwen:72b", tier=2
                ),
            ],
        )
        manager = ClusterManager(config)
        await manager.check_all_health()

        node, decision = manager.select_node_smart("What is 2+2?")
        assert node is not None
        assert node.name == "fast"
        assert decision.complexity == TaskComplexity.SIMPLE

    @pytest.mark.asyncio
    @respx.mock
    async def test_non_simple_query_routes_above_tier_0(self):
        """Non-trivial query should route to tier 1 or 2."""
        for host in ["fast.local", "medium.local", "powerful.local"]:
            respx.get(f"http://{host}:8000/health").mock(
                return_value=Response(200, json={"status": "ok"})
            )

        config = ClusterConfig(
            discovery=DiscoveryConfig(method="explicit"),
            routing=RoutingConfig(prefer_local=True, fallback_strategy="graceful"),
            nodes=[
                NodeConfig(name="fast", host="fast.local", port=8000, model="qwen:3b", tier=0),
                NodeConfig(name="medium", host="medium.local", port=8000, model="qwen:14b", tier=1),
                NodeConfig(
                    name="powerful", host="powerful.local", port=8000, model="qwen:72b", tier=2
                ),
            ],
        )
        manager = ClusterManager(config)
        await manager.check_all_health()

        node, decision = manager.select_node_smart(
            "Analyze this code, refactor to use async patterns, implement error handling, "
            "and design comprehensive test coverage"
        )
        assert node is not None
        assert node.tier >= 1
        assert decision.complexity in (TaskComplexity.MEDIUM, TaskComplexity.COMPLEX)

    @pytest.mark.asyncio
    @respx.mock
    async def test_fallback_routing_when_preferred_tier_down(self):
        """When preferred tier is down, should fallback to other tiers."""
        respx.get("http://fast.local:8000/health").mock(
            return_value=Response(200, json={"status": "ok"})
        )
        respx.get("http://medium.local:8000/health").mock(side_effect=ConnectionError)
        respx.get("http://powerful.local:8000/health").mock(side_effect=ConnectionError)

        config = ClusterConfig(
            discovery=DiscoveryConfig(method="explicit"),
            routing=RoutingConfig(prefer_local=True, fallback_strategy="graceful"),
            nodes=[
                NodeConfig(name="fast", host="fast.local", port=8000, model="qwen:3b", tier=0),
                NodeConfig(name="medium", host="medium.local", port=8000, model="qwen:14b", tier=1),
                NodeConfig(
                    name="powerful", host="powerful.local", port=8000, model="qwen:72b", tier=2
                ),
            ],
        )
        manager = ClusterManager(config)
        await manager.check_all_health()

        # Both tier 1 and 2 are down, should fallback to tier 0
        node = manager.select_node(tier=1, fallback=True)
        assert node is not None
        assert node.name == "fast"

    @pytest.mark.asyncio
    @respx.mock
    async def test_all_nodes_down_returns_none(self):
        """When all nodes are down, should return None."""
        for host in ["fast.local", "medium.local", "powerful.local"]:
            respx.get(f"http://{host}:8000/health").mock(side_effect=ConnectionError)

        config = ClusterConfig(
            discovery=DiscoveryConfig(method="explicit"),
            routing=RoutingConfig(prefer_local=True, fallback_strategy="graceful"),
            nodes=[
                NodeConfig(name="fast", host="fast.local", port=8000, model="qwen:3b", tier=0),
                NodeConfig(name="medium", host="medium.local", port=8000, model="qwen:14b", tier=1),
                NodeConfig(
                    name="powerful", host="powerful.local", port=8000, model="qwen:72b", tier=2
                ),
            ],
        )
        manager = ClusterManager(config)
        await manager.check_all_health()

        node, _decision = manager.select_node_smart("Hello")
        assert node is None

    @pytest.mark.asyncio
    @respx.mock
    async def test_client_available_for_selected_node(self):
        """Verify that LLM client is available for the selected node."""
        respx.get("http://fast.local:8000/health").mock(
            return_value=Response(200, json={"status": "ok"})
        )

        config = ClusterConfig(
            discovery=DiscoveryConfig(method="explicit"),
            routing=RoutingConfig(prefer_local=True, fallback_strategy="graceful"),
            nodes=[
                NodeConfig(name="fast", host="fast.local", port=8000, model="qwen:3b", tier=0),
            ],
        )
        manager = ClusterManager(config)
        await manager.check_all_health()

        node, _ = manager.select_node_smart("Hello")
        assert node is not None
        client = manager.get_client(node.name)
        assert client is not None
