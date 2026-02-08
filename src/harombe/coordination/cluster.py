"""Cluster management for multi-node orchestration."""

import asyncio
import time
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional

import httpx

from harombe.config.schema import ClusterConfig, NodeConfig
from harombe.coordination.circuit_breaker import CircuitBreakerConfig, CircuitBreakerRegistry
from harombe.coordination.discovery import ServiceDiscovery
from harombe.coordination.router import Router, RoutingDecision
from harombe.llm.client import LLMClient, Message
from harombe.llm.remote import RemoteLLMClient


class NodeStatus(Enum):
    """Node availability status."""

    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    DEGRADED = "degraded"  # Available but experiencing issues


@dataclass
class NodeHealth:
    """Runtime health information for a node."""

    name: str
    status: NodeStatus
    load: float  # 0.0-1.0, proportion of max concurrent requests
    latency_ms: float  # Network latency to coordinator
    last_check: datetime
    active_requests: int = 0
    error_count: int = 0


class ClusterManager:
    """
    Manages a cluster of harombe nodes for distributed inference.

    Responsibilities:
    - Node registry and lifecycle management
    - Health monitoring and status tracking
    - Node selection for query routing
    - Load balancing across same-tier nodes
    """

    def __init__(
        self,
        config: ClusterConfig,
        enable_discovery: bool = False,
        health_check_interval: int = 30,
    ):
        """
        Initialize cluster manager.

        Args:
            config: Cluster configuration
            enable_discovery: Enable mDNS service discovery
            health_check_interval: Seconds between health checks
        """
        self.config = config
        self._nodes: Dict[str, NodeConfig] = {}
        self._health: Dict[str, NodeHealth] = {}
        self._clients: Dict[str, RemoteLLMClient] = {}
        self._monitoring_task: Optional[asyncio.Task] = None
        self.health_check_interval = health_check_interval

        # Circuit breaker for failing nodes
        breaker_config = CircuitBreakerConfig(
            failure_threshold=5,
            success_threshold=2,
            timeout=60.0,
            half_open_timeout=30.0,
        )
        self._circuit_breakers = CircuitBreakerRegistry(breaker_config)

        # Smart router for complexity-based routing
        self._router = Router()

        # Service discovery
        self._discovery: Optional[ServiceDiscovery] = None
        if enable_discovery and config.discovery.method == "mdns":
            self._discovery = ServiceDiscovery(
                service_type=config.discovery.mdns_service,
                on_service_discovered=self._on_service_discovered,
            )

        # Register nodes from config
        for node in config.nodes:
            if node.enabled:
                self.register_node(node)

    def _on_service_discovered(self, node: NodeConfig) -> None:
        """Callback when a new service is discovered via mDNS."""
        if node.name not in self._nodes:
            self.register_node(node)

    def register_node(self, node: NodeConfig) -> None:
        """
        Register a new node in the cluster.

        Args:
            node: Node configuration
        """
        self._nodes[node.name] = node
        self._health[node.name] = NodeHealth(
            name=node.name,
            status=NodeStatus.UNAVAILABLE,  # Will be updated by health check
            load=0.0,
            latency_ms=0.0,
            last_check=datetime.now(),
        )

        # Create client for this node
        self._clients[node.name] = RemoteLLMClient(
            host=node.host,
            port=node.port,
            auth_token=node.auth_token,
        )

    async def unregister_node(self, name: str) -> None:
        """
        Remove a node from the cluster.

        Args:
            name: Node name
        """
        if name in self._nodes:
            del self._nodes[name]
            del self._health[name]

            # Close and remove client
            if name in self._clients:
                await self._clients[name].close()
                del self._clients[name]

    def get_nodes_by_tier(self, tier: int, available_only: bool = True) -> List[NodeConfig]:
        """
        Get all nodes in a specific tier.

        Args:
            tier: Tier level (0, 1, or 2)
            available_only: Only return available nodes

        Returns:
            List of nodes in the specified tier
        """
        nodes = [node for node in self._nodes.values() if node.tier == tier]

        if available_only:
            nodes = [
                node
                for node in nodes
                if self._health[node.name].status == NodeStatus.AVAILABLE
            ]

        return nodes

    def get_node_by_name(self, name: str) -> Optional[NodeConfig]:
        """
        Get a node by name.

        Args:
            name: Node name

        Returns:
            Node configuration or None if not found
        """
        return self._nodes.get(name)

    def get_node_health(self, name: str) -> Optional[NodeHealth]:
        """
        Get health information for a node.

        Args:
            name: Node name

        Returns:
            Node health or None if not found
        """
        return self._health.get(name)

    def get_client(self, name: str) -> Optional[LLMClient]:
        """
        Get LLM client for a specific node.

        Args:
            name: Node name

        Returns:
            LLM client or None if not found
        """
        return self._clients.get(name)

    async def check_node_health(self, name: str, max_retries: int = 3) -> NodeHealth:
        """
        Perform health check on a single node with retry logic.

        Args:
            name: Node name
            max_retries: Maximum number of retry attempts

        Returns:
            Updated health information
        """
        node = self._nodes.get(name)
        if not node:
            raise ValueError(f"Node {name} not found")

        health = self._health[name]

        # Check circuit breaker
        if not self._circuit_breakers.can_attempt(name):
            health.status = NodeStatus.UNAVAILABLE
            health.last_check = datetime.now()
            return health

        # Retry with exponential backoff
        for attempt in range(max_retries):
            try:
                # Measure latency with a simple HTTP ping
                start = time.time()
                async with httpx.AsyncClient(timeout=5.0) as client:
                    response = await client.get(f"http://{node.host}:{node.port}/health")
                    response.raise_for_status()

                latency_ms = (time.time() - start) * 1000

                # Update health
                health.status = NodeStatus.AVAILABLE
                health.latency_ms = latency_ms
                health.last_check = datetime.now()
                health.error_count = 0

                # Record success in circuit breaker
                self._circuit_breakers.record_success(name)

                return health

            except Exception as e:
                # Exponential backoff
                if attempt < max_retries - 1:
                    await asyncio.sleep(2 ** attempt)
                    continue

                # All retries failed
                health.status = NodeStatus.UNAVAILABLE
                health.last_check = datetime.now()
                health.error_count += 1

                # Record failure in circuit breaker
                self._circuit_breakers.record_failure(name)

        return health

    async def check_all_health(self) -> Dict[str, NodeHealth]:
        """
        Perform health checks on all nodes.

        Returns:
            Dictionary of node health by name
        """
        tasks = [self.check_node_health(name) for name in self._nodes.keys()]
        await asyncio.gather(*tasks, return_exceptions=True)
        return self._health

    async def start(self) -> None:
        """Start cluster manager with discovery and monitoring."""
        # Start service discovery if configured
        if self._discovery:
            await self._discovery.start_discovery()

        # Start periodic health monitoring
        await self.start_monitoring()

    async def start_monitoring(self, interval: Optional[int] = None) -> None:
        """
        Start periodic health monitoring.

        Args:
            interval: Check interval in seconds (uses default if None)
        """
        if self._monitoring_task and not self._monitoring_task.done():
            return  # Already running

        check_interval = interval or self.health_check_interval

        async def monitor():
            while True:
                await self.check_all_health()
                await asyncio.sleep(check_interval)

        self._monitoring_task = asyncio.create_task(monitor())

    async def stop_monitoring(self) -> None:
        """Stop periodic health monitoring."""
        if self._monitoring_task and not self._monitoring_task.done():
            self._monitoring_task.cancel()
            try:
                await self._monitoring_task
            except asyncio.CancelledError:
                pass

    def select_node(self, tier: int, fallback: bool = True) -> Optional[NodeConfig]:
        """
        Select the best node for a query.

        Args:
            tier: Preferred tier
            fallback: Whether to fallback to other tiers if preferred unavailable

        Returns:
            Selected node or None if no suitable node found
        """
        # Try preferred tier first
        nodes = self.get_nodes_by_tier(tier, available_only=True)

        if not nodes and fallback and self.config.routing.fallback_strategy == "graceful":
            # Fallback strategy: try adjacent tiers
            if tier == 2:
                nodes = self.get_nodes_by_tier(1, available_only=True)
                if not nodes:
                    nodes = self.get_nodes_by_tier(0, available_only=True)
            elif tier == 1:
                nodes = self.get_nodes_by_tier(2, available_only=True)
                if not nodes:
                    nodes = self.get_nodes_by_tier(0, available_only=True)
            elif tier == 0:
                nodes = self.get_nodes_by_tier(1, available_only=True)
                if not nodes:
                    nodes = self.get_nodes_by_tier(2, available_only=True)

        if not nodes:
            return None

        # Load balancing: select least loaded node
        if self.config.routing.load_balance and len(nodes) > 1:
            # Sort by load (ascending)
            nodes_with_load = [
                (node, self._health[node.name].load) for node in nodes
            ]
            nodes_with_load.sort(key=lambda x: x[1])
            return nodes_with_load[0][0]

        # Prefer local (lowest latency)
        if self.config.routing.prefer_local and len(nodes) > 1:
            nodes_with_latency = [
                (node, self._health[node.name].latency_ms) for node in nodes
            ]
            nodes_with_latency.sort(key=lambda x: x[1])
            return nodes_with_latency[0][0]

        # Default: return first available
        return nodes[0]

    def select_node_smart(
        self,
        query: str,
        context: Optional[List[Message]] = None,
        fallback: bool = True,
    ) -> tuple[Optional[NodeConfig], RoutingDecision]:
        """
        Smart node selection based on query complexity analysis.

        Args:
            query: User query text
            context: Optional conversation history
            fallback: Whether to fallback to other tiers if preferred unavailable

        Returns:
            Tuple of (selected node, routing decision)
        """
        # Analyze routing requirements
        decision = self._router.analyze_routing(query, context)

        # Select node based on recommended tier
        node = self.select_node(decision.recommended_tier, fallback=fallback)

        return node, decision

    async def close(self) -> None:
        """Close all clients, stop monitoring, and cleanup discovery."""
        await self.stop_monitoring()

        if self._discovery:
            await self._discovery.stop()

        for client in self._clients.values():
            await client.close()

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()
