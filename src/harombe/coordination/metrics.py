"""Performance metrics tracking for cluster nodes."""

import time
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class RequestMetrics:
    """Metrics for a single request."""

    node_name: str
    start_time: float
    end_time: float | None = None
    success: bool = True
    error: str | None = None
    tokens: int = 0

    @property
    def duration_ms(self) -> float:
        """Calculate request duration in milliseconds."""
        if self.end_time is None:
            return (time.time() - self.start_time) * 1000
        return (self.end_time - self.start_time) * 1000


@dataclass
class NodeMetrics:
    """Aggregated metrics for a node."""

    name: str
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    total_tokens: int = 0
    total_duration_ms: float = 0.0
    last_request_time: datetime | None = None
    error_history: list[str] = field(default_factory=list)

    @property
    def success_rate(self) -> float:
        """Calculate success rate (0.0 to 1.0)."""
        if self.total_requests == 0:
            return 0.0
        return self.successful_requests / self.total_requests

    @property
    def average_latency_ms(self) -> float:
        """Calculate average request latency in milliseconds."""
        if self.total_requests == 0:
            return 0.0
        return self.total_duration_ms / self.total_requests

    @property
    def tokens_per_second(self) -> float:
        """Calculate average tokens per second throughput."""
        if self.total_duration_ms == 0:
            return 0.0
        return (self.total_tokens * 1000) / self.total_duration_ms


class MetricsCollector:
    """
    Collects and aggregates performance metrics for cluster nodes.

    Tracks request latency, success rates, throughput, and errors.
    """

    def __init__(self, max_error_history: int = 100):
        """
        Initialize metrics collector.

        Args:
            max_error_history: Maximum errors to keep per node
        """
        self._node_metrics: dict[str, NodeMetrics] = {}
        self._active_requests: dict[str, RequestMetrics] = {}
        self.max_error_history = max_error_history

    def start_request(self, node_name: str) -> str:
        """
        Start tracking a new request.

        Args:
            node_name: Name of the node handling the request

        Returns:
            Request ID for tracking
        """
        request_id = f"{node_name}_{time.time()}"
        self._active_requests[request_id] = RequestMetrics(
            node_name=node_name,
            start_time=time.time(),
        )
        return request_id

    def end_request(
        self,
        request_id: str,
        success: bool = True,
        error: str | None = None,
        tokens: int = 0,
    ) -> None:
        """
        Complete a request and update metrics.

        Args:
            request_id: Request ID from start_request
            success: Whether request succeeded
            error: Optional error message
            tokens: Number of tokens processed
        """
        if request_id not in self._active_requests:
            return

        request = self._active_requests.pop(request_id)
        request.end_time = time.time()
        request.success = success
        request.error = error
        request.tokens = tokens

        # Update node metrics
        self._update_node_metrics(request)

    def _update_node_metrics(self, request: RequestMetrics) -> None:
        """Update aggregated metrics for a node."""
        node_name = request.node_name

        if node_name not in self._node_metrics:
            self._node_metrics[node_name] = NodeMetrics(name=node_name)

        metrics = self._node_metrics[node_name]
        metrics.total_requests += 1
        metrics.total_duration_ms += request.duration_ms
        metrics.total_tokens += request.tokens
        metrics.last_request_time = datetime.now()

        if request.success:
            metrics.successful_requests += 1
        else:
            metrics.failed_requests += 1
            if request.error:
                metrics.error_history.append(request.error)
                # Keep only recent errors
                if len(metrics.error_history) > self.max_error_history:
                    metrics.error_history.pop(0)

    def get_node_metrics(self, node_name: str) -> NodeMetrics | None:
        """
        Get metrics for a specific node.

        Args:
            node_name: Name of the node

        Returns:
            NodeMetrics or None if no metrics available
        """
        return self._node_metrics.get(node_name)

    def get_all_metrics(self) -> dict[str, NodeMetrics]:
        """
        Get metrics for all nodes.

        Returns:
            Dictionary mapping node names to their metrics
        """
        return self._node_metrics.copy()

    def reset_node_metrics(self, node_name: str) -> None:
        """
        Reset metrics for a specific node.

        Args:
            node_name: Name of the node
        """
        if node_name in self._node_metrics:
            del self._node_metrics[node_name]

    def reset_all_metrics(self) -> None:
        """Reset all collected metrics."""
        self._node_metrics.clear()
        self._active_requests.clear()

    def get_cluster_summary(self) -> dict[str, any]:
        """
        Get summary statistics for the entire cluster.

        Returns:
            Dictionary with cluster-wide metrics
        """
        if not self._node_metrics:
            return {
                "total_nodes": 0,
                "total_requests": 0,
                "average_success_rate": 0.0,
                "average_latency_ms": 0.0,
                "total_tokens": 0,
            }

        total_requests = sum(m.total_requests for m in self._node_metrics.values())
        total_successful = sum(m.successful_requests for m in self._node_metrics.values())
        total_duration = sum(m.total_duration_ms for m in self._node_metrics.values())
        total_tokens = sum(m.total_tokens for m in self._node_metrics.values())

        return {
            "total_nodes": len(self._node_metrics),
            "total_requests": total_requests,
            "average_success_rate": total_successful / total_requests
            if total_requests > 0
            else 0.0,
            "average_latency_ms": total_duration / total_requests if total_requests > 0 else 0.0,
            "total_tokens": total_tokens,
            "tokens_per_second": (total_tokens * 1000) / total_duration
            if total_duration > 0
            else 0.0,
        }
