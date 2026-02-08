"""Tests for metrics collection and tracking."""

import time

import pytest

from harombe.coordination.metrics import MetricsCollector, NodeMetrics, RequestMetrics


def test_request_metrics_duration():
    """Test request duration calculation."""
    metrics = RequestMetrics(node_name="test", start_time=time.time())
    time.sleep(0.01)  # 10ms
    metrics.end_time = time.time()

    assert metrics.duration_ms >= 10.0
    assert metrics.duration_ms < 50.0  # Should be quick


def test_node_metrics_success_rate():
    """Test success rate calculation."""
    metrics = NodeMetrics(name="test")

    # No requests yet
    assert metrics.success_rate == 0.0

    # After successful requests
    metrics.total_requests = 10
    metrics.successful_requests = 8
    metrics.failed_requests = 2

    assert metrics.success_rate == 0.8


def test_node_metrics_average_latency():
    """Test average latency calculation."""
    metrics = NodeMetrics(name="test")

    # No requests yet
    assert metrics.average_latency_ms == 0.0

    # After requests
    metrics.total_requests = 5
    metrics.total_duration_ms = 500.0

    assert metrics.average_latency_ms == 100.0


def test_node_metrics_throughput():
    """Test tokens per second calculation."""
    metrics = NodeMetrics(name="test")

    # No duration yet
    assert metrics.tokens_per_second == 0.0

    # After processing tokens
    metrics.total_tokens = 1000
    metrics.total_duration_ms = 2000.0  # 2 seconds

    assert metrics.tokens_per_second == 500.0


def test_metrics_collector_start_end_request():
    """Test basic request tracking."""
    collector = MetricsCollector()

    request_id = collector.start_request("node1")
    assert request_id.startswith("node1_")

    time.sleep(0.01)
    collector.end_request(request_id, success=True, tokens=100)

    metrics = collector.get_node_metrics("node1")
    assert metrics is not None
    assert metrics.total_requests == 1
    assert metrics.successful_requests == 1
    assert metrics.failed_requests == 0
    assert metrics.total_tokens == 100


def test_metrics_collector_successful_requests():
    """Test successful request tracking."""
    collector = MetricsCollector()

    # Track multiple successful requests
    for i in range(5):
        req_id = collector.start_request("node1")
        time.sleep(0.001)
        collector.end_request(req_id, success=True, tokens=50)

    metrics = collector.get_node_metrics("node1")
    assert metrics.total_requests == 5
    assert metrics.successful_requests == 5
    assert metrics.failed_requests == 0
    assert metrics.success_rate == 1.0
    assert metrics.total_tokens == 250


def test_metrics_collector_failed_requests():
    """Test failed request tracking."""
    collector = MetricsCollector()

    # Mix of successful and failed requests
    for i in range(10):
        req_id = collector.start_request("node1")
        time.sleep(0.001)
        success = i < 7  # 7 successful, 3 failed
        error = None if success else "Test error"
        collector.end_request(req_id, success=success, error=error, tokens=10)

    metrics = collector.get_node_metrics("node1")
    assert metrics.total_requests == 10
    assert metrics.successful_requests == 7
    assert metrics.failed_requests == 3
    assert metrics.success_rate == 0.7


def test_metrics_collector_error_history():
    """Test error history tracking."""
    collector = MetricsCollector(max_error_history=3)

    # Generate multiple errors
    for i in range(5):
        req_id = collector.start_request("node1")
        collector.end_request(req_id, success=False, error=f"Error {i}")

    metrics = collector.get_node_metrics("node1")
    # Should only keep last 3 errors
    assert len(metrics.error_history) == 3
    assert "Error 4" in metrics.error_history


def test_metrics_collector_multiple_nodes():
    """Test tracking multiple nodes independently."""
    collector = MetricsCollector()

    # Track requests for different nodes
    for node in ["node1", "node2", "node3"]:
        for i in range(3):
            req_id = collector.start_request(node)
            collector.end_request(req_id, success=True, tokens=100)

    # Verify each node has its own metrics
    for node in ["node1", "node2", "node3"]:
        metrics = collector.get_node_metrics(node)
        assert metrics.total_requests == 3
        assert metrics.total_tokens == 300


def test_metrics_collector_get_all_metrics():
    """Test retrieving all node metrics."""
    collector = MetricsCollector()

    # Add metrics for multiple nodes
    for node in ["node1", "node2"]:
        req_id = collector.start_request(node)
        collector.end_request(req_id, success=True)

    all_metrics = collector.get_all_metrics()
    assert len(all_metrics) == 2
    assert "node1" in all_metrics
    assert "node2" in all_metrics


def test_metrics_collector_reset_node():
    """Test resetting metrics for a specific node."""
    collector = MetricsCollector()

    # Add metrics
    req_id = collector.start_request("node1")
    collector.end_request(req_id, success=True)

    req_id = collector.start_request("node2")
    collector.end_request(req_id, success=True)

    # Reset one node
    collector.reset_node_metrics("node1")

    assert collector.get_node_metrics("node1") is None
    assert collector.get_node_metrics("node2") is not None


def test_metrics_collector_reset_all():
    """Test resetting all metrics."""
    collector = MetricsCollector()

    # Add metrics
    for node in ["node1", "node2", "node3"]:
        req_id = collector.start_request(node)
        collector.end_request(req_id, success=True)

    # Reset all
    collector.reset_all_metrics()

    assert len(collector.get_all_metrics()) == 0


def test_metrics_collector_cluster_summary():
    """Test cluster-wide summary statistics."""
    collector = MetricsCollector()

    # Empty cluster
    summary = collector.get_cluster_summary()
    assert summary["total_nodes"] == 0
    assert summary["total_requests"] == 0

    # Add metrics for multiple nodes
    for node in ["node1", "node2"]:
        for i in range(5):
            req_id = collector.start_request(node)
            time.sleep(0.001)
            collector.end_request(req_id, success=(i < 4), tokens=100)

    summary = collector.get_cluster_summary()
    assert summary["total_nodes"] == 2
    assert summary["total_requests"] == 10
    assert summary["average_success_rate"] == 0.8
    assert summary["total_tokens"] == 1000
    assert summary["average_latency_ms"] > 0
    assert summary["tokens_per_second"] > 0


def test_metrics_collector_invalid_request_id():
    """Test ending a request with invalid ID."""
    collector = MetricsCollector()

    # Should not raise error, just ignore
    collector.end_request("invalid_id", success=True)

    # No metrics should be created
    assert len(collector.get_all_metrics()) == 0


def test_metrics_collector_last_request_time():
    """Test last request timestamp tracking."""
    collector = MetricsCollector()

    req_id = collector.start_request("node1")
    collector.end_request(req_id, success=True)

    metrics = collector.get_node_metrics("node1")
    assert metrics.last_request_time is not None
    assert isinstance(metrics.last_request_time.isoformat(), str)
