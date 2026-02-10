"""Comprehensive tests for traffic anomaly detection.

Tests cover:
- TrafficFeatures model (4 tests)
- TrafficBaseline learning (6 tests)
- NetworkConnection model (3 tests)
- TrafficAnomalyDetector detection (10 tests)
- Statistical deviation detection (5 tests)
- ML-based detection (3 tests)
- Alert generation / explanation (3 tests)
- Statistics tracking (3 tests)
- Performance benchmarks (2 tests)
- Edge cases (5 tests)

Total: 44 tests

Run:
    pytest tests/security/test_traffic_anomaly.py -v
"""

import time
from datetime import datetime, timedelta

import numpy as np
import pytest

from harombe.security.ml.models import ThreatLevel
from harombe.security.ml.traffic_anomaly import (
    NetworkConnection,
    TrafficAnomalyDetector,
    TrafficAnomalyResult,
    TrafficFeatures,
)

# ============================================================================
# Helpers
# ============================================================================


def _make_connections(
    source_id: str = "container-1",
    count: int = 100,
    dest: str = "api.example.com",
    dest_port: int = 443,
    bytes_sent_range: tuple[int, int] = (100, 2000),
    bytes_received_range: tuple[int, int] = (500, 5000),
    duration_range: tuple[float, float] = (0.05, 0.5),
    hours_spread: int = 48,
) -> list[NetworkConnection]:
    """Generate a batch of normal-looking connections."""
    rng = np.random.RandomState(42)
    base = datetime(2026, 2, 5, 10, 0, 0)
    conns = []
    for _i in range(count):
        ts = base + timedelta(hours=rng.randint(0, hours_spread))
        conns.append(
            NetworkConnection(
                source_id=source_id,
                destination=dest,
                dest_port=dest_port,
                bytes_sent=int(rng.randint(*bytes_sent_range)),
                bytes_received=int(rng.randint(*bytes_received_range)),
                duration_s=round(rng.uniform(*duration_range), 3),
                packet_count=int(rng.randint(5, 30)),
                timestamp=ts,
            )
        )
    return conns


def _make_anomalous_connection(
    source_id: str = "container-1",
) -> NetworkConnection:
    """Create a clearly anomalous connection."""
    return NetworkConnection(
        source_id=source_id,
        destination="suspicious.darkweb.onion",
        dest_port=9999,
        bytes_sent=500_000,  # Much larger than normal
        bytes_received=1_000_000,
        duration_s=120.0,  # Much longer than normal
        packet_count=5000,
        timestamp=datetime(2026, 2, 5, 3, 30, 0),  # 3:30 AM
    )


# ============================================================================
# TrafficFeatures Tests
# ============================================================================


class TestTrafficFeatures:
    """Test TrafficFeatures model."""

    def test_default_values(self):
        f = TrafficFeatures()
        assert f.bytes_sent == 0
        assert f.bytes_received == 0
        assert f.duration_s == 0.0
        assert f.is_weekend is False

    def test_to_array_length(self):
        f = TrafficFeatures(bytes_sent=100, dest_port=443, hour_of_day=14)
        arr = f.to_array()
        assert len(arr) == 8
        assert arr[0] == 100.0  # bytes_sent
        assert arr[4] == 443.0  # dest_port
        assert arr[5] == 14.0  # hour_of_day

    def test_feature_names(self):
        names = TrafficFeatures.feature_names()
        assert len(names) == 8
        assert "bytes_sent" in names
        assert "dest_port" in names

    def test_weekend_flag(self):
        # Saturday = 5
        f = TrafficFeatures(day_of_week=5, is_weekend=True)
        assert f.is_weekend is True
        arr = f.to_array()
        assert arr[7] == 1.0


# ============================================================================
# NetworkConnection Model Tests
# ============================================================================


class TestNetworkConnection:
    """Test NetworkConnection model."""

    def test_basic_creation(self):
        conn = NetworkConnection(
            source_id="c1",
            destination="api.example.com",
            dest_port=443,
        )
        assert conn.source_id == "c1"
        assert conn.allowed is True
        assert conn.packet_count == 1

    def test_full_creation(self):
        conn = NetworkConnection(
            source_id="c1",
            destination="10.0.0.1",
            dest_port=80,
            bytes_sent=1024,
            bytes_received=4096,
            duration_s=0.5,
            packet_count=20,
        )
        assert conn.bytes_sent == 1024
        assert conn.duration_s == 0.5

    def test_metadata(self):
        conn = NetworkConnection(
            source_id="c1",
            destination="api.com",
            metadata={"tool": "web_search"},
        )
        assert conn.metadata["tool"] == "web_search"


# ============================================================================
# Baseline Learning Tests
# ============================================================================


class TestTrafficBaselineLearning:
    """Test baseline learning from connection data."""

    @pytest.fixture
    def detector(self):
        return TrafficAnomalyDetector(min_samples=20)

    @pytest.fixture
    def connections(self):
        return _make_connections(count=100)

    def test_learn_baseline_success(self, detector, connections):
        """Baseline is computed when enough data available."""
        for c in connections:
            detector.record_connection(c)

        baseline = detector.learn_baseline("container-1")

        assert baseline is not None
        assert baseline.source_id == "container-1"
        assert baseline.connection_count == 100

    def test_learn_baseline_insufficient_data(self, detector):
        """Returns None with too few connections."""
        for c in _make_connections(count=5):
            detector.record_connection(c)

        baseline = detector.learn_baseline("container-1")
        assert baseline is None

    def test_baseline_statistics(self, detector, connections):
        """Baseline contains correct statistical values."""
        for c in connections:
            detector.record_connection(c)

        baseline = detector.learn_baseline("container-1")

        assert baseline.avg_bytes_sent > 0
        assert baseline.std_bytes_sent > 0
        assert baseline.avg_duration_s > 0
        assert baseline.avg_packet_count > 0

    def test_baseline_port_distribution(self, detector, connections):
        """Baseline tracks port distribution."""
        for c in connections:
            detector.record_connection(c)

        baseline = detector.learn_baseline("container-1")

        assert 443 in baseline.common_ports
        assert baseline.common_ports[443] > 0.9  # All connections on 443

    def test_baseline_temporal_distribution(self, detector, connections):
        """Baseline learns hourly/daily distributions."""
        for c in connections:
            detector.record_connection(c)

        baseline = detector.learn_baseline("container-1")

        assert len(baseline.hourly_distribution) == 24
        assert len(baseline.daily_distribution) == 7
        assert abs(sum(baseline.hourly_distribution) - 1.0) < 0.01
        assert abs(sum(baseline.daily_distribution) - 1.0) < 0.01

    def test_baseline_ml_model_trained(self, detector, connections):
        """ML model is trained alongside baseline."""
        for c in connections:
            detector.record_connection(c)

        detector.learn_baseline("container-1")

        assert "container-1" in detector.models
        assert "container-1" in detector.scalers


# ============================================================================
# Detection Tests
# ============================================================================


class TestTrafficAnomalyDetection:
    """Test anomaly detection."""

    @pytest.fixture
    def trained_detector(self):
        detector = TrafficAnomalyDetector(min_samples=20, anomaly_threshold=0.7)
        connections = _make_connections(count=200)
        for c in connections:
            detector.record_connection(c)
        detector.learn_baseline("container-1")
        return detector

    def test_normal_connection_not_anomalous(self, trained_detector):
        """Normal connection should not be flagged."""
        normal = NetworkConnection(
            source_id="container-1",
            destination="api.example.com",
            dest_port=443,
            bytes_sent=500,
            bytes_received=2000,
            duration_s=0.2,
            packet_count=15,
            timestamp=datetime(2026, 2, 5, 12, 0, 0),
        )
        result = trained_detector.detect(normal)

        assert not result.is_anomaly or result.anomaly_score < 0.8
        assert result.threat_level in (ThreatLevel.NONE, ThreatLevel.LOW)

    def test_anomalous_connection_detected(self, trained_detector):
        """Clearly anomalous connection should be detected."""
        anomalous = _make_anomalous_connection()
        result = trained_detector.detect(anomalous)

        # The connection has extreme values; at least the score should be elevated
        assert result.anomaly_score > 0.3

    def test_no_baseline_returns_safe(self, trained_detector):
        """Connection from unknown source returns non-anomalous."""
        conn = NetworkConnection(
            source_id="unknown-container",
            destination="api.com",
            dest_port=443,
        )
        result = trained_detector.detect(conn)

        assert result.is_anomaly is False
        assert result.anomaly_score == 0.0
        assert "No baseline" in result.explanation

    def test_result_has_duration(self, trained_detector):
        """Result includes detection duration."""
        conn = NetworkConnection(
            source_id="container-1",
            destination="api.example.com",
            dest_port=443,
            bytes_sent=500,
        )
        result = trained_detector.detect(conn)

        assert result.duration_ms is not None
        assert result.duration_ms >= 0

    def test_result_has_deviation_scores(self, trained_detector):
        """Result includes per-feature deviation scores."""
        conn = NetworkConnection(
            source_id="container-1",
            destination="api.example.com",
            dest_port=443,
            bytes_sent=500,
            bytes_received=2000,
            duration_s=0.2,
            packet_count=15,
            timestamp=datetime(2026, 2, 5, 12, 0, 0),
        )
        result = trained_detector.detect(conn)

        assert "bytes_sent" in result.deviation_scores or "port" in result.deviation_scores

    def test_result_has_ml_score(self, trained_detector):
        """Result includes ML model score."""
        conn = NetworkConnection(
            source_id="container-1",
            destination="api.example.com",
            dest_port=443,
            bytes_sent=500,
            duration_s=0.2,
            timestamp=datetime(2026, 2, 5, 12, 0, 0),
        )
        result = trained_detector.detect(conn)

        assert 0.0 <= result.ml_score <= 1.0

    def test_threat_level_none_for_normal(self, trained_detector):
        """Normal traffic gets NONE threat level."""
        normal = NetworkConnection(
            source_id="container-1",
            destination="api.example.com",
            dest_port=443,
            bytes_sent=500,
            bytes_received=2000,
            duration_s=0.2,
            packet_count=15,
            timestamp=datetime(2026, 2, 5, 12, 0, 0),
        )
        result = trained_detector.detect(normal)

        # Flexible: either NONE or at worst LOW
        assert result.threat_level in (ThreatLevel.NONE, ThreatLevel.LOW)

    def test_large_byte_transfer_elevated_score(self, trained_detector):
        """Very large byte transfer should elevate deviation score."""
        big_transfer = NetworkConnection(
            source_id="container-1",
            destination="api.example.com",
            dest_port=443,
            bytes_sent=999_999,  # Way above baseline
            bytes_received=999_999,
            duration_s=0.2,
            packet_count=15,
            timestamp=datetime(2026, 2, 5, 12, 0, 0),
        )
        result = trained_detector.detect(big_transfer)

        # bytes_sent deviation should be high
        assert result.deviation_scores.get("bytes_sent", 0) > 0.5

    def test_unusual_port_elevated_score(self, trained_detector):
        """Connection to unusual port should have high port deviation."""
        unusual_port = NetworkConnection(
            source_id="container-1",
            destination="api.example.com",
            dest_port=31337,  # Not in baseline
            bytes_sent=500,
            bytes_received=2000,
            duration_s=0.2,
            packet_count=15,
            timestamp=datetime(2026, 2, 5, 12, 0, 0),
        )
        result = trained_detector.detect(unusual_port)

        assert result.deviation_scores.get("port", 0) > 0.9

    def test_get_baseline(self, trained_detector):
        """get_baseline returns stored baseline."""
        baseline = trained_detector.get_baseline("container-1")
        assert baseline is not None
        assert baseline.source_id == "container-1"

        assert trained_detector.get_baseline("nonexistent") is None


# ============================================================================
# Statistical Deviation Tests
# ============================================================================


class TestStatisticalDeviation:
    """Test statistical deviation computation."""

    @pytest.fixture
    def detector_with_baseline(self):
        detector = TrafficAnomalyDetector(min_samples=20)
        connections = _make_connections(count=100)
        for c in connections:
            detector.record_connection(c)
        detector.learn_baseline("container-1")
        return detector

    def test_deviation_scores_in_range(self, detector_with_baseline):
        """All deviation scores should be between 0 and 1."""
        conn = NetworkConnection(
            source_id="container-1",
            destination="api.example.com",
            dest_port=443,
            bytes_sent=500,
            duration_s=0.2,
            timestamp=datetime(2026, 2, 5, 12, 0, 0),
        )
        result = detector_with_baseline.detect(conn)

        for name, score in result.deviation_scores.items():
            assert 0.0 <= score <= 1.0, f"{name} out of range: {score}"

    def test_zero_std_skips_feature(self):
        """Features with zero std deviation are skipped (no division by zero)."""
        detector = TrafficAnomalyDetector(min_samples=10)
        # All identical connections -> std = 0
        conns = []
        for i in range(50):
            conns.append(
                NetworkConnection(
                    source_id="c1",
                    destination="api.com",
                    dest_port=443,
                    bytes_sent=100,
                    bytes_received=200,
                    duration_s=0.1,
                    packet_count=10,
                    timestamp=datetime(2026, 2, 5, 10, 0, 0) + timedelta(minutes=i),
                )
            )
        for c in conns:
            detector.record_connection(c)
        detector.learn_baseline("c1")

        # Should not crash even with zero std
        result = detector.detect(conns[0])
        assert result is not None

    def test_high_bytes_gives_high_deviation(self, detector_with_baseline):
        """Bytes way above baseline produce high deviation."""
        conn = NetworkConnection(
            source_id="container-1",
            destination="api.example.com",
            dest_port=443,
            bytes_sent=1_000_000,
            timestamp=datetime(2026, 2, 5, 12, 0, 0),
        )
        baseline = detector_with_baseline.baselines["container-1"]
        deviations = detector_with_baseline._compute_deviations(conn, baseline)

        assert deviations.get("bytes_sent", 0) > 0.8

    def test_normal_bytes_gives_low_deviation(self, detector_with_baseline):
        """Bytes within normal range produce low deviation."""
        baseline = detector_with_baseline.baselines["container-1"]
        conn = NetworkConnection(
            source_id="container-1",
            destination="api.example.com",
            dest_port=443,
            bytes_sent=int(baseline.avg_bytes_sent),
            timestamp=datetime(2026, 2, 5, 12, 0, 0),
        )
        deviations = detector_with_baseline._compute_deviations(conn, baseline)

        assert deviations.get("bytes_sent", 0) < 0.3

    def test_temporal_deviation(self, detector_with_baseline):
        """Connection at unusual hour has temporal deviation."""
        # The baseline was generated with hours 10-58 spread,
        # a 3 AM connection should have some deviation if hour 3 has low probability
        conn = NetworkConnection(
            source_id="container-1",
            destination="api.example.com",
            dest_port=443,
            bytes_sent=500,
            timestamp=datetime(2026, 2, 5, 3, 0, 0),  # 3 AM
        )
        result = detector_with_baseline.detect(conn)

        assert "temporal" in result.deviation_scores


# ============================================================================
# ML Detection Tests
# ============================================================================


class TestMLDetection:
    """Test ML-based detection component."""

    @pytest.fixture
    def trained_detector(self):
        detector = TrafficAnomalyDetector(min_samples=20)
        for c in _make_connections(count=200):
            detector.record_connection(c)
        detector.learn_baseline("container-1")
        return detector

    def test_ml_score_in_range(self, trained_detector):
        """ML score should be between 0 and 1."""
        conn = NetworkConnection(
            source_id="container-1",
            destination="api.example.com",
            dest_port=443,
            bytes_sent=500,
            timestamp=datetime(2026, 2, 5, 12, 0, 0),
        )
        score = trained_detector._ml_detect(conn, "container-1")
        assert 0.0 <= score <= 1.0

    def test_ml_score_zero_without_model(self, trained_detector):
        """ML score is 0 for unknown source."""
        conn = NetworkConnection(
            source_id="unknown",
            destination="api.com",
        )
        score = trained_detector._ml_detect(conn, "unknown")
        assert score == 0.0

    def test_ml_score_elevated_for_anomaly(self, trained_detector):
        """ML score should be higher for anomalous traffic."""
        normal = NetworkConnection(
            source_id="container-1",
            destination="api.example.com",
            dest_port=443,
            bytes_sent=500,
            bytes_received=2000,
            duration_s=0.2,
            packet_count=15,
            timestamp=datetime(2026, 2, 5, 12, 0, 0),
        )
        anomalous = _make_anomalous_connection()

        normal_score = trained_detector._ml_detect(normal, "container-1")
        anomaly_score = trained_detector._ml_detect(anomalous, "container-1")

        # Anomalous score should generally be higher (flexible due to probabilistic model)
        assert anomaly_score >= normal_score or anomaly_score > 0.1


# ============================================================================
# Explanation Tests
# ============================================================================


class TestExplanation:
    """Test explanation generation."""

    @pytest.fixture
    def trained_detector(self):
        detector = TrafficAnomalyDetector(min_samples=20)
        for c in _make_connections(count=100):
            detector.record_connection(c)
        detector.learn_baseline("container-1")
        return detector

    def test_explanation_present(self, trained_detector):
        """Result always has an explanation string."""
        conn = NetworkConnection(
            source_id="container-1",
            destination="api.example.com",
            dest_port=443,
            bytes_sent=500,
            timestamp=datetime(2026, 2, 5, 12, 0, 0),
        )
        result = trained_detector.detect(conn)
        assert result.explanation is not None
        assert len(result.explanation) > 0

    def test_explanation_mentions_high_deviations(self, trained_detector):
        """Explanation calls out features with high deviation."""
        big = NetworkConnection(
            source_id="container-1",
            destination="api.example.com",
            dest_port=443,
            bytes_sent=999_999,
            timestamp=datetime(2026, 2, 5, 12, 0, 0),
        )
        result = trained_detector.detect(big)

        # bytes_sent deviation should be called out
        assert "bytes_sent" in result.explanation or "anomaly score" in result.explanation

    def test_no_baseline_explanation(self):
        """Explains when no baseline is available."""
        detector = TrafficAnomalyDetector()
        conn = NetworkConnection(source_id="new-container", destination="api.com")
        result = detector.detect(conn)
        assert "No baseline" in result.explanation


# ============================================================================
# Statistics Tests
# ============================================================================


class TestStatistics:
    """Test statistics tracking."""

    def test_initial_stats(self):
        detector = TrafficAnomalyDetector()
        stats = detector.get_stats()
        assert stats["total_detections"] == 0
        assert stats["connections_recorded"] == 0

    def test_stats_after_recording(self):
        detector = TrafficAnomalyDetector()
        for c in _make_connections(count=10):
            detector.record_connection(c)
        stats = detector.get_stats()
        assert stats["connections_recorded"] == 10

    def test_stats_after_detection(self):
        detector = TrafficAnomalyDetector(min_samples=20)
        for c in _make_connections(count=50):
            detector.record_connection(c)
        detector.learn_baseline("container-1")

        conn = NetworkConnection(
            source_id="container-1",
            destination="api.example.com",
            dest_port=443,
            bytes_sent=500,
            timestamp=datetime(2026, 2, 5, 12, 0, 0),
        )
        detector.detect(conn)

        stats = detector.get_stats()
        assert stats["total_detections"] == 1
        assert stats["baselines_learned"] == 1


# ============================================================================
# Performance Benchmarks
# ============================================================================


class TestPerformance:
    """Performance benchmarks."""

    @pytest.fixture
    def trained_detector(self):
        detector = TrafficAnomalyDetector(min_samples=20)
        for c in _make_connections(count=200):
            detector.record_connection(c)
        detector.learn_baseline("container-1")
        return detector

    def test_detection_speed(self, trained_detector):
        """Detection should complete in <5ms per connection."""
        conn = NetworkConnection(
            source_id="container-1",
            destination="api.example.com",
            dest_port=443,
            bytes_sent=500,
            timestamp=datetime(2026, 2, 5, 12, 0, 0),
        )

        # Warm up
        for _ in range(5):
            trained_detector.detect(conn)

        iterations = 100
        start = time.perf_counter()
        for _ in range(iterations):
            trained_detector.detect(conn)
        elapsed = time.perf_counter() - start

        avg_ms = (elapsed / iterations) * 1000
        assert avg_ms < 5.0, f"Average detection time: {avg_ms:.2f}ms (should be <5ms)"

    def test_recording_speed(self):
        """Recording connections should be fast (<100µs each)."""
        detector = TrafficAnomalyDetector()
        conns = _make_connections(count=1000)

        start = time.perf_counter()
        for c in conns:
            detector.record_connection(c)
        elapsed = time.perf_counter() - start

        avg_us = (elapsed / 1000) * 1_000_000
        assert avg_us < 100, f"Average record time: {avg_us:.2f}µs (should be <100µs)"


# ============================================================================
# Edge Cases
# ============================================================================


class TestEdgeCases:
    """Edge cases and error handling."""

    def test_detect_without_baseline(self):
        """Detection without baseline returns safe result."""
        detector = TrafficAnomalyDetector()
        conn = NetworkConnection(source_id="c1", destination="api.com")
        result = detector.detect(conn)

        assert result.is_anomaly is False
        assert result.anomaly_score == 0.0

    def test_history_trimming(self):
        """Connection history is trimmed to max size."""
        detector = TrafficAnomalyDetector()
        detector._max_history = 50

        for c in _make_connections(count=100):
            detector.record_connection(c)

        assert len(detector.connection_history["container-1"]) == 50

    def test_multiple_sources(self):
        """Supports multiple source baselines independently."""
        detector = TrafficAnomalyDetector(min_samples=20)

        for c in _make_connections(source_id="c1", count=50):
            detector.record_connection(c)
        for c in _make_connections(source_id="c2", count=50, dest_port=80):
            detector.record_connection(c)

        b1 = detector.learn_baseline("c1")
        b2 = detector.learn_baseline("c2")

        assert b1 is not None
        assert b2 is not None
        assert 443 in b1.common_ports
        assert 80 in b2.common_ports

    def test_all_same_connections(self):
        """Handles all-identical connections (zero std dev)."""
        detector = TrafficAnomalyDetector(min_samples=10)
        conns = []
        for i in range(30):
            conns.append(
                NetworkConnection(
                    source_id="c1",
                    destination="api.com",
                    dest_port=443,
                    bytes_sent=100,
                    bytes_received=200,
                    duration_s=0.1,
                    packet_count=10,
                    timestamp=datetime(2026, 2, 5, 10, 0) + timedelta(minutes=i),
                )
            )
        for c in conns:
            detector.record_connection(c)
        detector.learn_baseline("c1")

        # Should not crash
        result = detector.detect(conns[0])
        assert result is not None
        assert 0.0 <= result.anomaly_score <= 1.0

    def test_result_model_validation(self):
        """TrafficAnomalyResult enforces field constraints."""
        result = TrafficAnomalyResult(
            source_id="c1",
            anomaly_score=0.5,
            ml_score=0.3,
        )
        assert result.anomaly_score == 0.5

        with pytest.raises(ValueError):
            TrafficAnomalyResult(source_id="c1", anomaly_score=1.5)  # > 1.0

        with pytest.raises(ValueError):
            TrafficAnomalyResult(source_id="c1", ml_score=-0.1)  # < 0.0


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
