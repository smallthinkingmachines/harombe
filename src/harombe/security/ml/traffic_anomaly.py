"""Traffic anomaly detection for identifying unusual network traffic patterns.

This module provides traffic-level anomaly detection that learns normal traffic
baselines per source (container/agent) and detects deviations using a combination
of statistical analysis and ML-based detection.

Features:
- Per-source traffic baseline learning
- Statistical deviation detection (Z-score)
- ML-based detection (Isolation Forest)
- Temporal pattern analysis (hourly/daily)
- Rate anomaly detection (connections per minute)
- Destination diversity analysis
- Alert generation for anomalous traffic
- <5% false positive rate target

Example:
    >>> from harombe.security.ml.traffic_anomaly import TrafficAnomalyDetector
    >>>
    >>> detector = TrafficAnomalyDetector()
    >>>
    >>> # Record normal connections for baseline
    >>> for conn in normal_connections:
    ...     detector.record_connection(conn)
    >>>
    >>> # Learn baseline
    >>> detector.learn_baseline("container-1")
    >>>
    >>> # Detect anomalies in new connection
    >>> result = detector.detect(new_connection)
    >>> if result.is_anomaly:
    ...     print(f"Anomaly: {result.explanation}")
"""

import logging
import time
from collections import defaultdict
from datetime import UTC, datetime
from typing import Any

import numpy as np
from pydantic import BaseModel, Field
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from .models import ThreatLevel

logger = logging.getLogger(__name__)


class TrafficFeatures(BaseModel):
    """Features extracted from a network connection for anomaly detection.

    Attributes:
        bytes_sent: Total bytes sent in connection
        bytes_received: Total bytes received
        duration_s: Connection duration in seconds
        packet_count: Number of packets in connection
        dest_port: Destination port
        hour_of_day: Hour when connection started (0-23)
        day_of_week: Day when connection started (0=Monday)
        is_weekend: Whether connection was on weekend
    """

    bytes_sent: int = 0
    bytes_received: int = 0
    duration_s: float = 0.0
    packet_count: int = 0
    dest_port: int = 0
    hour_of_day: int = Field(default=0, ge=0, le=23)
    day_of_week: int = Field(default=0, ge=0, le=6)
    is_weekend: bool = False

    def to_array(self) -> list[float]:
        """Convert to flat array for ML models."""
        return [
            float(self.bytes_sent),
            float(self.bytes_received),
            self.duration_s,
            float(self.packet_count),
            float(self.dest_port),
            float(self.hour_of_day),
            float(self.day_of_week),
            float(self.is_weekend),
        ]

    @classmethod
    def feature_names(cls) -> list[str]:
        """Feature names for model interpretation."""
        return [
            "bytes_sent",
            "bytes_received",
            "duration_s",
            "packet_count",
            "dest_port",
            "hour_of_day",
            "day_of_week",
            "is_weekend",
        ]


class TrafficBaseline(BaseModel):
    """Learned traffic baseline for a source.

    Attributes:
        source_id: Container or agent identifier
        learned_at: When baseline was computed
        connection_count: Number of connections used for baseline
        avg_bytes_sent: Mean bytes sent per connection
        std_bytes_sent: Standard deviation of bytes sent
        avg_bytes_received: Mean bytes received per connection
        std_bytes_received: Standard deviation of bytes received
        avg_duration_s: Mean connection duration
        std_duration_s: Standard deviation of connection duration
        avg_packet_count: Mean packets per connection
        std_packet_count: Standard deviation of packet count
        common_ports: Port -> frequency mapping
        hourly_distribution: 24-element distribution (probability per hour)
        daily_distribution: 7-element distribution (probability per day)
        avg_connections_per_minute: Mean connection rate
        avg_unique_destinations: Mean unique destinations per hour
    """

    source_id: str
    learned_at: datetime
    connection_count: int
    avg_bytes_sent: float = 0.0
    std_bytes_sent: float = 0.0
    avg_bytes_received: float = 0.0
    std_bytes_received: float = 0.0
    avg_duration_s: float = 0.0
    std_duration_s: float = 0.0
    avg_packet_count: float = 0.0
    std_packet_count: float = 0.0
    common_ports: dict[int, float] = Field(default_factory=dict)
    hourly_distribution: list[float] = Field(default_factory=lambda: [1.0 / 24] * 24)
    daily_distribution: list[float] = Field(default_factory=lambda: [1.0 / 7] * 7)
    avg_connections_per_minute: float = 0.0
    avg_unique_destinations: float = 0.0


class TrafficAnomalyResult(BaseModel):
    """Result of traffic anomaly detection.

    Attributes:
        source_id: Container or agent identifier
        timestamp: When detection was performed
        is_anomaly: Whether traffic is anomalous
        anomaly_score: Overall anomaly score (0-1, higher = more anomalous)
        threat_level: Severity classification
        deviation_scores: Per-feature deviation scores
        ml_score: ML model anomaly score (0-1)
        explanation: Human-readable explanation
        duration_ms: Time taken for detection
    """

    source_id: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    is_anomaly: bool = False
    anomaly_score: float = Field(default=0.0, ge=0.0, le=1.0)
    threat_level: ThreatLevel = ThreatLevel.NONE
    deviation_scores: dict[str, float] = Field(default_factory=dict)
    ml_score: float = Field(default=0.0, ge=0.0, le=1.0)
    explanation: str | None = None
    duration_ms: float | None = None


class NetworkConnection(BaseModel):
    """Represents a completed network connection for analysis.

    Attributes:
        source_id: Container or agent identifier
        destination: Destination domain or IP
        dest_port: Destination port
        bytes_sent: Total bytes sent
        bytes_received: Total bytes received
        duration_s: Connection duration in seconds
        packet_count: Number of packets
        timestamp: When connection started
        allowed: Whether connection was allowed by egress filter
        metadata: Additional metadata
    """

    source_id: str
    destination: str
    dest_port: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    duration_s: float = 0.0
    packet_count: int = 1
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    allowed: bool = True
    metadata: dict[str, Any] = Field(default_factory=dict)


class TrafficAnomalyDetector:
    """Detect anomalous network traffic using statistical and ML methods.

    Maintains per-source baselines of normal traffic and detects deviations.
    Combines statistical Z-score analysis with Isolation Forest ML detection.

    Example:
        >>> detector = TrafficAnomalyDetector()
        >>> for conn in connections:
        ...     detector.record_connection(conn)
        >>> detector.learn_baseline("my-container")
        >>> result = detector.detect(new_connection)
    """

    def __init__(
        self,
        min_samples: int = 50,
        contamination: float = 0.05,
        z_score_threshold: float = 3.0,
        anomaly_threshold: float = 0.7,
    ):
        """Initialize traffic anomaly detector.

        Args:
            min_samples: Minimum connections needed to build a baseline
            contamination: Expected proportion of anomalies for Isolation Forest
            z_score_threshold: Z-score threshold for statistical anomaly (sigma)
            anomaly_threshold: Combined score threshold for flagging anomaly (0-1)
        """
        self.min_samples = min_samples
        self.contamination = contamination
        self.z_score_threshold = z_score_threshold
        self.anomaly_threshold = anomaly_threshold

        # Per-source state
        self.connection_history: dict[str, list[NetworkConnection]] = defaultdict(list)
        self.baselines: dict[str, TrafficBaseline] = {}
        self.models: dict[str, IsolationForest] = {}
        self.scalers: dict[str, StandardScaler] = {}

        # History size limit
        self._max_history = 10000

        # Statistics
        self.stats: dict[str, int] = {
            "total_detections": 0,
            "anomalies_detected": 0,
            "connections_recorded": 0,
            "baselines_learned": 0,
        }

    def record_connection(self, connection: NetworkConnection) -> None:
        """Record a network connection for baseline learning.

        Args:
            connection: Completed network connection
        """
        source = connection.source_id
        self.connection_history[source].append(connection)
        self.stats["connections_recorded"] += 1

        # Trim history
        if len(self.connection_history[source]) > self._max_history:
            self.connection_history[source] = self.connection_history[source][-self._max_history :]

    def learn_baseline(self, source_id: str) -> TrafficBaseline | None:
        """Learn traffic baseline for a source.

        Args:
            source_id: Container or agent identifier

        Returns:
            Learned baseline or None if insufficient data
        """
        connections = self.connection_history.get(source_id, [])
        if len(connections) < self.min_samples:
            logger.info(
                f"Insufficient data for {source_id}: " f"{len(connections)}/{self.min_samples}"
            )
            return None

        # Extract numeric arrays
        bytes_sent = [c.bytes_sent for c in connections]
        bytes_received = [c.bytes_received for c in connections]
        durations = [c.duration_s for c in connections]
        packet_counts = [c.packet_count for c in connections]

        # Port distribution
        port_counts: dict[int, int] = defaultdict(int)
        for c in connections:
            port_counts[c.dest_port] += 1
        total = len(connections)
        common_ports = {port: count / total for port, count in port_counts.items()}

        # Temporal distributions
        hourly = [0] * 24
        daily = [0] * 7
        for c in connections:
            hourly[c.timestamp.hour] += 1
            daily[c.timestamp.weekday()] += 1
        hourly_dist = [h / total for h in hourly] if total else [1.0 / 24] * 24
        daily_dist = [d / total for d in daily] if total else [1.0 / 7] * 7

        # Rate: connections per minute
        if len(connections) >= 2:
            timestamps_sorted = sorted(c.timestamp for c in connections)
            span_seconds = (timestamps_sorted[-1] - timestamps_sorted[0]).total_seconds()
            rate = (total / (span_seconds / 60.0)) if span_seconds > 0 else 0.0
        else:
            rate = 0.0

        # Unique destinations per hour (approximate)
        destinations: set[str] = set()
        for c in connections:
            destinations.add(c.destination)
        hours_span = max(1.0, (span_seconds / 3600.0) if len(connections) >= 2 else 1.0)
        avg_unique_dest = len(destinations) / hours_span

        baseline = TrafficBaseline(
            source_id=source_id,
            learned_at=datetime.now(UTC).replace(tzinfo=None),
            connection_count=total,
            avg_bytes_sent=float(np.mean(bytes_sent)),
            std_bytes_sent=float(np.std(bytes_sent)),
            avg_bytes_received=float(np.mean(bytes_received)),
            std_bytes_received=float(np.std(bytes_received)),
            avg_duration_s=float(np.mean(durations)),
            std_duration_s=float(np.std(durations)),
            avg_packet_count=float(np.mean(packet_counts)),
            std_packet_count=float(np.std(packet_counts)),
            common_ports=common_ports,
            hourly_distribution=hourly_dist,
            daily_distribution=daily_dist,
            avg_connections_per_minute=rate,
            avg_unique_destinations=avg_unique_dest,
        )

        self.baselines[source_id] = baseline
        self.stats["baselines_learned"] += 1

        # Train ML model
        self._train_model(source_id, connections)

        logger.info(f"Learned traffic baseline for {source_id} " f"from {total} connections")
        return baseline

    def _train_model(self, source_id: str, connections: list[NetworkConnection]) -> None:
        """Train Isolation Forest model for a source.

        Args:
            source_id: Source identifier
            connections: Training connections
        """
        features_list = [self._extract_features(c).to_array() for c in connections]
        features_array = np.array(features_list)

        scaler = StandardScaler()
        features_scaled = scaler.fit_transform(features_array)

        model = IsolationForest(
            contamination=self.contamination,
            random_state=42,
            n_estimators=100,
        )
        model.fit(features_scaled)

        self.models[source_id] = model
        self.scalers[source_id] = scaler

    def detect(self, connection: NetworkConnection) -> TrafficAnomalyResult:
        """Detect if a connection is anomalous.

        Args:
            connection: Connection to analyze

        Returns:
            Anomaly detection result
        """
        start = time.perf_counter()
        self.stats["total_detections"] += 1
        source = connection.source_id

        baseline = self.baselines.get(source)
        if not baseline:
            duration_ms = (time.perf_counter() - start) * 1000
            return TrafficAnomalyResult(
                source_id=source,
                is_anomaly=False,
                anomaly_score=0.0,
                threat_level=ThreatLevel.NONE,
                explanation="No baseline available",
                duration_ms=duration_ms,
            )

        # Statistical deviation detection
        deviation_scores = self._compute_deviations(connection, baseline)

        # ML-based detection
        ml_score = self._ml_detect(connection, source)

        # Combine scores: 60% statistical, 40% ML
        stat_score = float(np.mean(list(deviation_scores.values()))) if deviation_scores else 0.0
        combined_score = float(min(1.0, 0.6 * stat_score + 0.4 * ml_score))

        is_anomaly = combined_score > self.anomaly_threshold

        # Determine threat level
        if not is_anomaly:
            threat_level = ThreatLevel.NONE
        elif combined_score < 0.8:
            threat_level = ThreatLevel.LOW
        elif combined_score < 0.9:
            threat_level = ThreatLevel.MEDIUM
        elif combined_score < 0.95:
            threat_level = ThreatLevel.HIGH
        else:
            threat_level = ThreatLevel.CRITICAL

        if is_anomaly:
            self.stats["anomalies_detected"] += 1

        # Generate explanation
        explanation = self._generate_explanation(
            connection, combined_score, deviation_scores, ml_score
        )

        duration_ms = (time.perf_counter() - start) * 1000

        return TrafficAnomalyResult(
            source_id=source,
            is_anomaly=is_anomaly,
            anomaly_score=combined_score,
            threat_level=threat_level,
            deviation_scores=deviation_scores,
            ml_score=ml_score,
            explanation=explanation,
            duration_ms=duration_ms,
        )

    def _extract_features(self, connection: NetworkConnection) -> TrafficFeatures:
        """Extract features from a connection.

        Args:
            connection: Network connection

        Returns:
            Extracted traffic features
        """
        return TrafficFeatures(
            bytes_sent=connection.bytes_sent,
            bytes_received=connection.bytes_received,
            duration_s=connection.duration_s,
            packet_count=connection.packet_count,
            dest_port=connection.dest_port,
            hour_of_day=connection.timestamp.hour,
            day_of_week=connection.timestamp.weekday(),
            is_weekend=connection.timestamp.weekday() >= 5,
        )

    def _compute_deviations(
        self, connection: NetworkConnection, baseline: TrafficBaseline
    ) -> dict[str, float]:
        """Compute statistical deviation scores for a connection.

        Args:
            connection: Connection to analyze
            baseline: Learned traffic baseline

        Returns:
            Feature name -> deviation score (0-1, higher = more anomalous)
        """
        scores: dict[str, float] = {}

        # Bytes sent deviation
        if baseline.std_bytes_sent > 0:
            z = abs(connection.bytes_sent - baseline.avg_bytes_sent) / baseline.std_bytes_sent
            scores["bytes_sent"] = min(1.0, z / self.z_score_threshold)

        # Bytes received deviation
        if baseline.std_bytes_received > 0:
            z = (
                abs(connection.bytes_received - baseline.avg_bytes_received)
                / baseline.std_bytes_received
            )
            scores["bytes_received"] = min(1.0, z / self.z_score_threshold)

        # Duration deviation
        if baseline.std_duration_s > 0:
            z = abs(connection.duration_s - baseline.avg_duration_s) / baseline.std_duration_s
            scores["duration"] = min(1.0, z / self.z_score_threshold)

        # Packet count deviation
        if baseline.std_packet_count > 0:
            z = abs(connection.packet_count - baseline.avg_packet_count) / baseline.std_packet_count
            scores["packet_count"] = min(1.0, z / self.z_score_threshold)

        # Port anomaly: how common is this port?
        port_freq = baseline.common_ports.get(connection.dest_port, 0.0)
        scores["port"] = 1.0 - port_freq

        # Temporal anomaly
        hour_prob = baseline.hourly_distribution[connection.timestamp.hour]
        day_prob = baseline.daily_distribution[connection.timestamp.weekday()]
        # Avoid log(0) by clamping
        temporal = 1.0 - max(hour_prob, 1e-6) * max(day_prob, 1e-6)
        scores["temporal"] = min(1.0, temporal)

        return scores

    def _ml_detect(self, connection: NetworkConnection, source_id: str) -> float:
        """Run ML-based anomaly detection.

        Args:
            connection: Connection to analyze
            source_id: Source identifier

        Returns:
            ML anomaly score (0-1, higher = more anomalous)
        """
        if source_id not in self.models:
            return 0.0

        features = self._extract_features(connection)
        features_array = np.array([features.to_array()])
        features_scaled = self.scalers[source_id].transform(features_array)

        score_samples = self.models[source_id].score_samples(features_scaled)[0]

        # Convert to 0-1 range (higher = more anomalous)
        return float(max(0.0, min(1.0, -score_samples)))

    def _generate_explanation(
        self,
        connection: NetworkConnection,
        score: float,
        deviations: dict[str, float],
        ml_score: float,
    ) -> str:
        """Generate human-readable explanation.

        Args:
            connection: Analyzed connection
            score: Combined anomaly score
            deviations: Per-feature deviation scores
            ml_score: ML model score

        Returns:
            Explanation string
        """
        if not deviations:
            return f"Traffic anomaly score {score:.2f}"

        # Find top contributing factors
        top_factors = sorted(deviations.items(), key=lambda x: x[1], reverse=True)[:3]

        parts = []
        for name, dev_score in top_factors:
            if dev_score > 0.5:
                parts.append(f"{name}={dev_score:.2f}")

        if not parts:
            return f"Traffic anomaly score {score:.2f}: within normal range"

        factors_str = ", ".join(parts)
        return f"Traffic anomaly score {score:.2f}: high deviation in {factors_str}"

    def get_baseline(self, source_id: str) -> TrafficBaseline | None:
        """Get learned baseline for a source.

        Args:
            source_id: Source identifier

        Returns:
            Traffic baseline or None if not learned
        """
        return self.baselines.get(source_id)

    def get_stats(self) -> dict[str, int]:
        """Get detection statistics.

        Returns:
            Dictionary with operation counts
        """
        return self.stats.copy()
