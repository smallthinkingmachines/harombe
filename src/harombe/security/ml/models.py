"""Data models for ML-based threat detection."""

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class ThreatLevel(StrEnum):
    """Threat severity levels."""

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SecurityEvent(BaseModel):
    """Security event for anomaly detection.

    Simplified representation of audit events focused on features
    relevant for anomaly detection.
    """

    event_id: str
    correlation_id: str
    timestamp: datetime
    event_type: str
    actor: str  # User/agent identifier
    tool_name: str | None = None
    action: str
    status: str  # "success", "error", "pending"
    duration_ms: int | None = None

    # Additional context for feature extraction
    destination_ip: str | None = None
    destination_domain: str | None = None
    file_path: str | None = None
    file_hash: str | None = None
    resource_usage: dict[str, float] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)


class FeatureVector(BaseModel):
    """Extracted features for ML models."""

    # Frequency features
    api_calls_per_hour: float = 0.0
    tool_invocations_per_hour: float = 0.0
    errors_per_hour: float = 0.0

    # Timing features
    avg_duration_ms: float = 0.0
    max_duration_ms: float = 0.0

    # Resource features
    avg_cpu_usage: float = 0.0
    avg_memory_mb: float = 0.0
    network_bytes_sent: float = 0.0

    # Behavioral features
    unique_tools_count: int = 0
    unique_destinations_count: int = 0
    file_operations_count: int = 0

    # Temporal features
    hour_of_day: int = 0
    day_of_week: int = 0
    is_weekend: bool = False

    def to_array(self) -> list[float]:
        """Convert to flat array for ML models."""
        return [
            self.api_calls_per_hour,
            self.tool_invocations_per_hour,
            self.errors_per_hour,
            self.avg_duration_ms,
            self.max_duration_ms,
            self.avg_cpu_usage,
            self.avg_memory_mb,
            self.network_bytes_sent,
            float(self.unique_tools_count),
            float(self.unique_destinations_count),
            float(self.file_operations_count),
            float(self.hour_of_day),
            float(self.day_of_week),
            float(self.is_weekend),
        ]

    @classmethod
    def feature_names(cls) -> list[str]:
        """Get feature names for model interpretation."""
        return [
            "api_calls_per_hour",
            "tool_invocations_per_hour",
            "errors_per_hour",
            "avg_duration_ms",
            "max_duration_ms",
            "avg_cpu_usage",
            "avg_memory_mb",
            "network_bytes_sent",
            "unique_tools_count",
            "unique_destinations_count",
            "file_operations_count",
            "hour_of_day",
            "day_of_week",
            "is_weekend",
        ]


class AnomalyResult(BaseModel):
    """Result of anomaly detection."""

    agent_id: str
    timestamp: datetime
    anomaly_score: float = Field(ge=0.0, le=1.0)
    is_anomaly: bool
    threat_level: ThreatLevel
    contributing_factors: dict[str, float] = Field(default_factory=dict)
    explanation: str | None = None


class BehavioralPattern(BaseModel):
    """Learned behavioral pattern for an agent."""

    hourly_distribution: list[float]  # 24 values, probability for each hour
    daily_distribution: list[float]  # 7 values, probability for each day
    avg_resources_per_event: float
    std_resources_per_event: float
    common_event_types: dict[str, float]  # Event type -> frequency
    avg_event_duration_ms: float
    std_event_duration_ms: float
    avg_events_per_hour: float


class BehavioralBaseline(BaseModel):
    """Behavioral baseline for an agent."""

    agent_id: str
    learned_at: datetime
    event_count: int
    time_window_days: int
    pattern: BehavioralPattern
