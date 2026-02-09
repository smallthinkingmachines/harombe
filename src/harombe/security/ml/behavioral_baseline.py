"""Behavioral baseline learning for agent activity."""

import logging
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any

import numpy as np

from .models import BehavioralBaseline, BehavioralPattern

logger = logging.getLogger(__name__)


class BaselineLearner:
    """Learns and maintains behavioral baselines for agents."""

    def __init__(self, window_days: int = 30, min_samples: int = 100):
        """Initialize baseline learner.

        Args:
            window_days: Number of days to use for baseline calculation
            min_samples: Minimum samples needed to establish baseline
        """
        self.window_days = window_days
        self.min_samples = min_samples
        self.baselines: dict[str, BehavioralBaseline] = {}
        self.event_history: dict[str, list[dict[str, Any]]] = defaultdict(list)

    def record_event(
        self,
        agent_id: str,
        event: dict[str, Any],
    ) -> None:
        """Record an event for baseline learning.

        Args:
            agent_id: Agent identifier
            event: Event data including timestamp, type, etc.
        """
        self.event_history[agent_id].append(event)

        # Cleanup old events
        cutoff = datetime.now() - timedelta(days=self.window_days)
        self.event_history[agent_id] = [
            e for e in self.event_history[agent_id] if e.get("timestamp", datetime.now()) > cutoff
        ]

    def compute_baseline(self, agent_id: str) -> BehavioralBaseline | None:
        """Compute behavioral baseline for an agent.

        Args:
            agent_id: Agent identifier

        Returns:
            Behavioral baseline or None if insufficient data
        """
        events = self.event_history.get(agent_id, [])
        if len(events) < self.min_samples:
            logger.info(f"Insufficient events for {agent_id}: {len(events)}/{self.min_samples}")
            return None

        # Extract metrics
        timestamps = [e.get("timestamp", datetime.now()) for e in events]
        event_types = [e.get("event_type", "") for e in events]
        resource_counts = [e.get("resource_count", 0) for e in events]
        durations = [e.get("duration_ms", 0) for e in events]

        # Compute temporal patterns
        hourly_distribution = self._compute_hourly_distribution(timestamps)
        daily_distribution = self._compute_daily_distribution(timestamps)

        # Compute resource patterns
        avg_resources = np.mean(resource_counts) if resource_counts else 0.0
        std_resources = np.std(resource_counts) if resource_counts else 0.0

        # Compute event type distribution
        event_type_freq = defaultdict(int)
        for et in event_types:
            event_type_freq[et] += 1
        total_events = len(event_types)
        event_type_distribution = {
            et: count / total_events for et, count in event_type_freq.items()
        }

        # Compute duration statistics
        avg_duration = np.mean(durations) if durations else 0.0
        std_duration = np.std(durations) if durations else 0.0

        # Compute rate statistics
        if len(timestamps) > 1:
            time_diffs = [
                (timestamps[i + 1] - timestamps[i]).total_seconds()
                for i in range(len(timestamps) - 1)
            ]
            avg_rate = 1.0 / np.mean(time_diffs) if time_diffs else 0.0
        else:
            avg_rate = 0.0

        # Create behavioral pattern
        pattern = BehavioralPattern(
            hourly_distribution=hourly_distribution,
            daily_distribution=daily_distribution,
            avg_resources_per_event=avg_resources,
            std_resources_per_event=std_resources,
            common_event_types=event_type_distribution,
            avg_event_duration_ms=avg_duration,
            std_event_duration_ms=std_duration,
            avg_events_per_hour=avg_rate * 3600,
        )

        baseline = BehavioralBaseline(
            agent_id=agent_id,
            learned_at=datetime.now(),
            event_count=len(events),
            time_window_days=self.window_days,
            pattern=pattern,
        )

        self.baselines[agent_id] = baseline
        return baseline

    def get_baseline(self, agent_id: str) -> BehavioralBaseline | None:
        """Get existing baseline or compute new one.

        Args:
            agent_id: Agent identifier

        Returns:
            Behavioral baseline or None
        """
        # Return existing if recent enough
        if agent_id in self.baselines:
            baseline = self.baselines[agent_id]
            if (datetime.now() - baseline.learned_at).days < self.window_days:
                return baseline

        # Compute new baseline
        return self.compute_baseline(agent_id)

    def _compute_hourly_distribution(self, timestamps: list[datetime]) -> list[float]:
        """Compute distribution of events across hours of day.

        Args:
            timestamps: Event timestamps

        Returns:
            24-element list with probability for each hour
        """
        hourly_counts = [0] * 24
        for ts in timestamps:
            hourly_counts[ts.hour] += 1

        total = sum(hourly_counts)
        if total == 0:
            return [1.0 / 24] * 24

        return [count / total for count in hourly_counts]

    def _compute_daily_distribution(self, timestamps: list[datetime]) -> list[float]:
        """Compute distribution of events across days of week.

        Args:
            timestamps: Event timestamps

        Returns:
            7-element list with probability for each day (0=Monday)
        """
        daily_counts = [0] * 7
        for ts in timestamps:
            daily_counts[ts.weekday()] += 1

        total = sum(daily_counts)
        if total == 0:
            return [1.0 / 7] * 7

        return [count / total for count in daily_counts]

    def detect_anomalies(
        self,
        agent_id: str,
        current_event: dict[str, Any],
    ) -> dict[str, float]:
        """Detect anomalies compared to baseline.

        Args:
            agent_id: Agent identifier
            current_event: Current event to check

        Returns:
            Dictionary of anomaly scores by feature
        """
        baseline = self.get_baseline(agent_id)
        if not baseline:
            return {}

        anomaly_scores = {}

        # Check temporal anomaly
        timestamp = current_event.get("timestamp", datetime.now())
        hour_prob = baseline.pattern.hourly_distribution[timestamp.hour]
        day_prob = baseline.pattern.daily_distribution[timestamp.weekday()]
        temporal_anomaly = 1.0 - (hour_prob * day_prob)
        anomaly_scores["temporal"] = temporal_anomaly

        # Check resource anomaly
        resource_count = current_event.get("resource_count", 0)
        if baseline.pattern.std_resources_per_event > 0:
            resource_z_score = abs(
                (resource_count - baseline.pattern.avg_resources_per_event)
                / baseline.pattern.std_resources_per_event
            )
            resource_anomaly = min(1.0, resource_z_score / 3.0)  # 3 sigma = 1.0
            anomaly_scores["resource"] = resource_anomaly

        # Check event type anomaly
        event_type = current_event.get("event_type", "")
        type_prob = baseline.pattern.common_event_types.get(event_type, 0.0)
        type_anomaly = 1.0 - type_prob
        anomaly_scores["event_type"] = type_anomaly

        # Check duration anomaly
        duration = current_event.get("duration_ms", 0)
        if baseline.pattern.std_event_duration_ms > 0:
            duration_z_score = abs(
                (duration - baseline.pattern.avg_event_duration_ms)
                / baseline.pattern.std_event_duration_ms
            )
            duration_anomaly = min(1.0, duration_z_score / 3.0)
            anomaly_scores["duration"] = duration_anomaly

        return anomaly_scores

    def update_from_feedback(
        self,
        agent_id: str,
        event: dict[str, Any],
        is_anomaly: bool,
    ) -> None:
        """Update baseline based on feedback.

        Args:
            agent_id: Agent identifier
            event: Event data
            is_anomaly: Whether event was confirmed as anomaly
        """
        if not is_anomaly:
            # If confirmed as normal, add to training data
            self.record_event(agent_id, event)
            # Recompute baseline periodically
            if len(self.event_history[agent_id]) % 100 == 0:
                self.compute_baseline(agent_id)
