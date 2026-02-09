"""ML-based anomaly detection for security events."""

import logging
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from .models import AnomalyResult, ThreatLevel

logger = logging.getLogger(__name__)


class AnomalyDetector:
    """ML-based anomaly detection for agent behavior.

    Uses Isolation Forest for unsupervised anomaly detection.
    """

    def __init__(
        self,
        model_dir: Path | None = None,
        contamination: float = 0.05,
        threshold: float = 0.7,
    ):
        """Initialize anomaly detector.

        Args:
            model_dir: Directory to save/load models
            contamination: Expected proportion of anomalies (0.05 = 5%)
            threshold: Anomaly score threshold for flagging (0-1)
        """
        self.model_dir = model_dir or Path.home() / ".harombe" / "models"
        self.model_dir.mkdir(parents=True, exist_ok=True)

        self.contamination = contamination
        self.threshold = threshold

        # Per-agent models and data
        self.models: dict[str, IsolationForest] = {}
        self.scalers: dict[str, StandardScaler] = {}
        self.training_data: dict[str, list[dict[str, Any]]] = defaultdict(list)

        # Feature definitions
        self.feature_names = [
            "resource_count",
            "duration_ms",
            "hour_of_day",
            "day_of_week",
            "is_weekend",
            "event_type_encoded",
            "success",
        ]

        # Global scaler for new agents
        self.scaler = StandardScaler()

    def _extract_features(self, event: dict[str, Any]) -> np.ndarray:
        """Extract feature vector from event.

        Args:
            event: Event dictionary

        Returns:
            Feature vector as numpy array
        """
        timestamp = event.get("timestamp", datetime.now())

        # Event type encoding (simple hash-based encoding)
        event_type = event.get("event_type", "")
        event_type_encoded = float(hash(event_type) % 1000) / 1000.0

        features = [
            float(event.get("resource_count", 0)),
            float(event.get("duration_ms", 0)),
            float(timestamp.hour),
            float(timestamp.weekday()),
            float(timestamp.weekday() >= 5),  # is_weekend
            event_type_encoded,
            float(event.get("success", True)),
        ]

        return np.array(features)

    def train(self, agent_id: str, events: list[dict[str, Any]]) -> None:
        """Train anomaly detection model for an agent.

        Args:
            agent_id: Agent identifier
            events: List of training events
        """
        if len(events) < 10:
            logger.warning(f"Insufficient training data for {agent_id}: {len(events)}")
            return

        # Extract features
        feature_vectors = [self._extract_features(event) for event in events]
        features_array = np.array(feature_vectors)

        # Fit scaler
        scaler = StandardScaler()
        features_scaled = scaler.fit_transform(features_array)

        # Train model
        model = IsolationForest(
            contamination=self.contamination,
            random_state=42,
            n_estimators=100,
        )
        model.fit(features_scaled)

        # Store model and scaler
        self.models[agent_id] = model
        self.scalers[agent_id] = scaler
        self.training_data[agent_id] = events.copy()

        logger.info(f"Trained anomaly detector for {agent_id} with {len(events)} events")

    def detect(self, agent_id: str, event: dict[str, Any]) -> AnomalyResult:
        """Detect anomalies in an event.

        Args:
            agent_id: Agent identifier
            event: Event to analyze

        Returns:
            Anomaly detection result
        """
        timestamp = event.get("timestamp", datetime.now())

        # Check if model exists
        if agent_id not in self.models:
            logger.info(f"No model for {agent_id}, returning non-anomalous")
            return AnomalyResult(
                agent_id=agent_id,
                timestamp=timestamp,
                anomaly_score=0.0,
                is_anomaly=False,
                threat_level=ThreatLevel.NONE,
                contributing_factors={},
                explanation="No baseline model available",
            )

        # Extract features
        features = self._extract_features(event)
        features_array = features.reshape(1, -1)

        # Scale features
        features_scaled = self.scalers[agent_id].transform(features_array)

        # Get anomaly score
        model = self.models[agent_id]
        prediction = model.predict(features_scaled)[0]  # 1 for normal, -1 for anomaly
        score_samples = model.score_samples(features_scaled)[0]

        # Convert score to 0-1 range (higher = more anomalous)
        # score_samples is typically in range [-0.5, 0.5] for anomalies to [-0.1, 0.1] for normal
        anomaly_score = max(0.0, min(1.0, -score_samples))

        # Determine if anomalous
        is_anomaly = prediction == -1 or anomaly_score > self.threshold

        # Determine threat level
        if not is_anomaly:
            threat_level = ThreatLevel.NONE
        elif anomaly_score < 0.7:
            threat_level = ThreatLevel.LOW
        elif anomaly_score < 0.85:
            threat_level = ThreatLevel.MEDIUM
        elif anomaly_score < 0.95:
            threat_level = ThreatLevel.HIGH
        else:
            threat_level = ThreatLevel.CRITICAL

        # Analyze contributing factors
        contributing_factors = self._analyze_factors(event, features)

        # Generate explanation
        explanation = self._generate_explanation(event, anomaly_score, contributing_factors)

        return AnomalyResult(
            agent_id=agent_id,
            timestamp=timestamp,
            anomaly_score=anomaly_score,
            is_anomaly=is_anomaly,
            threat_level=threat_level,
            contributing_factors=contributing_factors,
            explanation=explanation,
        )

    def _analyze_factors(self, event: dict[str, Any], features: np.ndarray) -> dict[str, float]:
        """Analyze which factors contribute to anomaly.

        Args:
            event: Event data
            features: Feature vector

        Returns:
            Dictionary of factor names to contribution scores
        """
        factors = {}

        # Check each feature for unusual values
        resource_count = event.get("resource_count", 0)
        if resource_count > 20:
            factors["high_resource_usage"] = min(1.0, resource_count / 50.0)

        duration = event.get("duration_ms", 0)
        if duration > 2000:
            factors["long_duration"] = min(1.0, duration / 5000.0)

        timestamp = event.get("timestamp", datetime.now())
        if timestamp.hour < 6 or timestamp.hour > 22:
            factors["unusual_time"] = 0.8

        if timestamp.weekday() >= 5:
            factors["weekend_activity"] = 0.6

        event_type = event.get("event_type", "")
        if event_type in ["rare_event", "rare_operation", "extremely_rare_event"]:
            factors["rare_event_type"] = 0.9

        if not event.get("success", True):
            factors["failure"] = 0.7

        return factors

    def _generate_explanation(
        self,
        event: dict[str, Any],
        score: float,
        factors: dict[str, float],
    ) -> str:
        """Generate human-readable explanation.

        Args:
            event: Event data
            score: Anomaly score
            factors: Contributing factors

        Returns:
            Explanation string
        """
        if not factors:
            return f"Anomaly score {score:.2f}: Pattern differs from baseline"

        explanations = []
        if "high_resource_usage" in factors:
            count = event.get("resource_count", 0)
            explanations.append(f"High resource usage ({count})")

        if "long_duration" in factors:
            duration = event.get("duration_ms", 0)
            explanations.append(f"Long duration ({duration}ms)")

        if "unusual_time" in factors:
            timestamp = event.get("timestamp", datetime.now())
            explanations.append(f"Unusual time ({timestamp.hour}:00)")

        if "weekend_activity" in factors:
            explanations.append("Weekend activity")

        if "rare_event_type" in factors:
            event_type = event.get("event_type", "")
            explanations.append(f"Rare event type ({event_type})")

        if "failure" in factors:
            explanations.append("Operation failed")

        return f"Anomaly score {score:.2f}: {'; '.join(explanations)}"

    def save_model(self, agent_id: str) -> Path:
        """Save trained model to disk.

        Args:
            agent_id: Agent identifier

        Returns:
            Path to saved model
        """
        if agent_id not in self.models:
            raise ValueError(f"No model trained for {agent_id}")

        model_path = self.model_dir / f"{agent_id}_anomaly_model.pkl"
        scaler_path = self.model_dir / f"{agent_id}_scaler.pkl"

        joblib.dump(self.models[agent_id], model_path)
        joblib.dump(self.scalers[agent_id], scaler_path)

        logger.info(f"Saved model for {agent_id} to {model_path}")
        return model_path

    def load_model(self, agent_id: str) -> None:
        """Load trained model from disk.

        Args:
            agent_id: Agent identifier
        """
        model_path = self.model_dir / f"{agent_id}_anomaly_model.pkl"
        scaler_path = self.model_dir / f"{agent_id}_scaler.pkl"

        if not model_path.exists() or not scaler_path.exists():
            raise FileNotFoundError(f"No saved model found for {agent_id}")

        self.models[agent_id] = joblib.load(model_path)
        self.scalers[agent_id] = joblib.load(scaler_path)

        logger.info(f"Loaded model for {agent_id} from {model_path}")

    def update_from_feedback(
        self,
        agent_id: str,
        event: dict[str, Any],
        is_anomaly: bool,
    ) -> None:
        """Update model based on feedback.

        Args:
            agent_id: Agent identifier
            event: Event data
            is_anomaly: Whether event is confirmed anomaly
        """
        if not is_anomaly:
            # Add to training data if confirmed normal
            self.training_data[agent_id].append(event)
            logger.info(f"Added false positive to training data for {agent_id}")
