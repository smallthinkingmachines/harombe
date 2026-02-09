# Machine Learning Security Module

ML-powered threat detection and behavioral analysis for Harombe agents.

## Quick Start

### Anomaly Detection

```python
from harombe.security.ml import AnomalyDetector
from datetime import datetime

# Initialize detector
detector = AnomalyDetector()

# Train on historical events
training_data = [
    {
        "timestamp": datetime.now(),
        "event_type": "tool_call",
        "resource_count": 3,
        "duration_ms": 200,
        "success": True
    },
    # ... more events
]
detector.train("agent-123", training_data)

# Detect anomalies in new events
result = detector.detect("agent-123", {
    "timestamp": datetime.now(),
    "event_type": "suspicious_operation",
    "resource_count": 50,
    "duration_ms": 5000,
    "success": False
})

print(f"Anomaly: {result.is_anomaly}")
print(f"Score: {result.anomaly_score:.2f}")
print(f"Threat: {result.threat_level}")
print(f"Reason: {result.explanation}")
```

### Behavioral Baseline

```python
from harombe.security.ml import BaselineLearner

# Initialize learner
learner = BaselineLearner(window_days=30, min_samples=100)

# Record events
for event in historical_events:
    learner.record_event("agent-123", event)

# Compute baseline
baseline = learner.compute_baseline("agent-123")

# Detect anomalies
anomalies = learner.detect_anomalies("agent-123", new_event)
print(f"Anomaly scores: {anomalies}")
```

## Components

### AnomalyDetector

ML-based anomaly detection using Isolation Forest algorithm.

**Features:**

- Per-agent model training
- Real-time anomaly scoring (0-1)
- Threat level classification (NONE, LOW, MEDIUM, HIGH, CRITICAL)
- Model persistence (save/load)
- Feedback loop for continuous learning

### BaselineLearner

Statistical baseline learning for behavioral pattern recognition.

**Features:**

- Automatic event history tracking
- Temporal pattern analysis (hourly/daily)
- Resource usage profiling
- Event type frequency analysis
- Rolling window cleanup

## Models

### AnomalyResult

Detection result containing:

- `agent_id`: Agent identifier
- `timestamp`: Detection time
- `anomaly_score`: Score from 0-1 (higher = more anomalous)
- `is_anomaly`: Boolean flag
- `threat_level`: ThreatLevel enum
- `contributing_factors`: Dict of factor scores
- `explanation`: Human-readable explanation

### BehavioralBaseline

Learned behavioral profile containing:

- `agent_id`: Agent identifier
- `learned_at`: Training timestamp
- `event_count`: Number of training events
- `time_window_days`: Window size used
- `pattern`: BehavioralPattern object

## Configuration

### AnomalyDetector Parameters

- `model_dir`: Directory for model storage (default: `~/.harombe/models`)
- `contamination`: Expected anomaly rate (default: 0.05 = 5%)
- `threshold`: Anomaly score threshold (default: 0.7)

### BaselineLearner Parameters

- `window_days`: Rolling window size in days (default: 30)
- `min_samples`: Minimum events needed for baseline (default: 100)

## Integration

### With Audit Logger

```python
from harombe.security.audit_logger import AuditLogger
from harombe.security.ml import AnomalyDetector

logger = AuditLogger()
detector = AnomalyDetector()

# On tool call
event = logger.log_tool_call(...)
result = detector.detect(agent_id, event)

if result.is_anomaly and result.threat_level >= ThreatLevel.HIGH:
    logger.log_security_alert(
        level=result.threat_level,
        description=result.explanation
    )
```

### With Security Gateway

```python
from harombe.security.gateway import SecurityGateway
from harombe.security.ml import AnomalyDetector, ThreatLevel

gateway = SecurityGateway()
detector = AnomalyDetector()

async def enhanced_check(request):
    # Standard gateway checks
    decision = await gateway.check_request(request)

    # ML anomaly detection
    result = detector.detect(request.agent_id, request)

    if result.threat_level >= ThreatLevel.CRITICAL:
        return RequestDecision.DENY

    return decision
```

## Performance

### Training

- **Time**: 100-500ms for 100 events
- **Model Size**: 50-200KB per agent
- **Memory**: 10-50MB per trained model

### Detection

- **Latency**: <10ms per event
- **Throughput**: >100 detections/second
- **Scalability**: Per-agent models allow horizontal scaling

## Testing

Run tests:

```bash
# All ML tests
pytest tests/security/test_anomaly_detection.py -v

# Specific test class
pytest tests/security/test_anomaly_detection.py::TestAnomalyDetector -v

# Integration tests
pytest tests/security/test_anomaly_detection.py::TestAnomalyDetectionIntegration -v
```

Test coverage: **85%+**

## Dependencies

- `scikit-learn>=1.3`: ML models (Isolation Forest)
- `scipy>=1.11`: Statistical functions
- `joblib>=1.3`: Model persistence
- `numpy>=1.24`: Numerical operations

## Security Considerations

### Model Security

- Models stored in `~/.harombe/models` with restricted permissions
- Consider encrypting model files at rest
- Regular model retraining recommended

### Privacy

- Event data may contain sensitive information
- Implement data retention policies
- Consider anonymization for long-term storage

### Robustness

- Models vulnerable to adversarial evasion
- Use ensemble methods for increased robustness
- Monitor for concept drift over time

## Future Enhancements

- [ ] Threat intelligence integration
- [ ] Multi-agent correlation analysis
- [ ] Attack pattern recognition
- [ ] Automated threat mitigation
- [ ] Deep learning models (autoencoders, LSTM)
- [ ] Federated learning for privacy-preserving training

## See Also

- [Phase 5 Implementation Summary](../../../../docs/phase5_anomaly_detection_summary.md)
- [Security Architecture](../README.md)
- [Audit Logging](../audit_logger.py)
