# Task 5.4.4: Traffic Anomaly Detection

**Status**: Complete
**Date**: 2026-02-09

## Summary

Implemented traffic anomaly detection that learns per-source baselines of normal network traffic and detects deviations using a combination of statistical analysis (Z-score) and ML-based detection (Isolation Forest).

## Components

### TrafficAnomalyDetector (Main Class)

Orchestrates the full detection pipeline:

1. **Record connections** - Maintains rolling history per source
2. **Learn baseline** - Computes statistical baseline + trains ML model
3. **Detect anomalies** - Combines statistical + ML scoring (60/40 weight)

### TrafficBaseline

Learned per-source traffic profile:

| Metric                       | Description                                   |
| ---------------------------- | --------------------------------------------- |
| `avg_bytes_sent/received`    | Mean and std deviation of transfer sizes      |
| `avg_duration_s`             | Mean and std deviation of connection duration |
| `avg_packet_count`           | Mean and std deviation of packet counts       |
| `common_ports`               | Port frequency distribution                   |
| `hourly_distribution`        | 24-element hour-of-day distribution           |
| `daily_distribution`         | 7-element day-of-week distribution            |
| `avg_connections_per_minute` | Connection rate                               |
| `avg_unique_destinations`    | Destination diversity per hour                |

### Detection Methods

**Statistical (60% weight)**:

- Z-score deviation for bytes_sent, bytes_received, duration, packet_count
- Port frequency analysis (unknown port = high anomaly)
- Temporal anomaly (hour \* day probability)

**ML-based (40% weight)**:

- Per-source Isolation Forest model
- 8-feature vector (bytes, duration, packets, port, temporal)
- StandardScaler normalization
- `contamination=0.05` (5% expected anomaly rate)

### Threat Level Classification

| Score Range | Level    |
| ----------- | -------- |
| < threshold | NONE     |
| 0.7 - 0.8   | LOW      |
| 0.8 - 0.9   | MEDIUM   |
| 0.9 - 0.95  | HIGH     |
| > 0.95      | CRITICAL |

## Files

| File                                         | Description                              |
| -------------------------------------------- | ---------------------------------------- |
| `src/harombe/security/ml/traffic_anomaly.py` | Traffic anomaly detection implementation |
| `tests/security/test_traffic_anomaly.py`     | 44 tests (all passing)                   |

## Test Coverage

- **44 tests** across 10 test classes
- TrafficFeatures model (4)
- NetworkConnection model (3)
- Baseline learning (6)
- Anomaly detection (10)
- Statistical deviation (5)
- ML detection (3)
- Explanation generation (3)
- Statistics tracking (3)
- Performance benchmarks (2)
- Edge cases (5)

### Performance

- Detection: <5ms per connection (benchmark verified)
- Connection recording: <100µs each (benchmark verified)

## Architecture

```
NetworkConnection
    │
    ▼
TrafficAnomalyDetector
    │
    ├─► record_connection()     ── rolling history per source
    │
    ├─► learn_baseline()        ── statistical baseline + ML training
    │   ├── Compute mean/std for numeric features
    │   ├── Port frequency distribution
    │   ├── Temporal distributions (hourly/daily)
    │   └── Train Isolation Forest model
    │
    └─► detect()                ── combined scoring
        │
        ├─► _compute_deviations()   ── Z-score per feature (60%)
        │   ├── bytes_sent deviation
        │   ├── bytes_received deviation
        │   ├── duration deviation
        │   ├── packet_count deviation
        │   ├── port anomaly (frequency)
        │   └── temporal anomaly (hour × day)
        │
        ├─► _ml_detect()            ── Isolation Forest (40%)
        │   └── score_samples → normalize to 0-1
        │
        └─► Combined score → threat level → explanation
```

## Integration Points

- Reuses `ThreatLevel` from `harombe.security.ml.models`
- Follows same patterns as `AnomalyDetector` and `BaselineLearner`
- Exported via `harombe.security.ml.__init__.py`
- Can be composed with `NetworkMonitor` for real-time monitoring
- `NetworkConnection` model can be populated from `ConnectionAttempt` data

## Phase 5.4 Complete

With this task, all four Phase 5.4 (Network Security Enhancements) tasks are complete:

- 5.4.1: TLS Certificate Pinning
- 5.4.2: Deep Packet Inspection
- 5.4.3: Protocol-Aware Filtering
- 5.4.4: Traffic Anomaly Detection
