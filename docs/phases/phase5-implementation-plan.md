# Phase 5: Advanced Security & Intelligence

**Version**: 1.0
**Date**: 2026-02-09
**Status**: Planning
**Dependencies**: Phase 4 Complete

## Executive Summary

Phase 5 builds upon the solid security foundation established in Phase 4 by adding intelligence, automation, and advanced detection capabilities. This phase transforms Harombe from a secure-by-design system to an intelligent, adaptive security platform.

### Goals

1. **Intelligent Threat Detection**: ML-powered anomaly detection and behavioral analysis
2. **Adaptive HITL**: Risk scoring that learns from user behavior and trust patterns
3. **Automated Secret Management**: Zero-touch credential rotation with verification
4. **Advanced Network Security**: Protocol-aware filtering and deep inspection
5. **Enterprise Audit**: SIEM integration and automated compliance reporting

### Success Metrics

| Metric                       | Target | Measurement                  |
| ---------------------------- | ------ | ---------------------------- |
| Anomaly Detection Accuracy   | >95%   | True positive rate           |
| False Positive Rate          | <5%    | False alarms per 1000 events |
| HITL Approval Reduction      | 50%    | Auto-approved low-risk ops   |
| Secret Rotation Downtime     | 0ms    | Service availability         |
| Threat Detection Latency     | <100ms | Detection to alert time      |
| SIEM Integration Latency     | <1s    | Event to SIEM ingestion      |
| Compliance Report Generation | <5min  | Full report generation time  |

## Phase Overview

```
Phase 5: Advanced Security & Intelligence
│
├── 5.1: Advanced Threat Detection (Weeks 1-3)
│   ├── ML anomaly detection framework
│   ├── Behavioral baseline learning
│   ├── Real-time threat scoring
│   └── Threat intelligence integration
│
├── 5.2: Enhanced HITL (Weeks 2-4)
│   ├── Historical risk scoring
│   ├── User trust level system
│   ├── Automated low-risk approvals
│   └── Context-aware decision engine
│
├── 5.3: Secret Rotation Automation (Weeks 3-5)
│   ├── Automatic credential rotation
│   ├── Zero-downtime rotation
│   ├── Rotation verification tests
│   └── Emergency rotation triggers
│
├── 5.4: Network Security Enhancements (Weeks 4-6)
│   ├── TLS certificate pinning
│   ├── Deep packet inspection
│   ├── Protocol-aware filtering
│   └── Traffic anomaly detection
│
├── 5.5: Audit Enhancements (Weeks 5-7)
│   ├── SIEM integration (Splunk, ELK, etc.)
│   ├── Automated alert rules
│   ├── Compliance report automation
│   └── Real-time dashboards
│
└── 5.6: Integration & Testing (Week 8)
    ├── End-to-end integration tests
    ├── Performance benchmarks
    ├── Security validation
    └── Documentation
```

## Phase 5.1: Advanced Threat Detection

### Overview

Implement ML-powered anomaly detection to identify suspicious agent behavior patterns and potential security threats in real-time.

### Components

#### 1. Anomaly Detection Framework

**Purpose**: Detect deviations from normal agent behavior

**Implementation**:

```python
# harombe/security/ml/anomaly_detector.py
class AnomalyDetector:
    """ML-based anomaly detection for agent behavior."""

    def __init__(self, model_type: str = "isolation_forest"):
        self.model = self._load_model(model_type)
        self.baseline = BehaviorBaseline()
        self.threshold = 0.8  # Anomaly score threshold

    async def detect(self, event: SecurityEvent) -> AnomalyResult:
        """Detect if event is anomalous."""
        # Extract features
        features = self._extract_features(event)

        # Get anomaly score
        score = self.model.predict_proba([features])[0]

        # Compare to baseline
        is_anomalous = score > self.threshold

        return AnomalyResult(
            event=event,
            score=score,
            is_anomalous=is_anomalous,
            features=features,
        )
```

**Features to Track**:

- API call patterns (frequency, timing, endpoints)
- Resource usage (CPU, memory, network)
- Tool invocation sequences
- Network destinations
- File access patterns
- Execution durations
- Error rates

**ML Models to Consider**:

- Isolation Forest (unsupervised)
- One-Class SVM (outlier detection)
- Autoencoders (deep learning)
- LSTM (sequence anomalies)

#### 2. Behavioral Baseline Learning

**Purpose**: Learn normal behavior patterns for each agent/user

**Implementation**:

```python
# harombe/security/ml/baseline.py
class BehaviorBaseline:
    """Learn and maintain behavioral baselines."""

    def __init__(self, learning_window: int = 7 * 24 * 3600):
        self.learning_window = learning_window  # 7 days
        self.baselines: dict[str, UserBaseline] = {}

    async def learn(self, user_id: str, events: list[SecurityEvent]) -> None:
        """Learn baseline from historical events."""
        # Aggregate features
        features = self._aggregate_features(events)

        # Calculate statistics
        baseline = UserBaseline(
            mean_api_calls_per_hour=features.api_calls.mean(),
            std_api_calls_per_hour=features.api_calls.std(),
            common_tools=features.tools.most_common(10),
            common_destinations=features.destinations.most_common(20),
            typical_hours=features.active_hours.percentile(50),
        )

        self.baselines[user_id] = baseline

    def get_deviation(self, user_id: str, current: dict) -> float:
        """Calculate deviation from baseline."""
        baseline = self.baselines.get(user_id)
        if not baseline:
            return 0.0  # No baseline yet

        # Calculate z-score for key metrics
        deviations = []
        deviations.append(
            abs(current["api_calls"] - baseline.mean_api_calls_per_hour)
            / baseline.std_api_calls_per_hour
        )

        return np.mean(deviations)
```

#### 3. Real-Time Threat Scoring

**Purpose**: Score threats in real-time as events occur

**Implementation**:

```python
# harombe/security/ml/threat_scoring.py
class ThreatScorer:
    """Real-time threat scoring engine."""

    def __init__(self):
        self.anomaly_detector = AnomalyDetector()
        self.rule_engine = ThreatRuleEngine()
        self.threat_intel = ThreatIntelligence()

    async def score_event(self, event: SecurityEvent) -> ThreatScore:
        """Score threat level of an event."""
        scores = []

        # ML anomaly score (0-1)
        anomaly = await self.anomaly_detector.detect(event)
        scores.append(("anomaly", anomaly.score, 0.4))  # 40% weight

        # Rule-based score (0-1)
        rule_score = await self.rule_engine.evaluate(event)
        scores.append(("rules", rule_score, 0.3))  # 30% weight

        # Threat intel score (0-1)
        intel_score = await self.threat_intel.lookup(event)
        scores.append(("intel", intel_score, 0.3))  # 30% weight

        # Weighted average
        total_score = sum(score * weight for _, score, weight in scores)

        return ThreatScore(
            event=event,
            total=total_score,
            components={name: score for name, score, _ in scores},
            level=self._score_to_level(total_score),
        )

    def _score_to_level(self, score: float) -> ThreatLevel:
        if score >= 0.8:
            return ThreatLevel.CRITICAL
        elif score >= 0.6:
            return ThreatLevel.HIGH
        elif score >= 0.4:
            return ThreatLevel.MEDIUM
        else:
            return ThreatLevel.LOW
```

#### 4. Threat Intelligence Integration

**Purpose**: Integrate external threat intelligence feeds

**Implementation**:

```python
# harombe/security/ml/threat_intel.py
class ThreatIntelligence:
    """External threat intelligence integration."""

    def __init__(self):
        self.feeds = [
            ThreatFeed("abuseipdb", "https://api.abuseipdb.com/api/v2/"),
            ThreatFeed("virustotal", "https://www.virustotal.com/api/v3/"),
            ThreatFeed("alienvault", "https://otx.alienvault.com/api/v1/"),
        ]
        self.cache = ThreatCache(ttl=3600)  # 1 hour

    async def lookup(self, event: SecurityEvent) -> float:
        """Lookup threat indicators in feeds."""
        score = 0.0

        # Check IPs
        if event.destination_ip:
            ip_score = await self._lookup_ip(event.destination_ip)
            score = max(score, ip_score)

        # Check domains
        if event.destination_domain:
            domain_score = await self._lookup_domain(event.destination_domain)
            score = max(score, domain_score)

        # Check file hashes
        if event.file_hash:
            hash_score = await self._lookup_hash(event.file_hash)
            score = max(score, hash_score)

        return score
```

### Tasks

#### Task 5.1.1: Anomaly Detection Framework

**Duration**: 1 week

**Deliverables**:

- [ ] Implement `AnomalyDetector` class
- [ ] Integrate scikit-learn Isolation Forest
- [ ] Feature extraction pipeline
- [ ] Model training script
- [ ] Unit tests

**Acceptance Criteria**:

- Detects 95%+ of known anomalies
- False positive rate <5%
- Processing latency <50ms

#### Task 5.1.2: Behavioral Baseline Learning

**Duration**: 1 week

**Deliverables**:

- [ ] Implement `BehaviorBaseline` class
- [ ] Historical data aggregation
- [ ] Baseline calculation logic
- [ ] Baseline persistence (SQLite)
- [ ] Unit tests

**Acceptance Criteria**:

- Learns baseline from 7 days of data
- Updates baseline incrementally
- Handles new users gracefully

#### Task 5.1.3: Real-Time Threat Scoring

**Duration**: 5 days

**Deliverables**:

- [ ] Implement `ThreatScorer` class
- [ ] Weighted scoring algorithm
- [ ] Threat level classification
- [ ] Integration with audit logger
- [ ] Unit tests

**Acceptance Criteria**:

- Scores events in <100ms
- Combines ML + rules + intel
- Logs high/critical threats

#### Task 5.1.4: Threat Intelligence Integration

**Duration**: 1 week

**Deliverables**:

- [ ] Implement `ThreatIntelligence` class
- [ ] API clients for 3+ feeds
- [ ] Caching layer
- [ ] Rate limiting
- [ ] Unit tests

**Acceptance Criteria**:

- Integrates with AbuseIPDB, VirusTotal, AlienVault
- Caches results for 1 hour
- Handles API failures gracefully

## Phase 5.2: Enhanced HITL

### Overview

Enhance Human-in-the-Loop system with risk scoring based on historical behavior, user trust levels, and automated approvals for low-risk operations.

### Components

#### 1. Historical Risk Scoring

**Purpose**: Score risk based on historical operation outcomes

**Implementation**:

```python
# harombe/security/hitl/risk_scorer.py
class HistoricalRiskScorer:
    """Score risk based on historical data."""

    def __init__(self, audit_db: AuditDatabase):
        self.audit_db = audit_db
        self.risk_cache: dict[str, float] = {}

    async def score_operation(
        self, operation: Operation, context: dict
    ) -> RiskScore:
        """Score operation risk based on history."""
        # Get historical operations
        history = await self.audit_db.query_operations(
            tool_name=operation.tool_name,
            limit=100,
        )

        # Calculate metrics
        total = len(history)
        failures = sum(1 for op in history if op.result == "failure")
        denials = sum(1 for op in history if op.decision == "denied")
        incidents = sum(1 for op in history if op.flagged_incident)

        # Calculate risk factors
        failure_rate = failures / total if total > 0 else 0.5
        denial_rate = denials / total if total > 0 else 0.5
        incident_rate = incidents / total if total > 0 else 0.0

        # Weighted score
        risk_score = (
            failure_rate * 0.3 + denial_rate * 0.4 + incident_rate * 0.3
        )

        return RiskScore(
            score=risk_score,
            factors={
                "failure_rate": failure_rate,
                "denial_rate": denial_rate,
                "incident_rate": incident_rate,
            },
            sample_size=total,
        )
```

#### 2. User Trust Level System

**Purpose**: Track user trust levels based on behavior

**Implementation**:

```python
# harombe/security/hitl/trust.py
class TrustManager:
    """Manage user trust levels."""

    def __init__(self, audit_db: AuditDatabase):
        self.audit_db = audit_db
        self.trust_levels: dict[str, TrustLevel] = {}

    async def get_trust_level(self, user_id: str) -> TrustLevel:
        """Get current trust level for user."""
        # Check cache
        if user_id in self.trust_levels:
            return self.trust_levels[user_id]

        # Calculate from history
        history = await self.audit_db.query_user_events(
            user_id=user_id, limit=1000
        )

        # Calculate trust score (0-100)
        score = self._calculate_trust_score(history)

        # Map to trust level
        if score >= 90:
            level = TrustLevel.HIGH
        elif score >= 70:
            level = TrustLevel.MEDIUM
        elif score >= 50:
            level = TrustLevel.LOW
        else:
            level = TrustLevel.UNTRUSTED

        self.trust_levels[user_id] = level
        return level

    def _calculate_trust_score(self, history: list[AuditEvent]) -> float:
        """Calculate trust score from history."""
        if not history:
            return 50.0  # Neutral for new users

        factors = []

        # Factor 1: Compliance rate (no violations)
        violations = sum(1 for e in history if e.violation)
        compliance = 1.0 - (violations / len(history))
        factors.append(("compliance", compliance, 0.4))

        # Factor 2: Approval success rate
        approvals = [e for e in history if e.event_type == "hitl_approval"]
        if approvals:
            successes = sum(1 for a in approvals if a.result == "success")
            approval_rate = successes / len(approvals)
        else:
            approval_rate = 1.0
        factors.append(("approvals", approval_rate, 0.3))

        # Factor 3: Tenure (days active)
        days_active = (
            max(e.timestamp for e in history) - min(e.timestamp for e in history)
        ).days
        tenure_score = min(days_active / 90, 1.0)  # 90 days = full score
        factors.append(("tenure", tenure_score, 0.3))

        # Weighted average (0-1) -> scale to 0-100
        score = sum(s * w for _, s, w in factors) * 100
        return score
```

#### 3. Automated Low-Risk Approvals

**Purpose**: Auto-approve low-risk operations without human intervention

**Implementation**:

```python
# harombe/security/hitl/auto_approval.py
class AutoApprovalEngine:
    """Automatically approve low-risk operations."""

    def __init__(
        self,
        trust_manager: TrustManager,
        risk_scorer: HistoricalRiskScorer,
    ):
        self.trust_manager = trust_manager
        self.risk_scorer = risk_scorer
        self.rules = self._load_auto_approval_rules()

    async def should_auto_approve(
        self, operation: Operation, user_id: str, context: dict
    ) -> tuple[bool, str]:
        """Determine if operation should be auto-approved."""
        # Get user trust level
        trust = await self.trust_manager.get_trust_level(user_id)

        # Get operation risk
        risk = await self.risk_scorer.score_operation(operation, context)

        # Apply rules
        for rule in self.rules:
            if rule.matches(operation, trust, risk):
                if rule.action == "auto_approve":
                    return True, rule.reason
                elif rule.action == "require_approval":
                    return False, rule.reason

        # Default: require approval for unknown cases
        return False, "No matching auto-approval rule"

    def _load_auto_approval_rules(self) -> list[AutoApprovalRule]:
        """Load auto-approval rules."""
        return [
            # High trust + low risk = auto-approve
            AutoApprovalRule(
                name="high_trust_low_risk",
                conditions={
                    "trust_level": TrustLevel.HIGH,
                    "risk_score_max": 0.3,
                },
                action="auto_approve",
                reason="High trust user, low risk operation",
            ),
            # Medium trust + very low risk = auto-approve
            AutoApprovalRule(
                name="medium_trust_very_low_risk",
                conditions={
                    "trust_level": TrustLevel.MEDIUM,
                    "risk_score_max": 0.1,
                },
                action="auto_approve",
                reason="Medium trust user, very low risk operation",
            ),
            # Any trust + critical risk = require approval
            AutoApprovalRule(
                name="always_approve_critical",
                conditions={
                    "risk_score_min": 0.8,
                },
                action="require_approval",
                reason="Critical risk operation requires approval",
            ),
        ]
```

#### 4. Context-Aware Decision Engine

**Purpose**: Make approval decisions based on full context

**Implementation**:

```python
# harombe/security/hitl/context_engine.py
class ContextAwareEngine:
    """Context-aware approval decision engine."""

    def __init__(self):
        self.auto_approval = AutoApprovalEngine()
        self.anomaly_detector = AnomalyDetector()
        self.threat_scorer = ThreatScorer()

    async def evaluate(
        self, operation: Operation, user_id: str, context: dict
    ) -> ApprovalDecision:
        """Evaluate if operation should be approved."""
        # Check for auto-approval
        auto_approve, reason = await self.auto_approval.should_auto_approve(
            operation, user_id, context
        )

        if auto_approve:
            return ApprovalDecision(
                decision="auto_approved",
                reason=reason,
                confidence=0.95,
            )

        # Detect anomalies
        event = self._operation_to_event(operation, context)
        anomaly = await self.anomaly_detector.detect(event)

        if anomaly.is_anomalous:
            return ApprovalDecision(
                decision="require_approval",
                reason=f"Anomalous behavior detected (score: {anomaly.score:.2f})",
                confidence=anomaly.score,
                require_human=True,
            )

        # Score threat
        threat = await self.threat_scorer.score_event(event)

        if threat.level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]:
            return ApprovalDecision(
                decision="require_approval",
                reason=f"Threat detected: {threat.level.name}",
                confidence=threat.total,
                require_human=True,
            )

        # Default: require approval
        return ApprovalDecision(
            decision="require_approval",
            reason="Standard approval required",
            confidence=0.5,
            require_human=True,
        )
```

### Tasks

#### Task 5.2.1: Historical Risk Scoring

**Duration**: 1 week

**Deliverables**:

- [ ] Implement `HistoricalRiskScorer` class
- [ ] Query audit database for historical data
- [ ] Risk calculation algorithm
- [ ] Caching layer
- [ ] Unit tests

**Acceptance Criteria**:

- Scores based on 100+ historical operations
- Updates scores daily
- Processing latency <10ms

#### Task 5.2.2: User Trust Level System

**Duration**: 1 week

**Deliverables**:

- [ ] Implement `TrustManager` class
- [ ] Trust score calculation
- [ ] Trust level mapping
- [ ] Persistence layer
- [ ] Unit tests

**Acceptance Criteria**:

- Tracks trust for all users
- Updates trust levels weekly
- Handles new users (neutral score)

#### Task 5.2.3: Automated Low-Risk Approvals

**Duration**: 1 week

**Deliverables**:

- [ ] Implement `AutoApprovalEngine` class
- [ ] Auto-approval rules engine
- [ ] Rule configuration file
- [ ] Integration with HITL gateway
- [ ] Unit tests

**Acceptance Criteria**:

- Auto-approves 50%+ of low-risk operations
- Zero false approvals of high-risk ops
- Logs all auto-approval decisions

#### Task 5.2.4: Context-Aware Decision Engine

**Duration**: 5 days

**Deliverables**:

- [ ] Implement `ContextAwareEngine` class
- [ ] Integration with anomaly detector
- [ ] Integration with threat scorer
- [ ] Decision logging
- [ ] Unit tests

**Acceptance Criteria**:

- Makes decisions in <100ms
- Considers all context factors
- Explains decision reasoning

## Phase 5.3: Secret Rotation Automation

### Overview

Implement automatic credential rotation with zero-downtime and verification testing.

### Components

#### 1. Automatic Credential Rotation

**Purpose**: Rotate credentials on a schedule or trigger

**Implementation**:

```python
# harombe/security/secrets/rotation.py
class SecretRotationManager:
    """Manage automatic secret rotation."""

    def __init__(self, vault: VaultClient):
        self.vault = vault
        self.rotation_policies: dict[str, RotationPolicy] = {}
        self.scheduler = RotationScheduler()

    async def rotate_secret(
        self, secret_path: str, policy: RotationPolicy
    ) -> RotationResult:
        """Rotate a secret according to policy."""
        # Get current secret
        current = await self.vault.get_secret(secret_path)

        # Generate new secret
        new_secret = await policy.generator.generate()

        # Write new secret to staging
        staging_path = f"{secret_path}.staging"
        await self.vault.write_secret(staging_path, new_secret)

        try:
            # Verify new secret works
            verification = await self._verify_secret(
                staging_path, policy.verification_tests
            )

            if not verification.success:
                raise RotationError(f"Verification failed: {verification.error}")

            # Promote staging to production (atomic)
            await self.vault.promote_secret(staging_path, secret_path)

            # Audit log
            audit_logger.log_secret_rotation(
                secret_path=secret_path,
                old_version=current.version,
                new_version=new_secret.version,
                result="success",
            )

            return RotationResult(
                success=True,
                old_version=current.version,
                new_version=new_secret.version,
            )

        except Exception as e:
            # Rollback
            await self.vault.delete_secret(staging_path)

            audit_logger.log_secret_rotation(
                secret_path=secret_path,
                old_version=current.version,
                result="failure",
                error=str(e),
            )

            raise
```

#### 2. Zero-Downtime Rotation

**Purpose**: Rotate secrets without service interruption

**Implementation**:

```python
# harombe/security/secrets/zero_downtime.py
class ZeroDowntimeRotation:
    """Zero-downtime secret rotation strategy."""

    async def rotate(
        self, secret_path: str, new_value: str
    ) -> None:
        """Rotate secret with zero downtime."""
        # Phase 1: Dual-write (old + new)
        await self._enable_dual_mode(secret_path, new_value)

        # Phase 2: Update all consumers to use new secret
        await self._wait_for_consumers_updated()

        # Phase 3: Remove old secret
        await self._remove_old_secret(secret_path)

    async def _enable_dual_mode(
        self, secret_path: str, new_value: str
    ) -> None:
        """Enable dual-mode where both old and new are valid."""
        # Store both versions
        await self.vault.write_secret(
            secret_path,
            {
                "current": await self.vault.get_secret(secret_path),
                "next": new_value,
            },
        )

        # Update metadata to indicate dual-mode
        await self.vault.update_metadata(
            secret_path, {"rotation_mode": "dual"}
        )
```

#### 3. Rotation Verification Tests

**Purpose**: Verify new credentials work before promoting

**Implementation**:

```python
# harombe/security/secrets/verification.py
class RotationVerificationTester:
    """Test new credentials before rotation."""

    async def verify(
        self, secret_path: str, tests: list[VerificationTest]
    ) -> VerificationResult:
        """Run verification tests on new secret."""
        results = []

        for test in tests:
            try:
                # Run test
                result = await test.run(secret_path)
                results.append((test.name, result.success, result.message))

            except Exception as e:
                results.append((test.name, False, str(e)))

        # All tests must pass
        all_passed = all(success for _, success, _ in results)

        return VerificationResult(
            success=all_passed,
            tests=results,
            error=None if all_passed else "One or more tests failed",
        )


# Example verification tests
class AnthropicAPIVerification(VerificationTest):
    """Verify Anthropic API key works."""

    async def run(self, secret_path: str) -> TestResult:
        # Get new API key
        api_key = await vault.get_secret(secret_path)

        # Test API call
        client = anthropic.Anthropic(api_key=api_key)
        try:
            response = await client.messages.create(
                model="claude-3-haiku-20240307",
                max_tokens=10,
                messages=[{"role": "user", "content": "Test"}],
            )
            return TestResult(success=True, message="API key valid")
        except Exception as e:
            return TestResult(success=False, message=f"API test failed: {e}")
```

#### 4. Emergency Rotation Triggers

**Purpose**: Trigger immediate rotation on security events

**Implementation**:

```python
# harombe/security/secrets/emergency.py
class EmergencyRotationTrigger:
    """Trigger emergency secret rotation."""

    def __init__(self, rotation_manager: SecretRotationManager):
        self.rotation_manager = rotation_manager
        self.audit_db = AuditDatabase()

    async def on_security_event(self, event: SecurityEvent) -> None:
        """Handle security events that may require rotation."""
        # Check if event indicates compromise
        if self._is_compromise_indicator(event):
            # Identify affected secrets
            affected_secrets = self._identify_affected_secrets(event)

            # Trigger emergency rotation
            for secret_path in affected_secrets:
                await self._emergency_rotate(secret_path, event)

    async def _emergency_rotate(
        self, secret_path: str, trigger_event: SecurityEvent
    ) -> None:
        """Perform emergency rotation."""
        # Log emergency rotation
        audit_logger.log_emergency_rotation(
            secret_path=secret_path,
            trigger=trigger_event,
            timestamp=datetime.utcnow(),
        )

        # Rotate immediately
        policy = RotationPolicy(
            interval=0,  # Immediate
            verification_tests=[],  # Skip verification in emergency
        )

        try:
            await self.rotation_manager.rotate_secret(secret_path, policy)

            # Notify security team
            await self._notify_security_team(secret_path, trigger_event)

        except Exception as e:
            # Alert on failure
            await self._alert_rotation_failure(secret_path, e)
```

### Tasks

#### Task 5.3.1: Automatic Credential Rotation

**Duration**: 1 week

**Deliverables**:

- [ ] Implement `SecretRotationManager` class
- [ ] Rotation policy configuration
- [ ] Scheduling system
- [ ] Integration with Vault
- [ ] Unit tests

**Acceptance Criteria**:

- Rotates secrets on schedule
- Supports custom rotation policies
- Logs all rotations

#### Task 5.3.2: Zero-Downtime Rotation

**Duration**: 1 week

**Deliverables**:

- [ ] Implement `ZeroDowntimeRotation` class
- [ ] Dual-mode secret handling
- [ ] Consumer update tracking
- [ ] Rollback mechanism
- [ ] Unit tests

**Acceptance Criteria**:

- Zero service downtime during rotation
- Handles consumer update failures
- Automatic rollback on errors

#### Task 5.3.3: Rotation Verification Tests

**Duration**: 1 week

**Deliverables**:

- [ ] Implement `RotationVerificationTester` class
- [ ] Verification test framework
- [ ] 5+ provider-specific tests (Anthropic, GitHub, AWS, etc.)
- [ ] Test result reporting
- [ ] Unit tests

**Acceptance Criteria**:

- Verifies new credentials before promotion
- Supports custom verification tests
- Reports detailed test results

#### Task 5.3.4: Emergency Rotation Triggers

**Duration**: 5 days

**Deliverables**:

- [ ] Implement `EmergencyRotationTrigger` class
- [ ] Security event monitoring
- [ ] Compromise detection logic
- [ ] Alert notification system
- [ ] Unit tests

**Acceptance Criteria**:

- Detects compromise indicators
- Triggers rotation within 5 minutes
- Notifies security team

## Phase 5.4: Network Security Enhancements

### Overview

Add advanced network security features including TLS certificate pinning, deep packet inspection, and protocol-aware filtering.

### Components

#### 1. TLS Certificate Pinning

**Purpose**: Prevent MITM attacks by pinning expected certificates

**Implementation**:

```python
# harombe/security/network/cert_pinning.py
class CertificatePinner:
    """TLS certificate pinning for trusted domains."""

    def __init__(self):
        self.pins: dict[str, list[str]] = self._load_pins()

    async def verify_certificate(
        self, domain: str, cert_chain: list[Certificate]
    ) -> bool:
        """Verify certificate matches pin."""
        # Get pins for domain
        expected_pins = self.pins.get(domain, [])

        if not expected_pins:
            # No pin configured, accept any valid cert
            return True

        # Check if any cert in chain matches pin
        for cert in cert_chain:
            fingerprint = self._get_fingerprint(cert)
            if fingerprint in expected_pins:
                return True

        # No match
        audit_logger.log_cert_pin_failure(domain, cert_chain)
        return False

    def _load_pins(self) -> dict[str, list[str]]:
        """Load certificate pins from configuration."""
        return {
            "api.anthropic.com": [
                "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                "sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
            ],
            "api.github.com": [
                "sha256/CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=",
            ],
        }
```

#### 2. Deep Packet Inspection

**Purpose**: Inspect packet contents for malicious patterns

**Implementation**:

```python
# harombe/security/network/dpi.py
class DeepPacketInspector:
    """Deep packet inspection for egress traffic."""

    def __init__(self):
        self.patterns = self._load_malicious_patterns()
        self.secret_scanner = SecretScanner()

    async def inspect(self, packet: NetworkPacket) -> InspectionResult:
        """Inspect packet for malicious content."""
        issues = []

        # Check for secrets
        secrets = self.secret_scanner.scan(packet.payload)
        if secrets:
            issues.append(
                Issue(
                    severity="critical",
                    type="secret_leak",
                    details=f"Found {len(secrets)} secrets in packet",
                )
            )

        # Check for malicious patterns
        for pattern in self.patterns:
            if pattern.matches(packet.payload):
                issues.append(
                    Issue(
                        severity=pattern.severity,
                        type=pattern.type,
                        details=pattern.description,
                    )
                )

        # Check for data exfiltration indicators
        if self._is_potential_exfiltration(packet):
            issues.append(
                Issue(
                    severity="high",
                    type="potential_exfiltration",
                    details="Large data transfer to unusual destination",
                )
            )

        return InspectionResult(
            allowed=len(issues) == 0,
            issues=issues,
        )
```

#### 3. Protocol-Aware Filtering

**Purpose**: Allow only specific protocols (HTTP/HTTPS)

**Implementation**:

```python
# harombe/security/network/protocol_filter.py
class ProtocolFilter:
    """Protocol-aware network filtering."""

    def __init__(self):
        self.allowed_protocols = ["http", "https"]
        self.http_validator = HTTPValidator()

    async def filter(self, packet: NetworkPacket) -> FilterResult:
        """Filter packet based on protocol."""
        # Detect protocol
        protocol = self._detect_protocol(packet)

        # Check if allowed
        if protocol not in self.allowed_protocols:
            return FilterResult(
                allowed=False,
                reason=f"Protocol {protocol} not allowed",
            )

        # Protocol-specific validation
        if protocol in ["http", "https"]:
            validation = await self.http_validator.validate(packet)
            if not validation.valid:
                return FilterResult(
                    allowed=False,
                    reason=f"HTTP validation failed: {validation.reason}",
                )

        return FilterResult(allowed=True)


class HTTPValidator:
    """Validate HTTP/HTTPS traffic."""

    async def validate(self, packet: NetworkPacket) -> ValidationResult:
        """Validate HTTP packet."""
        try:
            # Parse HTTP
            request = self._parse_http(packet.payload)

            # Check method
            if request.method not in ["GET", "POST", "PUT", "PATCH", "DELETE"]:
                return ValidationResult(
                    valid=False,
                    reason=f"HTTP method {request.method} not allowed",
                )

            # Check headers
            if "Host" not in request.headers:
                return ValidationResult(
                    valid=False,
                    reason="Missing Host header",
                )

            # Check for suspicious patterns
            if self._has_suspicious_patterns(request):
                return ValidationResult(
                    valid=False,
                    reason="Suspicious patterns detected in HTTP request",
                )

            return ValidationResult(valid=True)

        except Exception as e:
            return ValidationResult(
                valid=False,
                reason=f"HTTP parsing error: {e}",
            )
```

#### 4. Traffic Anomaly Detection

**Purpose**: Detect unusual traffic patterns

**Implementation**:

```python
# harombe/security/network/traffic_anomaly.py
class TrafficAnomalyDetector:
    """Detect anomalous network traffic."""

    def __init__(self):
        self.baseline = TrafficBaseline()
        self.detector = AnomalyDetector(model_type="isolation_forest")

    async def detect(
        self, connection: NetworkConnection
    ) -> AnomalyResult:
        """Detect if connection is anomalous."""
        # Extract features
        features = {
            "bytes_sent": connection.bytes_sent,
            "bytes_received": connection.bytes_received,
            "duration": connection.duration,
            "packet_count": connection.packet_count,
            "destination_port": connection.destination_port,
            "hour_of_day": connection.start_time.hour,
        }

        # Compare to baseline
        deviation = self.baseline.get_deviation(features)

        # ML detection
        ml_score = self.detector.predict_proba([list(features.values())])[0]

        # Combine scores
        is_anomalous = deviation > 3.0 or ml_score > 0.8

        return AnomalyResult(
            is_anomalous=is_anomalous,
            deviation_score=deviation,
            ml_score=ml_score,
            features=features,
        )
```

### Tasks

#### Task 5.4.1: TLS Certificate Pinning

**Duration**: 5 days

**Deliverables**:

- [ ] Implement `CertificatePinner` class
- [ ] Certificate fingerprint calculation
- [ ] Pin configuration file
- [ ] Integration with network filter
- [ ] Unit tests

**Acceptance Criteria**:

- Verifies certificates for pinned domains
- Logs pin failures
- Supports pin rotation

#### Task 5.4.2: Deep Packet Inspection

**Duration**: 1 week

**Deliverables**:

- [ ] Implement `DeepPacketInspector` class
- [ ] Malicious pattern database
- [ ] Secret scanning integration
- [ ] Exfiltration detection heuristics
- [ ] Unit tests

**Acceptance Criteria**:

- Detects secrets in packets
- Identifies malicious patterns
- Processing latency <10ms per packet

#### Task 5.4.3: Protocol-Aware Filtering

**Duration**: 1 week

**Deliverables**:

- [ ] Implement `ProtocolFilter` class
- [ ] Protocol detection logic
- [ ] HTTP/HTTPS validator
- [ ] Integration with network filter
- [ ] Unit tests

**Acceptance Criteria**:

- Allows only HTTP/HTTPS traffic
- Validates HTTP structure
- Blocks protocol abuse attempts

#### Task 5.4.4: Traffic Anomaly Detection

**Duration**: 1 week

**Deliverables**:

- [ ] Implement `TrafficAnomalyDetector` class
- [ ] Traffic baseline learning
- [ ] ML-based detection
- [ ] Alert generation
- [ ] Unit tests

**Acceptance Criteria**:

- Detects unusual traffic patterns
- <5% false positive rate
- Alerts on anomalies

## Phase 5.5: Audit Enhancements

### Overview

Enhance audit system with SIEM integration, automated alerting, and compliance report generation.

### Components

#### 1. SIEM Integration

**Purpose**: Forward audit events to enterprise SIEM platforms

**Implementation**:

```python
# harombe/security/audit/siem.py
class SIEMIntegrator:
    """Integrate with SIEM platforms."""

    def __init__(self):
        self.exporters = {
            "splunk": SplunkExporter(),
            "elk": ElasticsearchExporter(),
            "datadog": DatadogExporter(),
        }

    async def export_event(self, event: AuditEvent, siem: str) -> None:
        """Export event to SIEM."""
        exporter = self.exporters.get(siem)
        if not exporter:
            raise ValueError(f"Unknown SIEM: {siem}")

        # Convert to SIEM format
        siem_event = self._convert_to_siem_format(event, siem)

        # Send to SIEM
        await exporter.send(siem_event)


class SplunkExporter:
    """Export events to Splunk."""

    def __init__(self):
        self.hec_url = os.getenv("SPLUNK_HEC_URL")
        self.hec_token = os.getenv("SPLUNK_HEC_TOKEN")

    async def send(self, event: dict) -> None:
        """Send event to Splunk HEC."""
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.hec_url}/services/collector/event",
                headers={"Authorization": f"Splunk {self.hec_token}"},
                json={"event": event, "sourcetype": "harombe:security"},
            )
            response.raise_for_status()
```

#### 2. Automated Alert Rules

**Purpose**: Generate alerts based on audit events

**Implementation**:

```python
# harombe/security/audit/alerts.py
class AlertRuleEngine:
    """Automated alert rule engine."""

    def __init__(self):
        self.rules = self._load_alert_rules()
        self.notifiers = [
            EmailNotifier(),
            SlackNotifier(),
            PagerDutyNotifier(),
        ]

    async def evaluate_event(self, event: AuditEvent) -> None:
        """Evaluate event against alert rules."""
        for rule in self.rules:
            if rule.matches(event):
                alert = Alert(
                    rule=rule,
                    event=event,
                    severity=rule.severity,
                    message=rule.format_message(event),
                )

                # Send alert
                await self._send_alert(alert)

    def _load_alert_rules(self) -> list[AlertRule]:
        """Load alert rules from configuration."""
        return [
            # Multiple failed authentications
            AlertRule(
                name="multiple_auth_failures",
                condition="event_type == 'auth_failure' AND count(1h) >= 5",
                severity="high",
                message="Multiple authentication failures detected",
            ),
            # Secret rotation failure
            AlertRule(
                name="rotation_failure",
                condition="event_type == 'secret_rotation' AND result == 'failure'",
                severity="critical",
                message="Secret rotation failed",
            ),
            # High-risk operation denied
            AlertRule(
                name="high_risk_denied",
                condition="event_type == 'hitl_decision' AND risk_level == 'high' AND decision == 'denied'",
                severity="medium",
                message="High-risk operation was denied",
            ),
        ]
```

#### 3. Compliance Report Generation

**Purpose**: Generate compliance reports automatically

**Implementation**:

```python
# harombe/security/audit/compliance_reports.py
class ComplianceReportGenerator:
    """Generate compliance reports."""

    def __init__(self, audit_db: AuditDatabase):
        self.audit_db = audit_db
        self.templates = self._load_templates()

    async def generate_report(
        self, compliance_type: str, start_date: datetime, end_date: datetime
    ) -> ComplianceReport:
        """Generate compliance report."""
        template = self.templates.get(compliance_type)
        if not template:
            raise ValueError(f"Unknown compliance type: {compliance_type}")

        # Query relevant events
        events = await self.audit_db.query_events(
            start_date=start_date,
            end_date=end_date,
        )

        # Generate sections
        sections = []
        for section_def in template.sections:
            section = await self._generate_section(
                section_def, events, start_date, end_date
            )
            sections.append(section)

        return ComplianceReport(
            type=compliance_type,
            period=(start_date, end_date),
            sections=sections,
            generated_at=datetime.utcnow(),
        )

    def _load_templates(self) -> dict[str, ReportTemplate]:
        """Load report templates."""
        return {
            "pci_dss": PCIDSSTemplate(),
            "gdpr": GDPRTemplate(),
            "soc2": SOC2Template(),
        }


class PCIDSSTemplate(ReportTemplate):
    """PCI DSS compliance report template."""

    sections = [
        ReportSection(
            title="Requirement 3: Protect Stored Cardholder Data",
            queries=[
                "SELECT COUNT(*) FROM audit_events WHERE event_type = 'secret_access'",
                "SELECT COUNT(*) FROM audit_events WHERE event_type = 'secret_leak_detected'",
            ],
        ),
        ReportSection(
            title="Requirement 10: Log and Monitor All Access",
            queries=[
                "SELECT COUNT(*) FROM audit_events",
                "SELECT COUNT(DISTINCT user_id) FROM audit_events",
            ],
        ),
    ]
```

#### 4. Real-Time Dashboards

**Purpose**: Visualize security metrics in real-time

**Implementation**:

```python
# harombe/security/audit/dashboard.py
class SecurityDashboard:
    """Real-time security metrics dashboard."""

    def __init__(self, audit_db: AuditDatabase):
        self.audit_db = audit_db
        self.metrics_cache = MetricsCache(ttl=60)  # 1 minute

    async def get_metrics(self) -> DashboardMetrics:
        """Get current security metrics."""
        # Check cache
        cached = self.metrics_cache.get("current_metrics")
        if cached:
            return cached

        # Calculate metrics
        metrics = DashboardMetrics(
            # Activity metrics
            events_last_hour=await self._count_events(hours=1),
            events_last_day=await self._count_events(hours=24),
            active_users=await self._count_active_users(hours=1),
            # Security metrics
            auth_failures=await self._count_auth_failures(hours=1),
            hitl_denials=await self._count_hitl_denials(hours=24),
            network_blocks=await self._count_network_blocks(hours=1),
            secrets_detected=await self._count_secrets_detected(hours=24),
            anomalies_detected=await self._count_anomalies(hours=1),
            # Performance metrics
            avg_audit_latency=await self._avg_audit_latency(hours=1),
            p95_audit_latency=await self._p95_audit_latency(hours=1),
        )

        # Cache
        self.metrics_cache.set("current_metrics", metrics)

        return metrics
```

### Tasks

#### Task 5.5.1: SIEM Integration

**Duration**: 1 week

**Deliverables**:

- [ ] Implement `SIEMIntegrator` class
- [ ] Exporters for Splunk, ELK, Datadog
- [ ] Event format conversion
- [ ] Buffering and retry logic
- [ ] Unit tests

**Acceptance Criteria**:

- Forwards events to 3+ SIEMs
- <1s latency from event to SIEM
- Handles SIEM downtime gracefully

#### Task 5.5.2: Automated Alert Rules

**Duration**: 1 week

**Deliverables**:

- [ ] Implement `AlertRuleEngine` class
- [ ] Rule DSL or configuration format
- [ ] Email, Slack, PagerDuty notifiers
- [ ] Alert deduplication
- [ ] Unit tests

**Acceptance Criteria**:

- Evaluates 10+ alert rules
- Sends alerts within 1 minute
- Supports multiple notification channels

#### Task 5.5.3: Compliance Report Generation

**Duration**: 1 week

**Deliverables**:

- [ ] Implement `ComplianceReportGenerator` class
- [ ] Report templates for PCI DSS, GDPR, SOC 2
- [ ] PDF/HTML export
- [ ] Scheduling system
- [ ] Unit tests

**Acceptance Criteria**:

- Generates reports in <5 minutes
- Covers PCI DSS, GDPR, SOC 2
- Exports to PDF and HTML

#### Task 5.5.4: Real-Time Dashboards

**Duration**: 1 week

**Deliverables**:

- [ ] Implement `SecurityDashboard` class
- [ ] Metrics calculation
- [ ] Web UI (React/Vue)
- [ ] WebSocket real-time updates
- [ ] Unit tests

**Acceptance Criteria**:

- Displays 10+ key metrics
- Updates every 60 seconds
- <100ms dashboard load time

## Phase 5.6: Integration & Testing

### Overview

Integrate all Phase 5 components and perform comprehensive testing.

### Tasks

#### Task 5.6.1: Integration Tests

**Duration**: 3 days

**Deliverables**:

- [ ] End-to-end integration tests
- [ ] Test all Phase 5 components together
- [ ] Verify data flows
- [ ] Test error handling

**Acceptance Criteria**:

- 100% of integration tests pass
- All components work together
- No regressions from Phase 4

#### Task 5.6.2: Performance Benchmarks

**Duration**: 2 days

**Deliverables**:

- [ ] Performance benchmarks for Phase 5 features
- [ ] Threat detection latency
- [ ] HITL auto-approval speed
- [ ] Secret rotation downtime
- [ ] SIEM export throughput

**Acceptance Criteria**:

- All performance targets met
- No degradation from Phase 4
- Document results

#### Task 5.6.3: Security Validation

**Duration**: 2 days

**Deliverables**:

- [ ] Security validation tests
- [ ] Penetration testing
- [ ] Threat model validation
- [ ] Compliance verification

**Acceptance Criteria**:

- All security tests pass
- No new vulnerabilities introduced
- Compliance maintained

#### Task 5.6.4: Documentation

**Duration**: 1 day

**Deliverables**:

- [ ] Phase 5 implementation summary
- [ ] Updated security architecture
- [ ] API documentation
- [ ] Deployment guide updates

**Acceptance Criteria**:

- All Phase 5 features documented
- Deployment guide updated
- API docs complete

## Timeline

**Total Duration**: 8 weeks

```
Week 1:  [5.1.1][5.1.2]           [Threat Detection]
Week 2:  [5.1.3][5.1.4][5.2.1]    [Threat Detection + HITL]
Week 3:  [5.1.4][5.2.2][5.3.1]    [Threat Intel + HITL + Rotation]
Week 4:  [5.2.3][5.2.4][5.4.1]    [HITL + Network]
Week 5:  [5.3.2][5.3.3][5.5.1]    [Rotation + Audit]
Week 6:  [5.3.4][5.4.2][5.4.3]    [Rotation + Network]
Week 7:  [5.4.4][5.5.2][5.5.3]    [Network + Audit]
Week 8:  [5.5.4][5.6.1-5.6.4]     [Audit + Integration/Testing]
```

## Dependencies

### External Dependencies

- **ML Libraries**: scikit-learn, TensorFlow/PyTorch (for advanced models)
- **SIEM SDKs**: Splunk SDK, Elasticsearch client, Datadog API
- **Notification Services**: SendGrid, Slack SDK, PagerDuty API
- **Threat Intelligence APIs**: AbuseIPDB, VirusTotal, AlienVault OTX

### Internal Dependencies

- Phase 4 complete (all security components)
- Audit database with sufficient historical data (7+ days)
- Vault operational with secrets management

## Risk & Mitigation

### Technical Risks

1. **ML Model Accuracy**
   - **Risk**: Anomaly detection has high false positive rate
   - **Mitigation**: Extensive training data, tuning thresholds, human review
   - **Likelihood**: Medium
   - **Impact**: Medium

2. **Secret Rotation Failures**
   - **Risk**: Rotation causes service outage
   - **Mitigation**: Zero-downtime strategy, comprehensive verification, rollback
   - **Likelihood**: Low
   - **Impact**: High

3. **SIEM Integration Issues**
   - **Risk**: Events not reaching SIEM or high latency
   - **Mitigation**: Buffering, retry logic, multiple SIEM support
   - **Likelihood**: Medium
   - **Impact**: Low

4. **Performance Degradation**
   - **Risk**: New features slow down system
   - **Mitigation**: Performance benchmarks, profiling, optimization
   - **Likelihood**: Low
   - **Impact**: Medium

### Mitigation Strategy

- Weekly performance monitoring
- Staged rollout (feature flags)
- Comprehensive testing at each milestone
- Rollback plan for each component

## Success Criteria

### Technical Criteria

- [ ] Anomaly detection: >95% accuracy, <5% false positives
- [ ] HITL auto-approval: 50% reduction in manual approvals
- [ ] Secret rotation: Zero downtime, 100% verification success
- [ ] Network enhancements: All traffic inspected, <10ms overhead
- [ ] Audit enhancements: SIEM integration <1s latency
- [ ] All integration tests pass
- [ ] Performance targets met
- [ ] No security regressions

### Business Criteria

- [ ] Reduced operator workload (50% fewer HITL approvals)
- [ ] Improved security posture (threat detection active)
- [ ] Compliance automation (reports generated automatically)
- [ ] Zero production incidents during Phase 5

## Next Steps

1. **Immediate**: Review and approve Phase 5 plan
2. **Week 1**: Begin Task 5.1.1 (Anomaly Detection Framework)
3. **Week 2**: Complete threat detection, begin HITL enhancements
4. **Week 8**: Complete Phase 5, prepare for Phase 6

---

**Document Version**: 1.0
**Last Updated**: 2026-02-09
**Next Review**: 2026-02-16
**Owner**: Security Team
**Approver**: CTO
