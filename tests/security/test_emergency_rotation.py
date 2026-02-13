"""Tests for emergency credential rotation system."""

from datetime import UTC, datetime

import pytest

from harombe.security.emergency_rotation import (
    CompromiseIndicator,
    EmergencyRotationResult,
    EmergencyRotationTrigger,
    SecurityEvent,
    ThreatLevel,
)
from harombe.security.rotation import RotationResult, RotationStatus


class MockRotationManager:
    """Mock rotation manager for testing."""

    def __init__(self):
        self.rotations = []

    async def rotate_secret(self, secret_path, policy):
        """Mock secret rotation."""
        self.rotations.append({"path": secret_path, "policy": policy})
        return RotationResult(
            success=True,
            secret_path=secret_path,
            old_version="old123",
            new_version="new456",
            status=RotationStatus.SUCCESS,
            started_at=datetime.now(UTC).replace(tzinfo=None),
        )


class MockNotificationHandler:
    """Mock notification handler for testing."""

    def __init__(self):
        self.notifications = []

    async def send_notification(self, channel, message, priority, metadata):
        """Mock send notification."""
        self.notifications.append(
            {
                "channel": channel,
                "message": message,
                "priority": priority,
                "metadata": metadata,
            }
        )


@pytest.fixture
def mock_rotation_manager():
    """Create mock rotation manager."""
    return MockRotationManager()


@pytest.fixture
def mock_notification_handler():
    """Create mock notification handler."""
    return MockNotificationHandler()


@pytest.fixture
def emergency_trigger(mock_rotation_manager, mock_notification_handler):
    """Create emergency rotation trigger."""
    return EmergencyRotationTrigger(
        rotation_manager=mock_rotation_manager,
        notification_handler=mock_notification_handler,
    )


class TestCompromiseIndicator:
    """Test CompromiseIndicator enum."""

    def test_indicator_values(self):
        """Test compromise indicator values."""
        assert CompromiseIndicator.FAILED_AUTH_SPIKE == "failed_auth_spike"
        assert CompromiseIndicator.LEAKED_CREDENTIAL == "leaked_credential"
        assert CompromiseIndicator.SUSPICIOUS_ACCESS == "suspicious_access"
        assert CompromiseIndicator.RATE_LIMIT_EXCEEDED == "rate_limit_exceeded"
        assert CompromiseIndicator.UNAUTHORIZED_ACCESS == "unauthorized_access"
        assert CompromiseIndicator.API_KEY_EXPOSED == "api_key_exposed"
        assert CompromiseIndicator.BRUTE_FORCE_ATTACK == "brute_force_attack"
        assert CompromiseIndicator.ANOMALOUS_BEHAVIOR == "anomalous_behavior"
        assert CompromiseIndicator.MANUAL_TRIGGER == "manual_trigger"


class TestThreatLevel:
    """Test ThreatLevel enum."""

    def test_threat_level_values(self):
        """Test threat level values."""
        assert ThreatLevel.LOW == "low"
        assert ThreatLevel.MEDIUM == "medium"
        assert ThreatLevel.HIGH == "high"
        assert ThreatLevel.CRITICAL == "critical"


class TestSecurityEvent:
    """Test SecurityEvent model."""

    def test_security_event_creation(self):
        """Test creating security event."""
        event = SecurityEvent(
            event_type=CompromiseIndicator.LEAKED_CREDENTIAL,
            threat_level=ThreatLevel.CRITICAL,
            description="API key leaked on GitHub",
            affected_resources=["/secrets/api_key"],
            source_ip="203.0.113.1",
            timestamp=datetime.now(UTC).replace(tzinfo=None),
            metadata={"repository": "user/repo", "commit": "abc123"},
        )

        assert event.event_type == CompromiseIndicator.LEAKED_CREDENTIAL
        assert event.threat_level == ThreatLevel.CRITICAL
        assert len(event.affected_resources) == 1
        assert event.source_ip == "203.0.113.1"
        assert "repository" in event.metadata


class TestEmergencyRotationResult:
    """Test EmergencyRotationResult model."""

    def test_result_creation(self):
        """Test creating emergency rotation result."""
        event = SecurityEvent(
            event_type=CompromiseIndicator.MANUAL_TRIGGER,
            threat_level=ThreatLevel.HIGH,
            description="Manual rotation",
            timestamp=datetime.now(UTC).replace(tzinfo=None),
        )

        result = EmergencyRotationResult(
            success=True,
            secret_path="/secrets/test",
            trigger_event=event,
            rotation_started_at=datetime.now(UTC).replace(tzinfo=None),
            rotation_completed_at=datetime.now(UTC).replace(tzinfo=None),
            duration_ms=150.0,
            notifications_sent=1,
        )

        assert result.success
        assert result.secret_path == "/secrets/test"
        assert result.trigger_event == event
        assert result.duration_ms == 150.0
        assert result.notifications_sent == 1


class TestEmergencyRotationTrigger:
    """Test EmergencyRotationTrigger class."""

    def test_initialization(self, emergency_trigger, mock_rotation_manager):
        """Test trigger initialization."""
        assert emergency_trigger.rotation_manager == mock_rotation_manager
        assert emergency_trigger.stats["total_events"] == 0
        assert emergency_trigger.stats["emergency_rotations"] == 0

    @pytest.mark.asyncio
    async def test_critical_threat_triggers_rotation(self, emergency_trigger):
        """Test critical threat level triggers rotation."""
        event = SecurityEvent(
            event_type=CompromiseIndicator.LEAKED_CREDENTIAL,
            threat_level=ThreatLevel.CRITICAL,
            description="Critical security breach",
            affected_resources=["/secrets/api_key"],
            timestamp=datetime.now(UTC).replace(tzinfo=None),
        )

        results = await emergency_trigger.on_security_event(event)

        assert len(results) == 1
        assert results[0].success
        assert results[0].secret_path == "/secrets/api_key"
        assert emergency_trigger.stats["emergency_rotations"] == 1

    @pytest.mark.asyncio
    async def test_high_threat_leaked_credential(self, emergency_trigger):
        """Test high threat leaked credential triggers rotation."""
        event = SecurityEvent(
            event_type=CompromiseIndicator.LEAKED_CREDENTIAL,
            threat_level=ThreatLevel.HIGH,
            description="Credential leaked",
            affected_resources=["/secrets/leaked"],
            timestamp=datetime.now(UTC).replace(tzinfo=None),
        )

        results = await emergency_trigger.on_security_event(event)

        assert len(results) == 1
        assert results[0].success

    @pytest.mark.asyncio
    async def test_manual_trigger(self, emergency_trigger):
        """Test manual trigger always rotates."""
        event = SecurityEvent(
            event_type=CompromiseIndicator.MANUAL_TRIGGER,
            threat_level=ThreatLevel.HIGH,
            description="Manual emergency rotation",
            affected_resources=["/secrets/manual"],
            timestamp=datetime.now(UTC).replace(tzinfo=None),
        )

        results = await emergency_trigger.on_security_event(event)

        assert len(results) == 1
        assert results[0].success

    @pytest.mark.asyncio
    async def test_failed_auth_spike_above_threshold(self, emergency_trigger):
        """Test failed auth spike above threshold triggers rotation."""
        event = SecurityEvent(
            event_type=CompromiseIndicator.FAILED_AUTH_SPIKE,
            threat_level=ThreatLevel.MEDIUM,
            description="Failed auth spike",
            affected_resources=["/secrets/auth"],
            timestamp=datetime.now(UTC).replace(tzinfo=None),
            metadata={"failed_count": 15},  # Above default threshold of 10
        )

        results = await emergency_trigger.on_security_event(event)

        assert len(results) == 1
        assert results[0].success

    @pytest.mark.asyncio
    async def test_failed_auth_spike_below_threshold(self, emergency_trigger):
        """Test failed auth spike below threshold does not trigger."""
        event = SecurityEvent(
            event_type=CompromiseIndicator.FAILED_AUTH_SPIKE,
            threat_level=ThreatLevel.MEDIUM,
            description="Small auth spike",
            affected_resources=["/secrets/auth"],
            timestamp=datetime.now(UTC).replace(tzinfo=None),
            metadata={"failed_count": 5},  # Below threshold
        )

        results = await emergency_trigger.on_security_event(event)

        assert len(results) == 0  # Should not trigger

    @pytest.mark.asyncio
    async def test_rate_limit_exceeded_above_threshold(self, emergency_trigger):
        """Test rate limit exceeded above threshold."""
        event = SecurityEvent(
            event_type=CompromiseIndicator.RATE_LIMIT_EXCEEDED,
            threat_level=ThreatLevel.MEDIUM,
            description="Rate limit violations",
            affected_resources=["/secrets/api"],
            timestamp=datetime.now(UTC).replace(tzinfo=None),
            metadata={"violation_count": 150},  # Above default threshold of 100
        )

        results = await emergency_trigger.on_security_event(event)

        assert len(results) == 1

    @pytest.mark.asyncio
    async def test_low_threat_no_rotation(self, emergency_trigger):
        """Test low threat level does not trigger rotation."""
        event = SecurityEvent(
            event_type="generic_event",
            threat_level=ThreatLevel.LOW,
            description="Low threat event",
            affected_resources=["/secrets/test"],
            timestamp=datetime.now(UTC).replace(tzinfo=None),
        )

        results = await emergency_trigger.on_security_event(event)

        assert len(results) == 0
        assert emergency_trigger.stats["emergency_rotations"] == 0

    @pytest.mark.asyncio
    async def test_multiple_affected_secrets(self, emergency_trigger):
        """Test rotation of multiple affected secrets."""
        event = SecurityEvent(
            event_type=CompromiseIndicator.API_KEY_EXPOSED,
            threat_level=ThreatLevel.HIGH,
            description="Multiple keys exposed",
            affected_resources=["/secrets/key1", "/secrets/key2", "/secrets/key3"],
            timestamp=datetime.now(UTC).replace(tzinfo=None),
        )

        results = await emergency_trigger.on_security_event(event)

        assert len(results) == 3
        assert all(r.success for r in results)

    @pytest.mark.asyncio
    async def test_notification_sent_on_success(self, emergency_trigger, mock_notification_handler):
        """Test notification sent after successful rotation."""
        event = SecurityEvent(
            event_type=CompromiseIndicator.MANUAL_TRIGGER,
            threat_level=ThreatLevel.HIGH,
            description="Test rotation",
            affected_resources=["/secrets/test"],
            timestamp=datetime.now(UTC).replace(tzinfo=None),
        )

        results = await emergency_trigger.on_security_event(event)

        assert len(results) == 1
        assert results[0].notifications_sent == 1
        assert len(mock_notification_handler.notifications) == 1
        assert mock_notification_handler.notifications[0]["channel"] == "security-alerts"
        assert mock_notification_handler.notifications[0]["priority"] == "high"

    @pytest.mark.asyncio
    async def test_rotation_failure_handling(self):
        """Test handling of rotation failures."""
        # Create manager that fails rotation
        failing_manager = MockRotationManager()

        async def failing_rotate(secret_path, policy):
            return RotationResult(
                success=False,
                secret_path=secret_path,
                status=RotationStatus.FAILED,
                started_at=datetime.now(UTC).replace(tzinfo=None),
                error="Rotation failed",
            )

        failing_manager.rotate_secret = failing_rotate

        trigger = EmergencyRotationTrigger(
            rotation_manager=failing_manager,
            notification_handler=MockNotificationHandler(),
        )

        event = SecurityEvent(
            event_type=CompromiseIndicator.MANUAL_TRIGGER,
            threat_level=ThreatLevel.HIGH,
            description="Test",
            affected_resources=["/secrets/test"],
            timestamp=datetime.now(UTC).replace(tzinfo=None),
        )

        results = await trigger.on_security_event(event)

        assert len(results) == 1
        assert not results[0].success
        assert results[0].error == "Rotation failed"
        assert trigger.stats["failed_rotations"] == 1

    @pytest.mark.asyncio
    async def test_rotation_exception_handling(self):
        """Test handling of rotation exceptions."""
        # Create manager that raises exception
        failing_manager = MockRotationManager()

        async def exception_rotate(secret_path, policy):
            raise ValueError("Test exception")

        failing_manager.rotate_secret = exception_rotate

        trigger = EmergencyRotationTrigger(
            rotation_manager=failing_manager,
            notification_handler=MockNotificationHandler(),
        )

        event = SecurityEvent(
            event_type=CompromiseIndicator.MANUAL_TRIGGER,
            threat_level=ThreatLevel.HIGH,
            description="Test",
            affected_resources=["/secrets/test"],
            timestamp=datetime.now(UTC).replace(tzinfo=None),
        )

        results = await trigger.on_security_event(event)

        assert len(results) == 1
        assert not results[0].success
        assert "Test exception" in results[0].error

    @pytest.mark.asyncio
    async def test_no_affected_secrets(self, emergency_trigger):
        """Test event with no affected secrets."""
        event = SecurityEvent(
            event_type=CompromiseIndicator.SUSPICIOUS_ACCESS,
            threat_level=ThreatLevel.HIGH,
            description="Suspicious access",
            affected_resources=[],  # No resources
            timestamp=datetime.now(UTC).replace(tzinfo=None),
        )

        results = await emergency_trigger.on_security_event(event)

        assert len(results) == 0
        assert emergency_trigger.stats["emergency_rotations"] == 0

    @pytest.mark.asyncio
    async def test_secret_path_from_metadata(self, emergency_trigger):
        """Test extracting secret path from metadata."""
        event = SecurityEvent(
            event_type=CompromiseIndicator.MANUAL_TRIGGER,
            threat_level=ThreatLevel.HIGH,
            description="Test",
            timestamp=datetime.now(UTC).replace(tzinfo=None),
            metadata={"secret_path": "/secrets/from_metadata"},
        )

        results = await emergency_trigger.on_security_event(event)

        assert len(results) == 1
        assert results[0].secret_path == "/secrets/from_metadata"

    def test_get_statistics(self, emergency_trigger):
        """Test getting statistics."""
        stats = emergency_trigger.get_statistics()

        assert stats["total_events"] == 0
        assert stats["emergency_rotations"] == 0
        assert stats["successful_rotations"] == 0
        assert stats["failed_rotations"] == 0
        assert stats["success_rate"] == 0.0

    @pytest.mark.asyncio
    async def test_statistics_tracking(self, emergency_trigger):
        """Test statistics are tracked correctly."""
        event = SecurityEvent(
            event_type=CompromiseIndicator.MANUAL_TRIGGER,
            threat_level=ThreatLevel.HIGH,
            description="Test",
            affected_resources=["/secrets/test1", "/secrets/test2"],
            timestamp=datetime.now(UTC).replace(tzinfo=None),
        )

        await emergency_trigger.on_security_event(event)

        stats = emergency_trigger.get_statistics()
        assert stats["total_events"] == 1
        assert stats["emergency_rotations"] == 2
        assert stats["successful_rotations"] == 2
        assert stats["success_rate"] == 1.0

    def test_reset_statistics(self, emergency_trigger):
        """Test resetting statistics."""
        emergency_trigger.stats["total_events"] = 10
        emergency_trigger.stats["emergency_rotations"] = 5

        emergency_trigger.reset_statistics()

        stats = emergency_trigger.get_statistics()
        assert stats["total_events"] == 0
        assert stats["emergency_rotations"] == 0

    def test_format_notification_message(self, emergency_trigger):
        """Test formatting notification message."""
        event = SecurityEvent(
            event_type=CompromiseIndicator.LEAKED_CREDENTIAL,
            threat_level=ThreatLevel.CRITICAL,
            description="Credential leaked",
            source_ip="203.0.113.1",
            timestamp=datetime.now(UTC).replace(tzinfo=None),
            metadata={"repository": "test/repo"},
        )

        message = emergency_trigger._format_notification_message("/secrets/api_key", event)

        assert "Emergency Credential Rotation" in message
        assert "/secrets/api_key" in message
        assert "leaked_credential" in message
        assert "critical" in message
        assert "203.0.113.1" in message
        assert "repository: test/repo" in message

    @pytest.mark.asyncio
    async def test_monitor_audit_events_no_database(self, emergency_trigger):
        """Test monitoring without audit database."""
        results = await emergency_trigger.monitor_audit_events(lookback_minutes=15)

        assert len(results) == 0

    def test_analyze_events_failed_auth_spike(self, emergency_trigger):
        """Test analyzing events for failed auth spike."""
        events = [{"action": "authentication_failed"} for _ in range(15)]

        security_events = emergency_trigger._analyze_events_for_compromise(events)

        assert len(security_events) == 1
        assert security_events[0].event_type == CompromiseIndicator.FAILED_AUTH_SPIKE
        assert security_events[0].threat_level == ThreatLevel.HIGH

    def test_analyze_events_rate_limit_exceeded(self, emergency_trigger):
        """Test analyzing events for rate limit violations."""
        events = [{"action": "rate_limit_exceeded"} for _ in range(150)]

        security_events = emergency_trigger._analyze_events_for_compromise(events)

        assert len(security_events) == 1
        assert security_events[0].event_type == CompromiseIndicator.RATE_LIMIT_EXCEEDED

    def test_threshold_configuration(self, emergency_trigger):
        """Test threshold configuration."""
        assert emergency_trigger.thresholds["failed_auth_threshold"] == 10
        assert emergency_trigger.thresholds["rate_limit_threshold"] == 100

        # Modify thresholds
        emergency_trigger.thresholds["failed_auth_threshold"] = 20

        assert emergency_trigger.thresholds["failed_auth_threshold"] == 20


@pytest.mark.integration
class TestEmergencyRotationIntegration:
    """Integration tests for emergency rotation."""

    @pytest.mark.asyncio
    async def test_end_to_end_emergency_rotation(self):
        """Test complete emergency rotation workflow."""
        # Setup
        manager = MockRotationManager()
        notification_handler = MockNotificationHandler()
        trigger = EmergencyRotationTrigger(
            rotation_manager=manager,
            notification_handler=notification_handler,
        )

        # Create security event
        event = SecurityEvent(
            event_type=CompromiseIndicator.API_KEY_EXPOSED,
            threat_level=ThreatLevel.CRITICAL,
            description="API key found in public repository",
            affected_resources=["/secrets/production_api_key"],
            timestamp=datetime.now(UTC).replace(tzinfo=None),
            metadata={"repository": "user/sensitive-repo", "commit": "abc123def"},
        )

        # Trigger rotation
        results = await trigger.on_security_event(event)

        # Verify rotation occurred
        assert len(results) == 1
        assert results[0].success
        assert results[0].secret_path == "/secrets/production_api_key"

        # Verify notification sent
        assert len(notification_handler.notifications) == 1
        notification = notification_handler.notifications[0]
        assert notification["priority"] == "high"
        assert "/secrets/production_api_key" in notification["message"]

        # Verify statistics
        stats = trigger.get_statistics()
        assert stats["total_events"] == 1
        assert stats["emergency_rotations"] == 1
        assert stats["successful_rotations"] == 1
        assert stats["success_rate"] == 1.0

    @pytest.mark.asyncio
    async def test_multiple_events_multiple_secrets(self):
        """Test handling multiple security events."""
        manager = MockRotationManager()
        trigger = EmergencyRotationTrigger(rotation_manager=manager)

        # Event 1: Leaked credential
        event1 = SecurityEvent(
            event_type=CompromiseIndicator.LEAKED_CREDENTIAL,
            threat_level=ThreatLevel.CRITICAL,
            description="Credential leaked",
            affected_resources=["/secrets/key1"],
            timestamp=datetime.now(UTC).replace(tzinfo=None),
        )

        # Event 2: Brute force attack
        event2 = SecurityEvent(
            event_type=CompromiseIndicator.BRUTE_FORCE_ATTACK,
            threat_level=ThreatLevel.HIGH,
            description="Brute force detected",
            affected_resources=["/secrets/key2", "/secrets/key3"],
            timestamp=datetime.now(UTC).replace(tzinfo=None),
        )

        # Process both events
        results1 = await trigger.on_security_event(event1)
        results2 = await trigger.on_security_event(event2)

        # Verify all rotations
        assert len(results1) == 1
        assert len(results2) == 2
        assert all(r.success for r in results1 + results2)

        # Verify statistics
        stats = trigger.get_statistics()
        assert stats["total_events"] == 2
        assert stats["emergency_rotations"] == 3
        assert stats["successful_rotations"] == 3
