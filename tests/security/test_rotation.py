"""Tests for automatic credential rotation system."""

from datetime import datetime, timedelta

import pytest

from harombe.security.rotation import (
    RotationPolicy,
    RotationResult,
    RotationStatus,
    RotationStrategy,
    SecretGenerator,
    SecretRotationManager,
)


class MockVaultBackend:
    """Mock vault backend for testing."""

    def __init__(self):
        self.secrets = {}

    async def get_secret(self, key: str) -> str | None:
        return self.secrets.get(key)

    async def set_secret(self, key: str, value: str, **metadata) -> None:
        self.secrets[key] = value

    async def delete_secret(self, key: str) -> None:
        self.secrets.pop(key, None)


@pytest.fixture
def mock_vault():
    """Create mock vault backend."""
    return MockVaultBackend()


@pytest.fixture
def rotation_manager(mock_vault):
    """Create rotation manager instance."""
    return SecretRotationManager(vault_backend=mock_vault)


@pytest.fixture
def sample_policy():
    """Create sample rotation policy."""
    return RotationPolicy(
        name="test_policy",
        interval_days=30,
        strategy=RotationStrategy.STAGED,
        require_verification=False,
    )


class TestRotationStatus:
    """Test RotationStatus enum."""

    def test_status_values(self):
        """Test rotation status values."""
        assert RotationStatus.PENDING == "pending"
        assert RotationStatus.IN_PROGRESS == "in_progress"
        assert RotationStatus.VERIFYING == "verifying"
        assert RotationStatus.SUCCESS == "success"
        assert RotationStatus.FAILED == "failed"
        assert RotationStatus.ROLLED_BACK == "rolled_back"


class TestRotationStrategy:
    """Test RotationStrategy enum."""

    def test_strategy_values(self):
        """Test rotation strategy values."""
        assert RotationStrategy.IMMEDIATE == "immediate"
        assert RotationStrategy.STAGED == "staged"
        assert RotationStrategy.DUAL_WRITE == "dual_write"
        assert RotationStrategy.BLUE_GREEN == "blue_green"


class TestRotationPolicy:
    """Test RotationPolicy model."""

    def test_policy_creation(self):
        """Test creating rotation policy."""
        policy = RotationPolicy(
            name="daily",
            interval_days=1,
            strategy=RotationStrategy.STAGED,
            require_verification=True,
            verification_tests=["test1", "test2"],
        )

        assert policy.name == "daily"
        assert policy.interval_days == 1
        assert policy.strategy == RotationStrategy.STAGED
        assert policy.require_verification
        assert len(policy.verification_tests) == 2

    def test_policy_defaults(self):
        """Test policy default values."""
        policy = RotationPolicy(name="default", interval_days=90)

        assert policy.strategy == RotationStrategy.STAGED
        assert policy.require_verification
        assert policy.auto_rollback
        assert policy.max_retries == 3


class TestSecretGenerator:
    """Test SecretGenerator class."""

    def test_random_generator(self):
        """Test random secret generation."""
        generator = SecretGenerator(generator_type="random", length=32)
        secret = generator.generate()

        assert len(secret) == 32
        assert all(c in generator.charset for c in secret)

    def test_uuid_generator(self):
        """Test UUID generation."""
        generator = SecretGenerator(generator_type="uuid")
        secret = generator.generate()

        assert len(secret) == 36  # UUID format
        assert secret.count("-") == 4  # UUID dashes

    def test_hex_generator(self):
        """Test hex token generation."""
        generator = SecretGenerator(generator_type="hex", length=32)
        secret = generator.generate()

        assert len(secret) == 32
        assert all(c in "0123456789abcdef" for c in secret)

    def test_generator_uniqueness(self):
        """Test generated secrets are unique."""
        generator = SecretGenerator(generator_type="random", length=32)
        secrets = [generator.generate() for _ in range(10)]

        # All should be unique
        assert len(set(secrets)) == 10


class TestRotationResult:
    """Test RotationResult model."""

    def test_result_creation(self):
        """Test creating rotation result."""
        started = datetime.utcnow()
        result = RotationResult(
            success=True,
            secret_path="/secrets/test",
            old_version="abc123",
            new_version="def456",
            status=RotationStatus.SUCCESS,
            started_at=started,
            duration_ms=150.5,
        )

        assert result.success
        assert result.secret_path == "/secrets/test"
        assert result.old_version == "abc123"
        assert result.new_version == "def456"
        assert result.status == RotationStatus.SUCCESS
        assert result.duration_ms == 150.5


class TestSecretRotationManager:
    """Test SecretRotationManager class."""

    def test_initialization(self, rotation_manager, mock_vault):
        """Test manager initialization."""
        assert rotation_manager.vault == mock_vault
        assert rotation_manager.generator is not None
        assert rotation_manager.schedules == {}
        assert rotation_manager.active_rotations == {}

    def test_initialization_with_custom_generator(self, mock_vault):
        """Test initialization with custom generator."""
        generator = SecretGenerator(generator_type="uuid")
        manager = SecretRotationManager(vault_backend=mock_vault, generator=generator)

        assert manager.generator == generator
        assert manager.generator.generator_type == "uuid"

    @pytest.mark.asyncio
    async def test_rotate_secret_staged_strategy(self, rotation_manager, mock_vault, sample_policy):
        """Test staged secret rotation."""
        # Setup initial secret
        await mock_vault.set_secret("/secrets/api_key", "old_value")

        # Rotate
        result = await rotation_manager.rotate_secret("/secrets/api_key", sample_policy)

        # Verify result
        assert result.success
        assert result.status == RotationStatus.SUCCESS
        assert result.old_version is not None
        assert result.new_version is not None
        assert result.old_version != result.new_version

        # Verify new secret is in vault
        new_value = await mock_vault.get_secret("/secrets/api_key")
        assert new_value is not None
        assert new_value != "old_value"

        # Verify staging cleaned up
        staging_value = await mock_vault.get_secret("/secrets/api_key.staging")
        assert staging_value is None

    @pytest.mark.asyncio
    async def test_rotate_secret_immediate_strategy(self, rotation_manager, mock_vault):
        """Test immediate secret rotation."""
        # Setup initial secret
        await mock_vault.set_secret("/secrets/token", "old_token")

        # Create immediate policy
        policy = RotationPolicy(
            name="immediate",
            interval_days=0,
            strategy=RotationStrategy.IMMEDIATE,
            require_verification=False,
        )

        # Rotate
        result = await rotation_manager.rotate_secret("/secrets/token", policy)

        # Verify result
        assert result.success
        assert result.status == RotationStatus.SUCCESS

        # Verify new secret
        new_value = await mock_vault.get_secret("/secrets/token")
        assert new_value != "old_token"

    @pytest.mark.asyncio
    async def test_rotate_with_custom_value(self, rotation_manager, mock_vault, sample_policy):
        """Test rotation with provided value."""
        await mock_vault.set_secret("/secrets/custom", "old_value")

        # Rotate with custom value
        result = await rotation_manager.rotate_secret(
            "/secrets/custom", sample_policy, new_value="custom_new_value"
        )

        assert result.success
        new_value = await mock_vault.get_secret("/secrets/custom")
        assert new_value == "custom_new_value"

    @pytest.mark.asyncio
    async def test_concurrent_rotation_prevented(self, rotation_manager, mock_vault, sample_policy):
        """Test concurrent rotations are prevented."""
        await mock_vault.set_secret("/secrets/concurrent", "value")

        # Start first rotation (mark as active)
        rotation_manager.active_rotations["/secrets/concurrent"] = RotationResult(
            success=False,
            secret_path="/secrets/concurrent",
            status=RotationStatus.IN_PROGRESS,
            started_at=datetime.utcnow(),
        )

        # Try second rotation
        result = await rotation_manager.rotate_secret("/secrets/concurrent", sample_policy)

        assert not result.success
        assert result.status == RotationStatus.FAILED
        assert "already in progress" in result.error.lower()

    @pytest.mark.asyncio
    async def test_rotation_statistics_tracking(self, rotation_manager, mock_vault, sample_policy):
        """Test rotation statistics are tracked."""
        await mock_vault.set_secret("/secrets/stats1", "value1")
        await mock_vault.set_secret("/secrets/stats2", "value2")

        # Perform rotations
        await rotation_manager.rotate_secret("/secrets/stats1", sample_policy)
        await rotation_manager.rotate_secret("/secrets/stats2", sample_policy)

        stats = rotation_manager.get_statistics()

        assert stats["total_rotations"] == 2
        assert stats["successful_rotations"] == 2
        assert stats["failed_rotations"] == 0
        assert stats["success_rate"] == 1.0

    @pytest.mark.asyncio
    async def test_rotation_duration_tracking(self, rotation_manager, mock_vault, sample_policy):
        """Test rotation duration is tracked."""
        await mock_vault.set_secret("/secrets/duration", "value")

        result = await rotation_manager.rotate_secret("/secrets/duration", sample_policy)

        assert result.duration_ms is not None
        assert result.duration_ms > 0
        assert result.started_at is not None
        assert result.completed_at is not None

    def test_schedule_rotation(self, rotation_manager, sample_policy):
        """Test scheduling rotation."""
        schedule = rotation_manager.schedule_rotation("/secrets/scheduled", sample_policy)

        assert schedule.secret_path == "/secrets/scheduled"
        assert schedule.policy == sample_policy
        assert schedule.next_rotation > datetime.utcnow()
        assert schedule.enabled
        assert schedule.rotation_count == 0

        # Verify added to schedules
        assert "/secrets/scheduled" in rotation_manager.schedules

    def test_unschedule_rotation(self, rotation_manager, sample_policy):
        """Test unscheduling rotation."""
        rotation_manager.schedule_rotation("/secrets/to_remove", sample_policy)

        # Verify scheduled
        assert "/secrets/to_remove" in rotation_manager.schedules

        # Unschedule
        removed = rotation_manager.unschedule_rotation("/secrets/to_remove")

        assert removed
        assert "/secrets/to_remove" not in rotation_manager.schedules

    def test_unschedule_nonexistent(self, rotation_manager):
        """Test unscheduling nonexistent rotation."""
        removed = rotation_manager.unschedule_rotation("/secrets/nonexistent")
        assert not removed

    def test_get_schedule(self, rotation_manager, sample_policy):
        """Test getting rotation schedule."""
        original = rotation_manager.schedule_rotation("/secrets/get", sample_policy)
        retrieved = rotation_manager.get_schedule("/secrets/get")

        assert retrieved == original
        assert retrieved.secret_path == "/secrets/get"

    def test_get_nonexistent_schedule(self, rotation_manager):
        """Test getting nonexistent schedule."""
        schedule = rotation_manager.get_schedule("/secrets/nonexistent")
        assert schedule is None

    def test_list_schedules(self, rotation_manager, sample_policy):
        """Test listing schedules."""
        rotation_manager.schedule_rotation("/secrets/sched1", sample_policy)
        rotation_manager.schedule_rotation("/secrets/sched2", sample_policy)

        schedules = rotation_manager.list_schedules()

        assert len(schedules) == 2
        paths = [s.secret_path for s in schedules]
        assert "/secrets/sched1" in paths
        assert "/secrets/sched2" in paths

    @pytest.mark.asyncio
    async def test_process_scheduled_rotations_due(
        self, rotation_manager, mock_vault, sample_policy
    ):
        """Test processing due scheduled rotations."""
        await mock_vault.set_secret("/secrets/due", "value")

        # Schedule with past due time
        schedule = rotation_manager.schedule_rotation("/secrets/due", sample_policy)
        schedule.next_rotation = datetime.utcnow() - timedelta(hours=1)

        # Process
        results = await rotation_manager.process_scheduled_rotations()

        assert len(results) == 1
        assert results[0].success
        assert results[0].secret_path == "/secrets/due"

        # Verify schedule updated
        updated_schedule = rotation_manager.get_schedule("/secrets/due")
        assert updated_schedule.last_rotation is not None
        assert updated_schedule.rotation_count == 1
        assert updated_schedule.next_rotation > datetime.utcnow()

    @pytest.mark.asyncio
    async def test_process_scheduled_rotations_not_due(
        self, rotation_manager, mock_vault, sample_policy
    ):
        """Test processing schedules not yet due."""
        await mock_vault.set_secret("/secrets/not_due", "value")

        # Schedule in future
        schedule = rotation_manager.schedule_rotation("/secrets/not_due", sample_policy)
        schedule.next_rotation = datetime.utcnow() + timedelta(days=1)

        # Process
        results = await rotation_manager.process_scheduled_rotations()

        # No rotations should occur
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_process_disabled_schedule(self, rotation_manager, mock_vault, sample_policy):
        """Test disabled schedules are skipped."""
        await mock_vault.set_secret("/secrets/disabled", "value")

        # Schedule and disable
        schedule = rotation_manager.schedule_rotation("/secrets/disabled", sample_policy)
        schedule.next_rotation = datetime.utcnow() - timedelta(hours=1)
        schedule.enabled = False

        # Process
        results = await rotation_manager.process_scheduled_rotations()

        # Should not rotate disabled schedule
        assert len(results) == 0

    def test_get_statistics(self, rotation_manager):
        """Test getting statistics."""
        stats = rotation_manager.get_statistics()

        assert stats["total_rotations"] == 0
        assert stats["successful_rotations"] == 0
        assert stats["failed_rotations"] == 0
        assert stats["rollbacks"] == 0
        assert stats["success_rate"] == 0.0
        assert stats["active_schedules"] == 0
        assert stats["total_schedules"] == 0

    def test_reset_statistics(self, rotation_manager):
        """Test resetting statistics."""
        # Set some stats
        rotation_manager.stats["total_rotations"] = 10
        rotation_manager.stats["successful_rotations"] = 8

        # Reset
        rotation_manager.reset_statistics()

        stats = rotation_manager.get_statistics()
        assert stats["total_rotations"] == 0
        assert stats["successful_rotations"] == 0

    def test_version_identifier(self, rotation_manager):
        """Test version identifier generation."""
        v1 = rotation_manager._get_version_identifier("secret_value_1")
        v2 = rotation_manager._get_version_identifier("secret_value_2")
        v3 = rotation_manager._get_version_identifier("secret_value_1")  # Same as v1

        # Different values should have different identifiers
        assert v1 != v2

        # Same value should have same identifier
        assert v1 == v3

        # Should be 8 characters
        assert len(v1) == 8

    def test_version_identifier_none(self, rotation_manager):
        """Test version identifier for None value."""
        v = rotation_manager._get_version_identifier(None)
        assert v == "unknown"


@pytest.mark.integration
class TestRotationIntegration:
    """Integration tests for rotation manager."""

    @pytest.mark.asyncio
    async def test_end_to_end_rotation_workflow(self, mock_vault):
        """Test complete rotation workflow."""
        # Setup
        manager = SecretRotationManager(vault_backend=mock_vault)
        await mock_vault.set_secret("/prod/api_key", "initial_secret")

        # Create policy
        policy = RotationPolicy(
            name="production",
            interval_days=30,
            strategy=RotationStrategy.STAGED,
            require_verification=False,
        )

        # Schedule rotation
        schedule = manager.schedule_rotation("/prod/api_key", policy)
        assert schedule.enabled

        # Set as due
        schedule.next_rotation = datetime.utcnow() - timedelta(minutes=1)

        # Process scheduled rotations
        results = await manager.process_scheduled_rotations()

        assert len(results) == 1
        assert results[0].success

        # Verify new secret
        new_value = await mock_vault.get_secret("/prod/api_key")
        assert new_value != "initial_secret"

        # Verify schedule updated
        assert schedule.rotation_count == 1
        assert schedule.last_rotation is not None

    @pytest.mark.asyncio
    async def test_multiple_scheduled_rotations(self, mock_vault):
        """Test multiple scheduled rotations."""
        manager = SecretRotationManager(vault_backend=mock_vault)

        # Setup multiple secrets
        secrets = ["/secrets/key1", "/secrets/key2", "/secrets/key3"]
        for secret in secrets:
            await mock_vault.set_secret(secret, f"value_{secret}")

        # Schedule all
        policy = RotationPolicy(
            name="batch",
            interval_days=7,
            strategy=RotationStrategy.IMMEDIATE,
            require_verification=False,
        )

        for secret in secrets:
            schedule = manager.schedule_rotation(secret, policy)
            schedule.next_rotation = datetime.utcnow() - timedelta(hours=1)

        # Process all
        results = await manager.process_scheduled_rotations()

        assert len(results) == 3
        assert all(r.success for r in results)

        # Verify all rotated
        for secret in secrets:
            new_value = await mock_vault.get_secret(secret)
            assert new_value != f"value_{secret}"


@pytest.mark.integration
class TestZeroDowntimeRotation:
    """Integration tests for zero-downtime rotation strategies."""

    @pytest.mark.asyncio
    async def test_dual_write_rotation_success(self, mock_vault):
        """Test successful dual-write rotation."""
        manager = SecretRotationManager(vault_backend=mock_vault)
        await mock_vault.set_secret("/secrets/api_key", "old_key_value")

        # Create dual-write policy
        policy = RotationPolicy(
            name="dual_write",
            interval_days=90,
            strategy=RotationStrategy.DUAL_WRITE,
            require_verification=False,
            metadata={"migration_timeout_seconds": 1},  # Short timeout for testing
        )

        # Rotate
        result = await manager.rotate_secret("/secrets/api_key", policy)

        # Verify result
        assert result.success
        assert result.status == RotationStatus.SUCCESS
        assert result.old_version != result.new_version

        # Verify new secret is in place
        new_value = await mock_vault.get_secret("/secrets/api_key")
        assert new_value is not None
        assert new_value != "old_key_value"

    @pytest.mark.asyncio
    async def test_dual_write_rotation_with_verification(self, mock_vault):
        """Test dual-write rotation with verification."""
        manager = SecretRotationManager(vault_backend=mock_vault)
        await mock_vault.set_secret("/secrets/verified_key", "old_verified")

        policy = RotationPolicy(
            name="dual_write_verified",
            interval_days=90,
            strategy=RotationStrategy.DUAL_WRITE,
            require_verification=True,
            verification_tests=["api_test"],
            metadata={"migration_timeout_seconds": 1},
        )

        result = await manager.rotate_secret("/secrets/verified_key", policy)

        assert result.success
        assert result.verification_passed or result.verification_passed is None

    @pytest.mark.asyncio
    async def test_dual_write_rotation_rollback(self, mock_vault):
        """Test dual-write rotation rollback on verification failure."""
        manager = SecretRotationManager(vault_backend=mock_vault)
        await mock_vault.set_secret("/secrets/fail_key", "old_fail_value")

        # Mock verification to fail
        async def _failing_verify(secret_path, policy):
            return False

        manager._verify_secret = _failing_verify

        policy = RotationPolicy(
            name="dual_write_fail",
            interval_days=90,
            strategy=RotationStrategy.DUAL_WRITE,
            require_verification=True,
            auto_rollback=True,
            metadata={"migration_timeout_seconds": 1},
        )

        result = await manager.rotate_secret("/secrets/fail_key", policy)

        # Should fail and rollback
        assert not result.success
        assert result.status == RotationStatus.FAILED

        # Old value should be preserved
        current_value = await mock_vault.get_secret("/secrets/fail_key")
        assert current_value == "old_fail_value"

    @pytest.mark.asyncio
    async def test_blue_green_rotation_success(self, mock_vault):
        """Test successful blue-green rotation."""
        manager = SecretRotationManager(vault_backend=mock_vault)
        await mock_vault.set_secret("/secrets/bg_key", "blue_value")

        # Create blue-green policy
        policy = RotationPolicy(
            name="blue_green",
            interval_days=90,
            strategy=RotationStrategy.BLUE_GREEN,
            require_verification=False,
            metadata={"current_environment": "blue"},
        )

        # Rotate
        result = await manager.rotate_secret("/secrets/bg_key", policy)

        # Verify result
        assert result.success
        assert result.status == RotationStatus.SUCCESS
        assert result.old_version != result.new_version

        # Verify new secret is in place
        new_value = await mock_vault.get_secret("/secrets/bg_key")
        assert new_value is not None
        assert new_value != "blue_value"

        # Verify green environment was created
        green_value = await mock_vault.get_secret("/secrets/bg_key.green")
        assert green_value is not None

    @pytest.mark.asyncio
    async def test_blue_green_rotation_with_verification(self, mock_vault):
        """Test blue-green rotation with verification."""
        manager = SecretRotationManager(vault_backend=mock_vault)
        await mock_vault.set_secret("/secrets/bg_verified", "current_blue")

        policy = RotationPolicy(
            name="blue_green_verified",
            interval_days=90,
            strategy=RotationStrategy.BLUE_GREEN,
            require_verification=True,
            verification_tests=["environment_test"],
            metadata={"current_environment": "blue"},
        )

        result = await manager.rotate_secret("/secrets/bg_verified", policy)

        assert result.success
        assert result.verification_passed or result.verification_passed is None

    @pytest.mark.asyncio
    async def test_blue_green_rotation_rollback(self, mock_vault):
        """Test blue-green rotation rollback on verification failure."""
        manager = SecretRotationManager(vault_backend=mock_vault)
        await mock_vault.set_secret("/secrets/bg_fail", "blue_original")

        # Mock verification to fail
        async def _failing_verify(secret_path, policy):
            return False

        manager._verify_secret = _failing_verify

        policy = RotationPolicy(
            name="blue_green_fail",
            interval_days=90,
            strategy=RotationStrategy.BLUE_GREEN,
            require_verification=True,
            auto_rollback=True,
            metadata={"current_environment": "blue"},
        )

        result = await manager.rotate_secret("/secrets/bg_fail", policy)

        # Should fail and rollback
        assert not result.success
        assert result.status == RotationStatus.FAILED

        # Original value should be preserved
        current_value = await mock_vault.get_secret("/secrets/bg_fail")
        assert current_value == "blue_original"

        # Green environment should be cleaned up
        green_value = await mock_vault.get_secret("/secrets/bg_fail.green")
        assert green_value is None

    @pytest.mark.asyncio
    async def test_blue_green_toggle_between_environments(self, mock_vault):
        """Test toggling between blue and green environments."""
        manager = SecretRotationManager(vault_backend=mock_vault)
        await mock_vault.set_secret("/secrets/toggle", "initial_value")

        # First rotation: blue → green
        policy_blue_to_green = RotationPolicy(
            name="to_green",
            interval_days=90,
            strategy=RotationStrategy.BLUE_GREEN,
            require_verification=False,
            metadata={"current_environment": "blue"},
        )

        result1 = await manager.rotate_secret("/secrets/toggle", policy_blue_to_green)
        assert result1.success

        # Second rotation: green → blue
        policy_green_to_blue = RotationPolicy(
            name="to_blue",
            interval_days=90,
            strategy=RotationStrategy.BLUE_GREEN,
            require_verification=False,
            metadata={"current_environment": "green"},
        )

        result2 = await manager.rotate_secret("/secrets/toggle", policy_green_to_blue)
        assert result2.success

        # Values should be different each time
        assert result1.new_version != result2.new_version

    @pytest.mark.asyncio
    async def test_concurrent_dual_write_prevented(self, rotation_manager, mock_vault):
        """Test concurrent dual-write rotations are prevented."""
        await mock_vault.set_secret("/secrets/concurrent_dw", "value")

        policy = RotationPolicy(
            name="concurrent_dual",
            interval_days=0,
            strategy=RotationStrategy.DUAL_WRITE,
            require_verification=False,
            metadata={"migration_timeout_seconds": 1},
        )

        # Mark as active
        rotation_manager.active_rotations["/secrets/concurrent_dw"] = RotationResult(
            success=False,
            secret_path="/secrets/concurrent_dw",
            status=RotationStatus.IN_PROGRESS,
            started_at=datetime.utcnow(),
        )

        # Try second rotation
        result = await rotation_manager.rotate_secret("/secrets/concurrent_dw", policy)

        assert not result.success
        assert result.status == RotationStatus.FAILED
        assert "already in progress" in result.error.lower()

    @pytest.mark.asyncio
    async def test_dual_write_statistics_tracking(self, rotation_manager, mock_vault):
        """Test statistics tracking for dual-write rotations."""
        await mock_vault.set_secret("/secrets/stats_dw", "value")

        policy = RotationPolicy(
            name="stats_dual",
            interval_days=0,
            strategy=RotationStrategy.DUAL_WRITE,
            require_verification=False,
            metadata={"migration_timeout_seconds": 1},
        )

        result = await rotation_manager.rotate_secret("/secrets/stats_dw", policy)

        assert result.success

        stats = rotation_manager.get_statistics()
        assert stats["total_rotations"] >= 1
        assert stats["successful_rotations"] >= 1


class TestConsumerTracking:
    """Tests for consumer tracking during zero-downtime rotation."""

    def test_consumer_status_creation(self):
        """Test creating consumer status."""
        from harombe.security.rotation import ConsumerStatus

        status = ConsumerStatus(
            consumer_id="service-1",
            secret_version="old",
            last_heartbeat=datetime.utcnow(),
            migration_status="pending",
        )

        assert status.consumer_id == "service-1"
        assert status.secret_version == "old"
        assert status.migration_status == "pending"

    def test_dual_mode_config_creation(self):
        """Test creating dual-mode configuration."""
        from harombe.security.rotation import ConsumerStatus, DualModeConfig

        consumers = [
            ConsumerStatus(
                consumer_id="svc1",
                secret_version="old",
                last_heartbeat=datetime.utcnow(),
            ),
            ConsumerStatus(
                consumer_id="svc2",
                secret_version="new",
                last_heartbeat=datetime.utcnow(),
            ),
        ]

        config = DualModeConfig(
            old_value="old_secret",
            new_value="new_secret",
            enabled_at=datetime.utcnow(),
            consumers=consumers,
        )

        assert config.old_value == "old_secret"
        assert config.new_value == "new_secret"
        assert len(config.consumers) == 2
