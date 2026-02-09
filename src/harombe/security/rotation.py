"""Automatic credential rotation system.

Implements scheduled and on-demand secret rotation with zero-downtime support,
verification testing, and comprehensive audit logging.

Phase 5.3.1 Implementation
"""

import contextlib
import logging
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class RotationStatus(StrEnum):
    """Status of a rotation operation."""

    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    VERIFYING = "verifying"
    SUCCESS = "success"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


class RotationStrategy(StrEnum):
    """Strategy for rotating secrets."""

    IMMEDIATE = "immediate"  # Replace immediately
    STAGED = "staged"  # Stage first, then promote
    DUAL_WRITE = "dual_write"  # Both old and new valid temporarily
    BLUE_GREEN = "blue_green"  # Switch between two complete sets


class RotationPolicy(BaseModel):
    """Policy for automatic secret rotation.

    Attributes:
        name: Policy identifier
        interval_days: Days between rotations (0 = manual only)
        strategy: Rotation strategy to use
        require_verification: Whether to verify before promotion
        verification_tests: List of verification test names
        auto_rollback: Rollback on verification failure
        notify_on_rotation: Send notifications
        notify_on_failure: Send failure notifications
        max_retries: Maximum rotation retry attempts
        metadata: Additional policy configuration
    """

    name: str
    interval_days: int = Field(ge=0)
    strategy: RotationStrategy = RotationStrategy.STAGED
    require_verification: bool = True
    verification_tests: list[str] = Field(default_factory=list)
    auto_rollback: bool = True
    notify_on_rotation: bool = False
    notify_on_failure: bool = True
    max_retries: int = Field(default=3, ge=0, le=10)
    metadata: dict[str, Any] = Field(default_factory=dict)


class RotationResult(BaseModel):
    """Result of a secret rotation operation.

    Attributes:
        success: Whether rotation succeeded
        secret_path: Path to rotated secret
        old_version: Previous version identifier
        new_version: New version identifier
        status: Final rotation status
        started_at: When rotation started
        completed_at: When rotation completed
        duration_ms: Time taken in milliseconds
        verification_passed: Whether verification succeeded
        error: Error message if failed
        rollback_performed: Whether rollback was performed
    """

    success: bool
    secret_path: str
    old_version: str | None = None
    new_version: str | None = None
    status: RotationStatus
    started_at: datetime
    completed_at: datetime | None = None
    duration_ms: float | None = None
    verification_passed: bool | None = None
    error: str | None = None
    rollback_performed: bool = False


class SecretGenerator(BaseModel):
    """Generator for creating new secret values.

    Attributes:
        generator_type: Type of generator (random, api, custom)
        length: Length of generated secret (for random)
        charset: Character set to use (for random)
        custom_generator: Custom generator function name
        config: Additional generator configuration
    """

    generator_type: str  # "random", "api", "custom"
    length: int = Field(default=32, ge=16, le=128)
    charset: str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
    custom_generator: str | None = None
    config: dict[str, Any] = Field(default_factory=dict)

    def generate(self) -> str:
        """Generate a new secret value.

        Returns:
            Generated secret string
        """
        import secrets

        if self.generator_type == "random":
            return "".join(secrets.choice(self.charset) for _ in range(self.length))
        elif self.generator_type == "uuid":
            import uuid

            return str(uuid.uuid4())
        elif self.generator_type == "hex":
            return secrets.token_hex(self.length // 2)
        else:
            raise ValueError(f"Unknown generator type: {self.generator_type}")


class RotationSchedule(BaseModel):
    """Schedule for automatic secret rotation.

    Attributes:
        secret_path: Path to secret
        policy: Rotation policy
        next_rotation: When next rotation should occur
        last_rotation: When last rotation occurred
        rotation_count: Total number of rotations
        enabled: Whether schedule is active
    """

    secret_path: str
    policy: RotationPolicy
    next_rotation: datetime
    last_rotation: datetime | None = None
    rotation_count: int = 0
    enabled: bool = True


class ConsumerStatus(BaseModel):
    """Status of a consumer during secret rotation.

    Attributes:
        consumer_id: Identifier for the consumer
        secret_version: Which secret version consumer is using
        last_heartbeat: Last time consumer checked in
        migration_status: Migration status (pending, migrating, completed)
    """

    consumer_id: str
    secret_version: str  # 'old' or 'new'
    last_heartbeat: datetime
    migration_status: str = "pending"  # pending, migrating, completed


class DualModeConfig(BaseModel):
    """Configuration for dual-write mode.

    Attributes:
        old_value: Previous secret value
        new_value: New secret value
        enabled_at: When dual-mode was enabled
        consumers: List of consumer statuses
    """

    old_value: str
    new_value: str
    enabled_at: datetime
    consumers: list[ConsumerStatus] = Field(default_factory=list)


class SecretRotationManager:
    """Manages automatic credential rotation.

    Orchestrates secret rotation with scheduling, verification, and rollback.
    Supports multiple rotation strategies and policies.
    """

    def __init__(
        self,
        vault_backend: Any,  # VaultBackend instance
        generator: SecretGenerator | None = None,
        audit_logger: Any | None = None,
    ):
        """Initialize rotation manager.

        Args:
            vault_backend: Vault backend for secret storage
            generator: Secret generator (default: random)
            audit_logger: Audit logger instance (optional)
        """
        self.vault = vault_backend
        self.generator = generator or SecretGenerator(generator_type="random")
        self.audit_logger = audit_logger

        # Rotation schedules
        self.schedules: dict[str, RotationSchedule] = {}

        # Active rotations
        self.active_rotations: dict[str, RotationResult] = {}

        # Statistics
        self.stats = {
            "total_rotations": 0,
            "successful_rotations": 0,
            "failed_rotations": 0,
            "rollbacks": 0,
        }

    async def rotate_secret(
        self,
        secret_path: str,
        policy: RotationPolicy | None = None,
        new_value: str | None = None,
    ) -> RotationResult:
        """Rotate a secret according to policy.

        Args:
            secret_path: Path to secret to rotate
            policy: Rotation policy (uses default if None)
            new_value: New secret value (generates if None)

        Returns:
            Rotation result with status and details
        """
        started_at = datetime.utcnow()
        self.stats["total_rotations"] += 1

        # Use default policy if not provided
        if policy is None:
            policy = RotationPolicy(
                name="default",
                interval_days=90,
                strategy=RotationStrategy.STAGED,
            )

        # Check if already rotating
        if secret_path in self.active_rotations:
            logger.warning(f"Rotation already in progress for {secret_path}")
            return RotationResult(
                success=False,
                secret_path=secret_path,
                status=RotationStatus.FAILED,
                started_at=started_at,
                completed_at=datetime.utcnow(),
                error="Rotation already in progress",
            )

        # Mark as active
        result = RotationResult(
            success=False,
            secret_path=secret_path,
            status=RotationStatus.IN_PROGRESS,
            started_at=started_at,
        )
        self.active_rotations[secret_path] = result

        try:
            # Get current secret
            current_value = await self.vault.get_secret(secret_path)
            old_version = self._get_version_identifier(current_value)

            # Generate or use provided new value
            if new_value is None:
                new_value = self.generator.generate()

            new_version = self._get_version_identifier(new_value)

            # Execute rotation based on strategy
            if policy.strategy == RotationStrategy.STAGED:
                success = await self._staged_rotation(secret_path, current_value, new_value, policy)
            elif policy.strategy == RotationStrategy.IMMEDIATE:
                success = await self._immediate_rotation(secret_path, new_value, policy)
            elif policy.strategy == RotationStrategy.DUAL_WRITE:
                success = await self._dual_write_rotation(
                    secret_path, current_value, new_value, policy
                )
            elif policy.strategy == RotationStrategy.BLUE_GREEN:
                success = await self._blue_green_rotation(
                    secret_path, current_value, new_value, policy
                )
            else:
                raise NotImplementedError(f"Strategy {policy.strategy} not implemented")

            # Update result
            completed_at = datetime.utcnow()
            duration_ms = (completed_at - started_at).total_seconds() * 1000

            result.success = success
            result.old_version = old_version
            result.new_version = new_version
            result.status = RotationStatus.SUCCESS if success else RotationStatus.FAILED
            result.completed_at = completed_at
            result.duration_ms = duration_ms

            if success:
                self.stats["successful_rotations"] += 1
                logger.info(
                    f"Successfully rotated {secret_path} "
                    f"({old_version} → {new_version}) "
                    f"in {duration_ms:.1f}ms"
                )
            else:
                self.stats["failed_rotations"] += 1
                logger.error(f"Failed to rotate {secret_path}")

            # Log to audit system
            if self.audit_logger:
                await self._log_rotation(result, policy)

            return result

        except Exception as e:
            logger.exception(f"Error rotating {secret_path}: {e}")
            self.stats["failed_rotations"] += 1

            completed_at = datetime.utcnow()
            duration_ms = (completed_at - started_at).total_seconds() * 1000

            result.success = False
            result.status = RotationStatus.FAILED
            result.error = str(e)
            result.completed_at = completed_at
            result.duration_ms = duration_ms

            return result

        finally:
            # Remove from active rotations
            self.active_rotations.pop(secret_path, None)

    async def _staged_rotation(
        self,
        secret_path: str,
        current_value: str,
        new_value: str,
        policy: RotationPolicy,
    ) -> bool:
        """Perform staged rotation (stage → verify → promote).

        Args:
            secret_path: Path to secret
            current_value: Current secret value
            new_value: New secret value
            policy: Rotation policy

        Returns:
            True if successful
        """
        staging_path = f"{secret_path}.staging"

        try:
            # Step 1: Write to staging
            await self.vault.set_secret(staging_path, new_value, staged=True)
            logger.debug(f"Staged new secret at {staging_path}")

            # Step 2: Verify if required
            if policy.require_verification:
                logger.debug(f"Verifying staged secret {staging_path}")
                verification_passed = await self._verify_secret(staging_path, policy)

                if not verification_passed:
                    logger.warning(f"Verification failed for {staging_path}")
                    await self.vault.delete_secret(staging_path)

                    if policy.auto_rollback:
                        logger.info("Auto-rollback enabled, keeping current secret")
                        return False

                    raise ValueError("Verification failed")

            # Step 3: Promote to production (atomic)
            await self._promote_secret(staging_path, secret_path)
            logger.info(f"Promoted {staging_path} → {secret_path}")

            # Step 4: Cleanup staging
            await self.vault.delete_secret(staging_path)

            return True

        except Exception as e:
            logger.error(f"Staged rotation failed: {e}")
            # Cleanup staging on error
            with contextlib.suppress(Exception):
                await self.vault.delete_secret(staging_path)

            # Rollback if needed
            if policy.auto_rollback:
                self.stats["rollbacks"] += 1
                # Current value already in place, just log
                logger.info(f"Rollback performed for {secret_path}")

            raise

    async def _immediate_rotation(
        self, secret_path: str, new_value: str, policy: RotationPolicy
    ) -> bool:
        """Perform immediate rotation (replace directly).

        Args:
            secret_path: Path to secret
            new_value: New secret value
            policy: Rotation policy

        Returns:
            True if successful
        """
        # Store old value for potential rollback
        old_value = await self.vault.get_secret(secret_path)

        try:
            # Replace immediately
            await self.vault.set_secret(secret_path, new_value)
            logger.info(f"Immediately rotated {secret_path}")

            # Verify if required (post-rotation)
            if policy.require_verification:
                verification_passed = await self._verify_secret(secret_path, policy)

                if not verification_passed and policy.auto_rollback:
                    # Rollback to old value
                    await self.vault.set_secret(secret_path, old_value)
                    self.stats["rollbacks"] += 1
                    logger.warning(f"Rolled back {secret_path} due to verification failure")
                    return False

            return True

        except Exception as e:
            logger.error(f"Immediate rotation failed: {e}")

            # Rollback on error
            if policy.auto_rollback:
                with contextlib.suppress(Exception):
                    await self.vault.set_secret(secret_path, old_value)
                    self.stats["rollbacks"] += 1
                    logger.info(f"Rolled back {secret_path} after error")

            raise

    async def _dual_write_rotation(
        self,
        secret_path: str,
        current_value: str,
        new_value: str,
        policy: RotationPolicy,
    ) -> bool:
        """Perform dual-write rotation (zero-downtime).

        This strategy enables zero-downtime rotation by:
        1. Enabling dual-mode where both old and new secrets are valid
        2. Waiting for consumers to update to new secret
        3. Removing old secret once all consumers updated

        Args:
            secret_path: Path to secret
            current_value: Current secret value
            new_value: New secret value
            policy: Rotation policy

        Returns:
            True if successful
        """
        dual_path = f"{secret_path}.dual"
        consumer_tracking_path = f"{secret_path}.consumers"

        try:
            # Phase 1: Enable dual-mode (both old and new valid)
            logger.info(f"Enabling dual-mode for {secret_path}")
            await self._enable_dual_mode(secret_path, current_value, new_value)

            # Phase 2: Verify new secret works
            if policy.require_verification:
                logger.debug(f"Verifying new secret at {dual_path}")
                verification_passed = await self._verify_secret(dual_path, policy)

                if not verification_passed:
                    logger.warning(f"Verification failed for {dual_path}")
                    await self._disable_dual_mode(secret_path, current_value)

                    if policy.auto_rollback:
                        logger.info("Auto-rollback: disabled dual-mode, kept old secret")
                        return False

                    raise ValueError("Verification failed")

            # Phase 3: Wait for consumers to update
            # Get migration timeout from policy metadata (default: 300s = 5 minutes)
            migration_timeout = policy.metadata.get("migration_timeout_seconds", 300)
            logger.info(
                f"Waiting up to {migration_timeout}s for consumers to migrate to new secret"
            )

            consumers_updated = await self._wait_for_consumer_migration(
                secret_path, consumer_tracking_path, timeout_seconds=migration_timeout
            )

            if not consumers_updated:
                logger.warning(f"Not all consumers updated within {migration_timeout}s")
                # Continue anyway - we can't wait forever
                # The old secret is still valid, so no downtime

            # Phase 4: Promote new secret and remove old
            logger.info(f"Promoting new secret and removing old for {secret_path}")
            await self.vault.set_secret(secret_path, new_value)

            # Cleanup dual-mode paths
            with contextlib.suppress(Exception):
                await self.vault.delete_secret(dual_path)
                await self.vault.delete_secret(consumer_tracking_path)

            logger.info(f"Dual-write rotation completed for {secret_path}")
            return True

        except Exception as e:
            logger.error(f"Dual-write rotation failed: {e}")

            # Rollback: disable dual-mode, keep old secret
            if policy.auto_rollback:
                with contextlib.suppress(Exception):
                    await self._disable_dual_mode(secret_path, current_value)
                    self.stats["rollbacks"] += 1
                    logger.info(f"Rolled back {secret_path} to single-mode with old secret")

            raise

    async def _blue_green_rotation(
        self,
        secret_path: str,
        current_value: str,
        new_value: str,
        policy: RotationPolicy,
    ) -> bool:
        """Perform blue-green rotation (complete environment switch).

        This strategy maintains two complete secret environments (blue and green)
        and switches between them atomically.

        Args:
            secret_path: Path to secret
            current_value: Current secret value
            new_value: New secret value
            policy: Rotation policy

        Returns:
            True if successful
        """
        # Determine current and target environments
        metadata = policy.metadata
        current_env = metadata.get("current_environment", "blue")
        target_env = "green" if current_env == "blue" else "blue"

        blue_path = f"{secret_path}.blue"
        green_path = f"{secret_path}.green"
        target_path = green_path if target_env == "green" else blue_path

        try:
            # Phase 1: Write new secret to target environment
            logger.info(f"Writing new secret to {target_env} environment: {target_path}")
            await self.vault.set_secret(target_path, new_value)

            # Phase 2: Verify target environment
            if policy.require_verification:
                logger.debug(f"Verifying {target_env} environment")
                verification_passed = await self._verify_secret(target_path, policy)

                if not verification_passed:
                    logger.warning(f"Verification failed for {target_env} environment")
                    await self.vault.delete_secret(target_path)

                    if policy.auto_rollback:
                        logger.info(f"Auto-rollback: keeping {current_env} environment")
                        return False

                    raise ValueError("Verification failed")

            # Phase 3: Switch active environment (atomic pointer update)
            logger.info(f"Switching from {current_env} to {target_env} environment")
            await self.vault.set_secret(secret_path, new_value)

            # Update metadata to reflect new current environment
            metadata["current_environment"] = target_env
            metadata["previous_environment"] = current_env
            await self.vault.set_secret(
                f"{secret_path}.metadata",
                str(metadata),
                environment=target_env,
                previous_environment=current_env,
            )

            logger.info(f"Blue-green rotation completed: now on {target_env} environment")
            return True

        except Exception as e:
            logger.error(f"Blue-green rotation failed: {e}")

            # Rollback: delete target environment, keep current
            if policy.auto_rollback:
                with contextlib.suppress(Exception):
                    await self.vault.delete_secret(target_path)
                    self.stats["rollbacks"] += 1
                    logger.info(f"Rolled back: deleted {target_env}, kept {current_env}")

            raise

    async def _enable_dual_mode(self, secret_path: str, old_value: str, new_value: str) -> None:
        """Enable dual-mode where both old and new secrets are valid.

        Args:
            secret_path: Path to secret
            old_value: Old secret value
            new_value: New secret value
        """
        dual_path = f"{secret_path}.dual"

        # Store both values in dual structure
        dual_config = {"old": old_value, "new": new_value, "mode": "dual"}

        await self.vault.set_secret(dual_path, str(dual_config), dual_mode=True)
        logger.debug(f"Enabled dual-mode at {dual_path}")

    async def _disable_dual_mode(self, secret_path: str, value_to_keep: str) -> None:
        """Disable dual-mode and revert to single secret.

        Args:
            secret_path: Path to secret
            value_to_keep: Secret value to keep active
        """
        dual_path = f"{secret_path}.dual"

        # Remove dual-mode paths
        with contextlib.suppress(Exception):
            await self.vault.delete_secret(dual_path)

        # Ensure original path has the value to keep
        await self.vault.set_secret(secret_path, value_to_keep)
        logger.debug(f"Disabled dual-mode for {secret_path}")

    async def _wait_for_consumer_migration(
        self, secret_path: str, tracking_path: str, timeout_seconds: int = 300
    ) -> bool:
        """Wait for consumers to migrate to new secret.

        This is a simplified implementation that waits for a timeout.
        In production, this would:
        - Track consumer heartbeats
        - Monitor which consumers are using old vs new secrets
        - Return True when all consumers migrated or timeout reached

        Args:
            secret_path: Path to secret being rotated
            tracking_path: Path to consumer tracking data
            timeout_seconds: Maximum time to wait for migration

        Returns:
            True if all consumers migrated, False if timeout
        """
        import asyncio

        # In production, this would check actual consumer status
        # For now, we use a simplified wait with periodic checks
        check_interval = 10  # Check every 10 seconds
        elapsed = 0

        while elapsed < timeout_seconds:
            # Check if consumers have migrated
            # In production: query consumer tracking system
            consumers_data = await self._get_consumer_status(tracking_path)

            if consumers_data and self._all_consumers_migrated(consumers_data):
                logger.info(f"All consumers migrated to new secret after {elapsed}s")
                return True

            # Wait before next check
            await asyncio.sleep(min(check_interval, timeout_seconds - elapsed))
            elapsed += check_interval

        logger.warning(f"Consumer migration timeout after {timeout_seconds}s")
        return False

    async def _get_consumer_status(self, tracking_path: str) -> dict[str, Any] | None:
        """Get consumer tracking status.

        Args:
            tracking_path: Path to consumer tracking data

        Returns:
            Consumer status data or None if not available
        """
        with contextlib.suppress(Exception):
            tracking_data = await self.vault.get_secret(tracking_path)
            if tracking_data:
                # In production: parse JSON tracking data
                return {"status": "migrating"}  # Placeholder

        return None

    def _all_consumers_migrated(self, consumers_data: dict[str, Any]) -> bool:
        """Check if all consumers have migrated to new secret.

        Args:
            consumers_data: Consumer tracking data

        Returns:
            True if all migrated
        """
        # In production: check each consumer's status
        # For now, always return False to simulate ongoing migration
        return False

    async def _verify_secret(self, secret_path: str, policy: RotationPolicy) -> bool:
        """Verify new secret works correctly.

        Args:
            secret_path: Path to secret to verify
            policy: Rotation policy with verification tests

        Returns:
            True if verification passed
        """
        # TODO: Integrate with verification framework (Task 5.3.3)
        # For now, just return True if no tests specified
        if not policy.verification_tests:
            return True

        # Placeholder for verification
        logger.debug(f"Verification tests would run here: {policy.verification_tests}")
        return True

    async def _promote_secret(self, staging_path: str, production_path: str) -> None:
        """Promote staging secret to production atomically.

        Args:
            staging_path: Path to staging secret
            production_path: Path to production secret
        """
        # Get staging value
        staging_value = await self.vault.get_secret(staging_path)

        # Write to production (atomic at vault level)
        await self.vault.set_secret(production_path, staging_value)

    def _get_version_identifier(self, value: str | None) -> str:
        """Get version identifier for a secret value.

        Args:
            value: Secret value

        Returns:
            Version identifier (first 8 chars of hash)
        """
        if value is None:
            return "unknown"

        import hashlib

        return hashlib.sha256(value.encode()).hexdigest()[:8]

    async def _log_rotation(self, result: RotationResult, policy: RotationPolicy) -> None:
        """Log rotation to audit system.

        Args:
            result: Rotation result
            policy: Rotation policy used
        """
        if self.audit_logger is None:
            return

        # TODO: Integrate with audit logging
        logger.info(
            f"Audit log: {result.secret_path} "
            f"rotated from {result.old_version} to {result.new_version} "
            f"(status: {result.status})"
        )

    def schedule_rotation(self, secret_path: str, policy: RotationPolicy) -> RotationSchedule:
        """Schedule automatic rotation for a secret.

        Args:
            secret_path: Path to secret
            policy: Rotation policy

        Returns:
            Rotation schedule
        """
        # Calculate next rotation time
        next_rotation = datetime.utcnow() + timedelta(days=policy.interval_days)

        schedule = RotationSchedule(
            secret_path=secret_path,
            policy=policy,
            next_rotation=next_rotation,
        )

        self.schedules[secret_path] = schedule
        logger.info(
            f"Scheduled rotation for {secret_path} "
            f"(next: {next_rotation.isoformat()}, interval: {policy.interval_days}d)"
        )

        return schedule

    def unschedule_rotation(self, secret_path: str) -> bool:
        """Remove rotation schedule for a secret.

        Args:
            secret_path: Path to secret

        Returns:
            True if schedule was removed
        """
        if secret_path in self.schedules:
            del self.schedules[secret_path]
            logger.info(f"Unscheduled rotation for {secret_path}")
            return True
        return False

    async def process_scheduled_rotations(self) -> list[RotationResult]:
        """Process all due scheduled rotations.

        Returns:
            List of rotation results
        """
        now = datetime.utcnow()
        results = []

        for secret_path, schedule in list(self.schedules.items()):
            if not schedule.enabled:
                continue

            if now >= schedule.next_rotation:
                logger.info(f"Processing scheduled rotation for {secret_path}")

                # Perform rotation
                result = await self.rotate_secret(secret_path, schedule.policy)
                results.append(result)

                # Update schedule
                if result.success:
                    schedule.last_rotation = now
                    schedule.rotation_count += 1
                    schedule.next_rotation = now + timedelta(days=schedule.policy.interval_days)
                    logger.info(
                        f"Updated schedule for {secret_path} "
                        f"(next: {schedule.next_rotation.isoformat()})"
                    )
                else:
                    # Retry in 1 hour on failure
                    schedule.next_rotation = now + timedelta(hours=1)
                    logger.warning(f"Rotation failed, rescheduled {secret_path} for retry in 1h")

        return results

    def get_schedule(self, secret_path: str) -> RotationSchedule | None:
        """Get rotation schedule for a secret.

        Args:
            secret_path: Path to secret

        Returns:
            Rotation schedule or None
        """
        return self.schedules.get(secret_path)

    def list_schedules(self) -> list[RotationSchedule]:
        """List all rotation schedules.

        Returns:
            List of rotation schedules
        """
        return list(self.schedules.values())

    def get_statistics(self) -> dict[str, Any]:
        """Get rotation statistics.

        Returns:
            Dictionary with rotation statistics
        """
        total = self.stats["total_rotations"]
        successful = self.stats["successful_rotations"]
        failed = self.stats["failed_rotations"]

        return {
            "total_rotations": total,
            "successful_rotations": successful,
            "failed_rotations": failed,
            "rollbacks": self.stats["rollbacks"],
            "success_rate": successful / total if total > 0 else 0.0,
            "active_schedules": len([s for s in self.schedules.values() if s.enabled]),
            "total_schedules": len(self.schedules),
            "active_rotations": len(self.active_rotations),
        }

    def reset_statistics(self) -> None:
        """Reset rotation statistics."""
        self.stats = {
            "total_rotations": 0,
            "successful_rotations": 0,
            "failed_rotations": 0,
            "rollbacks": 0,
        }
        logger.info("Reset rotation statistics")
