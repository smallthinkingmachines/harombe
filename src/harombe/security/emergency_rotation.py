"""Emergency credential rotation triggers.

Detects security events and compromise indicators that require immediate
credential rotation. Monitors audit logs, triggers emergency rotation, and
notifies security teams.

Phase 5.3.4 Implementation
"""

import logging
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class CompromiseIndicator(StrEnum):
    """Types of compromise indicators."""

    FAILED_AUTH_SPIKE = "failed_auth_spike"  # Unusual failed auth attempts
    LEAKED_CREDENTIAL = "leaked_credential"  # Credential found in leak
    SUSPICIOUS_ACCESS = "suspicious_access"  # Access from unusual location/time
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"  # Rate limit violations
    UNAUTHORIZED_ACCESS = "unauthorized_access"  # Access denied events
    API_KEY_EXPOSED = "api_key_exposed"  # Key found in public repository
    BRUTE_FORCE_ATTACK = "brute_force_attack"  # Brute force detected
    ANOMALOUS_BEHAVIOR = "anomalous_behavior"  # ML-detected anomaly
    MANUAL_TRIGGER = "manual_trigger"  # Manual emergency rotation


class ThreatLevel(StrEnum):
    """Threat level for security events."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SecurityEvent(BaseModel):
    """Security event that may trigger rotation.

    Attributes:
        event_type: Type of security event
        threat_level: Severity of threat
        description: Human-readable description
        affected_resources: List of affected resource paths
        source_ip: Source IP address (if applicable)
        timestamp: When event occurred
        metadata: Additional event-specific data
    """

    event_type: str
    threat_level: ThreatLevel
    description: str
    affected_resources: list[str] = Field(default_factory=list)
    source_ip: str | None = None
    timestamp: datetime
    metadata: dict[str, Any] = Field(default_factory=dict)


class EmergencyRotationResult(BaseModel):
    """Result of emergency rotation.

    Attributes:
        success: Whether rotation succeeded
        secret_path: Path to rotated secret
        trigger_event: Event that triggered rotation
        rotation_started_at: When rotation started
        rotation_completed_at: When rotation completed
        duration_ms: Time taken for rotation
        notifications_sent: Number of notifications sent
        error: Error message if failed
    """

    success: bool
    secret_path: str
    trigger_event: SecurityEvent
    rotation_started_at: datetime
    rotation_completed_at: datetime | None = None
    duration_ms: float | None = None
    notifications_sent: int = 0
    error: str | None = None


class EmergencyRotationTrigger:
    """Trigger emergency secret rotation on security events.

    Monitors security events and triggers immediate credential rotation
    when compromise indicators are detected.
    """

    def __init__(
        self,
        rotation_manager: Any,  # SecretRotationManager
        audit_db: Any | None = None,
        notification_handler: Any | None = None,
    ):
        """Initialize emergency rotation trigger.

        Args:
            rotation_manager: Secret rotation manager
            audit_db: Audit database for event monitoring (optional)
            notification_handler: Handler for sending notifications (optional)
        """
        self.rotation_manager = rotation_manager
        self.audit_db = audit_db
        self.notification_handler = notification_handler

        # Compromise detection thresholds
        self.thresholds = {
            "failed_auth_window_minutes": 15,
            "failed_auth_threshold": 10,
            "rate_limit_window_minutes": 5,
            "rate_limit_threshold": 100,
        }

        # Statistics
        self.stats = {
            "total_events": 0,
            "emergency_rotations": 0,
            "successful_rotations": 0,
            "failed_rotations": 0,
            "notifications_sent": 0,
        }

    async def on_security_event(self, event: SecurityEvent) -> list[EmergencyRotationResult]:
        """Handle security events that may require rotation.

        Args:
            event: Security event to process

        Returns:
            List of emergency rotation results
        """
        self.stats["total_events"] += 1
        logger.info(
            f"Processing security event: {event.event_type} "
            f"(threat_level: {event.threat_level})"
        )

        # Check if event indicates compromise
        if not self._is_compromise_indicator(event):
            logger.debug(f"Event {event.event_type} does not indicate compromise")
            return []

        # Identify affected secrets
        affected_secrets = self._identify_affected_secrets(event)
        if not affected_secrets:
            logger.warning(f"No affected secrets identified for event: {event.event_type}")
            return []

        logger.warning(
            f"Compromise detected! Triggering emergency rotation for "
            f"{len(affected_secrets)} secrets"
        )

        # Trigger emergency rotation for all affected secrets
        results = []
        for secret_path in affected_secrets:
            result = await self._emergency_rotate(secret_path, event)
            results.append(result)

        return results

    def _is_compromise_indicator(self, event: SecurityEvent) -> bool:
        """Check if event indicates potential compromise.

        Args:
            event: Security event to check

        Returns:
            True if event indicates compromise
        """
        # Critical threat level always indicates compromise
        if event.threat_level == ThreatLevel.CRITICAL:
            return True

        # High threat level with specific event types
        if event.threat_level == ThreatLevel.HIGH:
            compromise_event_types = [
                CompromiseIndicator.LEAKED_CREDENTIAL,
                CompromiseIndicator.API_KEY_EXPOSED,
                CompromiseIndicator.UNAUTHORIZED_ACCESS,
                CompromiseIndicator.BRUTE_FORCE_ATTACK,
            ]
            if event.event_type in compromise_event_types:
                return True

        # Check for failed authentication spike
        if event.event_type == CompromiseIndicator.FAILED_AUTH_SPIKE:
            failed_count = event.metadata.get("failed_count", 0)
            threshold = self.thresholds["failed_auth_threshold"]
            if failed_count >= threshold:
                logger.warning(
                    f"Failed auth spike detected: {failed_count} attempts "
                    f"(threshold: {threshold})"
                )
                return True

        # Check for rate limit violations
        if event.event_type == CompromiseIndicator.RATE_LIMIT_EXCEEDED:
            violation_count = event.metadata.get("violation_count", 0)
            threshold = self.thresholds["rate_limit_threshold"]
            if violation_count >= threshold:
                logger.warning(
                    f"Rate limit violations detected: {violation_count} "
                    f"(threshold: {threshold})"
                )
                return True

        # Manual trigger always rotates
        return event.event_type == CompromiseIndicator.MANUAL_TRIGGER

    def _identify_affected_secrets(self, event: SecurityEvent) -> list[str]:
        """Identify secrets affected by security event.

        Args:
            event: Security event

        Returns:
            List of affected secret paths
        """
        # Use explicitly provided affected resources if available
        if event.affected_resources:
            return event.affected_resources

        # Try to extract from metadata
        if "secret_path" in event.metadata:
            return [event.metadata["secret_path"]]

        if "secret_paths" in event.metadata:
            return list(event.metadata["secret_paths"])

        # Try to infer from event type
        if (
            event.event_type
            in [
                CompromiseIndicator.API_KEY_EXPOSED,
                CompromiseIndicator.LEAKED_CREDENTIAL,
            ]
            and "api_key_prefix" in event.metadata
        ):
            # In production: query vault for secrets with matching prefix
            logger.debug(
                f"Would search for secrets with prefix: {event.metadata['api_key_prefix']}"
            )

        logger.warning(f"Could not identify affected secrets from event: {event.event_type}")
        return []

    async def _emergency_rotate(
        self, secret_path: str, trigger_event: SecurityEvent
    ) -> EmergencyRotationResult:
        """Perform emergency rotation.

        Args:
            secret_path: Path to secret to rotate
            trigger_event: Event that triggered rotation

        Returns:
            Emergency rotation result
        """
        started_at = datetime.utcnow()
        self.stats["emergency_rotations"] += 1

        logger.critical(
            f"EMERGENCY ROTATION: {secret_path} "
            f"(trigger: {trigger_event.event_type}, "
            f"threat: {trigger_event.threat_level})"
        )

        try:
            # Log emergency rotation
            if self.audit_db:
                await self._log_emergency_rotation(secret_path, trigger_event)

            # Create emergency rotation policy
            from harombe.security.rotation import RotationPolicy, RotationStrategy

            policy = RotationPolicy(
                name="emergency",
                interval_days=0,  # Immediate
                strategy=RotationStrategy.IMMEDIATE,  # Fastest strategy
                require_verification=False,  # Skip verification in emergency
                auto_rollback=False,  # Don't rollback in emergency
                notify_on_rotation=True,
                notify_on_failure=True,
            )

            # Perform rotation
            rotation_result = await self.rotation_manager.rotate_secret(secret_path, policy)

            completed_at = datetime.utcnow()
            duration_ms = (completed_at - started_at).total_seconds() * 1000

            if rotation_result.success:
                self.stats["successful_rotations"] += 1
                logger.info(
                    f"Emergency rotation completed successfully: {secret_path} "
                    f"({duration_ms:.1f}ms)"
                )

                # Notify security team
                notifications_sent = await self._notify_security_team(secret_path, trigger_event)

                return EmergencyRotationResult(
                    success=True,
                    secret_path=secret_path,
                    trigger_event=trigger_event,
                    rotation_started_at=started_at,
                    rotation_completed_at=completed_at,
                    duration_ms=duration_ms,
                    notifications_sent=notifications_sent,
                )
            else:
                self.stats["failed_rotations"] += 1
                logger.error(f"Emergency rotation failed: {secret_path} - {rotation_result.error}")

                # Alert on failure
                await self._alert_rotation_failure(
                    secret_path, trigger_event, rotation_result.error
                )

                return EmergencyRotationResult(
                    success=False,
                    secret_path=secret_path,
                    trigger_event=trigger_event,
                    rotation_started_at=started_at,
                    rotation_completed_at=completed_at,
                    duration_ms=duration_ms,
                    error=rotation_result.error,
                )

        except Exception as e:
            self.stats["failed_rotations"] += 1
            logger.exception(f"Emergency rotation raised exception: {secret_path} - {e}")

            completed_at = datetime.utcnow()
            duration_ms = (completed_at - started_at).total_seconds() * 1000

            # Alert on failure
            await self._alert_rotation_failure(secret_path, trigger_event, str(e))

            return EmergencyRotationResult(
                success=False,
                secret_path=secret_path,
                trigger_event=trigger_event,
                rotation_started_at=started_at,
                rotation_completed_at=completed_at,
                duration_ms=duration_ms,
                error=str(e),
            )

    async def _log_emergency_rotation(self, secret_path: str, trigger_event: SecurityEvent) -> None:
        """Log emergency rotation to audit database.

        Args:
            secret_path: Path to secret being rotated
            trigger_event: Event that triggered rotation
        """
        if self.audit_db is None:
            return

        # In production: log to audit database
        logger.info(
            f"Audit log: Emergency rotation triggered for {secret_path} "
            f"by {trigger_event.event_type}"
        )

    async def _notify_security_team(self, secret_path: str, trigger_event: SecurityEvent) -> int:
        """Notify security team of emergency rotation.

        Args:
            secret_path: Path to rotated secret
            trigger_event: Event that triggered rotation

        Returns:
            Number of notifications sent
        """
        if self.notification_handler is None:
            logger.debug("No notification handler configured, skipping notifications")
            return 0

        try:
            # Prepare notification message
            message = self._format_notification_message(secret_path, trigger_event)

            # Send notification
            await self.notification_handler.send_notification(
                channel="security-alerts",
                message=message,
                priority="high",
                metadata={
                    "secret_path": secret_path,
                    "event_type": trigger_event.event_type,
                    "threat_level": trigger_event.threat_level,
                },
            )

            self.stats["notifications_sent"] += 1
            logger.info(f"Security team notified of emergency rotation: {secret_path}")
            return 1

        except Exception as e:
            logger.error(f"Failed to send notification: {e}")
            return 0

    async def _alert_rotation_failure(
        self, secret_path: str, trigger_event: SecurityEvent, error: str | None
    ) -> None:
        """Alert on emergency rotation failure.

        Args:
            secret_path: Path to secret that failed to rotate
            trigger_event: Event that triggered rotation
            error: Error message
        """
        logger.critical(f"EMERGENCY ROTATION FAILED: {secret_path} - {error or 'Unknown error'}")

        if self.notification_handler:
            try:
                message = (
                    f"🚨 EMERGENCY ROTATION FAILED 🚨\n\n"
                    f"Secret: {secret_path}\n"
                    f"Trigger: {trigger_event.event_type}\n"
                    f"Threat Level: {trigger_event.threat_level}\n"
                    f"Error: {error or 'Unknown error'}\n\n"
                    f"IMMEDIATE ACTION REQUIRED!"
                )

                await self.notification_handler.send_notification(
                    channel="security-critical",
                    message=message,
                    priority="critical",
                    metadata={
                        "secret_path": secret_path,
                        "event_type": trigger_event.event_type,
                        "error": error,
                    },
                )
            except Exception as e:
                logger.error(f"Failed to send failure alert: {e}")

    def _format_notification_message(self, secret_path: str, trigger_event: SecurityEvent) -> str:
        """Format notification message for security team.

        Args:
            secret_path: Path to rotated secret
            trigger_event: Event that triggered rotation

        Returns:
            Formatted message
        """
        message = (
            f"🔐 Emergency Credential Rotation Triggered\n\n"
            f"Secret: {secret_path}\n"
            f"Trigger: {trigger_event.event_type}\n"
            f"Threat Level: {trigger_event.threat_level}\n"
            f"Description: {trigger_event.description}\n"
            f"Timestamp: {trigger_event.timestamp.isoformat()}\n"
        )

        if trigger_event.source_ip:
            message += f"Source IP: {trigger_event.source_ip}\n"

        if trigger_event.metadata:
            message += "\nAdditional Details:\n"
            for key, value in trigger_event.metadata.items():
                message += f"  {key}: {value}\n"

        return message

    async def monitor_audit_events(
        self, lookback_minutes: int = 15
    ) -> list[EmergencyRotationResult]:
        """Monitor recent audit events for compromise indicators.

        Args:
            lookback_minutes: How far back to look for events

        Returns:
            List of emergency rotation results
        """
        if self.audit_db is None:
            logger.warning("No audit database configured, cannot monitor events")
            return []

        logger.info(f"Monitoring audit events (lookback: {lookback_minutes} minutes)")

        try:
            # Query recent audit events
            since = datetime.utcnow() - timedelta(minutes=lookback_minutes)
            events = await self._query_recent_events(since)

            # Analyze events for compromise indicators
            security_events = self._analyze_events_for_compromise(events)

            # Process all detected security events
            all_results = []
            for security_event in security_events:
                results = await self.on_security_event(security_event)
                all_results.extend(results)

            return all_results

        except Exception as e:
            logger.error(f"Error monitoring audit events: {e}")
            return []

    async def _query_recent_events(self, since: datetime) -> list[dict[str, Any]]:
        """Query recent events from audit database.

        Args:
            since: Query events after this time

        Returns:
            List of audit events
        """
        # In production: query audit database
        # For now, return empty list
        logger.debug(f"Would query audit events since {since}")
        return []

    def _analyze_events_for_compromise(self, events: list[dict[str, Any]]) -> list[SecurityEvent]:
        """Analyze audit events for compromise indicators.

        Args:
            events: List of audit events

        Returns:
            List of detected security events
        """
        security_events = []

        # Count failed authentication attempts
        failed_auth_events = [e for e in events if e.get("action") == "authentication_failed"]
        if len(failed_auth_events) >= self.thresholds["failed_auth_threshold"]:
            security_events.append(
                SecurityEvent(
                    event_type=CompromiseIndicator.FAILED_AUTH_SPIKE,
                    threat_level=ThreatLevel.HIGH,
                    description=f"Failed authentication spike: {len(failed_auth_events)} attempts",
                    timestamp=datetime.utcnow(),
                    metadata={"failed_count": len(failed_auth_events)},
                )
            )

        # Check for rate limit violations
        rate_limit_events = [e for e in events if e.get("action") == "rate_limit_exceeded"]
        if len(rate_limit_events) >= self.thresholds["rate_limit_threshold"]:
            security_events.append(
                SecurityEvent(
                    event_type=CompromiseIndicator.RATE_LIMIT_EXCEEDED,
                    threat_level=ThreatLevel.MEDIUM,
                    description=f"Rate limit violations: {len(rate_limit_events)} occurrences",
                    timestamp=datetime.utcnow(),
                    metadata={"violation_count": len(rate_limit_events)},
                )
            )

        return security_events

    def get_statistics(self) -> dict[str, Any]:
        """Get emergency rotation statistics.

        Returns:
            Statistics dictionary
        """
        return {
            **self.stats,
            "success_rate": (
                self.stats["successful_rotations"] / self.stats["emergency_rotations"]
                if self.stats["emergency_rotations"] > 0
                else 0.0
            ),
        }

    def reset_statistics(self) -> None:
        """Reset statistics counters."""
        self.stats = {
            "total_events": 0,
            "emergency_rotations": 0,
            "successful_rotations": 0,
            "failed_rotations": 0,
            "notifications_sent": 0,
        }
