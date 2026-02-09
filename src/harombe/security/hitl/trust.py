"""User trust level management for HITL operations.

This module tracks and manages user trust levels based on historical behavior
patterns from the audit database. Trust levels influence auto-approval decisions
and security thresholds.

Phase 5.2.2 Implementation
"""

import logging
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any

from ..audit_db import AuditDatabase

logger = logging.getLogger(__name__)


class TrustLevel(StrEnum):
    """User trust level classification.

    Trust levels determine approval requirements and access privileges:
    - HIGH: 90-100 score, minimal approval requirements
    - MEDIUM: 70-89 score, standard approval requirements
    - LOW: 50-69 score, enhanced approval requirements
    - UNTRUSTED: <50 score, maximum approval requirements
    """

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNTRUSTED = "untrusted"


@dataclass
class TrustScore:
    """Trust score result for a user.

    Attributes:
        score: Overall trust score (0-100)
        level: Trust level classification
        factors: Individual factor scores
        sample_size: Number of events analyzed
        last_updated: When score was calculated
        days_active: Days since first activity
    """

    score: float
    level: TrustLevel
    factors: dict[str, float]
    sample_size: int
    last_updated: datetime
    days_active: int


class TrustManager:
    """Manage user trust levels based on behavioral patterns.

    Analyzes historical audit data to calculate trust scores for users.
    Trust scores are based on three factors:
    - Compliance rate (40% weight): No violations
    - Approval success rate (30% weight): Approved operations succeed
    - Tenure (30% weight): Days active (90 days = max score)

    Trust levels are cached and updated weekly or on demand.
    """

    def __init__(
        self,
        audit_db: AuditDatabase,
        cache_ttl: int = 604800,  # 1 week in seconds
        min_sample_size: int = 10,
    ):
        """Initialize trust manager.

        Args:
            audit_db: Audit database instance
            cache_ttl: Cache time-to-live in seconds (default 1 week)
            min_sample_size: Minimum events needed for reliable score
        """
        self.audit_db = audit_db
        self.cache_ttl = cache_ttl
        self.min_sample_size = min_sample_size
        # Cache: user_id -> (TrustScore, cached_at)
        self.trust_cache: dict[str, tuple[TrustScore, float]] = {}

    async def get_trust_level(self, user_id: str) -> TrustLevel:
        """Get current trust level for user.

        Args:
            user_id: User identifier

        Returns:
            Trust level classification
        """
        score = await self.get_trust_score(user_id)
        return score.level

    async def get_trust_score(self, user_id: str) -> TrustScore:
        """Get detailed trust score for user.

        Args:
            user_id: User identifier

        Returns:
            Complete trust score with factors
        """
        # Check cache
        import time

        cache_key = user_id
        if cache_key in self.trust_cache:
            cached_score, cached_at = self.trust_cache[cache_key]
            age = time.time() - cached_at
            if age < self.cache_ttl:
                logger.debug(f"Cache hit for user {user_id}: {cached_score.level}")
                return cached_score

        # Query user's audit history
        events = await self._get_user_events(user_id)

        # Calculate trust score
        trust_score = self._calculate_trust_score(user_id, events)

        # Cache the result
        self.trust_cache[cache_key] = (trust_score, time.time())

        logger.info(
            f"Calculated trust for {user_id}: {trust_score.level} "
            f"(score: {trust_score.score:.1f}, samples: {trust_score.sample_size})"
        )

        return trust_score

    async def _get_user_events(self, user_id: str) -> list[dict[str, Any]]:
        """Get audit events for user.

        Args:
            user_id: User identifier

        Returns:
            List of audit events
        """
        # Query audit events for this user (actor)
        events = self.audit_db.get_events_by_session(
            session_id=None,  # Get all sessions
            limit=1000,
        )

        # Filter by actor (user_id)
        user_events = [e for e in events if e.get("actor") == user_id]

        return user_events

    def _calculate_trust_score(self, user_id: str, events: list[dict[str, Any]]) -> TrustScore:
        """Calculate trust score from user's event history.

        Args:
            user_id: User identifier
            events: User's audit events

        Returns:
            Calculated trust score
        """
        sample_size = len(events)

        # New users or insufficient data
        if sample_size < self.min_sample_size:
            return TrustScore(
                score=50.0,  # Neutral score
                level=TrustLevel.LOW,
                factors={
                    "compliance": 1.0,
                    "approval_success": 1.0,
                    "tenure": 0.0,
                },
                sample_size=sample_size,
                last_updated=datetime.now(),
                days_active=0,
            )

        # Calculate factors
        factors = {}

        # Factor 1: Compliance rate (40% weight)
        # Count events with violations or security denials
        violations = sum(
            1
            for e in events
            if e.get("status") == "error" or "violation" in (e.get("metadata") or {})
        )
        compliance_rate = 1.0 - (violations / sample_size)
        factors["compliance"] = compliance_rate

        # Factor 2: Approval success rate (30% weight)
        # Get security decisions (HITL approvals)
        security_decisions = self.audit_db.get_security_decisions(decision_type="hitl", limit=1000)
        user_decisions = [d for d in security_decisions if d.get("actor") == user_id]

        if user_decisions:
            # Count approved operations that succeeded
            approved = [d for d in user_decisions if d.get("decision") == "allow"]
            # For approved operations, check if they succeeded
            # (no corresponding error event)
            approval_success_rate = len(approved) / len(user_decisions)
        else:
            approval_success_rate = 1.0  # No denials = perfect score

        factors["approval_success"] = approval_success_rate

        # Factor 3: Tenure (30% weight)
        # Calculate days active
        if events:
            timestamps = [
                datetime.fromisoformat(e["timestamp"])
                if isinstance(e["timestamp"], str)
                else e["timestamp"]
                for e in events
                if "timestamp" in e
            ]
            if timestamps:
                days_active = (max(timestamps) - min(timestamps)).days
                tenure_score = min(days_active / 90.0, 1.0)  # 90 days = max score
            else:
                days_active = 0
                tenure_score = 0.0
        else:
            days_active = 0
            tenure_score = 0.0

        factors["tenure"] = tenure_score

        # Calculate weighted score (0-1) -> scale to 0-100
        weights = {"compliance": 0.4, "approval_success": 0.3, "tenure": 0.3}

        weighted_score = sum(factors[f] * weights[f] for f in factors)
        final_score = weighted_score * 100

        # Map score to trust level
        if final_score >= 90:
            level = TrustLevel.HIGH
        elif final_score >= 70:
            level = TrustLevel.MEDIUM
        elif final_score >= 50:
            level = TrustLevel.LOW
        else:
            level = TrustLevel.UNTRUSTED

        return TrustScore(
            score=final_score,
            level=level,
            factors=factors,
            sample_size=sample_size,
            last_updated=datetime.now(),
            days_active=days_active,
        )

    def clear_cache(self, user_id: str | None = None) -> None:
        """Clear trust score cache.

        Args:
            user_id: Clear only for specific user (optional)
        """
        if user_id:
            if user_id in self.trust_cache:
                del self.trust_cache[user_id]
                logger.debug(f"Cleared trust cache for {user_id}")
        else:
            self.trust_cache.clear()
            logger.debug("Cleared all trust cache")

    def update_trust_on_event(self, user_id: str, event_type: str) -> None:
        """Update trust score when significant event occurs.

        Args:
            user_id: User identifier
            event_type: Type of event (e.g., "violation", "incident")
        """
        # For significant events, invalidate cache
        if event_type in ["violation", "security_incident", "denial"]:
            self.clear_cache(user_id)
            logger.warning(f"Invalidated trust cache for {user_id} due to {event_type}")

    def get_trust_statistics(self) -> dict[str, Any]:
        """Get statistics about trust management.

        Returns:
            Dictionary with cache statistics and trust distribution
        """
        # Count users by trust level
        trust_distribution = {
            TrustLevel.HIGH: 0,
            TrustLevel.MEDIUM: 0,
            TrustLevel.LOW: 0,
            TrustLevel.UNTRUSTED: 0,
        }

        for trust_score, _cached_at in self.trust_cache.values():
            trust_distribution[trust_score.level] += 1

        return {
            "cache_size": len(self.trust_cache),
            "cache_ttl_days": self.cache_ttl / 86400,
            "min_sample_size": self.min_sample_size,
            "trust_distribution": {
                level.value: count for level, count in trust_distribution.items()
            },
            "cached_users": list(self.trust_cache.keys()),
        }

    async def bulk_get_trust_levels(self, user_ids: list[str]) -> dict[str, TrustLevel]:
        """Get trust levels for multiple users efficiently.

        Args:
            user_ids: List of user identifiers

        Returns:
            Dictionary mapping user IDs to trust levels
        """
        results = {}

        for user_id in user_ids:
            level = await self.get_trust_level(user_id)
            results[user_id] = level

        return results
