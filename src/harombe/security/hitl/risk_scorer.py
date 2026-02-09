"""Historical risk scoring for HITL operations.

This module implements risk scoring based on historical operation outcomes
from the audit database. It analyzes past operations to predict risk levels
for future operations.

Phase 5.2.1 Implementation
"""

import logging
import time
from dataclasses import dataclass
from typing import Any

from ..audit_db import AuditDatabase
from .core import Operation

logger = logging.getLogger(__name__)


@dataclass
class RiskScore:
    """Risk score result for an operation.

    Attributes:
        score: Overall risk score (0-1, higher is riskier)
        factors: Individual risk factor scores
        sample_size: Number of historical operations analyzed
        confidence: Confidence in the score (0-1)
        cached: Whether this score was retrieved from cache
    """

    score: float
    factors: dict[str, float]
    sample_size: int
    confidence: float
    cached: bool = False


class HistoricalRiskScorer:
    """Score operation risk based on historical outcomes.

    Analyzes historical data from the audit database to calculate risk scores
    for operations. Uses failure rates, denial rates, and incident rates to
    compute a weighted risk score.

    Scoring Formula:
        risk_score = (failure_rate * 0.3) + (denial_rate * 0.4) + (incident_rate * 0.3)

    Cache Strategy:
        - Scores are cached for 24 hours
        - Cache key: tool_name
        - Cache invalidated on new incidents
    """

    def __init__(
        self,
        audit_db: AuditDatabase,
        cache_ttl: int = 86400,  # 24 hours
        min_sample_size: int = 10,
    ):
        """Initialize historical risk scorer.

        Args:
            audit_db: Audit database instance
            cache_ttl: Cache time-to-live in seconds (default 24 hours)
            min_sample_size: Minimum operations needed for reliable score
        """
        self.audit_db = audit_db
        self.cache_ttl = cache_ttl
        self.min_sample_size = min_sample_size
        self.risk_cache: dict[str, tuple[RiskScore, float]] = {}

    async def score_operation(
        self, operation: Operation, context: dict[str, Any] | None = None
    ) -> RiskScore:
        """Score operation risk based on historical data.

        Args:
            operation: Operation to score
            context: Additional context for scoring (optional)

        Returns:
            Risk score with breakdown of factors
        """
        start_time = time.perf_counter()

        # Check cache first
        cache_key = self._get_cache_key(operation)
        cached_score = self._get_cached_score(cache_key)
        if cached_score:
            logger.debug(f"Cache hit for {operation.tool_name}: {cached_score.score:.3f}")
            return cached_score

        # Query historical operations
        tool_calls = self.audit_db.get_tool_calls(
            tool_name=operation.tool_name,
            limit=1000,  # Analyze up to 1000 recent operations
        )

        # Also get security decisions for this tool
        security_decisions = self.audit_db.get_security_decisions(
            decision_type="hitl",
            limit=1000,
        )

        # Filter security decisions for this tool
        tool_decisions = [
            d for d in security_decisions if d.get("tool_name") == operation.tool_name
        ]

        # Calculate risk score
        risk_score = self._calculate_risk_score(tool_calls, tool_decisions, operation, context)

        # Cache the result
        self._cache_score(cache_key, risk_score)

        # Log performance
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        logger.debug(
            f"Scored {operation.tool_name} in {elapsed_ms:.2f}ms: "
            f"score={risk_score.score:.3f}, samples={risk_score.sample_size}"
        )

        return risk_score

    def _calculate_risk_score(
        self,
        tool_calls: list[dict[str, Any]],
        security_decisions: list[dict[str, Any]],
        operation: "Operation",
        context: dict[str, Any] | None,
    ) -> RiskScore:
        """Calculate risk score from historical data.

        Args:
            tool_calls: Historical tool call records
            security_decisions: Historical security decisions
            operation: Current operation being scored
            context: Additional context

        Returns:
            Calculated risk score
        """
        sample_size = len(tool_calls)

        # Not enough data for reliable score
        if sample_size < self.min_sample_size:
            return RiskScore(
                score=0.5,  # Neutral score for unknown operations
                factors={
                    "failure_rate": 0.5,
                    "denial_rate": 0.5,
                    "incident_rate": 0.0,
                },
                sample_size=sample_size,
                confidence=0.3,  # Low confidence
            )

        # Calculate failure rate
        failures = sum(1 for call in tool_calls if call.get("error") is not None)
        failure_rate = failures / sample_size if sample_size > 0 else 0.0

        # Calculate denial rate from security decisions
        denials = sum(1 for decision in security_decisions if decision.get("decision") == "deny")
        total_decisions = len(security_decisions)
        denial_rate = denials / total_decisions if total_decisions > 0 else 0.0

        # Calculate incident rate (operations that led to security incidents)
        # For now, we use errors as a proxy for incidents
        # In a full implementation, this would check for flagged incidents
        incidents = sum(
            1
            for call in tool_calls
            if call.get("error") and "security" in call.get("error", "").lower()
        )
        incident_rate = incidents / sample_size if sample_size > 0 else 0.0

        # Weighted risk score
        # Higher weight on denials (40%) as they indicate user-perceived risk
        risk_score = (failure_rate * 0.3) + (denial_rate * 0.4) + (incident_rate * 0.3)

        # Calculate confidence based on sample size
        # More samples = higher confidence
        confidence = min(sample_size / 100.0, 1.0)  # Max confidence at 100+ samples

        return RiskScore(
            score=risk_score,
            factors={
                "failure_rate": failure_rate,
                "denial_rate": denial_rate,
                "incident_rate": incident_rate,
            },
            sample_size=sample_size,
            confidence=confidence,
        )

    def _get_cache_key(self, operation: "Operation") -> str:
        """Generate cache key for operation.

        Args:
            operation: Operation to generate key for

        Returns:
            Cache key string
        """
        # Simple cache key based on tool name
        # Could be extended to include parameter patterns
        return f"risk:{operation.tool_name}"

    def _get_cached_score(self, cache_key: str) -> RiskScore | None:
        """Get cached risk score if valid.

        Args:
            cache_key: Cache key to lookup

        Returns:
            Cached risk score or None if not found/expired
        """
        if cache_key not in self.risk_cache:
            return None

        score, cached_at = self.risk_cache[cache_key]
        age = time.time() - cached_at

        # Check if cache is still valid
        if age > self.cache_ttl:
            del self.risk_cache[cache_key]
            return None

        # Return cached score with flag set
        score.cached = True
        return score

    def _cache_score(self, cache_key: str, score: RiskScore) -> None:
        """Cache risk score.

        Args:
            cache_key: Cache key
            score: Risk score to cache
        """
        self.risk_cache[cache_key] = (score, time.time())

    def clear_cache(self, tool_name: str | None = None) -> None:
        """Clear risk score cache.

        Args:
            tool_name: Clear only for specific tool (optional)
        """
        if tool_name:
            cache_key = f"risk:{tool_name}"
            if cache_key in self.risk_cache:
                del self.risk_cache[cache_key]
                logger.debug(f"Cleared risk cache for {tool_name}")
        else:
            self.risk_cache.clear()
            logger.debug("Cleared all risk cache")

    def get_risk_statistics(self) -> dict[str, Any]:
        """Get statistics about risk scoring.

        Returns:
            Dictionary with cache statistics and scoring info
        """
        return {
            "cache_size": len(self.risk_cache),
            "cache_ttl": self.cache_ttl,
            "min_sample_size": self.min_sample_size,
            "cached_tools": [key.replace("risk:", "") for key in self.risk_cache],
        }

    async def bulk_score_operations(self, operations: list[Operation]) -> dict[str, RiskScore]:
        """Score multiple operations efficiently.

        Args:
            operations: List of operations to score

        Returns:
            Dictionary mapping operation tool names to risk scores
        """
        results = {}

        # Group by tool name to avoid duplicate queries
        by_tool: dict[str, list[Operation]] = {}
        for op in operations:
            if op.tool_name not in by_tool:
                by_tool[op.tool_name] = []
            by_tool[op.tool_name].append(op)

        # Score each tool type once
        for _tool_name, ops in by_tool.items():
            # Score the first operation (all same tool)
            score = await self.score_operation(ops[0])
            # Apply to all operations with this tool
            for op in ops:
                results[op.tool_name] = score

        return results

    def update_cache_on_incident(self, tool_name: str) -> None:
        """Invalidate cache when security incident occurs.

        Args:
            tool_name: Tool involved in incident
        """
        self.clear_cache(tool_name)
        logger.warning(f"Invalidated risk cache for {tool_name} due to incident")
