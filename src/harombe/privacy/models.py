"""Data models for the privacy routing system."""

import hashlib
import time
from dataclasses import dataclass, field
from enum import Enum, StrEnum


class SensitivityLevel(Enum):
    """Classification of query sensitivity."""

    PUBLIC = 0  # Safe for cloud
    INTERNAL = 1  # Cloud OK with basic sanitization
    CONFIDENTIAL = 2  # PII/credentials detected; local-only or heavy sanitization
    RESTRICTED = 3  # User-defined restricted; always local-only


class RoutingMode(StrEnum):
    """How the privacy router should handle queries."""

    LOCAL_ONLY = "local-only"
    HYBRID = "hybrid"
    CLOUD_ASSISTED = "cloud-assisted"


class RoutingTarget(StrEnum):
    """Where a query is actually sent."""

    LOCAL = "local"
    CLOUD = "cloud"
    CLOUD_SANITIZED = "cloud_sanitized"


@dataclass
class PIIEntity:
    """A detected PII entity with location information."""

    type: str  # e.g. "email", "ssn", "phone", "credit_card", "credential"
    value: str
    start: int
    end: int
    confidence: float


@dataclass
class SensitivityResult:
    """Result of sensitivity classification."""

    level: SensitivityLevel
    reasons: list[str]
    detected_entities: list[PIIEntity]
    confidence: float
    pii_locations: list[tuple[int, int]] = field(default_factory=list)


@dataclass
class SanitizationMap:
    """Mapping of placeholders to original values for response reconstruction."""

    replacements: dict[str, str] = field(default_factory=dict)  # "[EMAIL_1]" -> "user@example.com"

    def add(self, placeholder: str, original: str) -> None:
        self.replacements[placeholder] = original

    def get_original(self, placeholder: str) -> str | None:
        return self.replacements.get(placeholder)


@dataclass
class PrivacyRoutingDecision:
    """Record of a routing decision for audit purposes."""

    query_hash: str
    sensitivity: SensitivityResult
    target: RoutingTarget
    mode: RoutingMode
    was_sanitized: bool
    sanitized_entity_count: int
    reasoning: str
    timestamp: float = field(default_factory=time.time)

    @staticmethod
    def hash_query(query: str) -> str:
        return hashlib.sha256(query.encode()).hexdigest()[:16]
