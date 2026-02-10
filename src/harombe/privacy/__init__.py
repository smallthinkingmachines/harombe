"""Privacy-preserving routing for hybrid local/cloud AI.

The Privacy Router classifies query sensitivity, sanitizes context when needed,
and routes to either a local or cloud LLM backend. From the Agent's perspective,
it's just another LLM client.
"""

from .classifier import SensitivityClassifier
from .models import (
    PIIEntity,
    PrivacyRoutingDecision,
    RoutingMode,
    RoutingTarget,
    SanitizationMap,
    SensitivityLevel,
    SensitivityResult,
)
from .router import PrivacyRouter, create_privacy_router
from .sanitizer import ContextSanitizer

__all__ = [
    "ContextSanitizer",
    "PIIEntity",
    "PrivacyRouter",
    "PrivacyRoutingDecision",
    "RoutingMode",
    "RoutingTarget",
    "SanitizationMap",
    "SensitivityClassifier",
    "SensitivityLevel",
    "SensitivityResult",
    "create_privacy_router",
]
