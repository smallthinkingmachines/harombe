"""Privacy-preserving routing for hybrid local/cloud AI.

The Privacy Router classifies query sensitivity, detects and redacts PII,
sanitizes context, and routes to either a local or cloud LLM backend.
From the Agent's perspective, it is just another LLM client.

Three routing modes are supported:

- ``local-only`` - All queries stay on local hardware (maximum privacy)
- ``hybrid`` (default) - Sensitive queries stay local, others may use cloud
- ``cloud-assisted`` - Cloud used freely, PII still redacted

Components:

- :class:`PrivacyRouter` - Main router implementing the LLM client interface
- :class:`SensitivityClassifier` - Classifies query sensitivity level
- :class:`ContextSanitizer` - Detects and redacts PII before cloud calls
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
