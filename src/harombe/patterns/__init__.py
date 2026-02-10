"""Multi-model collaboration patterns for hybrid local/cloud AI.

Each pattern wraps LLMClient instances and itself satisfies the
LLMClient protocol, making patterns composable via nesting.

Available patterns (auto-registered via ``@register_pattern``):
- ``smart_escalation``: Try local, escalate on low confidence
- ``privacy_handshake``: Pseudonymize PII before cloud
- ``data_minimization``: Filter to essential sentences before cloud
- ``specialized_routing``: Route by task complexity
- ``sliding_privacy``: User-adjustable privacy dial
- ``debate``: Multi-round debate between local and cloud
"""

# Import pattern modules to trigger registration
from . import (  # noqa: F401
    data_minimization,
    debate,
    privacy_handshake,
    sliding_privacy,
    smart_escalation,
    specialized_routing,
)
from .base import PatternBase, PatternMetrics
from .factory import create_pattern_client
from .registry import PatternRegistry, register_pattern

__all__ = [
    "PatternBase",
    "PatternMetrics",
    "PatternRegistry",
    "create_pattern_client",
    "register_pattern",
]
