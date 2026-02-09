"""Human-in-the-Loop (HITL) security components.

This package provides components for managing human approval workflows,
risk scoring, and trust management.
"""

# Import core HITL classes
# Import auto-approval
from .auto_approval import (
    ApprovalAction,
    AutoApprovalDecision,
    AutoApprovalEngine,
    AutoApprovalRule,
)

# Import context-aware engine
from .context_engine import ContextAwareEngine, ContextDecision, DecisionType
from .core import (
    ApprovalDecision,
    ApprovalStatus,
    HITLGate,
    HITLRule,
    Operation,
    PendingApproval,
    RiskClassifier,
    RiskLevel,
)

# Import risk scoring
from .risk_scorer import HistoricalRiskScorer, RiskScore

# Import trust management
from .trust import TrustLevel, TrustManager, TrustScore

__all__ = [
    "ApprovalAction",
    "ApprovalDecision",
    "ApprovalStatus",
    "AutoApprovalDecision",
    "AutoApprovalEngine",
    "AutoApprovalRule",
    "ContextAwareEngine",
    "ContextDecision",
    "DecisionType",
    "HITLGate",
    "HITLRule",
    "HistoricalRiskScorer",
    "Operation",
    "PendingApproval",
    "RiskClassifier",
    "RiskLevel",
    "RiskScore",
    "TrustLevel",
    "TrustManager",
    "TrustScore",
]
