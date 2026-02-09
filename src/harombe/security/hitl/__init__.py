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
