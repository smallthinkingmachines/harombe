"""Zero-Knowledge Proof primitives for the Harombe security framework.

Provides:
- Schnorr identification proofs
- Pedersen commitments
- Range proofs
- Privacy-preserving audit proofs
- ZKP-based authorization
"""

from .audit_proofs import (
    AuditClaim,
    AuditProofGenerator,
    AuditProofType,
    AuditProofVerifier,
    PrivacyPreservingAuditLog,
)
from .authorization import (
    AuthorizationClaim,
    ZKPAuthorizationProvider,
    ZKPAuthorizationVerifier,
    ZKPGateDecorator,
)
from .primitives import (
    Base64Bytes,
    PedersenCommitment,
    Proof,
    ProofType,
    RangeProof,
    SchnorrProof,
    VerificationResult,
    ZKPContext,
)

__all__ = [
    "AuditClaim",
    "AuditProofGenerator",
    "AuditProofType",
    "AuditProofVerifier",
    "AuthorizationClaim",
    "Base64Bytes",
    "PedersenCommitment",
    "PrivacyPreservingAuditLog",
    "Proof",
    "ProofType",
    "RangeProof",
    "SchnorrProof",
    "VerificationResult",
    "ZKPAuthorizationProvider",
    "ZKPAuthorizationVerifier",
    "ZKPContext",
    "ZKPGateDecorator",
]
