"""Distributed security primitives for the Harombe security framework.

This module provides cryptographic building blocks for distributed
secret management and multi-party operations:

- Shamir's Secret Sharing with Feldman verification
- Multi-Party Computation (additive sharing, Beaver triples)
- Hardware Security Module abstraction (software + PKCS#11 + Cloud KMS)
- Quorum-based approval for sensitive operations
"""

from .hsm import (
    PKCS11HSM,
    CloudKMSHSM,
    HSMBackend,
    HSMKeyInfo,
    HSMKeyType,
    HSMManager,
    HSMOperationResult,
    SoftwareHSM,
)
from .mpc import (
    MPCConfig,
    MPCEngine,
    MPCOperation,
    MPCParty,
    MPCProtocol,
    SecretShare,
    SecureComparison,
    ThresholdDecryption,
)
from .quorum import (
    QuorumManager,
    QuorumMember,
    QuorumPolicy,
    QuorumRequest,
    QuorumStatus,
    QuorumVote,
    create_distributed_secrets,
)
from .shamir import (
    ShamirConfig,
    ShamirSecretSharing,
    ShamirSplitResult,
    ShamirVaultBackend,
    Share,
)

__all__ = [
    "PKCS11HSM",
    "CloudKMSHSM",
    "HSMBackend",
    "HSMKeyInfo",
    "HSMKeyType",
    "HSMManager",
    "HSMOperationResult",
    "MPCConfig",
    "MPCEngine",
    "MPCOperation",
    "MPCParty",
    "MPCProtocol",
    "QuorumManager",
    "QuorumMember",
    "QuorumPolicy",
    "QuorumRequest",
    "QuorumStatus",
    "QuorumVote",
    "SecretShare",
    "SecureComparison",
    "ShamirConfig",
    "ShamirSecretSharing",
    "ShamirSplitResult",
    "ShamirVaultBackend",
    "Share",
    "SoftwareHSM",
    "ThresholdDecryption",
    "create_distributed_secrets",
]
