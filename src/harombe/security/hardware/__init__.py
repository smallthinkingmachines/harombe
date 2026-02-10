"""Hardware security components for TPM, enclave, attestation, and key hierarchy.

This module provides hardware-backed security features including:
- TPM integration for key storage, signing, sealing, and random generation
- Secure enclave utilization for isolated execution environments
- Hardware-backed attestation for platform integrity verification
- Hierarchical key derivation with HKDF-SHA256
"""

from .attestation import (
    AttestationGenerator,
    AttestationPolicy,
    AttestationReport,
    AttestationType,
    AttestationVerifier,
    RemoteAttestationService,
)
from .enclave import (
    EnclaveBackend,
    EnclaveConfig,
    EnclaveManager,
    EnclaveResult,
    EnclaveStatus,
    SGXEnclave,
    SoftwareEnclave,
)
from .key_hierarchy import (
    HardwareKeyHierarchy,
    KeyNode,
    KeyPurpose,
    create_hardware_security,
)
from .tpm import (
    LinuxTPM,
    SoftwareTPM,
    TPMAlgorithm,
    TPMBackend,
    TPMKeyHandle,
    TPMKeyManager,
    TPMSealedData,
)

__all__ = [
    "AttestationGenerator",
    "AttestationPolicy",
    "AttestationReport",
    "AttestationType",
    "AttestationVerifier",
    "EnclaveBackend",
    "EnclaveConfig",
    "EnclaveManager",
    "EnclaveResult",
    "EnclaveStatus",
    "HardwareKeyHierarchy",
    "KeyNode",
    "KeyPurpose",
    "LinuxTPM",
    "RemoteAttestationService",
    "SGXEnclave",
    "SoftwareEnclave",
    "SoftwareTPM",
    "TPMAlgorithm",
    "TPMBackend",
    "TPMKeyHandle",
    "TPMKeyManager",
    "TPMSealedData",
    "create_hardware_security",
]
