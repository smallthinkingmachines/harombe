"""TPM (Trusted Platform Module) integration for hardware-backed key storage.

This module provides TPM integration for cryptographic key management, data sealing,
and digital signatures. Includes a software-based fallback implementation that uses
the ``cryptography`` library for all operations, suitable for development and testing
environments without physical TPM hardware.

Supports RSA, ECDSA, and AES algorithms with a high-level key manager interface
that abstracts away backend details.

Example:
    >>> from harombe.security.hardware.tpm import TPMKeyManager, TPMAlgorithm
    >>>
    >>> # Create key manager (defaults to software TPM)
    >>> manager = TPMKeyManager()
    >>> await manager.backend.initialize()
    >>>
    >>> # Create a signing key
    >>> key = await manager.create_signing_key(TPMAlgorithm.ECDSA_P256)
    >>>
    >>> # Sign and verify data
    >>> signature = await manager.sign_data(key.key_id, b"hello world")
    >>> valid = await manager.verify_signature(key.key_id, b"hello world", signature)
    >>>
    >>> # Seal and unseal secrets
    >>> sealed = await manager.seal_secret(b"my-secret-api-key")
    >>> plaintext = await manager.unseal_secret(sealed)
"""

import logging
import os
import uuid
from abc import ABC, abstractmethod
from datetime import datetime
from enum import StrEnum
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class TPMAlgorithm(StrEnum):
    """Supported TPM key algorithms.

    Attributes:
        RSA_2048: RSA with 2048-bit key
        RSA_4096: RSA with 4096-bit key
        ECDSA_P256: ECDSA with NIST P-256 curve
        ECDSA_P384: ECDSA with NIST P-384 curve
        AES_128: AES with 128-bit key
        AES_256: AES with 256-bit key
    """

    RSA_2048 = "rsa_2048"
    RSA_4096 = "rsa_4096"
    ECDSA_P256 = "ecdsa_p256"
    ECDSA_P384 = "ecdsa_p384"
    AES_128 = "aes_128"
    AES_256 = "aes_256"


class TPMKeyHandle(BaseModel):
    """Handle to a key stored in the TPM.

    Attributes:
        key_id: Unique identifier for the key
        algorithm: Algorithm used for this key
        created_at: Timestamp when the key was created
        exportable: Whether the key can be exported from the TPM
        metadata: Additional key metadata
    """

    key_id: str
    algorithm: TPMAlgorithm
    created_at: datetime = Field(default_factory=datetime.utcnow)
    exportable: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)


class TPMSealedData(BaseModel):
    """Data sealed (encrypted) by the TPM.

    Attributes:
        data_id: Unique identifier for the sealed data blob
        ciphertext: Encrypted data bytes
        nonce: Nonce used for AES-GCM encryption
        tag: Authentication tag from AES-GCM
        sealed_at: Timestamp when data was sealed
        policy_hash: Optional PCR policy hash binding the sealed data
    """

    data_id: str
    ciphertext: bytes
    nonce: bytes
    tag: bytes
    sealed_at: datetime = Field(default_factory=datetime.utcnow)
    policy_hash: str | None = None


class TPMBackend(ABC):
    """Abstract base class for TPM backend implementations.

    Provides the interface for TPM operations including key management,
    signing/verification, data sealing, and random number generation.
    """

    @abstractmethod
    async def initialize(self) -> None:
        """Initialize the TPM backend and establish connection."""

    @abstractmethod
    async def create_key(self, algorithm: TPMAlgorithm, exportable: bool = False) -> TPMKeyHandle:
        """Create a new cryptographic key in the TPM.

        Args:
            algorithm: Algorithm to use for the key
            exportable: Whether the key can be exported

        Returns:
            Handle to the newly created key
        """

    @abstractmethod
    async def sign(self, key_handle: TPMKeyHandle, data: bytes) -> bytes:
        """Sign data using a key stored in the TPM.

        Args:
            key_handle: Handle to the signing key
            data: Data to sign

        Returns:
            Digital signature bytes
        """

    @abstractmethod
    async def verify(self, key_handle: TPMKeyHandle, data: bytes, signature: bytes) -> bool:
        """Verify a signature using a key stored in the TPM.

        Args:
            key_handle: Handle to the verification key
            data: Original data that was signed
            signature: Signature to verify

        Returns:
            True if signature is valid, False otherwise
        """

    @abstractmethod
    async def seal(self, data: bytes, policy_hash: str | None = None) -> TPMSealedData:
        """Seal (encrypt) data using the TPM.

        Args:
            data: Plaintext data to seal
            policy_hash: Optional PCR policy hash to bind the data

        Returns:
            Sealed data container with ciphertext and metadata
        """

    @abstractmethod
    async def unseal(self, sealed: TPMSealedData) -> bytes:
        """Unseal (decrypt) data previously sealed by the TPM.

        Args:
            sealed: Sealed data container to decrypt

        Returns:
            Original plaintext data
        """

    @abstractmethod
    async def get_random(self, num_bytes: int) -> bytes:
        """Generate cryptographically secure random bytes.

        Args:
            num_bytes: Number of random bytes to generate

        Returns:
            Random bytes
        """

    @abstractmethod
    async def destroy_key(self, key_handle: TPMKeyHandle) -> None:
        """Destroy a key stored in the TPM.

        Args:
            key_handle: Handle to the key to destroy
        """


class SoftwareTPM(TPMBackend):
    """Software-based TPM implementation for development and testing.

    Uses the ``cryptography`` library to provide all TPM operations in
    software. Keys are stored in memory and lost when the process exits.

    This backend is suitable for development, testing, and environments
    where hardware TPM is not available.
    """

    def __init__(self) -> None:
        """Initialize software TPM with empty key store."""
        self._keys: dict[str, Any] = {}
        self._master_seal_key: bytes | None = None
        self._initialized = False

    async def initialize(self) -> None:
        """Initialize the software TPM backend.

        Generates a master seal key from os.urandom for seal/unseal
        operations.
        """
        self._master_seal_key = os.urandom(32)
        self._initialized = True
        logger.info("Software TPM initialized")

    def _ensure_initialized(self) -> None:
        """Verify the backend has been initialized.

        Raises:
            RuntimeError: If initialize() has not been called
        """
        if not self._initialized:
            raise RuntimeError("SoftwareTPM not initialized. Call initialize() first.")

    async def create_key(self, algorithm: TPMAlgorithm, exportable: bool = False) -> TPMKeyHandle:
        """Create a new cryptographic key in the software key store.

        Args:
            algorithm: Algorithm to use for key generation
            exportable: Whether the key can be exported

        Returns:
            Handle to the created key

        Raises:
            RuntimeError: If backend is not initialized
            ValueError: If algorithm is not supported for key creation
        """
        self._ensure_initialized()

        key_id = str(uuid.uuid4())
        private_key: Any = None

        if algorithm == TPMAlgorithm.RSA_2048:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
        elif algorithm == TPMAlgorithm.RSA_4096:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=4096,
            )
        elif algorithm == TPMAlgorithm.ECDSA_P256:
            private_key = ec.generate_private_key(ec.SECP256R1())
        elif algorithm == TPMAlgorithm.ECDSA_P384:
            private_key = ec.generate_private_key(ec.SECP384R1())
        elif algorithm == TPMAlgorithm.AES_128:
            private_key = os.urandom(16)
        elif algorithm == TPMAlgorithm.AES_256:
            private_key = os.urandom(32)
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")

        handle = TPMKeyHandle(
            key_id=key_id,
            algorithm=algorithm,
            exportable=exportable,
        )

        self._keys[key_id] = {
            "handle": handle,
            "private_key": private_key,
        }

        logger.info(f"Created {algorithm.value} key {key_id} " f"(exportable={exportable})")
        return handle

    async def sign(self, key_handle: TPMKeyHandle, data: bytes) -> bytes:
        """Sign data using an RSA or ECDSA key.

        Args:
            key_handle: Handle to the signing key
            data: Data to sign

        Returns:
            Signature bytes

        Raises:
            RuntimeError: If backend is not initialized
            KeyError: If key_id is not found
            ValueError: If key algorithm does not support signing
        """
        self._ensure_initialized()

        if key_handle.key_id not in self._keys:
            raise KeyError(f"Key not found: {key_handle.key_id}")

        private_key = self._keys[key_handle.key_id]["private_key"]
        algorithm = key_handle.algorithm

        if algorithm in (TPMAlgorithm.RSA_2048, TPMAlgorithm.RSA_4096):
            signature = private_key.sign(
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
        elif algorithm in (TPMAlgorithm.ECDSA_P256, TPMAlgorithm.ECDSA_P384):
            hash_alg = hashes.SHA256() if algorithm == TPMAlgorithm.ECDSA_P256 else hashes.SHA384()
            signature = private_key.sign(
                data,
                ec.ECDSA(hash_alg),
            )
        else:
            raise ValueError(f"Algorithm {algorithm.value} does not support signing")

        logger.debug(f"Signed data with key {key_handle.key_id}")
        return signature

    async def verify(self, key_handle: TPMKeyHandle, data: bytes, signature: bytes) -> bool:
        """Verify a signature using an RSA or ECDSA key.

        Args:
            key_handle: Handle to the verification key
            data: Original data that was signed
            signature: Signature to verify

        Returns:
            True if signature is valid, False otherwise

        Raises:
            RuntimeError: If backend is not initialized
            KeyError: If key_id is not found
            ValueError: If key algorithm does not support verification
        """
        self._ensure_initialized()

        if key_handle.key_id not in self._keys:
            raise KeyError(f"Key not found: {key_handle.key_id}")

        private_key = self._keys[key_handle.key_id]["private_key"]
        public_key = private_key.public_key()
        algorithm = key_handle.algorithm

        try:
            if algorithm in (
                TPMAlgorithm.RSA_2048,
                TPMAlgorithm.RSA_4096,
            ):
                public_key.verify(
                    signature,
                    data,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH,
                    ),
                    hashes.SHA256(),
                )
            elif algorithm in (
                TPMAlgorithm.ECDSA_P256,
                TPMAlgorithm.ECDSA_P384,
            ):
                hash_alg = (
                    hashes.SHA256() if algorithm == TPMAlgorithm.ECDSA_P256 else hashes.SHA384()
                )
                public_key.verify(signature, data, ec.ECDSA(hash_alg))
            else:
                raise ValueError(f"Algorithm {algorithm.value} does not support " f"verification")
        except Exception as e:
            logger.debug(f"Signature verification failed for key " f"{key_handle.key_id}: {e}")
            return False

        logger.debug(f"Signature verified successfully for key {key_handle.key_id}")
        return True

    async def seal(self, data: bytes, policy_hash: str | None = None) -> TPMSealedData:
        """Seal data using AES-256-GCM with the master seal key.

        Args:
            data: Plaintext data to seal
            policy_hash: Optional PCR policy hash (stored as metadata)

        Returns:
            Sealed data container

        Raises:
            RuntimeError: If backend is not initialized
        """
        self._ensure_initialized()

        nonce = os.urandom(12)
        aesgcm = AESGCM(self._master_seal_key)

        # AES-GCM appends the tag to the ciphertext
        aad = policy_hash.encode() if policy_hash else None
        ct_with_tag = aesgcm.encrypt(nonce, data, aad)

        # Split ciphertext and tag (last 16 bytes are the GCM tag)
        ciphertext = ct_with_tag[:-16]
        tag = ct_with_tag[-16:]

        data_id = str(uuid.uuid4())
        sealed = TPMSealedData(
            data_id=data_id,
            ciphertext=ciphertext,
            nonce=nonce,
            tag=tag,
            policy_hash=policy_hash,
        )

        logger.info(f"Sealed data {data_id} (policy_hash={policy_hash})")
        return sealed

    async def unseal(self, sealed: TPMSealedData) -> bytes:
        """Unseal data previously sealed with seal().

        Args:
            sealed: Sealed data container

        Returns:
            Original plaintext data

        Raises:
            RuntimeError: If backend is not initialized
            Exception: If decryption fails (tampered data or wrong key)
        """
        self._ensure_initialized()

        aesgcm = AESGCM(self._master_seal_key)

        # Reconstruct ciphertext + tag for AESGCM
        ct_with_tag = sealed.ciphertext + sealed.tag
        aad = sealed.policy_hash.encode() if sealed.policy_hash else None

        plaintext = aesgcm.decrypt(sealed.nonce, ct_with_tag, aad)

        logger.debug(f"Unsealed data {sealed.data_id}")
        return plaintext

    async def get_random(self, num_bytes: int) -> bytes:
        """Generate random bytes using os.urandom.

        Args:
            num_bytes: Number of random bytes to generate

        Returns:
            Random bytes

        Raises:
            RuntimeError: If backend is not initialized
        """
        self._ensure_initialized()
        return os.urandom(num_bytes)

    async def destroy_key(self, key_handle: TPMKeyHandle) -> None:
        """Remove a key from the software key store.

        Args:
            key_handle: Handle to the key to destroy

        Raises:
            RuntimeError: If backend is not initialized
            KeyError: If key_id is not found
        """
        self._ensure_initialized()

        if key_handle.key_id not in self._keys:
            raise KeyError(f"Key not found: {key_handle.key_id}")

        del self._keys[key_handle.key_id]
        logger.info(f"Destroyed key {key_handle.key_id}")


class LinuxTPM(TPMBackend):
    """Linux TPM 2.0 backend using the tpm2-pytss library.

    This backend communicates with a hardware TPM via the TCG Software
    Stack (TSS). Requires the ``tpm2-pytss`` package and a TPM 2.0 device
    accessible at /dev/tpm0 or via the TPM resource manager.

    Currently a stub -- all methods raise NotImplementedError since the
    tpm2-pytss dependency is not bundled.
    """

    async def initialize(self) -> None:
        """Initialize connection to the Linux TPM 2.0 device.

        Would establish an ESAPI context via tpm2-pytss and verify
        the TPM is accessible and functional.
        """
        raise NotImplementedError("tpm2-pytss not available")

    async def create_key(self, algorithm: TPMAlgorithm, exportable: bool = False) -> TPMKeyHandle:
        """Create a key in the hardware TPM's key hierarchy.

        Would use TPM2_Create to generate a key under the storage
        primary key (SRK), with attributes set based on the algorithm
        and exportability flag.
        """
        raise NotImplementedError("tpm2-pytss not available")

    async def sign(self, key_handle: TPMKeyHandle, data: bytes) -> bytes:
        """Sign data using a key loaded in the hardware TPM.

        Would use TPM2_Sign with the specified key handle, hashing
        the data with the algorithm associated with the key.
        """
        raise NotImplementedError("tpm2-pytss not available")

    async def verify(self, key_handle: TPMKeyHandle, data: bytes, signature: bytes) -> bool:
        """Verify a signature using the hardware TPM.

        Would use TPM2_VerifySignature to validate the signature
        against the public portion of the signing key.
        """
        raise NotImplementedError("tpm2-pytss not available")

    async def seal(self, data: bytes, policy_hash: str | None = None) -> TPMSealedData:
        """Seal data to the hardware TPM with optional PCR policy.

        Would use TPM2_Create with a sealing key, binding the data
        to specific PCR values if a policy_hash is provided.
        """
        raise NotImplementedError("tpm2-pytss not available")

    async def unseal(self, sealed: TPMSealedData) -> bytes:
        """Unseal data from the hardware TPM.

        Would use TPM2_Unseal, satisfying any PCR policy requirements
        before releasing the sealed plaintext.
        """
        raise NotImplementedError("tpm2-pytss not available")

    async def get_random(self, num_bytes: int) -> bytes:
        """Get random bytes from the hardware TPM's RNG.

        Would use TPM2_GetRandom to obtain hardware-generated
        random bytes from the TPM's internal entropy source.
        """
        raise NotImplementedError("tpm2-pytss not available")

    async def destroy_key(self, key_handle: TPMKeyHandle) -> None:
        """Destroy a key stored in the hardware TPM.

        Would use TPM2_FlushContext to remove the key from the TPM
        and optionally TPM2_EvictControl to remove persistent keys.
        """
        raise NotImplementedError("tpm2-pytss not available")


class TPMKeyManager:
    """High-level key management interface for TPM operations.

    Provides a convenient API for common cryptographic operations,
    abstracting away the details of the underlying TPM backend.
    Tracks keys by their key_id for easy lookup.

    Example:
        >>> manager = TPMKeyManager()
        >>> await manager.backend.initialize()
        >>> key = await manager.create_signing_key()
        >>> sig = await manager.sign_data(key.key_id, b"data")
        >>> valid = await manager.verify_signature(key.key_id, b"data", sig)
    """

    def __init__(self, backend: TPMBackend | None = None) -> None:
        """Initialize the key manager.

        Args:
            backend: TPM backend to use. Defaults to SoftwareTPM if None.
        """
        self.backend = backend or SoftwareTPM()
        self._key_handles: dict[str, TPMKeyHandle] = {}

    async def create_signing_key(
        self, algorithm: TPMAlgorithm = TPMAlgorithm.ECDSA_P256
    ) -> TPMKeyHandle:
        """Create a new signing key.

        Args:
            algorithm: Signing algorithm (must be RSA or ECDSA)

        Returns:
            Handle to the new signing key
        """
        handle = await self.backend.create_key(algorithm)
        self._key_handles[handle.key_id] = handle
        logger.info(f"Created signing key {handle.key_id} " f"(algorithm={algorithm.value})")
        return handle

    async def create_encryption_key(
        self, algorithm: TPMAlgorithm = TPMAlgorithm.AES_256
    ) -> TPMKeyHandle:
        """Create a new encryption key.

        Args:
            algorithm: Encryption algorithm (must be AES)

        Returns:
            Handle to the new encryption key
        """
        handle = await self.backend.create_key(algorithm)
        self._key_handles[handle.key_id] = handle
        logger.info(f"Created encryption key {handle.key_id} " f"(algorithm={algorithm.value})")
        return handle

    async def sign_data(self, key_id: str, data: bytes) -> bytes:
        """Sign data using a managed key.

        Args:
            key_id: ID of the signing key
            data: Data to sign

        Returns:
            Signature bytes

        Raises:
            KeyError: If key_id is not found in managed keys
        """
        if key_id not in self._key_handles:
            raise KeyError(f"Key not found: {key_id}")

        handle = self._key_handles[key_id]
        return await self.backend.sign(handle, data)

    async def verify_signature(self, key_id: str, data: bytes, signature: bytes) -> bool:
        """Verify a signature using a managed key.

        Args:
            key_id: ID of the verification key
            data: Original data that was signed
            signature: Signature to verify

        Returns:
            True if signature is valid, False otherwise

        Raises:
            KeyError: If key_id is not found in managed keys
        """
        if key_id not in self._key_handles:
            raise KeyError(f"Key not found: {key_id}")

        handle = self._key_handles[key_id]
        return await self.backend.verify(handle, data, signature)

    async def seal_secret(self, secret: bytes, policy_hash: str | None = None) -> TPMSealedData:
        """Seal a secret using the TPM backend.

        Args:
            secret: Secret data to seal
            policy_hash: Optional PCR policy hash to bind the secret

        Returns:
            Sealed data container
        """
        return await self.backend.seal(secret, policy_hash)

    async def unseal_secret(self, sealed: TPMSealedData) -> bytes:
        """Unseal a previously sealed secret.

        Args:
            sealed: Sealed data container

        Returns:
            Original secret bytes
        """
        return await self.backend.unseal(sealed)

    async def list_keys(self) -> list[TPMKeyHandle]:
        """List all managed key handles.

        Returns:
            List of key handles tracked by this manager
        """
        return list(self._key_handles.values())

    async def destroy_key(self, key_id: str) -> None:
        """Destroy a managed key.

        Args:
            key_id: ID of the key to destroy

        Raises:
            KeyError: If key_id is not found in managed keys
        """
        if key_id not in self._key_handles:
            raise KeyError(f"Key not found: {key_id}")

        handle = self._key_handles[key_id]
        await self.backend.destroy_key(handle)
        del self._key_handles[key_id]
        logger.info(f"Destroyed managed key {key_id}")

    async def get_random_bytes(self, num_bytes: int = 32) -> bytes:
        """Generate cryptographically secure random bytes.

        Args:
            num_bytes: Number of random bytes (default 32)

        Returns:
            Random bytes from the TPM backend
        """
        return await self.backend.get_random(num_bytes)
