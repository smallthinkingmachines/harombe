"""Hardware Security Module (HSM) integration with software-based default.

This module provides an abstraction layer for HSM operations, with a software-based
implementation using the `cryptography` library as the default backend. Supports
RSA, ECDSA, AES, and HMAC key operations.

Additional backends (PKCS#11 hardware HSMs, Cloud KMS) can be integrated by
implementing the HSMBackend abstract base class.

Example:
    >>> from harombe.security.distributed.hsm import HSMManager, HSMKeyType
    >>>
    >>> # Create manager with software HSM backend (default)
    >>> manager = HSMManager()
    >>> await manager.start()
    >>>
    >>> # Generate an RSA key pair
    >>> key_info = await manager.generate_key(HSMKeyType.RSA_2048, label="my-signing-key")
    >>>
    >>> # Sign and verify data
    >>> signature = await manager.sign(key_info.key_id, b"Hello, world!")
    >>> is_valid = await manager.verify(key_info.key_id, b"Hello, world!", signature)
    >>>
    >>> await manager.stop()
"""

import logging
import os
import time
import uuid
from abc import ABC, abstractmethod
from datetime import datetime
from enum import StrEnum
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hmac import HMAC
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class HSMKeyType(StrEnum):
    """Supported key types for HSM operations.

    Attributes:
        RSA_2048: 2048-bit RSA key pair
        RSA_4096: 4096-bit RSA key pair
        ECDSA_P256: ECDSA key pair on NIST P-256 curve
        ECDSA_P384: ECDSA key pair on NIST P-384 curve
        AES_128: 128-bit AES symmetric key
        AES_256: 256-bit AES symmetric key
        HMAC_SHA256: HMAC key for SHA-256
    """

    RSA_2048 = "rsa_2048"
    RSA_4096 = "rsa_4096"
    ECDSA_P256 = "ecdsa_p256"
    ECDSA_P384 = "ecdsa_p384"
    AES_128 = "aes_128"
    AES_256 = "aes_256"
    HMAC_SHA256 = "hmac_sha256"


class HSMKeyInfo(BaseModel):
    """Metadata about a key stored in the HSM.

    Attributes:
        key_id: Unique identifier for the key
        key_type: Type of the key
        created_at: When the key was generated
        extractable: Whether key material can be exported
        label: Human-readable label for the key
        usage_count: Number of operations performed with this key
    """

    key_id: str
    key_type: HSMKeyType
    created_at: datetime = Field(default_factory=datetime.utcnow)
    extractable: bool = False
    label: str = ""
    usage_count: int = 0


class HSMOperationResult(BaseModel):
    """Result of an HSM cryptographic operation.

    Attributes:
        success: Whether the operation completed successfully
        data: Output data (signature, ciphertext, plaintext, etc.)
        key_id: ID of the key used in the operation
        error: Error message if the operation failed
        operation_time: Time taken for the operation in seconds
    """

    success: bool
    data: bytes | None = None
    key_id: str | None = None
    error: str | None = None
    operation_time: float = 0.0


class HSMBackend(ABC):
    """Abstract base class for HSM backends.

    All HSM implementations must implement this interface, providing key
    generation, signing, verification, encryption, decryption, HMAC, and
    key management operations.
    """

    @abstractmethod
    async def initialize(self) -> None:
        """Initialize the HSM backend and establish connection."""

    @abstractmethod
    async def generate_key(
        self,
        key_type: HSMKeyType,
        label: str = "",
        extractable: bool = False,
    ) -> HSMKeyInfo:
        """Generate a new cryptographic key.

        Args:
            key_type: Type of key to generate
            label: Human-readable label for the key
            extractable: Whether key material can be exported

        Returns:
            HSMKeyInfo with metadata about the generated key
        """

    @abstractmethod
    async def sign(self, key_id: str, data: bytes) -> HSMOperationResult:
        """Sign data using an asymmetric private key.

        Args:
            key_id: ID of the signing key
            data: Data to sign

        Returns:
            HSMOperationResult containing the signature
        """

    @abstractmethod
    async def verify(self, key_id: str, data: bytes, signature: bytes) -> HSMOperationResult:
        """Verify a signature against data.

        Args:
            key_id: ID of the verification key
            data: Original data that was signed
            signature: Signature to verify

        Returns:
            HSMOperationResult with success indicating validity
        """

    @abstractmethod
    async def encrypt(self, key_id: str, plaintext: bytes) -> HSMOperationResult:
        """Encrypt plaintext data.

        Args:
            key_id: ID of the encryption key
            plaintext: Data to encrypt

        Returns:
            HSMOperationResult containing the ciphertext
        """

    @abstractmethod
    async def decrypt(self, key_id: str, ciphertext: bytes) -> HSMOperationResult:
        """Decrypt ciphertext data.

        Args:
            key_id: ID of the decryption key
            ciphertext: Data to decrypt

        Returns:
            HSMOperationResult containing the plaintext
        """

    @abstractmethod
    async def hmac_sign(self, key_id: str, data: bytes) -> HSMOperationResult:
        """Compute HMAC for data.

        Args:
            key_id: ID of the HMAC key
            data: Data to authenticate

        Returns:
            HSMOperationResult containing the MAC
        """

    @abstractmethod
    async def hmac_verify(self, key_id: str, data: bytes, mac: bytes) -> HSMOperationResult:
        """Verify HMAC for data.

        Args:
            key_id: ID of the HMAC key
            data: Original data
            mac: MAC to verify

        Returns:
            HSMOperationResult with success indicating validity
        """

    @abstractmethod
    async def export_key(self, key_id: str) -> HSMOperationResult:
        """Export key material (only if the key is extractable).

        Args:
            key_id: ID of the key to export

        Returns:
            HSMOperationResult containing key material bytes
        """

    @abstractmethod
    async def destroy_key(self, key_id: str) -> None:
        """Destroy a key, removing it from the HSM.

        Args:
            key_id: ID of the key to destroy
        """

    @abstractmethod
    async def list_keys(self) -> list[HSMKeyInfo]:
        """List all keys in the HSM.

        Returns:
            List of HSMKeyInfo for all stored keys
        """

    @abstractmethod
    async def get_key_info(self, key_id: str) -> HSMKeyInfo | None:
        """Get metadata for a specific key.

        Args:
            key_id: ID of the key

        Returns:
            HSMKeyInfo if found, None otherwise
        """

    @abstractmethod
    async def shutdown(self) -> None:
        """Shutdown the HSM backend and release resources."""


class SoftwareHSM(HSMBackend):
    """Software-based HSM implementation using the cryptography library.

    Stores keys in memory and uses the `cryptography` library for all
    cryptographic operations. Suitable for development, testing, and
    environments without hardware HSM access.

    Key types supported:
        - RSA (2048/4096): Sign/verify with PSS+SHA256, encrypt/decrypt with OAEP+SHA256
        - ECDSA (P-256/P-384): Sign/verify with SHA256
        - AES (128/256): Encrypt/decrypt with AES-GCM (12-byte nonce prepended)
        - HMAC-SHA256: Sign/verify message authentication codes
    """

    def __init__(self) -> None:
        """Initialize the software HSM with empty key stores."""
        self._keys: dict[str, Any] = {}
        self._key_info: dict[str, HSMKeyInfo] = {}
        self._initialized = False

    async def initialize(self) -> None:
        """Initialize the software HSM backend."""
        self._initialized = True
        logger.info("SoftwareHSM initialized")

    async def generate_key(
        self,
        key_type: HSMKeyType,
        label: str = "",
        extractable: bool = False,
    ) -> HSMKeyInfo:
        """Generate a new cryptographic key in software.

        Args:
            key_type: Type of key to generate
            label: Human-readable label for the key
            extractable: Whether key material can be exported

        Returns:
            HSMKeyInfo with metadata about the generated key
        """
        key_id = str(uuid.uuid4())
        private_key: Any = None

        if key_type == HSMKeyType.RSA_2048:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            self._keys[key_id] = private_key
        elif key_type == HSMKeyType.RSA_4096:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=4096,
            )
            self._keys[key_id] = private_key
        elif key_type == HSMKeyType.ECDSA_P256:
            private_key = ec.generate_private_key(ec.SECP256R1())
            self._keys[key_id] = private_key
        elif key_type == HSMKeyType.ECDSA_P384:
            private_key = ec.generate_private_key(ec.SECP384R1())
            self._keys[key_id] = private_key
        elif key_type == HSMKeyType.AES_128:
            key_bytes = AESGCM.generate_key(bit_length=128)
            self._keys[key_id] = key_bytes
        elif key_type == HSMKeyType.AES_256:
            key_bytes = AESGCM.generate_key(bit_length=256)
            self._keys[key_id] = key_bytes
        elif key_type == HSMKeyType.HMAC_SHA256:
            key_bytes = os.urandom(32)
            self._keys[key_id] = key_bytes
        else:
            raise ValueError(f"Unsupported key type: {key_type}")

        info = HSMKeyInfo(
            key_id=key_id,
            key_type=key_type,
            extractable=extractable,
            label=label,
        )
        self._key_info[key_id] = info

        logger.info(
            f"Generated {key_type.value} key {key_id} "
            f"(label={label!r}, extractable={extractable})"
        )
        return info

    async def sign(self, key_id: str, data: bytes) -> HSMOperationResult:
        """Sign data using RSA-PSS or ECDSA.

        Args:
            key_id: ID of the signing key (RSA or ECDSA)
            data: Data to sign

        Returns:
            HSMOperationResult containing the signature
        """
        start = time.monotonic()
        try:
            key = self._keys.get(key_id)
            if key is None:
                return HSMOperationResult(
                    success=False,
                    key_id=key_id,
                    error=f"Key not found: {key_id}",
                )

            info = self._key_info[key_id]

            if info.key_type in (HSMKeyType.RSA_2048, HSMKeyType.RSA_4096):
                sig = key.sign(
                    data,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH,
                    ),
                    hashes.SHA256(),
                )
            elif info.key_type in (
                HSMKeyType.ECDSA_P256,
                HSMKeyType.ECDSA_P384,
            ):
                sig = key.sign(data, ec.ECDSA(hashes.SHA256()))
            else:
                return HSMOperationResult(
                    success=False,
                    key_id=key_id,
                    error=f"Key type {info.key_type} does not support signing",
                )

            info.usage_count += 1
            elapsed = time.monotonic() - start
            return HSMOperationResult(
                success=True,
                data=sig,
                key_id=key_id,
                operation_time=elapsed,
            )
        except Exception as e:
            elapsed = time.monotonic() - start
            logger.error(f"Sign operation failed for key {key_id}: {e}")
            return HSMOperationResult(
                success=False,
                key_id=key_id,
                error=str(e),
                operation_time=elapsed,
            )

    async def verify(self, key_id: str, data: bytes, signature: bytes) -> HSMOperationResult:
        """Verify a signature using RSA-PSS or ECDSA.

        Args:
            key_id: ID of the verification key (RSA or ECDSA)
            data: Original data that was signed
            signature: Signature to verify

        Returns:
            HSMOperationResult with success indicating validity
        """
        start = time.monotonic()
        try:
            key = self._keys.get(key_id)
            if key is None:
                return HSMOperationResult(
                    success=False,
                    key_id=key_id,
                    error=f"Key not found: {key_id}",
                )

            info = self._key_info[key_id]

            if info.key_type in (HSMKeyType.RSA_2048, HSMKeyType.RSA_4096):
                public_key = key.public_key()
                public_key.verify(
                    signature,
                    data,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH,
                    ),
                    hashes.SHA256(),
                )
            elif info.key_type in (
                HSMKeyType.ECDSA_P256,
                HSMKeyType.ECDSA_P384,
            ):
                public_key = key.public_key()
                public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
            else:
                return HSMOperationResult(
                    success=False,
                    key_id=key_id,
                    error=(f"Key type {info.key_type} does not support " f"verification"),
                )

            info.usage_count += 1
            elapsed = time.monotonic() - start
            return HSMOperationResult(
                success=True,
                key_id=key_id,
                operation_time=elapsed,
            )
        except Exception as e:
            elapsed = time.monotonic() - start
            return HSMOperationResult(
                success=False,
                key_id=key_id,
                error=str(e),
                operation_time=elapsed,
            )

    async def encrypt(self, key_id: str, plaintext: bytes) -> HSMOperationResult:
        """Encrypt data using RSA-OAEP or AES-GCM.

        For AES keys, a random 12-byte nonce is generated and prepended
        to the ciphertext output.

        Args:
            key_id: ID of the encryption key (RSA or AES)
            plaintext: Data to encrypt

        Returns:
            HSMOperationResult containing the ciphertext
        """
        start = time.monotonic()
        try:
            key = self._keys.get(key_id)
            if key is None:
                return HSMOperationResult(
                    success=False,
                    key_id=key_id,
                    error=f"Key not found: {key_id}",
                )

            info = self._key_info[key_id]

            if info.key_type in (HSMKeyType.RSA_2048, HSMKeyType.RSA_4096):
                public_key = key.public_key()
                ciphertext = public_key.encrypt(
                    plaintext,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None,
                    ),
                )
            elif info.key_type in (HSMKeyType.AES_128, HSMKeyType.AES_256):
                nonce = os.urandom(12)
                aesgcm = AESGCM(key)
                ct = aesgcm.encrypt(nonce, plaintext, None)
                ciphertext = nonce + ct
            else:
                return HSMOperationResult(
                    success=False,
                    key_id=key_id,
                    error=(f"Key type {info.key_type} does not support " f"encryption"),
                )

            info.usage_count += 1
            elapsed = time.monotonic() - start
            return HSMOperationResult(
                success=True,
                data=ciphertext,
                key_id=key_id,
                operation_time=elapsed,
            )
        except Exception as e:
            elapsed = time.monotonic() - start
            logger.error(f"Encrypt operation failed for key {key_id}: {e}")
            return HSMOperationResult(
                success=False,
                key_id=key_id,
                error=str(e),
                operation_time=elapsed,
            )

    async def decrypt(self, key_id: str, ciphertext: bytes) -> HSMOperationResult:
        """Decrypt data using RSA-OAEP or AES-GCM.

        For AES keys, expects the 12-byte nonce to be prepended to the
        ciphertext (as produced by the encrypt method).

        Args:
            key_id: ID of the decryption key (RSA or AES)
            ciphertext: Data to decrypt

        Returns:
            HSMOperationResult containing the plaintext
        """
        start = time.monotonic()
        try:
            key = self._keys.get(key_id)
            if key is None:
                return HSMOperationResult(
                    success=False,
                    key_id=key_id,
                    error=f"Key not found: {key_id}",
                )

            info = self._key_info[key_id]

            if info.key_type in (HSMKeyType.RSA_2048, HSMKeyType.RSA_4096):
                plaintext = key.decrypt(
                    ciphertext,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None,
                    ),
                )
            elif info.key_type in (HSMKeyType.AES_128, HSMKeyType.AES_256):
                nonce = ciphertext[:12]
                ct = ciphertext[12:]
                aesgcm = AESGCM(key)
                plaintext = aesgcm.decrypt(nonce, ct, None)
            else:
                return HSMOperationResult(
                    success=False,
                    key_id=key_id,
                    error=(f"Key type {info.key_type} does not support " f"decryption"),
                )

            info.usage_count += 1
            elapsed = time.monotonic() - start
            return HSMOperationResult(
                success=True,
                data=plaintext,
                key_id=key_id,
                operation_time=elapsed,
            )
        except Exception as e:
            elapsed = time.monotonic() - start
            logger.error(f"Decrypt operation failed for key {key_id}: {e}")
            return HSMOperationResult(
                success=False,
                key_id=key_id,
                error=str(e),
                operation_time=elapsed,
            )

    async def hmac_sign(self, key_id: str, data: bytes) -> HSMOperationResult:
        """Compute HMAC-SHA256 for data.

        Args:
            key_id: ID of the HMAC key
            data: Data to authenticate

        Returns:
            HSMOperationResult containing the MAC
        """
        start = time.monotonic()
        try:
            key = self._keys.get(key_id)
            if key is None:
                return HSMOperationResult(
                    success=False,
                    key_id=key_id,
                    error=f"Key not found: {key_id}",
                )

            info = self._key_info[key_id]
            if info.key_type != HSMKeyType.HMAC_SHA256:
                return HSMOperationResult(
                    success=False,
                    key_id=key_id,
                    error=(f"Key type {info.key_type} does not support " f"HMAC operations"),
                )

            h = HMAC(key, hashes.SHA256())
            h.update(data)
            mac = h.finalize()

            info.usage_count += 1
            elapsed = time.monotonic() - start
            return HSMOperationResult(
                success=True,
                data=mac,
                key_id=key_id,
                operation_time=elapsed,
            )
        except Exception as e:
            elapsed = time.monotonic() - start
            logger.error(f"HMAC sign operation failed for key {key_id}: {e}")
            return HSMOperationResult(
                success=False,
                key_id=key_id,
                error=str(e),
                operation_time=elapsed,
            )

    async def hmac_verify(self, key_id: str, data: bytes, mac: bytes) -> HSMOperationResult:
        """Verify HMAC-SHA256 for data.

        Args:
            key_id: ID of the HMAC key
            data: Original data
            mac: MAC to verify

        Returns:
            HSMOperationResult with success indicating validity
        """
        start = time.monotonic()
        try:
            key = self._keys.get(key_id)
            if key is None:
                return HSMOperationResult(
                    success=False,
                    key_id=key_id,
                    error=f"Key not found: {key_id}",
                )

            info = self._key_info[key_id]
            if info.key_type != HSMKeyType.HMAC_SHA256:
                return HSMOperationResult(
                    success=False,
                    key_id=key_id,
                    error=(f"Key type {info.key_type} does not support " f"HMAC operations"),
                )

            h = HMAC(key, hashes.SHA256())
            h.update(data)
            h.verify(mac)

            info.usage_count += 1
            elapsed = time.monotonic() - start
            return HSMOperationResult(
                success=True,
                key_id=key_id,
                operation_time=elapsed,
            )
        except Exception as e:
            elapsed = time.monotonic() - start
            return HSMOperationResult(
                success=False,
                key_id=key_id,
                error=str(e),
                operation_time=elapsed,
            )

    async def export_key(self, key_id: str) -> HSMOperationResult:
        """Export key material (only if the key is marked extractable).

        Args:
            key_id: ID of the key to export

        Returns:
            HSMOperationResult containing key material bytes
        """
        start = time.monotonic()
        try:
            info = self._key_info.get(key_id)
            if info is None:
                return HSMOperationResult(
                    success=False,
                    key_id=key_id,
                    error=f"Key not found: {key_id}",
                )

            if not info.extractable:
                return HSMOperationResult(
                    success=False,
                    key_id=key_id,
                    error="Key is not extractable",
                )

            key = self._keys[key_id]

            if info.key_type in (
                HSMKeyType.RSA_2048,
                HSMKeyType.RSA_4096,
                HSMKeyType.ECDSA_P256,
                HSMKeyType.ECDSA_P384,
            ):
                key_bytes = key.private_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            elif info.key_type in (
                HSMKeyType.AES_128,
                HSMKeyType.AES_256,
                HSMKeyType.HMAC_SHA256,
            ):
                key_bytes = key
            else:
                return HSMOperationResult(
                    success=False,
                    key_id=key_id,
                    error=f"Unsupported key type for export: {info.key_type}",
                )

            elapsed = time.monotonic() - start
            return HSMOperationResult(
                success=True,
                data=key_bytes,
                key_id=key_id,
                operation_time=elapsed,
            )
        except Exception as e:
            elapsed = time.monotonic() - start
            logger.error(f"Export key failed for {key_id}: {e}")
            return HSMOperationResult(
                success=False,
                key_id=key_id,
                error=str(e),
                operation_time=elapsed,
            )

    async def destroy_key(self, key_id: str) -> None:
        """Destroy a key, removing it from memory.

        Args:
            key_id: ID of the key to destroy
        """
        self._keys.pop(key_id, None)
        self._key_info.pop(key_id, None)
        logger.info(f"Destroyed key {key_id}")

    async def list_keys(self) -> list[HSMKeyInfo]:
        """List all keys stored in the software HSM.

        Returns:
            List of HSMKeyInfo for all stored keys
        """
        return list(self._key_info.values())

    async def get_key_info(self, key_id: str) -> HSMKeyInfo | None:
        """Get metadata for a specific key.

        Args:
            key_id: ID of the key

        Returns:
            HSMKeyInfo if found, None otherwise
        """
        return self._key_info.get(key_id)

    async def shutdown(self) -> None:
        """Shutdown the software HSM, clearing all keys from memory."""
        self._keys.clear()
        self._key_info.clear()
        self._initialized = False
        logger.info("SoftwareHSM shut down")


class PKCS11HSM(HSMBackend):
    """PKCS#11 hardware HSM backend (stub).

    This backend is a placeholder for PKCS#11 hardware HSM integration.
    All methods raise NotImplementedError until python-pkcs11 is installed
    and configured.
    """

    async def initialize(self) -> None:
        raise NotImplementedError("python-pkcs11 not installed")

    async def generate_key(
        self,
        key_type: HSMKeyType,
        label: str = "",
        extractable: bool = False,
    ) -> HSMKeyInfo:
        raise NotImplementedError("python-pkcs11 not installed")

    async def sign(self, key_id: str, data: bytes) -> HSMOperationResult:
        raise NotImplementedError("python-pkcs11 not installed")

    async def verify(self, key_id: str, data: bytes, signature: bytes) -> HSMOperationResult:
        raise NotImplementedError("python-pkcs11 not installed")

    async def encrypt(self, key_id: str, plaintext: bytes) -> HSMOperationResult:
        raise NotImplementedError("python-pkcs11 not installed")

    async def decrypt(self, key_id: str, ciphertext: bytes) -> HSMOperationResult:
        raise NotImplementedError("python-pkcs11 not installed")

    async def hmac_sign(self, key_id: str, data: bytes) -> HSMOperationResult:
        raise NotImplementedError("python-pkcs11 not installed")

    async def hmac_verify(self, key_id: str, data: bytes, mac: bytes) -> HSMOperationResult:
        raise NotImplementedError("python-pkcs11 not installed")

    async def export_key(self, key_id: str) -> HSMOperationResult:
        raise NotImplementedError("python-pkcs11 not installed")

    async def destroy_key(self, key_id: str) -> None:
        raise NotImplementedError("python-pkcs11 not installed")

    async def list_keys(self) -> list[HSMKeyInfo]:
        raise NotImplementedError("python-pkcs11 not installed")

    async def get_key_info(self, key_id: str) -> HSMKeyInfo | None:
        raise NotImplementedError("python-pkcs11 not installed")

    async def shutdown(self) -> None:
        raise NotImplementedError("python-pkcs11 not installed")


class CloudKMSHSM(HSMBackend):
    """Cloud KMS HSM backend (stub).

    This backend is a placeholder for Cloud KMS (AWS KMS, GCP KMS, Azure
    Key Vault) integration. All methods raise NotImplementedError until
    a cloud KMS provider is configured.
    """

    async def initialize(self) -> None:
        raise NotImplementedError("Cloud KMS not configured")

    async def generate_key(
        self,
        key_type: HSMKeyType,
        label: str = "",
        extractable: bool = False,
    ) -> HSMKeyInfo:
        raise NotImplementedError("Cloud KMS not configured")

    async def sign(self, key_id: str, data: bytes) -> HSMOperationResult:
        raise NotImplementedError("Cloud KMS not configured")

    async def verify(self, key_id: str, data: bytes, signature: bytes) -> HSMOperationResult:
        raise NotImplementedError("Cloud KMS not configured")

    async def encrypt(self, key_id: str, plaintext: bytes) -> HSMOperationResult:
        raise NotImplementedError("Cloud KMS not configured")

    async def decrypt(self, key_id: str, ciphertext: bytes) -> HSMOperationResult:
        raise NotImplementedError("Cloud KMS not configured")

    async def hmac_sign(self, key_id: str, data: bytes) -> HSMOperationResult:
        raise NotImplementedError("Cloud KMS not configured")

    async def hmac_verify(self, key_id: str, data: bytes, mac: bytes) -> HSMOperationResult:
        raise NotImplementedError("Cloud KMS not configured")

    async def export_key(self, key_id: str) -> HSMOperationResult:
        raise NotImplementedError("Cloud KMS not configured")

    async def destroy_key(self, key_id: str) -> None:
        raise NotImplementedError("Cloud KMS not configured")

    async def list_keys(self) -> list[HSMKeyInfo]:
        raise NotImplementedError("Cloud KMS not configured")

    async def get_key_info(self, key_id: str) -> HSMKeyInfo | None:
        raise NotImplementedError("Cloud KMS not configured")

    async def shutdown(self) -> None:
        raise NotImplementedError("Cloud KMS not configured")


class HSMManager:
    """High-level manager for HSM operations.

    Provides a simplified interface for key management and cryptographic
    operations, with built-in operation tracking and statistics. Defaults
    to SoftwareHSM if no backend is specified.

    Example:
        >>> manager = HSMManager()
        >>> await manager.start()
        >>> key = await manager.generate_key(HSMKeyType.AES_256, label="data-key")
        >>> ct = await manager.encrypt(key.key_id, b"secret data")
        >>> pt = await manager.decrypt(key.key_id, ct)
        >>> assert pt == b"secret data"
        >>> await manager.stop()
    """

    def __init__(self, backend: HSMBackend | None = None) -> None:
        """Initialize the HSM manager.

        Args:
            backend: HSM backend to use. Defaults to SoftwareHSM.
        """
        self._backend = backend or SoftwareHSM()
        self._started = False
        self._stats: dict[str, int] = {
            "keys_generated": 0,
            "sign_operations": 0,
            "verify_operations": 0,
            "encrypt_operations": 0,
            "decrypt_operations": 0,
            "hmac_sign_operations": 0,
            "hmac_verify_operations": 0,
            "keys_destroyed": 0,
            "errors": 0,
        }

    async def start(self) -> None:
        """Start the HSM manager and initialize the backend."""
        await self._backend.initialize()
        self._started = True
        logger.info("HSMManager started")

    async def stop(self) -> None:
        """Stop the HSM manager and shutdown the backend."""
        await self._backend.shutdown()
        self._started = False
        logger.info("HSMManager stopped")

    async def generate_key(
        self,
        key_type: HSMKeyType,
        label: str = "",
        extractable: bool = False,
    ) -> HSMKeyInfo:
        """Generate a new cryptographic key.

        Args:
            key_type: Type of key to generate
            label: Human-readable label for the key
            extractable: Whether key material can be exported

        Returns:
            HSMKeyInfo with metadata about the generated key
        """
        info = await self._backend.generate_key(key_type, label=label, extractable=extractable)
        self._stats["keys_generated"] += 1
        return info

    async def sign(self, key_id: str, data: bytes) -> bytes:
        """Sign data using an asymmetric private key.

        Args:
            key_id: ID of the signing key
            data: Data to sign

        Returns:
            Signature bytes

        Raises:
            RuntimeError: If the sign operation fails
        """
        result = await self._backend.sign(key_id, data)
        self._stats["sign_operations"] += 1
        if not result.success:
            self._stats["errors"] += 1
            raise RuntimeError(f"Sign operation failed: {result.error}")
        return result.data  # type: ignore[return-value]

    async def verify(self, key_id: str, data: bytes, signature: bytes) -> bool:
        """Verify a signature against data.

        Args:
            key_id: ID of the verification key
            data: Original data that was signed
            signature: Signature to verify

        Returns:
            True if signature is valid, False otherwise
        """
        result = await self._backend.verify(key_id, data, signature)
        self._stats["verify_operations"] += 1
        if not result.success:
            self._stats["errors"] += 1
        return result.success

    async def encrypt(self, key_id: str, plaintext: bytes) -> bytes:
        """Encrypt plaintext data.

        Args:
            key_id: ID of the encryption key
            plaintext: Data to encrypt

        Returns:
            Ciphertext bytes

        Raises:
            RuntimeError: If the encrypt operation fails
        """
        result = await self._backend.encrypt(key_id, plaintext)
        self._stats["encrypt_operations"] += 1
        if not result.success:
            self._stats["errors"] += 1
            raise RuntimeError(f"Encrypt operation failed: {result.error}")
        return result.data  # type: ignore[return-value]

    async def decrypt(self, key_id: str, ciphertext: bytes) -> bytes:
        """Decrypt ciphertext data.

        Args:
            key_id: ID of the decryption key
            ciphertext: Data to decrypt

        Returns:
            Plaintext bytes

        Raises:
            RuntimeError: If the decrypt operation fails
        """
        result = await self._backend.decrypt(key_id, ciphertext)
        self._stats["decrypt_operations"] += 1
        if not result.success:
            self._stats["errors"] += 1
            raise RuntimeError(f"Decrypt operation failed: {result.error}")
        return result.data  # type: ignore[return-value]

    async def hmac_sign(self, key_id: str, data: bytes) -> bytes:
        """Compute HMAC for data.

        Args:
            key_id: ID of the HMAC key
            data: Data to authenticate

        Returns:
            MAC bytes

        Raises:
            RuntimeError: If the HMAC operation fails
        """
        result = await self._backend.hmac_sign(key_id, data)
        self._stats["hmac_sign_operations"] += 1
        if not result.success:
            self._stats["errors"] += 1
            raise RuntimeError(f"HMAC sign operation failed: {result.error}")
        return result.data  # type: ignore[return-value]

    async def hmac_verify(self, key_id: str, data: bytes, mac: bytes) -> bool:
        """Verify HMAC for data.

        Args:
            key_id: ID of the HMAC key
            data: Original data
            mac: MAC to verify

        Returns:
            True if MAC is valid, False otherwise
        """
        result = await self._backend.hmac_verify(key_id, data, mac)
        self._stats["hmac_verify_operations"] += 1
        if not result.success:
            self._stats["errors"] += 1
        return result.success

    async def list_keys(self) -> list[HSMKeyInfo]:
        """List all keys in the HSM.

        Returns:
            List of HSMKeyInfo for all stored keys
        """
        return await self._backend.list_keys()

    async def destroy_key(self, key_id: str) -> None:
        """Destroy a key, removing it from the HSM.

        Args:
            key_id: ID of the key to destroy
        """
        await self._backend.destroy_key(key_id)
        self._stats["keys_destroyed"] += 1

    async def get_stats(self) -> dict[str, Any]:
        """Get operation statistics.

        Returns:
            Dictionary with operation counts and key inventory
        """
        keys = await self._backend.list_keys()
        return {
            **self._stats,
            "total_keys": len(keys),
            "backend": type(self._backend).__name__,
        }
