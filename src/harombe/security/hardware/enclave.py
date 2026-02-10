"""Secure enclave utilization for hardware-backed isolated execution.

This module provides secure enclave functionality for executing sensitive
computations in isolated environments. It supports a software-based enclave
for development and testing, with stubs for hardware-backed enclaves (Intel SGX).

The software enclave simulates sealed computation using HMAC and provides
data sealing/unsealing via AES-GCM encryption.

Example:
    >>> import asyncio
    >>> from harombe.security.hardware.enclave import (
    ...     EnclaveManager,
    ...     EnclaveConfig,
    ... )
    >>>
    >>> async def main():
    ...     manager = EnclaveManager()
    ...     enclave_id = await manager.create_enclave(
    ...         EnclaveConfig(max_memory_mb=128)
    ...     )
    ...
    ...     # Execute sealed computation
    ...     result = await manager.execute_in_enclave(
    ...         enclave_id, b"compute", b"input_data"
    ...     )
    ...     print(f"Success: {result.success}")
    ...
    ...     # Seal and unseal data
    ...     sealed = await manager.seal_data(enclave_id, b"secret")
    ...     original = await manager.unseal_data(enclave_id, sealed)
    ...     assert original == b"secret"
    ...
    ...     await manager.destroy_enclave(enclave_id)
    >>>
    >>> asyncio.run(main())
"""

import hashlib
import hmac
import logging
import os
import time
import uuid
from abc import ABC, abstractmethod
from enum import StrEnum
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

_NONCE_SIZE = 12
_KEY_SIZE = 32


class EnclaveStatus(StrEnum):
    """Enclave lifecycle status.

    Attributes:
        UNINITIALIZED: Enclave has been created but not yet initialized.
        INITIALIZING: Enclave is currently being initialized.
        READY: Enclave is initialized and ready for operations.
        EXECUTING: Enclave is currently executing a computation.
        ERROR: Enclave encountered an error.
        DESTROYED: Enclave has been destroyed and cannot be used.
    """

    UNINITIALIZED = "uninitialized"
    INITIALIZING = "initializing"
    READY = "ready"
    EXECUTING = "executing"
    ERROR = "error"
    DESTROYED = "destroyed"


class EnclaveConfig(BaseModel):
    """Configuration for enclave creation.

    Attributes:
        max_memory_mb: Maximum memory allocation in MB.
        max_execution_time: Maximum execution time in seconds.
        allow_networking: Whether the enclave may access the network.
        debug_mode: Enable debug output (insecure for production).
        enclave_id: Optional explicit enclave identifier.
    """

    max_memory_mb: int = 256
    max_execution_time: int = 30
    allow_networking: bool = False
    debug_mode: bool = False
    enclave_id: str | None = None


class EnclaveResult(BaseModel):
    """Result returned from enclave execution.

    Attributes:
        success: Whether the execution completed successfully.
        output: Raw output bytes from the computation.
        error: Error message if execution failed.
        execution_time: Wall-clock execution time in seconds.
        enclave_id: Identifier of the enclave that ran the computation.
        attestation_report: Attestation data proving enclave integrity.
    """

    success: bool
    output: bytes | None = None
    error: str | None = None
    execution_time: float = 0.0
    enclave_id: str = ""
    attestation_report: dict[str, Any] = Field(default_factory=dict)


class EnclaveBackend(ABC):
    """Abstract base class for enclave backends.

    All enclave implementations must follow the lifecycle:
    initialize -> (execute | seal_data | unseal_data)* -> destroy
    """

    @abstractmethod
    async def initialize(self, config: EnclaveConfig) -> None:
        """Initialize the enclave with the given configuration.

        Args:
            config: Enclave configuration parameters.
        """

    @abstractmethod
    async def execute(self, code: bytes, input_data: bytes | None = None) -> EnclaveResult:
        """Execute a sealed computation inside the enclave.

        Args:
            code: Code bytes representing the computation.
            input_data: Optional input data for the computation.

        Returns:
            EnclaveResult with the computation output.
        """

    @abstractmethod
    async def seal_data(self, data: bytes) -> bytes:
        """Encrypt data so only this enclave can decrypt it.

        Args:
            data: Plaintext data to seal.

        Returns:
            Sealed (encrypted) data bytes.
        """

    @abstractmethod
    async def unseal_data(self, sealed_data: bytes) -> bytes:
        """Decrypt data that was previously sealed by this enclave.

        Args:
            sealed_data: Sealed data bytes to decrypt.

        Returns:
            Original plaintext data.
        """

    @abstractmethod
    async def get_attestation_report(self) -> dict[str, Any]:
        """Generate an attestation report proving enclave integrity.

        Returns:
            Dictionary containing attestation measurements.
        """

    @abstractmethod
    async def destroy(self) -> None:
        """Destroy the enclave and wipe all secrets."""

    @property
    @abstractmethod
    def status(self) -> EnclaveStatus:
        """Current enclave lifecycle status."""


class SoftwareEnclave(EnclaveBackend):
    """Software-based enclave implementation.

    Provides a software simulation of a secure enclave for development
    and testing. Uses AES-GCM for data sealing and HMAC for simulating
    sealed computation. Does NOT provide the hardware isolation
    guarantees of a real enclave (Intel SGX, ARM TrustZone, etc.).

    Example:
        >>> enclave = SoftwareEnclave()
        >>> await enclave.initialize(EnclaveConfig())
        >>> result = await enclave.execute(b"code", b"input")
        >>> sealed = await enclave.seal_data(b"secret")
        >>> original = await enclave.unseal_data(sealed)
    """

    def __init__(self) -> None:
        """Initialize software enclave in uninitialized state."""
        self._status = EnclaveStatus.UNINITIALIZED
        self._config: EnclaveConfig | None = None
        self._seal_key: bytes | None = None
        self._enclave_id: str = ""
        self._hmac_key: bytes | None = None

    @property
    def status(self) -> EnclaveStatus:
        """Current enclave lifecycle status."""
        return self._status

    async def initialize(self, config: EnclaveConfig) -> None:
        """Initialize the software enclave.

        Generates cryptographic keys for sealing and HMAC computation.

        Args:
            config: Enclave configuration parameters.
        """
        self._status = EnclaveStatus.INITIALIZING
        logger.info("Initializing software enclave")

        try:
            self._config = config
            self._enclave_id = config.enclave_id or str(uuid.uuid4())
            self._seal_key = os.urandom(_KEY_SIZE)
            self._hmac_key = os.urandom(_KEY_SIZE)
            self._status = EnclaveStatus.READY
            logger.info(
                f"Software enclave {self._enclave_id} initialized "
                f"(memory={config.max_memory_mb}MB, "
                f"timeout={config.max_execution_time}s)"
            )
        except Exception as e:
            self._status = EnclaveStatus.ERROR
            logger.error(f"Failed to initialize software enclave: {e}")
            raise

    async def execute(self, code: bytes, input_data: bytes | None = None) -> EnclaveResult:
        """Execute a sealed computation via HMAC simulation.

        Instead of executing arbitrary code, this computes an HMAC of the
        code and input data to simulate a deterministic sealed computation.

        Args:
            code: Code bytes representing the computation.
            input_data: Optional input data for the computation.

        Returns:
            EnclaveResult with HMAC output bytes.

        Raises:
            RuntimeError: If enclave is not in READY state.
        """
        if self._status == EnclaveStatus.DESTROYED:
            raise RuntimeError("Enclave has been destroyed")
        if self._status != EnclaveStatus.READY:
            raise RuntimeError(f"Enclave not ready (status={self._status})")

        self._status = EnclaveStatus.EXECUTING
        start_time = time.monotonic()

        try:
            # Build the message to HMAC: code + optional input_data
            message = code
            if input_data is not None:
                message = code + input_data

            output = hmac.new(
                self._hmac_key,  # type: ignore[arg-type]
                message,
                hashlib.sha256,
            ).digest()

            execution_time = time.monotonic() - start_time
            self._status = EnclaveStatus.READY

            logger.debug(
                f"Enclave {self._enclave_id} execution completed " f"in {execution_time:.4f}s"
            )

            return EnclaveResult(
                success=True,
                output=output,
                execution_time=execution_time,
                enclave_id=self._enclave_id,
                attestation_report=await self.get_attestation_report(),
            )
        except Exception as e:
            self._status = EnclaveStatus.ERROR
            execution_time = time.monotonic() - start_time
            logger.error(f"Enclave {self._enclave_id} execution failed: {e}")
            return EnclaveResult(
                success=False,
                error=str(e),
                execution_time=execution_time,
                enclave_id=self._enclave_id,
            )

    async def seal_data(self, data: bytes) -> bytes:
        """Encrypt data using AES-GCM with the enclave seal key.

        The nonce (12 bytes) is prepended to the ciphertext so that
        unseal_data can extract it for decryption.

        Args:
            data: Plaintext data to seal.

        Returns:
            Nonce + ciphertext bytes.

        Raises:
            RuntimeError: If enclave is not in READY state.
        """
        if self._status == EnclaveStatus.DESTROYED:
            raise RuntimeError("Enclave has been destroyed")
        if self._status != EnclaveStatus.READY:
            raise RuntimeError(f"Enclave not ready (status={self._status})")

        nonce = os.urandom(_NONCE_SIZE)
        aesgcm = AESGCM(self._seal_key)  # type: ignore[arg-type]
        ciphertext = aesgcm.encrypt(nonce, data, None)

        logger.debug(f"Sealed {len(data)} bytes in enclave {self._enclave_id}")
        return nonce + ciphertext

    async def unseal_data(self, sealed_data: bytes) -> bytes:
        """Decrypt data that was previously sealed by this enclave.

        Extracts the 12-byte nonce prefix and decrypts the remainder
        using AES-GCM.

        Args:
            sealed_data: Nonce + ciphertext bytes from seal_data.

        Returns:
            Original plaintext data.

        Raises:
            RuntimeError: If enclave is not in READY state.
            ValueError: If sealed data is too short.
            cryptography.exceptions.InvalidTag: If data was tampered with.
        """
        if self._status == EnclaveStatus.DESTROYED:
            raise RuntimeError("Enclave has been destroyed")
        if self._status != EnclaveStatus.READY:
            raise RuntimeError(f"Enclave not ready (status={self._status})")

        if len(sealed_data) < _NONCE_SIZE:
            raise ValueError("Sealed data is too short to contain a nonce")

        nonce = sealed_data[:_NONCE_SIZE]
        ciphertext = sealed_data[_NONCE_SIZE:]
        aesgcm = AESGCM(self._seal_key)  # type: ignore[arg-type]
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)

        logger.debug(f"Unsealed {len(plaintext)} bytes in enclave " f"{self._enclave_id}")
        return plaintext

    async def get_attestation_report(self) -> dict[str, Any]:
        """Generate a software attestation report.

        The report includes the enclave identifier, current status, and
        SHA-256 measurements of the seal key and HMAC key.

        Returns:
            Dictionary with enclave_id, status, and measurements.
        """
        measurements: dict[str, str] = {}
        if self._seal_key:
            measurements["seal_key_hash"] = hashlib.sha256(self._seal_key).hexdigest()
        if self._hmac_key:
            measurements["hmac_key_hash"] = hashlib.sha256(self._hmac_key).hexdigest()

        return {
            "enclave_id": self._enclave_id,
            "status": self._status.value,
            "backend": "software",
            "measurements": measurements,
        }

    async def destroy(self) -> None:
        """Destroy the enclave and wipe all key material."""
        logger.info(f"Destroying software enclave {self._enclave_id}")
        self._seal_key = None
        self._hmac_key = None
        self._config = None
        self._status = EnclaveStatus.DESTROYED


class SGXEnclave(EnclaveBackend):
    """Intel SGX enclave backend stub.

    This class provides the interface for an Intel SGX hardware enclave.
    All methods raise NotImplementedError because SGX hardware support
    requires platform-specific drivers and SDKs that are not bundled
    with this package.

    When fully implemented, SGX enclaves would provide:
    - Hardware-enforced memory isolation via Memory Encryption Engine (MEE)
    - Remote attestation via Intel Attestation Service (IAS)
    - Sealed storage bound to the CPU's MRSIGNER identity
    - Protection against privileged software attacks (OS, hypervisor)
    """

    def __init__(self) -> None:
        """Initialize SGX enclave stub."""
        self._status = EnclaveStatus.UNINITIALIZED

    @property
    def status(self) -> EnclaveStatus:
        """Current enclave lifecycle status."""
        return self._status

    async def initialize(self, config: EnclaveConfig) -> None:
        """Initialize an SGX enclave.

        Would load the signed enclave binary into an SGX-protected
        memory region (EPC) and perform EINIT to establish the enclave
        identity (MRENCLAVE measurement).

        Raises:
            NotImplementedError: SGX hardware is not available.
        """
        raise NotImplementedError("SGX not available")

    async def execute(self, code: bytes, input_data: bytes | None = None) -> EnclaveResult:
        """Execute code inside the SGX enclave.

        Would perform an ECALL into the enclave, passing input data
        through the enclave's trusted interface and returning results
        via OCALL or shared memory.

        Raises:
            NotImplementedError: SGX hardware is not available.
        """
        raise NotImplementedError("SGX not available")

    async def seal_data(self, data: bytes) -> bytes:
        """Seal data using SGX sealing.

        Would use the SGX SDK's sgx_seal_data function to encrypt
        data with a key derived from the enclave's MRSIGNER identity,
        binding the sealed blob to this specific enclave on this CPU.

        Raises:
            NotImplementedError: SGX hardware is not available.
        """
        raise NotImplementedError("SGX not available")

    async def unseal_data(self, sealed_data: bytes) -> bytes:
        """Unseal data using SGX sealing.

        Would use sgx_unseal_data to decrypt data that was previously
        sealed by an enclave with the same MRSIGNER identity.

        Raises:
            NotImplementedError: SGX hardware is not available.
        """
        raise NotImplementedError("SGX not available")

    async def get_attestation_report(self) -> dict[str, Any]:
        """Generate an SGX remote attestation report.

        Would produce a quote signed by the SGX quoting enclave,
        suitable for verification by Intel Attestation Service (IAS)
        or a DCAP-based verification service.

        Raises:
            NotImplementedError: SGX hardware is not available.
        """
        raise NotImplementedError("SGX not available")

    async def destroy(self) -> None:
        """Destroy the SGX enclave.

        Would call sgx_destroy_enclave to reclaim EPC memory and
        securely erase all enclave state.

        Raises:
            NotImplementedError: SGX hardware is not available.
        """
        raise NotImplementedError("SGX not available")


class EnclaveManager:
    """High-level manager for creating and operating enclaves.

    Manages multiple enclave instances, each with its own backend.
    Provides a unified API for enclave lifecycle management, sealed
    execution, data sealing, and attestation.

    Example:
        >>> manager = EnclaveManager()
        >>> eid = await manager.create_enclave()
        >>> result = await manager.execute_in_enclave(eid, b"code")
        >>> await manager.destroy_enclave(eid)
    """

    def __init__(self, backend: type[EnclaveBackend] | None = None) -> None:
        """Initialize the enclave manager.

        Args:
            backend: Backend class to use for new enclaves.
                Defaults to SoftwareEnclave.
        """
        self._backend_class: type[EnclaveBackend] = backend or SoftwareEnclave
        self._enclaves: dict[str, EnclaveBackend] = {}

    async def create_enclave(self, config: EnclaveConfig | None = None) -> str:
        """Create and initialize a new enclave.

        Args:
            config: Optional enclave configuration. Uses defaults if None.

        Returns:
            The enclave_id string identifying the new enclave.
        """
        if config is None:
            config = EnclaveConfig()

        if config.enclave_id is None:
            config = config.model_copy(update={"enclave_id": str(uuid.uuid4())})

        assert config.enclave_id is not None
        enclave_id: str = config.enclave_id
        backend = self._backend_class()
        await backend.initialize(config)
        self._enclaves[enclave_id] = backend

        logger.info(f"Created enclave {enclave_id}")
        return enclave_id

    def _get_enclave(self, enclave_id: str) -> EnclaveBackend:
        """Retrieve an enclave by ID, validating it exists and is usable.

        Args:
            enclave_id: Enclave identifier.

        Returns:
            The enclave backend instance.

        Raises:
            KeyError: If the enclave_id is unknown.
            RuntimeError: If the enclave has been destroyed.
        """
        if enclave_id not in self._enclaves:
            raise KeyError(f"Unknown enclave: {enclave_id}")

        enclave = self._enclaves[enclave_id]
        if enclave.status == EnclaveStatus.DESTROYED:
            raise RuntimeError(f"Enclave {enclave_id} has been destroyed")
        return enclave

    async def execute_in_enclave(
        self,
        enclave_id: str,
        code: bytes,
        input_data: bytes | None = None,
    ) -> EnclaveResult:
        """Execute a sealed computation in the specified enclave.

        Args:
            enclave_id: Enclave to execute in.
            code: Code bytes for the computation.
            input_data: Optional input data.

        Returns:
            EnclaveResult with the computation output.

        Raises:
            KeyError: If enclave_id is unknown.
            RuntimeError: If the enclave is not usable.
        """
        enclave = self._get_enclave(enclave_id)
        return await enclave.execute(code, input_data)

    async def seal_data(self, enclave_id: str, data: bytes) -> bytes:
        """Seal data using the specified enclave.

        Args:
            enclave_id: Enclave to seal with.
            data: Plaintext data to seal.

        Returns:
            Sealed data bytes.

        Raises:
            KeyError: If enclave_id is unknown.
            RuntimeError: If the enclave is not usable.
        """
        enclave = self._get_enclave(enclave_id)
        return await enclave.seal_data(data)

    async def unseal_data(self, enclave_id: str, sealed_data: bytes) -> bytes:
        """Unseal data using the specified enclave.

        Args:
            enclave_id: Enclave to unseal with.
            sealed_data: Sealed data from seal_data.

        Returns:
            Original plaintext data.

        Raises:
            KeyError: If enclave_id is unknown.
            RuntimeError: If the enclave is not usable.
        """
        enclave = self._get_enclave(enclave_id)
        return await enclave.unseal_data(sealed_data)

    async def get_attestation(self, enclave_id: str) -> dict[str, Any]:
        """Get attestation report from the specified enclave.

        Args:
            enclave_id: Enclave to get attestation from.

        Returns:
            Attestation report dictionary.

        Raises:
            KeyError: If enclave_id is unknown.
            RuntimeError: If the enclave is not usable.
        """
        enclave = self._get_enclave(enclave_id)
        return await enclave.get_attestation_report()

    async def destroy_enclave(self, enclave_id: str) -> None:
        """Destroy the specified enclave.

        The enclave is destroyed but its ID remains in the registry
        so that subsequent operations produce clear error messages.

        Args:
            enclave_id: Enclave to destroy.

        Raises:
            KeyError: If enclave_id is unknown.
        """
        if enclave_id not in self._enclaves:
            raise KeyError(f"Unknown enclave: {enclave_id}")

        enclave = self._enclaves[enclave_id]
        await enclave.destroy()
        logger.info(f"Destroyed enclave {enclave_id}")

    async def list_enclaves(self) -> list[str]:
        """List all enclave IDs managed by this manager.

        Returns:
            List of enclave_id strings (includes destroyed enclaves).
        """
        return list(self._enclaves.keys())
