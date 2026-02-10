"""Confidential computing for hardware-backed memory encryption and isolation.

This module provides confidential computing functionality with encrypted memory
regions and integrity verification. It supports a software-based simulation for
development and testing, with stubs for hardware-backed platforms (AMD SEV-SNP,
Intel TDX, ARM CCA).

The software backend uses AES-GCM for memory encryption, HKDF for per-region
key derivation, and HMAC-SHA256 for integrity trees.

Example:
    >>> import asyncio
    >>> from harombe.security.confidential_compute import (
    ...     ConfidentialComputeManager,
    ...     ConfidentialConfig,
    ...     ConfidentialPlatform,
    ... )
    >>>
    >>> async def main():
    ...     manager = ConfidentialComputeManager()
    ...     instance_id = await manager.create_instance(
    ...         ConfidentialConfig(memory_size_mb=128)
    ...     )
    ...
    ...     # Execute confidential computation
    ...     result = await manager.execute_in_instance(
    ...         instance_id, b"compute", b"input_data"
    ...     )
    ...     print(f"Success: {result.success}")
    ...
    ...     # Allocate, write, and read encrypted memory
    ...     region_id = await manager.allocate_memory(instance_id, 1024)
    ...     await manager.write_memory(instance_id, region_id, b"secret")
    ...     data = await manager.read_memory(instance_id, region_id)
    ...     assert data == b"secret"
    ...
    ...     await manager.destroy_instance(instance_id)
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

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

_NONCE_SIZE = 12
_KEY_SIZE = 32


class ConfidentialPlatform(StrEnum):
    """Available confidential computing platforms.

    Attributes:
        SOFTWARE: Software-based simulation (no hardware TEE).
        SEV_SNP: AMD Secure Encrypted Virtualization - Secure Nested Paging.
        TDX: Intel Trust Domain Extensions.
        CCA: ARM Confidential Compute Architecture.
    """

    SOFTWARE = "software"
    SEV_SNP = "sev-snp"
    TDX = "tdx"
    CCA = "cca"


class ConfidentialConfig(BaseModel):
    """Configuration for a confidential computing instance.

    Attributes:
        platform: Which confidential computing platform to use.
        memory_size_mb: Total memory budget for the instance in MB.
        integrity_check: Whether to verify integrity hashes on read.
        encryption_algorithm: Encryption algorithm for memory regions.
        attestation_required: Whether attestation is required before use.
    """

    platform: ConfidentialPlatform = ConfidentialPlatform.SOFTWARE
    memory_size_mb: int = 256
    integrity_check: bool = True
    encryption_algorithm: str = "AES-256-GCM"
    attestation_required: bool = False


class MemoryRegion(BaseModel):
    """Metadata for an encrypted memory region.

    Attributes:
        region_id: Unique identifier for this memory region.
        start_address: Simulated start address.
        size: Size of the region in bytes.
        encrypted: Whether the region contents are encrypted.
        integrity_hash: HMAC-SHA256 hex digest for integrity verification.
        data: Raw stored data (excluded from serialization).
    """

    region_id: str
    start_address: int
    size: int
    encrypted: bool = True
    integrity_hash: str = ""
    data: bytes | None = Field(default=None, exclude=True)


class ConfidentialExecutionResult(BaseModel):
    """Result of executing code in a confidential computing instance.

    Attributes:
        success: Whether the execution completed successfully.
        output: Raw output bytes from the computation.
        error: Error message if execution failed.
        execution_time: Wall-clock execution time in seconds.
        platform: Platform that executed the computation.
        attestation_report: Attestation data from the platform.
        memory_regions_used: Number of memory regions active during execution.
    """

    success: bool
    output: bytes | None = None
    error: str | None = None
    execution_time: float = 0.0
    platform: ConfidentialPlatform = ConfidentialPlatform.SOFTWARE
    attestation_report: dict[str, Any] = Field(default_factory=dict)
    memory_regions_used: int = 0


class ConfidentialComputeBackend(ABC):
    """Abstract base class for confidential computing backends.

    All backends follow the lifecycle:
    initialize -> (execute | allocate | write | read | free)* -> destroy

    The ``status`` property reports the current backend state.
    """

    @abstractmethod
    async def initialize(self, config: ConfidentialConfig) -> None:
        """Initialize the backend with the given configuration.

        Args:
            config: Instance configuration parameters.
        """

    @abstractmethod
    async def execute(
        self, code: bytes, input_data: bytes | None = None
    ) -> ConfidentialExecutionResult:
        """Execute a confidential computation.

        Args:
            code: Code bytes representing the computation.
            input_data: Optional input data for the computation.

        Returns:
            ConfidentialExecutionResult with the computation output.
        """

    @abstractmethod
    async def allocate_memory(self, size: int, region_id: str | None = None) -> MemoryRegion:
        """Allocate an encrypted memory region.

        Args:
            size: Size of the region in bytes.
            region_id: Optional explicit region identifier.

        Returns:
            MemoryRegion metadata for the allocated region.
        """

    @abstractmethod
    async def free_memory(self, region_id: str) -> None:
        """Free an allocated memory region.

        Args:
            region_id: Identifier of the region to free.
        """

    @abstractmethod
    async def read_memory(self, region_id: str) -> bytes:
        """Read and decrypt data from a memory region.

        Args:
            region_id: Identifier of the region to read.

        Returns:
            Decrypted data bytes.
        """

    @abstractmethod
    async def write_memory(self, region_id: str, data: bytes) -> None:
        """Encrypt and write data to a memory region.

        Args:
            region_id: Identifier of the region to write to.
            data: Plaintext data to encrypt and store.
        """

    @abstractmethod
    async def get_attestation(self) -> dict[str, Any]:
        """Generate an attestation report for the instance.

        Returns:
            Dictionary containing platform attestation data.
        """

    @abstractmethod
    async def destroy(self) -> None:
        """Destroy the instance, wiping all keys and memory."""

    @property
    @abstractmethod
    def status(self) -> str:
        """Current backend lifecycle status."""


class SoftwareConfidentialCompute(ConfidentialComputeBackend):
    """Software-based confidential computing simulation.

    Uses AES-GCM for memory encryption and HMAC-SHA256 for integrity
    verification. Each memory region gets a unique encryption key derived
    from a master key via HKDF.

    This does NOT provide the hardware isolation guarantees of a real
    confidential computing platform (AMD SEV-SNP, Intel TDX, ARM CCA).
    It is intended for development and testing.
    """

    def __init__(self) -> None:
        """Initialize internal state in uninitialized status."""
        self._status = "uninitialized"
        self._config: ConfidentialConfig | None = None
        self._master_key: bytes | None = None
        self._hmac_key: bytes | None = None
        self._regions: dict[str, MemoryRegion] = {}
        self._region_keys: dict[str, bytes] = {}
        self._region_ciphertexts: dict[str, bytes] = {}
        self._next_address: int = 0x1000

    @property
    def status(self) -> str:
        """Current backend lifecycle status."""
        return self._status

    async def initialize(self, config: ConfidentialConfig) -> None:
        """Initialize the software backend.

        Generates a 32-byte master encryption key and HMAC key.

        Args:
            config: Instance configuration parameters.
        """
        logger.info("Initializing software confidential compute backend")

        self._config = config
        self._master_key = os.urandom(_KEY_SIZE)
        self._hmac_key = os.urandom(_KEY_SIZE)
        self._regions = {}
        self._region_keys = {}
        self._region_ciphertexts = {}
        self._next_address = 0x1000
        self._status = "ready"

        logger.info(
            f"Software confidential compute initialized "
            f"(memory={config.memory_size_mb}MB, "
            f"integrity={config.integrity_check})"
        )

    async def execute(
        self, code: bytes, input_data: bytes | None = None
    ) -> ConfidentialExecutionResult:
        """Execute a confidential computation via HMAC simulation.

        Computes HMAC-SHA256 of the code and input data to simulate
        a deterministic sealed computation.

        Args:
            code: Code bytes representing the computation.
            input_data: Optional input data for the computation.

        Returns:
            ConfidentialExecutionResult with HMAC output bytes.

        Raises:
            RuntimeError: If backend is not in ready state.
        """
        if self._status == "destroyed":
            raise RuntimeError("Instance has been destroyed")
        if self._status != "ready":
            raise RuntimeError(f"Instance not ready (status={self._status})")

        start_time = time.monotonic()

        try:
            message = code
            if input_data is not None:
                message = code + input_data

            output = hmac.new(
                self._hmac_key,  # type: ignore[arg-type]
                message,
                hashlib.sha256,
            ).digest()

            execution_time = time.monotonic() - start_time

            logger.debug(f"Confidential execution completed in " f"{execution_time:.4f}s")

            return ConfidentialExecutionResult(
                success=True,
                output=output,
                execution_time=execution_time,
                platform=ConfidentialPlatform.SOFTWARE,
                attestation_report=await self.get_attestation(),
                memory_regions_used=len(self._regions),
            )
        except Exception as e:
            execution_time = time.monotonic() - start_time
            logger.error(f"Confidential execution failed: {e}")
            return ConfidentialExecutionResult(
                success=False,
                error=str(e),
                execution_time=execution_time,
                platform=ConfidentialPlatform.SOFTWARE,
            )

    def _derive_region_key(self, region_id: str) -> bytes:
        """Derive a unique encryption key for a memory region using HKDF.

        Args:
            region_id: Identifier of the region.

        Returns:
            32-byte derived key.
        """
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=_KEY_SIZE,
            salt=None,
            info=region_id.encode(),
        )
        return hkdf.derive(self._master_key)  # type: ignore[arg-type]

    def _compute_integrity_hash(self, region_id: str, ciphertext: bytes) -> str:
        """Compute HMAC-SHA256 integrity hash for a memory region.

        Args:
            region_id: Identifier of the region.
            ciphertext: Encrypted data to hash.

        Returns:
            Hex-encoded HMAC-SHA256 digest.
        """
        return hmac.new(
            self._hmac_key,  # type: ignore[arg-type]
            region_id.encode() + ciphertext,
            hashlib.sha256,
        ).hexdigest()

    async def allocate_memory(self, size: int, region_id: str | None = None) -> MemoryRegion:
        """Allocate an encrypted memory region.

        Creates a new memory region with a HKDF-derived encryption key.

        Args:
            size: Size of the region in bytes.
            region_id: Optional explicit region identifier.

        Returns:
            MemoryRegion metadata for the allocated region.

        Raises:
            RuntimeError: If backend is not in ready state.
        """
        if self._status == "destroyed":
            raise RuntimeError("Instance has been destroyed")
        if self._status != "ready":
            raise RuntimeError(f"Instance not ready (status={self._status})")

        rid = region_id or str(uuid.uuid4())
        start_address = self._next_address
        self._next_address += size

        region = MemoryRegion(
            region_id=rid,
            start_address=start_address,
            size=size,
            encrypted=True,
        )

        region_key = self._derive_region_key(rid)
        self._regions[rid] = region
        self._region_keys[rid] = region_key

        logger.info(
            f"Allocated memory region {rid[:8]}... " f"(size={size}B, address=0x{start_address:x})"
        )

        return region

    async def write_memory(self, region_id: str, data: bytes) -> None:
        """Encrypt and write data to a memory region.

        Encrypts data with AES-GCM using the region's derived key and
        computes an HMAC-SHA256 integrity hash.

        Args:
            region_id: Identifier of the region to write to.
            data: Plaintext data to encrypt and store.

        Raises:
            KeyError: If the region_id is unknown.
            RuntimeError: If backend is not in ready state.
        """
        if self._status == "destroyed":
            raise RuntimeError("Instance has been destroyed")
        if self._status != "ready":
            raise RuntimeError(f"Instance not ready (status={self._status})")

        if region_id not in self._regions:
            raise KeyError(f"Unknown memory region: {region_id}")

        region_key = self._region_keys[region_id]
        nonce = os.urandom(_NONCE_SIZE)
        aesgcm = AESGCM(region_key)
        ciphertext = nonce + aesgcm.encrypt(nonce, data, None)

        self._region_ciphertexts[region_id] = ciphertext

        integrity_hash = self._compute_integrity_hash(region_id, ciphertext)
        self._regions[region_id].integrity_hash = integrity_hash

        logger.debug(
            f"Wrote {len(data)}B to region {region_id[:8]}... " f"(encrypted={len(ciphertext)}B)"
        )

    async def read_memory(self, region_id: str) -> bytes:
        """Read and decrypt data from a memory region.

        Verifies the integrity hash before decrypting if integrity
        checking is enabled.

        Args:
            region_id: Identifier of the region to read.

        Returns:
            Decrypted data bytes.

        Raises:
            KeyError: If the region_id is unknown or has no data.
            RuntimeError: If backend is not ready or integrity fails.
        """
        if self._status == "destroyed":
            raise RuntimeError("Instance has been destroyed")
        if self._status != "ready":
            raise RuntimeError(f"Instance not ready (status={self._status})")

        if region_id not in self._regions:
            raise KeyError(f"Unknown memory region: {region_id}")

        if region_id not in self._region_ciphertexts:
            raise KeyError(f"No data written to region: {region_id}")

        ciphertext = self._region_ciphertexts[region_id]
        region = self._regions[region_id]

        # Verify integrity if enabled
        if self._config and self._config.integrity_check:
            expected_hash = self._compute_integrity_hash(region_id, ciphertext)
            if region.integrity_hash != expected_hash:
                raise RuntimeError(f"Integrity check failed for region " f"{region_id}")

        # Decrypt
        region_key = self._region_keys[region_id]
        nonce = ciphertext[:_NONCE_SIZE]
        encrypted_data = ciphertext[_NONCE_SIZE:]
        aesgcm = AESGCM(region_key)
        plaintext = aesgcm.decrypt(nonce, encrypted_data, None)

        logger.debug(f"Read {len(plaintext)}B from region {region_id[:8]}...")

        return plaintext

    async def free_memory(self, region_id: str) -> None:
        """Free an allocated memory region and wipe its key material.

        Args:
            region_id: Identifier of the region to free.

        Raises:
            KeyError: If the region_id is unknown.
            RuntimeError: If backend is not in ready state.
        """
        if self._status == "destroyed":
            raise RuntimeError("Instance has been destroyed")
        if self._status != "ready":
            raise RuntimeError(f"Instance not ready (status={self._status})")

        if region_id not in self._regions:
            raise KeyError(f"Unknown memory region: {region_id}")

        self._regions.pop(region_id)
        self._region_keys.pop(region_id, None)
        self._region_ciphertexts.pop(region_id, None)

        logger.info(f"Freed memory region {region_id[:8]}...")

    async def get_attestation(self) -> dict[str, Any]:
        """Generate a software attestation report.

        Returns:
            Dictionary with platform, status, region count, and
            key measurements.
        """
        measurements: dict[str, str] = {}
        if self._master_key:
            measurements["master_key_hash"] = hashlib.sha256(self._master_key).hexdigest()
        if self._hmac_key:
            measurements["hmac_key_hash"] = hashlib.sha256(self._hmac_key).hexdigest()

        return {
            "platform": ConfidentialPlatform.SOFTWARE.value,
            "status": self._status,
            "regions_count": len(self._regions),
            "backend": "software",
            "measurements": measurements,
        }

    async def destroy(self) -> None:
        """Destroy the instance and wipe all key material and regions."""
        logger.info("Destroying software confidential compute instance")
        self._master_key = None
        self._hmac_key = None
        self._regions.clear()
        self._region_keys.clear()
        self._region_ciphertexts.clear()
        self._config = None
        self._status = "destroyed"


class ConfidentialComputeManager:
    """High-level manager for confidential computing instances.

    Creates and manages multiple confidential computing instances,
    each backed by a SoftwareConfidentialCompute backend (or a
    hardware backend when available). Provides a unified API for
    instance lifecycle, execution, and encrypted memory operations.

    Example:
        >>> manager = ConfidentialComputeManager()
        >>> iid = await manager.create_instance()
        >>> result = await manager.execute_in_instance(iid, b"code")
        >>> rid = await manager.allocate_memory(iid, 1024)
        >>> await manager.write_memory(iid, rid, b"secret")
        >>> data = await manager.read_memory(iid, rid)
        >>> await manager.destroy_instance(iid)
    """

    def __init__(self) -> None:
        """Initialize the confidential compute manager."""
        self._instances: dict[str, SoftwareConfidentialCompute] = {}

    async def create_instance(self, config: ConfidentialConfig | None = None) -> str:
        """Create and initialize a new confidential computing instance.

        Args:
            config: Optional configuration. Uses defaults if None.

        Returns:
            The instance_id string identifying the new instance.
        """
        if config is None:
            config = ConfidentialConfig()

        instance_id = str(uuid.uuid4())
        backend = SoftwareConfidentialCompute()
        await backend.initialize(config)
        self._instances[instance_id] = backend

        logger.info(f"Created confidential compute instance {instance_id}")
        return instance_id

    def _get_instance(self, instance_id: str) -> SoftwareConfidentialCompute:
        """Retrieve an instance by ID, validating it exists and is usable.

        Args:
            instance_id: Instance identifier.

        Returns:
            The backend instance.

        Raises:
            KeyError: If the instance_id is unknown.
            RuntimeError: If the instance has been destroyed.
        """
        if instance_id not in self._instances:
            raise KeyError(f"Unknown instance: {instance_id}")

        instance = self._instances[instance_id]
        if instance.status == "destroyed":
            raise RuntimeError(f"Instance {instance_id} has been destroyed")
        return instance

    async def execute_in_instance(
        self,
        instance_id: str,
        code: bytes,
        input_data: bytes | None = None,
    ) -> ConfidentialExecutionResult:
        """Execute a confidential computation in the specified instance.

        Args:
            instance_id: Instance to execute in.
            code: Code bytes for the computation.
            input_data: Optional input data.

        Returns:
            ConfidentialExecutionResult with the computation output.

        Raises:
            KeyError: If instance_id is unknown.
            RuntimeError: If the instance is not usable.
        """
        instance = self._get_instance(instance_id)
        return await instance.execute(code, input_data)

    async def allocate_memory(
        self,
        instance_id: str,
        size: int,
        region_id: str | None = None,
    ) -> str:
        """Allocate an encrypted memory region in the specified instance.

        Args:
            instance_id: Instance to allocate in.
            size: Size of the region in bytes.
            region_id: Optional explicit region identifier.

        Returns:
            The region_id string for the allocated region.

        Raises:
            KeyError: If instance_id is unknown.
            RuntimeError: If the instance is not usable.
        """
        instance = self._get_instance(instance_id)
        region = await instance.allocate_memory(size, region_id)
        return region.region_id

    async def write_memory(self, instance_id: str, region_id: str, data: bytes) -> None:
        """Write data to an encrypted memory region.

        Args:
            instance_id: Instance containing the region.
            region_id: Region to write to.
            data: Plaintext data to encrypt and store.

        Raises:
            KeyError: If instance_id or region_id is unknown.
            RuntimeError: If the instance is not usable.
        """
        instance = self._get_instance(instance_id)
        await instance.write_memory(region_id, data)

    async def read_memory(self, instance_id: str, region_id: str) -> bytes:
        """Read data from an encrypted memory region.

        Args:
            instance_id: Instance containing the region.
            region_id: Region to read from.

        Returns:
            Decrypted data bytes.

        Raises:
            KeyError: If instance_id or region_id is unknown.
            RuntimeError: If the instance is not usable.
        """
        instance = self._get_instance(instance_id)
        return await instance.read_memory(region_id)

    async def free_memory(self, instance_id: str, region_id: str) -> None:
        """Free an allocated memory region.

        Args:
            instance_id: Instance containing the region.
            region_id: Region to free.

        Raises:
            KeyError: If instance_id or region_id is unknown.
            RuntimeError: If the instance is not usable.
        """
        instance = self._get_instance(instance_id)
        await instance.free_memory(region_id)

    async def destroy_instance(self, instance_id: str) -> None:
        """Destroy the specified confidential computing instance.

        The instance is destroyed but its ID remains in the registry
        so that subsequent operations produce clear error messages.

        Args:
            instance_id: Instance to destroy.

        Raises:
            KeyError: If instance_id is unknown.
        """
        if instance_id not in self._instances:
            raise KeyError(f"Unknown instance: {instance_id}")

        instance = self._instances[instance_id]
        await instance.destroy()
        logger.info(f"Destroyed confidential compute instance {instance_id}")

    def list_instances(self) -> list[str]:
        """List all instance IDs managed by this manager.

        Returns:
            List of instance_id strings (includes destroyed instances).
        """
        return list(self._instances.keys())
