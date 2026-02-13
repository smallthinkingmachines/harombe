"""Hierarchical key derivation for hardware-backed key management.

This module implements a rooted key derivation tree where each key is derived
from its parent using HKDF-SHA256. The master (root) key can optionally be
sealed to a TPM for hardware-backed protection. Child keys inherit their
cryptographic lineage from the root, enabling structured key management with
purpose-based derivation, rotation, and revocation.

Example:
    >>> import asyncio
    >>> from harombe.security.hardware.key_hierarchy import (
    ...     HardwareKeyHierarchy,
    ...     KeyPurpose,
    ... )
    >>>
    >>> async def main():
    ...     hierarchy = HardwareKeyHierarchy()
    ...     await hierarchy.initialize()
    ...
    ...     # Derive a signing key from the root
    ...     signing = hierarchy.derive_key(
    ...         hierarchy.root.key_id, KeyPurpose.SIGNING
    ...     )
    ...
    ...     # Derive an encryption key under the signing key
    ...     enc = hierarchy.derive_key(signing.key_id, KeyPurpose.ENCRYPTION)
    ...
    ...     # Inspect the chain from root to the encryption key
    ...     chain = hierarchy.get_key_chain(enc.key_id)
    ...     print([node.purpose for node in chain])
    ...
    ...     # Revoke the signing key (cascades to encryption key)
    ...     revoked = hierarchy.revoke_key(signing.key_id)
    ...     print(f"Revoked {len(revoked)} keys")
    >>>
    >>> asyncio.run(main())
"""

import logging
import os
import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pydantic import BaseModel, Field

from harombe.security.hardware.attestation import AttestationVerifier
from harombe.security.hardware.enclave import EnclaveManager
from harombe.security.hardware.tpm import TPMBackend, TPMKeyManager, TPMSealedData

logger = logging.getLogger(__name__)


class KeyPurpose(StrEnum):
    """Purpose of a key within the hierarchy.

    Attributes:
        MASTER: Root master key from which all others derive.
        SIGNING: Key used for digital signatures.
        ENCRYPTION: Key used for data encryption.
        AUTHENTICATION: Key used for authentication protocols.
        DERIVATION: Intermediate key used solely for further derivation.
    """

    MASTER = "master"
    SIGNING = "signing"
    ENCRYPTION = "encryption"
    AUTHENTICATION = "authentication"
    DERIVATION = "derivation"


class KeyNode(BaseModel):
    """A node in the key derivation tree.

    Attributes:
        key_id: Unique identifier for this key.
        purpose: Intended purpose of this key.
        parent_id: Key ID of the parent node (None for root).
        depth: Depth in the tree (0 for root).
        created_at: Timestamp when the key was created.
        metadata: Additional key metadata.
        derived_key: Raw derived key material (excluded from serialization).
    """

    key_id: str
    purpose: KeyPurpose
    parent_id: str | None = None
    depth: int = 0
    created_at: datetime = Field(default_factory=datetime.utcnow)
    metadata: dict[str, Any] = Field(default_factory=dict)
    derived_key: bytes | None = Field(default=None, exclude=True)


class HardwareKeyHierarchy:
    """Manages a rooted key derivation tree with HKDF-SHA256.

    Each key in the hierarchy is derived from its parent using HKDF with
    the parent's key material as input keying material. The master key
    can optionally be sealed to a TPM backend for hardware protection.

    Example:
        >>> hierarchy = HardwareKeyHierarchy()
        >>> await hierarchy.initialize(master_secret=b"secret" * 6)
        >>> child = hierarchy.derive_key(
        ...     hierarchy.root.key_id, KeyPurpose.SIGNING
        ... )
        >>> assert hierarchy.size == 2
    """

    def __init__(self, tpm: TPMBackend | None = None) -> None:
        """Initialize the key hierarchy.

        Args:
            tpm: Optional TPM backend for sealing the master key.
        """
        self._tpm = tpm
        self._nodes: dict[str, KeyNode] = {}
        self._root_id: str | None = None
        self._sealed_data: TPMSealedData | None = None

    async def initialize(self, master_secret: bytes | None = None) -> None:
        """Create or unseal the master (root) key.

        If a TPM backend is set and a sealed master already exists, the
        master key is unsealed from the TPM. Otherwise a new master key
        is created from the provided secret or 32 random bytes, and
        sealed to the TPM if available.

        Args:
            master_secret: Optional explicit master key material.
                If not provided, 32 random bytes are generated.
        """
        if master_secret is not None:
            master_key = master_secret
        else:
            master_key = os.urandom(32)

        # Seal to TPM if available
        if self._tpm is not None:
            self._sealed_data = await self._tpm.seal(master_key)
            logger.info("Master key sealed to TPM")

        root_id = str(uuid.uuid4())
        root_node = KeyNode(
            key_id=root_id,
            purpose=KeyPurpose.MASTER,
            parent_id=None,
            depth=0,
            derived_key=master_key,
        )

        self._nodes[root_id] = root_node
        self._root_id = root_id
        logger.info(f"Key hierarchy initialized with root {root_id}")

    def derive_key(
        self,
        parent_id: str,
        purpose: KeyPurpose,
        context: bytes = b"",
        key_id: str | None = None,
    ) -> KeyNode:
        """Derive a child key from a parent using HKDF-SHA256.

        The HKDF info parameter is constructed from the purpose value
        concatenated with the optional context bytes.

        Args:
            parent_id: Key ID of the parent node.
            purpose: Purpose for the derived key.
            context: Additional context bytes for HKDF info.
            key_id: Optional explicit key ID (generated if None).

        Returns:
            The newly created KeyNode with derived_key set.

        Raises:
            KeyError: If parent_id is not found in the hierarchy.
            ValueError: If the parent has no key material.
        """
        if parent_id not in self._nodes:
            raise KeyError(f"Parent key not found: {parent_id}")

        parent = self._nodes[parent_id]
        if parent.derived_key is None:
            raise ValueError(f"Parent key {parent_id} has no key material")

        info = purpose.value.encode() + context
        hkdf = HKDF(
            algorithm=SHA256(),
            length=32,
            salt=None,
            info=info,
        )
        derived_material = hkdf.derive(parent.derived_key)

        child_id = key_id or str(uuid.uuid4())
        child_node = KeyNode(
            key_id=child_id,
            purpose=purpose,
            parent_id=parent_id,
            depth=parent.depth + 1,
            derived_key=derived_material,
        )

        self._nodes[child_id] = child_node
        logger.info(
            f"Derived {purpose.value} key {child_id} "
            f"from parent {parent_id} (depth={child_node.depth})"
        )
        return child_node

    def get_key(self, key_id: str) -> KeyNode | None:
        """Look up a key by its ID.

        Args:
            key_id: The key identifier to look up.

        Returns:
            The KeyNode if found, otherwise None.
        """
        return self._nodes.get(key_id)

    def get_children(self, key_id: str) -> list[KeyNode]:
        """Get the direct children of a key.

        Args:
            key_id: The parent key identifier.

        Returns:
            List of KeyNode instances whose parent_id matches key_id.
        """
        return [node for node in self._nodes.values() if node.parent_id == key_id]

    def get_key_chain(self, key_id: str) -> list[KeyNode]:
        """Get the full chain from the root to the specified key.

        Args:
            key_id: The key identifier to trace back to root.

        Returns:
            Ordered list of KeyNode from root to the specified key.

        Raises:
            KeyError: If key_id is not found in the hierarchy.
        """
        if key_id not in self._nodes:
            raise KeyError(f"Key not found: {key_id}")

        chain: list[KeyNode] = []
        current_id: str | None = key_id
        while current_id is not None:
            node = self._nodes[current_id]
            chain.append(node)
            current_id = node.parent_id

        chain.reverse()
        return chain

    def rotate_key(self, key_id: str) -> KeyNode:
        """Re-derive a key with fresh randomness.

        The key is re-derived from its parent using new random context
        bytes, effectively producing new key material while preserving
        the key's position in the hierarchy.

        Args:
            key_id: The key to rotate.

        Returns:
            The updated KeyNode with new derived_key material.

        Raises:
            KeyError: If key_id is not found in the hierarchy.
            ValueError: If attempting to rotate the root key, or if
                the parent has no key material.
        """
        if key_id not in self._nodes:
            raise KeyError(f"Key not found: {key_id}")

        node = self._nodes[key_id]
        if node.parent_id is None:
            raise ValueError("Cannot rotate the root key")

        parent = self._nodes[node.parent_id]
        if parent.derived_key is None:
            raise ValueError(f"Parent key {node.parent_id} has no key material")

        # Use random context for fresh derivation
        fresh_context = os.urandom(16)
        info = node.purpose.value.encode() + fresh_context
        hkdf = HKDF(
            algorithm=SHA256(),
            length=32,
            salt=None,
            info=info,
        )
        new_material = hkdf.derive(parent.derived_key)

        node.derived_key = new_material
        node.created_at = datetime.now(UTC).replace(tzinfo=None)
        node.metadata["rotated"] = True
        node.metadata["rotation_time"] = datetime.now(UTC).replace(tzinfo=None).isoformat()

        logger.info(f"Rotated key {key_id}")
        return node

    def revoke_key(self, key_id: str) -> list[str]:
        """Revoke a key and all of its descendants.

        Removes the specified key and every key in its subtree from
        the hierarchy, wiping their key material.

        Args:
            key_id: The key to revoke.

        Returns:
            List of revoked key IDs (including the specified key).

        Raises:
            KeyError: If key_id is not found in the hierarchy.
        """
        if key_id not in self._nodes:
            raise KeyError(f"Key not found: {key_id}")

        revoked: list[str] = []
        to_revoke = [key_id]

        while to_revoke:
            current = to_revoke.pop(0)
            if current in self._nodes:
                # Find children before removing
                children = [n.key_id for n in self._nodes.values() if n.parent_id == current]
                to_revoke.extend(children)

                # Wipe key material and remove
                self._nodes[current].derived_key = None
                del self._nodes[current]
                revoked.append(current)

        # Clear root if revoked
        if self._root_id in revoked:
            self._root_id = None

        logger.info(f"Revoked {len(revoked)} keys starting from {key_id}")
        return revoked

    def export_hierarchy(self) -> dict[str, Any]:
        """Export the tree structure without derived key material.

        Returns:
            Dictionary with ``root`` and ``nodes`` keys. Each node
            is serialized via Pydantic's model_dump (which excludes
            derived_key due to the Field(exclude=True) setting).
        """
        nodes_data = {}
        for nid, node in self._nodes.items():
            nodes_data[nid] = node.model_dump(mode="json")

        return {
            "root": self._root_id,
            "nodes": nodes_data,
            "size": self.size,
            "depth": self.depth,
        }

    @property
    def root(self) -> KeyNode | None:
        """The root (master) key node, or None if not initialized."""
        if self._root_id is None:
            return None
        return self._nodes.get(self._root_id)

    @property
    def depth(self) -> int:
        """Maximum depth of the key hierarchy tree."""
        if not self._nodes:
            return 0
        return max(node.depth for node in self._nodes.values())

    @property
    def size(self) -> int:
        """Total number of keys in the hierarchy."""
        return len(self._nodes)


def create_hardware_security() -> dict[str, Any]:
    """Factory function to create a complete hardware security stack.

    Creates and returns instances of all hardware security components:
    TPMKeyManager, EnclaveManager, AttestationVerifier, and
    HardwareKeyHierarchy.

    Returns:
        Dictionary with keys ``tpm_manager``, ``enclave_manager``,
        ``attestation_verifier``, and ``key_hierarchy``.

    Example:
        >>> components = create_hardware_security()
        >>> tpm = components["tpm_manager"]
        >>> hierarchy = components["key_hierarchy"]
    """
    tpm_manager = TPMKeyManager()
    enclave_manager = EnclaveManager()
    attestation_verifier = AttestationVerifier()
    key_hierarchy = HardwareKeyHierarchy()

    logger.info("Created hardware security component stack")

    return {
        "tpm_manager": tpm_manager,
        "enclave_manager": enclave_manager,
        "attestation_verifier": attestation_verifier,
        "key_hierarchy": key_hierarchy,
    }
