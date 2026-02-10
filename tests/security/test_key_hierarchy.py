"""Tests for the hierarchical key derivation module."""

import pytest

from harombe.security.hardware.attestation import AttestationVerifier
from harombe.security.hardware.enclave import EnclaveManager
from harombe.security.hardware.key_hierarchy import (
    HardwareKeyHierarchy,
    KeyNode,
    KeyPurpose,
    create_hardware_security,
)
from harombe.security.hardware.tpm import SoftwareTPM, TPMKeyManager

# ---------------------------------------------------------------------------
# KeyPurpose enum tests
# ---------------------------------------------------------------------------


async def test_key_purpose_master_value():
    """MASTER enum has the expected string value."""
    assert KeyPurpose.MASTER == "master"


async def test_key_purpose_signing_value():
    """SIGNING enum has the expected string value."""
    assert KeyPurpose.SIGNING == "signing"


async def test_key_purpose_encryption_value():
    """ENCRYPTION enum has the expected string value."""
    assert KeyPurpose.ENCRYPTION == "encryption"


async def test_key_purpose_authentication_value():
    """AUTHENTICATION enum has the expected string value."""
    assert KeyPurpose.AUTHENTICATION == "authentication"


async def test_key_purpose_derivation_value():
    """DERIVATION enum has the expected string value."""
    assert KeyPurpose.DERIVATION == "derivation"


async def test_key_purpose_member_count():
    """KeyPurpose has exactly 5 members."""
    assert len(KeyPurpose) == 5


# ---------------------------------------------------------------------------
# KeyNode model tests
# ---------------------------------------------------------------------------


async def test_key_node_creation():
    """KeyNode can be created with required fields and correct defaults."""
    node = KeyNode(
        key_id="node-1",
        purpose=KeyPurpose.SIGNING,
    )
    assert node.key_id == "node-1"
    assert node.purpose == KeyPurpose.SIGNING
    assert node.parent_id is None
    assert node.depth == 0
    assert node.created_at is not None
    assert node.metadata == {}
    assert node.derived_key is None


async def test_key_node_with_derived_key():
    """KeyNode stores derived_key when provided."""
    node = KeyNode(
        key_id="node-2",
        purpose=KeyPurpose.ENCRYPTION,
        derived_key=b"secret-material",
    )
    assert node.derived_key == b"secret-material"


async def test_key_node_serialization_excludes_derived_key():
    """model_dump excludes derived_key due to Field(exclude=True)."""
    node = KeyNode(
        key_id="node-3",
        purpose=KeyPurpose.MASTER,
        derived_key=b"top-secret",
    )
    data = node.model_dump(mode="json")
    assert "derived_key" not in data
    assert data["key_id"] == "node-3"
    assert data["purpose"] == "master"


# ---------------------------------------------------------------------------
# HardwareKeyHierarchy tests
# ---------------------------------------------------------------------------


async def test_hierarchy_initialize_default():
    """initialize() creates a root node with random master key."""
    hierarchy = HardwareKeyHierarchy()
    await hierarchy.initialize()

    assert hierarchy.root is not None
    assert hierarchy.root.purpose == KeyPurpose.MASTER
    assert hierarchy.root.depth == 0
    assert hierarchy.root.parent_id is None
    assert hierarchy.root.derived_key is not None
    assert len(hierarchy.root.derived_key) == 32
    assert hierarchy.size == 1


async def test_hierarchy_initialize_with_master_secret():
    """initialize() uses provided master secret."""
    secret = b"my-custom-master-secret-32bytes!"
    hierarchy = HardwareKeyHierarchy()
    await hierarchy.initialize(master_secret=secret)

    assert hierarchy.root is not None
    assert hierarchy.root.derived_key == secret


async def test_hierarchy_initialize_with_tpm():
    """initialize() seals master key to TPM when backend is provided."""
    tpm = SoftwareTPM()
    await tpm.initialize()

    hierarchy = HardwareKeyHierarchy(tpm=tpm)
    await hierarchy.initialize()

    assert hierarchy.root is not None
    assert hierarchy._sealed_data is not None
    assert hierarchy.root.derived_key is not None


async def test_hierarchy_derive_key():
    """derive_key() produces a child key with correct attributes."""
    hierarchy = HardwareKeyHierarchy()
    await hierarchy.initialize()

    root_id = hierarchy.root.key_id
    child = hierarchy.derive_key(root_id, KeyPurpose.SIGNING)

    assert child.parent_id == root_id
    assert child.purpose == KeyPurpose.SIGNING
    assert child.depth == 1
    assert child.derived_key is not None
    assert len(child.derived_key) == 32
    assert child.derived_key != hierarchy.root.derived_key
    assert hierarchy.size == 2


async def test_hierarchy_derive_key_with_context():
    """derive_key() with different contexts produces different keys."""
    hierarchy = HardwareKeyHierarchy()
    await hierarchy.initialize()

    root_id = hierarchy.root.key_id
    child_a = hierarchy.derive_key(root_id, KeyPurpose.SIGNING, context=b"context-a")
    child_b = hierarchy.derive_key(root_id, KeyPurpose.SIGNING, context=b"context-b")

    assert child_a.derived_key != child_b.derived_key


async def test_hierarchy_derive_key_with_custom_id():
    """derive_key() accepts a custom key_id."""
    hierarchy = HardwareKeyHierarchy()
    await hierarchy.initialize()

    child = hierarchy.derive_key(
        hierarchy.root.key_id,
        KeyPurpose.ENCRYPTION,
        key_id="my-custom-id",
    )
    assert child.key_id == "my-custom-id"


async def test_hierarchy_derive_key_unknown_parent():
    """derive_key() raises KeyError for unknown parent_id."""
    hierarchy = HardwareKeyHierarchy()
    await hierarchy.initialize()

    with pytest.raises(KeyError, match="Parent key not found"):
        hierarchy.derive_key("nonexistent", KeyPurpose.SIGNING)


async def test_hierarchy_get_key():
    """get_key() returns the correct node or None."""
    hierarchy = HardwareKeyHierarchy()
    await hierarchy.initialize()

    root_id = hierarchy.root.key_id
    assert hierarchy.get_key(root_id) is not None
    assert hierarchy.get_key(root_id).key_id == root_id
    assert hierarchy.get_key("nonexistent") is None


async def test_hierarchy_get_children():
    """get_children() returns direct children only."""
    hierarchy = HardwareKeyHierarchy()
    await hierarchy.initialize()

    root_id = hierarchy.root.key_id
    child1 = hierarchy.derive_key(root_id, KeyPurpose.SIGNING)
    child2 = hierarchy.derive_key(root_id, KeyPurpose.ENCRYPTION)
    _grandchild = hierarchy.derive_key(child1.key_id, KeyPurpose.DERIVATION)

    children = hierarchy.get_children(root_id)
    child_ids = {c.key_id for c in children}
    assert child_ids == {child1.key_id, child2.key_id}
    assert len(children) == 2


async def test_hierarchy_get_key_chain():
    """get_key_chain() returns the path from root to the given key."""
    hierarchy = HardwareKeyHierarchy()
    await hierarchy.initialize()

    root_id = hierarchy.root.key_id
    child = hierarchy.derive_key(root_id, KeyPurpose.SIGNING)
    grandchild = hierarchy.derive_key(child.key_id, KeyPurpose.ENCRYPTION)

    chain = hierarchy.get_key_chain(grandchild.key_id)

    assert len(chain) == 3
    assert chain[0].key_id == root_id
    assert chain[1].key_id == child.key_id
    assert chain[2].key_id == grandchild.key_id


async def test_hierarchy_get_key_chain_root():
    """get_key_chain() for root returns a single-element list."""
    hierarchy = HardwareKeyHierarchy()
    await hierarchy.initialize()

    chain = hierarchy.get_key_chain(hierarchy.root.key_id)
    assert len(chain) == 1
    assert chain[0].key_id == hierarchy.root.key_id


async def test_hierarchy_get_key_chain_unknown_key():
    """get_key_chain() raises KeyError for unknown key_id."""
    hierarchy = HardwareKeyHierarchy()
    await hierarchy.initialize()

    with pytest.raises(KeyError, match="Key not found"):
        hierarchy.get_key_chain("nonexistent")


async def test_hierarchy_rotate_key():
    """rotate_key() produces new key material for a child key."""
    hierarchy = HardwareKeyHierarchy()
    await hierarchy.initialize()

    child = hierarchy.derive_key(hierarchy.root.key_id, KeyPurpose.SIGNING)
    original_material = child.derived_key

    rotated = hierarchy.rotate_key(child.key_id)

    assert rotated.key_id == child.key_id
    assert rotated.derived_key is not None
    assert rotated.derived_key != original_material
    assert rotated.metadata.get("rotated") is True
    assert "rotation_time" in rotated.metadata


async def test_hierarchy_rotate_root_raises():
    """rotate_key() raises ValueError for the root key."""
    hierarchy = HardwareKeyHierarchy()
    await hierarchy.initialize()

    with pytest.raises(ValueError, match="Cannot rotate the root"):
        hierarchy.rotate_key(hierarchy.root.key_id)


async def test_hierarchy_rotate_unknown_key_raises():
    """rotate_key() raises KeyError for unknown key_id."""
    hierarchy = HardwareKeyHierarchy()
    await hierarchy.initialize()

    with pytest.raises(KeyError, match="Key not found"):
        hierarchy.rotate_key("nonexistent")


async def test_hierarchy_revoke_key():
    """revoke_key() removes the key and all descendants."""
    hierarchy = HardwareKeyHierarchy()
    await hierarchy.initialize()

    root_id = hierarchy.root.key_id
    child = hierarchy.derive_key(root_id, KeyPurpose.SIGNING)
    grandchild = hierarchy.derive_key(child.key_id, KeyPurpose.ENCRYPTION)

    revoked = hierarchy.revoke_key(child.key_id)

    assert child.key_id in revoked
    assert grandchild.key_id in revoked
    assert len(revoked) == 2
    assert hierarchy.get_key(child.key_id) is None
    assert hierarchy.get_key(grandchild.key_id) is None
    # Root should still be present
    assert hierarchy.get_key(root_id) is not None
    assert hierarchy.size == 1


async def test_hierarchy_revoke_root():
    """revoke_key() on root removes all keys."""
    hierarchy = HardwareKeyHierarchy()
    await hierarchy.initialize()

    root_id = hierarchy.root.key_id
    hierarchy.derive_key(root_id, KeyPurpose.SIGNING)

    revoked = hierarchy.revoke_key(root_id)

    assert len(revoked) == 2
    assert hierarchy.root is None
    assert hierarchy.size == 0


async def test_hierarchy_revoke_unknown_key_raises():
    """revoke_key() raises KeyError for unknown key_id."""
    hierarchy = HardwareKeyHierarchy()
    await hierarchy.initialize()

    with pytest.raises(KeyError, match="Key not found"):
        hierarchy.revoke_key("nonexistent")


async def test_hierarchy_export():
    """export_hierarchy() returns tree structure without key material."""
    hierarchy = HardwareKeyHierarchy()
    await hierarchy.initialize()

    root_id = hierarchy.root.key_id
    child = hierarchy.derive_key(root_id, KeyPurpose.SIGNING)

    exported = hierarchy.export_hierarchy()

    assert exported["root"] == root_id
    assert exported["size"] == 2
    assert exported["depth"] == 1
    assert root_id in exported["nodes"]
    assert child.key_id in exported["nodes"]
    # Verify derived_key is not in exported data
    for node_data in exported["nodes"].values():
        assert "derived_key" not in node_data


async def test_hierarchy_root_property():
    """root property returns None before initialization."""
    hierarchy = HardwareKeyHierarchy()
    assert hierarchy.root is None

    await hierarchy.initialize()
    assert hierarchy.root is not None


async def test_hierarchy_depth_property():
    """depth property reflects maximum tree depth."""
    hierarchy = HardwareKeyHierarchy()
    assert hierarchy.depth == 0

    await hierarchy.initialize()
    assert hierarchy.depth == 0  # root is depth 0

    root_id = hierarchy.root.key_id
    child = hierarchy.derive_key(root_id, KeyPurpose.SIGNING)
    assert hierarchy.depth == 1

    hierarchy.derive_key(child.key_id, KeyPurpose.ENCRYPTION)
    assert hierarchy.depth == 2


async def test_hierarchy_size_property():
    """size property reflects total number of keys."""
    hierarchy = HardwareKeyHierarchy()
    assert hierarchy.size == 0

    await hierarchy.initialize()
    assert hierarchy.size == 1

    hierarchy.derive_key(hierarchy.root.key_id, KeyPurpose.SIGNING)
    assert hierarchy.size == 2


# ---------------------------------------------------------------------------
# create_hardware_security factory tests
# ---------------------------------------------------------------------------


async def test_create_hardware_security_returns_dict():
    """create_hardware_security() returns a dict with expected keys."""
    result = create_hardware_security()

    assert isinstance(result, dict)
    assert "tpm_manager" in result
    assert "enclave_manager" in result
    assert "attestation_verifier" in result
    assert "key_hierarchy" in result


async def test_create_hardware_security_types():
    """create_hardware_security() returns instances of correct types."""
    result = create_hardware_security()

    assert isinstance(result["tpm_manager"], TPMKeyManager)
    assert isinstance(result["enclave_manager"], EnclaveManager)
    assert isinstance(result["attestation_verifier"], AttestationVerifier)
    assert isinstance(result["key_hierarchy"], HardwareKeyHierarchy)
