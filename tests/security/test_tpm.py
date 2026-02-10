"""Tests for TPM integration and key storage."""

import pytest
from cryptography.exceptions import InvalidTag

from harombe.security.hardware.tpm import (
    LinuxTPM,
    SoftwareTPM,
    TPMAlgorithm,
    TPMKeyHandle,
    TPMKeyManager,
    TPMSealedData,
)

# --- TPMAlgorithm enum tests ---


async def test_tpm_algorithm_rsa_values():
    """Test RSA algorithm enum values."""
    assert TPMAlgorithm.RSA_2048 == "rsa_2048"
    assert TPMAlgorithm.RSA_4096 == "rsa_4096"


async def test_tpm_algorithm_ecdsa_values():
    """Test ECDSA algorithm enum values."""
    assert TPMAlgorithm.ECDSA_P256 == "ecdsa_p256"
    assert TPMAlgorithm.ECDSA_P384 == "ecdsa_p384"


async def test_tpm_algorithm_aes_values():
    """Test AES algorithm enum values."""
    assert TPMAlgorithm.AES_128 == "aes_128"
    assert TPMAlgorithm.AES_256 == "aes_256"


# --- Pydantic model tests ---


async def test_tpm_key_handle_creation():
    """Test TPMKeyHandle model creation with defaults."""
    handle = TPMKeyHandle(
        key_id="test-key-1",
        algorithm=TPMAlgorithm.ECDSA_P256,
    )
    assert handle.key_id == "test-key-1"
    assert handle.algorithm == TPMAlgorithm.ECDSA_P256
    assert handle.exportable is False
    assert handle.metadata == {}
    assert handle.created_at is not None


async def test_tpm_sealed_data_creation():
    """Test TPMSealedData model creation."""
    sealed = TPMSealedData(
        data_id="sealed-1",
        ciphertext=b"encrypted",
        nonce=b"nonce12bytes",
        tag=b"tag16byteslong!x",
        policy_hash="abc123",
    )
    assert sealed.data_id == "sealed-1"
    assert sealed.ciphertext == b"encrypted"
    assert sealed.policy_hash == "abc123"
    assert sealed.sealed_at is not None


# --- SoftwareTPM tests ---


async def test_software_tpm_initialize():
    """Test SoftwareTPM initialization."""
    tpm = SoftwareTPM()
    assert tpm._initialized is False
    await tpm.initialize()
    assert tpm._initialized is True
    assert tpm._master_seal_key is not None
    assert len(tpm._master_seal_key) == 32


async def test_software_tpm_not_initialized_raises():
    """Test that operations before initialize() raise RuntimeError."""
    tpm = SoftwareTPM()
    with pytest.raises(RuntimeError, match="not initialized"):
        await tpm.create_key(TPMAlgorithm.ECDSA_P256)


async def test_software_tpm_create_key_rsa_2048():
    """Test creating an RSA 2048 key."""
    tpm = SoftwareTPM()
    await tpm.initialize()
    handle = await tpm.create_key(TPMAlgorithm.RSA_2048)
    assert handle.algorithm == TPMAlgorithm.RSA_2048
    assert handle.key_id in tpm._keys


async def test_software_tpm_create_key_rsa_4096():
    """Test creating an RSA 4096 key."""
    tpm = SoftwareTPM()
    await tpm.initialize()
    handle = await tpm.create_key(TPMAlgorithm.RSA_4096)
    assert handle.algorithm == TPMAlgorithm.RSA_4096
    assert handle.key_id in tpm._keys


async def test_software_tpm_create_key_ecdsa_p256():
    """Test creating an ECDSA P-256 key."""
    tpm = SoftwareTPM()
    await tpm.initialize()
    handle = await tpm.create_key(TPMAlgorithm.ECDSA_P256)
    assert handle.algorithm == TPMAlgorithm.ECDSA_P256
    assert handle.key_id in tpm._keys


async def test_software_tpm_create_key_ecdsa_p384():
    """Test creating an ECDSA P-384 key."""
    tpm = SoftwareTPM()
    await tpm.initialize()
    handle = await tpm.create_key(TPMAlgorithm.ECDSA_P384)
    assert handle.algorithm == TPMAlgorithm.ECDSA_P384
    assert handle.key_id in tpm._keys


async def test_software_tpm_create_key_aes_128():
    """Test creating an AES-128 key."""
    tpm = SoftwareTPM()
    await tpm.initialize()
    handle = await tpm.create_key(TPMAlgorithm.AES_128)
    assert handle.algorithm == TPMAlgorithm.AES_128
    assert handle.key_id in tpm._keys


async def test_software_tpm_create_key_aes_256():
    """Test creating an AES-256 key."""
    tpm = SoftwareTPM()
    await tpm.initialize()
    handle = await tpm.create_key(TPMAlgorithm.AES_256)
    assert handle.algorithm == TPMAlgorithm.AES_256
    assert handle.key_id in tpm._keys


async def test_software_tpm_sign_verify_rsa_2048():
    """Test sign and verify cycle with RSA 2048."""
    tpm = SoftwareTPM()
    await tpm.initialize()
    handle = await tpm.create_key(TPMAlgorithm.RSA_2048)

    data = b"hello world"
    signature = await tpm.sign(handle, data)
    assert isinstance(signature, bytes)
    assert len(signature) > 0

    valid = await tpm.verify(handle, data, signature)
    assert valid is True


async def test_software_tpm_sign_verify_ecdsa_p256():
    """Test sign and verify cycle with ECDSA P-256."""
    tpm = SoftwareTPM()
    await tpm.initialize()
    handle = await tpm.create_key(TPMAlgorithm.ECDSA_P256)

    data = b"test message for ecdsa signing"
    signature = await tpm.sign(handle, data)
    assert isinstance(signature, bytes)
    assert len(signature) > 0

    valid = await tpm.verify(handle, data, signature)
    assert valid is True


async def test_software_tpm_sign_verify_ecdsa_p384():
    """Test sign and verify cycle with ECDSA P-384."""
    tpm = SoftwareTPM()
    await tpm.initialize()
    handle = await tpm.create_key(TPMAlgorithm.ECDSA_P384)

    data = b"test message for p384"
    signature = await tpm.sign(handle, data)
    valid = await tpm.verify(handle, data, signature)
    assert valid is True


async def test_software_tpm_verify_wrong_data_fails():
    """Test that verification fails with tampered data."""
    tpm = SoftwareTPM()
    await tpm.initialize()
    handle = await tpm.create_key(TPMAlgorithm.ECDSA_P256)

    data = b"original message"
    signature = await tpm.sign(handle, data)

    # Verify with different data should fail
    valid = await tpm.verify(handle, b"tampered message", signature)
    assert valid is False


async def test_software_tpm_verify_wrong_signature_fails():
    """Test that verification fails with wrong signature."""
    tpm = SoftwareTPM()
    await tpm.initialize()
    handle = await tpm.create_key(TPMAlgorithm.RSA_2048)

    data = b"original message"
    await tpm.sign(handle, data)

    # Verify with garbage signature should fail
    valid = await tpm.verify(handle, data, b"not-a-real-signature")
    assert valid is False


async def test_software_tpm_sign_aes_key_raises():
    """Test that signing with an AES key raises ValueError."""
    tpm = SoftwareTPM()
    await tpm.initialize()
    handle = await tpm.create_key(TPMAlgorithm.AES_256)

    with pytest.raises(ValueError, match="does not support signing"):
        await tpm.sign(handle, b"data")


async def test_software_tpm_seal_unseal_cycle():
    """Test seal and unseal round-trip."""
    tpm = SoftwareTPM()
    await tpm.initialize()

    plaintext = b"super secret api key"
    sealed = await tpm.seal(plaintext)

    assert isinstance(sealed, TPMSealedData)
    assert sealed.ciphertext != plaintext
    assert len(sealed.nonce) == 12
    assert len(sealed.tag) == 16
    assert sealed.policy_hash is None

    recovered = await tpm.unseal(sealed)
    assert recovered == plaintext


async def test_software_tpm_seal_with_policy_hash():
    """Test seal/unseal with a PCR policy hash binding."""
    tpm = SoftwareTPM()
    await tpm.initialize()

    plaintext = b"policy-bound secret"
    policy = "sha256:pcr0+pcr7"
    sealed = await tpm.seal(plaintext, policy_hash=policy)

    assert sealed.policy_hash == policy

    recovered = await tpm.unseal(sealed)
    assert recovered == plaintext


async def test_software_tpm_unseal_tampered_ciphertext_fails():
    """Test that unsealing tampered ciphertext fails."""
    tpm = SoftwareTPM()
    await tpm.initialize()

    plaintext = b"secret data"
    sealed = await tpm.seal(plaintext)

    # Tamper with the ciphertext
    tampered = TPMSealedData(
        data_id=sealed.data_id,
        ciphertext=b"\x00" * len(sealed.ciphertext),
        nonce=sealed.nonce,
        tag=sealed.tag,
        policy_hash=sealed.policy_hash,
    )

    with pytest.raises(InvalidTag):
        await tpm.unseal(tampered)


async def test_software_tpm_unseal_tampered_tag_fails():
    """Test that unsealing with tampered tag fails."""
    tpm = SoftwareTPM()
    await tpm.initialize()

    plaintext = b"secret data"
    sealed = await tpm.seal(plaintext)

    # Tamper with the tag
    tampered = TPMSealedData(
        data_id=sealed.data_id,
        ciphertext=sealed.ciphertext,
        nonce=sealed.nonce,
        tag=b"\xff" * 16,
        policy_hash=sealed.policy_hash,
    )

    with pytest.raises(InvalidTag):
        await tpm.unseal(tampered)


async def test_software_tpm_get_random_correct_length():
    """Test that get_random returns the correct number of bytes."""
    tpm = SoftwareTPM()
    await tpm.initialize()

    for length in [16, 32, 64, 128]:
        random_bytes = await tpm.get_random(length)
        assert len(random_bytes) == length


async def test_software_tpm_get_random_unique():
    """Test that successive get_random calls return different values."""
    tpm = SoftwareTPM()
    await tpm.initialize()

    r1 = await tpm.get_random(32)
    r2 = await tpm.get_random(32)
    assert r1 != r2


async def test_software_tpm_destroy_key():
    """Test destroying a key removes it from the store."""
    tpm = SoftwareTPM()
    await tpm.initialize()

    handle = await tpm.create_key(TPMAlgorithm.ECDSA_P256)
    assert handle.key_id in tpm._keys

    await tpm.destroy_key(handle)
    assert handle.key_id not in tpm._keys


async def test_software_tpm_destroy_unknown_key_raises():
    """Test that destroying a nonexistent key raises KeyError."""
    tpm = SoftwareTPM()
    await tpm.initialize()

    fake_handle = TPMKeyHandle(
        key_id="nonexistent",
        algorithm=TPMAlgorithm.ECDSA_P256,
    )

    with pytest.raises(KeyError, match="Key not found"):
        await tpm.destroy_key(fake_handle)


async def test_software_tpm_sign_unknown_key_raises():
    """Test that signing with unknown key raises KeyError."""
    tpm = SoftwareTPM()
    await tpm.initialize()

    fake_handle = TPMKeyHandle(
        key_id="nonexistent",
        algorithm=TPMAlgorithm.ECDSA_P256,
    )

    with pytest.raises(KeyError, match="Key not found"):
        await tpm.sign(fake_handle, b"data")


# --- LinuxTPM stub tests ---


async def test_linux_tpm_initialize_raises():
    """Test LinuxTPM initialize raises NotImplementedError."""
    tpm = LinuxTPM()
    with pytest.raises(NotImplementedError, match="tpm2-pytss not available"):
        await tpm.initialize()


async def test_linux_tpm_create_key_raises():
    """Test LinuxTPM create_key raises NotImplementedError."""
    tpm = LinuxTPM()
    with pytest.raises(NotImplementedError, match="tpm2-pytss not available"):
        await tpm.create_key(TPMAlgorithm.ECDSA_P256)


async def test_linux_tpm_sign_raises():
    """Test LinuxTPM sign raises NotImplementedError."""
    tpm = LinuxTPM()
    handle = TPMKeyHandle(key_id="test", algorithm=TPMAlgorithm.ECDSA_P256)
    with pytest.raises(NotImplementedError, match="tpm2-pytss not available"):
        await tpm.sign(handle, b"data")


async def test_linux_tpm_verify_raises():
    """Test LinuxTPM verify raises NotImplementedError."""
    tpm = LinuxTPM()
    handle = TPMKeyHandle(key_id="test", algorithm=TPMAlgorithm.ECDSA_P256)
    with pytest.raises(NotImplementedError, match="tpm2-pytss not available"):
        await tpm.verify(handle, b"data", b"sig")


async def test_linux_tpm_seal_raises():
    """Test LinuxTPM seal raises NotImplementedError."""
    tpm = LinuxTPM()
    with pytest.raises(NotImplementedError, match="tpm2-pytss not available"):
        await tpm.seal(b"data")


async def test_linux_tpm_unseal_raises():
    """Test LinuxTPM unseal raises NotImplementedError."""
    tpm = LinuxTPM()
    sealed = TPMSealedData(
        data_id="test",
        ciphertext=b"ct",
        nonce=b"nonce",
        tag=b"tag",
    )
    with pytest.raises(NotImplementedError, match="tpm2-pytss not available"):
        await tpm.unseal(sealed)


async def test_linux_tpm_get_random_raises():
    """Test LinuxTPM get_random raises NotImplementedError."""
    tpm = LinuxTPM()
    with pytest.raises(NotImplementedError, match="tpm2-pytss not available"):
        await tpm.get_random(32)


async def test_linux_tpm_destroy_key_raises():
    """Test LinuxTPM destroy_key raises NotImplementedError."""
    tpm = LinuxTPM()
    handle = TPMKeyHandle(key_id="test", algorithm=TPMAlgorithm.ECDSA_P256)
    with pytest.raises(NotImplementedError, match="tpm2-pytss not available"):
        await tpm.destroy_key(handle)


# --- TPMKeyManager tests ---


async def test_key_manager_default_backend():
    """Test TPMKeyManager defaults to SoftwareTPM."""
    manager = TPMKeyManager()
    assert isinstance(manager.backend, SoftwareTPM)


async def test_key_manager_create_signing_key():
    """Test creating a signing key via the manager."""
    manager = TPMKeyManager()
    await manager.backend.initialize()

    handle = await manager.create_signing_key(TPMAlgorithm.ECDSA_P256)
    assert handle.algorithm == TPMAlgorithm.ECDSA_P256
    assert handle.key_id in manager._key_handles


async def test_key_manager_create_encryption_key():
    """Test creating an encryption key via the manager."""
    manager = TPMKeyManager()
    await manager.backend.initialize()

    handle = await manager.create_encryption_key(TPMAlgorithm.AES_256)
    assert handle.algorithm == TPMAlgorithm.AES_256
    assert handle.key_id in manager._key_handles


async def test_key_manager_create_encryption_key_aes_128():
    """Test creating an AES-128 encryption key via the manager."""
    manager = TPMKeyManager()
    await manager.backend.initialize()

    handle = await manager.create_encryption_key(TPMAlgorithm.AES_128)
    assert handle.algorithm == TPMAlgorithm.AES_128


async def test_key_manager_sign_data_and_verify():
    """Test sign and verify through the key manager."""
    manager = TPMKeyManager()
    await manager.backend.initialize()

    handle = await manager.create_signing_key(TPMAlgorithm.ECDSA_P256)
    data = b"manager sign/verify test"

    signature = await manager.sign_data(handle.key_id, data)
    assert isinstance(signature, bytes)

    valid = await manager.verify_signature(handle.key_id, data, signature)
    assert valid is True


async def test_key_manager_sign_unknown_key_raises():
    """Test that signing with unknown key_id raises KeyError."""
    manager = TPMKeyManager()
    await manager.backend.initialize()

    with pytest.raises(KeyError, match="Key not found"):
        await manager.sign_data("nonexistent-id", b"data")


async def test_key_manager_verify_unknown_key_raises():
    """Test that verifying with unknown key_id raises KeyError."""
    manager = TPMKeyManager()
    await manager.backend.initialize()

    with pytest.raises(KeyError, match="Key not found"):
        await manager.verify_signature("nonexistent-id", b"data", b"sig")


async def test_key_manager_seal_and_unseal_secret():
    """Test sealing and unsealing a secret via the manager."""
    manager = TPMKeyManager()
    await manager.backend.initialize()

    secret = b"my-secret-password-123"
    sealed = await manager.seal_secret(secret)

    recovered = await manager.unseal_secret(sealed)
    assert recovered == secret


async def test_key_manager_seal_with_policy():
    """Test sealing with a policy hash via the manager."""
    manager = TPMKeyManager()
    await manager.backend.initialize()

    secret = b"policy-bound-secret"
    sealed = await manager.seal_secret(secret, policy_hash="pcr-policy-hash")
    assert sealed.policy_hash == "pcr-policy-hash"

    recovered = await manager.unseal_secret(sealed)
    assert recovered == secret


async def test_key_manager_list_keys():
    """Test listing keys from the manager."""
    manager = TPMKeyManager()
    await manager.backend.initialize()

    # Start with no keys
    keys = await manager.list_keys()
    assert keys == []

    # Create some keys
    await manager.create_signing_key(TPMAlgorithm.ECDSA_P256)
    await manager.create_encryption_key(TPMAlgorithm.AES_256)
    await manager.create_signing_key(TPMAlgorithm.RSA_2048)

    keys = await manager.list_keys()
    assert len(keys) == 3


async def test_key_manager_destroy_key():
    """Test destroying a key via the manager."""
    manager = TPMKeyManager()
    await manager.backend.initialize()

    handle = await manager.create_signing_key(TPMAlgorithm.ECDSA_P256)
    assert len(await manager.list_keys()) == 1

    await manager.destroy_key(handle.key_id)
    assert len(await manager.list_keys()) == 0
    assert handle.key_id not in manager._key_handles


async def test_key_manager_destroy_unknown_key_raises():
    """Test that destroying unknown key_id raises KeyError."""
    manager = TPMKeyManager()
    await manager.backend.initialize()

    with pytest.raises(KeyError, match="Key not found"):
        await manager.destroy_key("does-not-exist")


async def test_key_manager_get_random_bytes_default():
    """Test get_random_bytes with default length."""
    manager = TPMKeyManager()
    await manager.backend.initialize()

    random_bytes = await manager.get_random_bytes()
    assert len(random_bytes) == 32


async def test_key_manager_get_random_bytes_custom_length():
    """Test get_random_bytes with custom length."""
    manager = TPMKeyManager()
    await manager.backend.initialize()

    random_bytes = await manager.get_random_bytes(num_bytes=64)
    assert len(random_bytes) == 64
