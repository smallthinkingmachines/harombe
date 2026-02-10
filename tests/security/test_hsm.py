"""Tests for the Hardware Security Module (HSM) integration."""

import pytest

from harombe.security.distributed.hsm import (
    PKCS11HSM,
    CloudKMSHSM,
    HSMKeyInfo,
    HSMKeyType,
    HSMManager,
    HSMOperationResult,
    SoftwareHSM,
)

# ---------------------------------------------------------------------------
# HSMKeyType enum tests
# ---------------------------------------------------------------------------


async def test_hsm_key_type_values():
    """HSMKeyType enum contains all expected key types."""
    assert HSMKeyType.RSA_2048 == "rsa_2048"
    assert HSMKeyType.RSA_4096 == "rsa_4096"
    assert HSMKeyType.ECDSA_P256 == "ecdsa_p256"
    assert HSMKeyType.ECDSA_P384 == "ecdsa_p384"
    assert HSMKeyType.AES_128 == "aes_128"
    assert HSMKeyType.AES_256 == "aes_256"
    assert HSMKeyType.HMAC_SHA256 == "hmac_sha256"


async def test_hsm_key_type_is_str_enum():
    """HSMKeyType members are strings."""
    for member in HSMKeyType:
        assert isinstance(member, str)


# ---------------------------------------------------------------------------
# HSMKeyInfo model tests
# ---------------------------------------------------------------------------


async def test_hsm_key_info_creation():
    """HSMKeyInfo can be created with required fields."""
    info = HSMKeyInfo(key_id="test-key-1", key_type=HSMKeyType.RSA_2048)
    assert info.key_id == "test-key-1"
    assert info.key_type == HSMKeyType.RSA_2048
    assert info.extractable is False
    assert info.label == ""
    assert info.usage_count == 0
    assert info.created_at is not None


# ---------------------------------------------------------------------------
# HSMOperationResult model tests
# ---------------------------------------------------------------------------


async def test_hsm_operation_result_success():
    """HSMOperationResult can represent a successful operation."""
    result = HSMOperationResult(
        success=True, data=b"signature", key_id="key-1", operation_time=0.01
    )
    assert result.success is True
    assert result.data == b"signature"
    assert result.key_id == "key-1"
    assert result.error is None


async def test_hsm_operation_result_failure():
    """HSMOperationResult can represent a failed operation."""
    result = HSMOperationResult(success=False, error="Key not found", key_id="missing")
    assert result.success is False
    assert result.data is None
    assert result.error == "Key not found"


# ---------------------------------------------------------------------------
# SoftwareHSM tests
# ---------------------------------------------------------------------------


async def test_software_hsm_initialize():
    """SoftwareHSM can be initialized."""
    hsm = SoftwareHSM()
    await hsm.initialize()
    assert hsm._initialized is True
    await hsm.shutdown()


async def test_software_hsm_rsa_sign_verify():
    """SoftwareHSM can generate an RSA key and sign/verify data."""
    hsm = SoftwareHSM()
    await hsm.initialize()

    key_info = await hsm.generate_key(HSMKeyType.RSA_2048, label="rsa-test")
    assert key_info.key_type == HSMKeyType.RSA_2048
    assert key_info.label == "rsa-test"

    data = b"Hello, RSA signing!"
    sign_result = await hsm.sign(key_info.key_id, data)
    assert sign_result.success is True
    assert sign_result.data is not None

    verify_result = await hsm.verify(key_info.key_id, data, sign_result.data)
    assert verify_result.success is True

    await hsm.shutdown()


async def test_software_hsm_ecdsa_sign_verify():
    """SoftwareHSM can generate an ECDSA key and sign/verify data."""
    hsm = SoftwareHSM()
    await hsm.initialize()

    key_info = await hsm.generate_key(HSMKeyType.ECDSA_P256, label="ec-test")
    assert key_info.key_type == HSMKeyType.ECDSA_P256

    data = b"Hello, ECDSA signing!"
    sign_result = await hsm.sign(key_info.key_id, data)
    assert sign_result.success is True
    assert sign_result.data is not None

    verify_result = await hsm.verify(key_info.key_id, data, sign_result.data)
    assert verify_result.success is True

    await hsm.shutdown()


async def test_software_hsm_ecdsa_p384_sign_verify():
    """SoftwareHSM can generate an ECDSA P-384 key and sign/verify."""
    hsm = SoftwareHSM()
    await hsm.initialize()

    key_info = await hsm.generate_key(HSMKeyType.ECDSA_P384)
    data = b"P-384 curve test"

    sign_result = await hsm.sign(key_info.key_id, data)
    assert sign_result.success is True

    verify_result = await hsm.verify(key_info.key_id, data, sign_result.data)
    assert verify_result.success is True

    await hsm.shutdown()


async def test_software_hsm_aes_encrypt_decrypt():
    """SoftwareHSM can generate an AES key and encrypt/decrypt data."""
    hsm = SoftwareHSM()
    await hsm.initialize()

    key_info = await hsm.generate_key(HSMKeyType.AES_256, label="aes-test")
    assert key_info.key_type == HSMKeyType.AES_256

    plaintext = b"Secret data for AES encryption"
    enc_result = await hsm.encrypt(key_info.key_id, plaintext)
    assert enc_result.success is True
    assert enc_result.data is not None
    assert enc_result.data != plaintext

    dec_result = await hsm.decrypt(key_info.key_id, enc_result.data)
    assert dec_result.success is True
    assert dec_result.data == plaintext

    await hsm.shutdown()


async def test_software_hsm_aes_128_encrypt_decrypt():
    """SoftwareHSM can generate an AES-128 key and encrypt/decrypt."""
    hsm = SoftwareHSM()
    await hsm.initialize()

    key_info = await hsm.generate_key(HSMKeyType.AES_128)
    plaintext = b"AES-128 test data"

    enc_result = await hsm.encrypt(key_info.key_id, plaintext)
    assert enc_result.success is True

    dec_result = await hsm.decrypt(key_info.key_id, enc_result.data)
    assert dec_result.success is True
    assert dec_result.data == plaintext

    await hsm.shutdown()


async def test_software_hsm_hmac_sign_verify():
    """SoftwareHSM can generate an HMAC key and sign/verify data."""
    hsm = SoftwareHSM()
    await hsm.initialize()

    key_info = await hsm.generate_key(HSMKeyType.HMAC_SHA256, label="hmac-test")
    assert key_info.key_type == HSMKeyType.HMAC_SHA256

    data = b"Message to authenticate"
    mac_result = await hsm.hmac_sign(key_info.key_id, data)
    assert mac_result.success is True
    assert mac_result.data is not None

    verify_result = await hsm.hmac_verify(key_info.key_id, data, mac_result.data)
    assert verify_result.success is True

    await hsm.shutdown()


async def test_software_hsm_rsa_encrypt_decrypt():
    """SoftwareHSM can encrypt/decrypt with RSA keys."""
    hsm = SoftwareHSM()
    await hsm.initialize()

    key_info = await hsm.generate_key(HSMKeyType.RSA_2048)
    plaintext = b"RSA encryption test"

    enc_result = await hsm.encrypt(key_info.key_id, plaintext)
    assert enc_result.success is True
    assert enc_result.data is not None

    dec_result = await hsm.decrypt(key_info.key_id, enc_result.data)
    assert dec_result.success is True
    assert dec_result.data == plaintext

    await hsm.shutdown()


async def test_software_hsm_verify_with_wrong_data():
    """Verification fails when data does not match the signature."""
    hsm = SoftwareHSM()
    await hsm.initialize()

    key_info = await hsm.generate_key(HSMKeyType.RSA_2048)
    data = b"Original data"
    sign_result = await hsm.sign(key_info.key_id, data)
    assert sign_result.success is True

    verify_result = await hsm.verify(key_info.key_id, b"Tampered data", sign_result.data)
    assert verify_result.success is False

    await hsm.shutdown()


async def test_software_hsm_decrypt_with_wrong_key():
    """Decryption fails when using the wrong key."""
    hsm = SoftwareHSM()
    await hsm.initialize()

    key1 = await hsm.generate_key(HSMKeyType.AES_256)
    key2 = await hsm.generate_key(HSMKeyType.AES_256)

    plaintext = b"Secret message"
    enc_result = await hsm.encrypt(key1.key_id, plaintext)
    assert enc_result.success is True

    dec_result = await hsm.decrypt(key2.key_id, enc_result.data)
    assert dec_result.success is False

    await hsm.shutdown()


async def test_software_hsm_export_key_extractable():
    """Export succeeds for keys marked as extractable."""
    hsm = SoftwareHSM()
    await hsm.initialize()

    key_info = await hsm.generate_key(HSMKeyType.AES_256, extractable=True)
    result = await hsm.export_key(key_info.key_id)
    assert result.success is True
    assert result.data is not None
    assert len(result.data) > 0

    await hsm.shutdown()


async def test_software_hsm_export_key_not_extractable():
    """Export fails for keys not marked as extractable."""
    hsm = SoftwareHSM()
    await hsm.initialize()

    key_info = await hsm.generate_key(HSMKeyType.AES_256, extractable=False)
    result = await hsm.export_key(key_info.key_id)
    assert result.success is False
    assert "not extractable" in result.error

    await hsm.shutdown()


async def test_software_hsm_export_rsa_key_extractable():
    """Export succeeds for extractable RSA keys."""
    hsm = SoftwareHSM()
    await hsm.initialize()

    key_info = await hsm.generate_key(HSMKeyType.RSA_2048, extractable=True)
    result = await hsm.export_key(key_info.key_id)
    assert result.success is True
    assert result.data is not None

    await hsm.shutdown()


async def test_software_hsm_destroy_key():
    """Destroying a key removes it from the HSM."""
    hsm = SoftwareHSM()
    await hsm.initialize()

    key_info = await hsm.generate_key(HSMKeyType.AES_256)
    assert await hsm.get_key_info(key_info.key_id) is not None

    await hsm.destroy_key(key_info.key_id)
    assert await hsm.get_key_info(key_info.key_id) is None

    await hsm.shutdown()


async def test_software_hsm_list_keys():
    """list_keys returns all generated keys."""
    hsm = SoftwareHSM()
    await hsm.initialize()

    await hsm.generate_key(HSMKeyType.RSA_2048, label="key-a")
    await hsm.generate_key(HSMKeyType.AES_256, label="key-b")

    keys = await hsm.list_keys()
    assert len(keys) == 2
    labels = {k.label for k in keys}
    assert labels == {"key-a", "key-b"}

    await hsm.shutdown()


async def test_software_hsm_get_key_info():
    """get_key_info returns metadata for an existing key."""
    hsm = SoftwareHSM()
    await hsm.initialize()

    key_info = await hsm.generate_key(HSMKeyType.ECDSA_P256, label="info-test")
    retrieved = await hsm.get_key_info(key_info.key_id)
    assert retrieved is not None
    assert retrieved.key_id == key_info.key_id
    assert retrieved.label == "info-test"

    await hsm.shutdown()


async def test_software_hsm_get_key_info_nonexistent():
    """get_key_info returns None for a nonexistent key ID."""
    hsm = SoftwareHSM()
    await hsm.initialize()

    result = await hsm.get_key_info("nonexistent-key-id")
    assert result is None

    await hsm.shutdown()


async def test_software_hsm_hmac_verify_wrong_mac():
    """HMAC verification fails with an incorrect MAC."""
    hsm = SoftwareHSM()
    await hsm.initialize()

    key_info = await hsm.generate_key(HSMKeyType.HMAC_SHA256)
    data = b"authenticated message"

    mac_result = await hsm.hmac_sign(key_info.key_id, data)
    assert mac_result.success is True

    # Tamper with the MAC
    bad_mac = b"\x00" * len(mac_result.data)
    verify_result = await hsm.hmac_verify(key_info.key_id, data, bad_mac)
    assert verify_result.success is False

    await hsm.shutdown()


async def test_software_hsm_usage_count_increments():
    """Usage count increments after each operation."""
    hsm = SoftwareHSM()
    await hsm.initialize()

    key_info = await hsm.generate_key(HSMKeyType.RSA_2048)
    data = b"usage count test"

    await hsm.sign(key_info.key_id, data)
    info = await hsm.get_key_info(key_info.key_id)
    assert info.usage_count == 1

    sign_result = await hsm.sign(key_info.key_id, data)
    await hsm.verify(key_info.key_id, data, sign_result.data)
    info = await hsm.get_key_info(key_info.key_id)
    assert info.usage_count == 3

    await hsm.shutdown()


# ---------------------------------------------------------------------------
# PKCS11HSM stub tests
# ---------------------------------------------------------------------------


async def test_pkcs11_hsm_raises_not_implemented():
    """All PKCS11HSM methods raise NotImplementedError."""
    hsm = PKCS11HSM()

    with pytest.raises(NotImplementedError, match="python-pkcs11"):
        await hsm.initialize()

    with pytest.raises(NotImplementedError, match="python-pkcs11"):
        await hsm.generate_key(HSMKeyType.RSA_2048)

    with pytest.raises(NotImplementedError, match="python-pkcs11"):
        await hsm.sign("k", b"d")

    with pytest.raises(NotImplementedError, match="python-pkcs11"):
        await hsm.verify("k", b"d", b"s")

    with pytest.raises(NotImplementedError, match="python-pkcs11"):
        await hsm.encrypt("k", b"d")

    with pytest.raises(NotImplementedError, match="python-pkcs11"):
        await hsm.decrypt("k", b"d")

    with pytest.raises(NotImplementedError, match="python-pkcs11"):
        await hsm.hmac_sign("k", b"d")

    with pytest.raises(NotImplementedError, match="python-pkcs11"):
        await hsm.hmac_verify("k", b"d", b"m")

    with pytest.raises(NotImplementedError, match="python-pkcs11"):
        await hsm.export_key("k")

    with pytest.raises(NotImplementedError, match="python-pkcs11"):
        await hsm.destroy_key("k")

    with pytest.raises(NotImplementedError, match="python-pkcs11"):
        await hsm.list_keys()

    with pytest.raises(NotImplementedError, match="python-pkcs11"):
        await hsm.get_key_info("k")

    with pytest.raises(NotImplementedError, match="python-pkcs11"):
        await hsm.shutdown()


# ---------------------------------------------------------------------------
# CloudKMSHSM stub tests
# ---------------------------------------------------------------------------


async def test_cloud_kms_hsm_raises_not_implemented():
    """All CloudKMSHSM methods raise NotImplementedError."""
    hsm = CloudKMSHSM()

    with pytest.raises(NotImplementedError, match="Cloud KMS"):
        await hsm.initialize()

    with pytest.raises(NotImplementedError, match="Cloud KMS"):
        await hsm.generate_key(HSMKeyType.RSA_2048)

    with pytest.raises(NotImplementedError, match="Cloud KMS"):
        await hsm.sign("k", b"d")

    with pytest.raises(NotImplementedError, match="Cloud KMS"):
        await hsm.shutdown()


# ---------------------------------------------------------------------------
# HSMManager tests
# ---------------------------------------------------------------------------


async def test_hsm_manager_start_stop():
    """HSMManager can start and stop."""
    manager = HSMManager()
    await manager.start()
    assert manager._started is True
    await manager.stop()
    assert manager._started is False


async def test_hsm_manager_generate_key_and_sign_verify():
    """HSMManager can generate a key and sign/verify data."""
    manager = HSMManager()
    await manager.start()

    key_info = await manager.generate_key(HSMKeyType.RSA_2048, label="mgr-test")
    assert key_info.key_type == HSMKeyType.RSA_2048

    data = b"Manager sign/verify test"
    signature = await manager.sign(key_info.key_id, data)
    assert isinstance(signature, bytes)

    is_valid = await manager.verify(key_info.key_id, data, signature)
    assert is_valid is True

    await manager.stop()


async def test_hsm_manager_encrypt_decrypt():
    """HSMManager can encrypt and decrypt data."""
    manager = HSMManager()
    await manager.start()

    key_info = await manager.generate_key(HSMKeyType.AES_256)
    plaintext = b"Manager encryption test"

    ciphertext = await manager.encrypt(key_info.key_id, plaintext)
    assert ciphertext != plaintext

    decrypted = await manager.decrypt(key_info.key_id, ciphertext)
    assert decrypted == plaintext

    await manager.stop()


async def test_hsm_manager_hmac_sign_verify():
    """HSMManager can compute and verify HMAC."""
    manager = HSMManager()
    await manager.start()

    key_info = await manager.generate_key(HSMKeyType.HMAC_SHA256)
    data = b"Manager HMAC test"

    mac = await manager.hmac_sign(key_info.key_id, data)
    assert isinstance(mac, bytes)

    is_valid = await manager.hmac_verify(key_info.key_id, data, mac)
    assert is_valid is True

    await manager.stop()


async def test_hsm_manager_list_keys():
    """HSMManager can list keys."""
    manager = HSMManager()
    await manager.start()

    await manager.generate_key(HSMKeyType.RSA_2048, label="list-1")
    await manager.generate_key(HSMKeyType.AES_256, label="list-2")

    keys = await manager.list_keys()
    assert len(keys) == 2

    await manager.stop()


async def test_hsm_manager_destroy_key():
    """HSMManager can destroy a key."""
    manager = HSMManager()
    await manager.start()

    key_info = await manager.generate_key(HSMKeyType.AES_256)
    await manager.destroy_key(key_info.key_id)

    keys = await manager.list_keys()
    assert len(keys) == 0

    await manager.stop()


async def test_hsm_manager_get_stats():
    """HSMManager tracks operation statistics."""
    manager = HSMManager()
    await manager.start()

    key_info = await manager.generate_key(HSMKeyType.AES_256)
    await manager.encrypt(key_info.key_id, b"test")

    stats = await manager.get_stats()
    assert stats["keys_generated"] == 1
    assert stats["encrypt_operations"] == 1
    assert stats["backend"] == "SoftwareHSM"
    assert stats["total_keys"] == 1

    await manager.stop()


async def test_hsm_manager_operation_on_nonexistent_key():
    """HSMManager raises RuntimeError for operations on nonexistent keys."""
    manager = HSMManager()
    await manager.start()

    with pytest.raises(RuntimeError, match="Sign operation failed"):
        await manager.sign("nonexistent-key", b"data")

    with pytest.raises(RuntimeError, match="Encrypt operation failed"):
        await manager.encrypt("nonexistent-key", b"data")

    with pytest.raises(RuntimeError, match="Decrypt operation failed"):
        await manager.decrypt("nonexistent-key", b"data")

    with pytest.raises(RuntimeError, match="HMAC sign operation failed"):
        await manager.hmac_sign("nonexistent-key", b"data")

    stats = await manager.get_stats()
    assert stats["errors"] == 4

    await manager.stop()


async def test_hsm_manager_verify_nonexistent_key_returns_false():
    """HSMManager.verify returns False for nonexistent keys."""
    manager = HSMManager()
    await manager.start()

    is_valid = await manager.verify("nonexistent-key", b"data", b"sig")
    assert is_valid is False

    await manager.stop()


async def test_hsm_manager_defaults_to_software_hsm():
    """HSMManager defaults to SoftwareHSM when no backend is provided."""
    manager = HSMManager()
    assert isinstance(manager._backend, SoftwareHSM)
