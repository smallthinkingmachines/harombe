"""Tests for the secure enclave utilization module."""

import pytest
from cryptography.exceptions import InvalidTag

from harombe.security.hardware.enclave import (
    EnclaveConfig,
    EnclaveManager,
    EnclaveResult,
    EnclaveStatus,
    SGXEnclave,
    SoftwareEnclave,
)

# ---------------------------------------------------------------------------
# EnclaveStatus enum tests
# ---------------------------------------------------------------------------


class TestEnclaveStatus:
    """Tests for EnclaveStatus enum."""

    def test_status_values(self):
        """All expected status values exist."""
        assert EnclaveStatus.UNINITIALIZED == "uninitialized"
        assert EnclaveStatus.INITIALIZING == "initializing"
        assert EnclaveStatus.READY == "ready"
        assert EnclaveStatus.EXECUTING == "executing"
        assert EnclaveStatus.ERROR == "error"
        assert EnclaveStatus.DESTROYED == "destroyed"

    def test_status_is_str(self):
        """EnclaveStatus members are strings."""
        for member in EnclaveStatus:
            assert isinstance(member, str)

    def test_status_member_count(self):
        """EnclaveStatus has exactly 6 members."""
        assert len(EnclaveStatus) == 6


# ---------------------------------------------------------------------------
# EnclaveConfig tests
# ---------------------------------------------------------------------------


class TestEnclaveConfig:
    """Tests for EnclaveConfig model."""

    def test_defaults(self):
        """Default config values are correct."""
        config = EnclaveConfig()
        assert config.max_memory_mb == 256
        assert config.max_execution_time == 30
        assert config.allow_networking is False
        assert config.debug_mode is False
        assert config.enclave_id is None

    def test_custom_values(self):
        """Custom config values are accepted."""
        config = EnclaveConfig(
            max_memory_mb=512,
            max_execution_time=60,
            allow_networking=True,
            debug_mode=True,
            enclave_id="test-enclave-001",
        )
        assert config.max_memory_mb == 512
        assert config.max_execution_time == 60
        assert config.allow_networking is True
        assert config.debug_mode is True
        assert config.enclave_id == "test-enclave-001"


# ---------------------------------------------------------------------------
# EnclaveResult tests
# ---------------------------------------------------------------------------


class TestEnclaveResult:
    """Tests for EnclaveResult model."""

    def test_defaults(self):
        """Default result values are correct."""
        result = EnclaveResult(success=True)
        assert result.success is True
        assert result.output is None
        assert result.error is None
        assert result.execution_time == 0.0
        assert result.enclave_id == ""
        assert result.attestation_report == {}

    def test_with_output(self):
        """Result can carry output bytes."""
        result = EnclaveResult(success=True, output=b"hello")
        assert result.output == b"hello"

    def test_with_error(self):
        """Failed result carries an error message."""
        result = EnclaveResult(success=False, error="boom")
        assert result.error == "boom"


# ---------------------------------------------------------------------------
# SoftwareEnclave tests
# ---------------------------------------------------------------------------


class TestSoftwareEnclave:
    """Tests for SoftwareEnclave backend."""

    async def test_initial_status(self):
        """New enclave starts in UNINITIALIZED status."""
        enclave = SoftwareEnclave()
        assert enclave.status == EnclaveStatus.UNINITIALIZED

    async def test_initialize(self):
        """Enclave transitions to READY after initialization."""
        enclave = SoftwareEnclave()
        await enclave.initialize(EnclaveConfig())
        assert enclave.status == EnclaveStatus.READY

    async def test_initialize_with_custom_id(self):
        """Enclave uses the provided enclave_id from config."""
        enclave = SoftwareEnclave()
        await enclave.initialize(EnclaveConfig(enclave_id="custom-id"))
        assert enclave._enclave_id == "custom-id"

    async def test_execute_returns_result(self):
        """Execute returns a successful EnclaveResult."""
        enclave = SoftwareEnclave()
        await enclave.initialize(EnclaveConfig())

        result = await enclave.execute(b"some_code")
        assert result.success is True
        assert result.output is not None
        assert len(result.output) == 32  # SHA-256 HMAC size
        assert result.execution_time > 0
        assert result.enclave_id != ""

    async def test_execute_with_input_data(self):
        """Execute with input data produces different output."""
        enclave = SoftwareEnclave()
        await enclave.initialize(EnclaveConfig())

        result_a = await enclave.execute(b"code", b"input_a")
        result_b = await enclave.execute(b"code", b"input_b")

        assert result_a.output != result_b.output

    async def test_execute_deterministic(self):
        """Same code+input produces the same output in the same enclave."""
        enclave = SoftwareEnclave()
        await enclave.initialize(EnclaveConfig())

        result_1 = await enclave.execute(b"code", b"data")
        result_2 = await enclave.execute(b"code", b"data")

        assert result_1.output == result_2.output

    async def test_execute_has_attestation_report(self):
        """Execute result includes an attestation report."""
        enclave = SoftwareEnclave()
        await enclave.initialize(EnclaveConfig())

        result = await enclave.execute(b"code")
        assert "enclave_id" in result.attestation_report
        assert "measurements" in result.attestation_report

    async def test_seal_unseal_roundtrip(self):
        """Data survives a seal then unseal cycle."""
        enclave = SoftwareEnclave()
        await enclave.initialize(EnclaveConfig())

        original = b"top secret data"
        sealed = await enclave.seal_data(original)
        assert sealed != original

        unsealed = await enclave.unseal_data(sealed)
        assert unsealed == original

    async def test_seal_produces_different_ciphertexts(self):
        """Sealing the same data twice yields different ciphertext."""
        enclave = SoftwareEnclave()
        await enclave.initialize(EnclaveConfig())

        data = b"same data"
        sealed_1 = await enclave.seal_data(data)
        sealed_2 = await enclave.seal_data(data)

        # Different nonces mean different ciphertexts
        assert sealed_1 != sealed_2

    async def test_unseal_tampered_data_fails(self):
        """Unsealing tampered ciphertext raises an exception."""
        enclave = SoftwareEnclave()
        await enclave.initialize(EnclaveConfig())

        sealed = await enclave.seal_data(b"important data")
        # Flip a byte in the ciphertext portion (after the 12-byte nonce)
        tampered = bytearray(sealed)
        tampered[14] ^= 0xFF
        tampered = bytes(tampered)

        with pytest.raises(InvalidTag):
            await enclave.unseal_data(tampered)

    async def test_unseal_short_data_raises(self):
        """Unsealing data shorter than nonce size raises ValueError."""
        enclave = SoftwareEnclave()
        await enclave.initialize(EnclaveConfig())

        with pytest.raises(ValueError, match="too short"):
            await enclave.unseal_data(b"short")

    async def test_get_attestation_report(self):
        """Attestation report contains expected fields."""
        enclave = SoftwareEnclave()
        await enclave.initialize(EnclaveConfig())

        report = await enclave.get_attestation_report()
        assert "enclave_id" in report
        assert "status" in report
        assert "backend" in report
        assert report["backend"] == "software"
        assert "measurements" in report
        assert "seal_key_hash" in report["measurements"]
        assert "hmac_key_hash" in report["measurements"]

    async def test_destroy(self):
        """Destroying an enclave transitions to DESTROYED status."""
        enclave = SoftwareEnclave()
        await enclave.initialize(EnclaveConfig())
        assert enclave.status == EnclaveStatus.READY

        await enclave.destroy()
        assert enclave.status == EnclaveStatus.DESTROYED

    async def test_execute_after_destroy_raises(self):
        """Executing on a destroyed enclave raises RuntimeError."""
        enclave = SoftwareEnclave()
        await enclave.initialize(EnclaveConfig())
        await enclave.destroy()

        with pytest.raises(RuntimeError, match="destroyed"):
            await enclave.execute(b"code")

    async def test_seal_after_destroy_raises(self):
        """Sealing on a destroyed enclave raises RuntimeError."""
        enclave = SoftwareEnclave()
        await enclave.initialize(EnclaveConfig())
        await enclave.destroy()

        with pytest.raises(RuntimeError, match="destroyed"):
            await enclave.seal_data(b"data")

    async def test_unseal_after_destroy_raises(self):
        """Unsealing on a destroyed enclave raises RuntimeError."""
        enclave = SoftwareEnclave()
        await enclave.initialize(EnclaveConfig())
        sealed = await enclave.seal_data(b"data")
        await enclave.destroy()

        with pytest.raises(RuntimeError, match="destroyed"):
            await enclave.unseal_data(sealed)

    async def test_execute_before_init_raises(self):
        """Executing before initialization raises RuntimeError."""
        enclave = SoftwareEnclave()

        with pytest.raises(RuntimeError, match="not ready"):
            await enclave.execute(b"code")

    async def test_status_returns_to_ready_after_execute(self):
        """Status goes back to READY after successful execution."""
        enclave = SoftwareEnclave()
        await enclave.initialize(EnclaveConfig())

        await enclave.execute(b"code")
        assert enclave.status == EnclaveStatus.READY


# ---------------------------------------------------------------------------
# SGXEnclave tests
# ---------------------------------------------------------------------------


class TestSGXEnclave:
    """Tests for SGXEnclave stub."""

    async def test_initialize_raises(self):
        """SGX initialize raises NotImplementedError."""
        enclave = SGXEnclave()
        with pytest.raises(NotImplementedError, match="SGX not available"):
            await enclave.initialize(EnclaveConfig())

    async def test_execute_raises(self):
        """SGX execute raises NotImplementedError."""
        enclave = SGXEnclave()
        with pytest.raises(NotImplementedError, match="SGX not available"):
            await enclave.execute(b"code")

    async def test_seal_data_raises(self):
        """SGX seal_data raises NotImplementedError."""
        enclave = SGXEnclave()
        with pytest.raises(NotImplementedError, match="SGX not available"):
            await enclave.seal_data(b"data")

    async def test_unseal_data_raises(self):
        """SGX unseal_data raises NotImplementedError."""
        enclave = SGXEnclave()
        with pytest.raises(NotImplementedError, match="SGX not available"):
            await enclave.unseal_data(b"sealed")

    async def test_get_attestation_report_raises(self):
        """SGX get_attestation_report raises NotImplementedError."""
        enclave = SGXEnclave()
        with pytest.raises(NotImplementedError, match="SGX not available"):
            await enclave.get_attestation_report()

    async def test_destroy_raises(self):
        """SGX destroy raises NotImplementedError."""
        enclave = SGXEnclave()
        with pytest.raises(NotImplementedError, match="SGX not available"):
            await enclave.destroy()

    def test_initial_status(self):
        """SGX enclave starts in UNINITIALIZED status."""
        enclave = SGXEnclave()
        assert enclave.status == EnclaveStatus.UNINITIALIZED


# ---------------------------------------------------------------------------
# EnclaveManager tests
# ---------------------------------------------------------------------------


class TestEnclaveManager:
    """Tests for EnclaveManager."""

    async def test_create_enclave(self):
        """Manager creates an enclave and returns an ID."""
        manager = EnclaveManager()
        enclave_id = await manager.create_enclave()
        assert isinstance(enclave_id, str)
        assert len(enclave_id) > 0

    async def test_create_enclave_with_config(self):
        """Manager respects the provided config."""
        manager = EnclaveManager()
        config = EnclaveConfig(max_memory_mb=128, enclave_id="my-enclave")
        enclave_id = await manager.create_enclave(config)
        assert enclave_id == "my-enclave"

    async def test_list_enclaves(self):
        """Manager lists all created enclaves."""
        manager = EnclaveManager()
        id_a = await manager.create_enclave()
        id_b = await manager.create_enclave()

        enclaves = await manager.list_enclaves()
        assert id_a in enclaves
        assert id_b in enclaves
        assert len(enclaves) == 2

    async def test_execute_in_enclave(self):
        """Manager delegates execution to the correct enclave."""
        manager = EnclaveManager()
        eid = await manager.create_enclave()

        result = await manager.execute_in_enclave(eid, b"code")
        assert result.success is True
        assert result.output is not None

    async def test_seal_unseal_via_manager(self):
        """Manager seal/unseal roundtrip works."""
        manager = EnclaveManager()
        eid = await manager.create_enclave()

        original = b"manager secret"
        sealed = await manager.seal_data(eid, original)
        unsealed = await manager.unseal_data(eid, sealed)
        assert unsealed == original

    async def test_get_attestation(self):
        """Manager retrieves attestation from the enclave."""
        manager = EnclaveManager()
        eid = await manager.create_enclave()

        report = await manager.get_attestation(eid)
        assert "enclave_id" in report
        assert "measurements" in report

    async def test_destroy_enclave(self):
        """Manager destroys the enclave."""
        manager = EnclaveManager()
        eid = await manager.create_enclave()

        await manager.destroy_enclave(eid)
        # Enclave should still be listed (but destroyed)
        assert eid in await manager.list_enclaves()

    async def test_operations_on_destroyed_enclave_fail(self):
        """Operations on a destroyed enclave raise RuntimeError."""
        manager = EnclaveManager()
        eid = await manager.create_enclave()
        await manager.destroy_enclave(eid)

        with pytest.raises(RuntimeError, match="destroyed"):
            await manager.execute_in_enclave(eid, b"code")

        with pytest.raises(RuntimeError, match="destroyed"):
            await manager.seal_data(eid, b"data")

        with pytest.raises(RuntimeError, match="destroyed"):
            await manager.unseal_data(eid, b"data")

    async def test_operations_on_unknown_enclave_fail(self):
        """Operations on an unknown enclave raise KeyError."""
        manager = EnclaveManager()

        with pytest.raises(KeyError, match="Unknown enclave"):
            await manager.execute_in_enclave("nonexistent", b"code")

        with pytest.raises(KeyError, match="Unknown enclave"):
            await manager.seal_data("nonexistent", b"data")

        with pytest.raises(KeyError, match="Unknown enclave"):
            await manager.unseal_data("nonexistent", b"sealed")

        with pytest.raises(KeyError, match="Unknown enclave"):
            await manager.destroy_enclave("nonexistent")

        with pytest.raises(KeyError, match="Unknown enclave"):
            await manager.get_attestation("nonexistent")

    async def test_default_backend_is_software(self):
        """Manager defaults to SoftwareEnclave backend."""
        manager = EnclaveManager()
        assert manager._backend_class is SoftwareEnclave

    async def test_multiple_enclaves_independent(self):
        """Data sealed in one enclave cannot be unsealed by another."""
        manager = EnclaveManager()
        eid_a = await manager.create_enclave()
        eid_b = await manager.create_enclave()

        sealed = await manager.seal_data(eid_a, b"secret")

        with pytest.raises(InvalidTag):
            await manager.unseal_data(eid_b, sealed)
