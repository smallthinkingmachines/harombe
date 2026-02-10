"""Tests for the confidential computing module."""

import os

import pytest

from harombe.security.confidential_compute import (
    ConfidentialComputeManager,
    ConfidentialConfig,
    ConfidentialExecutionResult,
    ConfidentialPlatform,
    MemoryRegion,
    SoftwareConfidentialCompute,
)

# ---------------------------------------------------------------------------
# ConfidentialPlatform enum tests
# ---------------------------------------------------------------------------


class TestConfidentialPlatform:
    """Tests for ConfidentialPlatform enum."""

    def test_software_value(self):
        """SOFTWARE platform has expected string value."""
        assert ConfidentialPlatform.SOFTWARE == "software"

    def test_sev_snp_value(self):
        """SEV_SNP platform has expected string value."""
        assert ConfidentialPlatform.SEV_SNP == "sev-snp"

    def test_tdx_value(self):
        """TDX platform has expected string value."""
        assert ConfidentialPlatform.TDX == "tdx"

    def test_cca_value(self):
        """CCA platform has expected string value."""
        assert ConfidentialPlatform.CCA == "cca"

    def test_platform_is_str(self):
        """ConfidentialPlatform members are strings."""
        for member in ConfidentialPlatform:
            assert isinstance(member, str)

    def test_platform_member_count(self):
        """ConfidentialPlatform has exactly 4 members."""
        assert len(ConfidentialPlatform) == 4


# ---------------------------------------------------------------------------
# ConfidentialConfig tests
# ---------------------------------------------------------------------------


class TestConfidentialConfig:
    """Tests for ConfidentialConfig model."""

    def test_defaults(self):
        """Default config values are correct."""
        config = ConfidentialConfig()
        assert config.platform == ConfidentialPlatform.SOFTWARE
        assert config.memory_size_mb == 256
        assert config.integrity_check is True
        assert config.encryption_algorithm == "AES-256-GCM"
        assert config.attestation_required is False

    def test_custom_values(self):
        """Custom config values are accepted."""
        config = ConfidentialConfig(
            platform=ConfidentialPlatform.TDX,
            memory_size_mb=512,
            integrity_check=False,
            encryption_algorithm="AES-128-GCM",
            attestation_required=True,
        )
        assert config.platform == ConfidentialPlatform.TDX
        assert config.memory_size_mb == 512
        assert config.integrity_check is False
        assert config.encryption_algorithm == "AES-128-GCM"
        assert config.attestation_required is True


# ---------------------------------------------------------------------------
# MemoryRegion tests
# ---------------------------------------------------------------------------


class TestMemoryRegion:
    """Tests for MemoryRegion model."""

    def test_creation(self):
        """MemoryRegion can be created with required fields."""
        region = MemoryRegion(
            region_id="test-region",
            start_address=0x1000,
            size=4096,
        )
        assert region.region_id == "test-region"
        assert region.start_address == 0x1000
        assert region.size == 4096

    def test_defaults(self):
        """MemoryRegion defaults are correct."""
        region = MemoryRegion(
            region_id="r1",
            start_address=0,
            size=1024,
        )
        assert region.encrypted is True
        assert region.integrity_hash == ""
        assert region.data is None

    def test_data_excluded_from_serialization(self):
        """The data field is excluded from model serialization."""
        region = MemoryRegion(
            region_id="r1",
            start_address=0,
            size=64,
            data=b"secret",
        )
        dumped = region.model_dump()
        assert "data" not in dumped


# ---------------------------------------------------------------------------
# ConfidentialExecutionResult tests
# ---------------------------------------------------------------------------


class TestConfidentialExecutionResult:
    """Tests for ConfidentialExecutionResult model."""

    def test_defaults(self):
        """Default result values are correct."""
        result = ConfidentialExecutionResult(success=True)
        assert result.success is True
        assert result.output is None
        assert result.error is None
        assert result.execution_time == 0.0
        assert result.platform == ConfidentialPlatform.SOFTWARE
        assert result.attestation_report == {}
        assert result.memory_regions_used == 0

    def test_with_output(self):
        """Result can carry output bytes."""
        result = ConfidentialExecutionResult(
            success=True,
            output=b"hello",
        )
        assert result.output == b"hello"

    def test_with_error(self):
        """Failed result carries an error message."""
        result = ConfidentialExecutionResult(
            success=False,
            error="something went wrong",
        )
        assert result.error == "something went wrong"
        assert result.success is False

    def test_with_platform(self):
        """Result can specify a platform."""
        result = ConfidentialExecutionResult(
            success=True,
            platform=ConfidentialPlatform.TDX,
        )
        assert result.platform == ConfidentialPlatform.TDX


# ---------------------------------------------------------------------------
# SoftwareConfidentialCompute tests
# ---------------------------------------------------------------------------


class TestSoftwareConfidentialCompute:
    """Tests for SoftwareConfidentialCompute backend."""

    async def test_initial_status(self):
        """New backend starts in uninitialized status."""
        backend = SoftwareConfidentialCompute()
        assert backend.status == "uninitialized"

    async def test_initialize(self):
        """Backend transitions to ready after initialization."""
        backend = SoftwareConfidentialCompute()
        await backend.initialize(ConfidentialConfig())
        assert backend.status == "ready"

    async def test_execute_returns_result(self):
        """Execute returns a successful result."""
        backend = SoftwareConfidentialCompute()
        await backend.initialize(ConfidentialConfig())

        result = await backend.execute(b"some_code")
        assert result.success is True
        assert result.output is not None
        assert len(result.output) == 32  # SHA-256 HMAC size
        assert result.execution_time > 0
        assert result.platform == ConfidentialPlatform.SOFTWARE

    async def test_execute_with_input_data(self):
        """Execute with different input data produces different output."""
        backend = SoftwareConfidentialCompute()
        await backend.initialize(ConfidentialConfig())

        result_a = await backend.execute(b"code", b"input_a")
        result_b = await backend.execute(b"code", b"input_b")

        assert result_a.output != result_b.output

    async def test_execute_deterministic(self):
        """Same code+input produces the same output."""
        backend = SoftwareConfidentialCompute()
        await backend.initialize(ConfidentialConfig())

        result_1 = await backend.execute(b"code", b"data")
        result_2 = await backend.execute(b"code", b"data")

        assert result_1.output == result_2.output

    async def test_execute_has_attestation_report(self):
        """Execute result includes an attestation report."""
        backend = SoftwareConfidentialCompute()
        await backend.initialize(ConfidentialConfig())

        result = await backend.execute(b"code")
        assert "platform" in result.attestation_report
        assert "measurements" in result.attestation_report

    async def test_allocate_memory(self):
        """Allocating a memory region returns valid metadata."""
        backend = SoftwareConfidentialCompute()
        await backend.initialize(ConfidentialConfig())

        region = await backend.allocate_memory(4096)
        assert region.region_id != ""
        assert region.size == 4096
        assert region.encrypted is True
        assert region.start_address >= 0x1000

    async def test_allocate_memory_with_custom_id(self):
        """Allocating with a custom region_id uses that ID."""
        backend = SoftwareConfidentialCompute()
        await backend.initialize(ConfidentialConfig())

        region = await backend.allocate_memory(1024, region_id="my-region")
        assert region.region_id == "my-region"

    async def test_write_read_roundtrip(self):
        """Data survives an encrypt-write then read-decrypt cycle."""
        backend = SoftwareConfidentialCompute()
        await backend.initialize(ConfidentialConfig())

        region = await backend.allocate_memory(1024)
        original = b"top secret data"
        await backend.write_memory(region.region_id, original)

        result = await backend.read_memory(region.region_id)
        assert result == original

    async def test_write_read_large_data(self):
        """Large data survives encrypt/decrypt roundtrip."""
        backend = SoftwareConfidentialCompute()
        await backend.initialize(ConfidentialConfig())

        region = await backend.allocate_memory(65536)
        original = os.urandom(8192)
        await backend.write_memory(region.region_id, original)

        result = await backend.read_memory(region.region_id)
        assert result == original

    async def test_integrity_verification(self):
        """Tampered ciphertext is detected by integrity check."""
        backend = SoftwareConfidentialCompute()
        await backend.initialize(ConfidentialConfig(integrity_check=True))

        region = await backend.allocate_memory(1024)
        await backend.write_memory(region.region_id, b"important")

        # Tamper with the stored ciphertext
        rid = region.region_id
        original_ct = backend._region_ciphertexts[rid]
        tampered = bytearray(original_ct)
        tampered[-1] ^= 0xFF
        backend._region_ciphertexts[rid] = bytes(tampered)
        # Also update integrity hash to NOT match
        backend._regions[rid].integrity_hash = "tampered"

        with pytest.raises(RuntimeError, match="Integrity check failed"):
            await backend.read_memory(rid)

    async def test_integrity_check_disabled(self):
        """With integrity_check=False, tampered hash does not raise."""
        backend = SoftwareConfidentialCompute()
        await backend.initialize(ConfidentialConfig(integrity_check=False))

        region = await backend.allocate_memory(1024)
        await backend.write_memory(region.region_id, b"data")

        # Tamper with integrity hash only (not ciphertext)
        backend._regions[region.region_id].integrity_hash = "bad"

        # Should not raise because integrity checking is off
        result = await backend.read_memory(region.region_id)
        assert result == b"data"

    async def test_free_memory(self):
        """Freed region cannot be read or written."""
        backend = SoftwareConfidentialCompute()
        await backend.initialize(ConfidentialConfig())

        region = await backend.allocate_memory(1024)
        await backend.write_memory(region.region_id, b"data")
        await backend.free_memory(region.region_id)

        with pytest.raises(KeyError, match="Unknown memory region"):
            await backend.read_memory(region.region_id)

        with pytest.raises(KeyError, match="Unknown memory region"):
            await backend.write_memory(region.region_id, b"new")

    async def test_free_unknown_region_raises(self):
        """Freeing an unknown region raises KeyError."""
        backend = SoftwareConfidentialCompute()
        await backend.initialize(ConfidentialConfig())

        with pytest.raises(KeyError, match="Unknown memory region"):
            await backend.free_memory("nonexistent")

    async def test_read_unwritten_region_raises(self):
        """Reading a region with no written data raises KeyError."""
        backend = SoftwareConfidentialCompute()
        await backend.initialize(ConfidentialConfig())

        region = await backend.allocate_memory(1024)

        with pytest.raises(KeyError, match="No data written"):
            await backend.read_memory(region.region_id)

    async def test_write_unknown_region_raises(self):
        """Writing to an unknown region raises KeyError."""
        backend = SoftwareConfidentialCompute()
        await backend.initialize(ConfidentialConfig())

        with pytest.raises(KeyError, match="Unknown memory region"):
            await backend.write_memory("nonexistent", b"data")

    async def test_get_attestation(self):
        """Attestation report contains expected fields."""
        backend = SoftwareConfidentialCompute()
        await backend.initialize(ConfidentialConfig())

        report = await backend.get_attestation()
        assert report["platform"] == "software"
        assert report["status"] == "ready"
        assert report["regions_count"] == 0
        assert report["backend"] == "software"
        assert "master_key_hash" in report["measurements"]
        assert "hmac_key_hash" in report["measurements"]

    async def test_destroy_lifecycle(self):
        """Destroying an instance transitions to destroyed status."""
        backend = SoftwareConfidentialCompute()
        await backend.initialize(ConfidentialConfig())
        assert backend.status == "ready"

        await backend.destroy()
        assert backend.status == "destroyed"

    async def test_execute_after_destroy_raises(self):
        """Executing on a destroyed backend raises RuntimeError."""
        backend = SoftwareConfidentialCompute()
        await backend.initialize(ConfidentialConfig())
        await backend.destroy()

        with pytest.raises(RuntimeError, match="destroyed"):
            await backend.execute(b"code")

    async def test_allocate_after_destroy_raises(self):
        """Allocating on a destroyed backend raises RuntimeError."""
        backend = SoftwareConfidentialCompute()
        await backend.initialize(ConfidentialConfig())
        await backend.destroy()

        with pytest.raises(RuntimeError, match="destroyed"):
            await backend.allocate_memory(1024)

    async def test_multiple_regions_independent(self):
        """Data in one region does not affect another."""
        backend = SoftwareConfidentialCompute()
        await backend.initialize(ConfidentialConfig())

        region_a = await backend.allocate_memory(1024)
        region_b = await backend.allocate_memory(1024)

        await backend.write_memory(region_a.region_id, b"data_a")
        await backend.write_memory(region_b.region_id, b"data_b")

        assert await backend.read_memory(region_a.region_id) == b"data_a"
        assert await backend.read_memory(region_b.region_id) == b"data_b"

    async def test_overwrite_memory(self):
        """Writing to a region overwrites previous data."""
        backend = SoftwareConfidentialCompute()
        await backend.initialize(ConfidentialConfig())

        region = await backend.allocate_memory(1024)
        await backend.write_memory(region.region_id, b"first")
        await backend.write_memory(region.region_id, b"second")

        result = await backend.read_memory(region.region_id)
        assert result == b"second"


# ---------------------------------------------------------------------------
# ConfidentialComputeManager tests
# ---------------------------------------------------------------------------


class TestConfidentialComputeManager:
    """Tests for ConfidentialComputeManager."""

    async def test_create_instance(self):
        """Manager creates an instance and returns an ID."""
        manager = ConfidentialComputeManager()
        instance_id = await manager.create_instance()
        assert isinstance(instance_id, str)
        assert len(instance_id) > 0

    async def test_list_instances(self):
        """Manager lists all created instances."""
        manager = ConfidentialComputeManager()
        id_a = await manager.create_instance()
        id_b = await manager.create_instance()

        instances = manager.list_instances()
        assert id_a in instances
        assert id_b in instances
        assert len(instances) == 2

    async def test_execute_in_instance(self):
        """Manager delegates execution to the correct instance."""
        manager = ConfidentialComputeManager()
        iid = await manager.create_instance()

        result = await manager.execute_in_instance(iid, b"code")
        assert result.success is True
        assert result.output is not None

    async def test_memory_operations(self):
        """Manager memory allocate/write/read/free roundtrip works."""
        manager = ConfidentialComputeManager()
        iid = await manager.create_instance()

        rid = await manager.allocate_memory(iid, 2048)
        assert isinstance(rid, str)

        original = b"confidential payload"
        await manager.write_memory(iid, rid, original)

        result = await manager.read_memory(iid, rid)
        assert result == original

        await manager.free_memory(iid, rid)

    async def test_destroy_instance(self):
        """Manager destroys the instance."""
        manager = ConfidentialComputeManager()
        iid = await manager.create_instance()

        await manager.destroy_instance(iid)
        # Instance should still be listed (but destroyed)
        assert iid in manager.list_instances()

    async def test_operations_on_destroyed_instance_fail(self):
        """Operations on a destroyed instance raise RuntimeError."""
        manager = ConfidentialComputeManager()
        iid = await manager.create_instance()
        await manager.destroy_instance(iid)

        with pytest.raises(RuntimeError, match="destroyed"):
            await manager.execute_in_instance(iid, b"code")

        with pytest.raises(RuntimeError, match="destroyed"):
            await manager.allocate_memory(iid, 1024)

        with pytest.raises(RuntimeError, match="destroyed"):
            await manager.write_memory(iid, "region", b"data")

        with pytest.raises(RuntimeError, match="destroyed"):
            await manager.read_memory(iid, "region")

        with pytest.raises(RuntimeError, match="destroyed"):
            await manager.free_memory(iid, "region")

    async def test_operations_on_unknown_instance_fail(self):
        """Operations on an unknown instance raise KeyError."""
        manager = ConfidentialComputeManager()

        with pytest.raises(KeyError, match="Unknown instance"):
            await manager.execute_in_instance("nonexistent", b"code")

        with pytest.raises(KeyError, match="Unknown instance"):
            await manager.allocate_memory("nonexistent", 1024)

        with pytest.raises(KeyError, match="Unknown instance"):
            await manager.write_memory("nonexistent", "r", b"data")

        with pytest.raises(KeyError, match="Unknown instance"):
            await manager.read_memory("nonexistent", "r")

        with pytest.raises(KeyError, match="Unknown instance"):
            await manager.free_memory("nonexistent", "r")

        with pytest.raises(KeyError, match="Unknown instance"):
            await manager.destroy_instance("nonexistent")

    async def test_allocate_with_custom_region_id(self):
        """Manager passes custom region_id to the backend."""
        manager = ConfidentialComputeManager()
        iid = await manager.create_instance()

        rid = await manager.allocate_memory(iid, 512, region_id="custom-region")
        assert rid == "custom-region"

    async def test_create_with_custom_config(self):
        """Manager respects the provided config."""
        manager = ConfidentialComputeManager()
        config = ConfidentialConfig(
            memory_size_mb=128,
            integrity_check=False,
        )
        iid = await manager.create_instance(config)

        # Verify instance was created and is functional
        result = await manager.execute_in_instance(iid, b"test")
        assert result.success is True
