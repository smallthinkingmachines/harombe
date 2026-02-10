"""Tests for Shamir's Secret Sharing with Feldman verification."""

import pytest

from harombe.security.distributed.shamir import (
    ShamirConfig,
    ShamirSecretSharing,
    ShamirSplitResult,
    ShamirVaultBackend,
    Share,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def default_sss():
    """Default 3-of-5 ShamirSecretSharing instance."""
    return ShamirSecretSharing()


@pytest.fixture
def sss_2_of_3():
    """2-of-3 ShamirSecretSharing instance."""
    return ShamirSecretSharing(ShamirConfig(threshold=2, total_shares=3))


@pytest.fixture
def sss_5_of_10():
    """5-of-10 ShamirSecretSharing instance."""
    return ShamirSecretSharing(ShamirConfig(threshold=5, total_shares=10))


@pytest.fixture
def vault():
    """ShamirVaultBackend with default config."""
    return ShamirVaultBackend()


# ---------------------------------------------------------------------------
# Share model
# ---------------------------------------------------------------------------


class TestShareModel:
    """Tests for the Share Pydantic model."""

    def test_share_creation(self):
        share = Share(share_id=1, value=42, threshold=3, total_shares=5)
        assert share.share_id == 1
        assert share.value == 42
        assert share.threshold == 3
        assert share.total_shares == 5
        assert share.commitment == []

    def test_share_with_commitment(self):
        share = Share(
            share_id=2,
            value=100,
            threshold=3,
            total_shares=5,
            commitment=[10, 20, 30],
        )
        assert share.commitment == [10, 20, 30]


# ---------------------------------------------------------------------------
# ShamirConfig model
# ---------------------------------------------------------------------------


class TestShamirConfig:
    """Tests for the ShamirConfig Pydantic model."""

    def test_defaults(self):
        config = ShamirConfig()
        assert config.threshold == 3
        assert config.total_shares == 5
        assert config.prime is None
        assert config.verify is True

    def test_custom_values(self):
        config = ShamirConfig(threshold=5, total_shares=10, prime=104729, verify=False)
        assert config.threshold == 5
        assert config.total_shares == 10
        assert config.prime == 104729
        assert config.verify is False


# ---------------------------------------------------------------------------
# ShamirSecretSharing -- core operations
# ---------------------------------------------------------------------------


class TestShamirSplitCombine:
    """Tests for split and combine operations."""

    def test_basic_round_trip(self, default_sss):
        secret = b"hello world"
        result = default_sss.split(secret)
        recovered = default_sss.combine(result.shares)
        assert recovered == secret

    def test_split_result_structure(self, default_sss):
        result = default_sss.split(b"test")
        assert isinstance(result, ShamirSplitResult)
        assert len(result.shares) == 5
        assert result.threshold == 3
        assert result.total_shares == 5
        # threshold coefficients => threshold commitments
        assert len(result.commitments) == 3

    def test_2_of_3(self, sss_2_of_3):
        secret = b"two-of-three"
        result = sss_2_of_3.split(secret)
        recovered = sss_2_of_3.combine(result.shares[:2])
        assert recovered == secret

    def test_3_of_5(self, default_sss):
        secret = b"three-of-five"
        result = default_sss.split(secret)
        recovered = default_sss.combine(result.shares[:3])
        assert recovered == secret

    def test_5_of_10(self, sss_5_of_10):
        secret = b"five-of-ten"
        result = sss_5_of_10.split(secret)
        recovered = sss_5_of_10.combine(result.shares[:5])
        assert recovered == secret

    def test_exact_threshold_succeeds(self, default_sss):
        secret = b"exact threshold"
        result = default_sss.split(secret)
        recovered = default_sss.combine(result.shares[:3])
        assert recovered == secret

    def test_more_than_threshold_succeeds(self, default_sss):
        secret = b"more than threshold"
        result = default_sss.split(secret)
        recovered = default_sss.combine(result.shares[:4])
        assert recovered == secret

    def test_all_shares_succeeds(self, default_sss):
        secret = b"all shares"
        result = default_sss.split(secret)
        recovered = default_sss.combine(result.shares)
        assert recovered == secret

    def test_fewer_than_threshold_fails(self, default_sss):
        result = default_sss.split(b"secret")
        with pytest.raises(ValueError, match="Need at least 3 shares"):
            default_sss.combine(result.shares[:2])

    def test_no_shares_fails(self, default_sss):
        with pytest.raises(ValueError, match="No shares provided"):
            default_sss.combine([])

    def test_different_subsets_same_secret(self, default_sss):
        secret = b"subset consistency"
        result = default_sss.split(secret)
        shares = result.shares

        subsets = [
            [shares[0], shares[1], shares[2]],
            [shares[0], shares[2], shares[4]],
            [shares[1], shares[3], shares[4]],
            [shares[2], shares[3], shares[4]],
        ]
        for subset in subsets:
            recovered = default_sss.combine(subset)
            assert recovered == secret

    def test_various_byte_lengths(self, default_sss):
        for length in [1, 2, 7, 16, 32, 64, 128]:
            secret = bytes(range(length % 256)) * (length // 256 + 1)
            secret = secret[:length]
            result = default_sss.split(secret)
            recovered = default_sss.combine(result.shares[:3])
            assert recovered == secret, f"Failed for length {length}"

    def test_empty_secret(self, default_sss):
        secret = b""
        result = default_sss.split(secret)
        recovered = default_sss.combine(result.shares)
        assert recovered == secret

    def test_large_secret_200_bytes(self, default_sss):
        # 200 bytes -- near the 255-byte limit of the 2047-bit field
        secret = bytes(range(200))
        result = default_sss.split(secret)
        recovered = default_sss.combine(result.shares[:3])
        assert recovered == secret

    def test_max_size_secret(self, default_sss):
        # Exactly 255 bytes (maximum for the 2047-bit field with sentinel)
        secret = bytes(range(256))[:255]
        result = default_sss.split(secret)
        recovered = default_sss.combine(result.shares[:3])
        assert recovered == secret

    def test_leading_zero_bytes_preserved(self, default_sss):
        secret = b"\x00\x00\x00ABC"
        result = default_sss.split(secret)
        recovered = default_sss.combine(result.shares[:3])
        assert recovered == secret

    def test_all_zero_bytes(self, default_sss):
        secret = b"\x00" * 10
        result = default_sss.split(secret)
        recovered = default_sss.combine(result.shares[:3])
        assert recovered == secret


# ---------------------------------------------------------------------------
# Feldman verification
# ---------------------------------------------------------------------------


class TestFeldmanVerification:
    """Tests for Feldman's Verifiable Secret Sharing."""

    def test_valid_shares_pass(self, default_sss):
        result = default_sss.split(b"verify me")
        for share in result.shares:
            assert default_sss.verify_share(share, result.commitments)

    def test_tampered_share_fails(self, default_sss):
        result = default_sss.split(b"tamper test")
        tampered = Share(
            share_id=result.shares[0].share_id,
            value=result.shares[0].value + 1,
            threshold=result.shares[0].threshold,
            total_shares=result.shares[0].total_shares,
            commitment=result.shares[0].commitment,
        )
        assert not default_sss.verify_share(tampered, result.commitments)

    def test_no_commitments_returns_false(self, default_sss):
        result = default_sss.split(b"no commitments")
        assert not default_sss.verify_share(result.shares[0], [])

    def test_verification_disabled(self):
        sss = ShamirSecretSharing(ShamirConfig(verify=False))
        result = sss.split(b"no verify")
        assert result.commitments == []
        for share in result.shares:
            assert share.commitment == []

    def test_verification_all_share_ids(self, default_sss):
        """Verify each share individually (covers share_id > 1)."""
        result = default_sss.split(b"check all ids")
        for share in result.shares:
            assert default_sss.verify_share(
                share, result.commitments
            ), f"Share {share.share_id} failed verification"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


class TestInternalHelpers:
    """Tests for private helper methods."""

    def test_polynomial_evaluation(self, default_sss):
        # P(x) = 5 + 3x + 2x^2  at x=2:  5 + 6 + 8 = 19
        coeffs = [5, 3, 2]
        p = default_sss.prime
        result = default_sss._evaluate_polynomial(coeffs, 2)
        assert result == 19 % p

    def test_polynomial_evaluation_constant(self, default_sss):
        assert default_sss._evaluate_polynomial([42], 0) == 42
        assert default_sss._evaluate_polynomial([42], 99) == 42

    def test_lagrange_interpolation_known(self, default_sss):
        # P(x) = 7 + 2x  =>  P(1) = 9, P(2) = 11
        points = [(1, 9), (2, 11)]
        secret = default_sss._lagrange_interpolation(points)
        assert secret == 7

    def test_lagrange_interpolation_quadratic(self, default_sss):
        # P(x) = 1 + x + x^2  =>  P(1)=3, P(2)=7, P(3)=13
        points = [(1, 3), (2, 7), (3, 13)]
        secret = default_sss._lagrange_interpolation(points)
        assert secret == 1

    def test_mod_inverse(self):
        p = ShamirSecretSharing.SAFE_PRIME
        inv = ShamirSecretSharing._mod_inverse(3, p)
        assert (3 * inv) % p == 1

    def test_mod_inverse_various(self):
        p = 104729
        for a in [2, 7, 100, 104728]:
            inv = ShamirSecretSharing._mod_inverse(a, p)
            assert (a * inv) % p == 1

    def test_bytes_to_int_round_trip(self, default_sss):
        data = b"\x00\x01\x02\xff"
        val = default_sss._bytes_to_int(data)
        recovered = default_sss._int_to_bytes(val)
        assert recovered == data

    def test_bytes_to_int_empty(self, default_sss):
        val = default_sss._bytes_to_int(b"")
        assert val == 1  # sentinel 0x01 only
        recovered = default_sss._int_to_bytes(val)
        assert recovered == b""

    def test_int_to_bytes_zero(self, default_sss):
        assert default_sss._int_to_bytes(0) == b""


# ---------------------------------------------------------------------------
# Configuration validation
# ---------------------------------------------------------------------------


class TestConfigValidation:
    """Tests for configuration edge cases."""

    def test_threshold_below_2_raises(self):
        with pytest.raises(ValueError, match="Threshold must be at least 2"):
            ShamirSecretSharing(ShamirConfig(threshold=1, total_shares=3))

    def test_total_less_than_threshold_raises(self):
        with pytest.raises(ValueError, match="total_shares must be >= threshold"):
            ShamirSecretSharing(ShamirConfig(threshold=5, total_shares=3))

    def test_custom_prime(self):
        # Use a prime large enough for sentinel + 1-byte secret
        # sentinel (0x01) + 0xAB = 0x01AB = 427, needs prime > 427
        small_prime = 104729
        sss = ShamirSecretSharing(
            ShamirConfig(
                threshold=2,
                total_shares=3,
                prime=small_prime,
                verify=False,
            )
        )
        secret = b"\xab"  # sentinel + secret = 0x01AB = 427 < 104729
        result = sss.split(secret)
        recovered = sss.combine(result.shares[:2])
        assert recovered == secret

    def test_different_primes_produce_valid_results(self):
        # Each (prime, secret) pair chosen so sentinel+secret < prime
        cases = [
            (104729, b"\x42"),  # 0x0142 = 322 < 104729
            ((2**127) - 1, b"prime-test"),  # ~11 bytes < 2^127
            ((2**521) - 1, b"prime-test"),  # ~11 bytes < 2^521
        ]
        for p, secret in cases:
            sss = ShamirSecretSharing(ShamirConfig(threshold=2, total_shares=3, prime=p))
            result = sss.split(secret)
            recovered = sss.combine(result.shares)
            assert recovered == secret, f"Failed with prime {p}"


# ---------------------------------------------------------------------------
# ShamirVaultBackend -- async VaultBackend interface
# ---------------------------------------------------------------------------


class TestShamirVaultBackend:
    """Tests for ShamirVaultBackend."""

    async def test_set_and_get_secret(self, vault):
        await vault.set_secret("db/password", "s3cret!")
        value = await vault.get_secret("db/password")
        assert value == "s3cret!"

    async def test_get_nonexistent_returns_none(self, vault):
        value = await vault.get_secret("does-not-exist")
        assert value is None

    async def test_delete_secret(self, vault):
        await vault.set_secret("tmp/key", "value")
        await vault.delete_secret("tmp/key")
        assert await vault.get_secret("tmp/key") is None

    async def test_delete_nonexistent_is_noop(self, vault):
        await vault.delete_secret("nonexistent")

    async def test_list_secrets(self, vault):
        await vault.set_secret("a", "1")
        await vault.set_secret("b", "2")
        await vault.set_secret("c", "3")
        keys = await vault.list_secrets()
        assert sorted(keys) == ["a", "b", "c"]

    async def test_list_secrets_with_prefix(self, vault):
        await vault.set_secret("db/host", "localhost")
        await vault.set_secret("db/port", "5432")
        await vault.set_secret("api/key", "abc")
        db_keys = await vault.list_secrets(prefix="db/")
        assert sorted(db_keys) == ["db/host", "db/port"]

    async def test_list_secrets_empty(self, vault):
        keys = await vault.list_secrets()
        assert keys == []

    async def test_rotate_secret(self, vault):
        await vault.set_secret("rotate-me", "original-value")
        old_shares = list(vault._secrets["rotate-me"].shares)

        await vault.rotate_secret("rotate-me")

        value = await vault.get_secret("rotate-me")
        assert value == "original-value"

        new_shares = vault._secrets["rotate-me"].shares
        old_values = {s.value for s in old_shares}
        new_values = {s.value for s in new_shares}
        assert old_values != new_values

    async def test_rotate_nonexistent_raises(self, vault):
        with pytest.raises(ValueError, match="not found"):
            await vault.rotate_secret("missing")

    async def test_unicode_secret(self, vault):
        await vault.set_secret("emoji", "hello-world-123")
        assert await vault.get_secret("emoji") == "hello-world-123"

    async def test_overwrite_secret(self, vault):
        await vault.set_secret("key", "v1")
        await vault.set_secret("key", "v2")
        assert await vault.get_secret("key") == "v2"
