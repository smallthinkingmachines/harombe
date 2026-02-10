"""Tests for the Multi-Party Computation (MPC) module."""

import pytest

from harombe.security.distributed.mpc import (
    DEFAULT_PRIME,
    MPCConfig,
    MPCEngine,
    MPCOperation,
    MPCParty,
    MPCProtocol,
    SecretShare,
    SecureComparison,
    ThresholdDecryption,
)

# ---------------------------------------------------------------------------
# Enum tests
# ---------------------------------------------------------------------------


class TestMPCProtocol:
    def test_additive_value(self):
        assert MPCProtocol.ADDITIVE == "additive"

    def test_beaver_triple_value(self):
        assert MPCProtocol.BEAVER_TRIPLE == "beaver_triple"

    def test_threshold_value(self):
        assert MPCProtocol.THRESHOLD == "threshold"


class TestMPCOperation:
    def test_add_value(self):
        assert MPCOperation.ADD == "add"

    def test_multiply_value(self):
        assert MPCOperation.MULTIPLY == "multiply"

    def test_compare_value(self):
        assert MPCOperation.COMPARE == "compare"

    def test_equality_value(self):
        assert MPCOperation.EQUALITY == "equality"

    def test_threshold_decrypt_value(self):
        assert MPCOperation.THRESHOLD_DECRYPT == "threshold_decrypt"


# ---------------------------------------------------------------------------
# Model tests
# ---------------------------------------------------------------------------


class TestMPCParty:
    def test_creation(self):
        party = MPCParty(party_id="p1")
        assert party.party_id == "p1"
        assert party.name == ""
        assert party.share == 0
        assert party.is_active is True

    def test_creation_with_fields(self):
        party = MPCParty(party_id="p2", name="Alice", share=42, is_active=False)
        assert party.party_id == "p2"
        assert party.name == "Alice"
        assert party.share == 42
        assert party.is_active is False


class TestMPCConfig:
    def test_defaults(self):
        config = MPCConfig()
        assert config.num_parties == 3
        assert config.threshold == 2
        assert config.prime is None
        assert config.protocol == MPCProtocol.ADDITIVE

    def test_custom(self):
        config = MPCConfig(
            num_parties=5,
            threshold=3,
            prime=997,
            protocol=MPCProtocol.BEAVER_TRIPLE,
        )
        assert config.num_parties == 5
        assert config.threshold == 3
        assert config.prime == 997
        assert config.protocol == MPCProtocol.BEAVER_TRIPLE


class TestSecretShare:
    def test_creation(self):
        share = SecretShare(party_id="party_0", value=123, share_index=0)
        assert share.party_id == "party_0"
        assert share.value == 123
        assert share.share_index == 0


# ---------------------------------------------------------------------------
# MPCEngine tests
# ---------------------------------------------------------------------------


class TestMPCEngineSharing:
    def test_share_secret_count(self):
        engine = MPCEngine()
        shares = engine.share_secret(42)
        assert len(shares) == 3

    def test_reconstruct_recovers_secret(self):
        engine = MPCEngine()
        shares = engine.share_secret(42)
        assert engine.reconstruct(shares) == 42

    def test_round_trip_zero(self):
        engine = MPCEngine()
        shares = engine.share_secret(0)
        assert engine.reconstruct(shares) == 0

    def test_round_trip_one(self):
        engine = MPCEngine()
        shares = engine.share_secret(1)
        assert engine.reconstruct(shares) == 1

    def test_round_trip_large_value(self):
        engine = MPCEngine()
        large_val = DEFAULT_PRIME - 1
        shares = engine.share_secret(large_val)
        assert engine.reconstruct(shares) == large_val

    def test_round_trip_various_values(self):
        engine = MPCEngine()
        for val in [0, 1, 7, 100, 999, 123456789, 2**128]:
            shares = engine.share_secret(val)
            assert engine.reconstruct(shares) == val

    def test_shares_are_different(self):
        """Individual shares should generally differ from the secret."""
        engine = MPCEngine()
        shares = engine.share_secret(42)
        # With overwhelming probability, not all shares equal the secret
        values = {s.value for s in shares}
        assert len(values) > 1

    def test_share_indices_sequential(self):
        engine = MPCEngine()
        shares = engine.share_secret(42)
        for i, s in enumerate(shares):
            assert s.share_index == i
            assert s.party_id == f"party_{i}"


class TestMPCEnginePartyCount:
    def test_two_parties(self):
        config = MPCConfig(num_parties=2)
        engine = MPCEngine(config)
        shares = engine.share_secret(100)
        assert len(shares) == 2
        assert engine.reconstruct(shares) == 100

    def test_three_parties(self):
        config = MPCConfig(num_parties=3)
        engine = MPCEngine(config)
        shares = engine.share_secret(200)
        assert len(shares) == 3
        assert engine.reconstruct(shares) == 200

    def test_five_parties(self):
        config = MPCConfig(num_parties=5)
        engine = MPCEngine(config)
        shares = engine.share_secret(300)
        assert len(shares) == 5
        assert engine.reconstruct(shares) == 300


class TestMPCEngineAddition:
    def test_add_shares(self):
        engine = MPCEngine()
        shares_a = engine.share_secret(10)
        shares_b = engine.share_secret(20)
        shares_sum = engine.add_shares(shares_a, shares_b)
        assert engine.reconstruct(shares_sum) == 30

    def test_add_shares_with_zero(self):
        engine = MPCEngine()
        shares_a = engine.share_secret(42)
        shares_b = engine.share_secret(0)
        shares_sum = engine.add_shares(shares_a, shares_b)
        assert engine.reconstruct(shares_sum) == 42

    def test_add_shares_large_values(self):
        engine = MPCEngine()
        a = 2**128
        b = 2**128
        shares_a = engine.share_secret(a)
        shares_b = engine.share_secret(b)
        shares_sum = engine.add_shares(shares_a, shares_b)
        assert engine.reconstruct(shares_sum) == (a + b) % DEFAULT_PRIME

    def test_add_shares_mismatched_length_raises(self):
        engine = MPCEngine()
        shares_a = engine.share_secret(10)
        config2 = MPCConfig(num_parties=5)
        engine2 = MPCEngine(config2)
        shares_b = engine2.share_secret(20)
        with pytest.raises(ValueError, match="Share count mismatch"):
            engine.add_shares(shares_a, shares_b)


class TestMPCEngineMultiplication:
    def test_multiply_shares(self):
        engine = MPCEngine()
        shares_a = engine.share_secret(6)
        shares_b = engine.share_secret(7)
        shares_prod = engine.multiply_shares(shares_a, shares_b)
        assert engine.reconstruct(shares_prod) == 42

    def test_multiply_by_zero(self):
        engine = MPCEngine()
        shares_a = engine.share_secret(100)
        shares_b = engine.share_secret(0)
        shares_prod = engine.multiply_shares(shares_a, shares_b)
        assert engine.reconstruct(shares_prod) == 0

    def test_multiply_by_one(self):
        engine = MPCEngine()
        shares_a = engine.share_secret(99)
        shares_b = engine.share_secret(1)
        shares_prod = engine.multiply_shares(shares_a, shares_b)
        assert engine.reconstruct(shares_prod) == 99

    def test_multiply_shares_mismatched_length_raises(self):
        engine = MPCEngine()
        shares_a = engine.share_secret(10)
        config2 = MPCConfig(num_parties=5)
        engine2 = MPCEngine(config2)
        shares_b = engine2.share_secret(20)
        with pytest.raises(ValueError, match="Share count mismatch"):
            engine.multiply_shares(shares_a, shares_b)


class TestMPCEngineScalarMultiply:
    def test_scalar_multiply(self):
        engine = MPCEngine()
        shares = engine.share_secret(10)
        scaled = engine.scalar_multiply(shares, 5)
        assert engine.reconstruct(scaled) == 50

    def test_scalar_multiply_by_zero(self):
        engine = MPCEngine()
        shares = engine.share_secret(42)
        scaled = engine.scalar_multiply(shares, 0)
        assert engine.reconstruct(scaled) == 0

    def test_scalar_multiply_by_one(self):
        engine = MPCEngine()
        shares = engine.share_secret(77)
        scaled = engine.scalar_multiply(shares, 1)
        assert engine.reconstruct(scaled) == 77


class TestBeaverTriple:
    def test_generate_beaver_triple_product_relation(self):
        engine = MPCEngine()
        triple_a, triple_b, triple_c = engine.generate_beaver_triple()
        a = engine.reconstruct(triple_a)
        b = engine.reconstruct(triple_b)
        c = engine.reconstruct(triple_c)
        assert c == (a * b) % engine._prime

    def test_beaver_triple_share_count(self):
        engine = MPCEngine()
        triple_a, triple_b, triple_c = engine.generate_beaver_triple()
        assert len(triple_a) == 3
        assert len(triple_b) == 3
        assert len(triple_c) == 3


# ---------------------------------------------------------------------------
# SecureComparison tests
# ---------------------------------------------------------------------------


class TestSecureComparison:
    def test_compare_greater(self):
        engine = MPCEngine()
        cmp = SecureComparison(engine)
        shares_a = engine.share_secret(10)
        shares_b = engine.share_secret(5)
        result = cmp.compare(shares_a, shares_b)
        assert engine.reconstruct(result) == 1

    def test_compare_less(self):
        engine = MPCEngine()
        cmp = SecureComparison(engine)
        shares_a = engine.share_secret(5)
        shares_b = engine.share_secret(10)
        result = cmp.compare(shares_a, shares_b)
        assert engine.reconstruct(result) == 0

    def test_compare_equal(self):
        engine = MPCEngine()
        cmp = SecureComparison(engine)
        shares_a = engine.share_secret(7)
        shares_b = engine.share_secret(7)
        result = cmp.compare(shares_a, shares_b)
        assert engine.reconstruct(result) == 0

    def test_equality_same(self):
        engine = MPCEngine()
        cmp = SecureComparison(engine)
        shares_a = engine.share_secret(42)
        shares_b = engine.share_secret(42)
        result = cmp.equality(shares_a, shares_b)
        assert engine.reconstruct(result) == 1

    def test_equality_different(self):
        engine = MPCEngine()
        cmp = SecureComparison(engine)
        shares_a = engine.share_secret(42)
        shares_b = engine.share_secret(99)
        result = cmp.equality(shares_a, shares_b)
        assert engine.reconstruct(result) == 0


# ---------------------------------------------------------------------------
# ThresholdDecryption tests
# ---------------------------------------------------------------------------


class TestThresholdDecryption:
    def test_generate_key_shares(self):
        engine = MPCEngine()
        td = ThresholdDecryption(engine)
        key, key_shares = td.generate_key_shares()
        assert isinstance(key, int)
        assert len(key_shares) == 3
        assert engine.reconstruct(key_shares) == key

    def test_encrypt_decrypt_round_trip(self):
        engine = MPCEngine()
        td = ThresholdDecryption(engine)
        key, key_shares = td.generate_key_shares()

        plaintext = b"hello, MPC world!"
        ciphertext = td.encrypt(plaintext, key)

        # Ciphertext should differ from plaintext
        assert ciphertext != plaintext

        # Collect partial decryptions
        partials = [td.partial_decrypt(ciphertext, s) for s in key_shares]

        # Combine and recover
        recovered = td.combine_partial_decryptions(partials, ciphertext)
        assert recovered == plaintext

    def test_encrypt_decrypt_empty(self):
        engine = MPCEngine()
        td = ThresholdDecryption(engine)
        key, key_shares = td.generate_key_shares()

        plaintext = b""
        ciphertext = td.encrypt(plaintext, key)
        partials = [td.partial_decrypt(ciphertext, s) for s in key_shares]
        recovered = td.combine_partial_decryptions(partials, ciphertext)
        assert recovered == plaintext

    def test_encrypt_decrypt_binary_data(self):
        engine = MPCEngine()
        td = ThresholdDecryption(engine)
        key, key_shares = td.generate_key_shares()

        plaintext = bytes(range(256))
        ciphertext = td.encrypt(plaintext, key)
        partials = [td.partial_decrypt(ciphertext, s) for s in key_shares]
        recovered = td.combine_partial_decryptions(partials, ciphertext)
        assert recovered == plaintext

    def test_wrong_key_fails(self):
        engine = MPCEngine()
        td = ThresholdDecryption(engine)
        key, _ = td.generate_key_shares()
        _, wrong_shares = td.generate_key_shares()

        plaintext = b"secret data"
        ciphertext = td.encrypt(plaintext, key)
        wrong_partials = [td.partial_decrypt(ciphertext, s) for s in wrong_shares]
        recovered = td.combine_partial_decryptions(wrong_partials, ciphertext)
        assert recovered != plaintext


# ---------------------------------------------------------------------------
# Custom prime tests
# ---------------------------------------------------------------------------


class TestCustomPrime:
    def test_small_prime(self):
        config = MPCConfig(prime=997)
        engine = MPCEngine(config)
        shares = engine.share_secret(500)
        assert engine.reconstruct(shares) == 500

    def test_operations_with_small_prime(self):
        config = MPCConfig(prime=997)
        engine = MPCEngine(config)
        shares_a = engine.share_secret(100)
        shares_b = engine.share_secret(200)

        # Addition
        shares_sum = engine.add_shares(shares_a, shares_b)
        assert engine.reconstruct(shares_sum) == 300

        # Multiplication
        shares_a2 = engine.share_secret(10)
        shares_b2 = engine.share_secret(20)
        shares_prod = engine.multiply_shares(shares_a2, shares_b2)
        assert engine.reconstruct(shares_prod) == 200
