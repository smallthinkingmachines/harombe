"""Tests for Zero-Knowledge Proof primitives."""

import pytest

from harombe.security.zkp.primitives import (
    PedersenCommitment,
    Proof,
    ProofType,
    RangeProof,
    SchnorrProof,
    VerificationResult,
    ZKPContext,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def ctx():
    """Create a ZKPContext for tests."""
    return ZKPContext()


# ---------------------------------------------------------------------------
# ProofType enum
# ---------------------------------------------------------------------------


def test_proof_type_schnorr():
    """ProofType.SCHNORR has the expected string value."""
    assert ProofType.SCHNORR == "schnorr"


def test_proof_type_pedersen():
    """ProofType.PEDERSEN_COMMITMENT has the expected string value."""
    assert ProofType.PEDERSEN_COMMITMENT == "pedersen_commitment"


def test_proof_type_range():
    """ProofType.RANGE_PROOF has the expected string value."""
    assert ProofType.RANGE_PROOF == "range_proof"


def test_proof_type_equality():
    """ProofType.EQUALITY has the expected string value."""
    assert ProofType.EQUALITY == "equality"


# ---------------------------------------------------------------------------
# ZKPContext creation and key generation
# ---------------------------------------------------------------------------


def test_zkp_context_creation(ctx):
    """ZKPContext can be instantiated with correct curve order."""
    expected_order = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    assert expected_order == ctx.CURVE_ORDER


def test_zkp_context_generate_private_key(ctx):
    """generate_private_key returns a valid EC private key."""
    key = ctx.generate_private_key()
    assert key.key_size == 256
    assert key.private_numbers().private_value > 0


def test_zkp_context_get_public_point(ctx):
    """get_public_point returns a public key for a private key."""
    priv = ctx.generate_private_key()
    pub = ctx.get_public_point(priv)
    nums = pub.public_numbers()
    assert nums.x > 0 and nums.y > 0


# ---------------------------------------------------------------------------
# ZKPContext hash_to_scalar
# ---------------------------------------------------------------------------


def test_hash_to_scalar_deterministic(ctx):
    """hash_to_scalar is deterministic for the same input."""
    s1 = ctx.hash_to_scalar(b"hello")
    s2 = ctx.hash_to_scalar(b"hello")
    assert s1 == s2


def test_hash_to_scalar_different_inputs(ctx):
    """hash_to_scalar produces different values for different inputs."""
    s1 = ctx.hash_to_scalar(b"hello")
    s2 = ctx.hash_to_scalar(b"world")
    assert s1 != s2


def test_hash_to_scalar_within_range(ctx):
    """hash_to_scalar returns a value in [1, n-1]."""
    s = ctx.hash_to_scalar(b"test data")
    assert 1 <= s < ctx.CURVE_ORDER


# ---------------------------------------------------------------------------
# ZKPContext point_to_bytes / scalar_to_bytes
# ---------------------------------------------------------------------------


def test_point_to_bytes_compressed(ctx):
    """point_to_bytes returns 33-byte compressed point."""
    priv = ctx.generate_private_key()
    pub = priv.public_key()
    encoded = ctx.point_to_bytes(pub)
    assert len(encoded) == 33
    # Compressed point starts with 0x02 or 0x03
    assert encoded[0] in (0x02, 0x03)


def test_scalar_to_bytes_length(ctx):
    """scalar_to_bytes returns exactly 32 bytes."""
    s = ctx.hash_to_scalar(b"some input")
    encoded = ctx.scalar_to_bytes(s)
    assert len(encoded) == 32


def test_scalar_to_bytes_round_trip(ctx):
    """scalar_to_bytes output can be decoded back to original value."""
    original = ctx.hash_to_scalar(b"round trip")
    encoded = ctx.scalar_to_bytes(original)
    decoded = int.from_bytes(encoded, "big")
    assert decoded == original


# ---------------------------------------------------------------------------
# SchnorrProof - generate and verify
# ---------------------------------------------------------------------------


def test_schnorr_generate_returns_proof(ctx):
    """SchnorrProof.generate returns a Proof with correct type."""
    proof = SchnorrProof.generate(42, ctx)
    assert isinstance(proof, Proof)
    assert proof.proof_type == ProofType.SCHNORR


def test_schnorr_valid_proof(ctx):
    """A legitimately generated Schnorr proof verifies successfully."""
    secret = 12345
    proof = SchnorrProof.generate(secret, ctx)
    result = SchnorrProof.verify(proof, ctx)
    assert result.valid is True
    assert result.proof_type == ProofType.SCHNORR
    assert result.error is None


def test_schnorr_proof_has_fields(ctx):
    """Schnorr proof has all expected non-None fields."""
    proof = SchnorrProof.generate(99, ctx)
    assert proof.commitment is not None and len(proof.commitment) == 33
    assert proof.challenge is not None and len(proof.challenge) == 32
    assert proof.response is not None and len(proof.response) == 32
    assert proof.public_input is not None and len(proof.public_input) == 33


def test_schnorr_verify_wrong_public_key(ctx):
    """Schnorr verify fails when the public key is replaced."""
    secret = 100
    proof = SchnorrProof.generate(secret, ctx)

    # Replace public_input with a different public key
    different_key = ctx.generate_private_key().public_key()
    proof.public_input = ctx.point_to_bytes(different_key)

    result = SchnorrProof.verify(proof, ctx)
    assert result.valid is False


def test_schnorr_verify_tampered_challenge(ctx):
    """Schnorr verify fails when the challenge is tampered."""
    proof = SchnorrProof.generate(200, ctx)

    # Flip a byte in the challenge
    tampered = bytearray(proof.challenge)
    tampered[0] ^= 0xFF
    proof.challenge = bytes(tampered)

    result = SchnorrProof.verify(proof, ctx)
    assert result.valid is False
    assert "challenge" in (result.error or "").lower()


def test_schnorr_verify_tampered_response(ctx):
    """Schnorr verify fails when the response is tampered."""
    proof = SchnorrProof.generate(300, ctx)

    # Flip a byte in the response
    tampered = bytearray(proof.response)
    tampered[-1] ^= 0xFF
    proof.response = bytes(tampered)

    result = SchnorrProof.verify(proof, ctx)
    assert result.valid is False


def test_schnorr_multiple_proofs_same_secret(ctx):
    """Multiple proofs for the same secret all verify but are distinct."""
    secret = 777
    proofs = [SchnorrProof.generate(secret, ctx) for _ in range(3)]

    # All should verify
    for p in proofs:
        assert SchnorrProof.verify(p, ctx).valid is True

    # Commitments (random nonces) should differ
    commitments = {p.commitment for p in proofs}
    assert len(commitments) == 3


def test_schnorr_different_secrets_different_proofs(ctx):
    """Proofs for different secrets have different public inputs."""
    p1 = SchnorrProof.generate(111, ctx)
    p2 = SchnorrProof.generate(222, ctx)

    # Different secrets -> different public keys
    assert p1.public_input != p2.public_input


def test_schnorr_large_secret(ctx):
    """Schnorr proof works with a large secret near the curve order."""
    large_secret = ctx.CURVE_ORDER - 2
    proof = SchnorrProof.generate(large_secret, ctx)
    result = SchnorrProof.verify(proof, ctx)
    assert result.valid is True


def test_schnorr_verify_wrong_proof_type(ctx):
    """Schnorr verify rejects proof with wrong proof_type."""
    proof = SchnorrProof.generate(42, ctx)
    proof.proof_type = ProofType.PEDERSEN_COMMITMENT

    result = SchnorrProof.verify(proof, ctx)
    assert result.valid is False
    assert "SCHNORR" in (result.error or "")


def test_schnorr_verify_missing_public_input(ctx):
    """Schnorr verify rejects proof with no public_input."""
    proof = SchnorrProof.generate(42, ctx)
    proof.public_input = None

    result = SchnorrProof.verify(proof, ctx)
    assert result.valid is False
    assert (
        "public_input" in (result.error or "").lower() or "public" in (result.error or "").lower()
    )


def test_schnorr_verification_time(ctx):
    """Schnorr verification records a positive verification_time."""
    proof = SchnorrProof.generate(42, ctx)
    result = SchnorrProof.verify(proof, ctx)
    assert result.verification_time > 0


# ---------------------------------------------------------------------------
# PedersenCommitment - commit and verify
# ---------------------------------------------------------------------------


def test_pedersen_commit_returns_tuple(ctx):
    """PedersenCommitment.commit returns (bytes, int) tuple."""
    c, b = PedersenCommitment.commit(10, 999, ctx)
    assert isinstance(c, bytes)
    assert isinstance(b, int)
    assert len(c) == 33  # compressed point


def test_pedersen_verify_opening(ctx):
    """A commitment verifies with the correct value and blinding."""
    value = 42
    blinding = 7777
    commitment, _ = PedersenCommitment.commit(value, blinding, ctx)
    assert PedersenCommitment.verify_opening(commitment, value, blinding, ctx)


def test_pedersen_wrong_value_fails(ctx):
    """Verification fails when opened with a wrong value."""
    value = 42
    blinding = 5555
    commitment, _ = PedersenCommitment.commit(value, blinding, ctx)
    assert not PedersenCommitment.verify_opening(commitment, 43, blinding, ctx)


def test_pedersen_wrong_blinding_fails(ctx):
    """Verification fails when opened with a wrong blinding factor."""
    value = 42
    blinding = 5555
    commitment, _ = PedersenCommitment.commit(value, blinding, ctx)
    assert not PedersenCommitment.verify_opening(commitment, value, 5556, ctx)


def test_pedersen_hiding_property(ctx):
    """Same value with different blinding produces different commitments."""
    c1, _ = PedersenCommitment.commit(100, 1111, ctx)
    c2, _ = PedersenCommitment.commit(100, 2222, ctx)
    assert c1 != c2


def test_pedersen_binding_property(ctx):
    """Different values produce different commitments (with same blinding)."""
    blinding = 9999
    c1, _ = PedersenCommitment.commit(10, blinding, ctx)
    c2, _ = PedersenCommitment.commit(20, blinding, ctx)
    assert c1 != c2


def test_pedersen_deterministic(ctx):
    """Same value and blinding always yield the same commitment."""
    c1, _ = PedersenCommitment.commit(50, 3333, ctx)
    c2, _ = PedersenCommitment.commit(50, 3333, ctx)
    assert c1 == c2


# ---------------------------------------------------------------------------
# RangeProof
# ---------------------------------------------------------------------------


def test_range_proof_generate_small_value(ctx):
    """RangeProof generates for a small value within range."""
    proof = RangeProof.generate(5, 8, ctx)
    assert proof.proof_type == ProofType.RANGE_PROOF
    assert proof.metadata["bit_length"] == 8


def test_range_proof_verify_small_value(ctx):
    """RangeProof verifies successfully for a valid small value."""
    proof = RangeProof.generate(5, 8, ctx)
    result = RangeProof.verify(proof, 8, ctx)
    assert result.valid is True


def test_range_proof_value_zero(ctx):
    """RangeProof works for value 0."""
    proof = RangeProof.generate(0, 4, ctx)
    result = RangeProof.verify(proof, 4, ctx)
    assert result.valid is True


def test_range_proof_value_max(ctx):
    """RangeProof works for the maximum value 2^n - 1."""
    proof = RangeProof.generate(255, 8, ctx)
    result = RangeProof.verify(proof, 8, ctx)
    assert result.valid is True


def test_range_proof_rejects_out_of_range(ctx):
    """RangeProof.generate raises ValueError for value >= 2^n."""
    with pytest.raises(ValueError, match="outside the valid range"):
        RangeProof.generate(256, 8, ctx)


def test_range_proof_rejects_negative(ctx):
    """RangeProof.generate raises ValueError for negative values."""
    with pytest.raises(ValueError, match="outside the valid range"):
        RangeProof.generate(-1, 8, ctx)


def test_range_proof_different_bit_lengths(ctx):
    """RangeProof works with different bit lengths."""
    for bits in [4, 8, 16]:
        value = (1 << bits) - 1  # max value for bit length
        proof = RangeProof.generate(value, bits, ctx)
        result = RangeProof.verify(proof, bits, ctx)
        assert result.valid is True, f"Failed for bit_length={bits}"


def test_range_proof_bit_length_mismatch(ctx):
    """RangeProof.verify rejects when bit_length does not match proof."""
    proof = RangeProof.generate(5, 8, ctx)
    result = RangeProof.verify(proof, 16, ctx)
    assert result.valid is False
    assert "mismatch" in (result.error or "").lower()


def test_range_proof_verification_time(ctx):
    """RangeProof verification records a positive verification_time."""
    proof = RangeProof.generate(10, 8, ctx)
    result = RangeProof.verify(proof, 8, ctx)
    assert result.verification_time > 0


# ---------------------------------------------------------------------------
# Proof model serialization
# ---------------------------------------------------------------------------


def test_proof_model_serialization(ctx):
    """Proof can be serialized to dict and deserialized."""
    proof = SchnorrProof.generate(42, ctx)
    data = proof.model_dump(mode="json")

    assert isinstance(data, dict)
    assert data["proof_type"] == "schnorr"
    assert isinstance(data["commitment"], str)  # base64-encoded by Pydantic

    restored = Proof.model_validate(data)
    assert restored.proof_type == ProofType.SCHNORR


def test_proof_model_json_round_trip(ctx):
    """Proof survives JSON serialization round trip."""
    proof = SchnorrProof.generate(42, ctx)
    json_str = proof.model_dump_json()
    restored = Proof.model_validate_json(json_str)
    assert restored.proof_type == proof.proof_type
    assert restored.commitment == proof.commitment
    assert restored.challenge == proof.challenge
    assert restored.response == proof.response
    assert restored.public_input == proof.public_input


# ---------------------------------------------------------------------------
# VerificationResult model
# ---------------------------------------------------------------------------


def test_verification_result_valid():
    """VerificationResult can represent a valid result."""
    result = VerificationResult(
        valid=True,
        proof_type=ProofType.SCHNORR,
        verification_time=0.001,
    )
    assert result.valid is True
    assert result.error is None


def test_verification_result_invalid():
    """VerificationResult can represent an invalid result with error."""
    result = VerificationResult(
        valid=False,
        proof_type=ProofType.SCHNORR,
        error="something went wrong",
    )
    assert result.valid is False
    assert result.error == "something went wrong"


def test_verification_result_serialization():
    """VerificationResult can be serialized and deserialized."""
    result = VerificationResult(
        valid=True,
        proof_type=ProofType.PEDERSEN_COMMITMENT,
        verification_time=0.123,
    )
    data = result.model_dump(mode="json")
    restored = VerificationResult.model_validate(data)
    assert restored.valid is True
    assert restored.proof_type == ProofType.PEDERSEN_COMMITMENT
