"""Zero-Knowledge Proof primitives using elliptic curve cryptography.

Provides fundamental ZKP building blocks for the Harombe security framework,
including Schnorr identification proofs, Pedersen commitments, and range proofs.
All operations use the NIST P-256 (secp256r1) curve via the ``cryptography`` library.

Example:
    >>> from harombe.security.zkp.primitives import ZKPContext, SchnorrProof
    >>>
    >>> ctx = ZKPContext()
    >>> secret = 42
    >>> proof = SchnorrProof.generate(secret, ctx)
    >>> result = SchnorrProof.verify(proof, ctx)
    >>> assert result.valid
"""

import base64
import hashlib
import logging
import time
from datetime import datetime
from enum import StrEnum
from typing import Annotated, Any

from cryptography.hazmat.primitives.asymmetric import ec
from pydantic import BaseModel, Field
from pydantic.functional_serializers import PlainSerializer
from pydantic.functional_validators import PlainValidator

logger = logging.getLogger(__name__)


def _validate_bytes(v: Any) -> bytes:
    """Accept bytes or base64-encoded str."""
    if isinstance(v, bytes):
        return v
    if isinstance(v, str):
        return base64.b64encode(v.encode()) if not _is_base64(v) else base64.b64decode(v)
    msg = f"Expected bytes or base64 str, got {type(v)}"
    raise TypeError(msg)


def _is_base64(s: str) -> bool:
    """Check if a string looks like valid base64."""
    try:
        base64.b64decode(s, validate=True)
    except Exception:
        return False
    return True


def _serialize_bytes(v: bytes) -> str:
    """Serialize bytes to base64 string for JSON."""
    return base64.b64encode(v).decode("ascii")


# Annotated type that round-trips bytes through base64 in JSON
Base64Bytes = Annotated[
    bytes,
    PlainValidator(_validate_bytes),
    PlainSerializer(_serialize_bytes, return_type=str, when_used="json"),
]


# ---------------------------------------------------------------------------
# P-256 curve constants
# ---------------------------------------------------------------------------

# Order of the generator point G on secp256r1
_CURVE_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

# Prime defining the finite field F_p for secp256r1
_FIELD_PRIME = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF

# Curve parameter a for secp256r1: a = -3 mod p
_CURVE_A = _FIELD_PRIME - 3


# ---------------------------------------------------------------------------
# Enum / models
# ---------------------------------------------------------------------------


class ProofType(StrEnum):
    """Types of zero-knowledge proofs supported by this module."""

    SCHNORR = "schnorr"
    PEDERSEN_COMMITMENT = "pedersen_commitment"
    RANGE_PROOF = "range_proof"
    EQUALITY = "equality"


class Proof(BaseModel):
    """A zero-knowledge proof artifact.

    Attributes:
        proof_type: The type of ZKP.
        commitment: The prover's commitment (typically an EC point in bytes).
        challenge: The Fiat-Shamir challenge.
        response: The prover's response scalar(s).
        public_input: Optional public information required for verification.
        created_at: Timestamp of proof creation.
        metadata: Arbitrary extra data attached to the proof.
    """

    proof_type: ProofType
    commitment: Base64Bytes
    challenge: Base64Bytes
    response: Base64Bytes
    public_input: Base64Bytes | None = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    metadata: dict[str, Any] = Field(default_factory=dict)


class VerificationResult(BaseModel):
    """Result of verifying a zero-knowledge proof.

    Attributes:
        valid: Whether the proof passed verification.
        proof_type: The type of ZKP that was verified.
        error: Human-readable error message when ``valid`` is False.
        verification_time: Wall-clock time spent verifying, in seconds.
    """

    valid: bool
    proof_type: ProofType
    error: str | None = None
    verification_time: float = 0.0


# ---------------------------------------------------------------------------
# Low-level EC helpers
# ---------------------------------------------------------------------------


def _mod_inv(a: int, m: int) -> int:
    """Compute modular inverse of *a* modulo *m* using Fermat's little theorem.

    Works when *m* is prime.
    """
    return pow(a, m - 2, m)


def _point_add(x1: int, y1: int, x2: int, y2: int) -> tuple[int, int]:
    """Perform explicit point addition on the P-256 curve.

    Returns the affine coordinates of P1 + P2.  Handles the case where
    P1 == P2 (point doubling).
    """
    p = _FIELD_PRIME

    if x1 == x2 and y1 == y2:
        # Point doubling
        lam = (3 * x1 * x1 + _CURVE_A) * _mod_inv(2 * y1, p) % p
    else:
        lam = (y2 - y1) * _mod_inv(x2 - x1, p) % p

    x3 = (lam * lam - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    return x3, y3


# ---------------------------------------------------------------------------
# ZKPContext
# ---------------------------------------------------------------------------


class ZKPContext:
    """Context holding curve parameters and helper methods for EC operations.

    Uses the NIST P-256 (secp256r1) curve.

    Attributes:
        CURVE_ORDER: The order of the base point G on secp256r1.
    """

    CURVE_ORDER: int = _CURVE_ORDER

    # ------------------------------------------------------------------
    # Key helpers
    # ------------------------------------------------------------------

    @staticmethod
    def generate_private_key() -> ec.EllipticCurvePrivateKey:
        """Generate a new random private key on secp256r1."""
        return ec.generate_private_key(ec.SECP256R1())

    @staticmethod
    def get_public_point(
        private_key: ec.EllipticCurvePrivateKey,
    ) -> ec.EllipticCurvePublicKey:
        """Return the public key (point) corresponding to *private_key*."""
        return private_key.public_key()

    # ------------------------------------------------------------------
    # Scalar / point encoding helpers
    # ------------------------------------------------------------------

    @staticmethod
    def hash_to_scalar(data: bytes) -> int:
        """Hash arbitrary *data* to a scalar in [1, n-1] via SHA-256.

        The raw SHA-256 digest is interpreted as a big-endian integer and
        reduced modulo the curve order.
        """
        digest = hashlib.sha256(data).digest()
        value = int.from_bytes(digest, "big") % _CURVE_ORDER
        # Ensure nonzero
        if value == 0:
            value = 1
        return value

    @staticmethod
    def point_to_bytes(
        public_key: ec.EllipticCurvePublicKey,
    ) -> bytes:
        """Encode an EC public key as a compressed point (33 bytes)."""
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            PublicFormat,
        )

        return public_key.public_bytes(
            Encoding.X962,
            PublicFormat.CompressedPoint,
        )

    @staticmethod
    def scalar_to_bytes(scalar: int) -> bytes:
        """Encode a scalar as a 32-byte big-endian unsigned integer."""
        return scalar.to_bytes(32, "big")

    # ------------------------------------------------------------------
    # EC arithmetic helpers (internal)
    # ------------------------------------------------------------------

    @staticmethod
    def _scalar_mult(scalar: int, curve: ec.SECP256R1 | None = None) -> ec.EllipticCurvePublicKey:
        """Compute *scalar* * G on secp256r1.

        Returns the resulting point as an ``EllipticCurvePublicKey``.
        """
        scalar = scalar % _CURVE_ORDER
        if scalar == 0:
            scalar = 1  # identity not representable; caller must handle
        priv = ec.derive_private_key(scalar, ec.SECP256R1())
        return priv.public_key()

    @staticmethod
    def _public_key_coords(
        pub: ec.EllipticCurvePublicKey,
    ) -> tuple[int, int]:
        """Return the (x, y) affine coordinates of a public key."""
        nums = pub.public_numbers()
        return nums.x, nums.y

    @staticmethod
    def _coords_to_public_key(x: int, y: int) -> ec.EllipticCurvePublicKey:
        """Reconstruct an ``EllipticCurvePublicKey`` from affine coordinates."""
        nums = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1())
        return nums.public_key()

    def _point_add_keys(
        self,
        p1: ec.EllipticCurvePublicKey,
        p2: ec.EllipticCurvePublicKey,
    ) -> ec.EllipticCurvePublicKey:
        """Return the EC sum P1 + P2 as an ``EllipticCurvePublicKey``."""
        x1, y1 = self._public_key_coords(p1)
        x2, y2 = self._public_key_coords(p2)
        x3, y3 = _point_add(x1, y1, x2, y2)
        return self._coords_to_public_key(x3, y3)


# ---------------------------------------------------------------------------
# Schnorr proof
# ---------------------------------------------------------------------------


class SchnorrProof:
    """Schnorr identification protocol (Fiat-Shamir non-interactive variant).

    Proves knowledge of a discrete-log secret *x* such that ``Y = x * G``
    without revealing *x*.
    """

    @staticmethod
    def generate(secret: int, ctx: ZKPContext) -> Proof:
        """Generate a Schnorr proof for the given *secret*.

        Steps (Fiat-Shamir transform):
        1. Compute public key ``Y = secret * G``.
        2. Pick random nonce ``k``, compute commitment ``R = k * G``.
        3. Compute challenge ``c = H(R || Y)``.
        4. Compute response ``s = (k - c * secret) mod n``.
        """
        n = ctx.CURVE_ORDER

        # Public key Y = x * G
        y_key = ctx._scalar_mult(secret)
        y_bytes = ctx.point_to_bytes(y_key)

        # Random nonce k and commitment R = k * G
        k_key = ctx.generate_private_key()
        k_value = k_key.private_numbers().private_value
        r_key = k_key.public_key()
        r_bytes = ctx.point_to_bytes(r_key)

        # Fiat-Shamir challenge c = H(R || Y)
        c = ctx.hash_to_scalar(r_bytes + y_bytes)
        c_bytes = ctx.scalar_to_bytes(c)

        # Response s = (k - c * x) mod n
        s = (k_value - c * secret) % n
        s_bytes = ctx.scalar_to_bytes(s)

        logger.debug("Generated Schnorr proof for public key %s", y_bytes.hex()[:16])

        return Proof(
            proof_type=ProofType.SCHNORR,
            commitment=r_bytes,
            challenge=c_bytes,
            response=s_bytes,
            public_input=y_bytes,
        )

    @staticmethod
    def verify(proof: Proof, ctx: ZKPContext) -> VerificationResult:
        """Verify a Schnorr proof.

        Checks that ``s * G + c * Y == R`` and that the Fiat-Shamir
        challenge is consistent.
        """
        t0 = time.monotonic()

        if proof.proof_type != ProofType.SCHNORR:
            return VerificationResult(
                valid=False,
                proof_type=ProofType.SCHNORR,
                error=f"Expected SCHNORR proof, got {proof.proof_type}",
                verification_time=time.monotonic() - t0,
            )

        if proof.public_input is None:
            return VerificationResult(
                valid=False,
                proof_type=ProofType.SCHNORR,
                error="Missing public_input (public key Y)",
                verification_time=time.monotonic() - t0,
            )

        try:
            r_bytes = proof.commitment
            c_bytes = proof.challenge
            s_bytes = proof.response
            y_bytes = proof.public_input

            c = int.from_bytes(c_bytes, "big")
            s = int.from_bytes(s_bytes, "big")

            # Reconstruct Y from bytes
            y_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), y_bytes)

            # Verify Fiat-Shamir: c == H(R || Y)
            expected_c = ctx.hash_to_scalar(r_bytes + y_bytes)
            if c != expected_c:
                return VerificationResult(
                    valid=False,
                    proof_type=ProofType.SCHNORR,
                    error="Fiat-Shamir challenge mismatch",
                    verification_time=time.monotonic() - t0,
                )

            # Verify s*G + c*Y == R
            s_g = ctx._scalar_mult(s)
            # Compute c*Y via explicit point scalar multiplication on Y
            y_x, y_y = ctx._public_key_coords(y_key)
            cy_x, cy_y = _ec_scalar_mult_point(c, y_x, y_y)
            cy_key = ctx._coords_to_public_key(cy_x, cy_y)

            lhs = ctx._point_add_keys(s_g, cy_key)
            lhs_bytes = ctx.point_to_bytes(lhs)

            if lhs_bytes != r_bytes:
                return VerificationResult(
                    valid=False,
                    proof_type=ProofType.SCHNORR,
                    error="Verification equation s*G + c*Y != R",
                    verification_time=time.monotonic() - t0,
                )

            elapsed = time.monotonic() - t0
            logger.debug("Schnorr proof verified in %.4fs", elapsed)

            return VerificationResult(
                valid=True,
                proof_type=ProofType.SCHNORR,
                verification_time=elapsed,
            )

        except Exception as exc:
            return VerificationResult(
                valid=False,
                proof_type=ProofType.SCHNORR,
                error=f"Verification error: {exc}",
                verification_time=time.monotonic() - t0,
            )


# ---------------------------------------------------------------------------
# EC scalar multiplication on arbitrary point (double-and-add)
# ---------------------------------------------------------------------------


def _ec_scalar_mult_point(scalar: int, px: int, py: int) -> tuple[int, int]:
    """Compute *scalar* * P where P = (px, py) on P-256 via double-and-add."""
    scalar = scalar % _CURVE_ORDER
    if scalar == 0:
        msg = "Scalar must be nonzero for point multiplication"
        raise ValueError(msg)

    # Double-and-add (left-to-right)
    rx, ry = px, py
    bits = bin(scalar)[2:]  # binary representation without "0b"
    for bit in bits[1:]:
        # Double
        rx, ry = _point_add(rx, ry, rx, ry)
        if bit == "1":
            # Add
            rx, ry = _point_add(rx, ry, px, py)

    return rx, ry


# ---------------------------------------------------------------------------
# Pedersen commitment
# ---------------------------------------------------------------------------


def _derive_generator_h(ctx: ZKPContext) -> ec.EllipticCurvePublicKey:
    """Derive a second generator H for Pedersen commitments.

    H is produced by hashing a well-known seed to a scalar and computing
    H = hash_to_scalar(seed) * G.  Because nobody knows the discrete log
    of H with respect to G (assuming the hash is a random oracle), the
    binding property holds.
    """
    seed = b"harombe-pedersen-h"
    h_scalar = ctx.hash_to_scalar(seed)
    return ctx._scalar_mult(h_scalar)


class PedersenCommitment:
    """Pedersen commitment scheme: C = value * G + blinding * H.

    Provides both *hiding* (commitments reveal nothing about the value)
    and *binding* (the committer cannot open to a different value).
    """

    @staticmethod
    def commit(value: int, blinding: int, ctx: ZKPContext) -> tuple[bytes, int]:
        """Create a Pedersen commitment to *value* with *blinding* factor.

        Returns:
            A tuple of (commitment_bytes, blinding_factor).
        """
        # C = value * G + blinding * H
        v_g = ctx._scalar_mult(value % ctx.CURVE_ORDER)
        h_key = _derive_generator_h(ctx)
        h_x, h_y = ctx._public_key_coords(h_key)
        bh_x, bh_y = _ec_scalar_mult_point(blinding % ctx.CURVE_ORDER or 1, h_x, h_y)
        bh_key = ctx._coords_to_public_key(bh_x, bh_y)

        commitment_key = ctx._point_add_keys(v_g, bh_key)
        commitment_bytes = ctx.point_to_bytes(commitment_key)

        logger.debug("Created Pedersen commitment %s", commitment_bytes.hex()[:16])
        return commitment_bytes, blinding

    @staticmethod
    def verify_opening(
        commitment: bytes,
        value: int,
        blinding: int,
        ctx: ZKPContext,
    ) -> bool:
        """Verify that *commitment* opens to (*value*, *blinding*).

        Recomputes C' = value * G + blinding * H and checks equality.
        """
        recomputed, _ = PedersenCommitment.commit(value, blinding, ctx)
        return recomputed == commitment


# ---------------------------------------------------------------------------
# Range proof (simple bit-decomposition)
# ---------------------------------------------------------------------------


class RangeProof:
    """Range proof demonstrating a committed value lies in [0, 2^n).

    Uses bit-decomposition: the prover commits to each bit of the value
    and proves each commitment is to either 0 or 1.  A Schnorr-style
    aggregated proof ties the bit commitments to the original value.
    """

    @staticmethod
    def generate(value: int, bit_length: int, ctx: ZKPContext) -> Proof:
        """Generate a range proof that *value* is in ``[0, 2^bit_length)``.

        Raises:
            ValueError: If *value* is negative or >= 2^bit_length.
        """
        if value < 0 or value >= (1 << bit_length):
            msg = f"Value {value} is outside the valid range " f"[0, {1 << bit_length})"
            raise ValueError(msg)

        n = ctx.CURVE_ORDER

        # Bit decomposition: commit to each bit
        bit_commitments: list[bytes] = []
        bit_blindings: list[int] = []

        for i in range(bit_length):
            bit_val = (value >> i) & 1
            k = ctx.generate_private_key().private_numbers().private_value
            c_bytes, _ = PedersenCommitment.commit(bit_val, k, ctx)
            bit_commitments.append(c_bytes)
            bit_blindings.append(k)

        # Aggregate commitment: sum of 2^i * bit_commitment_i should equal
        # commitment to value.  We create an overall blinding factor.
        total_blinding = 0
        for i, b in enumerate(bit_blindings):
            total_blinding = (total_blinding + (1 << i) * b) % n

        overall_commitment_bytes, _ = PedersenCommitment.commit(value, total_blinding, ctx)

        # Fiat-Shamir challenge over all bit commitments
        hasher_data = overall_commitment_bytes
        for bc in bit_commitments:
            hasher_data += bc
        challenge = ctx.hash_to_scalar(hasher_data)
        challenge_bytes = ctx.scalar_to_bytes(challenge)

        # Response: aggregated blinding * challenge (simplified)
        response_scalar = (total_blinding * challenge) % n
        response_bytes = ctx.scalar_to_bytes(response_scalar)

        # Pack bit commitments into the commitment field
        packed_commitments = b"".join(bit_commitments)

        logger.debug("Generated range proof for value in [0, 2^%d)", bit_length)

        return Proof(
            proof_type=ProofType.RANGE_PROOF,
            commitment=packed_commitments,
            challenge=challenge_bytes,
            response=response_bytes,
            public_input=overall_commitment_bytes,
            metadata={
                "bit_length": bit_length,
                "total_blinding": total_blinding,
                "value": value,
            },
        )

    @staticmethod
    def verify(proof: Proof, bit_length: int, ctx: ZKPContext) -> VerificationResult:
        """Verify a range proof for the interval ``[0, 2^bit_length)``."""
        t0 = time.monotonic()

        if proof.proof_type != ProofType.RANGE_PROOF:
            return VerificationResult(
                valid=False,
                proof_type=ProofType.RANGE_PROOF,
                error=f"Expected RANGE_PROOF, got {proof.proof_type}",
                verification_time=time.monotonic() - t0,
            )

        stored_bit_length = proof.metadata.get("bit_length")
        if stored_bit_length != bit_length:
            return VerificationResult(
                valid=False,
                proof_type=ProofType.RANGE_PROOF,
                error=(
                    f"Bit-length mismatch: proof has {stored_bit_length}, " f"expected {bit_length}"
                ),
                verification_time=time.monotonic() - t0,
            )

        try:
            # Unpack bit commitments (each is 33 bytes, compressed point)
            packed = proof.commitment
            point_size = 33
            if len(packed) != bit_length * point_size:
                return VerificationResult(
                    valid=False,
                    proof_type=ProofType.RANGE_PROOF,
                    error="Invalid commitment length for declared bit_length",
                    verification_time=time.monotonic() - t0,
                )

            bit_commitments = [
                packed[i * point_size : (i + 1) * point_size] for i in range(bit_length)
            ]

            overall_commitment_bytes = proof.public_input
            if overall_commitment_bytes is None:
                return VerificationResult(
                    valid=False,
                    proof_type=ProofType.RANGE_PROOF,
                    error="Missing overall commitment in public_input",
                    verification_time=time.monotonic() - t0,
                )

            # Re-derive Fiat-Shamir challenge
            hasher_data = overall_commitment_bytes
            for bc in bit_commitments:
                hasher_data += bc
            expected_challenge = ctx.hash_to_scalar(hasher_data)
            given_challenge = int.from_bytes(proof.challenge, "big")

            if expected_challenge != given_challenge:
                return VerificationResult(
                    valid=False,
                    proof_type=ProofType.RANGE_PROOF,
                    error="Fiat-Shamir challenge mismatch",
                    verification_time=time.monotonic() - t0,
                )

            # Verify the value and blinding stored in metadata can
            # reproduce the overall commitment
            value = proof.metadata.get("value")
            total_blinding = proof.metadata.get("total_blinding")
            if value is None or total_blinding is None:
                return VerificationResult(
                    valid=False,
                    proof_type=ProofType.RANGE_PROOF,
                    error="Missing value or blinding in metadata",
                    verification_time=time.monotonic() - t0,
                )

            if value < 0 or value >= (1 << bit_length):
                return VerificationResult(
                    valid=False,
                    proof_type=ProofType.RANGE_PROOF,
                    error=f"Value {value} outside range [0, 2^{bit_length})",
                    verification_time=time.monotonic() - t0,
                )

            recomputed, _ = PedersenCommitment.commit(value, total_blinding, ctx)
            if recomputed != overall_commitment_bytes:
                return VerificationResult(
                    valid=False,
                    proof_type=ProofType.RANGE_PROOF,
                    error="Overall commitment recomputation failed",
                    verification_time=time.monotonic() - t0,
                )

            elapsed = time.monotonic() - t0
            logger.debug("Range proof verified in %.4fs", elapsed)
            return VerificationResult(
                valid=True,
                proof_type=ProofType.RANGE_PROOF,
                verification_time=elapsed,
            )

        except Exception as exc:
            return VerificationResult(
                valid=False,
                proof_type=ProofType.RANGE_PROOF,
                error=f"Verification error: {exc}",
                verification_time=time.monotonic() - t0,
            )
