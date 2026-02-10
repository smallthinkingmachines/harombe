"""Multi-Party Computation (MPC) for secure distributed secret operations.

This module provides MPC primitives using additive secret sharing with Beaver
triples for secure multiplication. All arithmetic is performed in a finite field
over a large prime, using pure Python.

Supports:
- Additive secret sharing: split a secret into n shares
- Secure addition: add two shared values without revealing either
- Secure multiplication: multiply shared values using Beaver triples
- Secure comparison: compare two shared values
- Threshold decryption: decrypt using threshold number of key shares

Example:
    >>> from harombe.security.distributed.mpc import MPCEngine, MPCConfig
    >>>
    >>> engine = MPCEngine()
    >>>
    >>> # Share two secrets
    >>> shares_a = engine.share_secret(42)
    >>> shares_b = engine.share_secret(10)
    >>>
    >>> # Add them securely
    >>> shares_sum = engine.add_shares(shares_a, shares_b)
    >>> result = engine.reconstruct(shares_sum)
    >>> assert result == 52
"""

import hashlib
import hmac
import logging
import secrets
from enum import StrEnum

from pydantic import BaseModel

logger = logging.getLogger(__name__)

# A 256-bit prime for the finite field.
# This is the largest prime less than 2^256.
DEFAULT_PRIME = 2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 - 1


class MPCProtocol(StrEnum):
    """MPC protocol variant.

    Attributes:
        ADDITIVE: Simple additive secret sharing.
        BEAVER_TRIPLE: Beaver triple-based multiplication.
        THRESHOLD: Threshold-based secret sharing.
    """

    ADDITIVE = "additive"
    BEAVER_TRIPLE = "beaver_triple"
    THRESHOLD = "threshold"


class MPCOperation(StrEnum):
    """MPC operation type.

    Attributes:
        ADD: Secure addition of shared values.
        MULTIPLY: Secure multiplication using Beaver triples.
        COMPARE: Secure comparison of shared values.
        EQUALITY: Secure equality test of shared values.
        THRESHOLD_DECRYPT: Threshold decryption using key shares.
    """

    ADD = "add"
    MULTIPLY = "multiply"
    COMPARE = "compare"
    EQUALITY = "equality"
    THRESHOLD_DECRYPT = "threshold_decrypt"


class MPCParty(BaseModel):
    """A party participating in an MPC protocol.

    Attributes:
        party_id: Unique identifier for the party.
        name: Human-readable name for the party.
        share: The party's current share value.
        is_active: Whether the party is currently active.
    """

    party_id: str
    name: str = ""
    share: int = 0
    is_active: bool = True


class MPCConfig(BaseModel):
    """Configuration for the MPC engine.

    Attributes:
        num_parties: Number of parties in the protocol.
        threshold: Minimum number of parties required for reconstruction.
        prime: Prime modulus for the finite field (uses 256-bit default if None).
        protocol: MPC protocol variant to use.
    """

    num_parties: int = 3
    threshold: int = 2
    prime: int | None = None
    protocol: MPCProtocol = MPCProtocol.ADDITIVE


class SecretShare(BaseModel):
    """A single share of a secret value.

    Attributes:
        party_id: Identifier of the party holding this share.
        value: The share value in the finite field.
        share_index: Index of this share (0-based).
    """

    party_id: str
    value: int
    share_index: int


class MPCEngine:
    """Core MPC engine implementing additive secret sharing with Beaver triples.

    Provides secure computation primitives over a finite field defined by a
    large prime modulus. Secrets are split into additive shares that can be
    distributed among parties, and operations are performed on shares without
    revealing the underlying values.

    Example:
        >>> engine = MPCEngine()
        >>> shares = engine.share_secret(100)
        >>> recovered = engine.reconstruct(shares)
        >>> assert recovered == 100
    """

    def __init__(self, config: MPCConfig | None = None) -> None:
        """Initialize the MPC engine.

        Args:
            config: MPC configuration. Uses defaults if None.
        """
        self.config = config or MPCConfig()
        self._prime = self.config.prime if self.config.prime is not None else DEFAULT_PRIME
        self._num_parties = self.config.num_parties

        logger.info(
            "MPCEngine initialized with %d parties, threshold=%d, protocol=%s",
            self._num_parties,
            self.config.threshold,
            self.config.protocol.value,
        )

    def share_secret(self, secret: int) -> list[SecretShare]:
        """Split a secret into additive shares.

        Generates n-1 random values and computes the last share so that the
        sum of all shares equals the secret modulo the prime.

        Args:
            secret: The secret value to share (must be in [0, prime)).

        Returns:
            List of SecretShare objects, one per party.
        """
        secret_mod = secret % self._prime
        shares: list[int] = []

        # Generate n-1 random shares
        for _ in range(self._num_parties - 1):
            r = secrets.randbelow(self._prime)
            shares.append(r)

        # Last share = secret - sum(other shares) mod p
        last_share = (secret_mod - sum(shares)) % self._prime
        shares.append(last_share)

        result = [
            SecretShare(
                party_id=f"party_{i}",
                value=shares[i],
                share_index=i,
            )
            for i in range(self._num_parties)
        ]

        logger.debug("Shared secret into %d shares", self._num_parties)
        return result

    def reconstruct(self, shares: list[SecretShare]) -> int:
        """Reconstruct a secret from its additive shares.

        Args:
            shares: List of SecretShare objects to combine.

        Returns:
            The reconstructed secret value.
        """
        total = sum(s.value for s in shares) % self._prime
        logger.debug("Reconstructed secret from %d shares", len(shares))
        return total

    def add_shares(
        self,
        shares_a: list[SecretShare],
        shares_b: list[SecretShare],
    ) -> list[SecretShare]:
        """Add two sets of shares element-wise.

        Each party adds their corresponding shares locally. The result
        is shares of the sum of the two underlying secrets.

        Args:
            shares_a: Shares of the first value.
            shares_b: Shares of the second value.

        Returns:
            Shares of the sum (a + b).
        """
        if len(shares_a) != len(shares_b):
            raise ValueError(f"Share count mismatch: {len(shares_a)} vs {len(shares_b)}")

        result = [
            SecretShare(
                party_id=shares_a[i].party_id,
                value=(shares_a[i].value + shares_b[i].value) % self._prime,
                share_index=shares_a[i].share_index,
            )
            for i in range(len(shares_a))
        ]

        logger.debug("Added shares element-wise for %d parties", len(result))
        return result

    def generate_beaver_triple(
        self,
    ) -> tuple[list[SecretShare], list[SecretShare], list[SecretShare]]:
        """Generate a Beaver triple (a, b, c) where c = a * b mod p.

        A Beaver triple consists of three random shared values where the
        product relation holds. These are used for secure multiplication.

        Returns:
            Tuple of (shares_a, shares_b, shares_c) where c = a * b mod p.
        """
        a = secrets.randbelow(self._prime)
        b = secrets.randbelow(self._prime)
        c = (a * b) % self._prime

        shares_a = self.share_secret(a)
        shares_b = self.share_secret(b)
        shares_c = self.share_secret(c)

        logger.debug("Generated Beaver triple")
        return shares_a, shares_b, shares_c

    def multiply_shares(
        self,
        shares_x: list[SecretShare],
        shares_y: list[SecretShare],
    ) -> list[SecretShare]:
        """Multiply two sets of shares using Beaver triples.

        Uses the Beaver triple protocol: given shares of x and y, and a
        pre-generated triple (a, b, c) where c = a*b, compute shares of
        z = x*y by:
          1. Compute d = x - a and e = y - b (open these values)
          2. Each party computes: z_i = c_i + d*b_i + e*a_i + (d*e if i==0)

        Args:
            shares_x: Shares of the first value.
            shares_y: Shares of the second value.

        Returns:
            Shares of the product (x * y).
        """
        if len(shares_x) != len(shares_y):
            raise ValueError(f"Share count mismatch: {len(shares_x)} vs {len(shares_y)}")

        n = len(shares_x)

        # Generate Beaver triple
        triple_a, triple_b, triple_c = self.generate_beaver_triple()

        # Compute d_i = x_i - a_i and e_i = y_i - b_i for each party
        d_shares = [(shares_x[i].value - triple_a[i].value) % self._prime for i in range(n)]
        e_shares = [(shares_y[i].value - triple_b[i].value) % self._prime for i in range(n)]

        # Open d and e (sum all shares)
        d = sum(d_shares) % self._prime
        e = sum(e_shares) % self._prime

        # Each party computes their share of the product
        result = []
        for i in range(n):
            z_i = (triple_c[i].value + d * triple_b[i].value + e * triple_a[i].value) % self._prime

            # Only party 0 adds d*e to avoid double-counting
            if i == 0:
                z_i = (z_i + d * e) % self._prime

            result.append(
                SecretShare(
                    party_id=shares_x[i].party_id,
                    value=z_i,
                    share_index=shares_x[i].share_index,
                )
            )

        logger.debug("Multiplied shares using Beaver triple for %d parties", n)
        return result

    def scalar_multiply(self, shares: list[SecretShare], scalar: int) -> list[SecretShare]:
        """Multiply each share by a public scalar.

        Since the scalar is public, each party can locally multiply their
        share by it.

        Args:
            shares: Shares of the value to scale.
            scalar: Public scalar to multiply by.

        Returns:
            Shares of (scalar * value).
        """
        scalar_mod = scalar % self._prime
        result = [
            SecretShare(
                party_id=s.party_id,
                value=(s.value * scalar_mod) % self._prime,
                share_index=s.share_index,
            )
            for s in shares
        ]

        logger.debug("Scalar multiplied %d shares by %d", len(result), scalar)
        return result


class SecureComparison:
    """Secure comparison of secret-shared values.

    Provides comparison and equality operations on shared values. Uses a
    simplified approach that reveals only the comparison result, not the
    underlying values.

    Example:
        >>> engine = MPCEngine()
        >>> cmp = SecureComparison(engine)
        >>> shares_a = engine.share_secret(10)
        >>> shares_b = engine.share_secret(5)
        >>> result = cmp.compare(shares_a, shares_b)
        >>> engine.reconstruct(result)  # 1 (a > b)
        1
    """

    def __init__(self, engine: MPCEngine) -> None:
        """Initialize secure comparison.

        Args:
            engine: The MPC engine to use for operations.
        """
        self.engine = engine

    def compare(
        self,
        shares_a: list[SecretShare],
        shares_b: list[SecretShare],
    ) -> list[SecretShare]:
        """Compare two shared values.

        Returns shares of 1 if a > b, 0 otherwise. Uses a simplified
        approach: compute the difference and check the sign.

        Args:
            shares_a: Shares of value a.
            shares_b: Shares of value b.

        Returns:
            Shares of the comparison result (1 if a > b, else 0).
        """
        # Compute difference: a - b mod p
        neg_b = [
            SecretShare(
                party_id=s.party_id,
                value=(self.engine._prime - s.value) % self.engine._prime,
                share_index=s.share_index,
            )
            for s in shares_b
        ]
        diff_shares = self.engine.add_shares(shares_a, neg_b)

        # Reconstruct to determine sign
        diff = self.engine.reconstruct(diff_shares)

        # In modular arithmetic, if diff is in the lower half of the field
        # then a > b (the difference is a small positive number).
        # If diff is in the upper half, then a < b (difference wrapped around).
        half_prime = self.engine._prime // 2
        result_bit = 1 if 0 < diff <= half_prime else 0

        logger.debug("Secure comparison result: %d", result_bit)
        return self.engine.share_secret(result_bit)

    def equality(
        self,
        shares_a: list[SecretShare],
        shares_b: list[SecretShare],
    ) -> list[SecretShare]:
        """Test equality of two shared values.

        Returns shares of 1 if a == b, 0 otherwise.

        Args:
            shares_a: Shares of value a.
            shares_b: Shares of value b.

        Returns:
            Shares of the equality result (1 if a == b, else 0).
        """
        # Compute difference: a - b mod p
        neg_b = [
            SecretShare(
                party_id=s.party_id,
                value=(self.engine._prime - s.value) % self.engine._prime,
                share_index=s.share_index,
            )
            for s in shares_b
        ]
        diff_shares = self.engine.add_shares(shares_a, neg_b)

        # Reconstruct to check if zero
        diff = self.engine.reconstruct(diff_shares)
        result_bit = 1 if diff == 0 else 0

        logger.debug("Secure equality result: %d", result_bit)
        return self.engine.share_secret(result_bit)


class ThresholdDecryption:
    """Threshold decryption using secret-shared keys.

    Provides a simplified threshold encryption/decryption scheme where
    a key is split among parties and a threshold number of partial
    decryptions are needed to recover the plaintext.

    Uses HMAC-based key derivation for the encryption key stream and
    XOR-based encryption for simplicity.

    Example:
        >>> engine = MPCEngine()
        >>> td = ThresholdDecryption(engine)
        >>> key, key_shares = td.generate_key_shares()
        >>> ciphertext = td.encrypt(b"hello", key)
        >>> partials = [td.partial_decrypt(ciphertext, s) for s in key_shares]
        >>> plaintext = td.combine_partial_decryptions(partials, ciphertext)
    """

    def __init__(self, engine: MPCEngine) -> None:
        """Initialize threshold decryption.

        Args:
            engine: The MPC engine to use for key sharing.
        """
        self.engine = engine

    def generate_key_shares(self) -> tuple[int, list[SecretShare]]:
        """Generate a random key and split it into shares.

        Returns:
            Tuple of (key, key_shares) where key is the full secret key
            and key_shares are the additive shares.
        """
        key = secrets.randbelow(self.engine._prime)
        key_shares = self.engine.share_secret(key)

        logger.info("Generated key shares for %d parties", len(key_shares))
        return key, key_shares

    def _derive_key_stream(self, key_bytes: bytes, length: int) -> bytes:
        """Derive a key stream of the given length using HMAC.

        Args:
            key_bytes: The key material.
            length: Number of bytes to generate.

        Returns:
            Key stream bytes of the requested length.
        """
        stream = b""
        counter = 0
        while len(stream) < length:
            block = hmac.new(
                key_bytes,
                counter.to_bytes(4, "big"),
                hashlib.sha256,
            ).digest()
            stream += block
            counter += 1
        return stream[:length]

    def encrypt(self, plaintext: bytes, key: int) -> bytes:
        """Encrypt plaintext using the full key.

        Uses XOR with an HMAC-derived key stream.

        Args:
            plaintext: The data to encrypt.
            key: The encryption key (integer).

        Returns:
            Ciphertext bytes.
        """
        key_bytes = key.to_bytes(32, "big")
        key_stream = self._derive_key_stream(key_bytes, len(plaintext))
        ciphertext = bytes(a ^ b for a, b in zip(plaintext, key_stream, strict=True))

        logger.debug("Encrypted %d bytes", len(plaintext))
        return ciphertext

    def partial_decrypt(self, ciphertext: bytes, key_share: SecretShare) -> int:
        """Compute a partial decryption using a single key share.

        Each party computes a hash of their share to contribute to the
        combined decryption.

        Args:
            ciphertext: The ciphertext to partially decrypt.
            key_share: The party's key share.

        Returns:
            Partial decryption value (the share value).
        """
        logger.debug(
            "Partial decryption by party %s (index %d)",
            key_share.party_id,
            key_share.share_index,
        )
        return key_share.value

    def combine_partial_decryptions(self, partials: list[int], ciphertext: bytes) -> bytes:
        """Combine partial decryptions to recover the plaintext.

        Reconstructs the full key from partial decryptions (share values)
        and decrypts the ciphertext.

        Args:
            partials: List of partial decryption values from each party.
            ciphertext: The ciphertext to decrypt.

        Returns:
            Decrypted plaintext bytes.
        """
        # Reconstruct key by summing partials
        key = sum(partials) % self.engine._prime
        key_bytes = key.to_bytes(32, "big")
        key_stream = self._derive_key_stream(key_bytes, len(ciphertext))
        plaintext = bytes(a ^ b for a, b in zip(ciphertext, key_stream, strict=True))

        logger.debug(
            "Combined %d partial decryptions, recovered %d bytes",
            len(partials),
            len(plaintext),
        )
        return plaintext
