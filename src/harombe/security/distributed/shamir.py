"""Shamir's Secret Sharing with Feldman's verifiable extension.

Implements threshold secret sharing where a secret is split into *n* shares
such that any *k* (threshold) shares can reconstruct the original secret,
but fewer than *k* shares reveal no information about the secret.

Feldman's Verifiable Secret Sharing (VSS) adds public commitments so that
each share holder can independently verify their share is consistent with
the polynomial, without learning the secret.

Polynomial arithmetic is performed over GF(q) where *q* is a large
Sophie Germain prime derived from the RFC 3526 Group 14 safe prime.
Feldman commitments are computed in the order-*q* subgroup of ``Z_p*``
where ``p = 2q + 1``.

Example:
    >>> from harombe.security.distributed.shamir import (
    ...     ShamirSecretSharing,
    ...     ShamirConfig,
    ... )
    >>>
    >>> sss = ShamirSecretSharing(ShamirConfig(threshold=3, total_shares=5))
    >>> result = sss.split(b"my-secret-key")
    >>>
    >>> # Any 3 of 5 shares can reconstruct
    >>> recovered = sss.combine(result.shares[:3])
    >>> assert recovered == b"my-secret-key"
    >>>
    >>> # Verify individual shares
    >>> for share in result.shares:
    ...     assert sss.verify_share(share, result.commitments)
"""

import logging
import secrets
from typing import Any

from pydantic import BaseModel, Field

from harombe.security.vault import VaultBackend

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# RFC 3526 Group 14 (2048-bit MODP safe prime)
# p is prime and q = (p - 1) / 2 is also prime.
# g = 2 generates the order-q subgroup of Z_p*.
# ---------------------------------------------------------------------------
_RFC3526_PRIME_HEX = (
    "FFFFFFFFFFFFFFFF"
    "C90FDAA22168C234"
    "C4C6628B80DC1CD1"
    "29024E088A67CC74"
    "020BBEA63B139B22"
    "514A08798E3404DD"
    "EF9519B3CD3A431B"
    "302B0A6DF25F1437"
    "4FE1356D6D51C245"
    "E485B576625E7EC6"
    "F44C42E9A637ED6B"
    "0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5"
    "AE9F24117C4B1FE6"
    "49286651ECE45B3D"
    "C2007CB8A163BF05"
    "98DA48361C55D39A"
    "69163FA8FD24CF5F"
    "83655D23DCA3AD96"
    "1C62F356208552BB"
    "9ED529077096966D"
    "670C354E4ABC9804"
    "F1746C08CA18217C"
    "32905E462E36CE3B"
    "E39E772C180E8603"
    "9B2783A2EC07A28F"
    "B5C55DF06F4C52C9"
    "DE2BCBF695581718"
    "3995497CEA956AE5"
    "15D2261898FA0510"
    "15728E5A8AACAA68"
    "FFFFFFFFFFFFFFFF"
)

_GROUP_PRIME: int = int(_RFC3526_PRIME_HEX, 16)  # p (safe prime, 2048-bit)
_FIELD_PRIME: int = (_GROUP_PRIME - 1) // 2  # q (Sophie Germain prime)


class Share(BaseModel):
    """A single share from Shamir's Secret Sharing.

    Attributes:
        share_id: 1-indexed share number (evaluation point).
        value: The share value (big integer), i.e. polynomial evaluated
            at *share_id* mod *q*.
        threshold: Minimum number of shares needed to reconstruct.
        total_shares: Total number of shares that were created.
        commitment: Feldman commitments ``g^a_i mod p`` for each
            polynomial coefficient ``a_i``.
    """

    share_id: int
    value: int
    threshold: int
    total_shares: int
    commitment: list[int] = Field(default_factory=list)


class ShamirConfig(BaseModel):
    """Configuration for Shamir's Secret Sharing.

    Attributes:
        threshold: Minimum number of shares to reconstruct (k).
        total_shares: Total number of shares to create (n).
        prime: Prime field modulus for polynomial arithmetic.  Uses a
            2047-bit Sophie Germain prime when ``None``.
        verify: Whether to compute Feldman commitments.
    """

    threshold: int = 3
    total_shares: int = 5
    prime: int | None = None
    verify: bool = True


class ShamirSplitResult(BaseModel):
    """Result of splitting a secret into shares.

    Attributes:
        shares: The individual shares.
        threshold: Minimum shares needed for reconstruction.
        total_shares: Total shares created.
        commitments: Feldman commitments ``g^a_i mod p`` for each
            polynomial coefficient.
    """

    shares: list[Share]
    threshold: int
    total_shares: int
    commitments: list[int] = Field(default_factory=list)


class ShamirSecretSharing:
    """Core Shamir's Secret Sharing with Feldman VSS.

    Splits a secret into *n* shares such that any *k* can reconstruct
    the original.  When ``verify=True`` (and no custom prime is given),
    Feldman commitments allow each share holder to independently verify
    their share.

    The polynomial field is ``GF(q)`` where ``q`` is a 2047-bit Sophie
    Germain prime.  Feldman commitments live in the order-``q`` subgroup
    of ``Z_p*`` where ``p = 2q + 1`` (RFC 3526 Group 14).

    Example:
        >>> sss = ShamirSecretSharing()
        >>> result = sss.split(b"secret")
        >>> recovered = sss.combine(result.shares[:3])
        >>> assert recovered == b"secret"
    """

    # RFC 3526 Group 14 safe prime (p = 2q + 1)
    SAFE_PRIME: int = _GROUP_PRIME

    # Sophie Germain prime (q) -- the polynomial field
    FIELD_PRIME: int = _FIELD_PRIME

    # Generator of the order-q subgroup of Z_p*
    GENERATOR: int = 2

    def __init__(self, config: ShamirConfig | None = None) -> None:
        """Initialise with the given configuration.

        Args:
            config: Shamir configuration.  Defaults to 3-of-5 with
                Feldman verification.

        Raises:
            ValueError: If threshold < 2 or total_shares < threshold.
        """
        self.config = config or ShamirConfig()
        self.prime = self.config.prime or self.FIELD_PRIME

        # Feldman verification is only sound when the polynomial
        # field prime equals q = (p-1)/2 for our safe prime p.
        # When a custom prime is supplied, disable Feldman silently.
        self._feldman_enabled = self.config.verify and self.config.prime is None
        self._group_prime = self.SAFE_PRIME

        if self.config.threshold < 2:
            raise ValueError("Threshold must be at least 2")
        if self.config.total_shares < self.config.threshold:
            raise ValueError("total_shares must be >= threshold")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def split(self, secret: bytes) -> ShamirSplitResult:
        """Split *secret* into shares.

        A ``0x01`` sentinel byte is prepended internally so that
        leading zero bytes survive the integer round-trip.

        Args:
            secret: The secret to split (arbitrary bytes).

        Returns:
            :class:`ShamirSplitResult` with shares and optional
            Feldman commitments.

        Raises:
            ValueError: If the secret is too large for the prime field.
        """
        secret_int = self._bytes_to_int(secret)

        if secret_int >= self.prime:
            raise ValueError(
                "Secret is too large for the configured prime " "field. Use a larger prime."
            )

        coefficients = self._generate_polynomial(secret_int, self.config.threshold - 1)

        shares: list[Share] = []
        commitments: list[int] = []

        if self._feldman_enabled:
            commitments = [pow(self.GENERATOR, c, self._group_prime) for c in coefficients]

        for x in range(1, self.config.total_shares + 1):
            y = self._evaluate_polynomial(coefficients, x)
            shares.append(
                Share(
                    share_id=x,
                    value=y,
                    threshold=self.config.threshold,
                    total_shares=self.config.total_shares,
                    commitment=commitments,
                )
            )

        logger.info(
            "Split secret into %d shares (threshold=%d, verify=%s)",
            self.config.total_shares,
            self.config.threshold,
            self._feldman_enabled,
        )

        return ShamirSplitResult(
            shares=shares,
            threshold=self.config.threshold,
            total_shares=self.config.total_shares,
            commitments=commitments,
        )

    def combine(self, shares: list[Share]) -> bytes:
        """Reconstruct the secret from *shares*.

        Args:
            shares: At least *threshold* shares.

        Returns:
            The original secret bytes.

        Raises:
            ValueError: If fewer than *threshold* shares are provided.
        """
        if not shares:
            raise ValueError("No shares provided")

        threshold = shares[0].threshold
        if len(shares) < threshold:
            raise ValueError(f"Need at least {threshold} shares, " f"got {len(shares)}")

        points = [(s.share_id, s.value) for s in shares]
        secret_int = self._lagrange_interpolation(points)

        logger.info(
            "Reconstructed secret from %d shares (threshold=%d)",
            len(shares),
            threshold,
        )

        return self._int_to_bytes(secret_int)

    def verify_share(self, share: Share, commitments: list[int]) -> bool:
        """Verify a share against Feldman commitments.

        Checks ``g^{P(x)} mod p == prod(C_i^{x^i}) mod p`` where
        ``C_i = g^{a_i} mod p`` and ``g`` has order ``q`` in ``Z_p*``.
        Because the share value is ``P(x) mod q`` and ``g^q = 1``,
        both sides are consistent.

        Args:
            share: The share to verify.
            commitments: Feldman commitments (one per coefficient).

        Returns:
            ``True`` if the share is consistent.
        """
        if not commitments:
            logger.warning("No commitments provided; cannot verify share")
            return False

        p = self._group_prime

        # LHS: g^{share_value} mod p
        lhs = pow(self.GENERATOR, share.value, p)

        # RHS: product of C_i^{x^i} mod p
        rhs = 1
        x = share.share_id
        x_power = 1  # x^0
        for commitment in commitments:
            rhs = (rhs * pow(commitment, x_power, p)) % p
            x_power *= x

        verified = lhs == rhs
        if not verified:
            logger.warning(
                "Share %d failed Feldman verification",
                share.share_id,
            )

        return verified

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _generate_polynomial(self, secret: int, degree: int) -> list[int]:
        """Random polynomial with *secret* as constant term.

        Args:
            secret: Constant term ``a_0``.
            degree: Polynomial degree (threshold - 1).

        Returns:
            Coefficients ``[a_0, a_1, ..., a_degree]``.
        """
        coefficients = [secret]
        for _ in range(degree):
            coefficients.append(secrets.randbelow(self.prime - 1) + 1)
        return coefficients

    def _evaluate_polynomial(self, coefficients: list[int], x: int) -> int:
        """Evaluate polynomial at *x* (Horner's method, mod prime).

        Args:
            coefficients: ``[a_0, a_1, ..., a_d]``.
            x: Evaluation point.

        Returns:
            ``P(x) mod prime``.
        """
        p = self.prime
        result = 0
        for coeff in reversed(coefficients):
            result = (result * x + coeff) % p
        return result

    def _lagrange_interpolation(self, points: list[tuple[int, int]]) -> int:
        """Lagrange interpolation at ``x = 0`` over ``GF(prime)``.

        Args:
            points: ``(x_i, y_i)`` pairs.

        Returns:
            Interpolated value at ``x = 0`` (the secret).
        """
        p = self.prime
        k = len(points)
        secret = 0

        for i in range(k):
            x_i, y_i = points[i]
            numerator = 1
            denominator = 1

            for j in range(k):
                if i == j:
                    continue
                x_j = points[j][0]
                numerator = (numerator * (-x_j)) % p
                denominator = (denominator * (x_i - x_j)) % p

            lagrange_coeff = (numerator * self._mod_inverse(denominator, p)) % p
            secret = (secret + y_i * lagrange_coeff) % p

        return secret

    @staticmethod
    def _mod_inverse(a: int, p: int) -> int:
        """Modular inverse via ``pow(a, -1, p)``.

        Args:
            a: Value to invert.
            p: Prime modulus.

        Returns:
            ``a^{-1} mod p``.
        """
        return pow(a, -1, p)

    @staticmethod
    def _bytes_to_int(data: bytes) -> int:
        """Convert bytes to integer, preserving leading zeros.

        A ``0x01`` sentinel is prepended so that the byte length is
        encoded in the integer value itself.

        Args:
            data: Arbitrary bytes (may be empty).

        Returns:
            Positive integer.
        """
        return int.from_bytes(b"\x01" + data, byteorder="big")

    @staticmethod
    def _int_to_bytes(value: int) -> bytes:
        """Convert a sentinel-prefixed integer back to bytes.

        Args:
            value: Integer from :meth:`_bytes_to_int`.

        Returns:
            Original byte string.
        """
        if value == 0:
            return b""
        byte_length = (value.bit_length() + 7) // 8
        raw = value.to_bytes(byte_length, byteorder="big")
        # Strip the 0x01 sentinel
        if raw and raw[0:1] == b"\x01":
            return raw[1:]
        return raw


class ShamirVaultBackend(VaultBackend):
    """VaultBackend that stores secrets using Shamir's Secret Sharing.

    Secrets are split into shares on :meth:`set_secret` and
    reconstructed from available shares on :meth:`get_secret`.

    Example:
        >>> import asyncio
        >>> from harombe.security.distributed.shamir import ShamirVaultBackend
        >>>
        >>> vault = ShamirVaultBackend()
        >>> asyncio.run(vault.set_secret("api-key", "sk-abc123"))
        >>> value = asyncio.run(vault.get_secret("api-key"))
        >>> assert value == "sk-abc123"
    """

    def __init__(
        self,
        config: ShamirConfig | None = None,
        quorum_shares: list[Share] | None = None,
    ) -> None:
        """Initialise the Shamir vault backend.

        Args:
            config: Shamir configuration.
            quorum_shares: Pre-existing shares for bootstrapping.
        """
        self._sss = ShamirSecretSharing(config)
        self._secrets: dict[str, ShamirSplitResult] = {}
        self._active_shares: dict[str, list[Share]] = {}
        self._quorum_shares = quorum_shares or []

    async def get_secret(self, key: str) -> str | None:
        """Reconstruct a secret from available shares.

        Args:
            key: Secret key/path.

        Returns:
            Secret string, or ``None`` if not found.
        """
        if key not in self._secrets:
            return None

        split_result = self._secrets[key]
        available = self._active_shares.get(key, split_result.shares)

        if len(available) < split_result.threshold:
            logger.warning(
                "Not enough shares to reconstruct '%s' " "(have %d, need %d)",
                key,
                len(available),
                split_result.threshold,
            )
            return None

        secret_bytes = self._sss.combine(available)
        return secret_bytes.decode("utf-8")

    async def set_secret(self, key: str, value: str, **metadata: Any) -> None:
        """Split and store a secret.

        Args:
            key: Secret key/path.
            value: Secret value (UTF-8).
            metadata: Additional metadata (unused).
        """
        split_result = self._sss.split(value.encode("utf-8"))
        self._secrets[key] = split_result
        self._active_shares[key] = list(split_result.shares)

        logger.info(
            "Stored secret '%s' as %d shares (threshold=%d)",
            key,
            split_result.total_shares,
            split_result.threshold,
        )

    async def delete_secret(self, key: str) -> None:
        """Remove a secret and all its shares.

        Args:
            key: Secret key/path.
        """
        self._secrets.pop(key, None)
        self._active_shares.pop(key, None)
        logger.info("Deleted secret '%s'", key)

    async def list_secrets(self, prefix: str = "") -> list[str]:
        """List stored secret keys matching *prefix*.

        Args:
            prefix: Optional key prefix filter.

        Returns:
            List of matching secret keys.
        """
        if prefix:
            return [k for k in self._secrets if k.startswith(prefix)]
        return list(self._secrets.keys())

    async def rotate_secret(self, key: str) -> None:
        """Re-split with a new random polynomial.

        The secret value is unchanged but all shares are regenerated.

        Args:
            key: Secret key/path.

        Raises:
            ValueError: If the secret is missing or unrecoverable.
        """
        if key not in self._secrets:
            raise ValueError(f"Secret '{key}' not found")

        current_value = await self.get_secret(key)
        if current_value is None:
            raise ValueError(f"Cannot reconstruct secret '{key}' for rotation")

        split_result = self._sss.split(current_value.encode("utf-8"))
        self._secrets[key] = split_result
        self._active_shares[key] = list(split_result.shares)

        logger.info("Rotated secret '%s' with new shares", key)
