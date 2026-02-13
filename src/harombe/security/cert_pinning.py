"""TLS certificate pinning for preventing MITM attacks.

This module provides certificate pinning functionality to validate TLS connections
against known good certificates, preventing man-in-the-middle attacks.

Supports multiple pinning strategies:
- Certificate pinning: Pin entire certificate
- Public key pinning: Pin public key from certificate
- SPKI pinning: Pin Subject Public Key Info (recommended by HPKP)

Example:
    >>> from harombe.security.cert_pinning import CertificatePinner, PinningStrategy
    >>>
    >>> # Create pinner
    >>> pinner = CertificatePinner()
    >>>
    >>> # Add pin for domain
    >>> pinner.add_pin(
    ...     domain="api.anthropic.com",
    ...     pin="sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    ...     strategy=PinningStrategy.SPKI,
    ... )
    >>>
    >>> # Verify certificate during TLS handshake
    >>> cert_bytes = get_server_certificate("api.anthropic.com")
    >>> result = pinner.verify_certificate("api.anthropic.com", cert_bytes)
    >>>
    >>> if not result.success:
    ...     print(f"Certificate pinning failed: {result.error}")
"""

import base64
import hashlib
import logging
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class PinningStrategy(StrEnum):
    """Certificate pinning strategy.

    Attributes:
        CERTIFICATE: Pin entire certificate (most strict, requires rotation on cert renewal)
        PUBLIC_KEY: Pin public key from certificate (survives cert renewal if same key)
        SPKI: Pin Subject Public Key Info (recommended, RFC 7469)
    """

    CERTIFICATE = "certificate"
    PUBLIC_KEY = "public_key"
    SPKI = "spki"


class CertificatePin(BaseModel):
    """Certificate pin configuration.

    Attributes:
        domain: Domain name to pin (e.g., "api.anthropic.com")
        pin: Base64-encoded SHA-256 hash of pinned value
        strategy: Pinning strategy to use
        backup: Whether this is a backup pin (for rotation)
        created_at: When pin was created
        expires_at: Optional expiration date for pin
        description: Optional human-readable description
    """

    domain: str
    pin: str
    strategy: PinningStrategy = PinningStrategy.SPKI
    backup: bool = False
    created_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: datetime | None = None
    description: str | None = None


class PinVerificationResult(BaseModel):
    """Result of certificate pin verification.

    Attributes:
        success: Whether verification succeeded
        domain: Domain that was verified
        matched_pin: Pin that matched (if success=True)
        strategy: Strategy used for verification
        error: Error message if verification failed
        all_pins_checked: All pins that were checked
        certificate_info: Information about the certificate
    """

    success: bool
    domain: str
    matched_pin: str | None = None
    strategy: PinningStrategy | None = None
    error: str | None = None
    all_pins_checked: list[str] = Field(default_factory=list)
    certificate_info: dict[str, Any] = Field(default_factory=dict)


class CertificatePinner:
    """TLS certificate pinner for preventing MITM attacks.

    The certificate pinner validates TLS certificates against a known set of pins,
    preventing man-in-the-middle attacks even if a CA is compromised.

    Supports multiple pinning strategies (certificate, public key, SPKI) and
    backup pins for certificate rotation.

    Example:
        >>> pinner = CertificatePinner()
        >>> pinner.add_pin("api.anthropic.com", "sha256/abc123...", PinningStrategy.SPKI)
        >>> result = pinner.verify_certificate("api.anthropic.com", cert_bytes)
        >>> if result.success:
        ...     print("Certificate pinning validation passed")
    """

    def __init__(self, pin_file: Path | None = None):
        """Initialize certificate pinner.

        Args:
            pin_file: Optional path to JSON file containing pins
        """
        self.pins: dict[str, list[CertificatePin]] = {}
        self.pin_file = pin_file
        self.stats = {
            "total_verifications": 0,
            "successful_verifications": 0,
            "failed_verifications": 0,
            "pins_added": 0,
            "pins_removed": 0,
        }

        if pin_file and pin_file.exists():
            self._load_pins_from_file(pin_file)

    def add_pin(
        self,
        domain: str,
        pin: str,
        strategy: PinningStrategy = PinningStrategy.SPKI,
        backup: bool = False,
        expires_at: datetime | None = None,
        description: str | None = None,
    ) -> None:
        """Add certificate pin for domain.

        Args:
            domain: Domain to pin (e.g., "api.anthropic.com")
            pin: Base64-encoded SHA-256 hash (e.g., "sha256/abc123...")
            strategy: Pinning strategy to use
            backup: Whether this is a backup pin
            expires_at: Optional expiration date for pin
            description: Optional description
        """
        if domain not in self.pins:
            self.pins[domain] = []

        cert_pin = CertificatePin(
            domain=domain,
            pin=pin,
            strategy=strategy,
            backup=backup,
            expires_at=expires_at,
            description=description,
        )

        self.pins[domain].append(cert_pin)
        self.stats["pins_added"] += 1

        logger.info(
            f"Added {strategy.value} pin for {domain} "
            f"(backup={backup}, total={len(self.pins[domain])})"
        )

    def remove_pin(self, domain: str, pin: str) -> bool:
        """Remove certificate pin for domain.

        Args:
            domain: Domain to remove pin from
            pin: Pin to remove

        Returns:
            True if pin was removed, False if not found
        """
        if domain not in self.pins:
            return False

        initial_count = len(self.pins[domain])
        self.pins[domain] = [p for p in self.pins[domain] if p.pin != pin]

        removed = len(self.pins[domain]) < initial_count
        if removed:
            self.stats["pins_removed"] += 1
            logger.info(f"Removed pin for {domain}")

        # Clean up empty domain entries
        if not self.pins[domain]:
            del self.pins[domain]

        return removed

    def get_pins(self, domain: str) -> list[CertificatePin]:
        """Get all pins for domain.

        Args:
            domain: Domain to get pins for

        Returns:
            List of certificate pins (empty if none configured)
        """
        return self.pins.get(domain, [])

    def verify_certificate(
        self, domain: str, cert_bytes: bytes, allow_unpinned: bool = True
    ) -> PinVerificationResult:
        """Verify certificate matches pin for domain.

        Args:
            domain: Domain being connected to
            cert_bytes: DER-encoded certificate bytes
            allow_unpinned: Whether to allow domains without pins (default: True)

        Returns:
            PinVerificationResult with success/failure details
        """
        self.stats["total_verifications"] += 1

        # Get pins for domain
        domain_pins = self.pins.get(domain, [])

        # Filter out expired pins
        now = datetime.now(UTC).replace(tzinfo=None)
        active_pins = [p for p in domain_pins if p.expires_at is None or p.expires_at > now]

        if not active_pins:
            if allow_unpinned:
                # No pins configured, accept any valid certificate
                logger.debug(f"No pins configured for {domain}, allowing connection")
                self.stats["successful_verifications"] += 1
                return PinVerificationResult(
                    success=True,
                    domain=domain,
                    error=None,
                )
            else:
                # Require pinning for all domains
                logger.warning(f"No pins configured for {domain}, rejecting connection")
                self.stats["failed_verifications"] += 1
                return PinVerificationResult(
                    success=False,
                    domain=domain,
                    error="No pins configured for domain (pinning required)",
                )

        # Parse certificate
        try:
            cert = x509.load_der_x509_certificate(cert_bytes, default_backend())
        except Exception as e:
            logger.error(f"Failed to parse certificate for {domain}: {e}")
            self.stats["failed_verifications"] += 1
            return PinVerificationResult(
                success=False,
                domain=domain,
                error=f"Failed to parse certificate: {e}",
            )

        # Extract certificate info for logging
        cert_info = self._extract_cert_info(cert)

        # Check each pin
        pins_checked = []
        for pin_config in active_pins:
            pins_checked.append(pin_config.pin)

            # Calculate fingerprint based on strategy
            calculated_pin = self._calculate_pin(cert, pin_config.strategy)

            # Compare pins
            if calculated_pin == pin_config.pin:
                logger.info(
                    f"Certificate pin matched for {domain} "
                    f"(strategy={pin_config.strategy.value}, backup={pin_config.backup})"
                )
                self.stats["successful_verifications"] += 1
                return PinVerificationResult(
                    success=True,
                    domain=domain,
                    matched_pin=pin_config.pin,
                    strategy=pin_config.strategy,
                    all_pins_checked=pins_checked,
                    certificate_info=cert_info,
                )

        # No pins matched
        logger.warning(
            f"Certificate pin validation failed for {domain} " f"(checked {len(pins_checked)} pins)"
        )
        self.stats["failed_verifications"] += 1

        return PinVerificationResult(
            success=False,
            domain=domain,
            error=f"Certificate does not match any of {len(pins_checked)} configured pins",
            all_pins_checked=pins_checked,
            certificate_info=cert_info,
        )

    def _calculate_pin(self, cert: x509.Certificate, strategy: PinningStrategy) -> str:
        """Calculate pin for certificate based on strategy.

        Args:
            cert: Certificate to calculate pin for
            strategy: Pinning strategy to use

        Returns:
            Base64-encoded SHA-256 hash with "sha256/" prefix
        """
        if strategy == PinningStrategy.CERTIFICATE:
            # Pin entire certificate
            data = cert.public_bytes(serialization.Encoding.DER)
        elif strategy == PinningStrategy.PUBLIC_KEY:
            # Pin public key
            public_key = cert.public_key()
            data = public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        elif strategy == PinningStrategy.SPKI:
            # Pin Subject Public Key Info (SPKI) - recommended by RFC 7469
            public_key = cert.public_key()
            data = public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        else:
            raise ValueError(f"Unknown pinning strategy: {strategy}")

        # Calculate SHA-256 hash
        digest = hashlib.sha256(data).digest()

        # Encode as base64
        b64 = base64.b64encode(digest).decode("ascii")

        # Return with sha256/ prefix
        return f"sha256/{b64}"

    def _extract_cert_info(self, cert: x509.Certificate) -> dict[str, Any]:
        """Extract information from certificate for logging.

        Args:
            cert: Certificate to extract info from

        Returns:
            Dictionary with certificate details
        """
        try:
            return {
                "subject": cert.subject.rfc4514_string(),
                "issuer": cert.issuer.rfc4514_string(),
                "not_before": cert.not_valid_before_utc.isoformat(),
                "not_after": cert.not_valid_after_utc.isoformat(),
                "serial_number": hex(cert.serial_number),
            }
        except Exception as e:
            logger.warning(f"Failed to extract certificate info: {e}")
            return {}

    def _load_pins_from_file(self, pin_file: Path) -> None:
        """Load pins from JSON file.

        Args:
            pin_file: Path to JSON file
        """
        import json

        try:
            with open(pin_file) as f:
                data = json.load(f)

            for domain, pins in data.items():
                for pin_data in pins:
                    self.add_pin(
                        domain=domain,
                        pin=pin_data["pin"],
                        strategy=PinningStrategy(pin_data.get("strategy", "spki")),
                        backup=pin_data.get("backup", False),
                        expires_at=(
                            datetime.fromisoformat(pin_data["expires_at"])
                            if pin_data.get("expires_at")
                            else None
                        ),
                        description=pin_data.get("description"),
                    )

            logger.info(f"Loaded {len(self.pins)} domains from {pin_file}")
        except Exception as e:
            logger.error(f"Failed to load pins from {pin_file}: {e}")

    def save_pins_to_file(self, pin_file: Path | None = None) -> None:
        """Save pins to JSON file.

        Args:
            pin_file: Path to JSON file (uses self.pin_file if not specified)
        """
        import json

        output_file = pin_file or self.pin_file
        if not output_file:
            raise ValueError("No pin file specified")

        data = {}
        for domain, pins in self.pins.items():
            data[domain] = [
                {
                    "pin": p.pin,
                    "strategy": p.strategy.value,
                    "backup": p.backup,
                    "created_at": p.created_at.isoformat(),
                    "expires_at": p.expires_at.isoformat() if p.expires_at else None,
                    "description": p.description,
                }
                for p in pins
            ]

        try:
            with open(output_file, "w") as f:
                json.dump(data, f, indent=2)
            logger.info(f"Saved {len(self.pins)} domains to {output_file}")
        except Exception as e:
            logger.error(f"Failed to save pins to {output_file}: {e}")
            raise

    def get_stats(self) -> dict[str, int]:
        """Get statistics about certificate pinning operations.

        Returns:
            Dictionary with operation counts
        """
        return self.stats.copy()

    def clear_all_pins(self) -> int:
        """Clear all configured pins.

        Returns:
            Number of pins that were removed
        """
        total_pins = sum(len(pins) for pins in self.pins.values())
        self.pins.clear()
        self.stats["pins_removed"] += total_pins
        logger.warning(f"Cleared all {total_pins} pins")
        return total_pins


def calculate_certificate_pin(
    cert_bytes: bytes, strategy: PinningStrategy = PinningStrategy.SPKI
) -> str:
    """Calculate certificate pin for given certificate.

    Utility function to calculate a pin from a certificate without creating
    a CertificatePinner instance.

    Args:
        cert_bytes: DER-encoded certificate bytes
        strategy: Pinning strategy to use

    Returns:
        Base64-encoded SHA-256 hash with "sha256/" prefix

    Example:
        >>> from pathlib import Path
        >>> cert_bytes = Path("cert.pem").read_bytes()
        >>> pin = calculate_certificate_pin(cert_bytes, PinningStrategy.SPKI)
        >>> print(f"Pin: {pin}")
    """
    pinner = CertificatePinner()
    cert = x509.load_der_x509_certificate(cert_bytes, default_backend())
    return pinner._calculate_pin(cert, strategy)
