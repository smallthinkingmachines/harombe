"""Tests for TLS certificate pinning."""

from datetime import datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from harombe.security.cert_pinning import (
    CertificatePin,
    CertificatePinner,
    PinningStrategy,
    PinVerificationResult,
    calculate_certificate_pin,
)


@pytest.fixture
def test_cert():
    """Generate test certificate."""
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )

    # Create certificate
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org"),
            x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com"),
        ]
    )

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .sign(private_key, hashes.SHA256(), default_backend())
    )

    return cert


@pytest.fixture
def test_cert_bytes(test_cert):
    """Get DER-encoded certificate bytes."""
    return test_cert.public_bytes(serialization.Encoding.DER)


@pytest.fixture
def cert_pinner():
    """Create certificate pinner."""
    return CertificatePinner()


# Enum Tests


def test_pinning_strategy_values():
    """Test PinningStrategy enum values."""
    assert PinningStrategy.CERTIFICATE == "certificate"
    assert PinningStrategy.PUBLIC_KEY == "public_key"
    assert PinningStrategy.SPKI == "spki"


# Model Tests


def test_certificate_pin_creation():
    """Test CertificatePin model creation."""
    pin = CertificatePin(
        domain="api.example.com",
        pin="sha256/abc123",
        strategy=PinningStrategy.SPKI,
        backup=False,
        description="Production API pin",
    )

    assert pin.domain == "api.example.com"
    assert pin.pin == "sha256/abc123"
    assert pin.strategy == PinningStrategy.SPKI
    assert pin.backup is False
    assert pin.description == "Production API pin"
    assert pin.created_at is not None
    assert pin.expires_at is None


def test_certificate_pin_with_expiration():
    """Test CertificatePin with expiration date."""
    expires = datetime.utcnow() + timedelta(days=90)
    pin = CertificatePin(
        domain="api.example.com",
        pin="sha256/abc123",
        expires_at=expires,
    )

    assert pin.expires_at == expires


def test_pin_verification_result_success():
    """Test PinVerificationResult for successful verification."""
    result = PinVerificationResult(
        success=True,
        domain="api.example.com",
        matched_pin="sha256/abc123",
        strategy=PinningStrategy.SPKI,
        certificate_info={"subject": "CN=api.example.com"},
    )

    assert result.success is True
    assert result.domain == "api.example.com"
    assert result.matched_pin == "sha256/abc123"
    assert result.strategy == PinningStrategy.SPKI
    assert result.error is None


def test_pin_verification_result_failure():
    """Test PinVerificationResult for failed verification."""
    result = PinVerificationResult(
        success=False,
        domain="api.example.com",
        error="Certificate does not match pin",
        all_pins_checked=["sha256/abc123", "sha256/def456"],
    )

    assert result.success is False
    assert result.error == "Certificate does not match pin"
    assert len(result.all_pins_checked) == 2


# CertificatePinner Tests


def test_pinner_initialization(cert_pinner):
    """Test CertificatePinner initialization."""
    assert cert_pinner.pins == {}
    assert cert_pinner.stats["total_verifications"] == 0


def test_add_pin(cert_pinner):
    """Test adding a pin."""
    cert_pinner.add_pin(
        domain="api.example.com",
        pin="sha256/abc123",
        strategy=PinningStrategy.SPKI,
    )

    pins = cert_pinner.get_pins("api.example.com")
    assert len(pins) == 1
    assert pins[0].domain == "api.example.com"
    assert pins[0].pin == "sha256/abc123"
    assert pins[0].strategy == PinningStrategy.SPKI
    assert cert_pinner.stats["pins_added"] == 1


def test_add_multiple_pins_same_domain(cert_pinner):
    """Test adding multiple pins for same domain."""
    cert_pinner.add_pin("api.example.com", "sha256/abc123", PinningStrategy.SPKI)
    cert_pinner.add_pin("api.example.com", "sha256/def456", PinningStrategy.SPKI, backup=True)

    pins = cert_pinner.get_pins("api.example.com")
    assert len(pins) == 2
    assert pins[0].backup is False
    assert pins[1].backup is True


def test_add_backup_pin(cert_pinner):
    """Test adding backup pin for rotation."""
    cert_pinner.add_pin(
        "api.example.com",
        "sha256/backup123",
        strategy=PinningStrategy.SPKI,
        backup=True,
        description="Backup pin for certificate rotation",
    )

    pins = cert_pinner.get_pins("api.example.com")
    assert len(pins) == 1
    assert pins[0].backup is True
    assert pins[0].description == "Backup pin for certificate rotation"


def test_remove_pin(cert_pinner):
    """Test removing a pin."""
    cert_pinner.add_pin("api.example.com", "sha256/abc123")
    cert_pinner.add_pin("api.example.com", "sha256/def456")

    removed = cert_pinner.remove_pin("api.example.com", "sha256/abc123")
    assert removed is True

    pins = cert_pinner.get_pins("api.example.com")
    assert len(pins) == 1
    assert pins[0].pin == "sha256/def456"
    assert cert_pinner.stats["pins_removed"] == 1


def test_remove_nonexistent_pin(cert_pinner):
    """Test removing pin that doesn't exist."""
    removed = cert_pinner.remove_pin("api.example.com", "sha256/nonexistent")
    assert removed is False


def test_remove_last_pin_cleans_up_domain(cert_pinner):
    """Test that removing last pin removes domain entry."""
    cert_pinner.add_pin("api.example.com", "sha256/abc123")

    cert_pinner.remove_pin("api.example.com", "sha256/abc123")

    assert "api.example.com" not in cert_pinner.pins


def test_get_pins_no_pins(cert_pinner):
    """Test getting pins for domain with no pins."""
    pins = cert_pinner.get_pins("api.example.com")
    assert pins == []


def test_verify_certificate_no_pins_allowed(cert_pinner, test_cert_bytes):
    """Test verification with no pins configured (default: allow)."""
    result = cert_pinner.verify_certificate("api.example.com", test_cert_bytes, allow_unpinned=True)

    assert result.success is True
    assert result.domain == "api.example.com"
    assert result.matched_pin is None
    assert cert_pinner.stats["successful_verifications"] == 1


def test_verify_certificate_no_pins_disallowed(cert_pinner, test_cert_bytes):
    """Test verification with no pins configured (require pinning)."""
    result = cert_pinner.verify_certificate(
        "api.example.com", test_cert_bytes, allow_unpinned=False
    )

    assert result.success is False
    assert "No pins configured" in result.error
    assert cert_pinner.stats["failed_verifications"] == 1


def test_verify_certificate_matching_pin(cert_pinner, test_cert, test_cert_bytes):
    """Test verification with matching pin."""
    # Calculate correct pin
    pinner_temp = CertificatePinner()
    correct_pin = pinner_temp._calculate_pin(test_cert, PinningStrategy.SPKI)

    # Add pin
    cert_pinner.add_pin("api.example.com", correct_pin, PinningStrategy.SPKI)

    # Verify
    result = cert_pinner.verify_certificate("api.example.com", test_cert_bytes)

    assert result.success is True
    assert result.matched_pin == correct_pin
    assert result.strategy == PinningStrategy.SPKI
    assert cert_pinner.stats["successful_verifications"] == 1


def test_verify_certificate_wrong_pin(cert_pinner, test_cert_bytes):
    """Test verification with wrong pin."""
    # Add wrong pin
    cert_pinner.add_pin("api.example.com", "sha256/wrongpinwrongpin==")

    # Verify
    result = cert_pinner.verify_certificate("api.example.com", test_cert_bytes)

    assert result.success is False
    assert "does not match" in result.error
    assert len(result.all_pins_checked) == 1
    assert cert_pinner.stats["failed_verifications"] == 1


def test_verify_certificate_multiple_pins_second_matches(cert_pinner, test_cert, test_cert_bytes):
    """Test verification with multiple pins where second one matches."""
    # Add wrong pin first
    cert_pinner.add_pin("api.example.com", "sha256/wrongpin1==")

    # Add correct pin
    pinner_temp = CertificatePinner()
    correct_pin = pinner_temp._calculate_pin(test_cert, PinningStrategy.SPKI)
    cert_pinner.add_pin("api.example.com", correct_pin, PinningStrategy.SPKI)

    # Verify
    result = cert_pinner.verify_certificate("api.example.com", test_cert_bytes)

    assert result.success is True
    assert result.matched_pin == correct_pin


def test_verify_certificate_backup_pin_matches(cert_pinner, test_cert, test_cert_bytes):
    """Test verification where backup pin matches."""
    # Calculate correct pin
    pinner_temp = CertificatePinner()
    correct_pin = pinner_temp._calculate_pin(test_cert, PinningStrategy.SPKI)

    # Add as backup pin
    cert_pinner.add_pin("api.example.com", correct_pin, PinningStrategy.SPKI, backup=True)

    # Verify
    result = cert_pinner.verify_certificate("api.example.com", test_cert_bytes)

    assert result.success is True
    assert result.matched_pin == correct_pin


def test_verify_certificate_expired_pin_ignored(cert_pinner, test_cert_bytes):
    """Test that expired pins are ignored during verification."""
    # Add expired pin
    expired = datetime.utcnow() - timedelta(days=1)
    cert_pinner.add_pin(
        "api.example.com",
        "sha256/expiredpin==",
        expires_at=expired,
    )

    # Verify (should succeed since expired pin is ignored and allow_unpinned=True)
    result = cert_pinner.verify_certificate("api.example.com", test_cert_bytes)

    assert result.success is True


def test_verify_certificate_invalid_cert_bytes(cert_pinner):
    """Test verification with invalid certificate bytes."""
    cert_pinner.add_pin("api.example.com", "sha256/somepin==")

    result = cert_pinner.verify_certificate("api.example.com", b"invalid cert data")

    assert result.success is False
    assert "Failed to parse certificate" in result.error


def test_verify_certificate_includes_cert_info(cert_pinner, test_cert, test_cert_bytes):
    """Test that verification result includes certificate info."""
    # Calculate correct pin
    pinner_temp = CertificatePinner()
    correct_pin = pinner_temp._calculate_pin(test_cert, PinningStrategy.SPKI)
    cert_pinner.add_pin("api.example.com", correct_pin)

    result = cert_pinner.verify_certificate("api.example.com", test_cert_bytes)

    assert result.success is True
    assert "subject" in result.certificate_info
    assert "issuer" in result.certificate_info
    assert "serial_number" in result.certificate_info


def test_calculate_pin_spki_strategy(cert_pinner, test_cert):
    """Test calculating SPKI pin."""
    pin = cert_pinner._calculate_pin(test_cert, PinningStrategy.SPKI)

    assert pin.startswith("sha256/")
    assert len(pin) > 10  # Has base64 encoded hash


def test_calculate_pin_certificate_strategy(cert_pinner, test_cert):
    """Test calculating certificate pin."""
    pin = cert_pinner._calculate_pin(test_cert, PinningStrategy.CERTIFICATE)

    assert pin.startswith("sha256/")
    # Certificate pin should differ from SPKI pin
    spki_pin = cert_pinner._calculate_pin(test_cert, PinningStrategy.SPKI)
    assert pin != spki_pin


def test_calculate_pin_public_key_strategy(cert_pinner, test_cert):
    """Test calculating public key pin."""
    pin = cert_pinner._calculate_pin(test_cert, PinningStrategy.PUBLIC_KEY)

    assert pin.startswith("sha256/")


def test_different_strategies_produce_different_pins(cert_pinner, test_cert):
    """Test that different strategies produce different pins."""
    cert_pin = cert_pinner._calculate_pin(test_cert, PinningStrategy.CERTIFICATE)
    pubkey_pin = cert_pinner._calculate_pin(test_cert, PinningStrategy.PUBLIC_KEY)
    spki_pin = cert_pinner._calculate_pin(test_cert, PinningStrategy.SPKI)

    # SPKI and PUBLIC_KEY should be the same (both use SPKI format)
    assert spki_pin == pubkey_pin

    # Certificate pin should differ
    assert cert_pin != spki_pin


def test_get_stats(cert_pinner, test_cert_bytes):
    """Test getting statistics."""
    cert_pinner.add_pin("api.example.com", "sha256/pin1==")
    cert_pinner.add_pin("api.example.com", "sha256/pin2==")
    cert_pinner.verify_certificate("api.example.com", test_cert_bytes)
    cert_pinner.remove_pin("api.example.com", "sha256/pin1==")

    stats = cert_pinner.get_stats()

    assert stats["pins_added"] == 2
    assert stats["pins_removed"] == 1
    assert stats["total_verifications"] == 1
    # Verification fails because pins don't match the test certificate
    assert stats["failed_verifications"] == 1


def test_clear_all_pins(cert_pinner):
    """Test clearing all pins."""
    cert_pinner.add_pin("api1.example.com", "sha256/pin1==")
    cert_pinner.add_pin("api2.example.com", "sha256/pin2==")
    cert_pinner.add_pin("api2.example.com", "sha256/pin3==")

    count = cert_pinner.clear_all_pins()

    assert count == 3
    assert cert_pinner.pins == {}
    assert cert_pinner.stats["pins_removed"] == 3


def test_save_and_load_pins(cert_pinner, tmp_path):
    """Test saving and loading pins from file."""
    pin_file = tmp_path / "pins.json"

    # Add some pins
    cert_pinner.add_pin("api1.example.com", "sha256/pin1==", PinningStrategy.SPKI)
    cert_pinner.add_pin(
        "api2.example.com",
        "sha256/pin2==",
        PinningStrategy.CERTIFICATE,
        backup=True,
        description="Backup pin",
    )

    # Save
    cert_pinner.save_pins_to_file(pin_file)

    assert pin_file.exists()

    # Load into new pinner
    new_pinner = CertificatePinner(pin_file=pin_file)

    # Verify loaded correctly
    pins1 = new_pinner.get_pins("api1.example.com")
    assert len(pins1) == 1
    assert pins1[0].pin == "sha256/pin1=="
    assert pins1[0].strategy == PinningStrategy.SPKI

    pins2 = new_pinner.get_pins("api2.example.com")
    assert len(pins2) == 1
    assert pins2[0].pin == "sha256/pin2=="
    assert pins2[0].backup is True
    assert pins2[0].description == "Backup pin"


def test_load_pins_from_nonexistent_file(tmp_path):
    """Test loading from nonexistent file."""
    pin_file = tmp_path / "nonexistent.json"
    pinner = CertificatePinner(pin_file=pin_file)

    # Should not raise error, just have no pins
    assert pinner.pins == {}


def test_save_pins_without_file_specified():
    """Test saving pins without specifying file."""
    pinner = CertificatePinner()  # No pin_file
    pinner.add_pin("api.example.com", "sha256/pin1==")

    with pytest.raises(ValueError, match="No pin file specified"):
        pinner.save_pins_to_file()


# Utility Function Tests


def test_calculate_certificate_pin_utility(test_cert_bytes):
    """Test calculate_certificate_pin utility function."""
    pin = calculate_certificate_pin(test_cert_bytes, PinningStrategy.SPKI)

    assert pin.startswith("sha256/")
    assert len(pin) > 10


def test_calculate_certificate_pin_different_strategies(test_cert_bytes):
    """Test utility function with different strategies."""
    spki_pin = calculate_certificate_pin(test_cert_bytes, PinningStrategy.SPKI)
    cert_pin = calculate_certificate_pin(test_cert_bytes, PinningStrategy.CERTIFICATE)

    assert spki_pin != cert_pin


# Integration Tests


@pytest.mark.integration
def test_end_to_end_pin_verification(test_cert, test_cert_bytes):
    """Test end-to-end pin verification workflow."""
    # Setup pinner
    pinner = CertificatePinner()

    # Calculate pin from certificate
    pin = calculate_certificate_pin(test_cert_bytes, PinningStrategy.SPKI)

    # Add pin
    pinner.add_pin("api.example.com", pin, PinningStrategy.SPKI)

    # Verify certificate
    result = pinner.verify_certificate("api.example.com", test_cert_bytes)

    assert result.success is True
    assert result.matched_pin == pin
    assert result.strategy == PinningStrategy.SPKI


@pytest.mark.integration
def test_pin_rotation_workflow(test_cert, test_cert_bytes):
    """Test certificate pin rotation workflow with backup pins."""
    pinner = CertificatePinner()

    # Add current pin
    current_pin = calculate_certificate_pin(test_cert_bytes, PinningStrategy.SPKI)
    pinner.add_pin("api.example.com", current_pin, PinningStrategy.SPKI, backup=False)

    # Add backup pin for new certificate (fake pin)
    pinner.add_pin(
        "api.example.com",
        "sha256/newcertpin==",
        PinningStrategy.SPKI,
        backup=True,
    )

    # Current certificate still validates
    result = pinner.verify_certificate("api.example.com", test_cert_bytes)
    assert result.success is True
    assert result.matched_pin == current_pin

    # After rotation, remove old pin
    pinner.remove_pin("api.example.com", current_pin)

    # Now only backup pin remains
    pins = pinner.get_pins("api.example.com")
    assert len(pins) == 1
    assert pins[0].backup is True


@pytest.mark.integration
def test_multiple_domains_with_different_strategies(test_cert, test_cert_bytes):
    """Test pinning multiple domains with different strategies."""
    pinner = CertificatePinner()

    # Domain 1: SPKI pinning
    spki_pin = calculate_certificate_pin(test_cert_bytes, PinningStrategy.SPKI)
    pinner.add_pin("api1.example.com", spki_pin, PinningStrategy.SPKI)

    # Domain 2: Certificate pinning
    cert_pin = calculate_certificate_pin(test_cert_bytes, PinningStrategy.CERTIFICATE)
    pinner.add_pin("api2.example.com", cert_pin, PinningStrategy.CERTIFICATE)

    # Verify both work
    result1 = pinner.verify_certificate("api1.example.com", test_cert_bytes)
    assert result1.success is True
    assert result1.strategy == PinningStrategy.SPKI

    result2 = pinner.verify_certificate("api2.example.com", test_cert_bytes)
    assert result2.success is True
    assert result2.strategy == PinningStrategy.CERTIFICATE
