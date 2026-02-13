"""Tests for the hardware-backed attestation module."""

from datetime import UTC, datetime, timedelta

import pytest

from harombe.security.hardware.attestation import (
    AttestationGenerator,
    AttestationPolicy,
    AttestationReport,
    AttestationType,
    AttestationVerifier,
    RemoteAttestationService,
)
from harombe.security.hardware.enclave import EnclaveManager
from harombe.security.hardware.tpm import SoftwareTPM, TPMKeyManager

# ---------------------------------------------------------------------------
# AttestationType enum tests
# ---------------------------------------------------------------------------


async def test_attestation_type_software_value():
    """SOFTWARE enum has the expected string value."""
    assert AttestationType.SOFTWARE == "software"


async def test_attestation_type_tpm_value():
    """TPM enum has the expected string value."""
    assert AttestationType.TPM == "tpm"


async def test_attestation_type_enclave_value():
    """ENCLAVE enum has the expected string value."""
    assert AttestationType.ENCLAVE == "enclave"


async def test_attestation_type_remote_value():
    """REMOTE enum has the expected string value."""
    assert AttestationType.REMOTE == "remote"


async def test_attestation_type_member_count():
    """AttestationType has exactly 4 members."""
    assert len(AttestationType) == 4


# ---------------------------------------------------------------------------
# AttestationPolicy tests
# ---------------------------------------------------------------------------


async def test_attestation_policy_defaults():
    """AttestationPolicy has correct default values."""
    policy = AttestationPolicy(policy_id="test-policy")
    assert policy.policy_id == "test-policy"
    assert policy.required_type == AttestationType.SOFTWARE
    assert policy.min_freshness_seconds == 300
    assert policy.required_measurements == []
    assert policy.allow_debug is False
    assert policy.nonce_required is True


async def test_attestation_policy_custom():
    """AttestationPolicy accepts custom values."""
    policy = AttestationPolicy(
        policy_id="custom-policy",
        required_type=AttestationType.TPM,
        min_freshness_seconds=60,
        required_measurements=["python_version", "os_info"],
        allow_debug=True,
        nonce_required=False,
    )
    assert policy.required_type == AttestationType.TPM
    assert policy.min_freshness_seconds == 60
    assert policy.required_measurements == [
        "python_version",
        "os_info",
    ]
    assert policy.allow_debug is True
    assert policy.nonce_required is False


# ---------------------------------------------------------------------------
# AttestationReport tests
# ---------------------------------------------------------------------------


async def test_attestation_report_creation():
    """AttestationReport can be created with defaults."""
    report = AttestationReport(
        report_id="rpt-1",
        attestation_type=AttestationType.SOFTWARE,
    )
    assert report.report_id == "rpt-1"
    assert report.attestation_type == AttestationType.SOFTWARE
    assert report.timestamp is not None
    assert report.measurements == {}
    assert report.nonce is None
    assert report.signature is None
    assert report.platform_info == {}
    assert report.valid is False


async def test_attestation_report_with_measurements():
    """AttestationReport stores measurements correctly."""
    report = AttestationReport(
        report_id="rpt-2",
        attestation_type=AttestationType.TPM,
        measurements={
            "python_version": "abc123",
            "os_info": "def456",
        },
        nonce="test-nonce",
    )
    assert len(report.measurements) == 2
    assert report.measurements["python_version"] == "abc123"
    assert report.nonce == "test-nonce"


# ---------------------------------------------------------------------------
# AttestationGenerator tests
# ---------------------------------------------------------------------------


async def test_generator_generate_report_software():
    """Generator produces a valid SOFTWARE attestation report."""
    generator = AttestationGenerator()
    report = await generator.generate_report()

    assert report.attestation_type == AttestationType.SOFTWARE
    assert report.valid is True
    assert report.signature is not None
    assert len(report.signature) > 0
    assert report.report_id != ""


async def test_generator_report_contains_measurements():
    """Generated report includes expected platform measurements."""
    generator = AttestationGenerator()
    report = await generator.generate_report()

    assert "python_version" in report.measurements
    assert "os_info" in report.measurements
    assert "architecture" in report.measurements
    assert "module_integrity" in report.measurements
    # Each measurement is a hex-encoded SHA-256 (64 chars)
    for value in report.measurements.values():
        assert len(value) == 64


async def test_generator_report_contains_platform_info():
    """Generated report includes platform info."""
    generator = AttestationGenerator()
    report = await generator.generate_report()

    assert "python_version" in report.platform_info
    assert "os" in report.platform_info
    assert "architecture" in report.platform_info


async def test_generator_report_with_nonce():
    """Generator includes nonce in the report when provided."""
    generator = AttestationGenerator()
    report = await generator.generate_report(nonce="my-nonce-123")

    assert report.nonce == "my-nonce-123"


async def test_generator_generate_nonce_uniqueness():
    """Each generated nonce is unique."""
    generator = AttestationGenerator()
    nonces = set()
    for _ in range(20):
        nonce = await generator.generate_nonce()
        nonces.add(nonce)

    assert len(nonces) == 20


async def test_generator_nonce_is_hex_64_chars():
    """Generated nonce is a 64-character hex string (32 bytes)."""
    generator = AttestationGenerator()
    nonce = await generator.generate_nonce()

    assert len(nonce) == 64
    # Verify it's valid hex
    int(nonce, 16)


async def test_generator_report_ids_are_unique():
    """Each generated report has a unique ID."""
    generator = AttestationGenerator()
    ids = set()
    for _ in range(10):
        report = await generator.generate_report()
        ids.add(report.report_id)

    assert len(ids) == 10


# ---------------------------------------------------------------------------
# AttestationGenerator with TPM
# ---------------------------------------------------------------------------


async def test_generator_with_tpm_manager():
    """Generator uses TPM for signing when a TPM manager is provided."""
    tpm = SoftwareTPM()
    await tpm.initialize()
    tpm_manager = TPMKeyManager(backend=tpm)

    generator = AttestationGenerator(tpm_manager=tpm_manager)
    report = await generator.generate_report(attestation_type=AttestationType.TPM)

    assert report.valid is True
    assert report.signature is not None
    assert "tpm_key_id" in report.platform_info


async def test_generator_tpm_fallback_without_manager():
    """Generator falls back to software when no TPM manager is set."""
    generator = AttestationGenerator()
    report = await generator.generate_report(attestation_type=AttestationType.TPM)

    # Falls back to software signing
    assert report.valid is True
    assert report.signature is not None


# ---------------------------------------------------------------------------
# AttestationGenerator with Enclave
# ---------------------------------------------------------------------------


async def test_generator_with_enclave_manager():
    """Generator uses enclave attestation when manager is provided."""
    enclave_manager = EnclaveManager()
    generator = AttestationGenerator(enclave_manager=enclave_manager)
    report = await generator.generate_report(attestation_type=AttestationType.ENCLAVE)

    assert report.valid is True
    assert report.signature is not None
    assert "enclave_id" in report.platform_info
    # Enclave measurements should be merged in
    enclave_keys = [k for k in report.measurements if k.startswith("enclave_")]
    assert len(enclave_keys) > 0


async def test_generator_enclave_fallback_without_manager():
    """Generator falls back to software when no enclave manager is set."""
    generator = AttestationGenerator()
    report = await generator.generate_report(attestation_type=AttestationType.ENCLAVE)

    assert report.valid is True
    assert report.signature is not None


# ---------------------------------------------------------------------------
# AttestationVerifier tests
# ---------------------------------------------------------------------------


async def test_verifier_valid_report():
    """Verifier accepts a fresh, correctly signed report."""
    generator = AttestationGenerator()
    nonce = await generator.generate_nonce()
    report = await generator.generate_report(nonce=nonce)

    policy = AttestationPolicy(
        policy_id="test",
        nonce_required=True,
    )
    verifier = AttestationVerifier()

    valid = await verifier.verify_report(
        report, policy, expected_nonce=nonce, hmac_key=generator.hmac_key
    )
    assert valid is True


async def test_verifier_fails_expired_report():
    """Verifier rejects a report that exceeds the freshness window."""
    generator = AttestationGenerator()
    nonce = await generator.generate_nonce()
    report = await generator.generate_report(nonce=nonce)

    # Make the report appear old
    report.timestamp = datetime.now(UTC).replace(tzinfo=None) - timedelta(seconds=600)

    policy = AttestationPolicy(
        policy_id="test",
        min_freshness_seconds=300,
        nonce_required=True,
    )
    verifier = AttestationVerifier()

    valid = await verifier.verify_report(
        report, policy, expected_nonce=nonce, hmac_key=generator.hmac_key
    )
    assert valid is False


async def test_verifier_fails_wrong_nonce():
    """Verifier rejects a report with a non-matching nonce."""
    generator = AttestationGenerator()
    report = await generator.generate_report(nonce="correct-nonce")

    policy = AttestationPolicy(
        policy_id="test",
        nonce_required=True,
    )
    verifier = AttestationVerifier()

    valid = await verifier.verify_report(
        report,
        policy,
        expected_nonce="wrong-nonce",
        hmac_key=generator.hmac_key,
    )
    assert valid is False


async def test_verifier_fails_missing_nonce():
    """Verifier rejects when policy requires nonce but none provided."""
    generator = AttestationGenerator()
    report = await generator.generate_report()

    policy = AttestationPolicy(
        policy_id="test",
        nonce_required=True,
    )
    verifier = AttestationVerifier()

    # No expected_nonce provided
    valid = await verifier.verify_report(report, policy)
    assert valid is False


async def test_verifier_fails_missing_measurements():
    """Verifier rejects reports lacking required measurements."""
    generator = AttestationGenerator()
    nonce = await generator.generate_nonce()
    report = await generator.generate_report(nonce=nonce)

    policy = AttestationPolicy(
        policy_id="test",
        required_measurements=["nonexistent_measurement"],
        nonce_required=True,
    )
    verifier = AttestationVerifier()

    valid = await verifier.verify_report(
        report, policy, expected_nonce=nonce, hmac_key=generator.hmac_key
    )
    assert valid is False


async def test_verifier_passes_with_present_measurements():
    """Verifier accepts reports that have all required measurements."""
    generator = AttestationGenerator()
    nonce = await generator.generate_nonce()
    report = await generator.generate_report(nonce=nonce)

    policy = AttestationPolicy(
        policy_id="test",
        required_measurements=["python_version", "os_info"],
        nonce_required=True,
    )
    verifier = AttestationVerifier()

    valid = await verifier.verify_report(
        report, policy, expected_nonce=nonce, hmac_key=generator.hmac_key
    )
    assert valid is True


async def test_verifier_fails_bad_hmac_signature():
    """Verifier rejects a report with an invalid HMAC signature."""
    generator = AttestationGenerator()
    nonce = await generator.generate_nonce()
    report = await generator.generate_report(nonce=nonce)

    policy = AttestationPolicy(
        policy_id="test",
        nonce_required=True,
    )
    verifier = AttestationVerifier()

    # Use a wrong HMAC key
    wrong_key = b"wrong-key-material-for-hmac-test"
    valid = await verifier.verify_report(report, policy, expected_nonce=nonce, hmac_key=wrong_key)
    assert valid is False


async def test_verifier_debug_mode_rejected_by_default():
    """Verifier rejects debug-mode reports when policy disallows it."""
    generator = AttestationGenerator()
    nonce = await generator.generate_nonce()
    report = await generator.generate_report(nonce=nonce)
    report.platform_info["debug_mode"] = True

    policy = AttestationPolicy(
        policy_id="test",
        allow_debug=False,
        nonce_required=True,
    )
    verifier = AttestationVerifier()

    valid = await verifier.verify_report(
        report, policy, expected_nonce=nonce, hmac_key=generator.hmac_key
    )
    assert valid is False


async def test_verifier_debug_mode_allowed_by_policy():
    """Verifier accepts debug-mode reports when policy allows it."""
    generator = AttestationGenerator()
    nonce = await generator.generate_nonce()
    report = await generator.generate_report(nonce=nonce)
    report.platform_info["debug_mode"] = True

    policy = AttestationPolicy(
        policy_id="test",
        allow_debug=True,
        nonce_required=True,
    )
    verifier = AttestationVerifier()

    valid = await verifier.verify_report(
        report, policy, expected_nonce=nonce, hmac_key=generator.hmac_key
    )
    assert valid is True


async def test_verifier_nonce_not_required():
    """Verifier accepts reports without nonce when policy allows it."""
    generator = AttestationGenerator()
    report = await generator.generate_report()

    policy = AttestationPolicy(
        policy_id="test",
        nonce_required=False,
    )
    verifier = AttestationVerifier()

    valid = await verifier.verify_report(report, policy)
    assert valid is True


async def test_verifier_tpm_signature():
    """Verifier successfully verifies a TPM-signed report."""
    tpm = SoftwareTPM()
    await tpm.initialize()
    tpm_manager = TPMKeyManager(backend=tpm)

    generator = AttestationGenerator(tpm_manager=tpm_manager)
    verifier = AttestationVerifier(tpm_manager=tpm_manager)

    nonce = await generator.generate_nonce()
    report = await generator.generate_report(attestation_type=AttestationType.TPM, nonce=nonce)

    policy = AttestationPolicy(
        policy_id="tpm-policy",
        required_type=AttestationType.TPM,
        nonce_required=True,
    )

    valid = await verifier.verify_report(report, policy, expected_nonce=nonce)
    assert valid is True


# ---------------------------------------------------------------------------
# RemoteAttestationService tests
# ---------------------------------------------------------------------------


async def test_remote_service_create_challenge():
    """create_challenge returns a dict with challenge_id and nonce."""
    generator = AttestationGenerator()
    verifier = AttestationVerifier()
    service = RemoteAttestationService(generator, verifier)

    challenge = await service.create_challenge()

    assert "challenge_id" in challenge
    assert "nonce" in challenge
    assert len(challenge["nonce"]) == 64  # 32 bytes hex


async def test_remote_service_respond_to_challenge():
    """respond_to_challenge produces a report with the correct nonce."""
    generator = AttestationGenerator()
    verifier = AttestationVerifier()
    service = RemoteAttestationService(generator, verifier)

    challenge = await service.create_challenge()
    report = await service.respond_to_challenge(challenge["challenge_id"], challenge["nonce"])

    assert report.nonce == challenge["nonce"]
    assert report.attestation_type == AttestationType.REMOTE
    assert report.valid is True


async def test_remote_service_respond_unknown_challenge():
    """respond_to_challenge raises ValueError for unknown challenge."""
    generator = AttestationGenerator()
    verifier = AttestationVerifier()
    service = RemoteAttestationService(generator, verifier)

    with pytest.raises(ValueError, match="Unknown challenge"):
        await service.respond_to_challenge("bad-id", "bad-nonce")


async def test_remote_service_verify_response_succeeds():
    """Full challenge-response cycle succeeds."""
    generator = AttestationGenerator()
    verifier = AttestationVerifier()
    service = RemoteAttestationService(generator, verifier)

    challenge = await service.create_challenge()
    report = await service.respond_to_challenge(challenge["challenge_id"], challenge["nonce"])
    valid = await service.verify_response(report, challenge["challenge_id"])

    assert valid is True


async def test_remote_service_replay_prevention():
    """A nonce cannot be used twice (replay prevention)."""
    generator = AttestationGenerator()
    verifier = AttestationVerifier()
    service = RemoteAttestationService(generator, verifier)

    challenge = await service.create_challenge()
    report = await service.respond_to_challenge(challenge["challenge_id"], challenge["nonce"])

    # First verification succeeds
    valid1 = await service.verify_response(report, challenge["challenge_id"])
    assert valid1 is True

    # Second verification fails -- nonce was consumed
    valid2 = await service.verify_response(report, challenge["challenge_id"])
    assert valid2 is False


async def test_remote_service_verify_unknown_challenge():
    """verify_response returns False for unknown challenge_id."""
    generator = AttestationGenerator()
    verifier = AttestationVerifier()
    service = RemoteAttestationService(generator, verifier)

    report = await generator.generate_report(attestation_type=AttestationType.REMOTE, nonce="fake")
    valid = await service.verify_response(report, "unknown-id")

    assert valid is False


async def test_remote_service_cleanup_expired_nonces():
    """cleanup_expired_nonces removes old nonces."""
    generator = AttestationGenerator()
    verifier = AttestationVerifier()
    service = RemoteAttestationService(generator, verifier)

    # Create a challenge and backdate its nonce
    challenge = await service.create_challenge()
    old_time = datetime.now(UTC).replace(tzinfo=None) - timedelta(seconds=700)
    service._nonce_cache[challenge["nonce"]] = old_time

    removed = await service.cleanup_expired_nonces(max_age_seconds=600)
    assert removed == 1

    # The challenge should also be cleaned up
    assert challenge["challenge_id"] not in service._challenge_nonces


async def test_remote_service_cleanup_keeps_fresh_nonces():
    """cleanup_expired_nonces does not remove recent nonces."""
    generator = AttestationGenerator()
    verifier = AttestationVerifier()
    service = RemoteAttestationService(generator, verifier)

    challenge = await service.create_challenge()

    removed = await service.cleanup_expired_nonces(max_age_seconds=600)
    assert removed == 0

    # Challenge should still be present
    assert challenge["challenge_id"] in service._challenge_nonces


async def test_remote_service_end_to_end_flow():
    """Complete end-to-end challenge-response attestation flow."""
    tpm = SoftwareTPM()
    await tpm.initialize()
    tpm_manager = TPMKeyManager(backend=tpm)

    generator = AttestationGenerator(tpm_manager=tpm_manager)
    verifier = AttestationVerifier(tpm_manager=tpm_manager)
    service = RemoteAttestationService(generator, verifier)

    # Step 1: Verifier creates challenge
    challenge = await service.create_challenge()
    assert "challenge_id" in challenge
    assert "nonce" in challenge

    # Step 2: Prover responds with attestation report
    report = await service.respond_to_challenge(challenge["challenge_id"], challenge["nonce"])
    assert report.nonce == challenge["nonce"]
    assert report.valid is True

    # Step 3: Verifier validates the response
    valid = await service.verify_response(report, challenge["challenge_id"])
    assert valid is True

    # Step 4: Replay is rejected
    valid_again = await service.verify_response(report, challenge["challenge_id"])
    assert valid_again is False


# ---------------------------------------------------------------------------
# Multiple attestation type tests
# ---------------------------------------------------------------------------


async def test_multiple_attestation_types():
    """Generator supports all four attestation types."""
    generator = AttestationGenerator()

    for att_type in AttestationType:
        report = await generator.generate_report(attestation_type=att_type)
        assert report.attestation_type == att_type
        assert report.valid is True
        assert report.signature is not None
