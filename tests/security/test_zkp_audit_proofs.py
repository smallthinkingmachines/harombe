"""Tests for privacy-preserving audit proofs."""

import hashlib

import pytest

from harombe.security.zkp.audit_proofs import (
    AuditClaim,
    AuditProofGenerator,
    AuditProofType,
    AuditProofVerifier,
    PrivacyPreservingAuditLog,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def generator():
    """Create an AuditProofGenerator."""
    return AuditProofGenerator()


@pytest.fixture
def verifier():
    """Create an AuditProofVerifier."""
    return AuditProofVerifier()


@pytest.fixture
def audit_log():
    """Create a PrivacyPreservingAuditLog."""
    return PrivacyPreservingAuditLog()


# ---------------------------------------------------------------------------
# TestAuditProofType
# ---------------------------------------------------------------------------


class TestAuditProofType:
    """Tests for the AuditProofType enum."""

    def test_operation_count_value(self):
        assert AuditProofType.OPERATION_COUNT == "operation_count"

    def test_time_range_value(self):
        assert AuditProofType.TIME_RANGE == "time_range"

    def test_policy_compliance_value(self):
        assert AuditProofType.POLICY_COMPLIANCE == "policy_compliance"

    def test_resource_usage_value(self):
        assert AuditProofType.RESOURCE_USAGE == "resource_usage"

    def test_threshold_check_value(self):
        assert AuditProofType.THRESHOLD_CHECK == "threshold_check"


# ---------------------------------------------------------------------------
# TestAuditClaim
# ---------------------------------------------------------------------------


class TestAuditClaim:
    """Tests for the AuditClaim Pydantic model."""

    def test_creation_minimal(self):
        claim = AuditClaim(
            claim_type=AuditProofType.OPERATION_COUNT,
            description="test claim",
        )
        assert claim.claim_type == AuditProofType.OPERATION_COUNT
        assert claim.description == "test claim"

    def test_defaults(self):
        claim = AuditClaim(
            claim_type=AuditProofType.TIME_RANGE,
            description="defaults",
        )
        assert claim.public_parameters == {}
        assert claim.committed_value is None
        assert claim.proof_data == {}

    def test_full_creation(self):
        claim = AuditClaim(
            claim_type=AuditProofType.RESOURCE_USAGE,
            description="full claim",
            public_parameters={"limit": 100},
            committed_value=42,
            proof_data={"key": "val"},
        )
        assert claim.public_parameters == {"limit": 100}
        assert claim.committed_value == 42
        assert claim.proof_data == {"key": "val"}

    def test_serialization_round_trip(self):
        claim = AuditClaim(
            claim_type=AuditProofType.THRESHOLD_CHECK,
            description="round-trip",
            public_parameters={"threshold": 10},
        )
        data = claim.model_dump(mode="json")
        restored = AuditClaim.model_validate(data)
        assert restored.claim_type == claim.claim_type
        assert restored.description == claim.description


# ---------------------------------------------------------------------------
# TestAuditProofGenerator
# ---------------------------------------------------------------------------


class TestAuditProofGenerator:
    """Tests for AuditProofGenerator proof methods."""

    def test_prove_operation_count_valid(self, generator):
        claim = generator.prove_operation_count(5, 1, 10)
        assert claim.claim_type == AuditProofType.OPERATION_COUNT
        assert claim.committed_value == 5
        assert "commitment" in claim.proof_data
        assert "schnorr_proof" in claim.proof_data

    def test_prove_operation_count_boundary_min(self, generator):
        claim = generator.prove_operation_count(1, 1, 10)
        assert claim.committed_value == 1

    def test_prove_operation_count_boundary_max(self, generator):
        claim = generator.prove_operation_count(10, 1, 10)
        assert claim.committed_value == 10

    def test_prove_time_range(self, generator):
        claim = generator.prove_time_range(1500, 1000, 2000)
        assert claim.claim_type == AuditProofType.TIME_RANGE
        assert "timestamp" in claim.proof_data
        assert claim.public_parameters["range_start"] == 1000
        assert claim.public_parameters["range_end"] == 2000

    def test_prove_policy_compliance(self, generator):
        policy = b"policy-v1"
        claim = generator.prove_policy_compliance(policy, policy)
        assert claim.claim_type == AuditProofType.POLICY_COMPLIANCE
        assert claim.proof_data["hashes_match"] is True

    def test_prove_policy_compliance_mismatch(self, generator):
        claim = generator.prove_policy_compliance(b"a", b"b")
        assert claim.proof_data["hashes_match"] is False

    def test_prove_resource_usage(self, generator):
        claim = generator.prove_resource_usage(50, 100)
        assert claim.claim_type == AuditProofType.RESOURCE_USAGE
        assert claim.public_parameters["limit"] == 100
        assert claim.committed_value == 50

    def test_prove_threshold_above(self, generator):
        claim = generator.prove_threshold(15, 10, above=True)
        assert claim.claim_type == AuditProofType.THRESHOLD_CHECK
        assert claim.proof_data["above"] is True
        assert claim.public_parameters["threshold"] == 10

    def test_prove_threshold_below(self, generator):
        claim = generator.prove_threshold(5, 10, above=False)
        assert claim.proof_data["above"] is False
        assert claim.public_parameters["above"] is False


# ---------------------------------------------------------------------------
# TestAuditProofVerifier
# ---------------------------------------------------------------------------


class TestAuditProofVerifier:
    """Tests for AuditProofVerifier claim verification."""

    def test_verify_operation_count_valid(self, generator, verifier):
        claim = generator.prove_operation_count(5, 1, 10)
        assert verifier.verify_claim(claim) is True

    def test_verify_operation_count_out_of_range(self, generator, verifier):
        claim = generator.prove_operation_count(15, 1, 10)
        assert verifier.verify_claim(claim) is False

    def test_verify_time_range_valid(self, generator, verifier):
        claim = generator.prove_time_range(1500, 1000, 2000)
        assert verifier.verify_claim(claim) is True

    def test_verify_time_range_outside(self, generator, verifier):
        claim = generator.prove_time_range(500, 1000, 2000)
        assert verifier.verify_claim(claim) is False

    def test_verify_policy_compliance_valid(self, generator, verifier):
        policy = b"compliance-policy"
        claim = generator.prove_policy_compliance(policy, policy)
        assert verifier.verify_claim(claim) is True

    def test_verify_policy_compliance_mismatch(self, generator, verifier):
        claim = generator.prove_policy_compliance(b"a", b"b")
        assert verifier.verify_claim(claim) is False

    def test_verify_resource_usage_under_limit(self, generator, verifier):
        claim = generator.prove_resource_usage(50, 100)
        assert verifier.verify_claim(claim) is True

    def test_verify_resource_usage_over_limit(self, generator, verifier):
        claim = generator.prove_resource_usage(150, 100)
        assert verifier.verify_claim(claim) is False

    def test_verify_threshold_above_valid(self, generator, verifier):
        claim = generator.prove_threshold(15, 10, above=True)
        assert verifier.verify_claim(claim) is True

    def test_verify_threshold_above_invalid(self, generator, verifier):
        claim = generator.prove_threshold(5, 10, above=True)
        assert verifier.verify_claim(claim) is False

    def test_verify_threshold_below_valid(self, generator, verifier):
        claim = generator.prove_threshold(5, 10, above=False)
        assert verifier.verify_claim(claim) is True

    def test_verify_threshold_below_invalid(self, generator, verifier):
        claim = generator.prove_threshold(15, 10, above=False)
        assert verifier.verify_claim(claim) is False

    def test_verify_unknown_claim_type(self, verifier):
        """Verifier returns False for an unrecognised claim type."""
        claim = AuditClaim.model_construct(
            claim_type="unknown_type",
            description="bad type",
            public_parameters={},
            committed_value=None,
            proof_data={},
        )
        assert verifier.verify_claim(claim) is False


# ---------------------------------------------------------------------------
# TestPrivacyPreservingAuditLog
# ---------------------------------------------------------------------------


class TestPrivacyPreservingAuditLog:
    """Tests for the PrivacyPreservingAuditLog wrapper."""

    def test_record_event_returns_id(self, audit_log):
        event_id = audit_log.record_event("api_call")
        assert isinstance(event_id, str)
        assert len(event_id) == 32  # uuid4 hex

    def test_record_event_with_metadata(self, audit_log):
        event_id = audit_log.record_event("api_call", {"user": "alice"})
        assert event_id is not None

    def test_get_event_count_all(self, audit_log):
        audit_log.record_event("a")
        audit_log.record_event("b")
        assert audit_log.get_event_count() == 2

    def test_get_event_count_filtered(self, audit_log):
        audit_log.record_event("api_call")
        audit_log.record_event("api_call")
        audit_log.record_event("login")
        assert audit_log.get_event_count("api_call") == 2
        assert audit_log.get_event_count("login") == 1

    def test_generate_and_verify_count_proof(self, audit_log):
        for _ in range(3):
            audit_log.record_event("op")
        claim = audit_log.generate_count_proof("op", 1, 5)
        assert audit_log.verify_proof(claim) is True

    def test_count_proof_fails_out_of_range(self, audit_log):
        audit_log.record_event("op")
        claim = audit_log.generate_count_proof("op", 5, 10)
        assert audit_log.verify_proof(claim) is False

    def test_generate_and_verify_compliance_proof(self, audit_log):
        audit_log.record_event("setup")
        # Build the "actual" hash the same way the log does
        all_ids = "".join(e["event_id"] for e in audit_log._events)
        policy_hash = hashlib.sha256(all_ids.encode()).digest()
        claim = audit_log.generate_compliance_proof(policy_hash)
        assert audit_log.verify_proof(claim) is True

    def test_compliance_proof_fails_wrong_hash(self, audit_log):
        audit_log.record_event("setup")
        claim = audit_log.generate_compliance_proof(b"wrong")
        assert audit_log.verify_proof(claim) is False
