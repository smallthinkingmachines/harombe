"""Integration tests for ZKP audit proofs with AuditDatabase and AuditLogger."""

import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from harombe.security.audit_db import AuditDatabase, AuditProofRecord
from harombe.security.audit_logger import AuditLogger
from harombe.security.zkp.audit_proofs import AuditProofType


@pytest.fixture
def temp_db():
    """Create a temporary audit database."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    db = AuditDatabase(db_path=db_path, retention_days=0)
    yield db
    Path(db_path).unlink(missing_ok=True)
    Path(f"{db_path}-shm").unlink(missing_ok=True)
    Path(f"{db_path}-wal").unlink(missing_ok=True)


@pytest.fixture
def temp_db_path():
    """Return a temp path for audit db."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    yield db_path
    Path(db_path).unlink(missing_ok=True)
    Path(f"{db_path}-shm").unlink(missing_ok=True)
    Path(f"{db_path}-wal").unlink(missing_ok=True)


class TestProofRoundTrip:
    """Test proof persistence round-trip through AuditDatabase."""

    def test_log_and_retrieve_proof(self, temp_db):
        """Proof logged to DB can be retrieved."""
        proof = AuditProofRecord(
            correlation_id="corr-1",
            claim_type="operation_count",
            description="Count in [5, 10]",
            public_parameters={"claimed_min": 5, "claimed_max": 10},
            proof_data={"commitment": "abc", "actual_count": 7},
        )
        temp_db.log_audit_proof(proof)

        proofs = temp_db.get_audit_proofs()
        assert len(proofs) == 1
        assert proofs[0]["claim_type"] == "operation_count"
        assert proofs[0]["correlation_id"] == "corr-1"

    def test_filter_by_claim_type(self, temp_db):
        """Proofs can be filtered by claim_type."""
        for ct in ["operation_count", "time_range", "resource_usage"]:
            temp_db.log_audit_proof(AuditProofRecord(claim_type=ct, description=f"Test {ct}"))

        proofs = temp_db.get_audit_proofs(claim_type="time_range")
        assert len(proofs) == 1
        assert proofs[0]["claim_type"] == "time_range"

    def test_filter_by_time_range(self, temp_db):
        """Proofs can be filtered by time range."""
        now = datetime.now(UTC).replace(tzinfo=None)

        temp_db.log_audit_proof(
            AuditProofRecord(
                claim_type="old",
                description="old",
                created_at=now - timedelta(days=5),
            )
        )
        temp_db.log_audit_proof(
            AuditProofRecord(
                claim_type="recent",
                description="recent",
                created_at=now - timedelta(hours=1),
            )
        )

        proofs = temp_db.get_audit_proofs(start_time=now - timedelta(days=1), end_time=now)
        assert len(proofs) == 1
        assert proofs[0]["claim_type"] == "recent"

    def test_filter_by_correlation_id(self, temp_db):
        """Proofs can be filtered by correlation_id."""
        temp_db.log_audit_proof(
            AuditProofRecord(correlation_id="corr-A", claim_type="a", description="A")
        )
        temp_db.log_audit_proof(
            AuditProofRecord(correlation_id="corr-B", claim_type="b", description="B")
        )

        proofs = temp_db.get_audit_proofs(correlation_id="corr-A")
        assert len(proofs) == 1
        assert proofs[0]["claim_type"] == "a"


class TestAuditLoggerZKP:
    """Test AuditLogger ZKP integration."""

    def test_generate_proof_with_zkp_enabled(self, temp_db_path):
        """AuditLogger generates and persists proofs when ZKP is enabled."""
        logger = AuditLogger(db_path=temp_db_path, retention_days=0, enable_zkp=True)

        claim = logger.generate_proof(
            proof_type="operation_count",
            correlation_id="test-corr",
            actual_count=5,
            claimed_min=1,
            claimed_max=10,
        )

        assert claim is not None
        assert claim.claim_type == AuditProofType.OPERATION_COUNT
        assert claim.proof_data["actual_count"] == 5

        # Verify proof is persisted in DB
        proofs = logger.db.get_audit_proofs(correlation_id="test-corr")
        assert len(proofs) == 1
        assert proofs[0]["claim_type"] == "operation_count"

    def test_generate_proof_with_zkp_disabled(self, temp_db_path):
        """AuditLogger returns None when ZKP is disabled."""
        logger = AuditLogger(db_path=temp_db_path, retention_days=0, enable_zkp=False)

        claim = logger.generate_proof(
            proof_type="operation_count",
            actual_count=5,
            claimed_min=1,
            claimed_max=10,
        )

        assert claim is None

    def test_verify_proof(self, temp_db_path):
        """AuditLogger can verify generated proofs."""
        logger = AuditLogger(db_path=temp_db_path, retention_days=0, enable_zkp=True)

        claim = logger.generate_proof(
            proof_type="operation_count",
            actual_count=5,
            claimed_min=1,
            claimed_max=10,
        )

        assert claim is not None
        assert logger.verify_proof(claim) is True

    def test_generate_proof_sync(self, temp_db_path):
        """Synchronous proof generation works."""
        logger = AuditLogger(db_path=temp_db_path, retention_days=0, enable_zkp=True)

        claim = logger.generate_proof_sync(
            proof_type="resource_usage",
            actual_usage=50,
            limit=100,
        )

        assert claim is not None
        assert claim.claim_type == AuditProofType.RESOURCE_USAGE
        assert logger.verify_proof(claim) is True

    def test_generate_threshold_proof(self, temp_db_path):
        """Threshold proof type works."""
        logger = AuditLogger(db_path=temp_db_path, retention_days=0, enable_zkp=True)

        claim = logger.generate_proof(
            proof_type="threshold_check",
            value=80,
            threshold=50,
            above=True,
        )

        assert claim is not None
        assert claim.claim_type == AuditProofType.THRESHOLD_CHECK
        assert logger.verify_proof(claim) is True

    def test_generate_time_range_proof(self, temp_db_path):
        """Time range proof type works."""
        logger = AuditLogger(db_path=temp_db_path, retention_days=0, enable_zkp=True)

        claim = logger.generate_proof(
            proof_type="time_range",
            timestamp=1000,
            range_start=500,
            range_end=1500,
        )

        assert claim is not None
        assert claim.claim_type == AuditProofType.TIME_RANGE
        assert logger.verify_proof(claim) is True


class TestRetentionCleanup:
    """Test that proof cleanup works with retention policy."""

    def test_old_proofs_cleaned_up(self):
        """Old proofs are removed by retention cleanup."""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name

        db = AuditDatabase(db_path=db_path, retention_days=1)

        # Log old proof
        old_proof = AuditProofRecord(
            claim_type="old",
            description="old proof",
            created_at=datetime.now(UTC).replace(tzinfo=None) - timedelta(days=2),
        )
        db.log_audit_proof(old_proof)

        # Log recent proof
        recent_proof = AuditProofRecord(
            claim_type="recent",
            description="recent proof",
        )
        db.log_audit_proof(recent_proof)

        # Run cleanup
        db._cleanup_old_records()

        proofs = db.get_audit_proofs()
        assert len(proofs) == 1
        assert proofs[0]["claim_type"] == "recent"

        # Cleanup
        Path(db_path).unlink(missing_ok=True)
        Path(f"{db_path}-shm").unlink(missing_ok=True)
        Path(f"{db_path}-wal").unlink(missing_ok=True)
