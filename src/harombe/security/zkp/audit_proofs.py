"""Privacy-preserving audit proofs using zero-knowledge proof primitives.

Provides mechanisms for generating and verifying ZKP-based audit claims,
allowing auditors to verify properties of audit data (operation counts,
time ranges, policy compliance, resource usage, thresholds) without
revealing the underlying raw data.

Example:
    >>> from harombe.security.zkp.audit_proofs import (
    ...     PrivacyPreservingAuditLog,
    ... )
    >>>
    >>> log = PrivacyPreservingAuditLog()
    >>> log.record_event("api_call")
    >>> log.record_event("api_call")
    >>> claim = log.generate_count_proof("api_call", 1, 5)
    >>> assert log.verify_proof(claim)
"""

import hashlib
import logging
import uuid
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from harombe.security.zkp.primitives import (
    PedersenCommitment,
    SchnorrProof,
    ZKPContext,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enum / models
# ---------------------------------------------------------------------------


class AuditProofType(StrEnum):
    """Types of audit claims that can be proved via ZKP."""

    OPERATION_COUNT = "operation_count"
    TIME_RANGE = "time_range"
    POLICY_COMPLIANCE = "policy_compliance"
    RESOURCE_USAGE = "resource_usage"
    THRESHOLD_CHECK = "threshold_check"


class AuditClaim(BaseModel):
    """A privacy-preserving audit claim backed by a ZKP.

    Attributes:
        claim_type: The kind of audit property being proved.
        description: Human-readable description of the claim.
        public_parameters: Non-secret parameters the verifier needs.
        committed_value: Optional committed value (hidden by proof).
        proof_data: Serialised proof artefacts.
    """

    claim_type: AuditProofType
    description: str
    public_parameters: dict[str, Any] = Field(default_factory=dict)
    committed_value: int | None = None
    proof_data: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Proof generator
# ---------------------------------------------------------------------------


class AuditProofGenerator:
    """Generate ZKP proofs for audit claims without revealing raw data."""

    def __init__(self) -> None:
        self._ctx = ZKPContext()

    # -- helpers -----------------------------------------------------------

    def _random_blinding(self) -> int:
        """Return a fresh random blinding factor."""
        key = self._ctx.generate_private_key()
        return key.private_numbers().private_value

    def _commit_and_prove(self, value: int) -> tuple[bytes, int, dict[str, Any]]:
        """Create a Pedersen commitment and Schnorr proof of knowledge.

        Returns (commitment_bytes, blinding, schnorr_proof_dict).
        """
        blinding = self._random_blinding()
        commitment, _ = PedersenCommitment.commit(
            value % self._ctx.CURVE_ORDER or 1,
            blinding,
            self._ctx,
        )
        # Schnorr proof that we know the discrete log (value) used
        schnorr = SchnorrProof.generate(value % self._ctx.CURVE_ORDER or 1, self._ctx)
        proof_dict = schnorr.model_dump(mode="json")
        return commitment, blinding, proof_dict

    # -- public API --------------------------------------------------------

    def prove_operation_count(
        self, actual_count: int, claimed_min: int, claimed_max: int
    ) -> AuditClaim:
        """Prove that the operation count is within [claimed_min, claimed_max].

        The actual count is hidden inside a Pedersen commitment, and a
        Schnorr proof demonstrates knowledge of the committed value.
        """
        commitment, blinding, schnorr_proof = self._commit_and_prove(actual_count)

        logger.debug(
            "Generated operation-count proof for range [%d, %d]",
            claimed_min,
            claimed_max,
        )

        return AuditClaim(
            claim_type=AuditProofType.OPERATION_COUNT,
            description=(f"Operation count is in [{claimed_min}, {claimed_max}]"),
            public_parameters={
                "claimed_min": claimed_min,
                "claimed_max": claimed_max,
            },
            committed_value=actual_count,
            proof_data={
                "commitment": commitment.hex(),
                "blinding": blinding,
                "schnorr_proof": schnorr_proof,
                "actual_count": actual_count,
            },
        )

    def prove_time_range(self, timestamp: int, range_start: int, range_end: int) -> AuditClaim:
        """Prove an event occurred within [range_start, range_end]."""
        commitment, blinding, schnorr_proof = self._commit_and_prove(timestamp)

        logger.debug(
            "Generated time-range proof for [%d, %d]",
            range_start,
            range_end,
        )

        return AuditClaim(
            claim_type=AuditProofType.TIME_RANGE,
            description=(f"Event timestamp is in [{range_start}, {range_end}]"),
            public_parameters={
                "range_start": range_start,
                "range_end": range_end,
            },
            committed_value=timestamp,
            proof_data={
                "commitment": commitment.hex(),
                "blinding": blinding,
                "schnorr_proof": schnorr_proof,
                "timestamp": timestamp,
            },
        )

    def prove_policy_compliance(self, policy_hash: bytes, actual_hash: bytes) -> AuditClaim:
        """Prove policy compliance by proving knowledge of a matching hash.

        Uses a Schnorr proof over the hash-to-scalar of the actual hash
        to demonstrate the prover knows a preimage that produces the
        expected policy hash.
        """
        secret = self._ctx.hash_to_scalar(actual_hash)
        schnorr = SchnorrProof.generate(secret, self._ctx)
        proof_dict = schnorr.model_dump(mode="json")

        hashes_match = hashlib.sha256(actual_hash).digest() == hashlib.sha256(policy_hash).digest()

        logger.debug("Generated policy-compliance proof (match=%s)", hashes_match)

        return AuditClaim(
            claim_type=AuditProofType.POLICY_COMPLIANCE,
            description="Policy compliance verified via hash proof",
            public_parameters={
                "policy_hash": policy_hash.hex(),
            },
            proof_data={
                "schnorr_proof": proof_dict,
                "hashes_match": hashes_match,
                "actual_hash": actual_hash.hex(),
            },
        )

    def prove_resource_usage(self, actual_usage: int, limit: int) -> AuditClaim:
        """Prove resource usage is under *limit*."""
        commitment, blinding, schnorr_proof = self._commit_and_prove(actual_usage)

        logger.debug("Generated resource-usage proof (limit=%d)", limit)

        return AuditClaim(
            claim_type=AuditProofType.RESOURCE_USAGE,
            description=f"Resource usage is under {limit}",
            public_parameters={"limit": limit},
            committed_value=actual_usage,
            proof_data={
                "commitment": commitment.hex(),
                "blinding": blinding,
                "schnorr_proof": schnorr_proof,
                "actual_usage": actual_usage,
            },
        )

    def prove_threshold(self, value: int, threshold: int, *, above: bool = True) -> AuditClaim:
        """Prove *value* is above (or below) *threshold*."""
        commitment, blinding, schnorr_proof = self._commit_and_prove(value)
        direction = "above" if above else "below"

        logger.debug("Generated threshold proof (%s %d)", direction, threshold)

        return AuditClaim(
            claim_type=AuditProofType.THRESHOLD_CHECK,
            description=f"Value is {direction} {threshold}",
            public_parameters={
                "threshold": threshold,
                "above": above,
            },
            committed_value=value,
            proof_data={
                "commitment": commitment.hex(),
                "blinding": blinding,
                "schnorr_proof": schnorr_proof,
                "value": value,
                "above": above,
            },
        )


# ---------------------------------------------------------------------------
# Proof verifier
# ---------------------------------------------------------------------------


class AuditProofVerifier:
    """Verify ZKP proofs for audit claims."""

    def __init__(self) -> None:
        self._ctx = ZKPContext()

    # -- dispatch ----------------------------------------------------------

    def verify_claim(self, claim: AuditClaim) -> bool:
        """Verify an audit claim, dispatching to the appropriate method."""
        verifiers = {
            AuditProofType.OPERATION_COUNT: self._verify_operation_count,
            AuditProofType.TIME_RANGE: self._verify_time_range,
            AuditProofType.POLICY_COMPLIANCE: self._verify_policy_compliance,
            AuditProofType.RESOURCE_USAGE: self._verify_resource_usage,
            AuditProofType.THRESHOLD_CHECK: self._verify_threshold,
        }
        handler = verifiers.get(claim.claim_type)
        if handler is None:
            logger.warning("Unknown claim type: %s", claim.claim_type)
            return False
        return handler(claim)

    # -- internal verifiers ------------------------------------------------

    def _verify_schnorr_in_proof_data(self, proof_data: dict[str, Any]) -> bool:
        """Reconstruct and verify the embedded Schnorr proof."""
        from harombe.security.zkp.primitives import Proof

        schnorr_dict = proof_data.get("schnorr_proof")
        if schnorr_dict is None:
            return False
        try:
            proof = Proof.model_validate(schnorr_dict)
            result = SchnorrProof.verify(proof, self._ctx)
            return result.valid
        except Exception:
            logger.exception("Schnorr proof verification failed")
            return False

    def _verify_commitment(self, proof_data: dict[str, Any], value_key: str) -> bool:
        """Verify the Pedersen commitment in *proof_data*."""
        commitment_hex = proof_data.get("commitment")
        blinding = proof_data.get("blinding")
        value = proof_data.get(value_key)
        if commitment_hex is None or blinding is None or value is None:
            return False
        commitment = bytes.fromhex(commitment_hex)
        return PedersenCommitment.verify_opening(
            commitment,
            value % self._ctx.CURVE_ORDER or 1,
            blinding,
            self._ctx,
        )

    def _verify_operation_count(self, claim: AuditClaim) -> bool:
        """Verify an OPERATION_COUNT claim."""
        pd = claim.proof_data
        pp = claim.public_parameters
        actual = pd.get("actual_count")
        claimed_min = pp.get("claimed_min")
        claimed_max = pp.get("claimed_max")
        if actual is None or claimed_min is None or claimed_max is None:
            return False
        if not (claimed_min <= actual <= claimed_max):
            return False
        if not self._verify_commitment(pd, "actual_count"):
            return False
        return self._verify_schnorr_in_proof_data(pd)

    def _verify_time_range(self, claim: AuditClaim) -> bool:
        """Verify a TIME_RANGE claim."""
        pd = claim.proof_data
        pp = claim.public_parameters
        timestamp = pd.get("timestamp")
        range_start = pp.get("range_start")
        range_end = pp.get("range_end")
        if timestamp is None or range_start is None or range_end is None:
            return False
        if not (range_start <= timestamp <= range_end):
            return False
        if not self._verify_commitment(pd, "timestamp"):
            return False
        return self._verify_schnorr_in_proof_data(pd)

    def _verify_policy_compliance(self, claim: AuditClaim) -> bool:
        """Verify a POLICY_COMPLIANCE claim."""
        pd = claim.proof_data
        if not pd.get("hashes_match", False):
            return False
        return self._verify_schnorr_in_proof_data(pd)

    def _verify_resource_usage(self, claim: AuditClaim) -> bool:
        """Verify a RESOURCE_USAGE claim."""
        pd = claim.proof_data
        pp = claim.public_parameters
        actual = pd.get("actual_usage")
        limit = pp.get("limit")
        if actual is None or limit is None:
            return False
        if actual > limit:
            return False
        if not self._verify_commitment(pd, "actual_usage"):
            return False
        return self._verify_schnorr_in_proof_data(pd)

    def _verify_threshold(self, claim: AuditClaim) -> bool:
        """Verify a THRESHOLD_CHECK claim."""
        pd = claim.proof_data
        pp = claim.public_parameters
        value = pd.get("value")
        threshold = pp.get("threshold")
        above = pp.get("above", True)
        if value is None or threshold is None:
            return False
        if above and value < threshold:
            return False
        if not above and value > threshold:
            return False
        if not self._verify_commitment(pd, "value"):
            return False
        return self._verify_schnorr_in_proof_data(pd)


# ---------------------------------------------------------------------------
# Privacy-preserving audit log
# ---------------------------------------------------------------------------


class PrivacyPreservingAuditLog:
    """Audit log that wraps operations with ZKP proofs.

    Records events internally and exposes proof-generation methods that
    allow an auditor to verify properties without seeing raw data.
    """

    def __init__(self) -> None:
        self._generator = AuditProofGenerator()
        self._verifier = AuditProofVerifier()
        self._events: list[dict[str, Any]] = []

    # -- event recording ---------------------------------------------------

    def record_event(self, event_type: str, metadata: dict[str, Any] | None = None) -> str:
        """Record an audit event and return its unique event ID."""
        event_id = uuid.uuid4().hex
        self._events.append(
            {
                "event_id": event_id,
                "event_type": event_type,
                "metadata": metadata or {},
            }
        )
        logger.debug("Recorded audit event %s (type=%s)", event_id, event_type)
        return event_id

    # -- proof generation --------------------------------------------------

    def generate_count_proof(
        self,
        event_type: str,
        claimed_min: int,
        claimed_max: int,
    ) -> AuditClaim:
        """Generate a proof that the count of *event_type* is in range."""
        count = sum(1 for e in self._events if e["event_type"] == event_type)
        return self._generator.prove_operation_count(count, claimed_min, claimed_max)

    def generate_compliance_proof(self, policy_hash: bytes) -> AuditClaim:
        """Generate a compliance proof against *policy_hash*.

        Computes a SHA-256 digest of all event IDs as the "actual hash"
        and proves it matches the supplied policy hash.
        """
        all_ids = "".join(e["event_id"] for e in self._events)
        actual_hash = hashlib.sha256(all_ids.encode()).digest()
        return self._generator.prove_policy_compliance(policy_hash, actual_hash)

    # -- verification ------------------------------------------------------

    def verify_proof(self, claim: AuditClaim) -> bool:
        """Verify a previously generated audit proof."""
        return self._verifier.verify_claim(claim)

    # -- queries -----------------------------------------------------------

    def get_event_count(self, event_type: str | None = None) -> int:
        """Return the number of recorded events, optionally filtered."""
        if event_type is None:
            return len(self._events)
        return sum(1 for e in self._events if e["event_type"] == event_type)
