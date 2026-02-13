"""Quorum-based approval for sensitive distributed operations.

Provides a multi-party approval workflow where sensitive operations require
a configurable number of approvals from registered quorum members before
they can proceed.  Supports weighted voting, role-based restrictions,
automatic expiration, and cancellation by the original requester.

Example:
    >>> from harombe.security.distributed.quorum import (
    ...     QuorumManager,
    ...     QuorumMember,
    ...     QuorumPolicy,
    ... )
    >>>
    >>> manager = QuorumManager()
    >>> manager.add_member(QuorumMember(member_id="alice", name="Alice"))
    >>> manager.add_member(QuorumMember(member_id="bob", name="Bob"))
    >>> manager.add_member(QuorumMember(member_id="carol", name="Carol"))
    >>>
    >>> request = manager.create_request(
    ...     operation="rotate_master_key",
    ...     description="Rotate the production master key",
    ...     requester_id="alice",
    ... )
    >>>
    >>> request = manager.cast_vote(request.request_id, "bob", approved=True)
    >>> request = manager.cast_vote(request.request_id, "carol", approved=True)
    >>> assert request.status == QuorumStatus.APPROVED
"""

import logging
import uuid
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from harombe.security.distributed.hsm import HSMManager, SoftwareHSM
from harombe.security.distributed.mpc import MPCEngine
from harombe.security.distributed.shamir import ShamirSecretSharing

logger = logging.getLogger(__name__)


class QuorumStatus(StrEnum):
    """Status of a quorum approval request.

    Attributes:
        PENDING: Awaiting votes from quorum members.
        APPROVED: Sufficient approvals received; operation may proceed.
        REJECTED: Too many rejections; operation denied.
        EXPIRED: Voting window elapsed without a decision.
        CANCELLED: Requester withdrew the request.
    """

    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    CANCELLED = "cancelled"


class QuorumPolicy(BaseModel):
    """Policy governing quorum voting requirements.

    Attributes:
        min_approvals: Minimum weighted approvals to approve the request.
        max_rejections: Weighted rejections that trigger rejection.
        timeout_seconds: Seconds before a pending request expires.
        require_different_roles: Whether voters must hold distinct roles.
        allowed_roles: If non-empty, only members with these roles may vote.
    """

    min_approvals: int = 2
    max_rejections: int = 1
    timeout_seconds: int = 3600
    require_different_roles: bool = False
    allowed_roles: list[str] = Field(default_factory=list)


class QuorumMember(BaseModel):
    """A registered member of the quorum.

    Attributes:
        member_id: Unique identifier for the member.
        name: Human-readable display name.
        role: Role label used for role-based voting constraints.
        public_key: Optional public key for signature verification.
        weight: Voting weight; higher means more influence.
    """

    member_id: str
    name: str
    role: str = "member"
    public_key: str | None = None
    weight: int = 1


class QuorumVote(BaseModel):
    """A single vote cast on a quorum request.

    Attributes:
        member_id: ID of the member who cast this vote.
        approved: Whether the member voted to approve.
        reason: Optional free-text reason for the vote.
        timestamp: When the vote was cast.
    """

    member_id: str
    approved: bool
    reason: str = ""
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class QuorumRequest(BaseModel):
    """A request requiring quorum approval.

    Attributes:
        request_id: Unique identifier for the request.
        operation: Name of the operation requiring approval.
        description: Human-readable description of the request.
        requester_id: ID of the member who created the request.
        policy: Voting policy applied to this request.
        status: Current status of the request.
        votes: Votes cast so far.
        created_at: When the request was created.
        expires_at: When the request will expire (None = no expiry).
        metadata: Arbitrary key-value metadata.
    """

    request_id: str
    operation: str
    description: str
    requester_id: str
    policy: QuorumPolicy
    status: QuorumStatus = QuorumStatus.PENDING
    votes: list[QuorumVote] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: datetime | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class QuorumManager:
    """Manages quorum-based approval for sensitive operations.

    Maintains a registry of members and a collection of approval requests.
    Each request follows a configurable policy that determines how many
    weighted approvals (or rejections) are needed for a decision.

    Example:
        >>> mgr = QuorumManager()
        >>> mgr.add_member(QuorumMember(member_id="a", name="A"))
        >>> mgr.add_member(QuorumMember(member_id="b", name="B"))
        >>> req = mgr.create_request("op", "desc", requester_id="a")
        >>> req = mgr.cast_vote(req.request_id, "b", approved=True)
    """

    def __init__(self, default_policy: QuorumPolicy | None = None) -> None:
        """Initialize the quorum manager.

        Args:
            default_policy: Default policy applied to new requests when
                no explicit policy is provided.  Falls back to
                ``QuorumPolicy()`` if ``None``.
        """
        self._default_policy = default_policy or QuorumPolicy()
        self._members: dict[str, QuorumMember] = {}
        self._requests: dict[str, QuorumRequest] = {}

        logger.info(
            "QuorumManager initialized (default min_approvals=%d)",
            self._default_policy.min_approvals,
        )

    # ------------------------------------------------------------------
    # Member management
    # ------------------------------------------------------------------

    def add_member(self, member: QuorumMember) -> None:
        """Register a quorum member.

        Args:
            member: The member to add.
        """
        self._members[member.member_id] = member
        logger.info(
            "Added quorum member %s (role=%s, weight=%d)",
            member.member_id,
            member.role,
            member.weight,
        )

    def remove_member(self, member_id: str) -> bool:
        """Remove a quorum member.

        Args:
            member_id: ID of the member to remove.

        Returns:
            ``True`` if the member was found and removed, ``False``
            otherwise.
        """
        if member_id in self._members:
            del self._members[member_id]
            logger.info("Removed quorum member %s", member_id)
            return True
        return False

    def get_member(self, member_id: str) -> QuorumMember | None:
        """Look up a quorum member by ID.

        Args:
            member_id: ID of the member.

        Returns:
            The member if found, ``None`` otherwise.
        """
        return self._members.get(member_id)

    def list_members(self) -> list[QuorumMember]:
        """Return all registered quorum members.

        Returns:
            List of all members.
        """
        return list(self._members.values())

    # ------------------------------------------------------------------
    # Request management
    # ------------------------------------------------------------------

    def create_request(
        self,
        operation: str,
        description: str,
        requester_id: str,
        policy: QuorumPolicy | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> QuorumRequest:
        """Create a new quorum approval request.

        Args:
            operation: Name of the operation requiring approval.
            description: Human-readable description.
            requester_id: ID of the member making the request.
            policy: Voting policy.  Uses the manager's default if
                ``None``.
            metadata: Arbitrary key-value metadata to attach.

        Returns:
            The newly created :class:`QuorumRequest`.
        """
        effective_policy = policy or self._default_policy
        now = datetime.now(UTC).replace(tzinfo=None)
        expires_at = now + timedelta(seconds=effective_policy.timeout_seconds)

        request = QuorumRequest(
            request_id=str(uuid.uuid4()),
            operation=operation,
            description=description,
            requester_id=requester_id,
            policy=effective_policy,
            created_at=now,
            expires_at=expires_at,
            metadata=metadata or {},
        )

        self._requests[request.request_id] = request
        logger.info(
            "Created quorum request %s for operation '%s' " "(requester=%s)",
            request.request_id,
            operation,
            requester_id,
        )
        return request

    def cast_vote(
        self,
        request_id: str,
        member_id: str,
        approved: bool,
        reason: str = "",
    ) -> QuorumRequest:
        """Cast a vote on an approval request.

        Validates that the request exists and is pending, the member is
        registered, has not already voted, and is not the requester.
        After recording the vote the manager checks whether the quorum
        threshold has been met (approvals or rejections) and updates
        the request status accordingly.  Member weights are taken into
        account.

        Args:
            request_id: ID of the request to vote on.
            member_id: ID of the voting member.
            approved: ``True`` for approval, ``False`` for rejection.
            reason: Optional reason for the vote.

        Returns:
            The updated :class:`QuorumRequest`.

        Raises:
            ValueError: If any validation check fails.
        """
        request = self._requests.get(request_id)
        if request is None:
            raise ValueError(f"Request not found: {request_id}")

        if request.status != QuorumStatus.PENDING:
            raise ValueError(f"Request {request_id} is not pending " f"(status={request.status})")

        member = self._members.get(member_id)
        if member is None:
            raise ValueError(f"Member not found: {member_id}")

        if member_id == request.requester_id:
            raise ValueError("Requester cannot vote on their own request")

        # Check for duplicate vote
        existing_voter_ids = {v.member_id for v in request.votes}
        if member_id in existing_voter_ids:
            raise ValueError(f"Member {member_id} has already voted on " f"request {request_id}")

        # Check allowed roles
        if request.policy.allowed_roles and member.role not in request.policy.allowed_roles:
            raise ValueError(
                f"Member role '{member.role}' is not in the "
                f"allowed roles: {request.policy.allowed_roles}"
            )

        # Check require_different_roles
        if request.policy.require_different_roles:
            existing_roles = {
                self._members[v.member_id].role
                for v in request.votes
                if v.member_id in self._members
            }
            if member.role in existing_roles:
                raise ValueError(
                    f"A member with role '{member.role}' has "
                    f"already voted (different roles required)"
                )

        vote = QuorumVote(
            member_id=member_id,
            approved=approved,
            reason=reason,
        )
        request.votes.append(vote)

        logger.info(
            "Member %s voted %s on request %s%s",
            member_id,
            "approve" if approved else "reject",
            request_id,
            f" (reason: {reason})" if reason else "",
        )

        # Evaluate quorum using weighted votes
        self._evaluate_quorum(request)

        return request

    def get_request(self, request_id: str) -> QuorumRequest | None:
        """Look up an approval request by ID.

        Args:
            request_id: ID of the request.

        Returns:
            The request if found, ``None`` otherwise.
        """
        return self._requests.get(request_id)

    def list_requests(self, status: QuorumStatus | None = None) -> list[QuorumRequest]:
        """List approval requests, optionally filtered by status.

        Args:
            status: If provided, only return requests with this status.

        Returns:
            List of matching requests.
        """
        if status is None:
            return list(self._requests.values())
        return [r for r in self._requests.values() if r.status == status]

    def cancel_request(self, request_id: str, canceller_id: str) -> QuorumRequest:
        """Cancel a pending approval request.

        Only the original requester may cancel a request, and only
        while the request is still pending.

        Args:
            request_id: ID of the request to cancel.
            canceller_id: ID of the member requesting cancellation.

        Returns:
            The updated :class:`QuorumRequest`.

        Raises:
            ValueError: If the request is not found, not pending, or
                the canceller is not the original requester.
        """
        request = self._requests.get(request_id)
        if request is None:
            raise ValueError(f"Request not found: {request_id}")

        if request.status != QuorumStatus.PENDING:
            raise ValueError(f"Request {request_id} is not pending " f"(status={request.status})")

        if canceller_id != request.requester_id:
            raise ValueError("Only the requester can cancel a request")

        request.status = QuorumStatus.CANCELLED
        logger.info(
            "Request %s cancelled by %s",
            request_id,
            canceller_id,
        )
        return request

    def check_expired(self) -> list[str]:
        """Expire pending requests that have passed their deadline.

        Returns:
            List of request IDs that were expired.
        """
        now = datetime.now(UTC).replace(tzinfo=None)
        expired_ids: list[str] = []

        for request in self._requests.values():
            if (
                request.status == QuorumStatus.PENDING
                and request.expires_at is not None
                and now >= request.expires_at
            ):
                request.status = QuorumStatus.EXPIRED
                expired_ids.append(request.request_id)
                logger.info("Request %s expired", request.request_id)

        return expired_ids

    def get_vote_summary(self, request_id: str) -> dict[str, Any]:
        """Return a summary of votes for a request.

        Args:
            request_id: ID of the request.

        Returns:
            Dictionary with ``approvals``, ``rejections``,
            ``total_votes``, ``required_approvals``, and ``status``.

        Raises:
            ValueError: If the request is not found.
        """
        request = self._requests.get(request_id)
        if request is None:
            raise ValueError(f"Request not found: {request_id}")

        approvals = 0
        rejections = 0
        for vote in request.votes:
            member = self._members.get(vote.member_id)
            weight = member.weight if member else 1
            if vote.approved:
                approvals += weight
            else:
                rejections += weight

        return {
            "approvals": approvals,
            "rejections": rejections,
            "total_votes": len(request.votes),
            "required_approvals": request.policy.min_approvals,
            "status": request.status,
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _evaluate_quorum(self, request: QuorumRequest) -> None:
        """Evaluate whether a request has reached quorum.

        Updates the request status to APPROVED or REJECTED when the
        weighted vote totals meet the policy thresholds.

        Args:
            request: The request to evaluate.
        """
        approvals = 0
        rejections = 0

        for vote in request.votes:
            member = self._members.get(vote.member_id)
            weight = member.weight if member else 1
            if vote.approved:
                approvals += weight
            else:
                rejections += weight

        if approvals >= request.policy.min_approvals:
            request.status = QuorumStatus.APPROVED
            logger.info(
                "Request %s APPROVED (approvals=%d, required=%d)",
                request.request_id,
                approvals,
                request.policy.min_approvals,
            )
        elif rejections > request.policy.max_rejections:
            request.status = QuorumStatus.REJECTED
            logger.info(
                "Request %s REJECTED (rejections=%d, max=%d)",
                request.request_id,
                rejections,
                request.policy.max_rejections,
            )


def create_distributed_secrets() -> dict[str, Any]:
    """Create a complete set of distributed security components.

    Factory function that instantiates and returns the core
    distributed security primitives as a dictionary.

    Returns:
        Dictionary with keys ``shamir``, ``mpc``, ``hsm``, and
        ``quorum`` mapped to their respective instances.

    Example:
        >>> components = create_distributed_secrets()
        >>> assert "shamir" in components
        >>> assert "mpc" in components
        >>> assert "hsm" in components
        >>> assert "quorum" in components
    """
    return {
        "shamir": ShamirSecretSharing(),
        "mpc": MPCEngine(),
        "hsm": HSMManager(SoftwareHSM()),
        "quorum": QuorumManager(),
    }
