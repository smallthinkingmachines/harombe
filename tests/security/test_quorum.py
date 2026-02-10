"""Tests for the quorum-based approval manager."""

from datetime import datetime

import pytest

from harombe.security.distributed.quorum import (
    QuorumManager,
    QuorumMember,
    QuorumPolicy,
    QuorumRequest,
    QuorumStatus,
    create_distributed_secrets,
)

# ------------------------------------------------------------------ #
# Fixtures                                                            #
# ------------------------------------------------------------------ #


@pytest.fixture()
def policy() -> QuorumPolicy:
    """Default quorum policy for tests."""
    return QuorumPolicy(min_approvals=2, max_rejections=1)


@pytest.fixture()
def members() -> list[QuorumMember]:
    """Three members with default weight=1."""
    return [
        QuorumMember(member_id="alice", name="Alice", role="admin"),
        QuorumMember(member_id="bob", name="Bob", role="operator"),
        QuorumMember(member_id="carol", name="Carol", role="auditor"),
    ]


@pytest.fixture()
def manager(policy: QuorumPolicy, members: list[QuorumMember]) -> QuorumManager:
    """QuorumManager pre-loaded with three members."""
    mgr = QuorumManager(default_policy=policy)
    for m in members:
        mgr.add_member(m)
    return mgr


# ------------------------------------------------------------------ #
# TestQuorumStatus                                                    #
# ------------------------------------------------------------------ #


class TestQuorumStatus:
    """Enum value tests for QuorumStatus."""

    def test_pending_value(self) -> None:
        assert QuorumStatus.PENDING == "pending"

    def test_approved_value(self) -> None:
        assert QuorumStatus.APPROVED == "approved"

    def test_rejected_value(self) -> None:
        assert QuorumStatus.REJECTED == "rejected"

    def test_expired_value(self) -> None:
        assert QuorumStatus.EXPIRED == "expired"

    def test_cancelled_value(self) -> None:
        assert QuorumStatus.CANCELLED == "cancelled"


# ------------------------------------------------------------------ #
# TestQuorumPolicy                                                    #
# ------------------------------------------------------------------ #


class TestQuorumPolicy:
    """Tests for the QuorumPolicy data model."""

    def test_defaults(self) -> None:
        p = QuorumPolicy()
        assert p.min_approvals == 2
        assert p.max_rejections == 1
        assert p.timeout_seconds == 3600
        assert p.require_different_roles is False
        assert p.allowed_roles == []

    def test_custom_values(self) -> None:
        p = QuorumPolicy(
            min_approvals=3,
            max_rejections=2,
            timeout_seconds=7200,
            require_different_roles=True,
            allowed_roles=["admin", "operator"],
        )
        assert p.min_approvals == 3
        assert p.max_rejections == 2
        assert p.timeout_seconds == 7200
        assert p.require_different_roles is True
        assert p.allowed_roles == ["admin", "operator"]


# ------------------------------------------------------------------ #
# TestQuorumMember                                                    #
# ------------------------------------------------------------------ #


class TestQuorumMember:
    """Tests for the QuorumMember data model."""

    def test_creation(self) -> None:
        m = QuorumMember(member_id="x", name="X")
        assert m.member_id == "x"
        assert m.name == "X"

    def test_defaults(self) -> None:
        m = QuorumMember(member_id="x", name="X")
        assert m.role == "member"
        assert m.public_key is None
        assert m.weight == 1

    def test_custom_fields(self) -> None:
        m = QuorumMember(
            member_id="x",
            name="X",
            role="admin",
            public_key="pk123",
            weight=3,
        )
        assert m.role == "admin"
        assert m.public_key == "pk123"
        assert m.weight == 3


# ------------------------------------------------------------------ #
# TestQuorumRequest                                                   #
# ------------------------------------------------------------------ #


class TestQuorumRequest:
    """Tests for the QuorumRequest data model."""

    def test_creation(self) -> None:
        req = QuorumRequest(
            request_id="r1",
            operation="op",
            description="desc",
            requester_id="alice",
            policy=QuorumPolicy(),
        )
        assert req.request_id == "r1"
        assert req.operation == "op"
        assert req.description == "desc"
        assert req.requester_id == "alice"

    def test_defaults(self) -> None:
        req = QuorumRequest(
            request_id="r1",
            operation="op",
            description="desc",
            requester_id="alice",
            policy=QuorumPolicy(),
        )
        assert req.status == QuorumStatus.PENDING
        assert req.votes == []
        assert req.metadata == {}
        assert isinstance(req.created_at, datetime)


# ------------------------------------------------------------------ #
# TestQuorumManager                                                   #
# ------------------------------------------------------------------ #


class TestQuorumManager:
    """Comprehensive tests for the QuorumManager."""

    # -- Member management --

    def test_add_member(self, manager: QuorumManager) -> None:
        assert len(manager.list_members()) == 3

    def test_add_new_member(self, manager: QuorumManager) -> None:
        manager.add_member(QuorumMember(member_id="dave", name="Dave"))
        assert len(manager.list_members()) == 4

    def test_remove_member(self, manager: QuorumManager) -> None:
        assert manager.remove_member("alice") is True
        assert len(manager.list_members()) == 2

    def test_remove_nonexistent_member(self, manager: QuorumManager) -> None:
        assert manager.remove_member("unknown") is False

    def test_get_member(self, manager: QuorumManager) -> None:
        m = manager.get_member("alice")
        assert m is not None
        assert m.name == "Alice"

    def test_get_member_not_found(self, manager: QuorumManager) -> None:
        assert manager.get_member("unknown") is None

    def test_list_members(self, manager: QuorumManager) -> None:
        ids = {m.member_id for m in manager.list_members()}
        assert ids == {"alice", "bob", "carol"}

    # -- Request creation --

    def test_create_request(self, manager: QuorumManager) -> None:
        req = manager.create_request(
            operation="rotate_key",
            description="Rotate master key",
            requester_id="alice",
        )
        assert req.operation == "rotate_key"
        assert req.status == QuorumStatus.PENDING
        assert req.expires_at is not None

    def test_create_request_with_custom_policy(self, manager: QuorumManager) -> None:
        custom = QuorumPolicy(min_approvals=3, timeout_seconds=60)
        req = manager.create_request(
            operation="delete_data",
            description="Delete all data",
            requester_id="alice",
            policy=custom,
        )
        assert req.policy.min_approvals == 3
        assert req.policy.timeout_seconds == 60

    def test_create_request_with_metadata(self, manager: QuorumManager) -> None:
        req = manager.create_request(
            operation="op",
            description="desc",
            requester_id="alice",
            metadata={"env": "production"},
        )
        assert req.metadata == {"env": "production"}

    # -- Voting: approval --

    def test_cast_vote_approve(self, manager: QuorumManager) -> None:
        req = manager.create_request("op", "desc", requester_id="alice")
        updated = manager.cast_vote(req.request_id, "bob", approved=True)
        assert len(updated.votes) == 1
        assert updated.votes[0].approved is True

    def test_quorum_reached_approved(self, manager: QuorumManager) -> None:
        req = manager.create_request("op", "desc", requester_id="alice")
        manager.cast_vote(req.request_id, "bob", approved=True)
        updated = manager.cast_vote(req.request_id, "carol", approved=True)
        assert updated.status == QuorumStatus.APPROVED

    # -- Voting: rejection --

    def test_cast_vote_reject(self, manager: QuorumManager) -> None:
        req = manager.create_request("op", "desc", requester_id="alice")
        updated = manager.cast_vote(req.request_id, "bob", approved=False, reason="risky")
        assert updated.votes[0].approved is False
        assert updated.votes[0].reason == "risky"

    def test_quorum_rejected(self, manager: QuorumManager) -> None:
        # Default max_rejections=1, so >1 weighted rejections → reject
        req = manager.create_request("op", "desc", requester_id="alice")
        manager.cast_vote(req.request_id, "bob", approved=False)
        updated = manager.cast_vote(req.request_id, "carol", approved=False)
        assert updated.status == QuorumStatus.REJECTED

    # -- Voting: error cases --

    def test_double_vote_prevented(self, manager: QuorumManager) -> None:
        req = manager.create_request("op", "desc", requester_id="alice")
        manager.cast_vote(req.request_id, "bob", approved=True)
        with pytest.raises(ValueError, match="already voted"):
            manager.cast_vote(req.request_id, "bob", approved=True)

    def test_requester_cannot_vote(self, manager: QuorumManager) -> None:
        req = manager.create_request("op", "desc", requester_id="alice")
        with pytest.raises(ValueError, match="Requester cannot vote"):
            manager.cast_vote(req.request_id, "alice", approved=True)

    def test_vote_on_nonexistent_request(self, manager: QuorumManager) -> None:
        with pytest.raises(ValueError, match="Request not found"):
            manager.cast_vote("bad-id", "bob", approved=True)

    def test_vote_by_nonexistent_member(self, manager: QuorumManager) -> None:
        req = manager.create_request("op", "desc", requester_id="alice")
        with pytest.raises(ValueError, match="Member not found"):
            manager.cast_vote(req.request_id, "unknown", approved=True)

    def test_vote_on_non_pending_request(self, manager: QuorumManager) -> None:
        req = manager.create_request("op", "desc", requester_id="alice")
        # Approve the request first
        manager.cast_vote(req.request_id, "bob", approved=True)
        manager.cast_vote(req.request_id, "carol", approved=True)
        assert req.status == QuorumStatus.APPROVED

        # Add a fourth member and try to vote
        manager.add_member(QuorumMember(member_id="dave", name="Dave"))
        with pytest.raises(ValueError, match="not pending"):
            manager.cast_vote(req.request_id, "dave", approved=True)

    # -- Cancel --

    def test_cancel_request(self, manager: QuorumManager) -> None:
        req = manager.create_request("op", "desc", requester_id="alice")
        updated = manager.cancel_request(req.request_id, "alice")
        assert updated.status == QuorumStatus.CANCELLED

    def test_cancel_by_non_requester(self, manager: QuorumManager) -> None:
        req = manager.create_request("op", "desc", requester_id="alice")
        with pytest.raises(ValueError, match="Only the requester"):
            manager.cancel_request(req.request_id, "bob")

    def test_cancel_non_pending(self, manager: QuorumManager) -> None:
        req = manager.create_request("op", "desc", requester_id="alice")
        manager.cancel_request(req.request_id, "alice")
        with pytest.raises(ValueError, match="not pending"):
            manager.cancel_request(req.request_id, "alice")

    # -- Expiration --

    def test_check_expired(self, manager: QuorumManager) -> None:
        policy = QuorumPolicy(timeout_seconds=0)
        req = manager.create_request(
            "op",
            "desc",
            requester_id="alice",
            policy=policy,
        )
        # The request was created with expires_at ~= now, so it
        # should immediately be considered expired.
        expired = manager.check_expired()
        assert req.request_id in expired
        assert req.status == QuorumStatus.EXPIRED

    def test_check_expired_skips_non_pending(self, manager: QuorumManager) -> None:
        req = manager.create_request("op", "desc", requester_id="alice")
        manager.cancel_request(req.request_id, "alice")
        expired = manager.check_expired()
        assert req.request_id not in expired

    # -- Weighted voting --

    def test_weighted_voting(self) -> None:
        mgr = QuorumManager(default_policy=QuorumPolicy(min_approvals=5))
        mgr.add_member(QuorumMember(member_id="alice", name="Alice", weight=1))
        mgr.add_member(QuorumMember(member_id="bob", name="Bob", weight=3))
        mgr.add_member(QuorumMember(member_id="carol", name="Carol", weight=2))

        req = mgr.create_request("op", "desc", requester_id="alice")
        # bob (weight=3) + carol (weight=2) = 5 >= min_approvals=5
        mgr.cast_vote(req.request_id, "bob", approved=True)
        updated = mgr.cast_vote(req.request_id, "carol", approved=True)
        assert updated.status == QuorumStatus.APPROVED

    def test_weighted_rejection(self) -> None:
        mgr = QuorumManager(default_policy=QuorumPolicy(min_approvals=3, max_rejections=2))
        mgr.add_member(QuorumMember(member_id="alice", name="Alice", weight=1))
        mgr.add_member(QuorumMember(member_id="bob", name="Bob", weight=3))

        req = mgr.create_request("op", "desc", requester_id="alice")
        # bob rejects with weight=3, which is > max_rejections=2
        updated = mgr.cast_vote(req.request_id, "bob", approved=False)
        assert updated.status == QuorumStatus.REJECTED

    # -- Role-based validation --

    def test_allowed_roles(self, manager: QuorumManager) -> None:
        policy = QuorumPolicy(min_approvals=1, allowed_roles=["admin"])
        req = manager.create_request(
            "op",
            "desc",
            requester_id="bob",
            policy=policy,
        )
        # alice is admin -> allowed
        updated = manager.cast_vote(req.request_id, "alice", approved=True)
        assert updated.status == QuorumStatus.APPROVED

    def test_disallowed_role_rejected(self, manager: QuorumManager) -> None:
        policy = QuorumPolicy(min_approvals=1, allowed_roles=["admin"])
        req = manager.create_request(
            "op",
            "desc",
            requester_id="alice",
            policy=policy,
        )
        # bob is operator -> not allowed
        with pytest.raises(ValueError, match="not in the allowed"):
            manager.cast_vote(req.request_id, "bob", approved=True)

    def test_require_different_roles(self, manager: QuorumManager) -> None:
        # Add a second admin
        manager.add_member(QuorumMember(member_id="dave", name="Dave", role="admin"))
        policy = QuorumPolicy(min_approvals=2, require_different_roles=True)
        req = manager.create_request(
            "op",
            "desc",
            requester_id="bob",
            policy=policy,
        )
        # alice (admin) votes first
        manager.cast_vote(req.request_id, "alice", approved=True)
        # dave (also admin) should be blocked
        with pytest.raises(ValueError, match="different roles required"):
            manager.cast_vote(req.request_id, "dave", approved=True)

    # -- Vote summary --

    def test_get_vote_summary(self, manager: QuorumManager) -> None:
        req = manager.create_request("op", "desc", requester_id="alice")
        manager.cast_vote(req.request_id, "bob", approved=True)
        manager.cast_vote(req.request_id, "carol", approved=False)

        summary = manager.get_vote_summary(req.request_id)
        assert summary["approvals"] == 1
        assert summary["rejections"] == 1
        assert summary["total_votes"] == 2
        assert summary["required_approvals"] == 2

    def test_get_vote_summary_not_found(self, manager: QuorumManager) -> None:
        with pytest.raises(ValueError, match="Request not found"):
            manager.get_vote_summary("bad-id")

    # -- Listing --

    def test_list_requests_all(self, manager: QuorumManager) -> None:
        manager.create_request("op1", "desc1", requester_id="alice")
        manager.create_request("op2", "desc2", requester_id="bob")
        assert len(manager.list_requests()) == 2

    def test_list_requests_by_status(self, manager: QuorumManager) -> None:
        req = manager.create_request("op1", "desc1", requester_id="alice")
        manager.create_request("op2", "desc2", requester_id="bob")
        manager.cancel_request(req.request_id, "alice")

        pending = manager.list_requests(status=QuorumStatus.PENDING)
        cancelled = manager.list_requests(status=QuorumStatus.CANCELLED)
        assert len(pending) == 1
        assert len(cancelled) == 1

    def test_get_request(self, manager: QuorumManager) -> None:
        req = manager.create_request("op", "desc", requester_id="alice")
        fetched = manager.get_request(req.request_id)
        assert fetched is not None
        assert fetched.request_id == req.request_id

    def test_get_request_not_found(self, manager: QuorumManager) -> None:
        assert manager.get_request("bad-id") is None


# ------------------------------------------------------------------ #
# TestCreateDistributedSecrets                                        #
# ------------------------------------------------------------------ #


class TestCreateDistributedSecrets:
    """Tests for the create_distributed_secrets factory function."""

    def test_returns_dict_with_correct_keys(self) -> None:
        result = create_distributed_secrets()
        assert isinstance(result, dict)
        assert set(result.keys()) == {
            "shamir",
            "mpc",
            "hsm",
            "quorum",
        }

    def test_shamir_type(self) -> None:
        from harombe.security.distributed.shamir import (
            ShamirSecretSharing,
        )

        result = create_distributed_secrets()
        assert isinstance(result["shamir"], ShamirSecretSharing)

    def test_mpc_type(self) -> None:
        from harombe.security.distributed.mpc import MPCEngine

        result = create_distributed_secrets()
        assert isinstance(result["mpc"], MPCEngine)

    def test_hsm_type(self) -> None:
        from harombe.security.distributed.hsm import HSMManager

        result = create_distributed_secrets()
        assert isinstance(result["hsm"], HSMManager)

    def test_quorum_type(self) -> None:
        result = create_distributed_secrets()
        assert isinstance(result["quorum"], QuorumManager)
