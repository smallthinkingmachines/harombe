"""Tests for ZKP-based operation authorization."""

import base64

import pytest

from harombe.security.zkp.authorization import (
    AuthorizationClaim,
    ZKPAuthorizationProvider,
    ZKPAuthorizationVerifier,
    ZKPGateDecorator,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def provider():
    """Create a ZKPAuthorizationProvider for tests."""
    return ZKPAuthorizationProvider()


@pytest.fixture
def verifier():
    """Create a ZKPAuthorizationVerifier for tests."""
    return ZKPAuthorizationVerifier()


@pytest.fixture
def registered_agent(provider, verifier):
    """Register an agent and return (provider, verifier, pub_data)."""
    pub = provider.register_agent(
        "agent-1",
        trust_score=80,
        capabilities=["read", "write", "execute"],
        group_memberships=["admin", "devops"],
    )
    verifier.register_agent_public("agent-1", pub)
    return provider, verifier, pub


# ---------------------------------------------------------------------------
# TestAuthorizationClaim
# ---------------------------------------------------------------------------


class TestAuthorizationClaim:
    """Tests for the AuthorizationClaim data model."""

    def test_creation_with_defaults(self):
        """Claim can be created with only required fields."""
        claim = AuthorizationClaim(
            agent_id="a1",
            capability="read",
            proof_type="capability",
        )
        assert claim.agent_id == "a1"
        assert claim.capability == "read"
        assert claim.proof_type == "capability"
        assert claim.public_parameters == {}
        assert claim.proof_data == {}

    def test_timestamp_auto_set(self):
        """Timestamp is automatically populated on creation."""
        claim = AuthorizationClaim(
            agent_id="a1",
            capability="x",
            proof_type="test",
        )
        assert claim.timestamp is not None

    def test_valid_until_defaults_to_none(self):
        """valid_until defaults to None."""
        claim = AuthorizationClaim(
            agent_id="a1",
            capability="x",
            proof_type="test",
        )
        assert claim.valid_until is None

    def test_serialization_round_trip(self):
        """Claim survives JSON serialization round trip."""
        claim = AuthorizationClaim(
            agent_id="a1",
            capability="write",
            proof_type="capability",
            public_parameters={"key": "val"},
        )
        data = claim.model_dump(mode="json")
        restored = AuthorizationClaim.model_validate(data)
        assert restored.agent_id == claim.agent_id
        assert restored.public_parameters == {"key": "val"}


# ---------------------------------------------------------------------------
# TestZKPAuthorizationProvider
# ---------------------------------------------------------------------------


class TestZKPAuthorizationProvider:
    """Tests for ZKPAuthorizationProvider."""

    def test_register_agent_returns_public_data(self, provider):
        """register_agent returns dict with expected keys."""
        pub = provider.register_agent(
            "agent-1",
            trust_score=50,
            capabilities=["read"],
        )
        assert "agent_id" in pub
        assert "trust_commitment" in pub
        assert "capability_public_keys" in pub
        assert "group_public_keys" in pub
        assert pub["agent_id"] == "agent-1"

    def test_register_agent_capability_keys(self, provider):
        """Public data includes a key per capability."""
        pub = provider.register_agent(
            "agent-1",
            trust_score=50,
            capabilities=["read", "write"],
        )
        assert "read" in pub["capability_public_keys"]
        assert "write" in pub["capability_public_keys"]

    def test_register_agent_group_keys(self, provider):
        """Public data includes a key per group membership."""
        pub = provider.register_agent(
            "agent-1",
            trust_score=50,
            capabilities=[],
            group_memberships=["admin", "devops"],
        )
        assert "admin" in pub["group_public_keys"]
        assert "devops" in pub["group_public_keys"]

    def test_prove_capability_returns_claim(self, registered_agent):
        """prove_capability returns an AuthorizationClaim."""
        provider, _, _ = registered_agent
        claim = provider.prove_capability("agent-1", "read")
        assert isinstance(claim, AuthorizationClaim)
        assert claim.proof_type == "capability"
        assert claim.agent_id == "agent-1"

    def test_prove_capability_unknown_agent(self, provider):
        """prove_capability raises KeyError for unknown agent."""
        with pytest.raises(KeyError, match="not registered"):
            provider.prove_capability("unknown", "read")

    def test_prove_capability_missing_capability(self, registered_agent):
        """prove_capability raises ValueError for missing cap."""
        provider, _, _ = registered_agent
        with pytest.raises(ValueError, match="does not have"):
            provider.prove_capability("agent-1", "delete")

    def test_prove_trust_level_returns_claim(self, registered_agent):
        """prove_trust_level returns an AuthorizationClaim."""
        provider, _, _ = registered_agent
        claim = provider.prove_trust_level("agent-1", 50)
        assert isinstance(claim, AuthorizationClaim)
        assert claim.proof_type == "trust_level"

    def test_prove_trust_level_exact_threshold(self, registered_agent):
        """prove_trust_level works when score equals threshold."""
        provider, _, _ = registered_agent
        claim = provider.prove_trust_level("agent-1", 80)
        assert claim.proof_type == "trust_level"

    def test_prove_trust_level_insufficient(self, registered_agent):
        """prove_trust_level raises when score is too low."""
        provider, _, _ = registered_agent
        with pytest.raises(ValueError, match="below"):
            provider.prove_trust_level("agent-1", 99)

    def test_prove_trust_level_unknown_agent(self, provider):
        """prove_trust_level raises KeyError for unknown agent."""
        with pytest.raises(KeyError, match="not registered"):
            provider.prove_trust_level("unknown", 10)

    def test_prove_group_membership_returns_claim(self, registered_agent):
        """prove_group_membership returns an AuthorizationClaim."""
        provider, _, _ = registered_agent
        claim = provider.prove_group_membership("agent-1", "admin")
        assert isinstance(claim, AuthorizationClaim)
        assert claim.proof_type == "group_membership"

    def test_prove_group_membership_not_member(self, registered_agent):
        """prove_group_membership raises for non-member."""
        provider, _, _ = registered_agent
        with pytest.raises(ValueError, match="not a member"):
            provider.prove_group_membership("agent-1", "finance")

    def test_prove_group_membership_unknown_agent(self, provider):
        """prove_group_membership raises for unknown agent."""
        with pytest.raises(KeyError, match="not registered"):
            provider.prove_group_membership("unknown", "admin")


# ---------------------------------------------------------------------------
# TestZKPAuthorizationVerifier
# ---------------------------------------------------------------------------


class TestZKPAuthorizationVerifier:
    """Tests for ZKPAuthorizationVerifier."""

    def test_verify_capability_valid(self, registered_agent):
        """Valid capability claim verifies successfully."""
        provider, verifier, _ = registered_agent
        claim = provider.prove_capability("agent-1", "read")
        assert verifier.verify_capability(claim) is True

    def test_verify_capability_tampered_proof(self, registered_agent):
        """Tampered capability claim fails verification."""
        provider, verifier, _ = registered_agent
        claim = provider.prove_capability("agent-1", "read")
        # Tamper with the proof response by flipping a bit in the raw bytes
        resp = claim.proof_data.get("response", "")
        if resp:
            raw = bytearray(base64.b64decode(resp))
            raw[0] ^= 0x01
            claim.proof_data["response"] = base64.b64encode(bytes(raw)).decode()
        assert verifier.verify_capability(claim) is False

    def test_verify_capability_unknown_agent(self, verifier):
        """Capability claim from unknown agent fails."""
        claim = AuthorizationClaim(
            agent_id="unknown",
            capability="read",
            proof_type="capability",
            public_parameters={"capability": "read"},
        )
        assert verifier.verify_capability(claim) is False

    def test_verify_trust_level_valid(self, registered_agent):
        """Valid trust-level claim verifies successfully."""
        provider, verifier, _ = registered_agent
        claim = provider.prove_trust_level("agent-1", 50)
        assert verifier.verify_trust_level(claim) is True

    def test_verify_trust_level_tampered_commitment(self, registered_agent):
        """Tampered trust commitment fails verification."""
        provider, verifier, _ = registered_agent
        claim = provider.prove_trust_level("agent-1", 50)
        # Tamper with the commitment
        claim.public_parameters["commitment"] = "ff" * 33
        assert verifier.verify_trust_level(claim) is False

    def test_verify_trust_level_unknown_agent(self, verifier):
        """Trust-level claim from unknown agent fails."""
        claim = AuthorizationClaim(
            agent_id="unknown",
            capability="trust>=50",
            proof_type="trust_level",
            public_parameters={
                "required_level": 50,
                "commitment": "aa" * 33,
            },
        )
        assert verifier.verify_trust_level(claim) is False

    def test_verify_group_membership_valid(self, registered_agent):
        """Valid group-membership claim verifies successfully."""
        provider, verifier, _ = registered_agent
        claim = provider.prove_group_membership("agent-1", "admin")
        assert verifier.verify_group_membership(claim) is True

    def test_verify_group_membership_tampered(self, registered_agent):
        """Tampered group-membership claim fails verification."""
        provider, verifier, _ = registered_agent
        claim = provider.prove_group_membership("agent-1", "admin")
        resp = claim.proof_data.get("response", "")
        if resp:
            raw = bytearray(base64.b64decode(resp))
            raw[0] ^= 0x01
            claim.proof_data["response"] = base64.b64encode(bytes(raw)).decode()
        assert verifier.verify_group_membership(claim) is False

    def test_verify_group_membership_unknown_agent(self, verifier):
        """Group claim from unknown agent fails."""
        claim = AuthorizationClaim(
            agent_id="unknown",
            capability="admin",
            proof_type="group_membership",
            public_parameters={"group": "admin"},
        )
        assert verifier.verify_group_membership(claim) is False

    def test_verify_claim_dispatches_capability(self, registered_agent):
        """verify_claim dispatches to verify_capability."""
        provider, verifier, _ = registered_agent
        claim = provider.prove_capability("agent-1", "write")
        assert verifier.verify_claim(claim) is True

    def test_verify_claim_dispatches_trust_level(self, registered_agent):
        """verify_claim dispatches to verify_trust_level."""
        provider, verifier, _ = registered_agent
        claim = provider.prove_trust_level("agent-1", 60)
        assert verifier.verify_claim(claim) is True

    def test_verify_claim_dispatches_group(self, registered_agent):
        """verify_claim dispatches to verify_group_membership."""
        provider, verifier, _ = registered_agent
        claim = provider.prove_group_membership("agent-1", "devops")
        assert verifier.verify_claim(claim) is True

    def test_verify_claim_unknown_proof_type(self, verifier):
        """verify_claim returns False for unknown proof_type."""
        claim = AuthorizationClaim(
            agent_id="agent-1",
            capability="x",
            proof_type="unknown_type",
        )
        assert verifier.verify_claim(claim) is False


# ---------------------------------------------------------------------------
# TestZKPGateDecorator
# ---------------------------------------------------------------------------


class TestZKPGateDecorator:
    """Tests for ZKPGateDecorator."""

    def test_require_capability_allows_valid(self, registered_agent):
        """Decorated function executes with valid capability claim."""
        provider, verifier, _ = registered_agent
        gate = ZKPGateDecorator(verifier)

        @gate.require_capability("read")
        def protected(claim):
            return "success"

        claim = provider.prove_capability("agent-1", "read")
        assert protected(claim) == "success"

    def test_require_capability_rejects_invalid(self, registered_agent):
        """Decorated function raises PermissionError on bad claim."""
        provider, verifier, _ = registered_agent
        gate = ZKPGateDecorator(verifier)

        @gate.require_capability("read")
        def protected(claim):
            return "success"

        # Create a claim for a different capability
        claim = provider.prove_capability("agent-1", "write")
        with pytest.raises(PermissionError, match="required"):
            protected(claim)

    def test_require_capability_rejects_wrong_type(self, registered_agent):
        """Decorated function raises if claim is not capability type."""
        provider, verifier, _ = registered_agent
        gate = ZKPGateDecorator(verifier)

        @gate.require_capability("read")
        def protected(claim):
            return "success"

        claim = provider.prove_trust_level("agent-1", 50)
        with pytest.raises(PermissionError, match="capability"):
            protected(claim)

    def test_require_trust_level_allows_valid(self, registered_agent):
        """Decorated function executes with valid trust-level claim."""
        provider, verifier, _ = registered_agent
        gate = ZKPGateDecorator(verifier)

        @gate.require_trust_level(50)
        def protected(claim):
            return "trusted"

        claim = provider.prove_trust_level("agent-1", 50)
        assert protected(claim) == "trusted"

    def test_require_trust_level_rejects_insufficient(self, registered_agent):
        """Decorated function rejects claim proving lower level."""
        provider, verifier, _ = registered_agent
        gate = ZKPGateDecorator(verifier)

        @gate.require_trust_level(70)
        def protected(claim):
            return "trusted"

        # Agent proves >= 50, but decorator requires >= 70
        claim = provider.prove_trust_level("agent-1", 50)
        with pytest.raises(PermissionError, match="required"):
            protected(claim)

    def test_require_trust_level_rejects_wrong_type(self, registered_agent):
        """Decorated function raises if claim is not trust_level."""
        provider, verifier, _ = registered_agent
        gate = ZKPGateDecorator(verifier)

        @gate.require_trust_level(50)
        def protected(claim):
            return "trusted"

        claim = provider.prove_capability("agent-1", "read")
        with pytest.raises(PermissionError, match="trust_level"):
            protected(claim)


# ---------------------------------------------------------------------------
# TestEndToEnd
# ---------------------------------------------------------------------------


class TestEndToEnd:
    """End-to-end tests for the full register -> prove -> verify flow."""

    def test_full_capability_flow(self):
        """Full flow: register, prove capability, verify."""
        provider = ZKPAuthorizationProvider()
        verifier = ZKPAuthorizationVerifier()

        pub = provider.register_agent(
            "e2e-agent",
            trust_score=70,
            capabilities=["deploy", "monitor"],
        )
        verifier.register_agent_public("e2e-agent", pub)

        claim = provider.prove_capability("e2e-agent", "deploy")
        assert verifier.verify_claim(claim) is True

    def test_full_trust_level_flow(self):
        """Full flow: register, prove trust level, verify."""
        provider = ZKPAuthorizationProvider()
        verifier = ZKPAuthorizationVerifier()

        pub = provider.register_agent(
            "e2e-agent",
            trust_score=90,
            capabilities=[],
        )
        verifier.register_agent_public("e2e-agent", pub)

        claim = provider.prove_trust_level("e2e-agent", 75)
        assert verifier.verify_claim(claim) is True

    def test_full_group_membership_flow(self):
        """Full flow: register, prove group membership, verify."""
        provider = ZKPAuthorizationProvider()
        verifier = ZKPAuthorizationVerifier()

        pub = provider.register_agent(
            "e2e-agent",
            trust_score=50,
            capabilities=[],
            group_memberships=["ops", "security"],
        )
        verifier.register_agent_public("e2e-agent", pub)

        claim = provider.prove_group_membership("e2e-agent", "security")
        assert verifier.verify_claim(claim) is True

    def test_multiple_agents_isolated(self):
        """Proofs from one agent do not verify for another."""
        provider = ZKPAuthorizationProvider()
        verifier = ZKPAuthorizationVerifier()

        pub1 = provider.register_agent(
            "agent-a",
            trust_score=80,
            capabilities=["read"],
        )
        pub2 = provider.register_agent(
            "agent-b",
            trust_score=60,
            capabilities=["write"],
        )
        verifier.register_agent_public("agent-a", pub1)
        verifier.register_agent_public("agent-b", pub2)

        claim = provider.prove_capability("agent-a", "read")
        # Replace agent_id to attempt impersonation
        claim.agent_id = "agent-b"
        assert verifier.verify_claim(claim) is False
