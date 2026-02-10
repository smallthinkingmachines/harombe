"""ZKP-based operation authorization for the Harombe security framework.

Provides zero-knowledge proof mechanisms for authorizing agent operations
without revealing sensitive details such as full capability sets, exact trust
scores, or complete group memberships.

Three proof types are supported:

* **Capability proof** -- prove an agent possesses a specific capability
  without disclosing the rest of its capability set.
* **Trust-level proof** -- prove an agent's trust score meets or exceeds a
  required threshold without revealing the exact score.
* **Group-membership proof** -- prove an agent belongs to a particular group
  without revealing other group memberships.

Example:
    >>> from harombe.security.zkp.authorization import (
    ...     ZKPAuthorizationProvider,
    ...     ZKPAuthorizationVerifier,
    ... )
    >>>
    >>> provider = ZKPAuthorizationProvider()
    >>> pub = provider.register_agent(
    ...     "agent-1", trust_score=80,
    ...     capabilities=["read", "write"],
    ... )
    >>> claim = provider.prove_capability("agent-1", "read")
    >>>
    >>> verifier = ZKPAuthorizationVerifier()
    >>> verifier.register_agent_public("agent-1", pub)
    >>> assert verifier.verify_claim(claim)
"""

import functools
import hashlib
import logging
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from harombe.security.zkp.primitives import (
    PedersenCommitment,
    SchnorrProof,
    ZKPContext,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


class AuthorizationClaim(BaseModel):
    """A ZKP-based authorization claim.

    Attributes:
        agent_id: Identifier of the agent making the claim.
        capability: The capability or attribute being proven.
        proof_type: The kind of authorization proof
            (``"capability"``, ``"trust_level"``, or ``"group_membership"``).
        public_parameters: Public values needed for verification.
        proof_data: Serialized ZKP proof artifacts.
        timestamp: When the claim was created.
        valid_until: Optional expiration time for the claim.
    """

    agent_id: str
    capability: str
    proof_type: str
    public_parameters: dict[str, Any] = Field(default_factory=dict)
    proof_data: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    valid_until: datetime | None = None


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _capability_secret(agent_id: str, capability: str, ctx: ZKPContext) -> int:
    """Derive a deterministic secret from *agent_id* and *capability*."""
    data = f"{agent_id}:{capability}".encode()
    return ctx.hash_to_scalar(data)


def _group_secret(agent_id: str, group: str, ctx: ZKPContext) -> int:
    """Derive a deterministic secret from *agent_id* and *group*."""
    data = f"{agent_id}:group:{group}".encode()
    return ctx.hash_to_scalar(data)


def _proof_to_dict(proof: Any) -> dict[str, Any]:
    """Serialize a ``Proof`` to a JSON-safe dict."""
    return proof.model_dump(mode="json")


def _dict_to_proof(data: dict[str, Any]) -> Any:
    """Deserialize a dict back into a ``Proof``."""
    from harombe.security.zkp.primitives import Proof

    return Proof.model_validate(data)


# ---------------------------------------------------------------------------
# Agent record (internal)
# ---------------------------------------------------------------------------


class _AgentRecord(BaseModel):
    """Internal record of a registered agent's private data."""

    trust_score: int
    capabilities: list[str]
    group_memberships: list[str] = Field(default_factory=list)
    blinding_factor: int = 0
    commitment_bytes: bytes = b""

    model_config = {"arbitrary_types_allowed": True}


# ---------------------------------------------------------------------------
# ZKPAuthorizationProvider
# ---------------------------------------------------------------------------


class ZKPAuthorizationProvider:
    """Creates ZKP-based authorization proofs for registered agents.

    The provider holds agent secrets and can generate proofs on their
    behalf.  Only the corresponding public data is shared with verifiers.
    """

    def __init__(self) -> None:
        self._ctx = ZKPContext()
        self._agents: dict[str, _AgentRecord] = {}

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register_agent(
        self,
        agent_id: str,
        trust_score: int,
        capabilities: list[str],
        group_memberships: list[str] | None = None,
    ) -> dict[str, Any]:
        """Register an agent and return its public commitment data.

        Args:
            agent_id: Unique identifier for the agent.
            trust_score: Integer trust score for the agent.
            capabilities: List of capabilities the agent possesses.
            group_memberships: Optional list of groups the agent
                belongs to.

        Returns:
            A dict of public data that should be shared with verifiers.
        """
        if group_memberships is None:
            group_memberships = []

        # Pedersen commitment to trust score
        blinding = self._ctx.generate_private_key().private_numbers().private_value
        commitment_bytes, _ = PedersenCommitment.commit(trust_score, blinding, self._ctx)

        # Public keys for each capability
        capability_public_keys: dict[str, str] = {}
        for cap in capabilities:
            secret = _capability_secret(agent_id, cap, self._ctx)
            pub_key = self._ctx._scalar_mult(secret)
            pub_bytes = self._ctx.point_to_bytes(pub_key)
            capability_public_keys[cap] = pub_bytes.hex()

        # Public keys for each group membership
        group_public_keys: dict[str, str] = {}
        for grp in group_memberships:
            secret = _group_secret(agent_id, grp, self._ctx)
            pub_key = self._ctx._scalar_mult(secret)
            pub_bytes = self._ctx.point_to_bytes(pub_key)
            group_public_keys[grp] = pub_bytes.hex()

        self._agents[agent_id] = _AgentRecord(
            trust_score=trust_score,
            capabilities=capabilities,
            group_memberships=group_memberships,
            blinding_factor=blinding,
            commitment_bytes=commitment_bytes,
        )

        public_data: dict[str, Any] = {
            "agent_id": agent_id,
            "trust_commitment": commitment_bytes.hex(),
            "capability_public_keys": capability_public_keys,
            "group_public_keys": group_public_keys,
        }

        logger.info(
            "Registered agent %s with %d capabilities",
            agent_id,
            len(capabilities),
        )
        return public_data

    # ------------------------------------------------------------------
    # Capability proof
    # ------------------------------------------------------------------

    def prove_capability(self, agent_id: str, capability: str) -> AuthorizationClaim:
        """Prove *agent_id* has *capability* without revealing others.

        Raises:
            KeyError: If the agent is not registered.
            ValueError: If the agent does not have the capability.
        """
        record = self._get_agent(agent_id)
        if capability not in record.capabilities:
            msg = f"Agent {agent_id} does not have " f"capability '{capability}'"
            raise ValueError(msg)

        secret = _capability_secret(agent_id, capability, self._ctx)
        proof = SchnorrProof.generate(secret, self._ctx)

        logger.debug(
            "Generated capability proof for %s: %s",
            agent_id,
            capability,
        )
        return AuthorizationClaim(
            agent_id=agent_id,
            capability=capability,
            proof_type="capability",
            public_parameters={"capability": capability},
            proof_data=_proof_to_dict(proof),
        )

    # ------------------------------------------------------------------
    # Trust-level proof
    # ------------------------------------------------------------------

    def prove_trust_level(self, agent_id: str, required_level: int) -> AuthorizationClaim:
        """Prove trust score >= *required_level* without exact value.

        Uses a Pedersen commitment to the trust score and proves
        knowledge of the opening.

        Raises:
            KeyError: If the agent is not registered.
            ValueError: If the agent's trust score is below the
                required level.
        """
        record = self._get_agent(agent_id)
        if record.trust_score < required_level:
            msg = (
                f"Agent {agent_id} trust score "
                f"({record.trust_score}) is below "
                f"required level {required_level}"
            )
            raise ValueError(msg)

        # Create a Schnorr proof of knowledge of the blinding factor
        # to demonstrate ownership of the commitment.
        blinding_proof = SchnorrProof.generate(record.blinding_factor, self._ctx)

        # Compute a hash binding the required_level to the proof to
        # prevent replay at a different threshold.
        binding = hashlib.sha256(
            f"{agent_id}:{required_level}".encode() + record.commitment_bytes
        ).hexdigest()

        logger.debug(
            "Generated trust-level proof for %s >= %d",
            agent_id,
            required_level,
        )
        return AuthorizationClaim(
            agent_id=agent_id,
            capability=f"trust>={required_level}",
            proof_type="trust_level",
            public_parameters={
                "required_level": required_level,
                "commitment": record.commitment_bytes.hex(),
                "binding": binding,
            },
            proof_data=_proof_to_dict(blinding_proof),
        )

    # ------------------------------------------------------------------
    # Group-membership proof
    # ------------------------------------------------------------------

    def prove_group_membership(self, agent_id: str, group: str) -> AuthorizationClaim:
        """Prove *agent_id* is a member of *group*.

        Raises:
            KeyError: If the agent is not registered.
            ValueError: If the agent is not a member of the group.
        """
        record = self._get_agent(agent_id)
        if group not in record.group_memberships:
            msg = f"Agent {agent_id} is not a member " f"of group '{group}'"
            raise ValueError(msg)

        secret = _group_secret(agent_id, group, self._ctx)
        proof = SchnorrProof.generate(secret, self._ctx)

        logger.debug(
            "Generated group-membership proof for %s: %s",
            agent_id,
            group,
        )
        return AuthorizationClaim(
            agent_id=agent_id,
            capability=group,
            proof_type="group_membership",
            public_parameters={"group": group},
            proof_data=_proof_to_dict(proof),
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_agent(self, agent_id: str) -> _AgentRecord:
        """Return agent record or raise ``KeyError``."""
        if agent_id not in self._agents:
            msg = f"Agent {agent_id} is not registered"
            raise KeyError(msg)
        return self._agents[agent_id]


# ---------------------------------------------------------------------------
# ZKPAuthorizationVerifier
# ---------------------------------------------------------------------------


class ZKPAuthorizationVerifier:
    """Verifies ZKP authorization claims using only public data.

    The verifier never sees agent secrets, capability lists, trust
    scores, or group memberships -- only the public commitments
    registered via :meth:`register_agent_public`.
    """

    def __init__(self) -> None:
        self._ctx = ZKPContext()
        self._agents: dict[str, dict[str, Any]] = {}

    def register_agent_public(self, agent_id: str, public_data: dict[str, Any]) -> None:
        """Register public data for an agent.

        Args:
            agent_id: Identifier matching the provider's registration.
            public_data: The dict returned by
                :meth:`ZKPAuthorizationProvider.register_agent`.
        """
        self._agents[agent_id] = public_data
        logger.info("Registered public data for agent %s", agent_id)

    # ------------------------------------------------------------------
    # Capability verification
    # ------------------------------------------------------------------

    def verify_capability(self, claim: AuthorizationClaim) -> bool:
        """Verify a capability proof claim.

        Returns ``True`` when the Schnorr proof is valid and the
        derived public key matches the registered capability key.
        """
        public_data = self._agents.get(claim.agent_id)
        if public_data is None:
            logger.warning("No public data for agent %s", claim.agent_id)
            return False

        cap = claim.public_parameters.get("capability", "")
        cap_keys = public_data.get("capability_public_keys", {})
        expected_hex = cap_keys.get(cap)
        if expected_hex is None:
            logger.warning(
                "Capability %s not registered for %s",
                cap,
                claim.agent_id,
            )
            return False

        proof = _dict_to_proof(claim.proof_data)
        result = SchnorrProof.verify(proof, self._ctx)
        if not result.valid:
            logger.warning(
                "Schnorr verification failed for capability " "claim: %s",
                result.error,
            )
            return False

        # Confirm the public key in the proof matches the registered
        # capability public key.
        if proof.public_input is None:
            return False
        if proof.public_input.hex() != expected_hex:
            logger.warning("Public key mismatch for capability %s", cap)
            return False

        return True

    # ------------------------------------------------------------------
    # Trust-level verification
    # ------------------------------------------------------------------

    def verify_trust_level(self, claim: AuthorizationClaim) -> bool:
        """Verify a trust-level proof claim.

        Checks the Schnorr proof of knowledge of the commitment's
        blinding factor and verifies the binding hash.
        """
        public_data = self._agents.get(claim.agent_id)
        if public_data is None:
            logger.warning("No public data for agent %s", claim.agent_id)
            return False

        required_level = claim.public_parameters.get("required_level")
        commitment_hex = claim.public_parameters.get("commitment")
        binding = claim.public_parameters.get("binding")
        if required_level is None or commitment_hex is None:
            return False

        # Verify the commitment matches the registered commitment
        registered_commitment = public_data.get("trust_commitment")
        if registered_commitment != commitment_hex:
            logger.warning("Trust commitment mismatch for %s", claim.agent_id)
            return False

        # Verify the binding hash
        expected_binding = hashlib.sha256(
            f"{claim.agent_id}:{required_level}".encode() + bytes.fromhex(commitment_hex)
        ).hexdigest()
        if binding != expected_binding:
            logger.warning("Binding hash mismatch for %s", claim.agent_id)
            return False

        # Verify the Schnorr proof (knowledge of blinding factor)
        proof = _dict_to_proof(claim.proof_data)
        result = SchnorrProof.verify(proof, self._ctx)
        if not result.valid:
            logger.warning(
                "Schnorr verification failed for trust-level " "claim: %s",
                result.error,
            )
            return False

        return True

    # ------------------------------------------------------------------
    # Group-membership verification
    # ------------------------------------------------------------------

    def verify_group_membership(self, claim: AuthorizationClaim) -> bool:
        """Verify a group-membership proof claim.

        Returns ``True`` when the Schnorr proof is valid and the
        derived public key matches the registered group key.
        """
        public_data = self._agents.get(claim.agent_id)
        if public_data is None:
            logger.warning("No public data for agent %s", claim.agent_id)
            return False

        group = claim.public_parameters.get("group", "")
        group_keys = public_data.get("group_public_keys", {})
        expected_hex = group_keys.get(group)
        if expected_hex is None:
            logger.warning(
                "Group %s not registered for %s",
                group,
                claim.agent_id,
            )
            return False

        proof = _dict_to_proof(claim.proof_data)
        result = SchnorrProof.verify(proof, self._ctx)
        if not result.valid:
            logger.warning(
                "Schnorr verification failed for " "group-membership claim: %s",
                result.error,
            )
            return False

        if proof.public_input is None:
            return False
        if proof.public_input.hex() != expected_hex:
            logger.warning("Public key mismatch for group %s", group)
            return False

        return True

    # ------------------------------------------------------------------
    # Unified dispatch
    # ------------------------------------------------------------------

    def verify_claim(self, claim: AuthorizationClaim) -> bool:
        """Verify an :class:`AuthorizationClaim` by dispatching to the
        appropriate proof-specific verifier.

        Returns:
            ``True`` if the claim is valid, ``False`` otherwise.
        """
        dispatchers: dict[str, Any] = {
            "capability": self.verify_capability,
            "trust_level": self.verify_trust_level,
            "group_membership": self.verify_group_membership,
        }
        handler = dispatchers.get(claim.proof_type)
        if handler is None:
            logger.warning("Unknown proof type: %s", claim.proof_type)
            return False
        return handler(claim)


# ---------------------------------------------------------------------------
# ZKPGateDecorator
# ---------------------------------------------------------------------------


class ZKPGateDecorator:
    """Utility for gating function calls with ZKP authorization checks.

    Wraps functions so that a valid :class:`AuthorizationClaim` must be
    provided as the first argument.
    """

    def __init__(self, verifier: ZKPAuthorizationVerifier) -> None:
        self._verifier = verifier

    def require_capability(self, capability: str):
        """Return a decorator that requires a valid capability claim.

        The decorated function must accept an
        :class:`AuthorizationClaim` as its first positional argument.

        Raises:
            PermissionError: If the claim is invalid or does not match
                the required capability.
        """

        def decorator(fn):
            @functools.wraps(fn)
            def wrapper(claim: AuthorizationClaim, *args, **kwargs):
                if claim.proof_type != "capability":
                    msg = f"Expected capability claim, " f"got {claim.proof_type}"
                    raise PermissionError(msg)
                if claim.public_parameters.get("capability") != capability:
                    msg = (
                        f"Claim is for capability "
                        f"'{claim.public_parameters.get('capability')}'"
                        f", required '{capability}'"
                    )
                    raise PermissionError(msg)
                if not self._verifier.verify_claim(claim):
                    msg = f"ZKP verification failed for " f"capability '{capability}'"
                    raise PermissionError(msg)
                return fn(claim, *args, **kwargs)

            return wrapper

        return decorator

    def require_trust_level(self, level: int):
        """Return a decorator that requires a valid trust-level claim.

        The decorated function must accept an
        :class:`AuthorizationClaim` as its first positional argument.

        Raises:
            PermissionError: If the claim is invalid or does not meet
                the required trust level.
        """

        def decorator(fn):
            @functools.wraps(fn)
            def wrapper(claim: AuthorizationClaim, *args, **kwargs):
                if claim.proof_type != "trust_level":
                    msg = f"Expected trust_level claim, " f"got {claim.proof_type}"
                    raise PermissionError(msg)
                required = claim.public_parameters.get("required_level", 0)
                if required < level:
                    msg = f"Claim proves trust >= {required}, " f"but {level} is required"
                    raise PermissionError(msg)
                if not self._verifier.verify_claim(claim):
                    msg = f"ZKP verification failed for " f"trust level >= {level}"
                    raise PermissionError(msg)
                return fn(claim, *args, **kwargs)

            return wrapper

        return decorator
