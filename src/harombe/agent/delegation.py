"""Delegation context for tracking and constraining agent delegation chains."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class DelegationContext:
    """Tracks the delegation chain from root agent to current agent.

    Enforces max_depth and detects cycles (no agent name may appear
    twice in the chain).
    """

    chain: list[str] = field(default_factory=list)
    max_depth: int = 3

    @property
    def depth(self) -> int:
        """Current delegation depth."""
        return len(self.chain)

    def can_delegate(self, target_name: str) -> tuple[bool, str]:
        """Check if delegation to the target agent is allowed.

        Args:
            target_name: Name of the agent to delegate to

        Returns:
            Tuple of (allowed, reason_string)
        """
        if self.depth >= self.max_depth:
            return False, f"Maximum delegation depth ({self.max_depth}) reached"

        if target_name in self.chain:
            return False, f"Cycle detected: '{target_name}' already in chain {self.chain}"

        return True, ""

    def child_context(self, agent_name: str) -> DelegationContext:
        """Create a child context for a delegated agent.

        Args:
            agent_name: Name of the current agent being delegated to

        Returns:
            New DelegationContext with extended chain
        """
        return DelegationContext(
            chain=[*self.chain, agent_name],
            max_depth=self.max_depth,
        )
