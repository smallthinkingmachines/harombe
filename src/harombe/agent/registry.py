"""Agent registry for multi-agent delegation.

Stores agent blueprints (not live instances). Each delegation creates
a fresh Agent from the blueprint.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class AgentBlueprint:
    """Blueprint for creating an agent instance.

    This stores the configuration needed to create a fresh Agent.
    Each delegation creates a new Agent from this blueprint.
    """

    name: str
    description: str
    system_prompt: str
    tools_config: dict[str, bool] = field(
        default_factory=lambda: {
            "shell": True,
            "filesystem": True,
            "web_search": True,
        }
    )
    model: str | None = None
    max_steps: int = 10
    enable_rag: bool = False


class AgentRegistry:
    """Registry of named agent blueprints.

    Agents are registered by name. The registry stores blueprints,
    not live instances — each delegation creates a fresh Agent.
    """

    def __init__(self) -> None:
        self._blueprints: dict[str, AgentBlueprint] = {}

    def register(self, blueprint: AgentBlueprint) -> None:
        """Register an agent blueprint.

        Args:
            blueprint: Agent blueprint to register

        Raises:
            ValueError: If an agent with the same name already exists
        """
        if blueprint.name in self._blueprints:
            raise ValueError(f"Agent '{blueprint.name}' already registered")
        self._blueprints[blueprint.name] = blueprint

    def get(self, name: str) -> AgentBlueprint:
        """Get an agent blueprint by name.

        Args:
            name: Agent name

        Returns:
            AgentBlueprint instance

        Raises:
            KeyError: If agent not found
        """
        if name not in self._blueprints:
            raise KeyError(f"Agent '{name}' not found in registry")
        return self._blueprints[name]

    def has(self, name: str) -> bool:
        """Check if an agent is registered."""
        return name in self._blueprints

    def list_agents(self) -> list[AgentBlueprint]:
        """List all registered agent blueprints."""
        return list(self._blueprints.values())

    @property
    def names(self) -> list[str]:
        """List all registered agent names."""
        return list(self._blueprints.keys())
