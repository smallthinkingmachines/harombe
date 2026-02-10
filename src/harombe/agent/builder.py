"""Agent builder for constructing agents from configuration.

Provides functions to build an AgentRegistry from config and
create a root agent with delegation wired in.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from harombe.agent.delegation import DelegationContext
from harombe.agent.registry import AgentBlueprint, AgentRegistry

if TYPE_CHECKING:
    from harombe.config.schema import HarombeConfig, NamedAgentConfig


def build_agent_registry(agent_configs: list[NamedAgentConfig]) -> AgentRegistry:
    """Create an AgentRegistry from configuration.

    Args:
        agent_configs: List of named agent configurations

    Returns:
        Populated AgentRegistry
    """
    registry = AgentRegistry()
    for cfg in agent_configs:
        blueprint = AgentBlueprint(
            name=cfg.name,
            description=cfg.description,
            system_prompt=cfg.system_prompt,
            tools_config={
                "shell": cfg.tools.shell,
                "filesystem": cfg.tools.filesystem,
                "web_search": cfg.tools.web_search,
            },
            model=cfg.model,
            max_steps=cfg.max_steps,
            enable_rag=cfg.enable_rag,
        )
        registry.register(blueprint)
    return registry


def create_root_delegation_context(config: HarombeConfig) -> DelegationContext:
    """Create the root delegation context from config.

    Args:
        config: Harombe configuration

    Returns:
        Root DelegationContext with max_depth from config
    """
    return DelegationContext(
        chain=[],
        max_depth=config.delegation.max_depth,
    )
