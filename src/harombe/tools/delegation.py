"""Delegation tool factory for multi-agent delegation.

Creates a Tool that lets an agent delegate tasks to other named agents.
The tool is NOT registered in the global _TOOLS dict — it's created
per-agent and injected directly.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from harombe.tools.base import Tool, ToolParameter, ToolSchema

if TYPE_CHECKING:
    from harombe.agent.delegation import DelegationContext
    from harombe.agent.registry import AgentRegistry
    from harombe.llm.client import LLMClient

logger = logging.getLogger(__name__)


def create_delegation_tool(
    registry: AgentRegistry,
    llm: LLMClient,
    delegation_context: DelegationContext,
    confirm_dangerous: bool = False,
) -> Tool | None:
    """Create a delegation tool for an agent.

    Args:
        registry: Agent registry with available blueprints
        llm: Default LLM client (used when blueprint has no model override)
        delegation_context: Current delegation context
        confirm_dangerous: Whether child agents require dangerous tool confirmation

    Returns:
        Tool instance, or None if no agents are available
    """
    available_agents = registry.list_agents()
    if not available_agents:
        return None

    # Filter to agents we can actually delegate to
    delegatable = []
    for bp in available_agents:
        allowed, _ = delegation_context.can_delegate(bp.name)
        if allowed:
            delegatable.append(bp)

    if not delegatable:
        return None

    # Build agent descriptions for the tool description
    agent_descriptions = "\n".join(f"- {bp.name}: {bp.description}" for bp in delegatable)
    agent_names = [bp.name for bp in delegatable]

    schema = ToolSchema(
        name="delegate",
        description=(
            f"Delegate a task to a specialized agent. Available agents:\n{agent_descriptions}"
        ),
        parameters=[
            ToolParameter(
                name="agent_name",
                type="string",
                description="Name of the agent to delegate to",
                required=True,
                enum=agent_names,
            ),
            ToolParameter(
                name="task",
                type="string",
                description="The task to delegate (be specific about what you need)",
                required=True,
            ),
        ],
        dangerous=False,
    )

    async def delegate_fn(agent_name: str, task: str) -> str:
        """Execute delegation to a child agent."""
        # Validate agent exists
        if not registry.has(agent_name):
            return f"Error: Unknown agent '{agent_name}'"

        # Check delegation is allowed
        allowed, reason = delegation_context.can_delegate(agent_name)
        if not allowed:
            return f"Error: Cannot delegate to '{agent_name}': {reason}"

        blueprint = registry.get(agent_name)

        # Import Agent here to avoid circular import
        import harombe.tools.filesystem

        # Import tool modules to register them
        import harombe.tools.shell
        import harombe.tools.web_search  # noqa: F401
        from harombe.agent.loop import Agent
        from harombe.tools.registry import get_enabled_tools

        # Get tools for the child agent
        tools = get_enabled_tools(
            shell=blueprint.tools_config.get("shell", True),
            filesystem=blueprint.tools_config.get("filesystem", True),
            web_search=blueprint.tools_config.get("web_search", True),
        )

        # Create child delegation context
        child_context = delegation_context.child_context(agent_name)

        # Optionally add delegation tool to child agent if depth allows
        child_delegation_tool = create_delegation_tool(
            registry=registry,
            llm=llm,
            delegation_context=child_context,
            confirm_dangerous=confirm_dangerous,
        )
        if child_delegation_tool:
            tools.append(child_delegation_tool)

        # Create child agent
        child_agent = Agent(
            llm=llm,
            tools=tools,
            max_steps=blueprint.max_steps,
            system_prompt=blueprint.system_prompt,
            confirm_dangerous=confirm_dangerous,
        )

        try:
            result = await child_agent.run(task)
            logger.info(
                "Delegation to '%s' completed (depth %d)",
                agent_name,
                child_context.depth,
            )
            return result
        except Exception as e:
            logger.error("Delegation to '%s' failed: %s", agent_name, e)
            return f"Error: Delegation to '{agent_name}' failed: {e}"

    return Tool(schema=schema, fn=delegate_fn)
