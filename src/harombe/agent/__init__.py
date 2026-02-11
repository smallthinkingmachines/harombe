"""ReAct agent loop for autonomous task execution.

This module implements the Reasoning + Acting (ReAct) pattern where the agent
alternates between reasoning about what to do and executing tool calls.
The loop continues until the task is complete or the step limit is reached.

Usage::

    from harombe.agent.loop import Agent
    from harombe.llm.factory import create_llm_client
    from harombe.config.schema import HarombeConfig
    from harombe.tools.registry import get_enabled_tools

    llm = create_llm_client(HarombeConfig())
    tools = get_enabled_tools(shell=True, filesystem=True)
    agent = Agent(llm=llm, tools=tools)
    response = await agent.run("Analyze this file")
"""

from harombe.agent.builder import build_agent_registry, create_root_delegation_context
from harombe.agent.delegation import DelegationContext
from harombe.agent.loop import Agent, AgentState
from harombe.agent.registry import AgentBlueprint, AgentRegistry

__all__ = [
    "Agent",
    "AgentBlueprint",
    "AgentRegistry",
    "AgentState",
    "DelegationContext",
    "build_agent_registry",
    "create_root_delegation_context",
]
