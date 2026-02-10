"""Tests for multi-agent delegation."""

from unittest.mock import AsyncMock

import pytest

from harombe.agent.delegation import DelegationContext
from harombe.agent.registry import AgentBlueprint, AgentRegistry
from harombe.llm.client import CompletionResponse
from harombe.tools.delegation import create_delegation_tool


class TestDelegationContext:
    def test_initial_depth(self):
        ctx = DelegationContext(max_depth=3)
        assert ctx.depth == 0

    def test_can_delegate_within_limit(self):
        ctx = DelegationContext(max_depth=3)
        allowed, reason = ctx.can_delegate("agent_a")
        assert allowed is True
        assert reason == ""

    def test_depth_limit_blocks_delegation(self):
        ctx = DelegationContext(chain=["a", "b", "c"], max_depth=3)
        allowed, reason = ctx.can_delegate("d")
        assert allowed is False
        assert "Maximum delegation depth" in reason

    def test_cycle_detection(self):
        ctx = DelegationContext(chain=["a", "b"], max_depth=5)
        allowed, reason = ctx.can_delegate("a")
        assert allowed is False
        assert "Cycle detected" in reason

    def test_no_cycle_for_new_agent(self):
        ctx = DelegationContext(chain=["a", "b"], max_depth=5)
        allowed, _ = ctx.can_delegate("c")
        assert allowed is True

    def test_child_context(self):
        ctx = DelegationContext(chain=["root"], max_depth=3)
        child = ctx.child_context("child_agent")
        assert child.chain == ["root", "child_agent"]
        assert child.max_depth == 3
        assert child.depth == 2

    def test_child_context_does_not_mutate_parent(self):
        ctx = DelegationContext(chain=["root"], max_depth=3)
        child = ctx.child_context("child")
        assert ctx.chain == ["root"]
        assert child.chain == ["root", "child"]


class TestCreateDelegationTool:
    def _make_registry(self, agents: list[tuple[str, str]] | None = None) -> AgentRegistry:
        registry = AgentRegistry()
        if agents is None:
            agents = [
                ("researcher", "Searches the web"),
                ("coder", "Writes code"),
            ]
        for name, desc in agents:
            registry.register(
                AgentBlueprint(
                    name=name,
                    description=desc,
                    system_prompt=f"You are {name}.",
                )
            )
        return registry

    def test_creates_tool_with_agents(self):
        registry = self._make_registry()
        llm = AsyncMock()
        ctx = DelegationContext(max_depth=3)

        tool = create_delegation_tool(registry, llm, ctx)
        assert tool is not None
        assert tool.schema.name == "delegate"
        assert len(tool.schema.parameters) == 2

    def test_no_tool_for_empty_registry(self):
        registry = AgentRegistry()
        llm = AsyncMock()
        ctx = DelegationContext(max_depth=3)

        tool = create_delegation_tool(registry, llm, ctx)
        assert tool is None

    def test_enum_contains_agent_names(self):
        registry = self._make_registry()
        llm = AsyncMock()
        ctx = DelegationContext(max_depth=3)

        tool = create_delegation_tool(registry, llm, ctx)
        agent_param = next(p for p in tool.schema.parameters if p.name == "agent_name")
        assert set(agent_param.enum) == {"researcher", "coder"}

    def test_no_tool_when_depth_exhausted(self):
        registry = self._make_registry()
        llm = AsyncMock()
        ctx = DelegationContext(chain=["a", "b", "c"], max_depth=3)

        tool = create_delegation_tool(registry, llm, ctx)
        assert tool is None

    def test_filters_cyclic_agents(self):
        registry = self._make_registry()
        llm = AsyncMock()
        # "researcher" already in chain, should be filtered out
        ctx = DelegationContext(chain=["researcher"], max_depth=3)

        tool = create_delegation_tool(registry, llm, ctx)
        assert tool is not None
        agent_param = next(p for p in tool.schema.parameters if p.name == "agent_name")
        assert "researcher" not in agent_param.enum
        assert "coder" in agent_param.enum

    @pytest.mark.asyncio
    async def test_delegate_to_unknown_agent(self):
        registry = self._make_registry()
        llm = AsyncMock()
        ctx = DelegationContext(max_depth=3)

        tool = create_delegation_tool(registry, llm, ctx)
        result = await tool.execute(agent_name="nonexistent", task="do something")
        assert "Unknown agent" in result

    @pytest.mark.asyncio
    async def test_delegate_executes_child_agent(self):
        registry = self._make_registry([("helper", "A helper agent")])

        # Create a mock LLM that returns a direct answer (no tool calls)
        llm = AsyncMock()
        llm.complete = AsyncMock(
            return_value=CompletionResponse(
                content="I completed the task!",
                tool_calls=[],
            )
        )

        ctx = DelegationContext(max_depth=3)
        tool = create_delegation_tool(registry, llm, ctx, confirm_dangerous=False)

        result = await tool.execute(agent_name="helper", task="do something")
        assert result == "I completed the task!"

    @pytest.mark.asyncio
    async def test_delegate_handles_child_failure(self):
        registry = self._make_registry([("broken", "A broken agent")])

        llm = AsyncMock()
        llm.complete = AsyncMock(side_effect=RuntimeError("LLM exploded"))

        ctx = DelegationContext(max_depth=3)
        tool = create_delegation_tool(registry, llm, ctx, confirm_dangerous=False)

        result = await tool.execute(agent_name="broken", task="break things")
        assert "failed" in result.lower()
