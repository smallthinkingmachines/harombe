"""Tests for agent registry."""

import pytest

from harombe.agent.registry import AgentBlueprint, AgentRegistry


def _make_blueprint(name: str = "test_agent", description: str = "A test agent") -> AgentBlueprint:
    return AgentBlueprint(
        name=name,
        description=description,
        system_prompt="You are a test agent.",
    )


class TestAgentBlueprint:
    def test_defaults(self):
        bp = AgentBlueprint(name="a", description="b", system_prompt="c")
        assert bp.max_steps == 10
        assert bp.model is None
        assert bp.enable_rag is False
        assert "shell" in bp.tools_config


class TestAgentRegistry:
    def test_register_and_get(self):
        registry = AgentRegistry()
        bp = _make_blueprint("researcher")
        registry.register(bp)
        assert registry.get("researcher") is bp

    def test_has(self):
        registry = AgentRegistry()
        registry.register(_make_blueprint("coder"))
        assert registry.has("coder") is True
        assert registry.has("nonexistent") is False

    def test_list_agents(self):
        registry = AgentRegistry()
        registry.register(_make_blueprint("a"))
        registry.register(_make_blueprint("b"))
        agents = registry.list_agents()
        assert len(agents) == 2

    def test_names(self):
        registry = AgentRegistry()
        registry.register(_make_blueprint("researcher"))
        registry.register(_make_blueprint("coder"))
        assert set(registry.names) == {"researcher", "coder"}

    def test_duplicate_name_raises(self):
        registry = AgentRegistry()
        registry.register(_make_blueprint("dup"))
        with pytest.raises(ValueError, match="already registered"):
            registry.register(_make_blueprint("dup"))

    def test_missing_name_raises(self):
        registry = AgentRegistry()
        with pytest.raises(KeyError, match="not found"):
            registry.get("nonexistent")

    def test_empty_registry(self):
        registry = AgentRegistry()
        assert registry.list_agents() == []
        assert registry.names == []
