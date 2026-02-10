"""Tests for pattern registry."""

import pytest

from harombe.patterns.registry import PatternRegistry, register_pattern


class TestPatternRegistry:
    def test_register_and_get(self):
        class DummyPattern:
            pass

        PatternRegistry.register("_test_dummy", DummyPattern)
        assert PatternRegistry.get("_test_dummy") is DummyPattern
        # Cleanup
        del PatternRegistry._patterns["_test_dummy"]

    def test_get_unknown_raises_key_error(self):
        with pytest.raises(KeyError, match="Unknown pattern"):
            PatternRegistry.get("nonexistent_pattern_xyz")

    def test_available_returns_sorted_list(self):
        available = PatternRegistry.available()
        assert isinstance(available, list)
        assert available == sorted(available)

    def test_all_six_patterns_registered(self):
        # Importing the package triggers registration
        import harombe.patterns  # noqa: F401

        available = PatternRegistry.available()
        expected = [
            "data_minimization",
            "debate",
            "privacy_handshake",
            "sliding_privacy",
            "smart_escalation",
            "specialized_routing",
        ]
        for name in expected:
            assert name in available, f"{name} not registered"


class TestRegisterDecorator:
    def test_decorator_registers_class(self):
        @register_pattern("_test_decorated")
        class MyPattern:
            pass

        assert PatternRegistry.get("_test_decorated") is MyPattern
        # Cleanup
        del PatternRegistry._patterns["_test_decorated"]

    def test_decorator_returns_class_unchanged(self):
        @register_pattern("_test_identity")
        class Original:
            x = 42

        assert Original.x == 42
        del PatternRegistry._patterns["_test_identity"]
