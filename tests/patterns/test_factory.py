"""Tests for pattern factory."""

from unittest.mock import MagicMock, patch

from harombe.patterns.factory import create_pattern_client
from harombe.patterns.sliding_privacy import SlidingPrivacy
from harombe.patterns.smart_escalation import SmartEscalation
from harombe.patterns.specialized_routing import SpecializedRouting


def _make_config(pattern="none", enabled=False, **overrides):
    """Create a minimal mock config for testing the factory."""
    config = MagicMock()
    config.model.name = "qwen2.5:7b"
    config.model.temperature = 0.7
    config.ollama.host = "http://localhost:11434"
    config.ollama.timeout = 120
    config.privacy.mode = "hybrid"
    config.privacy.cloud_llm.api_key_env = "TEST_ANTHROPIC_KEY"
    config.privacy.cloud_llm.model = "claude-sonnet-4-20250514"
    config.privacy.cloud_llm.max_tokens = 4096
    config.privacy.cloud_llm.timeout = 120
    config.privacy.custom_patterns = {}
    config.privacy.custom_restricted_keywords = []
    config.privacy.audit_routing = False
    config.privacy.reconstruct_responses = True
    config.security.audit.enabled = False

    config.patterns.enabled = enabled
    config.patterns.pattern = pattern
    config.patterns.confidence_threshold = overrides.get("confidence_threshold", 0.5)
    config.patterns.privacy_level = overrides.get("privacy_level", 0.5)
    config.patterns.cloud_threshold = overrides.get("cloud_threshold", "complex")
    config.patterns.include_contextual = overrides.get("include_contextual", True)

    return config


class TestCreatePatternClient:
    def test_disabled_returns_base_client(self):
        config = _make_config(enabled=False)
        config.privacy.mode = "local-only"

        from harombe.llm.ollama import OllamaClient

        result = create_pattern_client(config)
        assert isinstance(result, OllamaClient)

    def test_none_pattern_returns_base_client(self):
        config = _make_config(pattern="none", enabled=True)
        config.privacy.mode = "local-only"

        from harombe.llm.ollama import OllamaClient

        result = create_pattern_client(config)
        assert isinstance(result, OllamaClient)

    def test_smart_escalation_created(self):
        config = _make_config(pattern="smart_escalation", enabled=True, confidence_threshold=0.7)
        with patch.dict("os.environ", {"TEST_ANTHROPIC_KEY": "sk-test-key"}):
            result = create_pattern_client(config)

        assert isinstance(result, SmartEscalation)
        assert result.confidence_threshold == 0.7

    def test_specialized_routing_created(self):
        config = _make_config(pattern="specialized_routing", enabled=True, cloud_threshold="medium")
        with patch.dict("os.environ", {"TEST_ANTHROPIC_KEY": "sk-test-key"}):
            result = create_pattern_client(config)

        assert isinstance(result, SpecializedRouting)

    def test_sliding_privacy_created(self):
        config = _make_config(pattern="sliding_privacy", enabled=True, privacy_level=0.8)
        with patch.dict("os.environ", {"TEST_ANTHROPIC_KEY": "sk-test-key"}):
            result = create_pattern_client(config)

        assert isinstance(result, SlidingPrivacy)
        assert result.privacy_level == 0.8

    def test_unknown_pattern_falls_back(self):
        config = _make_config(pattern="nonexistent_xyz", enabled=True)
        config.privacy.mode = "local-only"

        from harombe.llm.ollama import OllamaClient

        result = create_pattern_client(config)
        assert isinstance(result, OllamaClient)

    def test_local_only_mode_with_pattern(self):
        """When privacy mode is local-only but pattern needs cloud, local is used for both."""
        config = _make_config(pattern="smart_escalation", enabled=True)
        config.privacy.mode = "local-only"

        # No API key → both clients will be local
        with patch.dict("os.environ", {}, clear=False):
            result = create_pattern_client(config)

        assert isinstance(result, SmartEscalation)
