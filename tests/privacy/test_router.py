"""Tests for the privacy router."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from harombe.llm.client import CompletionResponse, Message
from harombe.privacy.classifier import SensitivityClassifier
from harombe.privacy.models import (
    PIIEntity,
    RoutingMode,
    RoutingTarget,
    SensitivityLevel,
    SensitivityResult,
)
from harombe.privacy.router import ROUTING_RULES, PrivacyRouter, create_privacy_router


@pytest.fixture
def mock_local():
    client = AsyncMock()
    client.complete = AsyncMock(return_value=CompletionResponse(content="local response"))
    client.stream_complete = AsyncMock()
    return client


@pytest.fixture
def mock_cloud():
    client = AsyncMock()
    client.complete = AsyncMock(return_value=CompletionResponse(content="cloud response"))
    client.stream_complete = AsyncMock()
    return client


@pytest.fixture
def mock_classifier():
    return MagicMock(spec=SensitivityClassifier)


@pytest.fixture
def mock_audit():
    return MagicMock()


class TestRoutingRules:
    """Verify the routing rules table."""

    def test_local_only_always_local(self):
        for level in SensitivityLevel:
            assert ROUTING_RULES[RoutingMode.LOCAL_ONLY][level] == RoutingTarget.LOCAL

    def test_hybrid_public_to_cloud(self):
        assert ROUTING_RULES[RoutingMode.HYBRID][SensitivityLevel.PUBLIC] == RoutingTarget.CLOUD

    def test_hybrid_internal_sanitized(self):
        assert (
            ROUTING_RULES[RoutingMode.HYBRID][SensitivityLevel.INTERNAL]
            == RoutingTarget.CLOUD_SANITIZED
        )

    def test_hybrid_confidential_local(self):
        assert (
            ROUTING_RULES[RoutingMode.HYBRID][SensitivityLevel.CONFIDENTIAL] == RoutingTarget.LOCAL
        )

    def test_hybrid_restricted_local(self):
        assert ROUTING_RULES[RoutingMode.HYBRID][SensitivityLevel.RESTRICTED] == RoutingTarget.LOCAL

    def test_cloud_assisted_public_to_cloud(self):
        assert (
            ROUTING_RULES[RoutingMode.CLOUD_ASSISTED][SensitivityLevel.PUBLIC]
            == RoutingTarget.CLOUD
        )

    def test_cloud_assisted_internal_to_cloud(self):
        assert (
            ROUTING_RULES[RoutingMode.CLOUD_ASSISTED][SensitivityLevel.INTERNAL]
            == RoutingTarget.CLOUD
        )

    def test_cloud_assisted_confidential_sanitized(self):
        assert (
            ROUTING_RULES[RoutingMode.CLOUD_ASSISTED][SensitivityLevel.CONFIDENTIAL]
            == RoutingTarget.CLOUD_SANITIZED
        )

    def test_cloud_assisted_restricted_local(self):
        assert (
            ROUTING_RULES[RoutingMode.CLOUD_ASSISTED][SensitivityLevel.RESTRICTED]
            == RoutingTarget.LOCAL
        )


class TestPrivacyRouter:
    @pytest.mark.asyncio
    async def test_public_query_routes_to_cloud(
        self, mock_local, mock_cloud, mock_classifier, mock_audit
    ):
        mock_classifier.classify.return_value = SensitivityResult(
            level=SensitivityLevel.PUBLIC,
            reasons=["No sensitive data"],
            detected_entities=[],
            confidence=0.85,
        )
        router = PrivacyRouter(
            local_client=mock_local,
            cloud_client=mock_cloud,
            mode=RoutingMode.HYBRID,
            classifier=mock_classifier,
            audit_logger=mock_audit,
        )

        messages = [Message(role="user", content="What is Python?")]
        response = await router.complete(messages)

        assert response.content == "cloud response"
        mock_cloud.complete.assert_called_once()
        mock_local.complete.assert_not_called()

    @pytest.mark.asyncio
    async def test_restricted_always_local(
        self, mock_local, mock_cloud, mock_classifier, mock_audit
    ):
        mock_classifier.classify.return_value = SensitivityResult(
            level=SensitivityLevel.RESTRICTED,
            reasons=["Restricted keyword: confidential"],
            detected_entities=[],
            confidence=0.95,
        )
        router = PrivacyRouter(
            local_client=mock_local,
            cloud_client=mock_cloud,
            mode=RoutingMode.CLOUD_ASSISTED,
            classifier=mock_classifier,
            audit_logger=mock_audit,
        )

        messages = [Message(role="user", content="This is confidential data")]
        response = await router.complete(messages)

        assert response.content == "local response"
        mock_local.complete.assert_called_once()
        mock_cloud.complete.assert_not_called()

    @pytest.mark.asyncio
    async def test_internal_hybrid_sanitized_cloud(
        self, mock_local, mock_cloud, mock_classifier, mock_audit
    ):
        mock_classifier.classify.return_value = SensitivityResult(
            level=SensitivityLevel.INTERNAL,
            reasons=["PII: email"],
            detected_entities=[
                PIIEntity(
                    type="email",
                    value="john@example.com",
                    start=9,
                    end=25,
                    confidence=0.9,
                )
            ],
            confidence=0.9,
        )
        mock_cloud.complete.return_value = CompletionResponse(content="I'll contact [EMAIL_1] now.")

        router = PrivacyRouter(
            local_client=mock_local,
            cloud_client=mock_cloud,
            mode=RoutingMode.HYBRID,
            classifier=mock_classifier,
            audit_logger=mock_audit,
        )

        messages = [Message(role="user", content="Contact john@example.com")]
        response = await router.complete(messages)

        # Cloud was called with sanitized messages
        mock_cloud.complete.assert_called_once()
        sent_messages = mock_cloud.complete.call_args[0][0]
        assert "john@example.com" not in sent_messages[0].content

        # Response was reconstructed
        assert "john@example.com" in response.content
        assert "[EMAIL_1]" not in response.content

    @pytest.mark.asyncio
    async def test_confidential_hybrid_routes_local(
        self, mock_local, mock_cloud, mock_classifier, mock_audit
    ):
        mock_classifier.classify.return_value = SensitivityResult(
            level=SensitivityLevel.CONFIDENTIAL,
            reasons=["Credential: api_key"],
            detected_entities=[
                PIIEntity(
                    type="credential:api_key",
                    value="sk-12345",
                    start=0,
                    end=8,
                    confidence=0.95,
                )
            ],
            confidence=0.95,
        )
        router = PrivacyRouter(
            local_client=mock_local,
            cloud_client=mock_cloud,
            mode=RoutingMode.HYBRID,
            classifier=mock_classifier,
            audit_logger=mock_audit,
        )

        messages = [Message(role="user", content="My key is sk-12345")]
        response = await router.complete(messages)

        assert response.content == "local response"
        mock_local.complete.assert_called_once()
        mock_cloud.complete.assert_not_called()

    @pytest.mark.asyncio
    async def test_confidential_cloud_assisted_sanitized(
        self, mock_local, mock_cloud, mock_classifier, mock_audit
    ):
        mock_classifier.classify.return_value = SensitivityResult(
            level=SensitivityLevel.CONFIDENTIAL,
            reasons=["Credential detected"],
            detected_entities=[
                PIIEntity(
                    type="credential:api_key",
                    value="sk-secret123",
                    start=0,
                    end=12,
                    confidence=0.95,
                )
            ],
            confidence=0.95,
        )
        mock_cloud.complete.return_value = CompletionResponse(
            content="Your key [API_KEY_1] is valid."
        )

        router = PrivacyRouter(
            local_client=mock_local,
            cloud_client=mock_cloud,
            mode=RoutingMode.CLOUD_ASSISTED,
            classifier=mock_classifier,
            audit_logger=mock_audit,
        )

        messages = [Message(role="user", content="Check sk-secret123")]
        response = await router.complete(messages)

        mock_cloud.complete.assert_called_once()
        assert "sk-secret123" in response.content

    @pytest.mark.asyncio
    async def test_no_reconstruct_when_disabled(
        self, mock_local, mock_cloud, mock_classifier, mock_audit
    ):
        mock_classifier.classify.return_value = SensitivityResult(
            level=SensitivityLevel.INTERNAL,
            reasons=["PII: email"],
            detected_entities=[
                PIIEntity(
                    type="email",
                    value="test@test.com",
                    start=0,
                    end=13,
                    confidence=0.9,
                )
            ],
            confidence=0.9,
        )
        mock_cloud.complete.return_value = CompletionResponse(content="Contacting [EMAIL_1]")

        router = PrivacyRouter(
            local_client=mock_local,
            cloud_client=mock_cloud,
            mode=RoutingMode.HYBRID,
            classifier=mock_classifier,
            audit_logger=mock_audit,
            reconstruct_responses=False,
        )

        messages = [Message(role="user", content="test@test.com")]
        response = await router.complete(messages)

        # Placeholders should NOT be reconstructed
        assert "[EMAIL_1]" in response.content

    @pytest.mark.asyncio
    async def test_audit_logger_called(self, mock_local, mock_cloud, mock_classifier, mock_audit):
        mock_classifier.classify.return_value = SensitivityResult(
            level=SensitivityLevel.PUBLIC,
            reasons=[],
            detected_entities=[],
            confidence=0.85,
        )
        router = PrivacyRouter(
            local_client=mock_local,
            cloud_client=mock_cloud,
            mode=RoutingMode.HYBRID,
            classifier=mock_classifier,
            audit_logger=mock_audit,
        )

        messages = [Message(role="user", content="Hello")]
        await router.complete(messages)

        mock_audit.log_routing_decision.assert_called_once()

    @pytest.mark.asyncio
    async def test_stats_tracking(self, mock_local, mock_cloud, mock_classifier, mock_audit):
        mock_classifier.classify.return_value = SensitivityResult(
            level=SensitivityLevel.PUBLIC,
            reasons=[],
            detected_entities=[],
            confidence=0.85,
        )
        router = PrivacyRouter(
            local_client=mock_local,
            cloud_client=mock_cloud,
            mode=RoutingMode.HYBRID,
            classifier=mock_classifier,
            audit_logger=mock_audit,
        )

        messages = [Message(role="user", content="Hi")]
        await router.complete(messages)
        await router.complete(messages)

        stats = router.get_stats()
        assert stats["total_requests"] == 2
        assert stats["cloud_count"] == 2
        assert stats["mode"] == "hybrid"

    @pytest.mark.asyncio
    async def test_passes_tools_and_params(
        self, mock_local, mock_cloud, mock_classifier, mock_audit
    ):
        mock_classifier.classify.return_value = SensitivityResult(
            level=SensitivityLevel.PUBLIC,
            reasons=[],
            detected_entities=[],
            confidence=0.85,
        )
        router = PrivacyRouter(
            local_client=mock_local,
            cloud_client=mock_cloud,
            mode=RoutingMode.HYBRID,
            classifier=mock_classifier,
            audit_logger=mock_audit,
        )

        tools = [{"type": "function", "function": {"name": "test"}}]
        messages = [Message(role="user", content="Hi")]
        await router.complete(messages, tools=tools, temperature=0.5, max_tokens=100)

        mock_cloud.complete.assert_called_once_with(messages, tools, 0.5, 100)


class TestCreatePrivacyRouter:
    def test_local_only_returns_ollama(self):
        config = MagicMock()
        config.privacy.mode = "local-only"
        config.model.name = "qwen2.5:7b"
        config.ollama.host = "http://localhost:11434"
        config.ollama.timeout = 120
        config.model.temperature = 0.7
        config.inference.backend = "ollama"

        from harombe.llm.ollama import OllamaClient

        result = create_privacy_router(config)
        assert isinstance(result, OllamaClient)

    def test_hybrid_without_api_key_falls_back(self):
        config = MagicMock()
        config.privacy.mode = "hybrid"
        config.privacy.cloud_llm.api_key_env = "NONEXISTENT_KEY_12345"
        config.model.name = "qwen2.5:7b"
        config.ollama.host = "http://localhost:11434"
        config.ollama.timeout = 120
        config.model.temperature = 0.7
        config.inference.backend = "ollama"

        from harombe.llm.ollama import OllamaClient

        with patch.dict("os.environ", {}, clear=False):
            result = create_privacy_router(config)
        assert isinstance(result, OllamaClient)

    def test_hybrid_with_api_key_returns_router(self):
        config = MagicMock()
        config.privacy.mode = "hybrid"
        config.privacy.cloud_llm.api_key_env = "TEST_ANTHROPIC_KEY"
        config.privacy.cloud_llm.model = "claude-sonnet-4-20250514"
        config.privacy.cloud_llm.max_tokens = 4096
        config.privacy.cloud_llm.timeout = 120
        config.privacy.custom_patterns = {}
        config.privacy.custom_restricted_keywords = []
        config.privacy.audit_routing = False
        config.privacy.reconstruct_responses = True
        config.model.name = "qwen2.5:7b"
        config.model.temperature = 0.7
        config.ollama.host = "http://localhost:11434"
        config.ollama.timeout = 120
        config.security.audit.enabled = False
        config.inference.backend = "ollama"

        with patch.dict("os.environ", {"TEST_ANTHROPIC_KEY": "sk-test-key"}):
            result = create_privacy_router(config)
        assert isinstance(result, PrivacyRouter)
        assert result.mode == RoutingMode.HYBRID


class TestIntegration:
    """End-to-end tests with real classifier and sanitizer."""

    @pytest.mark.asyncio
    async def test_e2e_public_to_cloud(self, mock_local, mock_cloud):
        router = PrivacyRouter(
            local_client=mock_local,
            cloud_client=mock_cloud,
            mode=RoutingMode.HYBRID,
        )
        messages = [Message(role="user", content="What is Python?")]
        response = await router.complete(messages)

        assert response.content == "cloud response"

    @pytest.mark.asyncio
    async def test_e2e_email_sanitized(self, mock_local, mock_cloud):
        mock_cloud.complete.return_value = CompletionResponse(
            content="I'll email [EMAIL_1] shortly."
        )
        router = PrivacyRouter(
            local_client=mock_local,
            cloud_client=mock_cloud,
            mode=RoutingMode.HYBRID,
        )
        messages = [Message(role="user", content="Email alice@corp.com about the project")]
        response = await router.complete(messages)

        # Should have sanitized and reconstructed
        assert "alice@corp.com" in response.content

    @pytest.mark.asyncio
    async def test_e2e_restricted_stays_local(self, mock_local, mock_cloud):
        router = PrivacyRouter(
            local_client=mock_local,
            cloud_client=mock_cloud,
            mode=RoutingMode.CLOUD_ASSISTED,
        )
        messages = [Message(role="user", content="This is HIPAA protected data")]
        response = await router.complete(messages)

        assert response.content == "local response"
        mock_cloud.complete.assert_not_called()
