"""Tests for PrivacyHandshake pattern."""

from unittest.mock import MagicMock

import pytest

from harombe.llm.client import CompletionResponse, Message
from harombe.patterns.privacy_handshake import PrivacyHandshake, PseudonymGenerator
from harombe.privacy.models import PIIEntity, SensitivityLevel, SensitivityResult


class TestPseudonymGenerator:
    def test_deterministic(self):
        gen = PseudonymGenerator(seed=42)
        entity = PIIEntity(type="email", value="alice@corp.com", start=0, end=14, confidence=0.9)
        fake1 = gen.generate(entity)
        fake2 = gen.generate(entity)
        assert fake1 == fake2

    def test_different_emails_produce_different_fakes(self):
        gen = PseudonymGenerator(seed=42)
        e1 = PIIEntity(type="email", value="alice@corp.com", start=0, end=14, confidence=0.9)
        e2 = PIIEntity(type="email", value="bob@corp.com", start=0, end=12, confidence=0.9)
        assert gen.generate(e1) != gen.generate(e2)

    def test_email_format(self):
        gen = PseudonymGenerator(seed=42)
        entity = PIIEntity(type="email", value="test@test.com", start=0, end=13, confidence=0.9)
        fake = gen.generate(entity)
        assert "@" in fake
        assert "." in fake

    def test_phone_format(self):
        gen = PseudonymGenerator(seed=42)
        entity = PIIEntity(type="phone", value="(555) 123-4567", start=0, end=14, confidence=0.9)
        fake = gen.generate(entity)
        assert "555-" in fake

    def test_ssn_format(self):
        gen = PseudonymGenerator(seed=42)
        entity = PIIEntity(type="ssn", value="123-45-6789", start=0, end=11, confidence=0.9)
        fake = gen.generate(entity)
        parts = fake.split("-")
        assert len(parts) == 3

    def test_credential_produces_token(self):
        gen = PseudonymGenerator(seed=42)
        entity = PIIEntity(
            type="credential:api_key", value="sk-12345", start=0, end=8, confidence=0.9
        )
        fake = gen.generate(entity)
        assert fake.startswith("tok_")

    def test_reset_clears_cache(self):
        gen = PseudonymGenerator(seed=42)
        entity = PIIEntity(type="email", value="a@b.com", start=0, end=7, confidence=0.9)
        gen.generate(entity)
        gen.reset()
        assert len(gen._cache) == 0


class TestPrivacyHandshake:
    def _make_classifier(self, level, entities=None):
        clf = MagicMock()
        clf.classify.return_value = SensitivityResult(
            level=level,
            reasons=[],
            detected_entities=entities or [],
            confidence=0.9,
        )
        return clf

    @pytest.mark.asyncio
    async def test_restricted_goes_local(self, mock_local, mock_cloud):
        clf = self._make_classifier(SensitivityLevel.RESTRICTED)
        pattern = PrivacyHandshake(mock_local, mock_cloud, classifier=clf)

        messages = [Message(role="user", content="HIPAA protected data")]
        response = await pattern.complete(messages)

        assert response.content == "local response"
        mock_cloud.complete.assert_not_called()

    @pytest.mark.asyncio
    async def test_public_goes_to_cloud(self, mock_local, mock_cloud):
        clf = self._make_classifier(SensitivityLevel.PUBLIC)
        pattern = PrivacyHandshake(mock_local, mock_cloud, classifier=clf)

        messages = [Message(role="user", content="What is Python?")]
        response = await pattern.complete(messages)

        assert response.content == "cloud response"
        mock_cloud.complete.assert_called_once()

    @pytest.mark.asyncio
    async def test_pii_pseudonymized_before_cloud(self, mock_local, mock_cloud):
        entities = [
            PIIEntity(type="email", value="alice@corp.com", start=6, end=20, confidence=0.9)
        ]
        clf = self._make_classifier(SensitivityLevel.INTERNAL, entities)

        mock_cloud.complete.return_value = CompletionResponse(content="cloud response")
        pattern = PrivacyHandshake(mock_local, mock_cloud, classifier=clf)

        messages = [Message(role="user", content="Email alice@corp.com about the project")]
        await pattern.complete(messages)

        # Verify cloud never saw the real email
        sent_messages = mock_cloud.complete.call_args[0][0]
        assert "alice@corp.com" not in sent_messages[0].content

    @pytest.mark.asyncio
    async def test_pseudonyms_reversed_in_response(self, mock_local, mock_cloud):
        entities = [
            PIIEntity(type="email", value="alice@corp.com", start=6, end=20, confidence=0.9)
        ]
        clf = self._make_classifier(SensitivityLevel.INTERNAL, entities)

        # Determine what fake will be generated
        gen = PseudonymGenerator(seed=42)
        fake_email = gen.generate(entities[0])

        mock_cloud.complete.return_value = CompletionResponse(
            content=f"I'll contact {fake_email} now."
        )
        pattern = PrivacyHandshake(mock_local, mock_cloud, classifier=clf, pseudonym_seed=42)

        messages = [Message(role="user", content="Email alice@corp.com about the project")]
        response = await pattern.complete(messages)

        # Response should have the real email restored
        assert "alice@corp.com" in response.content
        assert fake_email not in response.content

    @pytest.mark.asyncio
    async def test_metrics_tracked(self, mock_local, mock_cloud):
        clf = self._make_classifier(SensitivityLevel.PUBLIC)
        pattern = PrivacyHandshake(mock_local, mock_cloud, classifier=clf)

        messages = [Message(role="user", content="Hello")]
        await pattern.complete(messages)

        assert pattern.metrics.total_requests == 1
        assert pattern.metrics.cloud_requests == 1
