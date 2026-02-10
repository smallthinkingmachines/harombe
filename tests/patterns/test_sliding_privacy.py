"""Tests for SlidingPrivacy pattern."""

from unittest.mock import MagicMock

import pytest

from harombe.llm.client import Message
from harombe.patterns.sliding_privacy import SlidingPrivacy
from harombe.privacy.models import SensitivityLevel, SensitivityResult


class TestSlidingPrivacy:
    def _make_classifier(self, level: SensitivityLevel):
        clf = MagicMock()
        clf.classify.return_value = SensitivityResult(
            level=level,
            reasons=[],
            detected_entities=[],
            confidence=0.9,
        )
        return clf

    @pytest.mark.asyncio
    async def test_privacy_1_0_always_local(self, mock_local, mock_cloud):
        clf = self._make_classifier(SensitivityLevel.PUBLIC)
        pattern = SlidingPrivacy(mock_local, mock_cloud, privacy_level=1.0, classifier=clf)

        messages = [Message(role="user", content="Hello")]
        response = await pattern.complete(messages)

        assert response.content == "local response"
        mock_cloud.complete.assert_not_called()

    @pytest.mark.asyncio
    async def test_privacy_0_0_always_cloud(self, mock_local, mock_cloud):
        clf = self._make_classifier(SensitivityLevel.RESTRICTED)
        pattern = SlidingPrivacy(mock_local, mock_cloud, privacy_level=0.0, classifier=clf)

        messages = [Message(role="user", content="Secret data")]
        response = await pattern.complete(messages)

        assert response.content == "cloud response"
        mock_local.complete.assert_not_called()

    @pytest.mark.asyncio
    async def test_mid_dial_public_goes_to_cloud(self, mock_local, mock_cloud):
        clf = self._make_classifier(SensitivityLevel.PUBLIC)
        # privacy_level=0.5 means public (0.0) < threshold → cloud
        pattern = SlidingPrivacy(mock_local, mock_cloud, privacy_level=0.5, classifier=clf)

        messages = [Message(role="user", content="What is Python?")]
        response = await pattern.complete(messages)

        assert response.content == "cloud response"

    @pytest.mark.asyncio
    async def test_mid_dial_confidential_goes_local(self, mock_local, mock_cloud):
        clf = self._make_classifier(SensitivityLevel.CONFIDENTIAL)
        # privacy_level=0.5 means confidential (0.66) >= threshold → local
        pattern = SlidingPrivacy(mock_local, mock_cloud, privacy_level=0.5, classifier=clf)

        messages = [Message(role="user", content="My API key is sk-12345")]
        response = await pattern.complete(messages)

        assert response.content == "local response"

    @pytest.mark.asyncio
    async def test_internal_at_threshold_boundary(self, mock_local, mock_cloud):
        clf = self._make_classifier(SensitivityLevel.INTERNAL)
        # Internal sensitivity = 0.33, threshold = 0.33 → 0.33 >= 0.33 → local
        pattern = SlidingPrivacy(mock_local, mock_cloud, privacy_level=0.33, classifier=clf)

        messages = [Message(role="user", content="Email user@test.com")]
        response = await pattern.complete(messages)

        assert response.content == "local response"

    def test_privacy_level_clamped(self):
        clf = self._make_classifier(SensitivityLevel.PUBLIC)
        pattern = SlidingPrivacy(None, None, privacy_level=2.5, classifier=clf)
        assert pattern.privacy_level == 1.0

        pattern.privacy_level = -0.5
        assert pattern.privacy_level == 0.0

    @pytest.mark.asyncio
    async def test_adjustable_at_runtime(self, mock_local, mock_cloud):
        clf = self._make_classifier(SensitivityLevel.PUBLIC)
        pattern = SlidingPrivacy(mock_local, mock_cloud, privacy_level=0.0, classifier=clf)

        messages = [Message(role="user", content="Hello")]

        # Should go to cloud with privacy=0.0
        await pattern.complete(messages)
        assert pattern.metrics.cloud_requests == 1

        # Change to full privacy → should go local
        pattern.privacy_level = 1.0
        await pattern.complete(messages)
        assert pattern.metrics.local_requests == 1

    @pytest.mark.asyncio
    async def test_metrics_tracked(self, mock_local, mock_cloud):
        clf = self._make_classifier(SensitivityLevel.PUBLIC)
        pattern = SlidingPrivacy(mock_local, mock_cloud, privacy_level=0.0, classifier=clf)

        messages = [Message(role="user", content="Hello")]
        await pattern.complete(messages)

        assert pattern.metrics.total_requests == 1
