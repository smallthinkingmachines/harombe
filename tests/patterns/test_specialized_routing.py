"""Tests for SpecializedRouting pattern."""

from unittest.mock import MagicMock

import pytest

from harombe.coordination.router import ComplexityClassifier, TaskComplexity
from harombe.llm.client import Message
from harombe.patterns.specialized_routing import SpecializedRouting


class TestSpecializedRouting:
    def _make_classifier(self, complexity: TaskComplexity):
        clf = MagicMock(spec=ComplexityClassifier)
        clf.classify_query.return_value = complexity
        return clf

    @pytest.mark.asyncio
    async def test_simple_query_stays_local(self, mock_local, mock_cloud):
        clf = self._make_classifier(TaskComplexity.SIMPLE)
        pattern = SpecializedRouting(mock_local, mock_cloud, classifier=clf)

        messages = [Message(role="user", content="What time is it?")]
        response = await pattern.complete(messages)

        assert response.content == "local response"
        mock_local.complete.assert_called_once()
        mock_cloud.complete.assert_not_called()

    @pytest.mark.asyncio
    async def test_complex_query_goes_to_cloud(self, mock_local, mock_cloud):
        clf = self._make_classifier(TaskComplexity.COMPLEX)
        pattern = SpecializedRouting(mock_local, mock_cloud, classifier=clf)

        messages = [Message(role="user", content="Analyze this code thoroughly")]
        response = await pattern.complete(messages)

        assert response.content == "cloud response"
        mock_cloud.complete.assert_called_once()
        mock_local.complete.assert_not_called()

    @pytest.mark.asyncio
    async def test_medium_with_complex_threshold_stays_local(self, mock_local, mock_cloud):
        clf = self._make_classifier(TaskComplexity.MEDIUM)
        pattern = SpecializedRouting(
            mock_local, mock_cloud, classifier=clf, cloud_threshold=TaskComplexity.COMPLEX
        )

        messages = [Message(role="user", content="How does sorting work?")]
        response = await pattern.complete(messages)

        assert response.content == "local response"
        mock_local.complete.assert_called_once()

    @pytest.mark.asyncio
    async def test_medium_with_medium_threshold_goes_to_cloud(self, mock_local, mock_cloud):
        clf = self._make_classifier(TaskComplexity.MEDIUM)
        pattern = SpecializedRouting(
            mock_local, mock_cloud, classifier=clf, cloud_threshold=TaskComplexity.MEDIUM
        )

        messages = [Message(role="user", content="How does sorting work?")]
        response = await pattern.complete(messages)

        assert response.content == "cloud response"

    @pytest.mark.asyncio
    async def test_metrics_tracked(self, mock_local, mock_cloud):
        clf = self._make_classifier(TaskComplexity.SIMPLE)
        pattern = SpecializedRouting(mock_local, mock_cloud, classifier=clf)

        messages = [Message(role="user", content="Hello")]
        await pattern.complete(messages)

        assert pattern.metrics.total_requests == 1
        assert pattern.metrics.local_requests == 1

    @pytest.mark.asyncio
    async def test_tools_passed_through(self, mock_local, mock_cloud):
        clf = self._make_classifier(TaskComplexity.COMPLEX)
        pattern = SpecializedRouting(mock_local, mock_cloud, classifier=clf)

        tools = [{"type": "function", "function": {"name": "test"}}]
        messages = [Message(role="user", content="Analyze this")]
        await pattern.complete(messages, tools=tools, temperature=0.2, max_tokens=200)

        mock_cloud.complete.assert_called_once_with(messages, tools, 0.2, 200)
