"""Tests for SmartEscalation pattern."""

import pytest

from harombe.llm.client import CompletionResponse, Message
from harombe.patterns.smart_escalation import SmartEscalation, compute_confidence


class TestComputeConfidence:
    def test_empty_response(self):
        assert compute_confidence("") == 0.0
        assert compute_confidence("   ") == 0.0

    def test_confident_response(self):
        text = (
            "Python is a high-level programming language known for its readability and versatility."
        )
        score = compute_confidence(text)
        assert score >= 0.8

    def test_hedging_lowers_confidence(self):
        text = "I'm not sure, but I think Python might be a programming language."
        score = compute_confidence(text)
        assert score < 0.7

    def test_refusal_lowers_confidence(self):
        text = "Sorry, but I cannot help with that request."
        score = compute_confidence(text)
        assert score < 0.5

    def test_short_response_penalty(self):
        text = "Yes."
        score = compute_confidence(text)
        assert score < 0.8

    def test_question_marks_penalty(self):
        text = "Are you sure? What do you mean? Can you clarify? I'm confused?"
        score = compute_confidence(text)
        assert score < 0.8

    def test_score_clamped_to_0_1(self):
        # Trigger multiple penalties
        text = "I'm not sure. Sorry, I cannot help."
        score = compute_confidence(text)
        assert 0.0 <= score <= 1.0


class TestSmartEscalation:
    @pytest.mark.asyncio
    async def test_confident_local_response_not_escalated(self, mock_local, mock_cloud):
        mock_local.complete.return_value = CompletionResponse(
            content="Python is a versatile programming language used for web development and data science."
        )
        pattern = SmartEscalation(mock_local, mock_cloud, confidence_threshold=0.5)

        messages = [Message(role="user", content="What is Python?")]
        response = await pattern.complete(messages)

        assert "Python" in response.content
        mock_local.complete.assert_called_once()
        mock_cloud.complete.assert_not_called()
        assert pattern.metrics.local_requests == 1
        assert pattern.metrics.escalations == 0

    @pytest.mark.asyncio
    async def test_low_confidence_escalates_to_cloud(self, mock_local, mock_cloud):
        mock_local.complete.return_value = CompletionResponse(
            content="Sorry, I cannot help with that request."
        )
        pattern = SmartEscalation(mock_local, mock_cloud, confidence_threshold=0.5)

        messages = [Message(role="user", content="Explain quantum entanglement")]
        response = await pattern.complete(messages)

        assert response.content == "cloud response"
        mock_local.complete.assert_called_once()
        mock_cloud.complete.assert_called_once()
        assert pattern.metrics.cloud_requests == 1
        assert pattern.metrics.escalations == 1

    @pytest.mark.asyncio
    async def test_empty_local_response_escalates(self, mock_local, mock_cloud):
        mock_local.complete.return_value = CompletionResponse(content="")
        pattern = SmartEscalation(mock_local, mock_cloud, confidence_threshold=0.3)

        messages = [Message(role="user", content="Hello")]
        response = await pattern.complete(messages)

        assert response.content == "cloud response"
        assert pattern.metrics.escalations == 1

    @pytest.mark.asyncio
    async def test_high_threshold_escalates_more(self, mock_local, mock_cloud):
        mock_local.complete.return_value = CompletionResponse(content="A short answer.")
        # Very high threshold — almost everything escalates
        pattern = SmartEscalation(mock_local, mock_cloud, confidence_threshold=0.95)

        messages = [Message(role="user", content="Hi")]
        response = await pattern.complete(messages)

        assert response.content == "cloud response"

    @pytest.mark.asyncio
    async def test_tools_and_params_passed_through(self, mock_local, mock_cloud):
        mock_local.complete.return_value = CompletionResponse(content="I don't know")
        pattern = SmartEscalation(mock_local, mock_cloud, confidence_threshold=0.5)

        tools = [{"type": "function", "function": {"name": "test"}}]
        messages = [Message(role="user", content="Run test")]
        await pattern.complete(messages, tools=tools, temperature=0.3, max_tokens=100)

        mock_cloud.complete.assert_called_once_with(messages, tools, 0.3, 100)
