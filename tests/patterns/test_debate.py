"""Tests for Debate pattern."""

import pytest

from harombe.llm.client import CompletionResponse, Message
from harombe.patterns.debate import Debate


class TestDebate:
    @pytest.mark.asyncio
    async def test_full_debate_flow(self, mock_local, mock_cloud):
        # Track call order
        call_order = []

        async def local_complete(messages, *args, **kwargs):
            call_order.append(("local", messages[0].content[:30] if messages else ""))
            return CompletionResponse(content="local says: answer")

        async def cloud_complete(messages, *args, **kwargs):
            call_order.append(("cloud", messages[0].content[:30] if messages else ""))
            return CompletionResponse(content="cloud says: synthesized answer")

        mock_local.complete = local_complete
        mock_cloud.complete = cloud_complete

        pattern = Debate(mock_local, mock_cloud)
        messages = [Message(role="user", content="What is consciousness?")]
        response = await pattern.complete(messages)

        # Should have 5 LLM calls total:
        # 1. local answer, 2. cloud answer, 3. local critique, 4. cloud critique, 5. synthesis
        assert len(call_order) == 5
        assert call_order[0][0] == "local"  # local answer
        assert call_order[1][0] == "cloud"  # cloud answer
        assert call_order[2][0] == "local"  # local critiques cloud
        assert call_order[3][0] == "cloud"  # cloud critiques local
        assert call_order[4][0] == "cloud"  # cloud synthesizes

        assert response.content == "cloud says: synthesized answer"

    @pytest.mark.asyncio
    async def test_critique_contains_other_answer(self, mock_local, mock_cloud):
        critique_messages_seen = []

        async def local_complete(messages, *args, **kwargs):
            if "reviewing" in (messages[0].content if messages else "").lower():
                critique_messages_seen.append(messages[0].content)
            return CompletionResponse(content="local critique")

        async def cloud_complete(messages, *args, **kwargs):
            if "reviewing" in (messages[0].content if messages else "").lower():
                critique_messages_seen.append(messages[0].content)
            return CompletionResponse(content="cloud critique")

        mock_local.complete = local_complete
        mock_cloud.complete = cloud_complete

        pattern = Debate(mock_local, mock_cloud)
        messages = [Message(role="user", content="What is AI?")]
        await pattern.complete(messages)

        # Both critiques should have been generated
        assert len(critique_messages_seen) == 2

    @pytest.mark.asyncio
    async def test_synthesis_contains_all_parts(self, mock_local, mock_cloud):
        synthesis_prompt_seen = []

        async def local_complete(messages, *args, **kwargs):
            return CompletionResponse(content="local answer content")

        async def cloud_complete(messages, *args, **kwargs):
            content = messages[0].content if messages else ""
            if "synthesizing" in content.lower():
                synthesis_prompt_seen.append(content)
            return CompletionResponse(content="synthesized final")

        mock_local.complete = local_complete
        mock_cloud.complete = cloud_complete

        pattern = Debate(mock_local, mock_cloud)
        messages = [Message(role="user", content="What is AI?")]
        await pattern.complete(messages)

        assert len(synthesis_prompt_seen) == 1
        prompt = synthesis_prompt_seen[0]
        # Synthesis should reference the question, both answers, and both critiques
        assert "What is AI?" in prompt
        assert "local answer content" in prompt

    @pytest.mark.asyncio
    async def test_tools_passed_to_synthesis(self, mock_local, mock_cloud):
        synthesis_call_kwargs = {}

        call_count = 0

        async def cloud_complete(messages, tools=None, temperature=None, max_tokens=None):
            nonlocal call_count
            call_count += 1
            if call_count == 3:  # synthesis is the 3rd cloud call
                synthesis_call_kwargs["tools"] = tools
                synthesis_call_kwargs["temperature"] = temperature
                synthesis_call_kwargs["max_tokens"] = max_tokens
            return CompletionResponse(content="response")

        mock_local.complete.return_value = CompletionResponse(content="local")
        mock_cloud.complete = cloud_complete

        pattern = Debate(mock_local, mock_cloud)
        tools = [{"type": "function", "function": {"name": "test"}}]
        messages = [Message(role="user", content="Test")]
        await pattern.complete(messages, tools=tools, temperature=0.5, max_tokens=100)

        assert synthesis_call_kwargs["tools"] == tools
        assert synthesis_call_kwargs["temperature"] == 0.5
        assert synthesis_call_kwargs["max_tokens"] == 100

    @pytest.mark.asyncio
    async def test_metrics_recorded(self, mock_local, mock_cloud):
        mock_local.complete.return_value = CompletionResponse(content="local")
        mock_cloud.complete.return_value = CompletionResponse(content="cloud")

        pattern = Debate(mock_local, mock_cloud)
        messages = [Message(role="user", content="Test")]
        await pattern.complete(messages)

        assert pattern.metrics.total_requests == 1
        assert pattern.metrics.cloud_requests == 1
