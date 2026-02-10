"""Tests for DataMinimization pattern."""

import pytest

from harombe.llm.client import CompletionResponse, Message
from harombe.patterns.data_minimization import (
    DataMinimization,
    SentenceCategory,
    _parse_classifications,
    _split_sentences,
)


class TestSplitSentences:
    def test_basic(self):
        text = "Hello world. How are you? I'm fine!"
        assert _split_sentences(text) == ["Hello world.", "How are you?", "I'm fine!"]

    def test_single_sentence(self):
        assert _split_sentences("Just one.") == ["Just one."]

    def test_empty(self):
        assert _split_sentences("") == []
        assert _split_sentences("   ") == []


class TestParseClassifications:
    def test_basic_parse(self):
        response = "1: essential\n2: sensitive\n3: contextual"
        result = _parse_classifications(response, 3)
        assert result == [
            SentenceCategory.ESSENTIAL,
            SentenceCategory.SENSITIVE,
            SentenceCategory.CONTEXTUAL,
        ]

    def test_case_insensitive(self):
        response = "1: ESSENTIAL\n2: IRRELEVANT"
        result = _parse_classifications(response, 2)
        assert result == [SentenceCategory.ESSENTIAL, SentenceCategory.IRRELEVANT]

    def test_unparseable_defaults_to_essential(self):
        response = "garbage text\n1: essential"
        result = _parse_classifications(response, 3)
        assert result[0] == SentenceCategory.ESSENTIAL
        assert result[1] == SentenceCategory.ESSENTIAL  # default
        assert result[2] == SentenceCategory.ESSENTIAL  # default

    def test_out_of_range_index_ignored(self):
        response = "1: essential\n99: sensitive"
        result = _parse_classifications(response, 2)
        assert result == [SentenceCategory.ESSENTIAL, SentenceCategory.ESSENTIAL]


class TestDataMinimization:
    @pytest.mark.asyncio
    async def test_single_sentence_goes_to_cloud_directly(self, mock_local, mock_cloud):
        pattern = DataMinimization(mock_local, mock_cloud)

        messages = [Message(role="user", content="What is Python?")]
        response = await pattern.complete(messages)

        assert response.content == "cloud response"
        mock_cloud.complete.assert_called_once()
        mock_local.complete.assert_not_called()

    @pytest.mark.asyncio
    async def test_filters_sensitive_sentences(self, mock_local, mock_cloud):
        # Local model classifies sentence 1 as essential, sentence 2 as sensitive
        mock_local.complete.return_value = CompletionResponse(
            content="1: essential\n2: sensitive\n3: contextual"
        )

        pattern = DataMinimization(mock_local, mock_cloud)

        messages = [
            Message(
                role="user",
                content="What is Python? My SSN is 123-45-6789. It's used for web development.",
            )
        ]
        await pattern.complete(messages)

        # Cloud should have been called with filtered messages
        mock_cloud.complete.assert_called_once()
        sent_messages = mock_cloud.complete.call_args[0][0]
        # The sensitive sentence should not be in the query
        assert "123-45-6789" not in sent_messages[0].content

    @pytest.mark.asyncio
    async def test_all_filtered_falls_back_to_local(self, mock_local, mock_cloud):
        # All sentences classified as sensitive
        mock_local.complete.side_effect = [
            CompletionResponse(content="1: sensitive\n2: sensitive"),
            CompletionResponse(content="local fallback"),
        ]

        pattern = DataMinimization(mock_local, mock_cloud, include_contextual=False)

        messages = [Message(role="user", content="My SSN is 123-45-6789. My email is a@b.com.")]
        response = await pattern.complete(messages)

        assert response.content == "local fallback"
        mock_cloud.complete.assert_not_called()

    @pytest.mark.asyncio
    async def test_include_contextual_flag(self, mock_local, mock_cloud):
        mock_local.complete.return_value = CompletionResponse(content="1: contextual\n2: essential")

        # With include_contextual=False, only essential kept
        pattern = DataMinimization(mock_local, mock_cloud, include_contextual=False)

        messages = [Message(role="user", content="For background info. What is the answer?")]
        await pattern.complete(messages)

        sent_messages = mock_cloud.complete.call_args[0][0]
        # Only the essential sentence should remain
        assert "What is the answer?" in sent_messages[0].content
