"""Tests for web search tool."""

from unittest.mock import patch

import pytest

from harombe.tools.web_search import web_search


class TestWebSearch:
    @pytest.mark.asyncio
    async def test_successful_search(self):
        """Test web search returns formatted results."""
        mock_results = [
            {"title": "Python Docs", "href": "https://python.org", "body": "Python programming"},
            {"title": "Learn Python", "href": "https://learn.python.org", "body": "Free tutorials"},
        ]

        with patch("harombe.tools.web_search.DDGS") as mock_ddgs:
            instance = mock_ddgs.return_value.__enter__.return_value
            instance.text.return_value = mock_results

            result = await web_search("python tutorials", max_results=5)

            assert "Python Docs" in result
            assert "https://python.org" in result
            assert "Python programming" in result
            assert "Learn Python" in result

    @pytest.mark.asyncio
    async def test_no_results(self):
        """Test web search with no results."""
        with patch("harombe.tools.web_search.DDGS") as mock_ddgs:
            instance = mock_ddgs.return_value.__enter__.return_value
            instance.text.return_value = []

            result = await web_search("xyznonexistentquery12345")

            assert "No results found" in result

    @pytest.mark.asyncio
    async def test_max_results_clamped_high(self):
        """Test that max_results is clamped to 10."""
        with patch("harombe.tools.web_search.DDGS") as mock_ddgs:
            instance = mock_ddgs.return_value.__enter__.return_value
            instance.text.return_value = []

            await web_search("test", max_results=100)

            instance.text.assert_called_once_with("test", max_results=10)

    @pytest.mark.asyncio
    async def test_max_results_clamped_low(self):
        """Test that max_results minimum is 1."""
        with patch("harombe.tools.web_search.DDGS") as mock_ddgs:
            instance = mock_ddgs.return_value.__enter__.return_value
            instance.text.return_value = []

            await web_search("test", max_results=0)

            instance.text.assert_called_once_with("test", max_results=1)

    @pytest.mark.asyncio
    async def test_search_error_handling(self):
        """Test error handling when search fails."""
        with patch("harombe.tools.web_search.DDGS") as mock_ddgs:
            mock_ddgs.return_value.__enter__.return_value.text.side_effect = Exception(
                "network error"
            )

            result = await web_search("test query")

            assert "Error" in result

    @pytest.mark.asyncio
    async def test_result_formatting(self):
        """Test that results are numbered and formatted."""
        mock_results = [
            {"title": "First", "href": "https://first.com", "body": "First result"},
            {"title": "Second", "href": "https://second.com", "body": "Second result"},
        ]

        with patch("harombe.tools.web_search.DDGS") as mock_ddgs:
            instance = mock_ddgs.return_value.__enter__.return_value
            instance.text.return_value = mock_results

            result = await web_search("test")

            assert "1. First" in result
            assert "2. Second" in result

    @pytest.mark.asyncio
    async def test_missing_fields_handled(self):
        """Test handling of results with missing fields."""
        mock_results = [
            {},  # Missing all fields
        ]

        with patch("harombe.tools.web_search.DDGS") as mock_ddgs:
            instance = mock_ddgs.return_value.__enter__.return_value
            instance.text.return_value = mock_results

            result = await web_search("test")

            assert "No title" in result or "No description" in result

    @pytest.mark.asyncio
    async def test_query_included_in_output(self):
        """Test that search query appears in output."""
        with patch("harombe.tools.web_search.DDGS") as mock_ddgs:
            instance = mock_ddgs.return_value.__enter__.return_value
            instance.text.return_value = [{"title": "R", "href": "http://r.com", "body": "r"}]

            result = await web_search("my special query")

            assert "my special query" in result
