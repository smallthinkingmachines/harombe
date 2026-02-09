"""Web search tool using DuckDuckGo."""

import asyncio

from duckduckgo_search import DDGS

from harombe.tools.registry import tool


@tool(description="Search the web using DuckDuckGo")
async def web_search(query: str, max_results: int = 5) -> str:
    """Search the web and return results.

    Args:
        query: Search query string
        max_results: Maximum number of results to return (default: 5, max: 10)

    Returns:
        Formatted search results with titles, URLs, and snippets
    """
    try:
        # Clamp max_results
        max_results = min(max(1, max_results), 10)

        # Run synchronous DDGS in thread pool
        def _search():
            with DDGS() as ddgs:
                return list(ddgs.text(query, max_results=max_results))

        results = await asyncio.to_thread(_search)

        if not results:
            return f"No results found for query: {query}"

        # Format results
        output = f"Search results for '{query}':\n\n"

        for i, result in enumerate(results, 1):
            title = result.get("title", "No title")
            url = result.get("href", "")
            snippet = result.get("body", "No description")

            output += f"{i}. {title}\n"
            output += f"   URL: {url}\n"
            output += f"   {snippet}\n\n"

        return output.strip()

    except Exception as e:
        return f"Error performing web search: {e!s}"
