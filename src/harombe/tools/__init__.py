"""Built-in tool implementations for harombe agents.

Tools are registered via the ``@tool`` decorator and provide agents with
capabilities like shell execution, file operations, web search, and
browser automation. Tools declare whether they are dangerous (requiring
user confirmation) and expose JSON Schema for LLM function calling.

Available tools:

- **shell** - Execute shell commands (dangerous)
- **read_file** / **write_file** - Filesystem operations
- **web_search** - DuckDuckGo search (no API key required)
- **browser** - Playwright-based browser automation (Phase 4.6)

Usage::

    from harombe.tools.registry import get_enabled_tools

    tools = get_enabled_tools(shell=True, filesystem=True, web_search=True)
"""
