"""
Simple Agent Example
====================

This example demonstrates basic single-node agent usage with harombe.
The agent can:
- Answer questions
- Execute shell commands
- Read and write files
- Search the web

Prerequisites:
- Ollama installed and running
- A model pulled (e.g., qwen2.5:7b)
- harombe installed: pip install harombe

Usage:
    python examples/01_simple_agent.py
"""

import asyncio

# Import tools to register them
from harombe.agent.loop import Agent
from harombe.llm.ollama import OllamaClient
from harombe.tools.registry import get_enabled_tools


async def main():
    """Run a simple agent with all available tools."""

    # 1. Create LLM client
    print("🤖 Initializing harombe agent...\n")
    llm = OllamaClient(
        model="qwen2.5:7b",  # Use whatever model you have
        base_url="http://localhost:11434/v1",
        temperature=0.7,
    )

    # 2. Get all available tools
    # Tools: shell, read_file, write_file, web_search
    tools = get_enabled_tools(
        shell=True,
        filesystem=True,
        web_search=True,
    )
    print(f"📦 Loaded {len(tools)} tools: {', '.join(t.schema.name for t in tools)}\n")

    # 3. Create agent with custom system prompt
    agent = Agent(
        llm=llm,
        tools=tools,
        max_steps=10,
        system_prompt="""You are a helpful AI assistant with access to tools.
        You can execute shell commands, read/write files, and search the web.
        Always explain what you're doing and ask for confirmation before dangerous operations.""",
        confirm_dangerous=True,  # Require confirmation for shell/write operations
    )

    # 4. Example queries demonstrating different capabilities
    queries = [
        # Simple question (no tools needed)
        "What is 2 + 2?",
        # File reading
        "Read the README.md file and tell me what this project does in one sentence.",
        # Web search
        "Search for 'Python 3.13 new features' and summarize the top result.",
        # Multi-step analysis
        "List all Python files in the src directory and count how many there are.",
    ]

    print("=" * 70)
    print("Running example queries...")
    print("=" * 70 + "\n")

    for i, query in enumerate(queries, 1):
        print(f"\n{'=' * 70}")
        print(f"Query {i}: {query}")
        print("=" * 70 + "\n")

        try:
            # Run the agent
            response = await agent.run(query)
            print(f"\n✓ Agent response:\n{response}\n")
        except Exception as e:
            print(f"\n✗ Error: {e}\n")

        # Pause between queries
        if i < len(queries):
            print("\n" + "-" * 70)
            await asyncio.sleep(1)

    print("\n" + "=" * 70)
    print("Example complete!")
    print("=" * 70)


def sync_main():
    """Synchronous wrapper for the async main function."""
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted by user")
    except Exception as e:
        print(f"\n\n❌ Error: {e}")
        raise


if __name__ == "__main__":
    sync_main()
