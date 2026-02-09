"""
API/Programmatic Usage Example
================================

This example demonstrates how to use harombe programmatically in your own
Python applications, rather than just through the CLI.

Topics covered:
- Creating agents programmatically
- Custom confirmation callbacks
- Error handling patterns
- Working with agent state
- Integrating harombe into existing code

Prerequisites:
- Ollama installed and running
- A model pulled (e.g., qwen2.5:7b)
- harombe installed: pip install harombe

Usage:
    python examples/02_api_usage.py
"""

import asyncio
from typing import Any

# Import tools to register them
from harombe.agent.loop import Agent
from harombe.llm.ollama import OllamaClient
from harombe.tools.registry import get_enabled_tools


# Example 1: Basic programmatic usage
async def basic_agent_usage():
    """Demonstrate basic programmatic agent usage."""
    print("\n" + "=" * 70)
    print("Example 1: Basic Programmatic Usage")
    print("=" * 70 + "\n")

    # Create agent
    llm = OllamaClient(
        model="qwen2.5:7b",
        base_url="http://localhost:11434/v1",
    )
    tools = get_enabled_tools(shell=True, filesystem=True, web_search=True)
    agent = Agent(llm=llm, tools=tools, system_prompt="You are a helpful assistant.")

    # Run a query
    try:
        response = await agent.run("What is the capital of France?")
        print(f"Response: {response}\n")
    except Exception as e:
        print(f"Error: {e}\n")


# Example 2: Custom confirmation callback
async def custom_confirmation_callback():
    """Demonstrate custom confirmation callback for dangerous operations."""
    print("\n" + "=" * 70)
    print("Example 2: Custom Confirmation Callback")
    print("=" * 70 + "\n")

    # Define a custom callback that logs and auto-approves certain operations
    def smart_confirm(tool_name: str, description: str, args: dict[str, Any]) -> bool:
        """Custom confirmation callback with logging and conditional approval."""
        print("🔔 Confirmation requested:")
        print(f"   Tool: {tool_name}")
        print(f"   Description: {description}")
        print(f"   Arguments: {args}")

        # Auto-approve safe read operations
        if tool_name == "read_file":
            print("   ✓ Auto-approved (read operation)")
            return True

        # Auto-approve writes to specific directories
        if tool_name == "write_file":
            file_path = args.get("file_path", "")
            if file_path.startswith("/tmp/") or file_path.startswith("./output/"):
                print("   ✓ Auto-approved (safe directory)")
                return True

        # Reject shell commands containing dangerous patterns
        if tool_name == "shell":
            command = args.get("command", "")
            dangerous_keywords = ["rm -rf", "sudo", "chmod 777", "dd if="]
            if any(keyword in command for keyword in dangerous_keywords):
                print("   ✗ Rejected (dangerous command)")
                return False

            # Auto-approve safe commands
            safe_commands = ["ls", "pwd", "echo", "cat", "grep"]
            if any(command.startswith(cmd) for cmd in safe_commands):
                print("   ✓ Auto-approved (safe command)")
                return True

        # Default: ask user
        print("   ? Manual approval required")
        response = input("   Approve? (y/n): ")
        return response.lower() == "y"

    # Create agent with custom callback
    llm = OllamaClient(model="qwen2.5:7b", base_url="http://localhost:11434/v1")
    tools = get_enabled_tools(shell=True, filesystem=True, web_search=True)
    agent = Agent(
        llm=llm,
        tools=tools,
        system_prompt="You are a helpful assistant.",
        confirm_dangerous=True,
        confirm_callback=smart_confirm,
    )

    # Test with a safe read operation (should auto-approve)
    try:
        response = await agent.run("Read the README.md file and tell me the project name.")
        print(f"\nResponse: {response}\n")
    except Exception as e:
        print(f"\nError: {e}\n")


# Example 3: Error handling patterns
async def error_handling_patterns():
    """Demonstrate proper error handling when using the agent."""
    print("\n" + "=" * 70)
    print("Example 3: Error Handling Patterns")
    print("=" * 70 + "\n")

    llm = OllamaClient(model="qwen2.5:7b", base_url="http://localhost:11434/v1")
    tools = get_enabled_tools(shell=True, filesystem=True, web_search=True)
    agent = Agent(
        llm=llm,
        tools=tools,
        system_prompt="You are a helpful assistant.",
        max_steps=5,  # Limit steps to prevent infinite loops
    )

    # Pattern 1: Try-except with specific handling
    print("Pattern 1: Specific error handling\n")
    try:
        response = await agent.run(
            "Read a file that definitely doesn't exist: /nonexistent/file.txt"
        )
        print(f"Response: {response}")
    except FileNotFoundError as e:
        print(f"✗ File not found: {e}")
    except PermissionError as e:
        print(f"✗ Permission denied: {e}")
    except Exception as e:
        print(f"✗ Unexpected error: {e}")

    # Pattern 2: Graceful degradation
    print("\nPattern 2: Graceful degradation\n")
    fallback_response = "I couldn't complete that task."
    try:
        response = await agent.run("Perform an impossible task")
    except Exception as e:
        print(f"Error occurred: {e}")
        response = fallback_response
    print(f"Final response: {response}")

    # Pattern 3: Retry logic
    print("\nPattern 3: Retry with backoff\n")
    max_retries = 3
    retry_delay = 1.0

    for attempt in range(max_retries):
        try:
            response = await agent.run("What is 2 + 2?")
            print(f"✓ Success on attempt {attempt + 1}: {response}")
            break
        except Exception as e:
            if attempt < max_retries - 1:
                print(f"✗ Attempt {attempt + 1} failed: {e}")
                print(f"  Retrying in {retry_delay}s...")
                await asyncio.sleep(retry_delay)
                retry_delay *= 2  # Exponential backoff
            else:
                print(f"✗ All {max_retries} attempts failed: {e}")


# Example 4: Multiple agents with different configurations
async def multiple_agents():
    """Demonstrate using multiple agents with different configurations."""
    print("\n" + "=" * 70)
    print("Example 4: Multiple Agents with Different Configurations")
    print("=" * 70 + "\n")

    llm = OllamaClient(model="qwen2.5:7b", base_url="http://localhost:11434/v1")

    # Agent 1: Research assistant (web search only)
    research_agent = Agent(
        llm=llm,
        tools=get_enabled_tools(shell=False, filesystem=False, web_search=True),
        system_prompt="You are a research assistant. Focus on finding accurate information from the web.",
    )

    # Agent 2: System administrator (shell only)
    sysadmin_agent = Agent(
        llm=llm,
        tools=get_enabled_tools(shell=True, filesystem=False, web_search=False),
        system_prompt="You are a system administrator. Focus on system tasks and command execution.",
        confirm_dangerous=False,  # Auto-approve for this example
    )

    # Agent 3: Data analyst (filesystem only)
    analyst_agent = Agent(
        llm=llm,
        tools=get_enabled_tools(shell=False, filesystem=True, web_search=False),
        system_prompt="You are a data analyst. Focus on reading and analyzing files.",
    )

    # Use different agents for different tasks
    print("Research Agent: Searching for information...")
    try:
        response = await research_agent.run("What is the capital of France?")
        print(f"✓ {response}\n")
    except Exception as e:
        print(f"✗ Error: {e}\n")

    print("System Admin Agent: Checking system info...")
    try:
        response = await sysadmin_agent.run("What is the current directory?")
        print(f"✓ {response}\n")
    except Exception as e:
        print(f"✗ Error: {e}\n")

    print("Data Analyst Agent: Analyzing files...")
    try:
        response = await analyst_agent.run("List the files in the current directory")
        print(f"✓ {response}\n")
    except Exception as e:
        print(f"✗ Error: {e}\n")


# Example 5: Integration with existing code
async def integration_example():
    """Demonstrate integrating harombe into existing application logic."""
    print("\n" + "=" * 70)
    print("Example 5: Integration with Existing Code")
    print("=" * 70 + "\n")

    # Simulate an existing application that processes tasks
    class TaskProcessor:
        """Example application that processes user tasks."""

        def __init__(self):
            self.llm = OllamaClient(model="qwen2.5:7b", base_url="http://localhost:11434/v1")
            self.tools = get_enabled_tools(shell=False, filesystem=True, web_search=True)
            self.agent = Agent(
                llm=self.llm,
                tools=self.tools,
                system_prompt="You are a task processing assistant.",
                confirm_dangerous=False,  # Auto-approve in batch mode
            )

        async def process_task(self, task_description: str) -> dict[str, Any]:
            """Process a task and return structured results."""
            print(f"📋 Processing task: {task_description}")

            try:
                response = await self.agent.run(task_description)
                return {
                    "status": "success",
                    "task": task_description,
                    "result": response,
                    "error": None,
                }
            except Exception as e:
                return {
                    "status": "failed",
                    "task": task_description,
                    "result": None,
                    "error": str(e),
                }

        async def process_batch(self, tasks: list[str]) -> list[dict[str, Any]]:
            """Process multiple tasks in sequence."""
            results = []
            for task in tasks:
                result = await self.process_task(task)
                results.append(result)
                print(f"   Status: {result['status']}")
                await asyncio.sleep(0.5)  # Rate limiting
            return results

    # Use the task processor
    processor = TaskProcessor()

    tasks = [
        "What is the capital of Japan?",
        "Search for 'Python asyncio tutorial' and summarize the first result",
        "List the files in the current directory",
    ]

    print("Processing batch of tasks...\n")
    results = await processor.process_batch(tasks)

    # Summary
    print("\n" + "=" * 70)
    print("Batch Processing Summary:")
    print("=" * 70)
    successful = sum(1 for r in results if r["status"] == "success")
    print(f"Total tasks: {len(results)}")
    print(f"Successful: {successful}")
    print(f"Failed: {len(results) - successful}")


async def main():
    """Run all examples."""
    print("\n" + "=" * 70)
    print("Harombe API/Programmatic Usage Examples")
    print("=" * 70)

    # Run examples in sequence
    await basic_agent_usage()
    await custom_confirmation_callback()
    await error_handling_patterns()
    await multiple_agents()
    await integration_example()

    print("\n" + "=" * 70)
    print("All examples complete!")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted by user")
    except Exception as e:
        print(f"\n\n❌ Error: {e}")
        raise
