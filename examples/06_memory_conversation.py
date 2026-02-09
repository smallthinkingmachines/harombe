#!/usr/bin/env python3
"""Example: Conversation Memory

Demonstrates persistent conversation history across multiple agent interactions.

This example shows:
- Creating and managing conversation sessions
- Loading conversation history
- Maintaining context across agent runs
- Session management (list, delete, clear)

Usage:
    python examples/06_memory_conversation.py
"""

import asyncio
import tempfile
from pathlib import Path

from harombe.agent.loop import Agent
from harombe.llm.ollama import OllamaClient
from harombe.memory.manager import MemoryManager
from harombe.memory.schema import SessionMetadata
from harombe.tools.base import tool


# Define a simple tool for the agent
@tool(description="Get the current timestamp")
async def get_timestamp() -> str:
    """Get current timestamp.

    Returns:
        ISO format timestamp
    """
    from datetime import datetime

    return datetime.now().isoformat()


async def main():
    """Run memory conversation example."""
    # Create a temporary memory database for demo
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "demo_memory.db"

        print("=" * 60)
        print("Harombe Memory Example")
        print("=" * 60)
        print()

        # Initialize memory manager
        memory_manager = MemoryManager(
            storage_path=db_path,
            max_history_tokens=4096,  # Load up to 4K tokens from history
        )

        # Create LLM client
        llm = OllamaClient(
            model="qwen3:8b",
            host="http://localhost:11434",
        )

        # Session 1: Initial conversation
        print("Session 1: Initial Conversation")
        print("-" * 60)

        session_id = memory_manager.create_session(
            system_prompt="You are a helpful assistant with a great memory.",
            metadata=SessionMetadata(
                user="demo_user",
                title="Memory Demo Session",
                tags=["demo", "memory"],
            ),
        )
        print(f"Created session: {session_id}")
        print()

        # First interaction
        agent1 = Agent(
            llm=llm,
            tools=[get_timestamp],
            system_prompt="You are a helpful assistant with a great memory.",
            memory_manager=memory_manager,
            session_id=session_id,
        )

        print("User: What is your name?")
        response1 = await agent1.run("What is your name?")
        print(f"Agent: {response1}")
        print()

        # Second interaction (same session, new agent instance)
        print("User: Can you tell me the time?")
        agent2 = Agent(
            llm=llm,
            tools=[get_timestamp],
            system_prompt="You are a helpful assistant with a great memory.",
            memory_manager=memory_manager,
            session_id=session_id,
        )

        response2 = await agent2.run("Can you tell me the time?")
        print(f"Agent: {response2}")
        print()

        # Third interaction - test memory recall
        print("User: Do you remember what I asked you first?")
        agent3 = Agent(
            llm=llm,
            tools=[get_timestamp],
            system_prompt="You are a helpful assistant with a great memory.",
            memory_manager=memory_manager,
            session_id=session_id,
        )

        response3 = await agent3.run("Do you remember what I asked you first?")
        print(f"Agent: {response3}")
        print()

        # Inspect conversation history
        print("=" * 60)
        print("Conversation History")
        print("=" * 60)

        history = memory_manager.load_history(session_id)
        print(f"Total messages: {len(history)}")
        print()

        for i, msg in enumerate(history, 1):
            if msg.role == "system":
                print(f"{i}. [SYSTEM] {msg.content[:60]}...")
            elif msg.role == "user":
                print(f"{i}. [USER] {msg.content}")
            elif msg.role == "assistant":
                print(f"{i}. [ASSISTANT] {msg.content[:100]}...")
                if msg.tool_calls:
                    print(f"    └─ Tool calls: {len(msg.tool_calls)}")
            elif msg.role == "tool":
                print(f"{i}. [TOOL: {msg.name}] {msg.content[:60]}...")
            print()

        # Session management demo
        print("=" * 60)
        print("Session Management")
        print("=" * 60)

        # List sessions
        sessions = memory_manager.list_sessions(limit=10)
        print(f"Total sessions: {len(sessions)}")
        for session in sessions:
            print(f"- {session.id}: {session.metadata.title if session.metadata else 'Untitled'}")
        print()

        # Message count
        msg_count = memory_manager.get_message_count(session_id)
        print(f"Messages in current session: {msg_count}")
        print()

        # Get recent messages
        recent = memory_manager.get_recent_messages(session_id, count=3)
        print("Last 3 messages:")
        for msg in recent:
            role_str = msg.role.upper()
            content_preview = msg.content[:50] + "..." if len(msg.content) > 50 else msg.content
            print(f"  [{role_str}] {content_preview}")
        print()

        # Clear history (keeps session, removes messages)
        print("Clearing conversation history...")
        cleared_count = memory_manager.clear_history(session_id)
        print(f"Cleared {cleared_count} messages")
        print()

        # Verify empty
        history_after = memory_manager.load_history(session_id)
        print(f"Messages after clear: {len(history_after)}")
        print()

        # Delete session completely
        print("Deleting session...")
        deleted = memory_manager.delete_session(session_id)
        print(f"Session deleted: {deleted}")
        print()

        # Session 2: Token windowing demo
        print("=" * 60)
        print("Token Windowing Demo")
        print("=" * 60)

        session_id2 = memory_manager.create_session(
            system_prompt="You are a helpful assistant.",
            metadata=SessionMetadata(title="Token Window Test"),
        )

        # Create a conversation with many messages
        agent4 = Agent(
            llm=llm,
            tools=[],
            memory_manager=memory_manager,
            session_id=session_id2,
        )

        for i in range(5):
            print(f"Turn {i+1}...")
            await agent4.run(f"Message number {i+1}")

        # Load with different token limits
        all_history = memory_manager.load_history(session_id2, max_tokens=10000)
        limited_history = memory_manager.load_history(session_id2, max_tokens=512)

        print(f"Full history: {len(all_history)} messages")
        print(f"Limited (512 tokens): {len(limited_history)} messages")
        print("(Token windowing keeps most recent messages within limit)")
        print()

        memory_manager.delete_session(session_id2)

    print("=" * 60)
    print("Demo complete!")
    print()
    print("Key takeaways:")
    print("- Conversations persist across Agent instances")
    print("- History loads automatically when session_id is provided")
    print("- Token windowing prevents context overflow")
    print("- Sessions are independent and can be managed separately")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
