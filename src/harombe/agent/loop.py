"""ReAct agent loop implementation."""

import asyncio
from typing import Any, Callable, Dict, List, Optional

from harombe.llm.client import CompletionResponse, LLMClient, Message, ToolCall
from harombe.tools.base import Tool


class AgentState:
    """Maintains conversation state for the agent."""

    def __init__(self, system_prompt: str):
        """Initialize agent state.

        Args:
            system_prompt: System message for the agent
        """
        self.messages: List[Message] = [
            Message(role="system", content=system_prompt)
        ]

    def add_user_message(self, content: str) -> None:
        """Add a user message to the conversation.

        Args:
            content: User message content
        """
        self.messages.append(Message(role="user", content=content))

    def add_assistant_message(self, response: CompletionResponse) -> None:
        """Add an assistant response to the conversation.

        Args:
            response: LLM completion response
        """
        self.messages.append(
            Message(
                role="assistant",
                content=response.content,
                tool_calls=response.tool_calls,
            )
        )

    def add_tool_result(self, tool_call_id: str, tool_name: str, result: str) -> None:
        """Add a tool execution result to the conversation.

        Args:
            tool_call_id: ID of the tool call
            tool_name: Name of the tool that was executed
            result: Tool execution result
        """
        self.messages.append(
            Message(
                role="tool",
                content=result,
                tool_call_id=tool_call_id,
                name=tool_name,
            )
        )


class Agent:
    """ReAct agent with tool calling capabilities."""

    def __init__(
        self,
        llm: LLMClient,
        tools: List[Tool],
        max_steps: int = 10,
        system_prompt: str = "You are a helpful AI assistant.",
        confirm_dangerous: bool = True,
        confirm_callback: Optional[Callable[[str, str, Dict[str, Any]], bool]] = None,
    ):
        """Initialize the agent.

        Args:
            llm: LLM client for generating responses
            tools: List of available tools
            max_steps: Maximum reasoning steps before forcing final answer
            system_prompt: System prompt for the agent
            confirm_dangerous: Whether to require confirmation for dangerous tools
            confirm_callback: Function called for dangerous tool confirmation.
                             Takes (tool_name, description, args) -> bool.
                             If None and confirm_dangerous=True, auto-denies dangerous tools.
        """
        self.llm = llm
        self.tools = {tool.schema.name: tool for tool in tools}
        self.max_steps = max_steps
        self.system_prompt = system_prompt
        self.confirm_dangerous = confirm_dangerous
        self.confirm_callback = confirm_callback

        # Build tool schemas for LLM
        self.tool_schemas = [
            tool.schema.to_openai_format()
            for tool in tools
        ]

    async def run(self, user_message: str) -> str:
        """Run the agent on a user message.

        Args:
            user_message: User's input message

        Returns:
            Agent's final response
        """
        state = AgentState(self.system_prompt)
        state.add_user_message(user_message)

        for step in range(1, self.max_steps + 1):
            # Get LLM response
            response = await self.llm.complete(
                messages=state.messages,
                tools=self.tool_schemas if step < self.max_steps else None,
            )

            # If no tool calls, this is the final answer
            if not response.tool_calls:
                return response.content

            # Add assistant response with tool calls
            state.add_assistant_message(response)

            # Execute each tool call
            for tool_call in response.tool_calls:
                result = await self._execute_tool_call(tool_call)
                state.add_tool_result(tool_call.id, tool_call.name, result)

        # Max steps reached - force final answer
        final_response = await self.llm.complete(
            messages=state.messages,
            tools=None,  # No tools available - must give final answer
        )

        return final_response.content

    async def _execute_tool_call(self, tool_call: ToolCall) -> str:
        """Execute a tool call with optional confirmation for dangerous tools.

        Args:
            tool_call: The tool call to execute

        Returns:
            Tool execution result or cancellation message
        """
        tool_name = tool_call.name

        # Check if tool exists
        if tool_name not in self.tools:
            return f"Error: Unknown tool '{tool_name}'"

        tool = self.tools[tool_name]

        # Check for dangerous tool confirmation
        if self.confirm_dangerous and tool.schema.dangerous:
            if self.confirm_callback is None:
                # No callback provided - auto-deny dangerous tools
                return f"[CANCELLED] Tool '{tool_name}' requires user confirmation"

            # Ask user for confirmation
            confirmed = self.confirm_callback(
                tool_name,
                tool.schema.description,
                tool_call.arguments,
            )

            if not confirmed:
                return f"[CANCELLED] User declined to execute '{tool_name}'"

        # Execute the tool
        try:
            result = await tool.execute(**tool_call.arguments)
            return result
        except TypeError as e:
            return f"Error: Invalid arguments for tool '{tool_name}': {e}"
        except Exception as e:
            return f"Error executing tool '{tool_name}': {e}"


async def run_agent_with_streaming(
    agent: Agent,
    user_message: str,
    on_chunk: Optional[Callable[[str], None]] = None,
    on_tool_call: Optional[Callable[[str, Dict[str, Any]], None]] = None,
    on_tool_result: Optional[Callable[[str, str], None]] = None,
) -> str:
    """Run agent with streaming callbacks for UI updates.

    This is a more advanced version that supports streaming tokens and
    real-time tool execution feedback.

    Args:
        agent: Agent instance
        user_message: User's input
        on_chunk: Callback for each content chunk (token)
        on_tool_call: Callback when tool is about to be called
        on_tool_result: Callback when tool execution completes

    Returns:
        Final agent response
    """
    # For now, just call the regular run method
    # Streaming implementation can be added later if needed
    return await agent.run(user_message)
