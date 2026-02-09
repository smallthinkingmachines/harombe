"""Base types for the tool system."""

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any


@dataclass
class ToolParameter:
    """Definition of a tool parameter."""

    name: str
    type: str  # JSON Schema type
    description: str
    required: bool = True
    enum: list[str] | None = None


@dataclass
class ToolSchema:
    """JSON Schema representation of a tool for LLM function calling."""

    name: str
    description: str
    parameters: list[ToolParameter]
    dangerous: bool = False

    def to_openai_format(self) -> dict[str, Any]:
        """Convert to OpenAI function calling format.

        Returns:
            Dictionary matching OpenAI's function schema format
        """
        properties = {}
        required = []

        for param in self.parameters:
            param_schema: dict[str, Any] = {
                "type": param.type,
                "description": param.description,
            }
            if param.enum:
                param_schema["enum"] = param.enum

            properties[param.name] = param_schema

            if param.required:
                required.append(param.name)

        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "properties": properties,
                    "required": required,
                },
            },
        }


# Tool function signature: async function that returns a string result
ToolFunction = Callable[..., Awaitable[str]]


@dataclass
class Tool:
    """A tool that the agent can use."""

    schema: ToolSchema
    fn: ToolFunction

    async def execute(self, **kwargs: Any) -> str:
        """Execute the tool with given arguments.

        Args:
            **kwargs: Tool arguments

        Returns:
            Tool execution result as string
        """
        return await self.fn(**kwargs)
