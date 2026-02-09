"""Tool registration and discovery system."""

import inspect
from collections.abc import Callable
from typing import Any, Union, get_type_hints

from harombe.tools.base import Tool, ToolFunction, ToolParameter, ToolSchema

# Global tool registry
_TOOLS: dict[str, Tool] = {}


def _python_type_to_json_schema(py_type: Any) -> str:
    """Convert Python type hint to JSON Schema type.

    Args:
        py_type: Python type annotation

    Returns:
        JSON Schema type string
    """
    # Handle Optional types
    origin = getattr(py_type, "__origin__", None)
    if origin is type(None):
        return "null"

    # Unwrap Union types (including Optional)
    if origin is Union:
        args = getattr(py_type, "__args__", ())
        # Filter out NoneType and get the first non-None type
        non_none = [arg for arg in args if arg is not type(None)]
        if non_none:
            py_type = non_none[0]

    # Map Python types to JSON Schema types
    type_map = {
        str: "string",
        int: "integer",
        float: "number",
        bool: "boolean",
        list: "array",
        dict: "object",
    }

    return type_map.get(py_type, "string")


def tool(
    description: str,
    dangerous: bool = False,
) -> Callable[[ToolFunction], ToolFunction]:
    """Decorator to register a function as a tool.

    Introspects the function signature and docstring to build the tool schema.

    Args:
        description: Human-readable description of what the tool does
        dangerous: Whether the tool performs potentially dangerous operations

    Returns:
        Decorator function

    Example:
        @tool(description="Execute a shell command", dangerous=True)
        async def shell(command: str, timeout: int = 30) -> str:
            '''Run a shell command.

            Args:
                command: The shell command to execute
                timeout: Max execution time in seconds
            '''
            ...
    """

    def decorator(fn: ToolFunction) -> ToolFunction:
        # Get type hints
        hints = get_type_hints(fn)
        sig = inspect.signature(fn)

        # Build parameters from signature
        parameters: list[ToolParameter] = []

        for param_name, param in sig.parameters.items():
            if param_name == "return":
                continue

            param_type = hints.get(param_name, str)
            json_type = _python_type_to_json_schema(param_type)

            # Extract parameter description from docstring if available
            param_desc = f"Parameter {param_name}"
            if fn.__doc__:
                # Simple parsing: look for "param_name: description" pattern
                for line in fn.__doc__.split("\n"):
                    line = line.strip()
                    if line.startswith(f"{param_name}:"):
                        param_desc = line[len(param_name) + 1 :].strip()
                        break

            required = param.default == inspect.Parameter.empty

            parameters.append(
                ToolParameter(
                    name=param_name,
                    type=json_type,
                    description=param_desc,
                    required=required,
                )
            )

        # Create tool schema
        schema = ToolSchema(
            name=fn.__name__,
            description=description,
            parameters=parameters,
            dangerous=dangerous,
        )

        # Register the tool
        _TOOLS[fn.__name__] = Tool(schema=schema, fn=fn)

        return fn

    return decorator


def get_tool(name: str) -> Tool:
    """Get a registered tool by name.

    Args:
        name: Tool name

    Returns:
        Tool instance

    Raises:
        KeyError: If tool not found
    """
    return _TOOLS[name]


def get_all_tools() -> dict[str, Tool]:
    """Get all registered tools.

    Returns:
        Dictionary mapping tool names to Tool instances
    """
    return _TOOLS.copy()


def get_enabled_tools(
    shell: bool = True,
    filesystem: bool = True,
    web_search: bool = True,
) -> list[Tool]:
    """Get tools based on configuration flags.

    Args:
        shell: Include shell execution tool
        filesystem: Include filesystem tools
        web_search: Include web search tool

    Returns:
        List of enabled Tool instances
    """
    enabled = []

    for name, tool_obj in _TOOLS.items():
        # Map tool names to configuration flags
        if name == "shell" and not shell:
            continue
        if name in ("read_file", "write_file") and not filesystem:
            continue
        if name == "web_search" and not web_search:
            continue

        enabled.append(tool_obj)

    return enabled


def clear_tools() -> None:
    """Clear all registered tools. Used for testing."""
    _TOOLS.clear()
