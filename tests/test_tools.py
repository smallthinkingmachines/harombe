"""Tests for tool registration and schema generation."""


import pytest

from harombe.tools.base import ToolParameter, ToolSchema
from harombe.tools.registry import clear_tools, get_all_tools, get_tool, tool


@pytest.fixture(autouse=True)
def cleanup_registry():
    """Clear tool registry before and after each test."""
    clear_tools()
    yield
    clear_tools()


def test_tool_schema_to_openai_format():
    """Test converting ToolSchema to OpenAI format."""
    schema = ToolSchema(
        name="test_tool",
        description="A test tool",
        parameters=[
            ToolParameter(name="arg1", type="string", description="First arg", required=True),
            ToolParameter(name="arg2", type="integer", description="Second arg", required=False),
        ],
    )

    openai_format = schema.to_openai_format()

    assert openai_format["type"] == "function"
    assert openai_format["function"]["name"] == "test_tool"
    assert openai_format["function"]["description"] == "A test tool"
    assert "arg1" in openai_format["function"]["parameters"]["properties"]
    assert "arg2" in openai_format["function"]["parameters"]["properties"]
    assert openai_format["function"]["parameters"]["required"] == ["arg1"]


def test_tool_decorator_registration():
    """Test that @tool decorator registers the function."""

    @tool(description="Test function")
    async def test_func(arg1: str) -> str:
        """Test function.

        Args:
            arg1: First argument
        """
        return f"Result: {arg1}"

    # Check registration
    registered = get_tool("test_func")
    assert registered.schema.name == "test_func"
    assert registered.schema.description == "Test function"
    assert len(registered.schema.parameters) == 1
    assert registered.schema.parameters[0].name == "arg1"


def test_tool_decorator_type_inference():
    """Test that decorator infers types from type hints."""

    @tool(description="Multi-type function")
    async def multi_type(
        str_arg: str,
        int_arg: int,
        float_arg: float,
        bool_arg: bool,
    ) -> str:
        """Function with multiple types.

        Args:
            str_arg: String parameter
            int_arg: Integer parameter
            float_arg: Float parameter
            bool_arg: Boolean parameter
        """
        return "ok"

    registered = get_tool("multi_type")
    params = {p.name: p for p in registered.schema.parameters}

    assert params["str_arg"].type == "string"
    assert params["int_arg"].type == "integer"
    assert params["float_arg"].type == "number"
    assert params["bool_arg"].type == "boolean"


def test_tool_decorator_optional_parameters():
    """Test that optional parameters are detected correctly."""

    @tool(description="Function with defaults")
    async def with_defaults(required: str, optional: int = 10) -> str:
        """Function with optional parameters.

        Args:
            required: Required parameter
            optional: Optional parameter
        """
        return f"{required}:{optional}"

    registered = get_tool("with_defaults")
    params = {p.name: p for p in registered.schema.parameters}

    assert params["required"].required is True
    assert params["optional"].required is False


def test_tool_decorator_dangerous_flag():
    """Test that dangerous flag is preserved."""

    @tool(description="Dangerous operation", dangerous=True)
    async def dangerous_func(cmd: str) -> str:
        """Dangerous function.

        Args:
            cmd: Command to run
        """
        return "executed"

    registered = get_tool("dangerous_func")
    assert registered.schema.dangerous is True


@pytest.mark.asyncio
async def test_tool_execution():
    """Test executing a registered tool."""

    @tool(description="Addition tool")
    async def add(a: int, b: int) -> str:
        """Add two numbers.

        Args:
            a: First number
            b: Second number
        """
        return str(a + b)

    registered = get_tool("add")
    result = await registered.execute(a=5, b=3)

    assert result == "8"


def test_get_all_tools():
    """Test getting all registered tools."""

    @tool(description="Tool 1")
    async def tool1() -> str:
        return "1"

    @tool(description="Tool 2")
    async def tool2() -> str:
        return "2"

    all_tools = get_all_tools()
    assert len(all_tools) == 2
    assert "tool1" in all_tools
    assert "tool2" in all_tools
