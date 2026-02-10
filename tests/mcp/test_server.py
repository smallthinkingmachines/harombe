"""Tests for MCP server."""

from harombe.mcp.converters import harombe_tool_to_mcp_input_schema
from harombe.mcp.server import create_mcp_server
from harombe.tools.base import Tool, ToolParameter, ToolSchema


def _make_tool(name: str, result: str = "ok", dangerous: bool = False) -> Tool:
    """Create a test tool."""

    async def fn(**kwargs):
        return result

    schema = ToolSchema(
        name=name,
        description=f"Test tool: {name}",
        parameters=[
            ToolParameter(name="input", type="string", description="Input value", required=True),
        ],
        dangerous=dangerous,
    )
    return Tool(schema=schema, fn=fn)


def _make_failing_tool(name: str) -> Tool:
    """Create a tool that raises an exception."""

    async def fn(**kwargs):
        raise RuntimeError("tool failed")

    schema = ToolSchema(
        name=name,
        description=f"Failing tool: {name}",
        parameters=[],
    )
    return Tool(schema=schema, fn=fn)


class TestCreateMCPServer:
    def test_creates_server(self):
        tools = {"echo": _make_tool("echo")}
        server = create_mcp_server(tools)
        assert server is not None

    def test_creates_server_with_custom_name(self):
        tools = {"echo": _make_tool("echo")}
        server = create_mcp_server(tools, server_name="test-server")
        assert server is not None


class TestMCPServerToolConversion:
    def test_tool_to_mcp_schema(self):
        tool = _make_tool("search")
        schema = harombe_tool_to_mcp_input_schema(tool)
        assert schema["type"] == "object"
        assert "input" in schema["properties"]
        assert schema["required"] == ["input"]

    def test_empty_tools(self):
        server = create_mcp_server({})
        assert server is not None

    def test_multiple_tools(self):
        tools = {
            "search": _make_tool("search"),
            "read": _make_tool("read"),
            "write": _make_tool("write"),
        }
        server = create_mcp_server(tools)
        assert server is not None
