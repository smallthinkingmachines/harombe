"""Tests for MCP schema converters."""

from harombe.mcp.converters import (
    harombe_tool_to_mcp_input_schema,
    mcp_input_schema_to_harombe_params,
    mcp_tool_to_harombe_schema,
)
from harombe.tools.base import Tool, ToolParameter, ToolSchema


def _make_tool(name: str = "test_tool", params: list[ToolParameter] | None = None) -> Tool:
    """Helper to create a test tool."""

    async def noop(**kwargs):
        return "ok"

    schema = ToolSchema(
        name=name,
        description="A test tool",
        parameters=params or [],
    )
    return Tool(schema=schema, fn=noop)


class TestHarombeToolToMCPSchema:
    def test_empty_params(self):
        tool = _make_tool(params=[])
        result = harombe_tool_to_mcp_input_schema(tool)
        assert result["type"] == "object"
        assert result["properties"] == {}
        assert "required" not in result

    def test_required_string_param(self):
        tool = _make_tool(
            params=[
                ToolParameter(
                    name="query",
                    type="string",
                    description="Search query",
                    required=True,
                )
            ]
        )
        result = harombe_tool_to_mcp_input_schema(tool)
        assert "query" in result["properties"]
        assert result["properties"]["query"]["type"] == "string"
        assert result["required"] == ["query"]

    def test_optional_param(self):
        tool = _make_tool(
            params=[
                ToolParameter(
                    name="limit",
                    type="integer",
                    description="Max results",
                    required=False,
                )
            ]
        )
        result = harombe_tool_to_mcp_input_schema(tool)
        assert "limit" in result["properties"]
        assert "required" not in result or "limit" not in result.get("required", [])

    def test_enum_param(self):
        tool = _make_tool(
            params=[
                ToolParameter(
                    name="format",
                    type="string",
                    description="Output format",
                    required=True,
                    enum=["json", "csv", "xml"],
                )
            ]
        )
        result = harombe_tool_to_mcp_input_schema(tool)
        assert result["properties"]["format"]["enum"] == ["json", "csv", "xml"]

    def test_multiple_params(self):
        tool = _make_tool(
            params=[
                ToolParameter(name="query", type="string", description="Query", required=True),
                ToolParameter(name="limit", type="integer", description="Limit", required=False),
                ToolParameter(
                    name="verbose", type="boolean", description="Verbose", required=False
                ),
            ]
        )
        result = harombe_tool_to_mcp_input_schema(tool)
        assert len(result["properties"]) == 3
        assert result["required"] == ["query"]


class TestMCPInputSchemaToHarombeParams:
    def test_empty_schema(self):
        params = mcp_input_schema_to_harombe_params({})
        assert params == []

    def test_basic_properties(self):
        schema = {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "User name"},
                "age": {"type": "integer", "description": "User age"},
            },
            "required": ["name"],
        }
        params = mcp_input_schema_to_harombe_params(schema)
        assert len(params) == 2

        name_param = next(p for p in params if p.name == "name")
        assert name_param.type == "string"
        assert name_param.required is True

        age_param = next(p for p in params if p.name == "age")
        assert age_param.type == "integer"
        assert age_param.required is False

    def test_enum_property(self):
        schema = {
            "type": "object",
            "properties": {
                "color": {
                    "type": "string",
                    "description": "Color choice",
                    "enum": ["red", "blue", "green"],
                }
            },
        }
        params = mcp_input_schema_to_harombe_params(schema)
        assert params[0].enum == ["red", "blue", "green"]

    def test_missing_description(self):
        schema = {
            "type": "object",
            "properties": {
                "foo": {"type": "string"},
            },
        }
        params = mcp_input_schema_to_harombe_params(schema)
        assert params[0].description == "Parameter foo"


class TestMCPToolToHarombeSchema:
    def test_basic_conversion(self):
        schema = mcp_tool_to_harombe_schema(
            name="search",
            description="Search the web",
            input_schema={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Query"},
                },
                "required": ["query"],
            },
        )
        assert schema.name == "search"
        assert schema.description == "Search the web"
        assert len(schema.parameters) == 1
        assert schema.dangerous is False

    def test_none_description(self):
        schema = mcp_tool_to_harombe_schema(
            name="tool1",
            description=None,
            input_schema={},
        )
        assert "tool1" in schema.description
