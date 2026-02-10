"""Schema converters between Harombe tools and MCP format."""

from __future__ import annotations

from typing import Any

from harombe.tools.base import Tool, ToolParameter, ToolSchema


def harombe_tool_to_mcp_input_schema(tool: Tool) -> dict[str, Any]:
    """Convert a Harombe Tool to an MCP-compatible input schema.

    Args:
        tool: Harombe Tool instance

    Returns:
        JSON Schema dict for MCP Tool.inputSchema
    """
    properties: dict[str, Any] = {}
    required: list[str] = []

    for param in tool.schema.parameters:
        param_schema: dict[str, Any] = {
            "type": param.type,
            "description": param.description,
        }
        if param.enum:
            param_schema["enum"] = param.enum
        properties[param.name] = param_schema
        if param.required:
            required.append(param.name)

    schema: dict[str, Any] = {
        "type": "object",
        "properties": properties,
    }
    if required:
        schema["required"] = required

    return schema


def mcp_input_schema_to_harombe_params(
    input_schema: dict[str, Any],
) -> list[ToolParameter]:
    """Convert an MCP input schema to Harombe ToolParameter list.

    Args:
        input_schema: MCP Tool.inputSchema dict

    Returns:
        List of ToolParameter instances
    """
    params: list[ToolParameter] = []
    properties = input_schema.get("properties", {})
    required_fields = set(input_schema.get("required", []))

    for name, prop in properties.items():
        params.append(
            ToolParameter(
                name=name,
                type=prop.get("type", "string"),
                description=prop.get("description", f"Parameter {name}"),
                required=name in required_fields,
                enum=prop.get("enum"),
            )
        )

    return params


def mcp_tool_to_harombe_schema(
    name: str,
    description: str | None,
    input_schema: dict[str, Any],
) -> ToolSchema:
    """Convert MCP tool metadata to a Harombe ToolSchema.

    Args:
        name: Tool name
        description: Tool description
        input_schema: MCP input schema

    Returns:
        ToolSchema instance
    """
    return ToolSchema(
        name=name,
        description=description or f"External tool: {name}",
        parameters=mcp_input_schema_to_harombe_params(input_schema),
        dangerous=False,
    )
