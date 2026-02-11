"""Tests for the tool registration and discovery system."""

from typing import Union
from unittest.mock import MagicMock

import pytest

from harombe.tools.base import Tool, ToolSchema
from harombe.tools.registry import (
    _TOOL_SOURCES,
    _TOOLS,
    _python_type_to_json_schema,
    clear_tools,
    get_all_tools,
    get_enabled_tools,
    get_enabled_tools_v2,
    get_tool,
    tool,
)


@pytest.fixture(autouse=True)
def _clean_registry():
    """Ensure the global tool registry is clean for every test."""
    clear_tools()
    yield
    clear_tools()


# -- _python_type_to_json_schema ------------------------------------------------


def test_python_type_to_json_schema():
    assert _python_type_to_json_schema(str) == "string"
    assert _python_type_to_json_schema(int) == "integer"
    assert _python_type_to_json_schema(float) == "number"
    assert _python_type_to_json_schema(bool) == "boolean"
    assert _python_type_to_json_schema(list) == "array"
    assert _python_type_to_json_schema(dict) == "object"
    # NoneType has no __origin__, so falls through to default "string"
    assert _python_type_to_json_schema(type(None)) == "string"


def test_python_type_optional():
    assert _python_type_to_json_schema(str | None) == "string"


def test_python_type_union():
    assert _python_type_to_json_schema(Union[int, str]) == "integer"  # noqa: UP007


# -- tool decorator --------------------------------------------------------------


def test_tool_decorator_registration():
    @tool(description="Say hello", dangerous=False)
    async def greet(name: str, loud: bool = False) -> str:
        """Greet someone.

        name: The person's name
        loud: Whether to shout
        """
        return f"Hello, {name}!"

    assert "greet" in _TOOLS
    registered = _TOOLS["greet"]
    assert registered.schema.name == "greet"
    assert registered.schema.description == "Say hello"
    assert registered.schema.dangerous is False
    assert len(registered.schema.parameters) == 2

    name_param = registered.schema.parameters[0]
    assert name_param.name == "name"
    assert name_param.type == "string"
    assert name_param.required is True

    loud_param = registered.schema.parameters[1]
    assert loud_param.name == "loud"
    assert loud_param.type == "boolean"
    assert loud_param.required is False

    assert _TOOL_SOURCES["greet"] == "builtin"


# -- get_tool / get_all_tools ----------------------------------------------------


def test_get_tool_not_found():
    with pytest.raises(KeyError):
        get_tool("nonexistent_tool")


def test_get_all_tools_returns_copy():
    @tool(description="dummy")
    async def dummy_tool() -> str:
        return ""

    all_tools = get_all_tools()
    assert "dummy_tool" in all_tools
    # Modifying the copy should not affect the registry
    all_tools.pop("dummy_tool")
    assert "dummy_tool" in _TOOLS


# -- get_enabled_tools -----------------------------------------------------------


def _register_stub(name: str, source: str = "builtin") -> None:
    """Register a minimal stub tool in the global registry."""
    schema = ToolSchema(
        name=name,
        description=f"stub {name}",
        parameters=[],
        source=source,
    )

    async def _noop() -> str:
        return ""

    _TOOLS[name] = Tool(schema=schema, fn=_noop)
    _TOOL_SOURCES[name] = source


def test_get_enabled_tools_filtering():
    for name in ("shell", "read_file", "write_file", "web_search", "custom"):
        _register_stub(name)

    # All enabled
    enabled = get_enabled_tools(shell=True, filesystem=True, web_search=True)
    enabled_names = {t.schema.name for t in enabled}
    assert enabled_names == {"shell", "read_file", "write_file", "web_search", "custom"}

    # Disable shell
    enabled = get_enabled_tools(shell=False, filesystem=True, web_search=True)
    assert "shell" not in {t.schema.name for t in enabled}

    # Disable filesystem
    enabled = get_enabled_tools(shell=True, filesystem=False, web_search=True)
    names = {t.schema.name for t in enabled}
    assert "read_file" not in names
    assert "write_file" not in names

    # Disable web_search
    enabled = get_enabled_tools(shell=True, filesystem=True, web_search=False)
    assert "web_search" not in {t.schema.name for t in enabled}


# -- get_enabled_tools_v2 --------------------------------------------------------


def test_get_enabled_tools_v2_plugin_filtering():
    _register_stub("shell")
    _register_stub("plugin_tool", source="my_plugin")

    plugins_config = MagicMock()
    plugins_config.blocked = ["my_plugin"]
    plugins_config.plugins = {}

    enabled = get_enabled_tools_v2(
        shell=True, filesystem=True, web_search=True, plugins_config=plugins_config
    )
    enabled_names = {t.schema.name for t in enabled}
    assert "shell" in enabled_names
    assert "plugin_tool" not in enabled_names


def test_get_enabled_tools_v2_plugin_disabled_override():
    _register_stub("shell")
    _register_stub("plugin_tool", source="my_plugin")

    override = MagicMock()
    override.enabled = False

    plugins_config = MagicMock()
    plugins_config.blocked = []
    plugins_config.plugins = {"my_plugin": override}

    enabled = get_enabled_tools_v2(
        shell=True, filesystem=True, web_search=True, plugins_config=plugins_config
    )
    enabled_names = {t.schema.name for t in enabled}
    assert "plugin_tool" not in enabled_names


# -- clear_tools -----------------------------------------------------------------


def test_clear_tools():
    _register_stub("temp_tool")
    assert "temp_tool" in _TOOLS
    clear_tools()
    assert len(_TOOLS) == 0
    assert len(_TOOL_SOURCES) == 0
