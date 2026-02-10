"""Tests for dynamic tool route registration in the MCP Gateway."""

from harombe.security.gateway import (
    TOOL_ROUTES,
    _tool_routes,
    register_plugin_routes,
    register_tool_route,
    unregister_tool_route,
)


class TestDynamicRouteRegistration:
    """Test register/unregister tool route functions."""

    def setup_method(self):
        """Snapshot built-in routes and restore after each test."""
        self._original_routes = dict(_tool_routes)

    def teardown_method(self):
        """Restore original routes."""
        _tool_routes.clear()
        _tool_routes.update(self._original_routes)

    def test_register_tool_route(self):
        register_tool_route("my_custom_tool", "localhost:4000")
        assert _tool_routes["my_custom_tool"] == "localhost:4000"

    def test_unregister_tool_route(self):
        register_tool_route("temp_tool", "localhost:4001")
        assert "temp_tool" in _tool_routes
        result = unregister_tool_route("temp_tool")
        assert result is True
        assert "temp_tool" not in _tool_routes

    def test_unregister_nonexistent_route(self):
        result = unregister_tool_route("does_not_exist")
        assert result is False

    def test_register_plugin_routes_batch(self):
        routes = {
            "plugin_tool_a": "localhost:3100",
            "plugin_tool_b": "localhost:3101",
            "plugin_tool_c": "localhost:3102",
        }
        register_plugin_routes(routes)
        for tool_name, endpoint in routes.items():
            assert _tool_routes[tool_name] == endpoint

    def test_builtin_routes_preserved_after_plugin_registration(self):
        # Verify built-in routes exist
        assert "browser_navigate" in _tool_routes
        assert "filesystem_read" in _tool_routes
        assert "code_execute" in _tool_routes
        assert "web_search" in _tool_routes

        # Register plugin routes
        register_plugin_routes({"plugin_x": "localhost:3200"})

        # Built-in routes still present
        assert _tool_routes["browser_navigate"] == "browser-container:3000"
        assert _tool_routes["filesystem_read"] == "filesystem-container:3001"
        assert _tool_routes["code_execute"] == "code-exec-container:3002"
        assert _tool_routes["web_search"] == "web-search-container:3003"

        # Plugin route also present
        assert _tool_routes["plugin_x"] == "localhost:3200"

    def test_backward_compatible_alias(self):
        """TOOL_ROUTES is the same object as _tool_routes."""
        assert TOOL_ROUTES is _tool_routes

    def test_register_overwrites_existing(self):
        register_tool_route("browser_navigate", "new-container:5000")
        assert _tool_routes["browser_navigate"] == "new-container:5000"

    def test_register_and_unregister_cycle(self):
        register_tool_route("cycle_tool", "localhost:9000")
        assert "cycle_tool" in _tool_routes

        unregister_tool_route("cycle_tool")
        assert "cycle_tool" not in _tool_routes

        # Re-register
        register_tool_route("cycle_tool", "localhost:9001")
        assert _tool_routes["cycle_tool"] == "localhost:9001"
