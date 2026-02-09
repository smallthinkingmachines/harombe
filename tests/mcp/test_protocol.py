"""Tests for MCP JSON-RPC 2.0 protocol."""

from harombe.mcp.protocol import (
    ContentItem,
    ErrorCode,
    MCPRequest,
    MCPResponse,
    MCPResult,
    ToolCallParams,
    create_error_response,
    create_text_content,
)


def test_mcp_request_basic():
    """Test basic MCP request creation."""
    req = MCPRequest(
        id="req-123",
        method="tools/call",
        params={
            "name": "browser_navigate",
            "arguments": {"url": "https://example.com"},
        },
    )

    assert req.jsonrpc == "2.0"
    assert req.id == "req-123"
    assert req.method == "tools/call"
    assert req.params["name"] == "browser_navigate"


def test_mcp_request_get_tool_params():
    """Test extracting tool parameters from request."""
    req = MCPRequest(
        id="req-123",
        method="tools/call",
        params={
            "name": "filesystem_read",
            "arguments": {"path": "/workspace/data.txt"},
        },
    )

    tool_params = req.get_tool_params()
    assert tool_params is not None
    assert tool_params.name == "filesystem_read"
    assert tool_params.arguments["path"] == "/workspace/data.txt"


def test_mcp_request_non_tool_method():
    """Test get_tool_params returns None for non-tool methods."""
    req = MCPRequest(
        id="req-123",
        method="server/health",
        params={},
    )

    tool_params = req.get_tool_params()
    assert tool_params is None


def test_content_item_text():
    """Test text content item."""
    item = ContentItem(type="text", text="Hello, World!")

    assert item.type == "text"
    assert item.text == "Hello, World!"
    assert item.data is None
    assert item.uri is None


def test_content_item_image():
    """Test image content item."""
    item = ContentItem(
        type="image",
        data="iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==",
        mimeType="image/png",
    )

    assert item.type == "image"
    assert item.data is not None
    assert item.mimeType == "image/png"


def test_mcp_response_success():
    """Test success response creation."""
    content = [ContentItem(type="text", text="Operation successful")]
    response = MCPResponse.success(request_id="req-123", content=content)

    assert response.jsonrpc == "2.0"
    assert response.id == "req-123"
    assert response.result is not None
    assert len(response.result.content) == 1
    assert response.result.content[0].text == "Operation successful"
    assert response.error is None
    assert response.is_success()
    assert not response.is_error_response()


def test_mcp_response_error():
    """Test error response creation."""
    response = MCPResponse.from_error(
        request_id="req-123",
        code=ErrorCode.CONTAINER_UNAVAILABLE.value,
        message="Container not responding",
        error_type="ContainerError",
        details="Browser container failed health check",
    )

    assert response.jsonrpc == "2.0"
    assert response.id == "req-123"
    assert response.result is None
    assert response.error is not None
    assert response.error.code == ErrorCode.CONTAINER_UNAVAILABLE.value
    assert response.error.message == "Container not responding"
    assert response.error.data.type == "ContainerError"  # type: ignore[union-attr]
    assert "health check" in response.error.data.details  # type: ignore[union-attr]
    assert not response.is_success()
    assert response.is_error_response()


def test_create_text_content_helper():
    """Test create_text_content helper function."""
    item = create_text_content("Test message")

    assert item.type == "text"
    assert item.text == "Test message"


def test_create_error_response_helper():
    """Test create_error_response helper function."""
    response = create_error_response(
        request_id="req-123",
        code=ErrorCode.INVALID_PARAMS,
        message="Missing required parameter",
        details="Parameter 'url' is required",
    )

    assert response.id == "req-123"
    assert response.error is not None
    assert response.error.code == ErrorCode.INVALID_PARAMS.value
    assert response.error.message == "Missing required parameter"
    assert response.error.data.type == "INVALID_PARAMS"  # type: ignore[union-attr]


def test_error_code_enum():
    """Test ErrorCode enum values."""
    assert ErrorCode.PARSE_ERROR.value == -32700
    assert ErrorCode.INVALID_REQUEST.value == -32600
    assert ErrorCode.METHOD_NOT_FOUND.value == -32601
    assert ErrorCode.INVALID_PARAMS.value == -32602
    assert ErrorCode.INTERNAL_ERROR.value == -32603

    # Harombe-specific codes
    assert ErrorCode.AUTHENTICATION_FAILED.value == -32000
    assert ErrorCode.AUTHORIZATION_DENIED.value == -32001
    assert ErrorCode.CONTAINER_UNAVAILABLE.value == -32002
    assert ErrorCode.CONTAINER_TIMEOUT.value == -32003
    assert ErrorCode.SECRET_DETECTED.value == -32004


def test_mcp_request_json_serialization():
    """Test MCP request JSON serialization."""
    req = MCPRequest(
        id="req-123",
        method="tools/call",
        params={
            "name": "web_search",
            "arguments": {"query": "python tutorial"},
        },
    )

    json_str = req.model_dump_json()
    assert '"jsonrpc":"2.0"' in json_str
    assert '"id":"req-123"' in json_str
    assert '"method":"tools/call"' in json_str


def test_mcp_response_json_serialization():
    """Test MCP response JSON serialization."""
    response = MCPResponse.success(
        request_id="req-123",
        content=[create_text_content("Success")],
    )

    json_str = response.model_dump_json()
    assert '"jsonrpc":"2.0"' in json_str
    assert '"id":"req-123"' in json_str
    assert '"result"' in json_str
    assert '"Success"' in json_str


def test_tool_call_params_validation():
    """Test ToolCallParams validation."""
    # Valid params
    params = ToolCallParams(
        name="filesystem_write",
        arguments={"path": "/tmp/test.txt", "content": "Hello"},
    )
    assert params.name == "filesystem_write"
    assert params.arguments["path"] == "/tmp/test.txt"

    # Empty arguments (valid)
    params = ToolCallParams(name="web_search")
    assert params.arguments == {}


def test_mcp_result_with_multiple_content():
    """Test MCPResult with multiple content items."""
    result = MCPResult(
        content=[
            create_text_content("First message"),
            create_text_content("Second message"),
            ContentItem(type="image", data="base64data", mimeType="image/png"),
        ]
    )

    assert len(result.content) == 3
    assert result.content[0].text == "First message"
    assert result.content[1].text == "Second message"
    assert result.content[2].type == "image"


def test_mcp_request_integer_id():
    """Test MCP request with integer ID."""
    req = MCPRequest(id=123, method="tools/call", params={})

    assert req.id == 123
    assert isinstance(req.id, int)


def test_mcp_response_matches_request_id():
    """Test response ID matches request ID."""
    request_id = "req-abc-123"

    success_response = MCPResponse.success(
        request_id=request_id,
        content=[create_text_content("Done")],
    )
    assert success_response.id == request_id

    error_response = MCPResponse.from_error(
        request_id=request_id,
        code=ErrorCode.INTERNAL_ERROR.value,
        message="Error",
    )
    assert error_response.id == request_id
