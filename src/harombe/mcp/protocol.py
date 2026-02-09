"""MCP (Model Context Protocol) JSON-RPC 2.0 implementation.

This module provides data models and utilities for MCP communication
using JSON-RPC 2.0 protocol.
"""

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class ErrorCode(int, Enum):
    """JSON-RPC 2.0 and Harombe-specific error codes."""

    # Standard JSON-RPC 2.0 errors
    PARSE_ERROR = -32700
    INVALID_REQUEST = -32600
    METHOD_NOT_FOUND = -32601
    INVALID_PARAMS = -32602
    INTERNAL_ERROR = -32603

    # Harombe-specific errors (-32000 to -32099)
    AUTHENTICATION_FAILED = -32000
    AUTHORIZATION_DENIED = -32001
    CONTAINER_UNAVAILABLE = -32002
    CONTAINER_TIMEOUT = -32003
    SECRET_DETECTED = -32004
    RATE_LIMIT_EXCEEDED = -32005
    RESOURCE_LIMIT_EXCEEDED = -32006


class ContentItem(BaseModel):
    """Content item in MCP response."""

    model_config = ConfigDict(populate_by_name=True)

    type: Literal["text", "image", "resource"]
    text: str | None = None
    data: str | None = None  # Base64 encoded for images
    uri: str | None = None  # For resources
    mimeType: str | None = Field(None, alias="mime_type")  # noqa: N815


class ToolCallParams(BaseModel):
    """Parameters for tools/call method."""

    name: str = Field(..., description="Tool name to execute")
    arguments: dict[str, Any] = Field(default_factory=dict, description="Tool arguments")


class MCPRequest(BaseModel):
    """JSON-RPC 2.0 request for MCP."""

    jsonrpc: Literal["2.0"] = "2.0"
    id: str | int = Field(..., description="Request identifier")
    method: str = Field(..., description="Method name (e.g., 'tools/call')")
    params: dict[str, Any] = Field(default_factory=dict, description="Method parameters")

    def get_tool_params(self) -> ToolCallParams | None:
        """Extract tool call parameters if method is 'tools/call'."""
        if self.method == "tools/call":
            return ToolCallParams(**self.params)
        return None


class MCPResult(BaseModel):
    """Result payload for MCP response."""

    model_config = ConfigDict(populate_by_name=True)

    content: list[ContentItem] = Field(default_factory=list, description="Response content items")
    isError: bool = Field(False, alias="is_error", description="Whether this is an error")  # noqa: N815


class MCPErrorData(BaseModel):
    """Additional error data."""

    type: str = Field(..., description="Error type")
    details: str | None = Field(None, description="Error details")


class MCPError(BaseModel):
    """JSON-RPC 2.0 error object."""

    code: int = Field(..., description="Error code")
    message: str = Field(..., description="Error message")
    data: MCPErrorData | dict[str, Any] | None = Field(None, description="Additional error data")


class MCPResponse(BaseModel):
    """JSON-RPC 2.0 response for MCP."""

    jsonrpc: Literal["2.0"] = "2.0"
    id: str | int = Field(..., description="Request identifier (matches request)")
    result: MCPResult | None = None
    error: MCPError | None = None

    def is_success(self) -> bool:
        """Check if response is successful."""
        return self.error is None

    def is_error_response(self) -> bool:
        """Check if response is an error."""
        return self.error is not None

    @classmethod
    def success(cls, request_id: str | int, content: list[ContentItem]) -> "MCPResponse":
        """Create a success response."""
        return cls(
            id=request_id,
            result=MCPResult(content=content),
        )

    @classmethod
    def from_error(
        cls,
        request_id: str | int,
        code: int,
        message: str,
        error_type: str | None = None,
        details: str | None = None,
    ) -> "MCPResponse":
        """Create an error response."""
        error_data = None
        if error_type or details:
            error_data = MCPErrorData(
                type=error_type or "InternalError",
                details=details,
            )

        return cls(
            id=request_id,
            error=MCPError(
                code=code,
                message=message,
                data=error_data,
            ),
        )


class HealthStatus(BaseModel):
    """Health check response."""

    status: Literal["healthy", "unhealthy", "degraded"]
    version: str
    uptime: int  # seconds
    containers: dict[str, str] | None = None  # container_name -> status


class ReadinessStatus(BaseModel):
    """Readiness check response."""

    ready: bool
    containers_healthy: int
    containers_total: int


def create_text_content(text: str) -> ContentItem:
    """Helper to create text content item."""
    return ContentItem(type="text", text=text)


def create_error_response(
    request_id: str | int,
    code: ErrorCode,
    message: str,
    details: str | None = None,
) -> MCPResponse:
    """Helper to create error response with ErrorCode enum."""
    return MCPResponse.from_error(
        request_id=request_id,
        code=code.value,
        message=message,
        error_type=code.name,
        details=details,
    )
