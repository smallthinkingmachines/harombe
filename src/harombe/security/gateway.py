"""MCP Gateway - Central security enforcement point for tool execution.

The MCP Gateway acts as a proxy between the agent and capability containers,
providing request routing, health checking, and audit logging.
"""

import asyncio
import logging
import time

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from harombe.mcp.protocol import (
    ErrorCode,
    HealthStatus,
    MCPRequest,
    MCPResponse,
    ReadinessStatus,
    create_error_response,
)

logger = logging.getLogger(__name__)

# Tool → Container routing table
TOOL_ROUTES: dict[str, str] = {
    # Browser tools
    "browser_navigate": "browser-container:3000",
    "browser_click": "browser-container:3000",
    "browser_type": "browser-container:3000",
    "browser_read": "browser-container:3000",
    # Filesystem tools
    "filesystem_read": "filesystem-container:3001",
    "filesystem_write": "filesystem-container:3001",
    "filesystem_list": "filesystem-container:3001",
    # Code execution tools
    "code_execute": "code-exec-container:3002",
    # Web search tools
    "web_search": "web-search-container:3003",
}


class MCPClientPool:
    """HTTP client pool for capability containers."""

    def __init__(
        self,
        max_connections: int = 10,
        timeout: float = 30.0,
        max_retries: int = 3,
    ):
        """Initialize client pool.

        Args:
            max_connections: Maximum connections per container
            timeout: Request timeout in seconds
            max_retries: Maximum retry attempts
        """
        self._clients: dict[str, httpx.AsyncClient] = {}
        self._max_connections = max_connections
        self._timeout = timeout
        self._max_retries = max_retries
        self._container_health: dict[str, bool] = {}

    async def get_client(self, container: str) -> httpx.AsyncClient:
        """Get or create HTTP client for container.

        Args:
            container: Container endpoint (e.g., "browser-container:3000")

        Returns:
            Async HTTP client
        """
        if container not in self._clients:
            self._clients[container] = httpx.AsyncClient(
                base_url=f"http://{container}",
                timeout=self._timeout,
                limits=httpx.Limits(
                    max_keepalive_connections=self._max_connections,
                    max_connections=self._max_connections,
                ),
            )
            self._container_health[container] = True
            logger.info(f"Created HTTP client for {container}")

        return self._clients[container]

    async def send_request(
        self,
        container: str,
        request: MCPRequest,
    ) -> MCPResponse:
        """Send MCP request to container with retry logic.

        Args:
            container: Container endpoint
            request: MCP request

        Returns:
            MCP response

        Raises:
            HTTPException: If request fails after retries
        """
        client = await self.get_client(container)

        for attempt in range(self._max_retries):
            try:
                logger.debug(f"Sending request to {container} (attempt {attempt + 1})")

                response = await client.post(
                    "/mcp",
                    json=request.model_dump(mode="json"),
                )

                if response.status_code == 200:
                    data = response.json()
                    return MCPResponse(**data)

                # Retry on 502, 503, 504
                if response.status_code in {502, 503, 504} and attempt < self._max_retries - 1:
                    wait_time = 2.0**attempt  # Exponential backoff
                    logger.warning(
                        f"Container {container} returned {response.status_code}, "
                        f"retrying in {wait_time}s"
                    )
                    await asyncio.sleep(wait_time)
                    continue

                # Other errors
                raise HTTPException(
                    status_code=response.status_code,
                    detail=f"Container returned error: {response.text}",
                )

            except httpx.TimeoutException:
                if attempt < self._max_retries - 1:
                    wait_time = 2.0**attempt
                    logger.warning(f"Timeout on {container}, retrying in {wait_time}s")
                    await asyncio.sleep(wait_time)
                    continue

                logger.error(f"Container {container} timed out after {self._max_retries} attempts")
                return create_error_response(
                    request_id=request.id,
                    code=ErrorCode.CONTAINER_TIMEOUT,
                    message=f"Container {container} did not respond in time",
                    details=f"Timeout after {self._timeout}s",
                )

            except httpx.ConnectError as e:
                logger.error(f"Failed to connect to {container}: {e}")
                self._container_health[container] = False
                return create_error_response(
                    request_id=request.id,
                    code=ErrorCode.CONTAINER_UNAVAILABLE,
                    message=f"Cannot connect to {container}",
                    details=str(e),
                )

            except Exception as e:
                logger.exception(f"Unexpected error contacting {container}")
                return create_error_response(
                    request_id=request.id,
                    code=ErrorCode.INTERNAL_ERROR,
                    message="Internal gateway error",
                    details=str(e),
                )

        # All retries exhausted
        return create_error_response(
            request_id=request.id,
            code=ErrorCode.CONTAINER_TIMEOUT,
            message=f"Container {container} failed after {self._max_retries} attempts",
        )

    async def check_health(self, container: str) -> bool:
        """Check if container is healthy.

        Args:
            container: Container endpoint

        Returns:
            True if healthy, False otherwise
        """
        try:
            client = await self.get_client(container)
            response = await client.get("/health", timeout=5.0)
            healthy = response.status_code == 200
            self._container_health[container] = healthy
            return healthy
        except Exception as e:
            logger.warning(f"Health check failed for {container}: {e}")
            self._container_health[container] = False
            return False

    def get_health_status(self) -> dict[str, str]:
        """Get health status of all containers.

        Returns:
            Dict mapping container to status ("healthy" or "unhealthy")
        """
        return {
            container: "healthy" if healthy else "unhealthy"
            for container, healthy in self._container_health.items()
        }

    async def close_all(self) -> None:
        """Close all HTTP clients."""
        for container, client in self._clients.items():
            await client.aclose()
            logger.info(f"Closed HTTP client for {container}")
        self._clients.clear()


class MCPGateway:
    """MCP Gateway server for routing and security enforcement."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8100,
        version: str = "0.1.0",
    ):
        """Initialize MCP Gateway.

        Args:
            host: Host to bind to
            port: Port to listen on
            version: Gateway version
        """
        self.host = host
        self.port = port
        self.version = version
        self.app = FastAPI(
            title="Harombe MCP Gateway",
            description="Central security enforcement point for AI agent tool execution",
            version=version,
        )
        self.client_pool = MCPClientPool()
        self.start_time = time.time()

        # Register routes
        self._setup_routes()

    def _setup_routes(self) -> None:
        """Set up FastAPI routes."""

        @self.app.post("/mcp")
        async def handle_mcp_request(request: Request) -> JSONResponse:
            """Handle MCP JSON-RPC requests.

            Args:
                request: FastAPI request

            Returns:
                JSON-RPC response
            """
            try:
                # Parse request
                body = await request.json()
                mcp_request = MCPRequest(**body)

                logger.info(f"Received MCP request: {mcp_request.method} (id={mcp_request.id})")

                # Extract tool name
                tool_params = mcp_request.get_tool_params()
                if tool_params is None:
                    return JSONResponse(
                        content=create_error_response(
                            request_id=mcp_request.id,
                            code=ErrorCode.INVALID_PARAMS,
                            message="Invalid method or parameters",
                            details=f"Method '{mcp_request.method}' is not supported",
                        ).model_dump(mode="json")
                    )

                tool_name = tool_params.name

                # Route to container
                if tool_name not in TOOL_ROUTES:
                    return JSONResponse(
                        content=create_error_response(
                            request_id=mcp_request.id,
                            code=ErrorCode.METHOD_NOT_FOUND,
                            message=f"Tool '{tool_name}' not found",
                            details=f"No container registered for tool '{tool_name}'",
                        ).model_dump(mode="json")
                    )

                container = TOOL_ROUTES[tool_name]
                logger.debug(f"Routing {tool_name} to {container}")

                # Forward request to container
                response = await self.client_pool.send_request(container, mcp_request)

                return JSONResponse(content=response.model_dump(mode="json"))

            except ValueError as e:
                # Invalid JSON-RPC format
                return JSONResponse(
                    content=create_error_response(
                        request_id="unknown",
                        code=ErrorCode.INVALID_REQUEST,
                        message="Invalid request format",
                        details=str(e),
                    ).model_dump(mode="json"),
                    status_code=400,
                )

            except Exception as e:
                logger.exception("Unexpected error handling MCP request")
                return JSONResponse(
                    content=create_error_response(
                        request_id="unknown",
                        code=ErrorCode.INTERNAL_ERROR,
                        message="Internal gateway error",
                        details=str(e),
                    ).model_dump(mode="json"),
                    status_code=500,
                )

        @self.app.get("/health")
        async def health_check() -> HealthStatus:
            """Gateway health check.

            Returns:
                Health status with container statuses
            """
            uptime = int(time.time() - self.start_time)
            container_statuses = self.client_pool.get_health_status()

            return HealthStatus(
                status="healthy",
                version=self.version,
                uptime=uptime,
                containers=container_statuses if container_statuses else None,
            )

        @self.app.get("/ready")
        async def readiness_check() -> ReadinessStatus:
            """Gateway readiness check.

            Returns:
                Readiness status (all containers healthy)
            """
            container_statuses = self.client_pool.get_health_status()
            healthy_count = sum(1 for status in container_statuses.values() if status == "healthy")
            total_count = len(container_statuses)

            return ReadinessStatus(
                ready=healthy_count == total_count and total_count > 0,
                containers_healthy=healthy_count,
                containers_total=total_count,
            )

    async def startup(self) -> None:
        """Gateway startup tasks."""
        logger.info(f"MCP Gateway starting on {self.host}:{self.port}")
        logger.info(f"Version: {self.version}")
        logger.info(f"Registered tools: {len(TOOL_ROUTES)}")

    async def shutdown(self) -> None:
        """Gateway shutdown tasks."""
        logger.info("MCP Gateway shutting down")
        await self.client_pool.close_all()


def create_gateway(
    host: str = "127.0.0.1",
    port: int = 8100,
    version: str = "0.1.0",
) -> MCPGateway:
    """Create MCP Gateway instance.

    Args:
        host: Host to bind to
        port: Port to listen on
        version: Gateway version

    Returns:
        MCPGateway instance
    """
    gateway = MCPGateway(host=host, port=port, version=version)

    # Register startup/shutdown handlers
    gateway.app.add_event_handler("startup", gateway.startup)
    gateway.app.add_event_handler("shutdown", gateway.shutdown)

    return gateway
