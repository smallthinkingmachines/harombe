"""API routes for Harombe server."""

import asyncio
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from sse_starlette.sse import EventSourceResponse

from harombe.agent.loop import Agent
from harombe.config.schema import HarombeConfig
from harombe.llm.client import Message, ToolCall
from harombe.llm.ollama import OllamaClient
from harombe.tools.registry import get_enabled_tools

# Import tools to register them
import harombe.tools.shell
import harombe.tools.filesystem
import harombe.tools.web_search


class ChatRequest(BaseModel):
    """Request body for chat endpoint."""

    message: str
    stream: bool = False


class ChatResponse(BaseModel):
    """Response body for chat endpoint."""

    response: str


class HealthResponse(BaseModel):
    """Health check response."""

    status: str
    model: str
    version: str


class CompletionRequest(BaseModel):
    """Request body for completion endpoint (used by RemoteLLMClient)."""

    messages: List[Dict[str, Any]]
    tools: Optional[List[Dict[str, Any]]] = None
    temperature: float = 0.7


class CompletionResponse(BaseModel):
    """Response body for completion endpoint."""

    content: str
    tool_calls: Optional[List[Dict[str, Any]]] = None


def create_router(config: HarombeConfig) -> APIRouter:
    """Create API router with configured agent.

    Args:
        config: Harombe configuration

    Returns:
        Configured API router
    """
    router = APIRouter()

    # Initialize LLM client
    llm = OllamaClient(
        model=config.model.name,
        base_url=config.ollama.host + "/v1",
        timeout=config.ollama.timeout,
        temperature=config.model.temperature,
    )

    # Get enabled tools
    tools = get_enabled_tools(
        shell=config.tools.shell,
        filesystem=config.tools.filesystem,
        web_search=config.tools.web_search,
    )

    # Create agent (no dangerous tool confirmation in server mode)
    agent = Agent(
        llm=llm,
        tools=tools,
        max_steps=config.agent.max_steps,
        system_prompt=config.agent.system_prompt,
        confirm_dangerous=False,  # Auto-approve in server mode
    )

    @router.get("/health", response_model=HealthResponse)
    async def health():
        """Health check endpoint."""
        from harombe import __version__

        return HealthResponse(
            status="healthy",
            model=config.model.name,
            version=__version__,
        )

    @router.post("/chat", response_model=ChatResponse)
    async def chat(request: ChatRequest):
        """Chat endpoint - non-streaming version.

        Args:
            request: Chat request with message

        Returns:
            Chat response
        """
        try:
            response = await agent.run(request.message)
            return ChatResponse(response=response)
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @router.post("/chat/stream")
    async def chat_stream(request: ChatRequest):
        """Chat endpoint - Server-Sent Events streaming version.

        Args:
            request: Chat request with message

        Returns:
            SSE stream of response chunks
        """

        async def event_generator():
            """Generate SSE events."""
            try:
                # For now, just run normally and yield the full response
                # TODO: Implement true streaming with token-by-token output
                response = await agent.run(request.message)

                # Yield response as single event for now
                yield {
                    "event": "message",
                    "data": response,
                }

                yield {
                    "event": "done",
                    "data": "",
                }

            except Exception as e:
                yield {
                    "event": "error",
                    "data": str(e),
                }

        return EventSourceResponse(event_generator())

    @router.post("/api/complete", response_model=CompletionResponse)
    async def complete(request: CompletionRequest):
        """
        Completion endpoint for remote LLM clients.

        This is used by RemoteLLMClient to proxy requests to this node.
        Implements the same interface as the LLM client protocol.

        Args:
            request: Completion request with messages and tools

        Returns:
            Completion response
        """
        try:
            # Convert request messages to Message objects
            messages = [Message(**msg) for msg in request.messages]

            # Convert tools if provided
            tools_schemas = None
            if request.tools:
                from harombe.tools.base import ToolSchema
                tools_schemas = []
                for tool_def in request.tools:
                    func = tool_def["function"]
                    tools_schemas.append(
                        ToolSchema(
                            name=func["name"],
                            description=func["description"],
                            parameters=func["parameters"]["properties"],
                            dangerous=False,  # Remote calls don't check dangerous flag
                        )
                    )

            # Call LLM
            response = await llm.complete(
                messages=messages,
                tools=tools_schemas,
                temperature=request.temperature,
            )

            # Convert tool calls to dict format
            tool_calls_dict = None
            if response.tool_calls:
                tool_calls_dict = [
                    {
                        "id": tc.id,
                        "name": tc.name,
                        "arguments": tc.arguments,
                    }
                    for tc in response.tool_calls
                ]

            return CompletionResponse(
                content=response.content,
                tool_calls=tool_calls_dict,
            )

        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    return router
