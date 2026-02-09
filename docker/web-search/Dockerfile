FROM python:3.12-slim

LABEL org.opencontainers.image.title="Harombe Web Search MCP Server"
LABEL org.opencontainers.image.description="Web search capability container"
LABEL org.opencontainers.image.vendor="Harombe"

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
RUN pip install --no-cache-dir \
    fastapi>=0.115 \
    uvicorn[standard]>=0.30 \
    pydantic>=2.7 \
    duckduckgo-search>=6.0 \
    httpx>=0.27

# Create non-root user
RUN useradd -m -u 1000 harombe && \
    chown -R harombe:harombe /app

USER harombe

# Expose MCP server port
EXPOSE 3003

# Health check
HEALTHCHECK --interval=10s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:3003/health || exit 1

# Run web search MCP server (placeholder - will be implemented in Phase 4.6)
CMD ["sh", "-c", "echo 'Web Search MCP server starting on port ${MCP_PORT:-3003}...' && echo 'Note: Web search server implementation pending (Phase 4.6)' && python3 -m http.server ${MCP_PORT:-3003}"]
