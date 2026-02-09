FROM python:3.12-slim

LABEL org.opencontainers.image.title="Harombe Code Execution MCP Server"
LABEL org.opencontainers.image.description="Sandboxed code execution capability container"
LABEL org.opencontainers.image.vendor="Harombe"

# Set working directory
WORKDIR /app

# Install system dependencies and language runtimes
RUN apt-get update && apt-get install -y \
    curl \
    nodejs \
    npm \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
RUN pip install --no-cache-dir \
    fastapi>=0.115 \
    uvicorn[standard]>=0.30 \
    pydantic>=2.7

# Create sandbox directory
RUN mkdir -p /sandbox && chmod 755 /sandbox

# Create non-root user
RUN useradd -m -u 1000 harombe && \
    chown -R harombe:harombe /app /sandbox

USER harombe

# Expose MCP server port
EXPOSE 3002

# Health check
HEALTHCHECK --interval=10s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:3002/health || exit 1

# Run code execution MCP server (placeholder - will be implemented in Phase 4.7)
CMD ["sh", "-c", "echo 'Code Execution MCP server starting on port ${MCP_PORT:-3002}...' && echo 'Note: Code execution server implementation pending (Phase 4.7)' && python3 -m http.server ${MCP_PORT:-3002}"]
