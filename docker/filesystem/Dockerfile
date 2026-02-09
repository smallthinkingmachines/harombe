FROM python:3.12-slim

LABEL org.opencontainers.image.title="Harombe Filesystem MCP Server"
LABEL org.opencontainers.image.description="File operations capability container"
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
    aiofiles>=23.0

# Create workspace directories
RUN mkdir -p /workspace /projects

# Create non-root user
RUN useradd -m -u 1000 harombe && \
    chown -R harombe:harombe /app /workspace /projects

USER harombe

# Expose MCP server port
EXPOSE 3001

# Health check
HEALTHCHECK --interval=10s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:3001/health || exit 1

# Run filesystem MCP server (placeholder - will be implemented in Phase 4.6)
CMD ["sh", "-c", "echo 'Filesystem MCP server starting on port ${MCP_PORT:-3001}...' && echo 'Note: Filesystem server implementation pending (Phase 4.6)' && python3 -m http.server ${MCP_PORT:-3001}"]
