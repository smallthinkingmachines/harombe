FROM python:3.12-slim

LABEL org.opencontainers.image.title="Harombe Browser MCP Server"
LABEL org.opencontainers.image.description="Browser automation capability container"
LABEL org.opencontainers.image.vendor="Harombe"

# Set working directory
WORKDIR /app

# Install system dependencies for browser automation
RUN apt-get update && apt-get install -y \
    chromium \
    chromium-driver \
    xvfb \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
RUN pip install --no-cache-dir \
    fastapi>=0.115 \
    uvicorn[standard]>=0.30 \
    selenium>=4.0 \
    pydantic>=2.7

# Copy MCP server implementation
COPY entrypoint.sh /app/
RUN chmod +x /app/entrypoint.sh

# Create non-root user
RUN useradd -m -u 1000 harombe && \
    chown -R harombe:harombe /app

USER harombe

# Expose MCP server port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=10s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:3000/health || exit 1

# Run browser MCP server with Xvfb
ENTRYPOINT ["/app/entrypoint.sh"]
