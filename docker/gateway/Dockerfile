FROM python:3.12-slim

LABEL org.opencontainers.image.title="Harombe MCP Gateway"
LABEL org.opencontainers.image.description="Central security enforcement point for MCP tool execution"
LABEL org.opencontainers.image.vendor="Harombe"

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/

# Install harombe with docker support
RUN pip install --no-cache-dir -e ".[docker]"

# Create non-root user
RUN useradd -m -u 1000 harombe && \
    chown -R harombe:harombe /app

USER harombe

# Expose gateway port
EXPOSE 8100

# Health check
HEALTHCHECK --interval=10s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8100/health || exit 1

# Run gateway server
CMD ["python", "-m", "harombe.security.gateway"]
