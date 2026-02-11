# --- Builder stage ---
FROM python:3.12-slim AS builder

WORKDIR /build
COPY pyproject.toml README.md ./
COPY src/ src/

RUN pip install --no-cache-dir build \
    && python -m build --wheel \
    && pip install --no-cache-dir dist/*.whl

# --- Runtime stage ---
FROM python:3.12-slim

RUN groupadd --gid 1000 harombe \
    && useradd --uid 1000 --gid harombe --create-home harombe

COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin/harombe /usr/local/bin/harombe

USER harombe
WORKDIR /home/harombe

EXPOSE 8000

ENTRYPOINT ["harombe"]
CMD ["start", "--config", "/home/harombe/harombe.yaml"]
