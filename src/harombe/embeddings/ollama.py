"""Ollama embedding client (local, via Ollama API)."""

import httpx


class OllamaEmbedding:
    """Embedding generation using Ollama's embedding models.

    Alternative to sentence-transformers that uses Ollama's API.
    Useful when Ollama is already running and you want consistency.
    """

    def __init__(
        self,
        model: str = "nomic-embed-text",
        host: str = "http://localhost:11434",
        timeout: int = 30,
    ):
        """Initialize Ollama embedding client.

        Args:
            model: Ollama model name (e.g., "nomic-embed-text")
            host: Ollama server URL
            timeout: Request timeout in seconds
        """
        self._model = model
        self._host = host.rstrip("/")
        self._timeout = timeout
        self._dimension: int | None = None

    async def embed(self, texts: list[str]) -> list[list[float]]:
        """Generate embeddings for a list of texts.

        Args:
            texts: List of text strings to embed

        Returns:
            List of embedding vectors
        """
        if not texts:
            return []

        async with httpx.AsyncClient(timeout=self._timeout) as client:
            embeddings = []
            for text in texts:
                response = await client.post(
                    f"{self._host}/api/embeddings",
                    json={"model": self._model, "prompt": text},
                )
                response.raise_for_status()
                data = response.json()
                embedding = data["embedding"]
                embeddings.append(embedding)

                # Cache dimension from first response
                if self._dimension is None:
                    self._dimension = len(embedding)

            return embeddings

    async def embed_single(self, text: str) -> list[float]:
        """Generate embedding for a single text.

        Args:
            text: Text string to embed

        Returns:
            Embedding vector
        """
        embeddings = await self.embed([text])
        return embeddings[0]

    @property
    def dimension(self) -> int:
        """Get the dimension of the embedding vectors."""
        if self._dimension is None:
            # For nomic-embed-text, dimension is 768
            # For other models, we'd need to query or embed once
            if "nomic-embed-text" in self._model:
                return 768
            msg = "Dimension unknown until first embedding is generated"
            raise ValueError(msg)
        return self._dimension

    @property
    def model_name(self) -> str:
        """Get the name of the embedding model."""
        return self._model
