"""Abstract embedding client interface."""

from typing import Protocol


class EmbeddingClient(Protocol):
    """Protocol for embedding generation clients."""

    async def embed(self, texts: list[str]) -> list[list[float]]:
        """Generate embeddings for a list of texts.

        Args:
            texts: List of text strings to embed

        Returns:
            List of embedding vectors (one per input text)
        """
        ...

    async def embed_single(self, text: str) -> list[float]:
        """Generate embedding for a single text.

        Args:
            text: Text string to embed

        Returns:
            Embedding vector
        """
        ...

    @property
    def dimension(self) -> int:
        """Get the dimension of the embedding vectors.

        Returns:
            Embedding dimension
        """
        ...

    @property
    def model_name(self) -> str:
        """Get the name of the embedding model.

        Returns:
            Model name
        """
        ...
