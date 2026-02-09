"""Sentence-transformers embedding client (local, privacy-first)."""

import asyncio
from typing import Any

import numpy as np  # type: ignore[import-not-found]


class SentenceTransformerEmbedding:
    """Local embedding generation using sentence-transformers.

    This is the default embedding backend for harombe, providing:
    - Fully local execution (no API calls)
    - Fast inference on CPU or GPU
    - High-quality embeddings for semantic search
    """

    def __init__(
        self,
        model_name: str = "sentence-transformers/all-MiniLM-L6-v2",
        device: str | None = None,
        cache_dir: str | None = None,
    ):
        """Initialize sentence-transformers client.

        Args:
            model_name: HuggingFace model identifier
            device: Device to run on ("cuda", "mps", "cpu", or None for auto)
            cache_dir: Directory to cache models (None uses default)
        """
        self._model_name = model_name
        self._device = device
        self._cache_dir = cache_dir
        self._model: Any = None
        self._dimension: int | None = None

    def _load_model(self) -> None:
        """Load the sentence-transformers model (lazy initialization)."""
        if self._model is not None:
            return

        try:
            from sentence_transformers import SentenceTransformer  # type: ignore[import-not-found]
        except ImportError as e:
            msg = (
                "sentence-transformers is required for local embeddings. "
                "Install with: pip install sentence-transformers"
            )
            raise ImportError(msg) from e

        # Load model
        self._model = SentenceTransformer(
            self._model_name,
            device=self._device,
            cache_folder=self._cache_dir,
        )

        # Get embedding dimension
        self._dimension = self._model.get_sentence_embedding_dimension()

    async def embed(self, texts: list[str]) -> list[list[float]]:
        """Generate embeddings for a list of texts.

        Args:
            texts: List of text strings to embed

        Returns:
            List of embedding vectors
        """
        if not texts:
            return []

        # Load model if not already loaded
        self._load_model()

        # Run embedding in thread pool (blocking call)
        loop = asyncio.get_event_loop()
        embeddings_raw = await loop.run_in_executor(
            None,
            self._model.encode,
            texts,
        )

        # Convert numpy arrays to lists
        if isinstance(embeddings_raw, np.ndarray):
            embeddings: list[list[float]] = embeddings_raw.tolist()
            return embeddings
        return [emb.tolist() if isinstance(emb, np.ndarray) else emb for emb in embeddings_raw]

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
            self._load_model()
        return self._dimension  # type: ignore[return-value]

    @property
    def model_name(self) -> str:
        """Get the name of the embedding model."""
        return self._model_name
