"""Abstract vector store interface."""

from typing import Any, Protocol


class VectorStore(Protocol):
    """Protocol for vector store implementations."""

    def add(
        self,
        ids: list[str],
        embeddings: list[list[float]],
        documents: list[str],
        metadata: list[dict[str, Any]],
    ) -> None:
        """Add embeddings to the vector store.

        Args:
            ids: Unique identifiers for each embedding
            embeddings: List of embedding vectors
            documents: Original text documents
            metadata: Metadata for each document
        """
        ...

    def search(
        self,
        query_embedding: list[float],
        top_k: int = 10,
        where: dict[str, Any] | None = None,
    ) -> tuple[list[str], list[str], list[dict[str, Any]], list[float]]:
        """Search for similar embeddings.

        Args:
            query_embedding: Query vector
            top_k: Number of results to return
            where: Optional metadata filters

        Returns:
            Tuple of (ids, documents, metadatas, distances)
        """
        ...

    def delete(self, ids: list[str]) -> None:
        """Delete embeddings by ID.

        Args:
            ids: IDs to delete
        """
        ...

    def get(
        self,
        ids: list[str] | None = None,
        where: dict[str, Any] | None = None,
        limit: int | None = None,
    ) -> tuple[list[str], list[str], list[dict[str, Any]]]:
        """Get embeddings by ID or filter.

        Args:
            ids: Optional specific IDs to retrieve
            where: Optional metadata filters
            limit: Maximum number of results

        Returns:
            Tuple of (ids, documents, metadatas)
        """
        ...

    def count(self) -> int:
        """Get total number of embeddings in the store.

        Returns:
            Count of embeddings
        """
        ...

    def clear(self) -> None:
        """Clear all embeddings from the store."""
        ...
