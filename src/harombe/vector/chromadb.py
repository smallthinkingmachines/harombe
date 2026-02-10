"""ChromaDB vector store implementation."""

from pathlib import Path
from typing import Any

import chromadb


class ChromaDBVectorStore:
    """Vector store using ChromaDB for semantic search.

    ChromaDB is a lightweight, embedded vector database that works well
    for local deployments. It uses SQLite for persistence and HNSW for
    fast approximate nearest neighbor search.
    """

    def __init__(
        self,
        collection_name: str = "harombe_embeddings",
        persist_directory: str | Path | None = None,
    ):
        """Initialize ChromaDB vector store.

        Args:
            collection_name: Name of the ChromaDB collection
            persist_directory: Directory for persistent storage (None = in-memory)
        """
        self.collection_name = collection_name

        # Create client
        if persist_directory is None:
            # In-memory mode (for testing)
            self.client = chromadb.EphemeralClient()
        else:
            # Persistent mode
            persist_path = Path(persist_directory).expanduser().resolve()
            persist_path.mkdir(parents=True, exist_ok=True)

            self.client = chromadb.PersistentClient(path=str(persist_path))

        # Get or create collection
        self.collection = self.client.get_or_create_collection(
            name=collection_name,
            metadata={"hnsw:space": "cosine"},  # Cosine similarity for embeddings
        )

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
        if not ids:
            return

        self.collection.add(
            ids=ids,
            embeddings=embeddings,  # type: ignore[arg-type]
            documents=documents,
            metadatas=metadata,  # type: ignore[arg-type]
        )

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
        results = self.collection.query(
            query_embeddings=[query_embedding],  # type: ignore[arg-type]
            n_results=top_k,
            where=where,
        )

        # ChromaDB returns results in a batched format
        ids = results["ids"][0] if results["ids"] else []
        documents = results["documents"][0] if results["documents"] else []
        metadatas = results["metadatas"][0] if results["metadatas"] else []
        distances = results["distances"][0] if results["distances"] else []

        return ids, documents, metadatas, distances  # type: ignore[return-value]

    def delete(self, ids: list[str]) -> None:
        """Delete embeddings by ID.

        Args:
            ids: IDs to delete
        """
        if not ids:
            return

        self.collection.delete(ids=ids)

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
        results = self.collection.get(
            ids=ids,
            where=where,
            limit=limit,
        )

        ids_result = results["ids"] if results["ids"] else []
        documents = results["documents"] if results["documents"] else []
        metadatas = results["metadatas"] if results["metadatas"] else []

        return ids_result, documents, metadatas  # type: ignore[return-value]

    def count(self) -> int:
        """Get total number of embeddings in the store.

        Returns:
            Count of embeddings
        """
        count_result: int = self.collection.count()
        return count_result

    def clear(self) -> None:
        """Clear all embeddings from the store."""
        # Delete the collection and recreate it
        self.client.delete_collection(name=self.collection_name)
        self.collection = self.client.get_or_create_collection(
            name=self.collection_name,
            metadata={"hnsw:space": "cosine"},
        )

    def update(
        self,
        ids: list[str],
        embeddings: list[list[float]] | None = None,
        documents: list[str] | None = None,
        metadata: list[dict[str, Any]] | None = None,
    ) -> None:
        """Update existing embeddings.

        Args:
            ids: IDs to update
            embeddings: New embeddings (optional)
            documents: New documents (optional)
            metadata: New metadata (optional)
        """
        if not ids:
            return

        self.collection.update(
            ids=ids,
            embeddings=embeddings,  # type: ignore[arg-type]
            documents=documents,
            metadatas=metadata,  # type: ignore[arg-type]
        )
