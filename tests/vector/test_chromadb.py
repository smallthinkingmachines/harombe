"""Tests for ChromaDB vector store."""

import tempfile

import pytest

try:
    import chromadb  # noqa: F401

    from harombe.vector.chromadb import ChromaDBVectorStore
except Exception:
    pytest.skip(
        "chromadb not compatible with this Python version",
        allow_module_level=True,
    )


@pytest.fixture
def vector_store():
    """Create an in-memory ChromaDB vector store for testing."""
    import uuid

    # Use unique collection name for test isolation
    collection_name = f"test_collection_{uuid.uuid4().hex[:8]}"
    return ChromaDBVectorStore(collection_name=collection_name)


@pytest.fixture
def persistent_vector_store():
    """Create a persistent ChromaDB vector store for testing."""
    import uuid

    with tempfile.TemporaryDirectory() as tmpdir:
        collection_name = f"test_persistent_{uuid.uuid4().hex[:8]}"
        yield ChromaDBVectorStore(
            collection_name=collection_name,
            persist_directory=tmpdir,
        )


def test_add_embeddings(vector_store):
    """Test adding embeddings to the store."""
    ids = ["doc1", "doc2", "doc3"]
    embeddings = [
        [0.1, 0.2, 0.3],
        [0.4, 0.5, 0.6],
        [0.7, 0.8, 0.9],
    ]
    documents = ["First document", "Second document", "Third document"]
    metadata = [
        {"session_id": "s1", "role": "user"},
        {"session_id": "s1", "role": "assistant"},
        {"session_id": "s2", "role": "user"},
    ]

    vector_store.add(ids, embeddings, documents, metadata)

    # Verify count
    assert vector_store.count() == 3


def test_add_empty(vector_store):
    """Test that adding empty list doesn't error."""
    vector_store.add([], [], [], [])
    assert vector_store.count() == 0


def test_search_similar(vector_store):
    """Test semantic search."""
    # Add some embeddings
    ids = ["doc1", "doc2", "doc3"]
    embeddings = [
        [1.0, 0.0, 0.0],  # Vector pointing in x direction
        [0.9, 0.1, 0.0],  # Similar to doc1
        [0.0, 1.0, 0.0],  # Orthogonal (different)
    ]
    documents = ["Document one", "Document two", "Document three"]
    metadata = [{"type": "test"} for _ in range(3)]

    vector_store.add(ids, embeddings, documents, metadata)

    # Search with vector similar to doc1
    query = [0.95, 0.05, 0.0]
    result_ids, result_docs, result_meta, distances = vector_store.search(
        query_embedding=query,
        top_k=2,
    )

    # Should return doc2 and doc1 as most similar
    assert len(result_ids) == 2
    assert "doc1" in result_ids or "doc2" in result_ids
    assert len(result_docs) == 2
    assert len(result_meta) == 2
    assert len(distances) == 2


def test_search_with_filter(vector_store):
    """Test search with metadata filtering."""
    ids = ["doc1", "doc2", "doc3"]
    embeddings = [[0.1, 0.2, 0.3] for _ in range(3)]
    documents = ["Doc 1", "Doc 2", "Doc 3"]
    metadata = [
        {"role": "user"},
        {"role": "assistant"},
        {"role": "user"},
    ]

    vector_store.add(ids, embeddings, documents, metadata)

    # Search only for user messages
    query = [0.1, 0.2, 0.3]
    result_ids, _, _, _ = vector_store.search(
        query_embedding=query,
        top_k=10,
        where={"role": "user"},
    )

    # Should only return user messages
    assert len(result_ids) == 2
    assert "doc1" in result_ids
    assert "doc3" in result_ids


def test_delete_embeddings(vector_store):
    """Test deleting embeddings."""
    ids = ["doc1", "doc2", "doc3"]
    embeddings = [[0.1, 0.2, 0.3] for _ in range(3)]
    documents = ["Doc 1", "Doc 2", "Doc 3"]
    metadata = [{"id": i} for i in range(3)]

    vector_store.add(ids, embeddings, documents, metadata)
    assert vector_store.count() == 3

    # Delete one embedding
    vector_store.delete(["doc2"])
    assert vector_store.count() == 2

    # Verify doc2 is gone
    result_ids, _, _ = vector_store.get(ids=["doc1", "doc2", "doc3"])
    assert "doc1" in result_ids
    assert "doc2" not in result_ids
    assert "doc3" in result_ids


def test_delete_empty(vector_store):
    """Test that deleting empty list doesn't error."""
    vector_store.delete([])
    assert vector_store.count() == 0


def test_get_by_ids(vector_store):
    """Test retrieving embeddings by ID."""
    ids = ["doc1", "doc2", "doc3"]
    embeddings = [[0.1, 0.2, 0.3] for _ in range(3)]
    documents = ["Doc 1", "Doc 2", "Doc 3"]
    metadata = [{"id": i} for i in range(3)]

    vector_store.add(ids, embeddings, documents, metadata)

    # Get specific IDs
    result_ids, result_docs, _result_meta = vector_store.get(ids=["doc1", "doc3"])

    assert len(result_ids) == 2
    assert "doc1" in result_ids
    assert "doc3" in result_ids
    assert "Doc 1" in result_docs
    assert "Doc 3" in result_docs


def test_get_with_filter(vector_store):
    """Test retrieving embeddings with metadata filter."""
    ids = ["doc1", "doc2", "doc3"]
    embeddings = [[0.1, 0.2, 0.3] for _ in range(3)]
    documents = ["Doc 1", "Doc 2", "Doc 3"]
    metadata = [
        {"category": "A"},
        {"category": "B"},
        {"category": "A"},
    ]

    vector_store.add(ids, embeddings, documents, metadata)

    # Get by category
    result_ids, _, result_meta = vector_store.get(where={"category": "A"})

    assert len(result_ids) == 2
    assert all(m["category"] == "A" for m in result_meta)


def test_get_with_limit(vector_store):
    """Test retrieving embeddings with limit."""
    ids = [f"doc{i}" for i in range(10)]
    embeddings = [[0.1, 0.2, 0.3] for _ in range(10)]
    documents = [f"Doc {i}" for i in range(10)]
    metadata = [{"id": i} for i in range(10)]

    vector_store.add(ids, embeddings, documents, metadata)

    # Get with limit
    result_ids, _, _ = vector_store.get(limit=5)

    assert len(result_ids) == 5


def test_count(vector_store):
    """Test counting embeddings."""
    assert vector_store.count() == 0

    # Add embeddings
    ids = ["doc1", "doc2"]
    embeddings = [[0.1, 0.2, 0.3], [0.4, 0.5, 0.6]]
    documents = ["Doc 1", "Doc 2"]
    metadata = [{"id": "doc1"}, {"id": "doc2"}]  # Non-empty metadata

    vector_store.add(ids, embeddings, documents, metadata)
    assert vector_store.count() == 2


def test_clear(vector_store):
    """Test clearing all embeddings."""
    # Add some data
    ids = ["doc1", "doc2", "doc3"]
    embeddings = [[0.1, 0.2, 0.3] for _ in range(3)]
    documents = ["Doc 1", "Doc 2", "Doc 3"]
    metadata = [{"idx": i} for i in range(3)]  # Non-empty metadata

    vector_store.add(ids, embeddings, documents, metadata)
    assert vector_store.count() == 3

    # Clear
    vector_store.clear()
    assert vector_store.count() == 0


def test_update_embeddings(vector_store):
    """Test updating embeddings."""
    # Add initial data
    ids = ["doc1", "doc2"]
    embeddings = [[0.1, 0.2, 0.3], [0.4, 0.5, 0.6]]
    documents = ["Original 1", "Original 2"]
    metadata = [{"version": 1}, {"version": 1}]

    vector_store.add(ids, embeddings, documents, metadata)

    # Update documents and metadata (with matching embedding dimension)
    vector_store.update(
        ids=["doc1"],
        embeddings=[[0.2, 0.3, 0.4]],  # Same dimension as original
        documents=["Updated 1"],
        metadata=[{"version": 2}],
    )

    # Verify update
    _result_ids, result_docs, result_meta = vector_store.get(ids=["doc1"])
    assert result_docs[0] == "Updated 1"
    assert result_meta[0]["version"] == 2


def test_persistent_storage(persistent_vector_store):
    """Test that data persists to disk."""
    # Add data
    ids = ["doc1", "doc2"]
    embeddings = [[0.1, 0.2, 0.3], [0.4, 0.5, 0.6]]
    documents = ["Doc 1", "Doc 2"]
    metadata = [{"id": "doc1"}, {"id": "doc2"}]  # Non-empty metadata

    persistent_vector_store.add(ids, embeddings, documents, metadata)
    assert persistent_vector_store.count() == 2


def test_duplicate_ids_update(vector_store):
    """Test that updating existing IDs works via update method."""
    # Add initial
    vector_store.add(
        ids=["doc1"],
        embeddings=[[0.1, 0.2, 0.3]],
        documents=["First version"],
        metadata=[{"version": 1}],
    )

    # Use update method for same ID
    vector_store.update(
        ids=["doc1"],
        embeddings=[[0.4, 0.5, 0.6]],
        documents=["Second version"],
        metadata=[{"version": 2}],
    )

    # Should still have only one entry
    assert vector_store.count() == 1

    # Should have the updated version
    _, docs, meta = vector_store.get(ids=["doc1"])
    assert docs[0] == "Second version"
    assert meta[0]["version"] == 2


def test_search_empty_store(vector_store):
    """Test searching an empty store."""
    query = [0.1, 0.2, 0.3]
    result_ids, result_docs, result_meta, distances = vector_store.search(
        query_embedding=query,
        top_k=5,
    )

    assert len(result_ids) == 0
    assert len(result_docs) == 0
    assert len(result_meta) == 0
    assert len(distances) == 0
