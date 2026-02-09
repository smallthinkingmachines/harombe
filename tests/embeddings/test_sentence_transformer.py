"""Tests for sentence-transformers embedding client."""

import pytest

from harombe.embeddings.sentence_transformer import SentenceTransformerEmbedding


@pytest.fixture
def embedding_client():
    """Create a sentence-transformers embedding client."""
    # Use a small model for testing
    return SentenceTransformerEmbedding(
        model_name="sentence-transformers/all-MiniLM-L6-v2",
        device="cpu",  # Force CPU for CI
    )


@pytest.mark.asyncio
async def test_embed_single_text(embedding_client):
    """Test embedding a single text."""
    text = "This is a test sentence."
    embedding = await embedding_client.embed_single(text)

    # Check that we get a valid embedding
    assert isinstance(embedding, list)
    assert len(embedding) == embedding_client.dimension
    assert all(isinstance(x, float) for x in embedding)


@pytest.mark.asyncio
async def test_embed_multiple_texts(embedding_client):
    """Test embedding multiple texts."""
    texts = [
        "This is the first sentence.",
        "This is the second sentence.",
        "And this is the third one.",
    ]
    embeddings = await embedding_client.embed(texts)

    # Check that we get correct number of embeddings
    assert len(embeddings) == len(texts)

    # Check that each embedding is valid
    for embedding in embeddings:
        assert isinstance(embedding, list)
        assert len(embedding) == embedding_client.dimension
        assert all(isinstance(x, float) for x in embedding)


@pytest.mark.asyncio
async def test_embed_empty_list(embedding_client):
    """Test embedding an empty list."""
    embeddings = await embedding_client.embed([])
    assert embeddings == []


@pytest.mark.asyncio
async def test_semantic_similarity(embedding_client):
    """Test that similar texts have similar embeddings."""
    import numpy as np

    texts = [
        "The cat sits on the mat.",
        "A feline is resting on a rug.",  # Similar meaning
        "Python is a programming language.",  # Different meaning
    ]
    embeddings = await embedding_client.embed(texts)

    # Convert to numpy for easier calculations
    emb1 = np.array(embeddings[0])
    emb2 = np.array(embeddings[1])
    emb3 = np.array(embeddings[2])

    # Cosine similarity
    def cosine_sim(a, b):
        return np.dot(a, b) / (np.linalg.norm(a) * np.linalg.norm(b))

    sim_1_2 = cosine_sim(emb1, emb2)  # Similar sentences
    sim_1_3 = cosine_sim(emb1, emb3)  # Different sentences

    # Similar sentences should have higher similarity
    assert sim_1_2 > sim_1_3
    assert sim_1_2 > 0.5  # Reasonably similar


@pytest.mark.asyncio
async def test_dimension_property(embedding_client):
    """Test that dimension property returns correct value."""
    # all-MiniLM-L6-v2 has 384 dimensions
    assert embedding_client.dimension == 384


@pytest.mark.asyncio
async def test_model_name_property(embedding_client):
    """Test that model_name property returns correct value."""
    assert embedding_client.model_name == "sentence-transformers/all-MiniLM-L6-v2"


@pytest.mark.asyncio
async def test_lazy_loading(embedding_client):
    """Test that model is loaded lazily."""
    # Before first use, model should not be loaded
    assert embedding_client._model is None

    # After first use, model should be loaded
    await embedding_client.embed_single("Test")
    assert embedding_client._model is not None


@pytest.mark.asyncio
async def test_consistent_embeddings(embedding_client):
    """Test that same text produces consistent embeddings."""
    text = "Consistency test"

    embedding1 = await embedding_client.embed_single(text)
    embedding2 = await embedding_client.embed_single(text)

    # Embeddings should be identical (or very close due to floating point)
    import numpy as np

    np.testing.assert_allclose(embedding1, embedding2, rtol=1e-5)


@pytest.mark.asyncio
async def test_batch_vs_single_consistency(embedding_client):
    """Test that batch and single embedding give same results."""
    text = "Test sentence"

    single_embedding = await embedding_client.embed_single(text)
    batch_embeddings = await embedding_client.embed([text])

    # Should be identical
    import numpy as np

    np.testing.assert_allclose(single_embedding, batch_embeddings[0], rtol=1e-5)
