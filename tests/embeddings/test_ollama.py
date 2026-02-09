"""Tests for Ollama embedding client."""

import pytest
import respx
from httpx import Response

from harombe.embeddings.ollama import OllamaEmbedding


@pytest.fixture
def mock_ollama():
    """Mock Ollama API responses."""
    with respx.mock:
        yield


@pytest.fixture
def embedding_client():
    """Create an Ollama embedding client."""
    return OllamaEmbedding(
        model="nomic-embed-text",
        host="http://localhost:11434",
        timeout=30,
    )


@pytest.mark.asyncio
async def test_embed_single_text(mock_ollama, embedding_client):
    """Test embedding a single text."""
    # Mock response
    mock_embedding = [0.1] * 768
    respx.post("http://localhost:11434/api/embeddings").mock(
        return_value=Response(
            200,
            json={"embedding": mock_embedding},
        )
    )

    text = "This is a test sentence."
    embedding = await embedding_client.embed_single(text)

    # Check that we get the mocked embedding
    assert isinstance(embedding, list)
    assert len(embedding) == 768
    assert embedding == mock_embedding


@pytest.mark.asyncio
async def test_embed_multiple_texts(mock_ollama, embedding_client):
    """Test embedding multiple texts."""
    # Mock responses for each text
    mock_embedding = [0.1] * 768
    respx.post("http://localhost:11434/api/embeddings").mock(
        return_value=Response(
            200,
            json={"embedding": mock_embedding},
        )
    )

    texts = [
        "This is the first sentence.",
        "This is the second sentence.",
    ]
    embeddings = await embedding_client.embed(texts)

    # Check that we get correct number of embeddings
    assert len(embeddings) == len(texts)
    assert all(len(emb) == 768 for emb in embeddings)


@pytest.mark.asyncio
async def test_embed_empty_list(embedding_client):
    """Test embedding an empty list."""
    embeddings = await embedding_client.embed([])
    assert embeddings == []


@pytest.mark.asyncio
async def test_dimension_property(embedding_client):
    """Test that dimension property returns correct value for nomic-embed-text."""
    # nomic-embed-text has 768 dimensions
    assert embedding_client.dimension == 768


@pytest.mark.asyncio
async def test_model_name_property(embedding_client):
    """Test that model_name property returns correct value."""
    assert embedding_client.model_name == "nomic-embed-text"


@pytest.mark.asyncio
async def test_dimension_caching(mock_ollama, embedding_client):
    """Test that dimension is cached after first embedding."""
    # Mock response
    mock_embedding = [0.1] * 768
    respx.post("http://localhost:11434/api/embeddings").mock(
        return_value=Response(
            200,
            json={"embedding": mock_embedding},
        )
    )

    # Before first embedding, dimension is from model knowledge
    assert embedding_client._dimension is None

    # After first embedding, dimension is cached
    await embedding_client.embed_single("Test")
    assert embedding_client._dimension == 768


@pytest.mark.asyncio
async def test_error_handling(mock_ollama, embedding_client):
    """Test that HTTP errors are properly raised."""
    # Mock error response
    respx.post("http://localhost:11434/api/embeddings").mock(
        return_value=Response(500, text="Internal Server Error")
    )

    from httpx import HTTPStatusError

    with pytest.raises(HTTPStatusError):
        await embedding_client.embed_single("Test")


@pytest.mark.asyncio
async def test_custom_model():
    """Test using a custom Ollama model."""
    client = OllamaEmbedding(model="custom-embed-model")
    assert client.model_name == "custom-embed-model"


@pytest.mark.asyncio
async def test_custom_host():
    """Test using a custom Ollama host."""
    client = OllamaEmbedding(host="http://example.com:8080")
    assert client._host == "http://example.com:8080"


@pytest.mark.asyncio
async def test_host_trailing_slash():
    """Test that trailing slash is stripped from host."""
    client = OllamaEmbedding(host="http://localhost:11434/")
    assert client._host == "http://localhost:11434"
