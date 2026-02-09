"""Tests for Piper TTS implementation.

Note: These tests require piper-tts to be installed and will download
models on first run. They can be slow on first execution.

Piper tests are marked to skip if piper is not available.
"""

import pytest

# Try to import piper, skip all tests if not available
piper_available = True
model_available = True
try:
    import piper.voice  # type: ignore[import-not-found] # noqa: F401

    from harombe.voice.piper import PiperTTS, create_piper_tts

    # Try to load the test model to check if it's available
    try:
        test_tts = PiperTTS(model="en_US-lessac-medium", device="cpu")
        # Try to access the voice to trigger model download/loading
        test_tts._get_piper()
    except Exception:
        model_available = False
except ImportError:
    piper_available = False
    PiperTTS = None  # type: ignore[misc,assignment]
    create_piper_tts = None  # type: ignore[misc,assignment]

pytestmark = pytest.mark.skipif(
    not piper_available or not model_available,
    reason="piper-tts not installed or model not available",
)


def test_piper_initialization():
    """Test Piper TTS initialization."""
    tts = PiperTTS(model="en_US-lessac-medium", device="cpu")

    assert tts._model_name == "en_US-lessac-medium"
    assert tts._device == "cpu"
    assert tts._piper_instance is None  # Lazy loading


def test_create_piper_tts():
    """Test factory function."""
    tts = create_piper_tts(model="en_US-lessac-medium", device="cpu")

    assert isinstance(tts, PiperTTS)
    assert tts.engine_name == "piper-en_US-lessac-medium"


@pytest.mark.asyncio
async def test_synthesize_empty_text():
    """Test synthesis with empty text."""
    tts = PiperTTS(model="en_US-lessac-medium", device="cpu")

    # Empty text should return empty WAV
    audio = await tts.synthesize("", voice="default")

    assert isinstance(audio, bytes)
    assert len(audio) == 44  # WAV header only


@pytest.mark.asyncio
async def test_synthesize_simple_text():
    """Test synthesis with simple text."""
    tts = PiperTTS(model="en_US-lessac-medium", device="cpu")

    # Synthesize a short phrase
    audio = await tts.synthesize("Hello world", voice="default")

    assert isinstance(audio, bytes)
    assert len(audio) > 44  # Should have audio data after header

    # Check WAV header
    assert audio[:4] == b"RIFF"
    assert audio[8:12] == b"WAVE"


@pytest.mark.asyncio
async def test_synthesize_with_speed():
    """Test synthesis with different speeds."""
    tts = PiperTTS(model="en_US-lessac-medium", device="cpu")

    # Synthesize at different speeds
    normal = await tts.synthesize("Test", speed=1.0)
    fast = await tts.synthesize("Test", speed=1.5)
    slow = await tts.synthesize("Test", speed=0.5)

    # All should produce audio
    assert len(normal) > 44
    assert len(fast) > 44
    assert len(slow) > 44

    # Slow should be longer than fast (more audio data)
    assert len(slow) > len(fast)


@pytest.mark.asyncio
async def test_synthesize_stream():
    """Test streaming synthesis."""
    tts = PiperTTS(model="en_US-lessac-medium", device="cpu")

    chunks = []
    async for chunk in tts.synthesize_stream("Hello world"):
        chunks.append(chunk)

    # Should have received multiple chunks
    assert len(chunks) > 0

    # First chunk should be WAV header
    assert chunks[0][:4] == b"RIFF"

    # All chunks should be bytes
    for chunk in chunks:
        assert isinstance(chunk, bytes)


def test_properties():
    """Test TTS properties."""
    tts = PiperTTS(model="en_US-lessac-medium", device="cpu")

    # Properties should be accessible
    assert isinstance(tts.engine_name, str)
    assert "piper" in tts.engine_name.lower()

    assert isinstance(tts.sample_rate, int)
    assert tts.sample_rate > 0

    # Available voices should return the model
    voices = tts.available_voices
    assert isinstance(voices, list)
    assert len(voices) > 0


def test_different_devices():
    """Test that different devices can be specified."""
    tts_cpu = PiperTTS(model="en_US-lessac-medium", device="cpu")
    assert tts_cpu._device == "cpu"

    tts_cuda = PiperTTS(model="en_US-lessac-medium", device="cuda")
    assert tts_cuda._device == "cuda"


@pytest.mark.asyncio
async def test_multiple_synthesize_calls():
    """Test that multiple synthesis calls work."""
    tts = PiperTTS(model="en_US-lessac-medium", device="cpu")

    # First call loads model
    audio1 = await tts.synthesize("First")
    assert len(audio1) > 44

    # Second call reuses loaded model
    audio2 = await tts.synthesize("Second")
    assert len(audio2) > 44

    # Third call
    audio3 = await tts.synthesize("Third")
    assert len(audio3) > 44
