"""Tests for Coqui TTS implementation.

Note: These tests require TTS (Coqui) to be installed and will download
models on first run. They can be slow on first execution.

Coqui tests are marked to skip if TTS is not available.
"""

import pytest

# Try to import TTS, skip all tests if not available
coqui_available = True
try:
    import TTS.api  # type: ignore[import-not-found] # noqa: F401

    from harombe.voice.coqui import CoquiTTS, create_coqui_tts
except ImportError:
    coqui_available = False
    CoquiTTS = None  # type: ignore[misc,assignment]
    create_coqui_tts = None  # type: ignore[misc,assignment]

pytestmark = pytest.mark.skipif(
    not coqui_available,
    reason="Coqui TTS not installed",
)


def test_coqui_initialization():
    """Test Coqui TTS initialization."""
    tts = CoquiTTS(
        model_name="tts_models/en/ljspeech/tacotron2-DDC",
        device="cpu",
    )

    assert tts._model_name == "tts_models/en/ljspeech/tacotron2-DDC"
    assert tts._device == "cpu"
    assert tts._tts is None  # Lazy loading


def test_create_coqui_tts():
    """Test factory function."""
    tts = create_coqui_tts(
        model_name="tts_models/en/ljspeech/tacotron2-DDC",
        device="cpu",
    )

    assert isinstance(tts, CoquiTTS)
    assert "coqui" in tts.engine_name.lower()


@pytest.mark.asyncio
async def test_synthesize_empty_text():
    """Test synthesis with empty text."""
    tts = CoquiTTS(
        model_name="tts_models/en/ljspeech/tacotron2-DDC",
        device="cpu",
    )

    # Empty text should return empty WAV
    audio = await tts.synthesize("", voice="default")

    assert isinstance(audio, bytes)
    assert len(audio) == 44  # WAV header only


@pytest.mark.asyncio
async def test_synthesize_simple_text():
    """Test synthesis with simple text."""
    tts = CoquiTTS(
        model_name="tts_models/en/ljspeech/tacotron2-DDC",
        device="cpu",
    )

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
    tts = CoquiTTS(
        model_name="tts_models/en/ljspeech/tacotron2-DDC",
        device="cpu",
    )

    # Synthesize at different speeds
    normal = await tts.synthesize("Test", speed=1.0)
    fast = await tts.synthesize("Test", speed=1.5)
    slow = await tts.synthesize("Test", speed=0.5)

    # All should produce audio
    assert len(normal) > 44
    assert len(fast) > 44
    assert len(slow) > 44

    # Slow should be longer than fast
    assert len(slow) > len(fast)


@pytest.mark.asyncio
async def test_synthesize_stream():
    """Test streaming synthesis."""
    tts = CoquiTTS(
        model_name="tts_models/en/ljspeech/tacotron2-DDC",
        device="cpu",
    )

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
    tts = CoquiTTS(
        model_name="tts_models/en/ljspeech/tacotron2-DDC",
        device="cpu",
    )

    # Properties should be accessible
    assert isinstance(tts.engine_name, str)
    assert "coqui" in tts.engine_name.lower()

    assert isinstance(tts.sample_rate, int)
    assert tts.sample_rate > 0


def test_different_devices():
    """Test that different devices can be specified."""
    tts_cpu = CoquiTTS(
        model_name="tts_models/en/ljspeech/tacotron2-DDC",
        device="cpu",
    )
    assert tts_cpu._device == "cpu"

    tts_cuda = CoquiTTS(
        model_name="tts_models/en/ljspeech/tacotron2-DDC",
        device="cuda",
    )
    assert tts_cuda._device == "cuda"


@pytest.mark.asyncio
async def test_multiple_synthesize_calls():
    """Test that multiple synthesis calls work."""
    tts = CoquiTTS(
        model_name="tts_models/en/ljspeech/tacotron2-DDC",
        device="cpu",
    )

    # First call loads model
    audio1 = await tts.synthesize("First")
    assert len(audio1) > 44

    # Second call reuses loaded model
    audio2 = await tts.synthesize("Second")
    assert len(audio2) > 44

    # Third call
    audio3 = await tts.synthesize("Third")
    assert len(audio3) > 44
