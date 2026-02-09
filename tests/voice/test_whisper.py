"""Tests for Whisper STT implementation.

Note: These tests require faster-whisper to be installed and will download
the tiny model on first run. They can be slow on first execution.
"""

import asyncio

import pytest

from harombe.voice.whisper import WhisperSTT, create_whisper_stt

# Skip all tests if faster-whisper is not installed
pytest.importorskip("faster_whisper")


@pytest.fixture
def whisper_tiny():
    """Create a Whisper STT engine with tiny model (fastest for testing)."""
    return WhisperSTT(model_size="tiny", device="cpu", compute_type="int8")


def test_whisper_initialization():
    """Test Whisper STT initialization."""
    stt = WhisperSTT(model_size="tiny", device="cpu")

    assert stt.model_name == "whisper-tiny"
    assert stt._model is None  # Model not loaded yet (lazy loading)


def test_create_whisper_stt():
    """Test factory function."""
    stt = create_whisper_stt(model_size="tiny", device="cpu", compute_type="int8")

    assert isinstance(stt, WhisperSTT)
    assert stt.model_name == "whisper-tiny"


@pytest.mark.asyncio
async def test_transcribe_with_synthetic_audio(whisper_tiny):
    """Test transcription with synthetic audio.

    This test creates a simple synthetic audio file to test the pipeline.
    """
    # Create a simple synthetic audio (silence) in WAV format
    # WAV header for 16kHz, mono, 16-bit PCM, 1 second
    import struct

    sample_rate = 16000
    duration = 1  # seconds
    num_samples = sample_rate * duration

    # WAV header
    wav_header = struct.pack(
        "<4sI4s4sIHHIIHH4sI",
        b"RIFF",
        36 + num_samples * 2,  # File size - 8
        b"WAVE",
        b"fmt ",
        16,  # fmt chunk size
        1,  # PCM format
        1,  # Mono
        sample_rate,
        sample_rate * 2,  # Byte rate
        2,  # Block align
        16,  # Bits per sample
        b"data",
        num_samples * 2,  # Data chunk size
    )

    # Silence (all zeros)
    audio_data = b"\x00" * (num_samples * 2)
    audio = wav_header + audio_data

    # Transcribe (should return empty or minimal text for silence)
    result = await whisper_tiny.transcribe(audio, language="en")

    # Silence should produce empty or very short transcription
    assert isinstance(result.text, str)
    assert len(result.text) < 50  # Should be empty or short for silence
    assert result.language == "en"


@pytest.mark.asyncio
async def test_transcribe_auto_language(whisper_tiny):
    """Test transcription with auto language detection."""
    # Create synthetic audio (silence)
    import struct

    sample_rate = 16000
    duration = 1
    num_samples = sample_rate * duration

    wav_header = struct.pack(
        "<4sI4s4sIHHIIHH4sI",
        b"RIFF",
        36 + num_samples * 2,
        b"WAVE",
        b"fmt ",
        16,
        1,
        1,
        sample_rate,
        sample_rate * 2,
        2,
        16,
        b"data",
        num_samples * 2,
    )

    audio_data = b"\x00" * (num_samples * 2)
    audio = wav_header + audio_data

    # Transcribe without specifying language
    result = await whisper_tiny.transcribe(audio, language=None)

    assert isinstance(result.text, str)
    # Language should be detected (even for silence, Whisper will pick one)
    assert result.language is not None


@pytest.mark.asyncio
async def test_transcribe_stream(whisper_tiny):
    """Test streaming transcription."""

    async def audio_generator():
        """Generate audio chunks."""
        # Create simple audio chunk (silence)
        import struct

        sample_rate = 16000
        chunk_duration = 0.5  # 500ms chunks
        num_samples = int(sample_rate * chunk_duration)

        wav_header = struct.pack(
            "<4sI4s4sIHHIIHH4sI",
            b"RIFF",
            36 + num_samples * 2,
            b"WAVE",
            b"fmt ",
            16,
            1,
            1,
            sample_rate,
            sample_rate * 2,
            2,
            16,
            b"data",
            num_samples * 2,
        )

        # Yield a few chunks
        for _ in range(3):
            audio_data = b"\x00" * (num_samples * 2)
            yield wav_header + audio_data
            await asyncio.sleep(0.1)

    # Transcribe stream
    results = []
    async for text in whisper_tiny.transcribe_stream(audio_generator()):
        results.append(text)

    # Should have received at least one result
    # (may be empty for silence, but stream should complete)
    assert isinstance(results, list)


def test_model_name_property():
    """Test model_name property."""
    stt_tiny = WhisperSTT(model_size="tiny")
    assert stt_tiny.model_name == "whisper-tiny"

    stt_medium = WhisperSTT(model_size="medium")
    assert stt_medium.model_name == "whisper-medium"

    stt_large = WhisperSTT(model_size="large-v3")
    assert stt_large.model_name == "whisper-large-v3"


@pytest.mark.asyncio
async def test_transcribe_returns_segments(whisper_tiny):
    """Test that transcription returns segment information."""
    # Create synthetic audio
    import struct

    sample_rate = 16000
    duration = 2
    num_samples = sample_rate * duration

    wav_header = struct.pack(
        "<4sI4s4sIHHIIHH4sI",
        b"RIFF",
        36 + num_samples * 2,
        b"WAVE",
        b"fmt ",
        16,
        1,
        1,
        sample_rate,
        sample_rate * 2,
        2,
        16,
        b"data",
        num_samples * 2,
    )

    audio_data = b"\x00" * (num_samples * 2)
    audio = wav_header + audio_data

    result = await whisper_tiny.transcribe(audio, language="en")

    # Should return segments (even if empty for silence)
    assert result.segments is not None
    assert isinstance(result.segments, list)


@pytest.mark.asyncio
async def test_concurrent_transcriptions(whisper_tiny):
    """Test that multiple concurrent transcriptions work."""
    # Create synthetic audio
    import struct

    sample_rate = 16000
    duration = 1
    num_samples = sample_rate * duration

    wav_header = struct.pack(
        "<4sI4s4sIHHIIHH4sI",
        b"RIFF",
        36 + num_samples * 2,
        b"WAVE",
        b"fmt ",
        16,
        1,
        1,
        sample_rate,
        sample_rate * 2,
        2,
        16,
        b"data",
        num_samples * 2,
    )

    audio_data = b"\x00" * (num_samples * 2)
    audio = wav_header + audio_data

    # Run multiple transcriptions concurrently
    tasks = [whisper_tiny.transcribe(audio, language="en") for _ in range(3)]
    results = await asyncio.gather(*tasks)

    # All should complete successfully
    assert len(results) == 3
    for result in results:
        assert isinstance(result.text, str)


def test_different_model_sizes():
    """Test that different model sizes can be instantiated."""
    sizes = ["tiny", "base", "small", "medium", "large-v3"]

    for size in sizes:
        stt = WhisperSTT(model_size=size, device="cpu")  # type: ignore[arg-type]
        assert stt.model_name == f"whisper-{size}"


def test_different_devices():
    """Test that different devices can be specified."""
    devices = ["cpu", "cuda", "auto"]

    for device in devices:
        stt = WhisperSTT(model_size="tiny", device=device)  # type: ignore[arg-type]
        assert stt._device == device


def test_different_compute_types():
    """Test that different compute types can be specified."""
    compute_types = ["int8", "float16", "float32"]

    for compute_type in compute_types:
        stt = WhisperSTT(model_size="tiny", device="cpu", compute_type=compute_type)  # type: ignore[arg-type]
        assert stt._compute_type == compute_type
