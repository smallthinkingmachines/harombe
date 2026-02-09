"""Tests for STT abstraction."""

from harombe.voice.stt import TranscriptionResult


def test_transcription_result():
    """Test TranscriptionResult dataclass."""
    result = TranscriptionResult(
        text="Hello world",
        language="en",
        confidence=0.95,
    )

    assert result.text == "Hello world"
    assert result.language == "en"
    assert result.confidence == 0.95
    assert result.segments is None


def test_transcription_result_with_segments():
    """Test TranscriptionResult with segments."""
    segments = [
        {"start": 0.0, "end": 1.0, "text": "Hello", "confidence": 0.98},
        {"start": 1.0, "end": 2.0, "text": "world", "confidence": 0.92},
    ]

    result = TranscriptionResult(
        text="Hello world",
        language="en",
        confidence=0.95,
        segments=segments,
    )

    assert result.text == "Hello world"
    assert result.segments == segments
    assert len(result.segments) == 2
