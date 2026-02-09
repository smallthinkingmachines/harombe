"""Speech-to-text abstraction."""

from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Protocol


@dataclass
class TranscriptionResult:
    """Result of speech-to-text transcription."""

    text: str
    language: str | None = None
    confidence: float | None = None
    segments: list[dict[str, float | str]] | None = None  # Word-level timestamps if available


class STTEngine(Protocol):
    """Protocol for speech-to-text engines."""

    async def transcribe(
        self,
        audio: bytes,
        language: str | None = None,
    ) -> TranscriptionResult:
        """Transcribe audio to text.

        Args:
            audio: Audio data in WAV format (16kHz, mono)
            language: Optional language code (e.g., "en", "es"). None for auto-detect.

        Returns:
            Transcription result with text and metadata
        """
        ...

    def transcribe_stream(
        self,
        audio_stream: AsyncIterator[bytes],
    ) -> AsyncIterator[str]:
        """Stream transcription in real-time.

        Args:
            audio_stream: Async iterator of audio chunks

        Yields:
            Partial transcription results as they become available
        """
        ...

    @property
    def model_name(self) -> str:
        """Return the name of the STT model being used."""
        ...
