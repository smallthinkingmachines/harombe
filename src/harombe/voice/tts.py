"""Text-to-speech abstraction."""

from collections.abc import AsyncIterator
from typing import Protocol


class TTSEngine(Protocol):
    """Protocol for text-to-speech engines."""

    async def synthesize(
        self,
        text: str,
        voice: str = "default",
        speed: float = 1.0,
    ) -> bytes:
        """Convert text to audio.

        Args:
            text: Text to convert to speech
            voice: Voice name or ID to use
            speed: Speech speed multiplier (0.5-2.0)

        Returns:
            Audio data in WAV format
        """
        ...

    def synthesize_stream(
        self,
        text: str,
        voice: str = "default",
        speed: float = 1.0,
    ) -> AsyncIterator[bytes]:
        """Stream audio generation.

        Args:
            text: Text to convert to speech
            voice: Voice name or ID to use
            speed: Speech speed multiplier (0.5-2.0)

        Yields:
            Audio chunks as they are generated
        """
        ...

    @property
    def available_voices(self) -> list[str]:
        """Return list of available voice names."""
        ...

    @property
    def sample_rate(self) -> int:
        """Return the sample rate of generated audio."""
        ...

    @property
    def engine_name(self) -> str:
        """Return the name of the TTS engine."""
        ...
