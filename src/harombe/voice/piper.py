"""Piper text-to-speech implementation.

Piper is an ultra-fast, local TTS engine with good quality and low resource usage.
It's significantly faster than Coqui TTS while maintaining acceptable quality.
"""

import asyncio
import logging
import struct
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any, Literal

from harombe.voice.tts import TTSEngine

logger = logging.getLogger(__name__)


class PiperTTS(TTSEngine):
    """Piper-based text-to-speech engine.

    Piper is a fast, local TTS system that uses ONNX models for inference.
    It provides good quality with very low latency (100-300ms for short phrases).
    """

    def __init__(
        self,
        model: str = "en_US-lessac-medium",
        device: Literal["cpu", "cuda"] = "cpu",
        download_root: str | Path | None = None,
    ):
        """Initialize Piper TTS engine.

        Args:
            model: Piper model name (e.g., "en_US-lessac-medium")
            device: Device to run inference on (Piper uses ONNX, limited GPU support)
            download_root: Directory to download models to
        """
        self._model_name = model
        self._device = device
        self._download_root = download_root
        self._piper_instance: Any = None
        self._sample_rate = 22050  # Piper default

    def _load_model(self) -> None:
        """Lazy load the Piper model."""
        if self._piper_instance is not None:
            return

        try:
            from piper.voice import PiperVoice  # type: ignore[import-not-found]
        except ImportError as e:
            msg = "piper-tts not installed. Install with: " "pip install piper-tts"
            raise ImportError(msg) from e

        logger.info(f"Loading Piper TTS model: {self._model_name}")

        # Download and load model
        try:
            self._piper_instance = PiperVoice.load(
                self._model_name,
                download_dir=str(self._download_root) if self._download_root else None,
                use_cuda=(self._device == "cuda"),
            )
            self._sample_rate = self._piper_instance.config.sample_rate

            logger.info(f"Piper model loaded successfully (sample_rate={self._sample_rate})")
        except Exception as e:
            logger.error(f"Failed to load Piper model {self._model_name}: {e}")
            raise

    async def synthesize(
        self,
        text: str,
        voice: str = "default",
        speed: float = 1.0,
    ) -> bytes:
        """Convert text to audio.

        Args:
            text: Text to convert to speech
            voice: Unused for Piper (model determines voice)
            speed: Speech speed multiplier (0.5-2.0)

        Returns:
            Audio data in WAV format
        """
        self._load_model()

        if not text.strip():
            return self._create_empty_wav()

        # Run synthesis in thread pool
        loop = asyncio.get_event_loop()
        audio_samples = await loop.run_in_executor(
            None,
            lambda: self._synthesize_sync(text, speed),
        )

        # Convert to WAV format
        return self._samples_to_wav(audio_samples)

    def _synthesize_sync(self, text: str, speed: float) -> list[int]:
        """Synchronous synthesis (runs in thread pool)."""

        # Piper generates audio samples
        audio_stream = self._piper_instance.synthesize_stream_raw(text)

        # Collect all audio samples
        audio_samples = []
        for audio_chunk in audio_stream:
            # Adjust speed if needed
            if speed != 1.0:
                # Simple speed adjustment (more sophisticated methods exist)
                audio_chunk = self._adjust_speed(audio_chunk, speed)

            audio_samples.extend(audio_chunk)

        return audio_samples

    def _adjust_speed(self, audio: Any, speed: float) -> Any:
        """Adjust audio speed (simple resampling)."""
        import numpy as np  # type: ignore[import-not-found]

        if speed == 1.0:
            return audio

        # Convert to numpy array if needed
        audio_array = np.array(audio, dtype=np.float32)

        # Simple speed adjustment via resampling
        target_length = int(len(audio_array) / speed)
        indices = np.linspace(0, len(audio_array) - 1, target_length)
        resampled = np.interp(indices, np.arange(len(audio_array)), audio_array)

        return resampled.tolist()

    def _samples_to_wav(self, samples: list[int]) -> bytes:
        """Convert audio samples to WAV format."""
        import numpy as np

        # Convert to 16-bit PCM
        audio_array = np.array(samples, dtype=np.float32)
        audio_int16 = np.clip(audio_array * 32767, -32768, 32767).astype(np.int16)

        # Create WAV header
        num_samples = len(audio_int16)
        byte_rate = self._sample_rate * 2  # 16-bit mono
        data_size = num_samples * 2

        wav_header = struct.pack(
            "<4sI4s4sIHHIIHH4sI",
            b"RIFF",
            36 + data_size,
            b"WAVE",
            b"fmt ",
            16,  # PCM format chunk size
            1,  # PCM format
            1,  # Mono
            self._sample_rate,
            byte_rate,
            2,  # Block align
            16,  # Bits per sample
            b"data",
            data_size,
        )

        # Combine header and audio data
        result: bytes = wav_header + audio_int16.tobytes()
        return result

    def _create_empty_wav(self) -> bytes:
        """Create empty WAV file for empty text."""
        wav_header = struct.pack(
            "<4sI4s4sIHHIIHH4sI",
            b"RIFF",
            36,  # No data
            b"WAVE",
            b"fmt ",
            16,
            1,
            1,
            self._sample_rate,
            self._sample_rate * 2,
            2,
            16,
            b"data",
            0,  # No data
        )
        return wav_header

    async def synthesize_stream(
        self,
        text: str,
        voice: str = "default",
        speed: float = 1.0,
    ) -> AsyncIterator[bytes]:
        """Stream audio generation.

        Args:
            text: Text to convert to speech
            voice: Unused for Piper (model determines voice)
            speed: Speech speed multiplier

        Yields:
            Audio chunks in WAV format
        """
        self._load_model()

        if not text.strip():
            yield self._create_empty_wav()
            return

        # Yield WAV header first
        # Note: We don't know final size yet, so we'll use max size
        max_samples = len(text) * 1000  # Rough estimate
        wav_header = struct.pack(
            "<4sI4s4sIHHIIHH4sI",
            b"RIFF",
            36 + max_samples * 2,
            b"WAVE",
            b"fmt ",
            16,
            1,
            1,
            self._sample_rate,
            self._sample_rate * 2,
            2,
            16,
            b"data",
            max_samples * 2,
        )
        yield wav_header

        # Stream audio chunks
        loop = asyncio.get_event_loop()

        # Run synthesis in thread pool with streaming
        def stream_synthesis() -> list[bytes]:
            import numpy as np

            chunks: list[bytes] = []
            for audio_chunk in self._piper_instance.synthesize_stream_raw(text):
                if speed != 1.0:
                    audio_chunk = self._adjust_speed(audio_chunk, speed)

                # Convert to 16-bit PCM
                audio_array = np.array(audio_chunk, dtype=np.float32)
                audio_int16 = np.clip(audio_array * 32767, -32768, 32767).astype(np.int16)
                chunks.append(audio_int16.tobytes())
            return chunks

        # Yield chunks as they're generated
        for chunk in await loop.run_in_executor(None, stream_synthesis):
            yield chunk

    @property
    def available_voices(self) -> list[str]:
        """Return list of available voice names.

        Note: Piper models are voice-specific, so this returns the current model.
        """
        return [self._model_name]

    @property
    def sample_rate(self) -> int:
        """Return the sample rate of generated audio."""
        return self._sample_rate

    @property
    def engine_name(self) -> str:
        """Return the name of the TTS engine."""
        return f"piper-{self._model_name}"


def create_piper_tts(
    model: str = "en_US-lessac-medium",
    device: str = "cpu",
) -> PiperTTS:
    """Factory function to create a Piper TTS engine.

    Args:
        model: Piper model name
        device: Device to run on ("cpu" or "cuda")

    Returns:
        Configured PiperTTS instance

    Popular Piper models:
        - en_US-lessac-medium (default, good quality, fast)
        - en_US-lessac-high (better quality, slower)
        - en_US-amy-medium (female voice)
        - en_GB-alan-medium (British accent)
    """
    return PiperTTS(
        model=model,
        device=device,  # type: ignore[arg-type]
    )
