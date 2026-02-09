"""Coqui TTS text-to-speech implementation.

Coqui TTS is a high-quality, open source TTS engine with voice cloning support.
It's slower than Piper (500ms-1s) but offers better quality and more features.
"""

import asyncio
import logging
import struct
from collections.abc import AsyncIterator
from typing import Any, Literal

from harombe.voice.tts import TTSEngine

logger = logging.getLogger(__name__)


class CoquiTTS(TTSEngine):
    """Coqui TTS-based text-to-speech engine.

    Coqui TTS provides high-quality speech synthesis with support for
    multiple languages, voices, and even voice cloning.
    """

    def __init__(
        self,
        model_name: str = "tts_models/en/ljspeech/tacotron2-DDC",
        device: Literal["cpu", "cuda"] = "cpu",
        vocoder: str | None = None,
    ):
        """Initialize Coqui TTS engine.

        Args:
            model_name: Coqui TTS model path
            device: Device to run inference on
            vocoder: Optional vocoder model (auto-selected if None)
        """
        self._model_name = model_name
        self._device = device
        self._vocoder = vocoder
        self._tts: Any = None
        self._sample_rate = 22050  # Default, updated after model load

    def _load_model(self) -> None:
        """Lazy load the Coqui TTS model."""
        if self._tts is not None:
            return

        try:
            from TTS.api import TTS  # type: ignore[import-not-found]
        except ImportError as e:
            msg = (
                "Coqui TTS not installed. "
                "Note: Coqui TTS only supports Python <3.11. "
                "Install with: pip install 'harombe[coqui]' (Python 3.10 or earlier) "
                "or use Piper TTS instead (supports all Python versions)."
            )
            raise ImportError(msg) from e

        logger.info(f"Loading Coqui TTS model: {self._model_name}")

        try:
            # Initialize TTS
            self._tts = TTS(
                model_name=self._model_name,
                vocoder_name=self._vocoder,
                progress_bar=False,
                gpu=(self._device == "cuda"),
            )

            # Get sample rate from model config
            if hasattr(self._tts.synthesizer, "output_sample_rate"):
                self._sample_rate = self._tts.synthesizer.output_sample_rate
            elif hasattr(self._tts, "config"):
                self._sample_rate = getattr(self._tts.config, "audio", {}).get("sample_rate", 22050)

            logger.info(f"Coqui TTS loaded successfully (sample_rate={self._sample_rate})")

        except Exception as e:
            logger.error(f"Failed to load Coqui TTS model: {e}")
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
            voice: Speaker name (if multi-speaker model)
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
            lambda: self._synthesize_sync(text, voice, speed),
        )

        # Convert to WAV format
        return self._samples_to_wav(audio_samples)

    def _synthesize_sync(
        self,
        text: str,
        voice: str,
        speed: float,
    ) -> list[float]:
        """Synchronous synthesis (runs in thread pool)."""
        import numpy as np  # type: ignore[import-not-found]

        # Prepare kwargs
        kwargs = {}
        if voice != "default" and self._tts.is_multi_speaker:
            kwargs["speaker"] = voice

        # Generate audio
        wav = self._tts.tts(text, **kwargs)

        # Adjust speed if needed
        if speed != 1.0:
            wav = self._adjust_speed(np.array(wav), speed)

        return wav if isinstance(wav, list) else wav.tolist()

    def _adjust_speed(self, audio: Any, speed: float) -> Any:
        """Adjust audio speed via resampling."""
        import numpy as np

        if speed == 1.0:
            return audio

        audio_array = np.array(audio, dtype=np.float32)
        target_length = int(len(audio_array) / speed)
        indices = np.linspace(0, len(audio_array) - 1, target_length)
        resampled = np.interp(indices, np.arange(len(audio_array)), audio_array)

        return resampled

    def _samples_to_wav(self, samples: list[float]) -> bytes:
        """Convert audio samples to WAV format."""
        import numpy as np

        # Convert to 16-bit PCM
        audio_array = np.array(samples, dtype=np.float32)
        audio_int16 = np.clip(audio_array * 32767, -32768, 32767).astype(np.int16)

        # Create WAV header
        num_samples = len(audio_int16)
        byte_rate = self._sample_rate * 2
        data_size = num_samples * 2

        wav_header = struct.pack(
            "<4sI4s4sIHHIIHH4sI",
            b"RIFF",
            36 + data_size,
            b"WAVE",
            b"fmt ",
            16,
            1,
            1,
            self._sample_rate,
            byte_rate,
            2,
            16,
            b"data",
            data_size,
        )

        result: bytes = wav_header + audio_int16.tobytes()
        return result

    def _create_empty_wav(self) -> bytes:
        """Create empty WAV file."""
        wav_header = struct.pack(
            "<4sI4s4sIHHIIHH4sI",
            b"RIFF",
            36,
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
            0,
        )
        return wav_header

    async def synthesize_stream(
        self,
        text: str,
        voice: str = "default",
        speed: float = 1.0,
    ) -> AsyncIterator[bytes]:
        """Stream audio generation.

        Note: Coqui TTS doesn't have native streaming support, so this
        generates the full audio then yields it in chunks.

        Args:
            text: Text to convert to speech
            voice: Speaker name (if multi-speaker model)
            speed: Speech speed multiplier

        Yields:
            Audio chunks
        """
        # Generate full audio
        audio = await self.synthesize(text, voice, speed)

        # Yield WAV header
        header_size = 44
        yield audio[:header_size]

        # Yield audio data in chunks
        chunk_size = 4096
        data = audio[header_size:]

        for i in range(0, len(data), chunk_size):
            yield data[i : i + chunk_size]
            await asyncio.sleep(0)  # Allow other tasks to run

    @property
    def available_voices(self) -> list[str]:
        """Return list of available voice names."""
        self._load_model()

        if self._tts.is_multi_speaker:
            return self._tts.speakers or []

        return ["default"]

    @property
    def sample_rate(self) -> int:
        """Return the sample rate of generated audio."""
        return self._sample_rate

    @property
    def engine_name(self) -> str:
        """Return the name of the TTS engine."""
        model_short = self._model_name.split("/")[-1]
        return f"coqui-{model_short}"


def create_coqui_tts(
    model_name: str = "tts_models/en/ljspeech/tacotron2-DDC",
    device: str = "cpu",
) -> CoquiTTS:
    """Factory function to create a Coqui TTS engine.

    Args:
        model_name: Coqui TTS model path
        device: Device to run on ("cpu" or "cuda")

    Returns:
        Configured CoquiTTS instance

    Popular Coqui models:
        - tts_models/en/ljspeech/tacotron2-DDC (default, good quality)
        - tts_models/en/vctk/vits (multi-speaker, high quality)
        - tts_models/en/ljspeech/fast_pitch (fast, good quality)
    """
    return CoquiTTS(
        model_name=model_name,
        device=device,  # type: ignore[arg-type]
    )
