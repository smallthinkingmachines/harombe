"""Whisper speech-to-text implementation using faster-whisper."""

import asyncio
import io
import logging
import tempfile
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any, Literal

from harombe.voice.stt import STTEngine, TranscriptionResult

logger = logging.getLogger(__name__)


class WhisperSTT(STTEngine):
    """Whisper-based speech-to-text engine using faster-whisper.

    faster-whisper is a reimplementation of OpenAI's Whisper model using CTranslate2,
    which is up to 4x faster than the original implementation with lower memory usage.
    """

    def __init__(
        self,
        model_size: Literal["tiny", "base", "small", "medium", "large-v3"] = "medium",
        device: Literal["cpu", "cuda", "auto"] = "auto",
        compute_type: Literal["int8", "float16", "float32"] = "float16",
        download_root: str | Path | None = None,
    ):
        """Initialize Whisper STT engine.

        Args:
            model_size: Size of Whisper model to use
            device: Device to run inference on
            compute_type: Compute type for inference (lower = faster but less accurate)
            download_root: Directory to download models to (default: ~/.cache/huggingface)
        """
        self._model_size = model_size
        self._device = device
        self._compute_type = compute_type
        self._download_root = download_root
        self._model: Any = None

    def _load_model(self) -> None:
        """Lazy load the Whisper model."""
        if self._model is not None:
            return

        try:
            from faster_whisper import WhisperModel  # type: ignore[import-not-found]
        except ImportError as e:
            msg = "faster-whisper not installed. Install with: " "pip install faster-whisper"
            raise ImportError(msg) from e

        logger.info(
            f"Loading Whisper model: {self._model_size} "
            f"(device={self._device}, compute_type={self._compute_type})"
        )

        self._model = WhisperModel(
            self._model_size,
            device=self._device,
            compute_type=self._compute_type,
            download_root=self._download_root,
        )

        logger.info("Whisper model loaded successfully")

    async def transcribe(
        self,
        audio: bytes,
        language: str | None = None,
    ) -> TranscriptionResult:
        """Transcribe audio to text.

        Args:
            audio: Audio data (WAV format, 16kHz mono recommended)
            language: Optional language code (e.g., "en", "es"). None for auto-detect.

        Returns:
            Transcription result with text and metadata
        """
        self._load_model()

        # Save audio to temporary file (faster-whisper requires file path)
        with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as tmp_file:
            tmp_path = Path(tmp_file.name)
            tmp_file.write(audio)

        try:
            # Run transcription in thread pool to avoid blocking
            loop = asyncio.get_event_loop()
            segments, info = await loop.run_in_executor(
                None,
                lambda: self._model.transcribe(
                    str(tmp_path),
                    language=language,
                    beam_size=5,
                    vad_filter=True,  # Filter out non-speech
                    word_timestamps=True,  # Get word-level timestamps
                ),
            )

            # Collect all segments
            segment_list = []
            text_parts = []

            for segment in segments:
                segment_dict = {
                    "start": segment.start,
                    "end": segment.end,
                    "text": segment.text,
                    "confidence": getattr(segment, "avg_logprob", None),
                }

                # Add word-level timestamps if available
                if hasattr(segment, "words") and segment.words:
                    segment_dict["words"] = [
                        {
                            "word": word.word,
                            "start": word.start,
                            "end": word.end,
                            "probability": word.probability,
                        }
                        for word in segment.words
                    ]

                segment_list.append(segment_dict)
                text_parts.append(segment.text)

            # Combine all text
            full_text = " ".join(text_parts).strip()

            # Calculate average confidence
            confidences = [s["confidence"] for s in segment_list if s["confidence"] is not None]
            avg_confidence = sum(confidences) / len(confidences) if confidences else None

            return TranscriptionResult(
                text=full_text,
                language=info.language,
                confidence=avg_confidence,
                segments=segment_list,
            )

        finally:
            # Clean up temporary file
            try:
                tmp_path.unlink()
            except Exception as e:
                logger.warning(f"Failed to delete temporary file {tmp_path}: {e}")

    async def transcribe_stream(
        self,
        audio_stream: AsyncIterator[bytes],
    ) -> AsyncIterator[str]:
        """Stream transcription using VAD-based speech boundary detection.

        Uses Voice Activity Detection to segment audio into utterances and
        transcribes each utterance as soon as it ends. This reduces latency
        compared to fixed-size buffering and avoids wasting compute on silence.

        Falls back to time-based buffering (1.5s) if no speech boundaries
        are detected, ensuring partial results are still emitted.

        Args:
            audio_stream: Async iterator of audio chunks (16kHz, 16-bit mono)

        Yields:
            Transcription text for each detected utterance
        """
        self._load_model()

        from harombe.voice.vad import VADConfig, VoiceActivityDetector

        vad = VoiceActivityDetector(
            VADConfig(
                silence_duration_ms=600,
                min_speech_duration_ms=200,
            )
        )

        # Also keep a time-based fallback buffer
        buffer = io.BytesIO()
        fallback_bytes = 16000 * 2 * 2  # 2 seconds fallback if VAD doesn't trigger

        async for chunk in audio_stream:
            events = vad.process_frame(chunk)
            buffer.write(chunk)

            for event in events:
                if event.type == "speech_end" and event.audio:
                    # VAD detected end of utterance — transcribe it
                    result = await self.transcribe(event.audio)
                    if result.text:
                        yield result.text
                    buffer = io.BytesIO()

            # Fallback: if buffer gets large without a speech_end, transcribe anyway
            if buffer.tell() >= fallback_bytes:
                audio_data = buffer.getvalue()
                result = await self.transcribe(audio_data)
                if result.text:
                    yield result.text
                buffer = io.BytesIO()

        # Transcribe any remaining audio
        if buffer.tell() > 0:
            audio_data = buffer.getvalue()
            result = await self.transcribe(audio_data)
            if result.text:
                yield result.text

    @property
    def model_name(self) -> str:
        """Return the name of the STT model being used."""
        return f"whisper-{self._model_size}"


def create_whisper_stt(
    model_size: str = "medium",
    device: str = "auto",
    compute_type: str = "float16",
) -> WhisperSTT:
    """Factory function to create a Whisper STT engine.

    Args:
        model_size: Size of Whisper model ("tiny", "base", "small", "medium", "large-v3")
        device: Device to run on ("cpu", "cuda", "auto")
        compute_type: Compute type ("int8", "float16", "float32")

    Returns:
        Configured WhisperSTT instance
    """
    return WhisperSTT(
        model_size=model_size,  # type: ignore[arg-type]
        device=device,  # type: ignore[arg-type]
        compute_type=compute_type,  # type: ignore[arg-type]
    )
