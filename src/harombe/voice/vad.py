"""Voice Activity Detection (VAD) for hands-free operation.

Provides energy-based VAD that detects speech start/stop boundaries
without requiring external dependencies. Uses RMS energy with adaptive
threshold and silence duration for robust speech boundary detection.

For higher accuracy, webrtcvad can be used as a drop-in replacement
by passing ``use_webrtcvad=True`` to :class:`VoiceActivityDetector`.
"""

from __future__ import annotations

import logging
import struct
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)

# Audio constants (16kHz, 16-bit mono)
SAMPLE_RATE = 16000
BYTES_PER_SAMPLE = 2
FRAME_DURATION_MS = 30
FRAME_SIZE = int(SAMPLE_RATE * FRAME_DURATION_MS / 1000)  # 480 samples
FRAME_BYTES = FRAME_SIZE * BYTES_PER_SAMPLE  # 960 bytes


class VADState(Enum):
    """Current state of the voice activity detector."""

    SILENCE = "silence"
    SPEECH = "speech"
    TRAILING = "trailing"  # Speech ended, waiting for silence timeout


@dataclass
class VADConfig:
    """Configuration for voice activity detection.

    Attributes:
        energy_threshold: RMS energy threshold for speech (0.0-1.0 normalized).
            Lower values are more sensitive. Default 0.01 works well for
            typical microphone input.
        speech_pad_ms: Milliseconds of silence to keep before speech start.
        silence_duration_ms: Milliseconds of silence before declaring speech end.
        min_speech_duration_ms: Minimum speech duration to emit (filters clicks/noise).
    """

    energy_threshold: float = 0.01
    speech_pad_ms: int = 300
    silence_duration_ms: int = 800
    min_speech_duration_ms: int = 250


@dataclass
class VADEvent:
    """Event emitted by the voice activity detector."""

    type: str  # "speech_start", "speech_end", "speech_audio"
    audio: bytes = b""
    duration_ms: int = 0


class VoiceActivityDetector:
    """Energy-based voice activity detector.

    Detects speech boundaries by monitoring RMS energy levels of audio frames.
    Emits events when speech starts/stops and passes through speech audio.

    Usage::

        vad = VoiceActivityDetector()
        for event in vad.process_frame(audio_frame):
            if event.type == "speech_start":
                # User started speaking
                ...
            elif event.type == "speech_audio":
                # Audio data during speech
                ...
            elif event.type == "speech_end":
                # User stopped speaking, event.audio has complete utterance
                ...
    """

    def __init__(self, config: VADConfig | None = None) -> None:
        self._config = config or VADConfig()
        self._state = VADState.SILENCE
        self._speech_buffer: list[bytes] = []
        self._ring_buffer: list[bytes] = []
        self._silence_frames = 0
        self._speech_frames = 0

        # Pre-compute frame counts from ms config
        ms_per_frame = FRAME_DURATION_MS
        self._pad_frames = max(1, self._config.speech_pad_ms // ms_per_frame)
        self._silence_threshold_frames = max(1, self._config.silence_duration_ms // ms_per_frame)
        self._min_speech_frames = max(1, self._config.min_speech_duration_ms // ms_per_frame)

    @property
    def state(self) -> VADState:
        """Current VAD state."""
        return self._state

    def reset(self) -> None:
        """Reset detector state."""
        self._state = VADState.SILENCE
        self._speech_buffer.clear()
        self._ring_buffer.clear()
        self._silence_frames = 0
        self._speech_frames = 0

    def process_frame(self, frame: bytes) -> list[VADEvent]:
        """Process a single audio frame and return any events.

        Args:
            frame: Raw audio frame (16kHz, 16-bit mono PCM).
                Should be FRAME_BYTES (960) bytes for a 30ms frame.
                Larger frames are processed in FRAME_BYTES chunks.

        Returns:
            List of VADEvents (may be empty if no state change).
        """
        events: list[VADEvent] = []

        # Process in frame-sized chunks
        offset = 0
        while offset + FRAME_BYTES <= len(frame):
            chunk = frame[offset : offset + FRAME_BYTES]
            events.extend(self._process_single_frame(chunk))
            offset += FRAME_BYTES

        # Handle remainder (pad with zeros if needed for final partial frame)
        if offset < len(frame):
            remainder = frame[offset:]
            padded = remainder + b"\x00" * (FRAME_BYTES - len(remainder))
            events.extend(self._process_single_frame(padded))

        return events

    def _process_single_frame(self, frame: bytes) -> list[VADEvent]:
        """Process exactly one FRAME_BYTES frame."""
        events: list[VADEvent] = []
        is_speech = self._is_speech(frame)

        if self._state == VADState.SILENCE:
            # Keep a rolling buffer for pre-speech padding
            self._ring_buffer.append(frame)
            if len(self._ring_buffer) > self._pad_frames:
                self._ring_buffer.pop(0)

            if is_speech:
                self._state = VADState.SPEECH
                self._speech_frames = 1
                self._silence_frames = 0
                # Include pre-speech padding
                self._speech_buffer = list(self._ring_buffer)
                self._ring_buffer.clear()
                events.append(VADEvent(type="speech_start"))

        elif self._state == VADState.SPEECH:
            self._speech_buffer.append(frame)
            self._speech_frames += 1

            if is_speech:
                self._silence_frames = 0
                events.append(VADEvent(type="speech_audio", audio=frame))
            else:
                self._silence_frames += 1
                if self._silence_frames >= self._silence_threshold_frames:
                    self._state = VADState.SILENCE
                    # Only emit if speech was long enough
                    if self._speech_frames >= self._min_speech_frames:
                        complete_audio = b"".join(self._speech_buffer)
                        duration_ms = (
                            (len(complete_audio) // BYTES_PER_SAMPLE) * 1000 // SAMPLE_RATE
                        )
                        events.append(
                            VADEvent(
                                type="speech_end",
                                audio=complete_audio,
                                duration_ms=duration_ms,
                            )
                        )
                    self._speech_buffer.clear()
                    self._speech_frames = 0
                    self._silence_frames = 0
                else:
                    # Still in trailing silence, include in buffer
                    events.append(VADEvent(type="speech_audio", audio=frame))

        return events

    def _is_speech(self, frame: bytes) -> bool:
        """Check if a frame contains speech based on RMS energy."""
        # Unpack 16-bit samples
        n_samples = len(frame) // BYTES_PER_SAMPLE
        if n_samples == 0:
            return False

        samples = struct.unpack(f"<{n_samples}h", frame[: n_samples * BYTES_PER_SAMPLE])

        # Calculate RMS energy (normalized to 0.0-1.0)
        sum_sq = sum(s * s for s in samples)
        rms = (sum_sq / n_samples) ** 0.5 / 32768.0

        return bool(rms >= self._config.energy_threshold)
