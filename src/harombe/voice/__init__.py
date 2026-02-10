"""Voice capabilities for harombe (STT, TTS, VAD, voice client).

Provides speech-to-text via Whisper (tiny to large-v3 models) and
text-to-speech via Piper (fast, all Python versions) or Coqui
(high-quality, Python <3.11 only). Includes energy-based Voice Activity
Detection (VAD) for hands-free operation. Supports push-to-talk voice
interaction and REST/WebSocket streaming APIs.

Components:

- :class:`WhisperSTT` - Speech-to-text with faster-whisper
- :class:`PiperTTS` - Fast text-to-speech engine
- :class:`CoquiTTS` - High-quality text-to-speech (Python <3.11)
- :class:`VoiceActivityDetector` - Energy-based VAD for speech boundary detection
"""

from harombe.voice.coqui import CoquiTTS, create_coqui_tts
from harombe.voice.piper import PiperTTS, create_piper_tts
from harombe.voice.stt import STTEngine, TranscriptionResult
from harombe.voice.tts import TTSEngine
from harombe.voice.vad import VADConfig, VADEvent, VADState, VoiceActivityDetector
from harombe.voice.whisper import WhisperSTT, create_whisper_stt

__all__ = [
    "CoquiTTS",
    "PiperTTS",
    "STTEngine",
    "TTSEngine",
    "TranscriptionResult",
    "VADConfig",
    "VADEvent",
    "VADState",
    "VoiceActivityDetector",
    "WhisperSTT",
    "create_coqui_tts",
    "create_piper_tts",
    "create_whisper_stt",
]
