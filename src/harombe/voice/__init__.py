"""Voice capabilities for harombe (STT, TTS, voice client)."""

from harombe.voice.coqui import CoquiTTS, create_coqui_tts
from harombe.voice.piper import PiperTTS, create_piper_tts
from harombe.voice.stt import STTEngine, TranscriptionResult
from harombe.voice.tts import TTSEngine
from harombe.voice.whisper import WhisperSTT, create_whisper_stt

__all__ = [
    "CoquiTTS",
    "PiperTTS",
    "STTEngine",
    "TTSEngine",
    "TranscriptionResult",
    "WhisperSTT",
    "create_coqui_tts",
    "create_piper_tts",
    "create_whisper_stt",
]
