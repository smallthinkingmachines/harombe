"""Tests for TTS abstraction."""


def test_tts_protocol_exists():
    """Test that TTSEngine protocol is defined."""
    from harombe.voice.tts import TTSEngine

    # Protocol should have required methods
    assert hasattr(TTSEngine, "synthesize")
    assert hasattr(TTSEngine, "synthesize_stream")
    assert hasattr(TTSEngine, "available_voices")
    assert hasattr(TTSEngine, "sample_rate")
    assert hasattr(TTSEngine, "engine_name")
