"""Tests for voice activity detection."""

import struct

from harombe.voice.vad import (
    FRAME_BYTES,
    FRAME_SIZE,
    VADConfig,
    VADState,
    VoiceActivityDetector,
)


def _make_silence_frame(n_frames: int = 1) -> bytes:
    """Create silent audio frames (all zeros)."""
    return b"\x00" * FRAME_BYTES * n_frames


def _make_speech_frame(amplitude: int = 5000, n_frames: int = 1) -> bytes:
    """Create audio frames with a sine-like pattern above the energy threshold."""
    samples = []
    for i in range(FRAME_SIZE * n_frames):
        # Alternating positive/negative to create energy
        val = amplitude if i % 2 == 0 else -amplitude
        samples.append(val)
    return struct.pack(f"<{len(samples)}h", *samples)


class TestVADConfig:
    """Test VAD configuration."""

    def test_default_config(self):
        config = VADConfig()
        assert config.energy_threshold == 0.01
        assert config.speech_pad_ms == 300
        assert config.silence_duration_ms == 800
        assert config.min_speech_duration_ms == 250

    def test_custom_config(self):
        config = VADConfig(
            energy_threshold=0.05,
            silence_duration_ms=500,
        )
        assert config.energy_threshold == 0.05
        assert config.silence_duration_ms == 500


class TestVoiceActivityDetector:
    """Test voice activity detection logic."""

    def test_initial_state_is_silence(self):
        vad = VoiceActivityDetector()
        assert vad.state == VADState.SILENCE

    def test_silence_produces_no_events(self):
        vad = VoiceActivityDetector()
        events = vad.process_frame(_make_silence_frame(5))
        # No speech_start or speech_end events for pure silence
        assert all(e.type != "speech_start" for e in events)
        assert all(e.type != "speech_end" for e in events)

    def test_speech_triggers_speech_start(self):
        vad = VoiceActivityDetector()
        events = vad.process_frame(_make_speech_frame())
        types = [e.type for e in events]
        assert "speech_start" in types
        assert vad.state == VADState.SPEECH

    def test_speech_then_silence_triggers_speech_end(self):
        config = VADConfig(silence_duration_ms=60, min_speech_duration_ms=30)
        vad = VoiceActivityDetector(config)

        # Start speech
        vad.process_frame(_make_speech_frame(n_frames=3))
        assert vad.state == VADState.SPEECH

        # Send enough silence to trigger end
        events = vad.process_frame(_make_silence_frame(n_frames=10))
        types = [e.type for e in events]
        assert "speech_end" in types
        assert vad.state == VADState.SILENCE

    def test_speech_end_contains_audio(self):
        config = VADConfig(silence_duration_ms=60, min_speech_duration_ms=30)
        vad = VoiceActivityDetector(config)

        vad.process_frame(_make_speech_frame(n_frames=5))
        events = vad.process_frame(_make_silence_frame(n_frames=10))

        end_events = [e for e in events if e.type == "speech_end"]
        assert len(end_events) == 1
        assert len(end_events[0].audio) > 0
        assert end_events[0].duration_ms > 0

    def test_short_noise_filtered_by_min_duration(self):
        config = VADConfig(
            silence_duration_ms=60,
            min_speech_duration_ms=500,  # High threshold
        )
        vad = VoiceActivityDetector(config)

        # Very short speech (1 frame = 30ms < 500ms minimum)
        vad.process_frame(_make_speech_frame(n_frames=1))
        events = vad.process_frame(_make_silence_frame(n_frames=10))

        # Should not emit speech_end because speech was too short
        end_events = [e for e in events if e.type == "speech_end"]
        assert len(end_events) == 0

    def test_reset_clears_state(self):
        vad = VoiceActivityDetector()
        vad.process_frame(_make_speech_frame())
        assert vad.state == VADState.SPEECH

        vad.reset()
        assert vad.state == VADState.SILENCE

    def test_continuous_speech_stays_in_speech_state(self):
        vad = VoiceActivityDetector()
        for _ in range(20):
            vad.process_frame(_make_speech_frame())
        assert vad.state == VADState.SPEECH

    def test_speech_audio_events_emitted_during_speech(self):
        vad = VoiceActivityDetector()

        # First frame triggers speech_start
        events1 = vad.process_frame(_make_speech_frame())
        assert any(e.type == "speech_start" for e in events1)

        # Subsequent frames emit speech_audio
        events2 = vad.process_frame(_make_speech_frame())
        assert any(e.type == "speech_audio" for e in events2)

    def test_large_frame_processed_in_chunks(self):
        """Frames larger than FRAME_BYTES are split and processed."""
        vad = VoiceActivityDetector()
        # Send 3 frames worth of speech at once
        large_frame = _make_speech_frame(n_frames=3)
        assert len(large_frame) == FRAME_BYTES * 3

        events = vad.process_frame(large_frame)
        # Should get speech_start from first sub-frame
        assert any(e.type == "speech_start" for e in events)

    def test_is_speech_energy_threshold(self):
        """Test that energy threshold correctly classifies frames."""
        vad = VoiceActivityDetector(VADConfig(energy_threshold=0.05))

        # Low amplitude should be silence
        assert not vad._is_speech(_make_silence_frame())

        # High amplitude should be speech
        assert vad._is_speech(_make_speech_frame(amplitude=10000))

    def test_multiple_utterances(self):
        """Test detecting multiple speech segments."""
        config = VADConfig(silence_duration_ms=60, min_speech_duration_ms=30)
        vad = VoiceActivityDetector(config)

        all_events = []

        # First utterance
        all_events.extend(vad.process_frame(_make_speech_frame(n_frames=5)))
        all_events.extend(vad.process_frame(_make_silence_frame(n_frames=10)))

        # Second utterance
        all_events.extend(vad.process_frame(_make_speech_frame(n_frames=5)))
        all_events.extend(vad.process_frame(_make_silence_frame(n_frames=10)))

        starts = [e for e in all_events if e.type == "speech_start"]
        ends = [e for e in all_events if e.type == "speech_end"]
        assert len(starts) == 2
        assert len(ends) == 2
