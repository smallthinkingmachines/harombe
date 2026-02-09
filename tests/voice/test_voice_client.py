"""Tests for voice client CLI."""

import struct
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from harombe.voice.stt import TranscriptionResult


@pytest.fixture
def mock_stt():
    """Mock STT engine."""
    stt = MagicMock()
    stt.transcribe = AsyncMock(return_value=TranscriptionResult(text="Hello world", language="en"))
    return stt


@pytest.fixture
def mock_tts():
    """Mock TTS engine."""
    tts = MagicMock()

    # Create minimal WAV file
    wav_header = struct.pack(
        "<4sI4s4sIHHIIHH4sI",
        b"RIFF",
        36,
        b"WAVE",
        b"fmt ",
        16,
        1,
        1,
        22050,
        22050 * 2,
        2,
        16,
        b"data",
        0,
    )
    tts.synthesize = AsyncMock(return_value=wav_header)
    return tts


@pytest.fixture
def mock_agent():
    """Mock agent."""
    agent = MagicMock()
    agent.run = AsyncMock(return_value="Agent response")
    return agent


def test_voice_client_import():
    """Test that voice client can be imported."""
    from harombe.cli.voice import VoiceClient

    assert VoiceClient is not None


def test_voice_client_initialization(mock_stt, mock_tts):
    """Test voice client initialization."""
    from harombe.cli.voice import VoiceClient

    client = VoiceClient(stt_engine=mock_stt, tts_engine=mock_tts)

    assert client._stt == mock_stt
    assert client._tts == mock_tts
    assert client._agent is None
    assert not client._recording
    assert client._audio_chunks == []


def test_voice_client_with_agent(mock_stt, mock_tts, mock_agent):
    """Test voice client with agent."""
    from harombe.cli.voice import VoiceClient

    client = VoiceClient(
        stt_engine=mock_stt,
        tts_engine=mock_tts,
        agent=mock_agent,
    )

    assert client._agent == mock_agent


@pytest.mark.asyncio
async def test_process_recording_no_audio(mock_stt, mock_tts):
    """Test processing with no audio."""
    from harombe.cli.voice import VoiceClient

    client = VoiceClient(stt_engine=mock_stt, tts_engine=mock_tts)
    client._audio_chunks = []

    # Should return early without error
    await client._process_recording()

    mock_stt.transcribe.assert_not_called()


@pytest.mark.asyncio
async def test_process_recording_empty_transcription(mock_stt, mock_tts):
    """Test processing with empty transcription."""
    from harombe.cli.voice import VoiceClient

    # Mock empty transcription
    mock_stt.transcribe.return_value = TranscriptionResult(text="", language="en")

    client = VoiceClient(stt_engine=mock_stt, tts_engine=mock_tts)
    # Add some fake audio data
    client._audio_chunks = [b"\x00" * 1024]

    await client._process_recording()

    mock_stt.transcribe.assert_called_once()
    mock_tts.synthesize.assert_not_called()


@pytest.mark.asyncio
async def test_process_recording_with_agent(mock_stt, mock_tts, mock_agent):
    """Test full processing pipeline with agent."""
    from harombe.cli.voice import VoiceClient

    client = VoiceClient(
        stt_engine=mock_stt,
        tts_engine=mock_tts,
        agent=mock_agent,
    )

    # Add fake audio data
    client._audio_chunks = [b"\x00" * 1024]

    # Mock audio playback to avoid actual sound
    with patch.object(client, "_play_audio", new_callable=AsyncMock):
        await client._process_recording()

    # Verify pipeline
    mock_stt.transcribe.assert_called_once()
    mock_agent.run.assert_called_once_with("Hello world")
    mock_tts.synthesize.assert_called_once_with("Agent response")


@pytest.mark.asyncio
async def test_process_recording_without_agent(mock_stt, mock_tts):
    """Test processing pipeline without agent (echo mode)."""
    from harombe.cli.voice import VoiceClient

    client = VoiceClient(stt_engine=mock_stt, tts_engine=mock_tts)
    client._audio_chunks = [b"\x00" * 1024]

    with patch.object(client, "_play_audio", new_callable=AsyncMock):
        await client._process_recording()

    # Should transcribe and echo back
    mock_stt.transcribe.assert_called_once()
    mock_tts.synthesize.assert_called_once()

    # Check it echoed the transcription
    call_args = mock_tts.synthesize.call_args[0][0]
    assert "Hello world" in call_args


def test_chunks_to_wav(mock_stt, mock_tts):
    """Test audio chunks to WAV conversion."""
    from harombe.cli.voice import VoiceClient

    client = VoiceClient(stt_engine=mock_stt, tts_engine=mock_tts)

    # Create fake audio chunks (16-bit samples)
    chunks = [b"\x00\x01" * 100, b"\x02\x03" * 100]

    wav_data = client._chunks_to_wav(chunks)

    # Check WAV header
    assert wav_data[:4] == b"RIFF"
    assert wav_data[8:12] == b"WAVE"
    assert len(wav_data) > 44  # Has header + data


@pytest.mark.asyncio
async def test_process_recording_error_handling(mock_stt, mock_tts):
    """Test error handling in processing."""
    from harombe.cli.voice import VoiceClient

    # Make STT fail
    mock_stt.transcribe.side_effect = RuntimeError("STT failed")

    client = VoiceClient(stt_engine=mock_stt, tts_engine=mock_tts)
    client._audio_chunks = [b"\x00" * 1024]

    # Should not raise, just log error
    await client._process_recording()

    mock_stt.transcribe.assert_called_once()
    mock_tts.synthesize.assert_not_called()
