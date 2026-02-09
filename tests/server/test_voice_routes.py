"""Tests for voice API routes."""

import base64
import struct
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient

from harombe.voice.stt import TranscriptionResult


@pytest.fixture
def mock_stt():
    """Mock STT engine."""
    stt = MagicMock()
    stt.transcribe = AsyncMock(
        return_value=TranscriptionResult(
            text="Hello world",
            language="en",
            confidence=0.95,
        )
    )
    return stt


@pytest.fixture
def mock_tts():
    """Mock TTS engine."""
    tts = MagicMock()
    tts.sample_rate = 22050

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

    # Mock streaming
    async def mock_stream(text, voice="default", speed=1.0):
        yield wav_header[:44]  # Header
        yield wav_header[44:]  # Data (empty in this case)

    tts.synthesize_stream = mock_stream

    return tts


@pytest.fixture
def voice_app(mock_stt, mock_tts):
    """Create test app with voice routes."""
    from fastapi import FastAPI

    from harombe.server.voice_routes import init_voice_engines, voice_router

    app = FastAPI()
    app.include_router(voice_router)

    # Initialize engines
    init_voice_engines(stt_engine=mock_stt, tts_engine=mock_tts)

    return app


def test_stt_endpoint(voice_app, mock_stt):
    """Test STT endpoint."""
    client = TestClient(voice_app)

    # Create fake audio (just some bytes)
    audio_data = b"\x00" * 1024
    audio_b64 = base64.b64encode(audio_data).decode("utf-8")

    response = client.post(
        "/voice/stt",
        json={"audio_base64": audio_b64, "language": "en"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["text"] == "Hello world"
    assert data["language"] == "en"
    assert data["confidence"] == 0.95

    # Verify STT was called
    mock_stt.transcribe.assert_called_once()


def test_tts_endpoint(voice_app, mock_tts):
    """Test TTS endpoint."""
    client = TestClient(voice_app)

    response = client.post(
        "/voice/tts",
        json={"text": "Test message", "voice": "default", "speed": 1.0},
    )

    assert response.status_code == 200
    data = response.json()
    assert "audio_base64" in data
    assert data["format"] == "wav"
    assert data["sample_rate"] == 22050

    # Verify TTS was called
    mock_tts.synthesize.assert_called_once()


def test_stt_file_endpoint(voice_app, mock_stt):
    """Test STT file upload endpoint."""
    client = TestClient(voice_app)

    # Create fake audio file
    audio_data = b"\x00" * 1024

    response = client.post(
        "/voice/stt/file",
        files={"file": ("audio.wav", audio_data, "audio/wav")},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["text"] == "Hello world"

    # Verify STT was called
    mock_stt.transcribe.assert_called_once()


def test_stt_endpoint_no_engine():
    """Test STT endpoint without engine initialized."""
    from fastapi import FastAPI

    from harombe.server import voice_routes

    # Reset global engines
    voice_routes._stt_engine = None
    voice_routes._tts_engine = None
    voice_routes._agent = None

    app = FastAPI()
    app.include_router(voice_routes.voice_router)

    client = TestClient(app)

    audio_b64 = base64.b64encode(b"\x00" * 1024).decode("utf-8")

    response = client.post(
        "/voice/stt",
        json={"audio_base64": audio_b64},
    )

    assert response.status_code == 503
    assert "not initialized" in response.json()["detail"]


def test_tts_endpoint_no_engine():
    """Test TTS endpoint without engine initialized."""
    from fastapi import FastAPI

    from harombe.server import voice_routes

    # Reset global engines
    voice_routes._stt_engine = None
    voice_routes._tts_engine = None
    voice_routes._agent = None

    app = FastAPI()
    app.include_router(voice_routes.voice_router)

    client = TestClient(app)

    response = client.post(
        "/voice/tts",
        json={"text": "Test"},
    )

    assert response.status_code == 503
    assert "not initialized" in response.json()["detail"]


def test_stt_invalid_base64(voice_app):
    """Test STT with invalid base64 data."""
    client = TestClient(voice_app)

    response = client.post(
        "/voice/stt",
        json={"audio_base64": "not-valid-base64!!!"},
    )

    assert response.status_code == 500


@pytest.mark.asyncio
async def test_websocket_voice_stream(voice_app, mock_stt, mock_tts):
    """Test WebSocket voice streaming."""
    from starlette.testclient import TestClient as StarletteTestClient

    client = StarletteTestClient(voice_app)

    with client.websocket_connect("/voice/stream") as websocket:
        # Send audio chunk
        audio_data = b"\x00" * 1024
        audio_b64 = base64.b64encode(audio_data).decode("utf-8")

        websocket.send_json({"type": "audio_chunk", "data": audio_b64})

        # Signal end of audio
        websocket.send_json({"type": "audio_end"})

        # Receive transcription
        msg = websocket.receive_json()
        assert msg["type"] == "transcription"
        assert msg["text"] == "Hello world"
        assert msg["is_final"] is True

        # Receive agent response
        msg = websocket.receive_json()
        assert msg["type"] == "agent_response"
        assert "Hello world" in msg["text"]

        # Receive audio chunks (there may be multiple)
        audio_chunks = []
        while True:
            msg = websocket.receive_json()
            if msg["type"] == "audio_end":
                break
            assert msg["type"] == "audio_chunk"
            assert "data" in msg
            audio_chunks.append(msg)

        assert len(audio_chunks) > 0


@pytest.mark.asyncio
async def test_websocket_ping_pong(voice_app):
    """Test WebSocket ping/pong."""
    from starlette.testclient import TestClient as StarletteTestClient

    client = StarletteTestClient(voice_app)

    with client.websocket_connect("/voice/stream") as websocket:
        websocket.send_json({"type": "ping"})
        msg = websocket.receive_json()
        assert msg["type"] == "pong"


@pytest.mark.asyncio
async def test_websocket_unknown_message(voice_app):
    """Test WebSocket with unknown message type."""
    from starlette.testclient import TestClient as StarletteTestClient

    client = StarletteTestClient(voice_app)

    with client.websocket_connect("/voice/stream") as websocket:
        websocket.send_json({"type": "unknown_type"})
        msg = websocket.receive_json()
        assert msg["type"] == "error"
        assert "Unknown message type" in msg["message"]
