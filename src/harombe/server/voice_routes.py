"""Voice API routes for speech-to-text and text-to-speech."""

import base64
import contextlib
import logging
from typing import Any

from fastapi import APIRouter, HTTPException, UploadFile, WebSocket, WebSocketDisconnect
from pydantic import BaseModel

logger = logging.getLogger(__name__)

# Create router
voice_router = APIRouter(prefix="/voice", tags=["voice"])


class STTRequest(BaseModel):
    """Request for speech-to-text conversion."""

    audio_base64: str
    language: str | None = None


class STTResponse(BaseModel):
    """Response from speech-to-text conversion."""

    text: str
    language: str | None = None
    confidence: float | None = None


class TTSRequest(BaseModel):
    """Request for text-to-speech conversion."""

    text: str
    voice: str = "default"
    speed: float = 1.0


class TTSResponse(BaseModel):
    """Response from text-to-speech conversion."""

    audio_base64: str
    format: str = "wav"
    sample_rate: int


# Global instances (will be initialized by app factory)
_stt_engine: Any = None
_tts_engine: Any = None
_agent: Any = None


def init_voice_engines(stt_engine: Any, tts_engine: Any, agent: Any = None) -> None:
    """Initialize voice engines for the API.

    Args:
        stt_engine: Speech-to-text engine
        tts_engine: Text-to-speech engine
        agent: Optional agent for processing queries
    """
    global _stt_engine, _tts_engine, _agent
    _stt_engine = stt_engine
    _tts_engine = tts_engine
    _agent = agent


@voice_router.post("/stt", response_model=STTResponse)
async def speech_to_text(request: STTRequest) -> STTResponse:
    """Convert speech audio to text.

    Args:
        request: Audio data (base64 encoded) and optional language

    Returns:
        Transcription result with text and metadata
    """
    if _stt_engine is None:
        raise HTTPException(status_code=503, detail="STT engine not initialized")

    try:
        # Decode audio from base64
        audio_data = base64.b64decode(request.audio_base64)

        # Transcribe
        result = await _stt_engine.transcribe(audio_data, language=request.language)

        return STTResponse(
            text=result.text,
            language=result.language,
            confidence=result.confidence,
        )

    except Exception as e:
        logger.exception("Error in speech-to-text")
        raise HTTPException(status_code=500, detail=f"STT error: {e}") from e


@voice_router.post("/tts", response_model=TTSResponse)
async def text_to_speech(request: TTSRequest) -> TTSResponse:
    """Convert text to speech audio.

    Args:
        request: Text to synthesize with optional voice and speed

    Returns:
        Audio data (base64 encoded) with format and sample rate
    """
    if _tts_engine is None:
        raise HTTPException(status_code=503, detail="TTS engine not initialized")

    try:
        # Generate audio
        audio_data = await _tts_engine.synthesize(
            text=request.text,
            voice=request.voice,
            speed=request.speed,
        )

        # Encode to base64
        audio_base64 = base64.b64encode(audio_data).decode("utf-8")

        return TTSResponse(
            audio_base64=audio_base64,
            format="wav",
            sample_rate=_tts_engine.sample_rate,
        )

    except Exception as e:
        logger.exception("Error in text-to-speech")
        raise HTTPException(status_code=500, detail=f"TTS error: {e}") from e


@voice_router.post("/stt/file")
async def speech_to_text_file(file: UploadFile) -> STTResponse:
    """Convert uploaded audio file to text.

    Args:
        file: Audio file upload (WAV, MP3, etc.)

    Returns:
        Transcription result
    """
    if _stt_engine is None:
        raise HTTPException(status_code=503, detail="STT engine not initialized")

    try:
        # Read file
        audio_data = await file.read()

        # Transcribe
        result = await _stt_engine.transcribe(audio_data)

        return STTResponse(
            text=result.text,
            language=result.language,
            confidence=result.confidence,
        )

    except Exception as e:
        logger.exception("Error transcribing file")
        raise HTTPException(status_code=500, detail=f"STT error: {e}") from e


@voice_router.websocket("/stream")
async def voice_stream(websocket: WebSocket) -> None:
    """Bidirectional voice streaming endpoint.

    Protocol:
        Client → Server: {"type": "audio_chunk", "data": "<base64>", "format": "wav"}
        Server → Client: {"type": "transcription", "text": "...", "is_final": true}
        Server → Client: {"type": "agent_response", "text": "..."}
        Server → Client: {"type": "audio_chunk", "data": "<base64>", "format": "wav"}
    """
    await websocket.accept()

    if _stt_engine is None or _tts_engine is None:
        await websocket.send_json({"type": "error", "message": "Voice engines not initialized"})
        await websocket.close()
        return

    audio_chunks: list[bytes] = []

    try:
        while True:
            # Receive message
            data = await websocket.receive_json()
            msg_type = data.get("type")

            if msg_type == "audio_chunk":
                # Accumulate audio chunks
                audio_b64 = data.get("data", "")
                audio_data = base64.b64decode(audio_b64)
                audio_chunks.append(audio_data)

            elif msg_type == "audio_end":
                # Process accumulated audio
                if not audio_chunks:
                    await websocket.send_json({"type": "error", "message": "No audio received"})
                    continue

                # Combine chunks
                full_audio = b"".join(audio_chunks)
                audio_chunks = []

                # Transcribe
                result = await _stt_engine.transcribe(full_audio)
                transcription = result.text.strip()

                # Send transcription
                await websocket.send_json(
                    {
                        "type": "transcription",
                        "text": transcription,
                        "is_final": True,
                        "language": result.language,
                    }
                )

                if not transcription:
                    continue

                # Process with agent if available
                if _agent:
                    response_text = await _agent.run(transcription)
                else:
                    response_text = f"You said: {transcription}"

                # Send agent response
                await websocket.send_json({"type": "agent_response", "text": response_text})

                # Generate and stream TTS audio
                async for audio_chunk in _tts_engine.synthesize_stream(response_text):
                    audio_b64 = base64.b64encode(audio_chunk).decode("utf-8")
                    await websocket.send_json(
                        {
                            "type": "audio_chunk",
                            "data": audio_b64,
                            "format": "wav",
                        }
                    )

                # Signal completion
                await websocket.send_json({"type": "audio_end"})

            elif msg_type == "ping":
                await websocket.send_json({"type": "pong"})

            else:
                await websocket.send_json(
                    {"type": "error", "message": f"Unknown message type: {msg_type}"}
                )

    except WebSocketDisconnect:
        logger.info("WebSocket disconnected")
    except Exception as e:
        logger.exception("Error in voice stream")
        with contextlib.suppress(Exception):
            await websocket.send_json({"type": "error", "message": str(e)})
        await websocket.close()
