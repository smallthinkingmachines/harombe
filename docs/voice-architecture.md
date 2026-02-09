# Voice & Multi-Modal Architecture (Phase 3)

## Overview

Phase 3 extends harombe with voice capabilities, enabling natural voice-based interaction with the AI assistant. This phase implements speech-to-text (STT), text-to-speech (TTS), and a voice client interface.

## Goals

1. **Natural interaction** - Enable conversational voice interface
2. **Low latency** - < 1s end-to-end response time for simple queries
3. **Privacy-first** - All voice processing runs locally, no cloud APIs
4. **Resource efficient** - Target 24GB VRAM for full voice pipeline
5. **Progressive feedback** - Stream audio and provide updates during tool execution

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Voice Client (CLI/App)                       │
│  - Microphone capture                                           │
│  - Push-to-talk interface                                       │
│  - Audio playback                                               │
│  - Visual feedback                                              │
└───────────┬─────────────────────────────────────────────────────┘
            │ Audio stream (WebSocket)
            ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Voice Service (Alienware)                    │
│  ┌──────────────────┐          ┌──────────────────┐            │
│  │  Whisper STT     │          │   TTS Engine     │            │
│  │  - Medium/Large  │          │   - Coqui/Piper  │            │
│  │  - Real-time     │          │   - Voice cloning│            │
│  │  - Multi-lang    │          │   - Streaming    │            │
│  └────────┬─────────┘          └────────▲─────────┘            │
│           │                              │                      │
└───────────┼──────────────────────────────┼──────────────────────┘
            │ Text                         │ Text
            ▼                              │
┌─────────────────────────────────────────┼──────────────────────┐
│                Agent Service (DGX)       │                      │
│  - Process transcribed text              │                      │
│  - Execute tools                         │                      │
│  - Generate response                     │                      │
│  - Send text to TTS ─────────────────────┘                      │
└─────────────────────────────────────────────────────────────────┘
```

## Hardware Allocation

Based on the strategic plan, voice processing is allocated to specific hardware:

| Machine   | VRAM  | Role                          |
| --------- | ----- | ----------------------------- |
| Alienware | 24GB  | Voice processing (STT + TTS)  |
| DGX Spark | 128GB | Agent loop, LLM inference     |
| Mac Mini  | 64GB  | Development, testing, gateway |

**Voice path:** Alienware (STT) → DGX (agent) → Alienware (TTS)

## Component Design

### 1. Speech-to-Text (Whisper)

**Model Selection:**

- **whisper-medium** (1.5GB VRAM) - Recommended default, good accuracy/speed balance
- **whisper-large-v3** (3GB VRAM) - Maximum accuracy for important use cases
- **whisper-tiny** (400MB VRAM) - Ultra-fast for low-latency needs

**Implementation Options:**

1. **faster-whisper** (Recommended)
   - CTranslate2-based, 4x faster than OpenAI Whisper
   - Lower VRAM usage
   - Streaming support
   - CPU/GPU inference

2. **whisper.cpp**
   - C++ implementation, very fast
   - Lower memory footprint
   - Good for CPU-only systems

**Features:**

- Automatic language detection
- Timestamp generation for word-level alignment
- Streaming transcription for real-time feedback
- VAD (Voice Activity Detection) for automatic segmentation

**API:**

```python
class WhisperSTT:
    async def transcribe(
        self,
        audio: bytes,
        language: str | None = None,
    ) -> TranscriptionResult:
        """Transcribe audio to text."""

    async def transcribe_stream(
        self,
        audio_stream: AsyncIterator[bytes],
    ) -> AsyncIterator[str]:
        """Stream transcription in real-time."""
```

### 2. Text-to-Speech (TTS)

**Engine Options:**

1. **Coqui TTS** (Recommended for quality)
   - Open source, high quality
   - Voice cloning support
   - Multiple languages
   - ~2-3GB VRAM
   - Latency: 500ms-1s for short sentences

2. **Piper** (Recommended for speed)
   - Ultra-fast inference
   - Good quality
   - Low resource usage (~1GB VRAM)
   - Latency: 100-300ms

3. **Kokoro** (Alternative)
   - New, promising quality
   - Relatively fast
   - Good for specific voices

**Decision factors:**

- **Quality priority** → Coqui TTS
- **Speed priority** → Piper
- **Voice variety** → Coqui TTS

**API:**

```python
class TTSEngine:
    async def synthesize(
        self,
        text: str,
        voice: str = "default",
        speed: float = 1.0,
    ) -> bytes:
        """Convert text to audio."""

    async def synthesize_stream(
        self,
        text: str,
        voice: str = "default",
        speed: float = 1.0,
    ) -> AsyncIterator[bytes]:
        """Stream audio generation."""
```

### 3. Voice Client

**Interface Modes:**

1. **Push-to-talk** (Phase 3.0)
   - Hold spacebar to record
   - Release to send
   - Immediate visual feedback
   - Simple, reliable

2. **Wake word** (Phase 3.1 - Future)
   - "Hey Harombe" or custom phrase
   - Always-listening mode
   - Requires wake word detection model
   - Privacy considerations

**CLI Interface:**

```bash
$ harombe voice
🎤 Voice Assistant Mode
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Press [SPACE] to talk, [ESC] to exit

[Ready]

[Recording...] ●

[Transcribing...] "What's the weather like today?"

[Agent processing...] 🔧 Using web_search tool

[Responding...] "The weather in San Francisco..."

[Audio playing...] 🔊

[Ready]
```

**Features:**

- Real-time waveform visualization
- Transcription display
- Tool execution feedback
- Progress indicators
- Error handling with voice feedback

### 4. Voice API Endpoints

**REST Endpoints:**

```
POST   /voice/stt           - Upload audio file, get transcription
POST   /voice/tts           - Convert text to audio
```

**WebSocket Endpoint:**

```
WS     /voice/stream        - Bidirectional streaming
```

**WebSocket Protocol:**

```json
// Client → Server (audio chunks)
{
  "type": "audio_chunk",
  "data": "<base64-encoded-audio>",
  "format": "wav",
  "sample_rate": 16000
}

// Server → Client (transcription)
{
  "type": "transcription",
  "text": "partial transcription...",
  "is_final": false
}

// Server → Client (agent response)
{
  "type": "agent_response",
  "text": "Let me check that for you.",
  "tool_calls": ["web_search"]
}

// Server → Client (audio response)
{
  "type": "audio_chunk",
  "data": "<base64-encoded-audio>",
  "format": "wav"
}
```

## Data Flow

### Request Flow (Voice → Response)

```
1. User speaks → Microphone capture
   ↓
2. Audio chunks → WebSocket stream → Voice Service
   ↓
3. Whisper STT → Transcription (streaming)
   ↓
4. Text → Agent Service (DGX)
   ↓
5. Agent processes:
   a. Loads conversation history
   b. Routes through LLM
   c. Executes tools if needed
   d. Generates response text
   ↓
6. Response text → Voice Service
   ↓
7. TTS Engine → Audio (streaming)
   ↓
8. Audio chunks → WebSocket → Voice Client
   ↓
9. Speaker playback → User hears response
```

### Progressive Feedback

During long-running tool execution:

```
User: "Search for recent AI papers and summarize the top 3"

[Transcribing...] ✓ "Search for recent AI papers..."

[Agent] 🔧 Using web_search tool
        [Status] Searching arXiv...

[Agent] 📄 Processing 3 papers...

[Agent] ✓ Summary ready

[Responding...] "I found three interesting papers..."
[Audio playing...] 🔊
```

## Configuration

```yaml
voice:
  enabled: true

  # Speech-to-Text
  stt:
    engine: faster-whisper # or whisper.cpp
    model: medium # tiny, base, small, medium, large-v3
    device: cuda # cuda, cpu
    language: auto # auto-detect or specific (en, es, fr, etc.)
    compute_type: float16 # float16, int8, float32

  # Text-to-Speech
  tts:
    engine: coqui # coqui, piper, kokoro
    model: tts_models/en/vctk/vits # Coqui model path
    voice: default # Voice name or ID
    speed: 1.0 # 0.5-2.0
    device: cuda

  # Client settings
  client:
    mode: push-to-talk # push-to-talk, wake-word
    sample_rate: 16000
    chunk_duration_ms: 30 # Audio chunk size
    vad_enabled: true # Voice activity detection
```

## Performance Targets

| Metric                     | Target  | Measured On |
| -------------------------- | ------- | ----------- |
| STT latency (medium)       | < 500ms | Alienware   |
| TTS latency (short phrase) | < 1s    | Alienware   |
| End-to-end (simple query)  | < 3s    | Full path   |
| Memory usage (STT + TTS)   | < 8GB   | Alienware   |
| Audio quality              | 48kHz   | Client      |

## Dependencies

**Core:**

- `faster-whisper` - Optimized Whisper inference
- `TTS` (Coqui) - Text-to-speech engine
- `pyaudio` or `sounddevice` - Audio I/O
- `websockets` - Real-time streaming

**Optional:**

- `webrtcvad` - Voice activity detection
- `pydub` - Audio format conversion
- `numpy` - Audio processing utilities

## Testing Strategy

1. **Unit tests:**
   - STT transcription accuracy (sample audio files)
   - TTS audio generation (output format validation)
   - Audio format conversion

2. **Integration tests:**
   - End-to-end voice → response → audio
   - WebSocket streaming
   - Error handling (disconnects, timeouts)

3. **Performance tests:**
   - Latency measurements at each stage
   - Memory usage under load
   - Concurrent voice sessions

4. **Quality tests:**
   - Transcription Word Error Rate (WER)
   - TTS Mean Opinion Score (MOS) - subjective
   - Multi-language support

## File Structure

```
src/harombe/voice/
├── __init__.py
├── stt.py              # Speech-to-text abstraction
├── whisper.py          # Whisper implementation
├── tts.py              # Text-to-speech abstraction
├── coqui.py            # Coqui TTS implementation
├── piper.py            # Piper TTS implementation
├── client.py           # Voice client logic
└── stream.py           # WebSocket streaming handler

src/harombe/cli/
└── voice.py            # Voice CLI command

src/harombe/server/
└── voice_routes.py     # Voice API endpoints

tests/voice/
├── __init__.py
├── test_stt.py
├── test_tts.py
├── test_client.py
├── test_stream.py
└── fixtures/           # Sample audio files
    ├── test_en.wav
    ├── test_es.wav
    └── test_fr.wav
```

## Implementation Phases

### Phase 3.0: Foundation (Current)

- [x] Design architecture (this document)
- [ ] Implement Whisper STT integration
- [ ] Implement TTS engine (Coqui or Piper)
- [ ] Build voice client CLI (push-to-talk)
- [ ] Add voice API endpoints
- [ ] Configuration and documentation

### Phase 3.1: Enhancement (Future)

- [ ] Wake word detection
- [ ] Voice activity detection
- [ ] Multi-speaker support
- [ ] Voice cloning (custom voices)
- [ ] Multi-language optimization

### Phase 3.2: Multi-Modal (Future)

- [ ] Vision support (image input)
- [ ] Screen sharing analysis
- [ ] Video processing
- [ ] Multi-modal reasoning

## Security Considerations

1. **Audio privacy**
   - All processing runs locally
   - No audio sent to cloud
   - Optionally disable audio logging

2. **Resource isolation**
   - Voice service runs on dedicated hardware
   - Resource limits to prevent OOM
   - Rate limiting on API endpoints

3. **Input validation**
   - Audio format validation
   - File size limits
   - Sample rate restrictions

## Future Enhancements

1. **Voice profiles** - User-specific voice recognition
2. **Emotion detection** - Analyze voice tone for context
3. **Noise cancellation** - Improved audio preprocessing
4. **Multi-speaker diarization** - Identify different speakers
5. **Real-time translation** - Speak in one language, respond in another
6. **Voice commands** - System control via voice ("pause", "repeat", "louder")

## References

- [faster-whisper documentation](https://github.com/guillaumekln/faster-whisper)
- [Coqui TTS](https://github.com/coqui-ai/TTS)
- [Piper TTS](https://github.com/rhasspy/piper)
- [whisper.cpp](https://github.com/ggerganov/whisper.cpp)
- [WebRTC VAD](https://github.com/wiseman/py-webrtcvad)
