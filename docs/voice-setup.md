# Voice Setup Guide

This guide covers setting up and using Harombe's voice features (Phase 3).

## Table of Contents

- [Overview](#overview)
- [Hardware Requirements](#hardware-requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Troubleshooting](#troubleshooting)

## Overview

Harombe's voice features enable natural spoken interaction with the AI agent using:

- **Speech-to-Text (STT)**: Whisper models (OpenAI) for transcription
- **Text-to-Speech (TTS)**: Piper (fast, local) or Coqui (high-quality) for voice synthesis
- **Push-to-Talk**: SPACE key to record audio
- **Real-time Processing**: Streaming audio input/output

## Hardware Requirements

### Minimum Requirements

- **CPU**: Multi-core processor (4+ cores recommended)
- **RAM**: 4GB available
- **VRAM**: 2GB for Whisper base model
- **Audio**: Microphone and speakers/headphones

### Recommended Configuration

- **CPU**: 8+ cores
- **RAM**: 8GB available
- **VRAM**: 4GB+ for Whisper medium model
- **GPU**: NVIDIA (CUDA) or Apple Silicon (MPS) for acceleration
- **Audio**: USB microphone or headset for better quality

### Model VRAM Requirements

| Whisper Model | VRAM | Accuracy  | Speed     |
| ------------- | ---- | --------- | --------- |
| tiny          | 1GB  | Good      | Very Fast |
| base          | 2GB  | Better    | Fast      |
| small         | 3GB  | Good      | Medium    |
| medium        | 4GB  | Very Good | Slower    |
| large-v2      | 8GB  | Excellent | Slow      |
| large-v3      | 10GB | Best      | Slowest   |

## Installation

### System Dependencies

#### macOS

```bash
# Audio libraries (usually pre-installed)
brew install portaudio
```

#### Ubuntu/Debian

```bash
sudo apt-get update
sudo apt-get install -y portaudio19-dev libsndfile1 ffmpeg
```

#### Fedora/RHEL

```bash
sudo dnf install portaudio-devel libsndfile ffmpeg
```

#### Windows

Audio drivers are typically included. If issues occur:

```powershell
# Install PortAudio via pip (bundled)
# No additional system packages needed
```

### Python Dependencies

```bash
# Already included if you installed harombe
pip install harombe

# Or install with voice extras explicitly
pip install "harombe[voice]"
```

## Configuration

### Basic Configuration

Create or edit `harombe.yaml`:

```yaml
voice:
  enabled: true

  stt:
    model: base # Whisper model size
    language: null # Auto-detect language
    device: auto # auto, cpu, cuda, mps
    compute_type: default # default, int8, float16, float32

  tts:
    engine: piper # piper or coqui
    model: en_US-lessac-medium
    speed: 1.0
    device: auto
```

### STT Configuration Options

**model**: Whisper model size

- `tiny`: 39M params, 1GB VRAM, fastest
- `base`: 74M params, 2GB VRAM, good balance
- `small`: 244M params, 3GB VRAM
- `medium`: 769M params, 4GB VRAM, recommended
- `large-v2`: 1550M params, 8GB VRAM
- `large-v3`: 1550M params, 10GB VRAM, most accurate

**language**: Language code (ISO 639-1)

- `null`: Auto-detect language
- `"en"`: English
- `"es"`: Spanish
- `"fr"`: French
- `"de"`: German
- `"zh"`: Chinese
- See [Whisper docs](https://github.com/openai/whisper) for full list

**device**: Compute device

- `"auto"`: Auto-select (CUDA > MPS > CPU)
- `"cpu"`: Force CPU (slower)
- `"cuda"`: NVIDIA GPU
- `"mps"`: Apple Silicon GPU

**compute_type**: Precision mode

- `"default"`: Auto-select based on device
- `"int8"`: Integer quantization (faster, less accurate)
- `"float16"`: Half precision (good balance)
- `"float32"`: Full precision (slower, most accurate)

### TTS Configuration Options

**engine**: TTS backend

- `"piper"`: Fast, local, neural TTS (recommended for real-time)
- `"coqui"`: High-quality, slower (better for production audio)

**Piper Models** (engine: piper):

- `en_US-lessac-medium`: Male voice, high quality
- `en_US-amy-medium`: Female voice, high quality
- `en_US-lessac-low`: Male voice, faster
- `en_GB-southern_english_female-medium`: British female

**Coqui Models** (engine: coqui):

- `tts_models/en/ljspeech/tacotron2-DDC`: High quality
- `tts_models/en/vctk/vits`: Multi-speaker
- `tts_models/multilingual/multi-dataset/your_tts`: Multilingual

**speed**: Speech rate multiplier

- `0.5`: Half speed (clearer for transcription)
- `1.0`: Normal speed (default)
- `1.5`: 50% faster
- `2.0`: Double speed (maximum)

## Usage

### CLI Voice Mode

```bash
# Start voice assistant
harombe voice

# With custom STT model
harombe voice --stt-model medium

# With different TTS engine
harombe voice --tts-engine coqui --tts-model tts_models/en/ljspeech/tacotron2-DDC
```

**Controls:**

- **SPACE**: Press and hold to record, release to process
- **Ctrl+C**: Exit voice mode

### Programmatic Usage

```python
import asyncio
from harombe.agent.loop import Agent
from harombe.config.schema import HarombeConfig
from harombe.llm.ollama import OllamaClient
from harombe.voice.whisper import WhisperSTT
from harombe.voice.piper import PiperTTS
from harombe.cli.voice import VoiceClient

async def main():
    # Configuration
    config = HarombeConfig(
        voice={
            "enabled": True,
            "stt": {"model": "base", "language": "en"},
            "tts": {"engine": "piper", "model": "en_US-lessac-medium"},
        }
    )

    # Initialize engines
    stt = WhisperSTT(model="base")
    await stt.initialize()

    tts = PiperTTS(model="en_US-lessac-medium")
    await tts.initialize()

    # Create agent
    llm = OllamaClient(config=config)
    agent = Agent(llm=llm, config=config)

    # Run voice client
    client = VoiceClient(stt_engine=stt, tts_engine=tts, agent=agent)
    await client.run()

asyncio.run(main())
```

See [`examples/09_voice_assistant.py`](../examples/09_voice_assistant.py) for a complete example.

### API Endpoints

Voice features are available via REST and WebSocket APIs:

**REST Endpoints:**

```bash
# Speech-to-text (base64 audio)
curl -X POST http://localhost:8000/voice/stt \
  -H "Content-Type: application/json" \
  -d '{"audio_base64": "...", "language": "en"}'

# Text-to-speech
curl -X POST http://localhost:8000/voice/tts \
  -H "Content-Type: application/json" \
  -d '{"text": "Hello world", "voice": "default", "speed": 1.0}'

# Upload audio file
curl -X POST http://localhost:8000/voice/stt/file \
  -F "file=@recording.wav"
```

**WebSocket Streaming:**

```javascript
const ws = new WebSocket("ws://localhost:8000/voice/stream");

// Send audio chunk
ws.send(
  JSON.stringify({
    type: "audio_chunk",
    data: base64AudioData,
    format: "wav",
  }),
);

// Signal end of audio
ws.send(JSON.stringify({ type: "audio_end" }));

// Receive transcription
ws.onmessage = (event) => {
  const msg = JSON.parse(event.data);
  if (msg.type === "transcription") {
    console.log("Transcribed:", msg.text);
  } else if (msg.type === "audio_chunk") {
    // Play audio chunk
    playAudio(msg.data);
  }
};
```

## Troubleshooting

### Audio Input Issues

**Microphone not detected:**

```bash
# macOS: Check System Settings > Privacy & Security > Microphone
# Linux: List audio devices
arecord -l

# Test microphone
python -c "import sounddevice as sd; print(sd.query_devices())"
```

**Permission denied:**

```bash
# macOS: Grant microphone permission in System Settings
# Linux: Add user to audio group
sudo usermod -a -G audio $USER
# Log out and back in
```

### VRAM / OOM Errors

**Reduce model size:**

```yaml
voice:
  stt:
    model: base # Switch from medium to base
    compute_type: int8 # Use quantization
```

**Force CPU:**

```yaml
voice:
  stt:
    device: cpu # Disable GPU acceleration
```

### Audio Quality Issues

**Improve STT accuracy:**

```yaml
voice:
  stt:
    model: medium # Use larger model
    language: en # Specify language (don't auto-detect)
```

**Improve TTS quality:**

```yaml
voice:
  tts:
    engine: coqui # Switch from piper to coqui
    model: tts_models/en/ljspeech/tacotron2-DDC
    speed: 0.9 # Slightly slower for clarity
```

### Common Errors

**"No module named 'sounddevice'":**

```bash
pip install sounddevice
```

**"PortAudio library not found":**

```bash
# macOS
brew install portaudio

# Ubuntu/Debian
sudo apt-get install portaudio19-dev

# Then reinstall sounddevice
pip uninstall sounddevice
pip install sounddevice
```

**"CUDA out of memory":**

Use smaller model or CPU:

```yaml
voice:
  stt:
    model: base # or tiny
    device: cpu
```

### Performance Optimization

**For real-time interaction:**

```yaml
voice:
  stt:
    model: base # Fast transcription
    compute_type: int8 # Quantization
  tts:
    engine: piper # Fast synthesis
```

**For best quality:**

```yaml
voice:
  stt:
    model: large-v3 # Most accurate
    compute_type: float16
  tts:
    engine: coqui
    model: tts_models/en/ljspeech/tacotron2-DDC
```

## Next Steps

- See [voice-architecture.md](voice-architecture.md) for technical details
- Check [examples/09_voice_assistant.py](../examples/09_voice_assistant.py) for code examples
- Read [API documentation](README.md) for endpoint reference
