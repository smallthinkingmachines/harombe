"""Example 09: Voice Assistant with Speech-to-Text and Text-to-Speech.

This example demonstrates how to build a voice-enabled AI assistant using:
- Whisper for speech-to-text (STT)
- Piper or Coqui for text-to-speech (TTS)
- Real-time audio input/output

Hardware Requirements:
- Microphone for audio input
- Speaker/headphones for audio output
- Recommended: 4GB+ VRAM for medium Whisper model
- Minimum: 2GB VRAM for base Whisper model

Usage:
    python examples/09_voice_assistant.py

Press SPACE to start recording, release to process.
Press Ctrl+C to exit.
"""

import asyncio

from harombe.agent.loop import Agent
from harombe.config.schema import HarombeConfig
from harombe.llm.ollama import OllamaClient
from harombe.tools.registry import get_tool_schemas
from harombe.voice.piper import PiperTTS
from harombe.voice.whisper import WhisperSTT


async def main() -> None:
    """Run voice assistant example."""
    # Configuration
    config = HarombeConfig(
        voice={
            "enabled": True,
            "stt": {
                "model": "base",  # Options: tiny, base, small, medium, large-v3
                "language": None,  # Auto-detect, or specify: "en", "es", etc.
                "device": "auto",  # auto, cpu, cuda, mps
            },
            "tts": {
                "engine": "piper",  # piper (fast) or coqui (high-quality)
                "model": "en_US-lessac-medium",
                "speed": 1.0,
                "device": "auto",
            },
        },
        agent={
            "max_steps": 10,
            "system_prompt": "You are a helpful voice assistant. Keep responses concise and conversational.",
        },
    )

    print("Initializing voice assistant...")
    print(f"STT Model: {config.voice.stt.model}")
    print(f"TTS Engine: {config.voice.tts.engine}")
    print()

    # Initialize STT engine
    stt_engine = WhisperSTT(
        model=config.voice.stt.model,
        device=config.voice.stt.device,
        compute_type=config.voice.stt.compute_type,
    )
    await stt_engine.initialize()

    # Initialize TTS engine
    tts_engine = PiperTTS(
        model=config.voice.tts.model,
        device=config.voice.tts.device,
    )
    await tts_engine.initialize()

    # Create LLM client and agent
    llm = OllamaClient(config=config)
    tools = get_tool_schemas()
    agent = Agent(llm=llm, config=config, tools=tools)

    print("Voice assistant ready!")
    print()
    print("Voice Interface:")
    print("  - Press and hold SPACE to record")
    print("  - Release SPACE to process speech")
    print("  - Press Ctrl+C to exit")
    print()

    # Import and run voice client
    from harombe.cli.voice import VoiceClient

    client = VoiceClient(
        stt_engine=stt_engine,
        tts_engine=tts_engine,
        agent=agent,
    )

    try:
        await client.run()
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        await stt_engine.cleanup()
        await tts_engine.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
