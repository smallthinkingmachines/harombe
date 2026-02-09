"""Voice client CLI for interactive voice conversations.

Push-to-talk interface with real-time audio capture and playback.
"""

import asyncio
import logging
import wave
from io import BytesIO
from typing import Any

from rich.console import Console
from rich.panel import Panel

logger = logging.getLogger(__name__)

# Audio configuration
SAMPLE_RATE = 16000  # 16kHz for Whisper
CHANNELS = 1  # Mono
CHUNK_SIZE = 1024
FORMAT_WIDTH = 2  # 16-bit audio


class VoiceClient:
    """Interactive voice client with push-to-talk interface."""

    def __init__(
        self,
        stt_engine: Any,
        tts_engine: Any,
        agent: Any = None,
    ) -> None:
        """Initialize voice client.

        Args:
            stt_engine: Speech-to-text engine
            tts_engine: Text-to-speech engine
            agent: Optional agent for processing queries
        """
        self._stt = stt_engine
        self._tts = tts_engine
        self._agent = agent
        self._console = Console()
        self._recording = False
        self._audio_chunks: list[bytes] = []
        self._tasks: set[Any] = set()  # Track background tasks

    async def run(self) -> None:
        """Run the interactive voice client."""
        try:
            import sounddevice as sd  # type: ignore[import-not-found]
        except ImportError as e:
            msg = "sounddevice not installed. Install with: pip install sounddevice"
            raise ImportError(msg) from e

        self._console.print(
            Panel.fit(
                "[bold cyan]🎤 Voice Assistant Mode[/bold cyan]\n"
                "Press [bold yellow]SPACE[/bold yellow] to talk, "
                "[bold red]ESC[/bold red] to exit",
                border_style="cyan",
            )
        )

        # Start keyboard listener in separate thread
        from pynput import keyboard  # type: ignore[import-untyped]

        def on_press(key: Any) -> None:
            if key == keyboard.Key.space and not self._recording:
                self._recording = True
                self._audio_chunks = []
                self._console.print("\n[bold red]● Recording...[/bold red]")

        def on_release(key: Any) -> bool | None:
            if key == keyboard.Key.esc:
                return False  # Stop listener
            if key == keyboard.Key.space and self._recording:
                self._recording = False
                # Trigger processing in async context
                task = asyncio.create_task(self._process_recording())
                self._tasks.add(task)
                task.add_done_callback(self._tasks.discard)
            return None

        # Audio callback
        def audio_callback(indata: Any, frames: Any, time: Any, status: Any) -> None:
            if status:
                logger.warning(f"Audio callback status: {status}")
            if self._recording:
                # Convert to bytes
                self._audio_chunks.append(indata.tobytes())

        # Start audio stream
        with (
            sd.InputStream(
                samplerate=SAMPLE_RATE,
                channels=CHANNELS,
                dtype="int16",
                callback=audio_callback,
                blocksize=CHUNK_SIZE,
            ),
            keyboard.Listener(on_press=on_press, on_release=on_release) as listener,
        ):
            self._console.print("\n[bold green]✓ Ready[/bold green]")
            listener.join()

        self._console.print("\n[yellow]Voice assistant stopped[/yellow]")

    async def _process_recording(self) -> None:
        """Process recorded audio through STT → Agent → TTS pipeline."""
        if not self._audio_chunks:
            self._console.print("[yellow]No audio recorded[/yellow]")
            return

        try:
            # Convert chunks to WAV format
            audio_data = self._chunks_to_wav(self._audio_chunks)

            # Transcribe
            self._console.print("[cyan]Transcribing...[/cyan]")
            result = await self._stt.transcribe(audio_data)
            transcription = result.text.strip()

            if not transcription:
                self._console.print("[yellow]No speech detected[/yellow]")
                return

            self._console.print(f'[bold]You:[/bold] "{transcription}"')

            # Process with agent if available
            if self._agent:
                self._console.print("[cyan]Agent processing...[/cyan]")
                response = await self._agent.run(transcription)
                response_text = response
            else:
                # Echo mode if no agent
                response_text = f"You said: {transcription}"

            self._console.print(f"[bold]Assistant:[/bold] {response_text}")

            # Generate speech
            self._console.print("[cyan]Generating speech...[/cyan]")
            audio = await self._tts.synthesize(response_text)

            # Play audio
            self._console.print("[green]🔊 Playing audio...[/green]")
            await self._play_audio(audio)

            self._console.print("\n[bold green]✓ Ready[/bold green]")

        except Exception as e:
            self._console.print(f"[bold red]Error:[/bold red] {e}")
            logger.exception("Error processing recording")

    def _chunks_to_wav(self, chunks: list[bytes]) -> bytes:
        """Convert audio chunks to WAV format.

        Args:
            chunks: List of raw audio byte chunks

        Returns:
            Complete WAV file as bytes
        """
        # Combine all chunks
        audio_data = b"".join(chunks)

        # Create WAV file in memory
        wav_buffer = BytesIO()
        with wave.open(wav_buffer, "wb") as wav_file:
            wav_file.setnchannels(CHANNELS)
            wav_file.setsampwidth(FORMAT_WIDTH)
            wav_file.setframerate(SAMPLE_RATE)
            wav_file.writeframes(audio_data)

        return wav_buffer.getvalue()

    async def _play_audio(self, audio_data: bytes) -> None:
        """Play audio through speakers.

        Args:
            audio_data: WAV file data
        """
        try:
            import numpy as np
            import sounddevice as sd
        except ImportError as e:
            msg = "sounddevice/numpy not installed"
            raise ImportError(msg) from e

        # Parse WAV file
        with wave.open(BytesIO(audio_data), "rb") as wav_file:
            sample_rate = wav_file.getframerate()
            audio_frames = wav_file.readframes(wav_file.getnframes())

            # Convert to numpy array
            audio_array = np.frombuffer(audio_frames, dtype=np.int16)

            # Normalize to float32
            audio_normalized = audio_array.astype(np.float32) / 32768.0

            # Play audio
            sd.play(audio_normalized, samplerate=sample_rate)
            sd.wait()  # Wait until audio finishes


async def voice_command(
    stt_model: str = "medium",
    tts_engine: str = "piper",
    tts_model: str = "en_US-lessac-medium",
) -> None:
    """Run voice client from CLI.

    Args:
        stt_model: Whisper model size (tiny/base/small/medium/large-v3)
        tts_engine: TTS engine to use (piper/coqui)
        tts_model: TTS model name
    """
    console = Console()

    try:
        # Import engines
        from harombe.voice.whisper import WhisperSTT

        tts_instance: Any
        if tts_engine == "piper":
            from harombe.voice.piper import PiperTTS

            tts_instance = PiperTTS(model=tts_model)
        elif tts_engine == "coqui":
            from harombe.voice.coqui import CoquiTTS

            tts_instance = CoquiTTS(model_name=tts_model)
        else:
            console.print(f"[red]Unknown TTS engine: {tts_engine}[/red]")
            return

        stt = WhisperSTT(model_size=stt_model)  # type: ignore[arg-type]

        # TODO: Initialize agent from config
        agent = None

        # Run client
        client = VoiceClient(stt_engine=stt, tts_engine=tts_instance, agent=agent)
        await client.run()

    except ImportError as e:
        console.print(f"[bold red]Import error:[/bold red] {e}")
        console.print("\nInstall voice dependencies:")
        console.print("  pip install sounddevice pynput faster-whisper piper-tts")
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted[/yellow]")
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        logger.exception("Voice client error")
