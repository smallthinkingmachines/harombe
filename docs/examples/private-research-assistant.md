# Reference Architecture: Private Research Assistant

A single Apple Silicon Mac setup for privacy-first research and analysis.

## Overview

This architecture runs entirely on a single Mac with Apple Silicon, keeping all data local. The privacy router ensures no information leaves the machine. Ideal for processing sensitive documents, internal research, or regulated data analysis.

## Hardware Requirements

| Component | Minimum       | Recommended             |
| --------- | ------------- | ----------------------- |
| Mac       | M1 Pro, 16 GB | M2 Pro/Max, 32 GB+      |
| Storage   | 20 GB free    | 50 GB free (for models) |
| macOS     | 14.0+         | 15.0+                   |

## Architecture

```
┌────────────────────────────────┐
│  macOS (Apple Silicon)         │
│                                │
│  ┌──────────────────────────┐  │
│  │  harombe chat            │  │
│  │  Privacy mode: local-only│  │
│  └──────────┬───────────────┘  │
│             │                  │
│  ┌──────────▼───────────────┐  │
│  │  Ollama (Metal GPU)      │  │
│  │  llama3.1:8b             │  │
│  │  nomic-embed-text        │  │
│  └──────────────────────────┘  │
│                                │
│  ┌──────────────────────────┐  │
│  │  ChromaDB (local)        │  │
│  │  Semantic memory + RAG   │  │
│  └──────────────────────────┘  │
│                                │
│  ┌──────────────────────────┐  │
│  │  SQLite (WAL mode)       │  │
│  │  Conversations + Audit   │  │
│  └──────────────────────────┘  │
└────────────────────────────────┘
```

## Setup

### 1. Install Ollama and Models

```bash
# Install Ollama
brew install ollama

# Pull models
ollama pull llama3.1:8b
ollama pull nomic-embed-text
```

### 2. Install Harombe

```bash
pip install harombe
harombe init
```

### 3. Configure

```yaml
# harombe.yaml

model:
  name: llama3.1:8b
  temperature: 0.3

ollama:
  host: http://localhost:11434

privacy:
  mode: local-only
  pii_detection: true
  sensitivity_threshold: 0.3

memory:
  enabled: true
  backend: sqlite
  embedding:
    model: nomic-embed-text
    provider: ollama

tools:
  shell: true
  filesystem: true
  web_search: false # No network access
  confirm_dangerous: true

voice:
  enabled: true
  stt:
    model: tiny # Fast, runs on CPU
  tts:
    engine: piper
    model: en_US-lessac-medium

agent:
  system_prompt: |
    You are a private research assistant. All processing happens locally.
    Never suggest uploading data to external services.
    When analyzing documents, summarize key findings and cite sources.
  max_steps: 15
```

## Usage

```bash
# Interactive research session
harombe chat

# With voice (push-to-talk)
harombe chat --voice

# Example prompts
You> Summarize the key findings from quarterly-report.pdf
You> Search my previous conversations about project X
You> Analyze the CSV data in sales/ and find trends
```

## Key Features

- **Zero network calls**: Privacy mode `local-only` ensures nothing leaves the machine
- **PII detection**: Catches and warns about personally identifiable information
- **Semantic memory**: Past conversations are searchable via RAG
- **Voice interface**: Whisper STT + Piper TTS, fully local
- **Audit trail**: All interactions logged in local SQLite

## Performance Tips

- Use `llama3.1:8b` for a good speed/quality balance on 16 GB machines
- On 32 GB+ machines, upgrade to `llama3.1:70b-q4_0` for better reasoning
- Keep ChromaDB collection sizes under 100K documents for fast retrieval
- Use `tiny` Whisper model for real-time voice; `small` for better accuracy
