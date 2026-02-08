# harombe

**Declarative self-hosted AI assistant platform**

harombe is an open source platform that orchestrates heterogeneous consumer hardware into a unified, tool-using AI system. Think "Terraform for self-hosted AI."

> **⚠️ Security Notice**
>
> harombe can execute shell commands and modify files on your system. While dangerous operations require confirmation by default, you should:
> - Review what the AI plans to do before approving
> - Run harombe in sandboxed environments (Docker, VMs) when testing
> - Keep `confirm_dangerous: true` in your configuration
> - Understand that LLM outputs can be unpredictable
>
> See [SECURITY.md](SECURITY.md) for detailed security guidance.

## Why harombe?

Currently, there's no open source project that combines:

1. **Distributed inference** across mixed hardware (Apple Silicon, NVIDIA, AMD, CPU)
2. **Agent loop** with tool calling and memory
3. **Declarative cluster configuration** via YAML

harombe fills this gap by providing a batteries-included AI assistant that you can run on your own hardware, with zero cloud dependencies.

## Phase 0: Weekend MVP ✅

This initial release provides a working single-machine AI assistant with:

- ✅ Tool calling (shell, filesystem, web search)
- ✅ ReAct agent loop (~300 LOC)
- ✅ Hardware auto-detection and model selection
- ✅ Interactive CLI chat interface
- ✅ REST API with SSE streaming
- ✅ Zero-config deployment

## Quick Start

### Prerequisites

- Python 3.11+
- [Ollama](https://ollama.ai) installed and running

### Installation

```bash
# Install Harombe
pip install harombe

# Initialize configuration (detects your hardware)
harombe init

# Pull recommended model
ollama pull qwen2.5:7b  # or whatever model was recommended

# Start chatting!
harombe chat
```

That's it! You should be up and running in under 5 minutes.

## Usage

### Interactive Chat

```bash
harombe chat
```

Chat commands:
- `/help` - Show available commands
- `/model` - Show current model info
- `/tools` - List enabled tools
- `/exit` - Exit chat

### API Server

```bash
# Start server
harombe start

# In another terminal, test it
curl http://localhost:8000/health

# Send a chat message
curl -X POST http://localhost:8000/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "Hello!"}'
```

### Configuration

Configuration is stored at `~/.harombe/harombe.yaml`. Here's an example:

```yaml
model:
  name: qwen2.5:7b
  quantization: Q4_K_M
  context_length: 8192
  temperature: 0.7

ollama:
  host: http://localhost:11434
  timeout: 120

agent:
  max_steps: 10
  system_prompt: "You are Harombe, a helpful AI assistant..."

tools:
  shell: true
  filesystem: true
  web_search: true
  confirm_dangerous: true

server:
  host: 127.0.0.1
  port: 8000
```

All fields have sensible defaults - you can run with an empty config file or no config at all!

## Architecture

```
┌─────────────────────────────────────────────┐
│              CLI / API Server               │
├─────────────────────────────────────────────┤
│            ReAct Agent Loop                 │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  │
│  │   LLM    │  │  Tools   │  │  Memory  │  │
│  │ (Ollama) │  │ Registry │  │  (TODO)  │  │
│  └──────────┘  └──────────┘  └──────────┘  │
├─────────────────────────────────────────────┤
│         Hardware Abstraction Layer          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  │
│  │  Apple   │  │  NVIDIA  │  │   AMD    │  │
│  │ Silicon  │  │   GPU    │  │   GPU    │  │
│  └──────────┘  └──────────┘  └──────────┘  │
└─────────────────────────────────────────────┘
```

### Key Components

**Agent Loop** (`src/harombe/agent/loop.py`)
- ReAct-style reasoning loop
- Tool calling with dangerous operation confirmation
- Configurable max steps to prevent infinite loops

**LLM Client** (`src/harombe/llm/ollama.py`)
- OpenAI SDK pointed at Ollama's OpenAI-compatible endpoint
- Supports function calling / tool use
- Easy to swap for cloud providers

**Tool System** (`src/harombe/tools/`)
- Decorator-based tool registration
- Automatic JSON Schema generation from type hints
- Built-in tools: shell, filesystem, web search

**Hardware Detection** (`src/harombe/hardware/detect.py`)
- Auto-detects Apple Silicon, NVIDIA, AMD GPUs
- Recommends model based on available VRAM
- Conservative memory allocation

## Troubleshooting

### Ollama Not Running

If you see errors about connecting to Ollama:

```bash
# Start Ollama server
ollama serve

# In another terminal, verify it's running
curl http://localhost:11434/api/tags
```

### Model Not Found

If harombe can't find your model:

```bash
# List available models
ollama list

# Pull a model (recommended: qwen2.5:7b)
ollama pull qwen2.5:7b

# Update your config
nano ~/.harombe/harombe.yaml  # Change model.name
```

### Installation Issues

```bash
# Ensure Python 3.11+ is installed
python3 --version

# Upgrade pip
pip install --upgrade pip

# Reinstall harombe
pip install --force-reinstall harombe
```

### Permission Errors

If you get permission errors during tool execution:

1. Check that `confirm_dangerous: true` in your config
2. Review the operation before approving
3. Consider running in a sandboxed environment

### Getting Help

- Check existing [Issues](https://github.com/smallthinkingmachines/harombe/issues)
- Start a [Discussion](https://github.com/smallthinkingmachines/harombe/discussions)
- Review the [Security Policy](SECURITY.md) for security concerns

## Development

### With Nix (Recommended)

```bash
# Clone the repo
git clone https://github.com/harombe/harombe.git
cd harombe

# Enter dev environment (direnv auto-activates)
direnv allow

# Run tests
pytest

# Lint
ruff check src tests

# Type check
mypy src
```

### Without Nix

```bash
# Clone and install
git clone https://github.com/harombe/harombe.git
cd harombe
pip install -e ".[dev]"

# Run tests
pytest
```

## Roadmap

### Phase 1: Multi-Machine Coordination (Q1 2026)
- mDNS service discovery
- Distributed inference across multiple machines
- Load balancing and failover

### Phase 2: Privacy & Memory (Q2 2026)
- Privacy router with PII detection
- Long-term memory with vector store
- Conversation history management

### Phase 3: Voice & Multimodal (Q3 2026)
- Speech-to-text / text-to-speech
- Image understanding
- Video processing

## Contributing

Contributions welcome! Please read our [contributing guidelines](CONTRIBUTING.md) first.

## License

Apache 2.0 - see [LICENSE](LICENSE)

## Credits

A Small Thinking Machines project.

Born from lessons learned building Baldwin (llama.cpp + GGUF on DGX Spark).

Built with:
- [Ollama](https://ollama.ai) - Local LLM inference
- [OpenAI SDK](https://github.com/openai/openai-python) - LLM client
- [Typer](https://typer.tiangolo.com) - CLI framework
- [FastAPI](https://fastapi.tiangolo.com) - API server
- [Rich](https://rich.readthedocs.io) - Terminal UI
- [Pydantic](https://docs.pydantic.dev) - Configuration validation

## Support

- [Documentation](https://github.com/smallthinkingmachines/harombe#readme)
- [Issues](https://github.com/smallthinkingmachines/harombe/issues)
- [Discussions](https://github.com/smallthinkingmachines/harombe/discussions)
