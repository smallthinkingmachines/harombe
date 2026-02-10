# Quick Start

Get up and running with Harombe in 5 minutes.

## Prerequisites

- Python 3.11, 3.12, or 3.13
- [Ollama](https://ollama.ai) installed and running
- Git

## Installation

```bash
# Clone repository
git clone https://github.com/smallthinkingmachines/harombe.git
cd harombe

# Install
pip install -e ".[dev]"
```

## Configuration

Initialize harombe (detects your hardware and recommends a model):

```bash
harombe init

# Pull the recommended model
ollama pull qwen2.5:7b
```

## Your First Agent

### Interactive Chat

Start an interactive chat session:

```bash
harombe chat
```

Example interaction:

```
You: Hello! What can you help me with?
Agent: I'm Harombe, your AI assistant. I can help you with:
- Code execution (in secure sandboxes)
- File operations
- Web searches
- Complex reasoning tasks
- And much more!

What would you like to do?

You: What's the capital of France?
Agent: The capital of France is Paris.

You: exit
```

### Programmatic Usage (Ollama — Local)

Create a simple Python script:

```python
# example.py
import asyncio
from harombe.agent.loop import Agent
from harombe.llm.ollama import OllamaClient
from harombe.tools.registry import get_enabled_tools

async def main():
    # Create a local LLM client via Ollama
    llm = OllamaClient(model="qwen2.5:7b")
    tools = get_enabled_tools(shell=True, filesystem=True, web_search=True)

    # Create the agent
    agent = Agent(
        llm=llm,
        tools=tools,
        system_prompt="You are a helpful assistant.",
    )

    # Send a message
    response = await agent.run("What is 2 + 2?")
    print(f"Agent: {response}")

if __name__ == "__main__":
    asyncio.run(main())
```

Run it:

```bash
python example.py
```

### Alternative: Cloud LLM (Anthropic)

If you prefer to use a cloud provider instead of local inference, harombe also supports Anthropic's Claude:

```bash
# Set your API key
export ANTHROPIC_API_KEY=sk-ant-your-key-here
```

```python
# example_cloud.py
import asyncio
from harombe.agent.runtime import AgentRuntime
from harombe.agent.config import AgentConfig

async def main():
    config = AgentConfig(
        name="MyAgent",
        model="claude-sonnet-4-5-20250929",
        max_iterations=10,
    )

    runtime = AgentRuntime(config)
    response = await runtime.run("What is 2 + 2?")
    print(f"Agent: {response.final_answer}")

if __name__ == "__main__":
    asyncio.run(main())
```

## Enable Memory (Optional)

Harombe supports semantic memory with RAG:

```python
import asyncio
from harombe.agent.loop import Agent
from harombe.llm.ollama import OllamaClient
from harombe.memory.manager import MemoryManager
from harombe.tools.registry import get_enabled_tools

async def main():
    # Create memory manager
    memory = MemoryManager(
        storage_path="~/.harombe/memory.db",
        max_history_tokens=4096,
    )

    # Create or get session
    session_id, created = memory.get_or_create_session(
        session_id="my-conversation",
        system_prompt="You are a helpful assistant.",
    )

    llm = OllamaClient(model="qwen2.5:7b")
    tools = get_enabled_tools(shell=True, filesystem=True)

    agent = Agent(
        llm=llm,
        tools=tools,
        memory_manager=memory,
        session_id=session_id,
    )

    # First interaction - store info
    await agent.run("My favorite color is blue.")

    # Second interaction - recall info
    response = await agent.run("What's my favorite color?")
    print(f"Agent: {response}")

if __name__ == "__main__":
    asyncio.run(main())
```

## Enable Security Features (Optional)

For production deployments, enable security features:

### 1. Setup Docker + gVisor

```bash
# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Install gVisor
# See installation guide for details
```

### 2. Setup Vault

```bash
# Install Vault
brew install vault  # macOS
# or
sudo apt install vault  # Linux

# Start Vault dev server
vault server -dev
```

### 3. Configure Environment

```bash
# .env
# Security features
ENABLE_SANDBOXING=true
SANDBOX_RUNTIME=runsc
VAULT_ADDR=http://127.0.0.1:8200
VAULT_TOKEN=your-vault-token

# Audit logging
AUDIT_DB_PATH=./data/audit.db

# Network security
EGRESS_MODE=allowlist
ALLOWED_DOMAINS=api.anthropic.com,api.openai.com
```

### 4. Use Secure Agent

```python
import asyncio
from harombe.agent.runtime import AgentRuntime
from harombe.agent.config import AgentConfig
from harombe.security.sandbox import SandboxManager
from harombe.security.hitl import HITLGateway
from harombe.security.audit import AuditLogger

async def main():
    # Initialize security components
    sandbox_manager = SandboxManager(runtime="runsc")
    hitl_gateway = HITLGateway()
    audit_logger = AuditLogger(db_path="./data/audit.db")

    # Create secure agent config
    config = AgentConfig(
        name="SecureAgent",
        model="claude-sonnet-4-5-20250929",
        sandbox_manager=sandbox_manager,
        hitl_gateway=hitl_gateway,
        audit_logger=audit_logger,
    )

    runtime = AgentRuntime(config)

    # Execute code in sandbox
    response = await runtime.run(
        "Write a Python script that prints 'Hello, World!'"
    )

    print(f"Agent: {response.final_answer}")

if __name__ == "__main__":
    asyncio.run(main())
```

## Common Tasks

### Execute Code

```python
response = await agent.run(
    "Write and execute Python code to calculate the factorial of 10"
)
```

### File Operations

```python
response = await agent.run(
    "Read the file 'data.txt' and tell me how many lines it has"
)
```

### Web Search

```python
response = await agent.run(
    "Search for the latest news about AI and summarize the top 3 results"
)
```

## Next Steps

- [Configuration Guide](configuration.md) - Learn about all configuration options
- [Architecture Overview](../architecture/overview.md) - Understand how Harombe works
- [Security Guide](../security-quickstart.md) - Enable security features
- [Glossary](../glossary.md) - Key terms and concepts

## Examples

Check out the `examples/` directory for more:

- `examples/basic_chat.py` - Simple chat agent
- `examples/memory_agent.py` - Agent with semantic memory
- `examples/secure_agent.py` - Agent with security features
- `examples/tool_usage.py` - Custom tool integration
- `examples/voice_agent.py` - Voice-enabled agent

## Troubleshooting

### Ollama Not Running

```bash
# Start Ollama server
ollama serve

# Verify it's running
curl http://localhost:11434/api/tags
```

### Memory Issues

If ChromaDB fails to initialize:

```bash
# Install with explicit versions
pip install chromadb==0.4.22

# Clear old data
rm -rf ./data/memory
```

### Import Errors

```bash
# Reinstall in editable mode
pip install -e ".[dev]"

# Verify installation
python -c "import harombe; print(harombe.__version__)"
```
