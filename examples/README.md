# Harombe Examples

This directory contains example scripts demonstrating how to use harombe for various agent workloads.

## Prerequisites

All examples require:

- Python 3.11+
- Ollama installed and running (`ollama serve`)
- A model pulled (e.g., `ollama pull qwen2.5:7b`)
- harombe installed: `pip install harombe`

## Examples

### 01. Simple Agent (`01_simple_agent.py`)

**What it demonstrates:**

- Basic agent setup with LLM client
- Loading and using tools (shell, filesystem, web search)
- Running single-node agent workflows
- Autonomous multi-step reasoning

**What you'll learn:**

- How to create an `Agent` instance
- How to configure tools and system prompts
- How the agent autonomously uses tools to accomplish tasks
- How to handle dangerous operations with confirmation

**Run it:**

```bash
python examples/01_simple_agent.py
```

**Expected output:**

The agent will:

1. Answer a simple math question (no tools)
2. Read README.md and summarize the project
3. Search the web for Python 3.13 features
4. List and count Python files in the src directory

Each query demonstrates different agent capabilities and tool usage.

## Coming Soon

- **02. Multi-step Data Pipeline** - Process CSV files, analyze data, generate reports
- **03. Code Review Agent** - Analyze code quality, suggest improvements
- **04. Research Agent** - Multi-source web research with synthesis
- **05. Cluster Routing** - Multi-node deployment with complexity-based routing

## Example Template

Here's a minimal template for creating your own agent:

```python
import asyncio
from harombe.agent.loop import Agent
from harombe.llm.ollama import OllamaClient
from harombe.tools.registry import get_enabled_tools

# Import tools to register them
import harombe.tools.filesystem
import harombe.tools.shell
import harombe.tools.web_search

async def main():
    # Create LLM client
    llm = OllamaClient(
        model="qwen2.5:7b",
        base_url="http://localhost:11434/v1",
    )

    # Get tools
    tools = get_enabled_tools(
        shell=True,
        filesystem=True,
        web_search=True,
    )

    # Create agent
    agent = Agent(
        llm=llm,
        tools=tools,
        system_prompt="You are a helpful AI assistant.",
    )

    # Run a task
    response = await agent.run("Your task here")
    print(response)

if __name__ == "__main__":
    asyncio.run(main())
```

## Tips

### Customizing the System Prompt

The system prompt defines the agent's behavior:

```python
system_prompt = """You are a data analyst assistant.
Focus on accuracy and provide detailed explanations.
Always show your work when performing calculations."""
```

### Selecting Specific Tools

Instead of `get_all_tools()`, load only what you need:

```python
from harombe.tools.registry import get_tool

tools = [
    get_tool("read_file"),
    get_tool("write_file"),
    # Don't include shell or web_search
]
```

### Adjusting Agent Behavior

Control how the agent works:

```python
agent = Agent(
    llm=llm,
    tools=tools,
    max_steps=5,              # Limit reasoning steps
    confirm_dangerous=True,    # Require user confirmation
    system_prompt="...",
)
```

### Error Handling

Always wrap agent execution in try-except:

```python
try:
    response = await agent.run(query)
except Exception as e:
    print(f"Agent error: {e}")
    # Handle gracefully
```

## Contributing Examples

Have a useful agent workflow? Contribute an example:

1. Create a new file: `XX_description.py`
2. Follow the template structure
3. Add clear comments and docstrings
4. Update this README
5. Submit a PR

See [CONTRIBUTING.md](../docs/CONTRIBUTING.md) for guidelines.
