# Harombe Examples

This directory contains example scripts demonstrating how to use harombe as a **library** for various agent workloads.

## About These Examples

These examples show the **library approach** to using harombe: you create and control agents programmatically in your Python code. This gives you maximum flexibility to integrate AI capabilities into your applications.

**Future approach:** In a later phase, harombe will also support a **platform approach** where you can define agents declaratively in YAML configuration files, and the framework will create and manage them for you. For now, all examples use the programmatic library approach.

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

### 02. API/Programmatic Usage (`02_api_usage.py`)

**What it demonstrates:**

- Using harombe programmatically in Python applications
- Custom confirmation callbacks for dangerous operations
- Error handling patterns (try-except, retry, graceful degradation)
- Multiple agents with different tool configurations
- Integrating harombe into existing codebases

**What you'll learn:**

- How to create custom confirmation logic
- Best practices for error handling with agents
- How to use multiple specialized agents
- How to build batch processing systems with agents
- Production patterns for using harombe in applications

**Run it:**

```bash
python examples/02_api_usage.py
```

**Expected output:**

The example runs 5 demonstrations:

1. Basic programmatic agent creation and usage
2. Custom confirmation callback with auto-approval logic
3. Error handling patterns (specific errors, fallbacks, retries)
4. Agent state inspection (conversation history)
5. Integration example (batch task processor)

## Coming Soon

- **03. Multi-step Data Pipeline** - Process CSV files, analyze data, generate reports
- **04. Code Review Agent** - Analyze code quality, suggest improvements
- **05. Research Agent** - Multi-source web research with synthesis
- **06. Cluster Routing** - Multi-node deployment with complexity-based routing

## Example Template

Here's a minimal template for creating your own agent programmatically (library approach):

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
