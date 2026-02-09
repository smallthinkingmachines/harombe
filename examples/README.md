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
4. Multiple specialized agents with different configurations
5. Integration example (batch task processor)

### 03. Multi-step Data Pipeline (`03_data_pipeline.py`)

**What it demonstrates:**

- Real-world data processing workflows
- CSV file analysis and transformation
- Multi-step calculations and aggregations
- Automated report generation
- Error handling in data pipelines
- Batch file processing

**What you'll learn:**

- How to build data analysis workflows with agents
- Automating repetitive data tasks
- Generating insights from structured data
- Handling missing or invalid data gracefully
- Creating comprehensive reports automatically

**Run it:**

```bash
python examples/03_data_pipeline.py
```

**Expected output:**

The example processes sample sales data through multiple stages:

1. Data exploration (row count, columns, date range)
2. Category analysis (revenue by category, units sold)
3. Regional analysis (sales by region, top regions)
4. Product insights (best-selling products, averages)
5. Comprehensive report generation (sales_report.md)

Plus demonstrations of error recovery and batch processing.

### 04. Code Review Agent (`04_code_review.py`)

**What it demonstrates:**

- Automated code quality analysis
- Bug and error detection
- Security vulnerability scanning
- Performance issue identification
- Code smell and anti-pattern detection
- Refactoring suggestions with examples

**What you'll learn:**

- How to automate code reviews with AI
- Identifying security vulnerabilities (OWASP)
- Detecting bugs before they reach production
- Generating comprehensive review reports
- Getting actionable refactoring suggestions
- Prioritizing issues by severity

**Run it:**

```bash
python examples/04_code_review.py
```

**Expected output:**

The example performs 5 types of code review:

1. Single file analysis - Detailed review with severity ratings
2. Multi-file analysis - Compare quality across files
3. Security audit - OWASP-focused vulnerability scan
4. Refactoring suggestions - Before/after code examples
5. Comprehensive report - Full markdown report with action items

Sample code files included with intentional bugs and security issues.

### 05. Research Agent (`05_research_agent.py`)

**What it demonstrates:**

- Automated web research and information gathering
- Multi-source synthesis and analysis
- Comparative research across topics
- Fact-checking and verification
- Literature reviews
- Comprehensive research report generation

**What you'll learn:**

- How to automate research workflows with AI
- Gathering and synthesizing information from multiple sources
- Cross-referencing and fact-checking
- Generating well-structured research reports
- Comparing different perspectives
- Building research agents for specific domains

**Run it:**

```bash
python examples/05_research_agent.py
```

**Expected output:**

The example demonstrates 6 types of research:

1. Simple research - Basic topic investigation with sources
2. Comparative analysis - GraphQL vs REST with pros/cons
3. Multi-source investigation - Breaking down complex topics
4. Fact-checking - Verifying claims with confidence levels
5. Literature review - Academic-style synthesis
6. Comprehensive report - Full markdown report with citations

Generated reports saved to research_output/ directory.

### 06. Conversation Memory (`06_memory_conversation.py`)

**What it demonstrates:**

- Persistent conversation history across agent interactions
- Session creation and management
- Loading conversation context automatically
- Token windowing for context limits
- Multi-turn conversations with memory recall
- Session lifecycle (create, list, clear, delete)

**What you'll learn:**

- How to enable persistent conversations
- Managing multiple conversation sessions
- Loading and replaying conversation history
- Token-based context window management
- Session metadata and organization
- Memory cleanup and maintenance

**Run it:**

```bash
python examples/06_memory_conversation.py
```

**Expected output:**

The example demonstrates memory features in 3 parts:

1. Session persistence - Multiple agent instances share conversation context
2. History inspection - View full conversation logs with messages
3. Token windowing - Automatic context management for long conversations

The agent remembers previous interactions and can reference earlier messages.

### 07. Cluster Routing (`07_cluster_routing.py`)

**What it demonstrates:**

- Multi-node cluster orchestration
- Automatic task complexity classification
- Smart routing to appropriate hardware tiers
- Health monitoring and circuit breakers
- Load balancing across nodes
- Phase 1's unique distributed inference value

**What you'll learn:**

- How to configure multi-machine clusters
- Routing strategies for different workload types
- Health monitoring and failover patterns
- Load balancing across heterogeneous hardware
- Distributed AI without cloud dependencies

**Run it:**

```bash
python examples/06_cluster_routing.py
```

**Expected output:**

The example demonstrates cluster concepts in 5 parts:

1. Routing strategy - How complexity classification works
2. Simulated routing - Local demonstration of routing logic
3. Cluster configuration - YAML setup for multi-node clusters
4. Health monitoring - Circuit breakers, failover, load balancing
5. Real cluster usage - Live demonstration if cluster is configured

Works without a real cluster (educational mode) or with real nodes (live demo).

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
