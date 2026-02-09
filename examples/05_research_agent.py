"""
Research Agent Example
=======================

This example demonstrates using harombe for automated research tasks:
- Multi-source web research
- Information gathering and synthesis
- Fact-checking and cross-referencing
- Generating comprehensive research reports
- Comparing different sources

This showcases how harombe can automate research workflows that would
normally require hours of manual web searching and analysis.

Prerequisites:
- Ollama installed and running
- A model pulled (e.g., qwen2.5:7b)
- harombe installed: pip install harombe

Usage:
    python examples/05_research_agent.py
"""

import asyncio
from pathlib import Path

# Import tools to register them
from harombe.agent.loop import Agent
from harombe.llm.ollama import OllamaClient
from harombe.tools.registry import get_enabled_tools


async def simple_research():
    """Demonstrate basic research task."""
    print("\n" + "=" * 70)
    print("Research: Simple Topic")
    print("=" * 70 + "\n")

    llm = OllamaClient(
        model="qwen2.5:7b",
        base_url="http://localhost:11434/v1",
    )

    tools = get_enabled_tools(
        shell=False,
        filesystem=True,  # For saving results
        web_search=True,  # Essential for research
    )

    agent = Agent(
        llm=llm,
        tools=tools,
        system_prompt="""You are a research assistant.
        Your job is to gather accurate information from multiple sources,
        synthesize findings, and present them clearly.
        Always cite your sources and note any conflicting information.""",
        confirm_dangerous=False,
        max_steps=15,
    )

    topic = "Python 3.13 new features"

    print(f"Researching: {topic}\n")

    try:
        response = await agent.run(
            f"Research '{topic}' and provide a comprehensive summary.\n"
            "Include:\n"
            "1. Key findings\n"
            "2. Important details\n"
            "3. Sources (URLs if found)\n"
            "4. Your assessment of the information quality"
        )
        print(f"Research Results:\n{response}\n")

    except Exception as e:
        print(f"✗ Error: {e}\n")


async def comparative_research():
    """Demonstrate comparative research across topics."""
    print("\n" + "=" * 70)
    print("Research: Comparative Analysis")
    print("=" * 70 + "\n")

    llm = OllamaClient(model="qwen2.5:7b", base_url="http://localhost:11434/v1")
    tools = get_enabled_tools(shell=False, filesystem=True, web_search=True)

    agent = Agent(
        llm=llm,
        tools=tools,
        system_prompt="You are a research analyst specializing in comparative studies.",
        confirm_dangerous=False,
        max_steps=20,
    )

    topics = ["GraphQL vs REST APIs"]

    print(f"Comparative research: {topics[0]}\n")

    try:
        response = await agent.run(
            f"Research {topics[0]} and provide a comprehensive comparison.\n"
            "Include:\n"
            "1. Overview of each approach\n"
            "2. Key differences\n"
            "3. Advantages and disadvantages of each\n"
            "4. Use cases for each\n"
            "5. Industry adoption and trends\n"
            "6. Recommendations for different scenarios\n\n"
            "Use multiple sources and note any consensus or disagreements."
        )
        print(f"Comparative Analysis:\n{response}\n")

    except Exception as e:
        print(f"✗ Error: {e}\n")


async def multi_source_research():
    """Demonstrate gathering information from multiple searches."""
    print("\n" + "=" * 70)
    print("Research: Multi-Source Investigation")
    print("=" * 70 + "\n")

    llm = OllamaClient(model="qwen2.5:7b", base_url="http://localhost:11434/v1")
    tools = get_enabled_tools(shell=False, filesystem=True, web_search=True)

    agent = Agent(
        llm=llm,
        tools=tools,
        system_prompt="""You are a thorough research assistant.
        When researching complex topics:
        1. Break down the topic into sub-questions
        2. Search for each aspect separately
        3. Cross-reference findings
        4. Note conflicting information
        5. Synthesize into coherent summary""",
        confirm_dangerous=False,
        max_steps=25,
    )

    topic = "Transformer neural networks"

    print(f"Multi-source research: {topic}\n")

    try:
        response = await agent.run(
            f"Conduct thorough research on '{topic}'.\n\n"
            "Research these aspects separately, then synthesize:\n"
            "1. What are transformers and how do they work?\n"
            "2. Key innovations that made them successful\n"
            "3. Major implementations (BERT, GPT, etc.)\n"
            "4. Current limitations and challenges\n"
            "5. Recent developments and future directions\n\n"
            "Provide a comprehensive report with clear sections."
        )
        print(f"Research Report:\n{response}\n")

    except Exception as e:
        print(f"✗ Error: {e}\n")


async def fact_checking_research():
    """Demonstrate fact-checking and verification."""
    print("\n" + "=" * 70)
    print("Research: Fact-Checking & Verification")
    print("=" * 70 + "\n")

    llm = OllamaClient(model="qwen2.5:7b", base_url="http://localhost:11434/v1")
    tools = get_enabled_tools(shell=False, filesystem=True, web_search=True)

    agent = Agent(
        llm=llm,
        tools=tools,
        system_prompt="""You are a fact-checking researcher.
        Your job is to verify claims by:
        1. Finding multiple reliable sources
        2. Comparing information across sources
        3. Noting consensus and disagreements
        4. Assessing source credibility
        5. Providing confidence levels""",
        confirm_dangerous=False,
        max_steps=15,
    )

    claim = "Python is the most popular programming language in 2024"

    print(f"Fact-checking: '{claim}'\n")

    try:
        response = await agent.run(
            f"Fact-check this claim: '{claim}'\n\n"
            "Provide:\n"
            "1. What the evidence shows\n"
            "2. Sources found\n"
            "3. Any nuances or caveats\n"
            "4. Verdict (True/Mostly True/Mixed/Mostly False/False)\n"
            "5. Confidence level in your assessment"
        )
        print(f"Fact-Check Results:\n{response}\n")

    except Exception as e:
        print(f"✗ Error: {e}\n")


async def generate_research_report():
    """Generate a comprehensive research report with citations."""
    print("\n" + "=" * 70)
    print("Research: Generate Comprehensive Report")
    print("=" * 70 + "\n")

    llm = OllamaClient(model="qwen2.5:7b", base_url="http://localhost:11434/v1")
    tools = get_enabled_tools(shell=False, filesystem=True, web_search=True)

    agent = Agent(
        llm=llm,
        tools=tools,
        system_prompt="""You are a research report writer.
        Create well-structured, properly cited research reports.
        Use academic writing style with clear sections and references.""",
        confirm_dangerous=False,
        max_steps=30,
    )

    topic = "The impact of large language models on software development"
    output_dir = Path(__file__).parent / "research_output"
    output_dir.mkdir(exist_ok=True)
    report_file = output_dir / "research_report.md"

    print(f"Generating research report on: {topic}\n")

    try:
        response = await agent.run(
            f"Research '{topic}' and create a comprehensive report.\n"
            f"Save the report to {report_file}.\n\n"
            "The report should include:\n"
            "1. Executive Summary\n"
            "2. Introduction\n"
            "3. Background/Context\n"
            "4. Current State of the Field\n"
            "5. Key Findings (with subsections)\n"
            "6. Analysis and Discussion\n"
            "7. Future Directions\n"
            "8. Conclusion\n"
            "9. References/Sources\n\n"
            "Use markdown formatting with proper headings, lists, and emphasis."
        )
        print(f"Result:\n{response}\n")

        if report_file.exists():
            print(f"✓ Report generated: {report_file}")
            print(f"  File size: {report_file.stat().st_size} bytes\n")
        else:
            print(f"⚠️  Report not found at: {report_file}\n")

    except Exception as e:
        print(f"✗ Error: {e}\n")


async def literature_review():
    """Demonstrate literature review style research."""
    print("\n" + "=" * 70)
    print("Research: Literature Review")
    print("=" * 70 + "\n")

    llm = OllamaClient(model="qwen2.5:7b", base_url="http://localhost:11434/v1")
    tools = get_enabled_tools(shell=False, filesystem=True, web_search=True)

    agent = Agent(
        llm=llm,
        tools=tools,
        system_prompt="""You are an academic researcher conducting literature reviews.
        Synthesize information across multiple sources, identify themes,
        note methodological approaches, and highlight research gaps.""",
        confirm_dangerous=False,
        max_steps=25,
    )

    topic = "Retrieval-Augmented Generation (RAG) techniques"

    print(f"Literature review: {topic}\n")

    try:
        response = await agent.run(
            f"Conduct a literature review on '{topic}'.\n\n"
            "Include:\n"
            "1. Overview of the field\n"
            "2. Key papers and contributions\n"
            "3. Common approaches and methodologies\n"
            "4. Major findings and insights\n"
            "5. Controversies or debates\n"
            "6. Research gaps and future directions\n"
            "7. Summary table of key works (if applicable)\n\n"
            "Organize by themes or chronologically as appropriate."
        )
        print(f"Literature Review:\n{response}\n")

    except Exception as e:
        print(f"✗ Error: {e}\n")


async def main():
    """Run all research agent examples."""
    print("\n" + "=" * 70)
    print("Harombe Research Agent Examples")
    print("=" * 70)
    print("\nThese examples demonstrate automated research capabilities:")
    print("- Web search and information gathering")
    print("- Multi-source synthesis")
    print("- Comparative analysis")
    print("- Fact-checking and verification")
    print("- Literature reviews")
    print("- Report generation\n")

    # Simple research
    await simple_research()

    # Comparative research
    await comparative_research()

    # Multi-source research
    await multi_source_research()

    # Fact-checking
    await fact_checking_research()

    # Literature review
    await literature_review()

    # Generate comprehensive report
    await generate_research_report()

    print("\n" + "=" * 70)
    print("All examples complete!")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted by user")
    except Exception as e:
        print(f"\n\n❌ Error: {e}")
        raise
