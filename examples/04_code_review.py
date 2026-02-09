"""
Code Review Agent Example
==========================

This example demonstrates using harombe to automatically review code for:
- Bugs and potential errors
- Security vulnerabilities
- Code smells and anti-patterns
- Performance issues
- Style and readability problems

This showcases how harombe can assist with code quality and catch issues
that might be missed in manual reviews.

Prerequisites:
- Ollama installed and running
- A model pulled (e.g., qwen2.5:7b)
- harombe installed: pip install harombe

Usage:
    python examples/04_code_review.py
"""

import asyncio
from pathlib import Path

# Import tools to register them
from harombe.agent.loop import Agent
from harombe.llm.ollama import OllamaClient
from harombe.tools.registry import get_enabled_tools


async def review_single_file():
    """Demonstrate reviewing a single file."""
    print("\n" + "=" * 70)
    print("Code Review: Single File Analysis")
    print("=" * 70 + "\n")

    llm = OllamaClient(
        model="qwen2.5:7b",
        base_url="http://localhost:11434/v1",
    )

    tools = get_enabled_tools(
        shell=False,  # Not needed for code review
        filesystem=True,
        web_search=False,
    )

    # Create a code review agent
    agent = Agent(
        llm=llm,
        tools=tools,
        system_prompt="""You are an expert code reviewer.
        Your job is to analyze code for:
        1. Bugs and potential errors
        2. Security vulnerabilities
        3. Performance issues
        4. Code smells and anti-patterns
        5. Style and readability problems

        Be specific and provide actionable feedback with examples.
        Prioritize issues by severity: Critical > High > Medium > Low.""",
        confirm_dangerous=False,
        max_steps=10,
    )

    # Check if sample code exists
    sample_file = Path(__file__).parent / "sample_code" / "calculator.py"

    if not sample_file.exists():
        print(f"⚠️  Sample file not found: {sample_file}")
        print("   Run this from the repository root.\n")
        return

    print(f"Reviewing: {sample_file.name}\n")

    try:
        response = await agent.run(
            f"Review the code in {sample_file} and provide a detailed analysis.\n"
            "For each issue found, provide:\n"
            "1. Severity (Critical/High/Medium/Low)\n"
            "2. Description of the problem\n"
            "3. Line number if applicable\n"
            "4. Suggested fix with code example\n\n"
            "Organize findings by category: Bugs, Security, Performance, Code Smells, Style."
        )
        print(f"Review Results:\n{response}\n")

    except Exception as e:
        print(f"✗ Error: {e}\n")


async def review_multiple_files():
    """Demonstrate reviewing multiple files."""
    print("\n" + "=" * 70)
    print("Code Review: Multi-File Analysis")
    print("=" * 70 + "\n")

    llm = OllamaClient(model="qwen2.5:7b", base_url="http://localhost:11434/v1")
    tools = get_enabled_tools(shell=False, filesystem=True, web_search=False)

    agent = Agent(
        llm=llm,
        tools=tools,
        system_prompt="You are a code review expert. Identify issues and suggest improvements.",
        confirm_dangerous=False,
        max_steps=15,
    )

    sample_dir = Path(__file__).parent / "sample_code"

    if not sample_dir.exists():
        print(f"⚠️  Sample directory not found: {sample_dir}\n")
        return

    print(f"Reviewing all Python files in: {sample_dir.name}\n")

    try:
        response = await agent.run(
            f"Review all Python files in {sample_dir}.\n"
            "For each file, provide:\n"
            "1. File name\n"
            "2. Overall quality rating (1-10)\n"
            "3. Top 3 most critical issues\n"
            "4. Brief recommendations\n\n"
            "Then provide a summary comparing the files."
        )
        print(f"Review Results:\n{response}\n")

    except Exception as e:
        print(f"✗ Error: {e}\n")


async def security_focused_review():
    """Demonstrate security-focused code review."""
    print("\n" + "=" * 70)
    print("Code Review: Security Audit")
    print("=" * 70 + "\n")

    llm = OllamaClient(model="qwen2.5:7b", base_url="http://localhost:11434/v1")
    tools = get_enabled_tools(shell=False, filesystem=True, web_search=False)

    agent = Agent(
        llm=llm,
        tools=tools,
        system_prompt="""You are a security-focused code reviewer.
        Focus specifically on security vulnerabilities like:
        - SQL injection
        - XSS (Cross-Site Scripting)
        - Authentication/Authorization issues
        - Hardcoded credentials
        - Insecure data storage
        - Input validation problems
        - Cryptography issues

        Rate each vulnerability by OWASP Top 10 severity.""",
        confirm_dangerous=False,
        max_steps=10,
    )

    sample_file = Path(__file__).parent / "sample_code" / "data_processor.py"

    if not sample_file.exists():
        print(f"⚠️  Sample file not found: {sample_file}\n")
        return

    print(f"Security audit: {sample_file.name}\n")

    try:
        response = await agent.run(
            f"Perform a security audit of {sample_file}.\n"
            "Identify all security vulnerabilities.\n"
            "For each vulnerability:\n"
            "1. OWASP category if applicable\n"
            "2. Risk level (Critical/High/Medium/Low)\n"
            "3. Detailed explanation\n"
            "4. Secure code example\n\n"
            "Prioritize by risk level."
        )
        print(f"Security Audit:\n{response}\n")

    except Exception as e:
        print(f"✗ Error: {e}\n")


async def generate_review_report():
    """Generate a comprehensive review report."""
    print("\n" + "=" * 70)
    print("Code Review: Generate Report")
    print("=" * 70 + "\n")

    llm = OllamaClient(model="qwen2.5:7b", base_url="http://localhost:11434/v1")
    tools = get_enabled_tools(shell=False, filesystem=True, web_search=False)

    agent = Agent(
        llm=llm,
        tools=tools,
        system_prompt="You are a code reviewer generating comprehensive reports.",
        confirm_dangerous=False,
        max_steps=20,
    )

    sample_dir = Path(__file__).parent / "sample_code"
    report_file = Path(__file__).parent / "sample_code" / "code_review_report.md"

    if not sample_dir.exists():
        print(f"⚠️  Sample directory not found: {sample_dir}\n")
        return

    print("Generating comprehensive code review report...\n")

    try:
        response = await agent.run(
            f"Analyze all Python files in {sample_dir} and create a comprehensive "
            f"code review report. Save it to {report_file}.\n\n"
            "The report should include:\n"
            "1. Executive Summary\n"
            "2. Files Reviewed\n"
            "3. Overall Quality Metrics\n"
            "4. Critical Issues (with severity)\n"
            "5. Security Vulnerabilities\n"
            "6. Performance Concerns\n"
            "7. Code Smells\n"
            "8. Recommendations\n"
            "9. Action Items (prioritized)\n\n"
            "Use markdown formatting with tables and code blocks."
        )
        print(f"Result:\n{response}\n")

        if report_file.exists():
            print(f"✓ Report generated: {report_file}")
            print(f"  File size: {report_file.stat().st_size} bytes\n")
        else:
            print(f"⚠️  Report not found at: {report_file}\n")

    except Exception as e:
        print(f"✗ Error: {e}\n")


async def demonstrate_refactoring():
    """Demonstrate code refactoring suggestions."""
    print("\n" + "=" * 70)
    print("Code Review: Refactoring Suggestions")
    print("=" * 70 + "\n")

    llm = OllamaClient(model="qwen2.5:7b", base_url="http://localhost:11434/v1")
    tools = get_enabled_tools(shell=False, filesystem=True, web_search=False)

    agent = Agent(
        llm=llm,
        tools=tools,
        system_prompt="""You are a code refactoring expert.
        Suggest improvements for:
        - Code organization and structure
        - Function decomposition
        - Naming conventions
        - Design patterns
        - Removing duplication
        - Improving readability

        Provide before/after code examples.""",
        confirm_dangerous=False,
        max_steps=10,
    )

    sample_file = Path(__file__).parent / "sample_code" / "calculator.py"

    if not sample_file.exists():
        print(f"⚠️  Sample file not found: {sample_file}\n")
        return

    print(f"Refactoring suggestions for: {sample_file.name}\n")

    try:
        response = await agent.run(
            f"Analyze {sample_file} and suggest refactoring improvements.\n"
            "For each suggestion:\n"
            "1. What to refactor\n"
            "2. Why it should be refactored\n"
            "3. Before code\n"
            "4. After code (improved version)\n\n"
            "Focus on the most impactful improvements."
        )
        print(f"Refactoring Suggestions:\n{response}\n")

    except Exception as e:
        print(f"✗ Error: {e}\n")


async def main():
    """Run all code review examples."""
    print("\n" + "=" * 70)
    print("Harombe Code Review Agent Examples")
    print("=" * 70)
    print("\nThese examples demonstrate automated code review:")
    print("- Bug detection")
    print("- Security vulnerability scanning")
    print("- Performance analysis")
    print("- Code smell identification")
    print("- Refactoring suggestions")
    print("- Report generation\n")

    # Single file review
    await review_single_file()

    # Multiple files review
    await review_multiple_files()

    # Security audit
    await security_focused_review()

    # Refactoring suggestions
    await demonstrate_refactoring()

    # Generate comprehensive report
    await generate_review_report()

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
