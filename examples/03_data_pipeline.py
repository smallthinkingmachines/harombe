"""
Multi-step Data Pipeline Example
=================================

This example demonstrates using harombe for real-world data processing tasks:
- Reading and analyzing CSV files
- Performing calculations and transformations
- Generating insights and reports
- Handling multi-step workflows with error recovery

This showcases how harombe can automate data analysis workflows that would
normally require writing custom scripts.

Prerequisites:
- Ollama installed and running
- A model pulled (e.g., qwen2.5:7b)
- harombe installed: pip install harombe

Usage:
    python examples/03_data_pipeline.py
"""

import asyncio
from pathlib import Path

# Import tools to register them
from harombe.agent.loop import Agent
from harombe.llm.ollama import OllamaClient
from harombe.tools.registry import get_enabled_tools


async def analyze_sales_data():
    """Demonstrate a complete data pipeline workflow."""
    print("\n" + "=" * 70)
    print("Data Pipeline: Sales Analysis")
    print("=" * 70 + "\n")

    # Setup
    llm = OllamaClient(
        model="qwen2.5:7b",
        base_url="http://localhost:11434/v1",
    )

    # For data analysis, we mainly need filesystem and shell (for CSV processing)
    tools = get_enabled_tools(
        shell=True,
        filesystem=True,
        web_search=False,  # Not needed for local data
    )

    # Create a data analyst agent
    agent = Agent(
        llm=llm,
        tools=tools,
        system_prompt="""You are a data analyst assistant.
        You help analyze CSV data, perform calculations, and generate insights.
        Always show your work and explain your findings clearly.
        When analyzing data, be thorough and accurate.""",
        confirm_dangerous=False,  # Auto-approve for smooth demo
        max_steps=15,  # Allow more steps for complex analysis
    )

    # Ensure data directory exists
    data_dir = Path(__file__).parent / "data"
    data_dir.mkdir(exist_ok=True)

    # Check if sample data exists
    sample_file = data_dir / "sales_data.csv"
    if not sample_file.exists():
        print("⚠️  Sample data not found. Creating sample dataset...")
        print(f"   Expected location: {sample_file}\n")
        print("   Please ensure examples/data/sales_data.csv exists.")
        print("   Run this from the repository root.\n")
        return

    # Pipeline tasks
    tasks = [
        # Task 1: Data exploration
        {
            "name": "Data Exploration",
            "query": f"Read the CSV file at {sample_file} and tell me:\n"
            "1. How many rows of data are there?\n"
            "2. What columns exist?\n"
            "3. What's the date range of the data?",
        },
        # Task 2: Category analysis
        {
            "name": "Category Analysis",
            "query": f"Analyze {sample_file} and calculate:\n"
            "1. Total revenue by category (quantity * price)\n"
            "2. Total units sold by category\n"
            "3. Which category had higher sales?",
        },
        # Task 3: Regional analysis
        {
            "name": "Regional Analysis",
            "query": f"Analyze {sample_file} by region:\n"
            "1. Which region had the most sales (by revenue)?\n"
            "2. How much revenue did each region generate?\n"
            "3. Which region sold the most units?",
        },
        # Task 4: Product insights
        {
            "name": "Product Insights",
            "query": f"Find product patterns in {sample_file}:\n"
            "1. What was the best-selling product by revenue?\n"
            "2. What was the best-selling product by quantity?\n"
            "3. What's the average price per product category?",
        },
        # Task 5: Generate report
        {
            "name": "Generate Report",
            "query": f"Create a comprehensive sales report and save it to {data_dir / 'sales_report.md'}.\n"
            "The report should include:\n"
            "1. Executive Summary\n"
            "2. Total Revenue and Units Sold\n"
            "3. Category Performance\n"
            "4. Regional Performance\n"
            "5. Top Products\n"
            "6. Key Insights and Recommendations\n"
            f"Use the data from {sample_file}",
        },
    ]

    # Execute pipeline
    results = []
    for i, task in enumerate(tasks, 1):
        print(f"\n{'─' * 70}")
        print(f"Task {i}/{len(tasks)}: {task['name']}")
        print(f"{'─' * 70}\n")

        try:
            response = await agent.run(task["query"])
            results.append({"task": task["name"], "status": "success", "result": response})
            print(f"\n✓ Result:\n{response}\n")

        except Exception as e:
            print(f"\n✗ Error: {e}\n")
            results.append({"task": task["name"], "status": "failed", "error": str(e)})

        # Brief pause between tasks
        if i < len(tasks):
            await asyncio.sleep(1)

    # Pipeline summary
    print("\n" + "=" * 70)
    print("Pipeline Summary")
    print("=" * 70)

    successful = sum(1 for r in results if r["status"] == "success")
    print(f"Total tasks: {len(results)}")
    print(f"Successful: {successful}")
    print(f"Failed: {len(results) - successful}")

    # Check if report was generated
    report_file = data_dir / "sales_report.md"
    if report_file.exists():
        print(f"\n✓ Report generated: {report_file}")
        print(f"  File size: {report_file.stat().st_size} bytes")
    else:
        print(f"\n⚠️  Report file not found at: {report_file}")

    print("\n" + "=" * 70 + "\n")


async def demonstrate_error_recovery():
    """Demonstrate error handling in data pipelines."""
    print("\n" + "=" * 70)
    print("Error Recovery: Handling Missing Data")
    print("=" * 70 + "\n")

    llm = OllamaClient(model="qwen2.5:7b", base_url="http://localhost:11434/v1")
    tools = get_enabled_tools(shell=True, filesystem=True, web_search=False)

    agent = Agent(
        llm=llm,
        tools=tools,
        system_prompt="You are a data analyst. Handle missing data gracefully.",
        confirm_dangerous=False,
    )

    # Try to analyze a non-existent file
    print("Attempting to analyze non-existent file...\n")

    try:
        response = await agent.run(
            "Analyze the file at examples/data/nonexistent.csv and tell me about it."
        )
        print(f"Response: {response}\n")
    except Exception as e:
        print(f"✗ Pipeline failed: {e}\n")

    # Try with a fallback approach
    print("\nDemonstrating graceful degradation...\n")

    try:
        response = await agent.run(
            "Check if examples/data/sales_data.csv exists. "
            "If it does, summarize it. "
            "If it doesn't, tell me what data you would need to perform sales analysis."
        )
        print(f"Response: {response}\n")
    except Exception as e:
        print(f"✗ Error: {e}\n")


async def demonstrate_streaming_pipeline():
    """Demonstrate processing multiple files in sequence."""
    print("\n" + "=" * 70)
    print("Batch Processing: Multiple Files")
    print("=" * 70 + "\n")

    llm = OllamaClient(model="qwen2.5:7b", base_url="http://localhost:11434/v1")
    tools = get_enabled_tools(shell=True, filesystem=True, web_search=False)

    agent = Agent(
        llm=llm,
        tools=tools,
        system_prompt="You are a data processing assistant.",
        confirm_dangerous=False,
    )

    # Simulate batch processing scenario
    print("Scenario: Processing multiple CSV files in a directory\n")

    try:
        response = await agent.run(
            "List all CSV files in the examples/data directory. "
            "For each CSV file found, tell me: "
            "1. The filename "
            "2. The file size "
            "3. How many lines it contains"
        )
        print(f"Result:\n{response}\n")
    except Exception as e:
        print(f"✗ Error: {e}\n")


async def main():
    """Run all data pipeline examples."""
    print("\n" + "=" * 70)
    print("Harombe Data Pipeline Examples")
    print("=" * 70)
    print("\nThese examples demonstrate how harombe can automate data workflows:")
    print("- CSV processing and analysis")
    print("- Multi-step calculations")
    print("- Report generation")
    print("- Error handling and recovery")
    print("- Batch file processing\n")

    # Main sales analysis pipeline
    await analyze_sales_data()

    # Error handling demonstration
    await demonstrate_error_recovery()

    # Batch processing demonstration
    await demonstrate_streaming_pipeline()

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
