"""ReAct agent loop for autonomous task execution.

This module implements the Reasoning + Acting (ReAct) pattern where the agent
alternates between reasoning about what to do and executing tool calls.
The loop continues until the task is complete or the step limit is reached.

Usage::

    from harombe.agent.loop import Agent
    from harombe.llm.ollama import OllamaClient
    from harombe.tools.registry import get_enabled_tools

    llm = OllamaClient(model="qwen2.5:7b")
    tools = get_enabled_tools(shell=True, filesystem=True)
    agent = Agent(llm=llm, tools=tools)
    response = await agent.run("Analyze this file")
"""
