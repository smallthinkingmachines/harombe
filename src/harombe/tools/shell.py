"""Shell command execution tool."""

import asyncio

from harombe.tools.registry import tool


@tool(description="Execute a shell command", dangerous=True)
async def shell(command: str, timeout: int = 30) -> str:
    """Run a shell command and return its output.

    WARNING: This tool can execute arbitrary commands. Use with caution.

    Args:
        command: The shell command to execute
        timeout: Maximum execution time in seconds (default: 30)

    Returns:
        Combined stdout and stderr output, truncated to 10KB
    """
    try:
        process = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout,
            )
        except TimeoutError:
            process.kill()
            await process.wait()
            return f"Error: Command timed out after {timeout} seconds"

        # Combine output
        output = ""
        if stdout:
            output += stdout.decode("utf-8", errors="replace")
        if stderr:
            if output:
                output += "\n--- stderr ---\n"
            output += stderr.decode("utf-8", errors="replace")

        if not output:
            output = f"Command completed with exit code {process.returncode}"

        # Truncate to 10KB
        max_chars = 10_000
        if len(output) > max_chars:
            output = (
                output[:max_chars] + f"\n... (truncated, {len(output) - max_chars} chars omitted)"
            )

        return output

    except Exception as e:
        return f"Error executing command: {e!s}"
