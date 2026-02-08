"""Filesystem read/write tools."""

import os
from pathlib import Path

from harombe.tools.registry import tool


@tool(description="Read contents of a file")
async def read_file(path: str) -> str:
    """Read and return the contents of a file.

    Args:
        path: Path to the file to read (can be relative or absolute)

    Returns:
        File contents, truncated to 20KB
    """
    try:
        file_path = Path(path).expanduser().resolve()

        if not file_path.exists():
            return f"Error: File not found: {path}"

        if not file_path.is_file():
            return f"Error: Path is not a file: {path}"

        # Read file
        content = file_path.read_text(encoding="utf-8", errors="replace")

        # Truncate to 20KB
        max_chars = 20_000
        if len(content) > max_chars:
            content = content[:max_chars] + f"\n... (truncated, {len(content) - max_chars} chars omitted)"

        return content

    except PermissionError:
        return f"Error: Permission denied: {path}"
    except Exception as e:
        return f"Error reading file: {str(e)}"


@tool(description="Write content to a file", dangerous=True)
async def write_file(path: str, content: str, append: bool = False) -> str:
    """Write content to a file.

    WARNING: This will overwrite existing files unless append=True.

    Args:
        path: Path to the file to write (can be relative or absolute)
        content: Content to write to the file
        append: If True, append to file instead of overwriting (default: False)

    Returns:
        Success message or error description
    """
    try:
        file_path = Path(path).expanduser().resolve()

        # Create parent directories if needed
        file_path.parent.mkdir(parents=True, exist_ok=True)

        # Write file
        mode = "a" if append else "w"
        file_path.write_text(content, encoding="utf-8")

        action = "appended to" if append else "written to"
        size = len(content)
        return f"Successfully {action} {path} ({size} chars)"

    except PermissionError:
        return f"Error: Permission denied: {path}"
    except Exception as e:
        return f"Error writing file: {str(e)}"
