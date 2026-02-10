"""Tests for shell command execution tool."""

import pytest

from harombe.tools.shell import shell


class TestShell:
    @pytest.mark.asyncio
    async def test_simple_command(self):
        """Test executing a simple command."""
        result = await shell("echo hello")
        assert "hello" in result

    @pytest.mark.asyncio
    async def test_command_with_exit_code(self):
        """Test that exit code is included when no output."""
        result = await shell("true")
        assert "exit code 0" in result.lower() or result.strip() == ""

    @pytest.mark.asyncio
    async def test_command_stderr(self):
        """Test capturing stderr output."""
        result = await shell("echo error >&2")
        assert "error" in result

    @pytest.mark.asyncio
    async def test_command_timeout(self):
        """Test command timeout."""
        result = await shell("sleep 10", timeout=1)
        assert "timed out" in result.lower()

    @pytest.mark.asyncio
    async def test_combined_stdout_stderr(self):
        """Test command with both stdout and stderr."""
        result = await shell("echo out && echo err >&2")
        assert "out" in result
        assert "err" in result

    @pytest.mark.asyncio
    async def test_failed_command(self):
        """Test a command that fails."""
        result = await shell("false")
        # false returns exit code 1 with no output
        assert "exit code" in result.lower() or result.strip() != ""

    @pytest.mark.asyncio
    async def test_output_truncation(self):
        """Test that long output is truncated to 10KB."""
        # Generate more than 10KB of output
        result = await shell("python3 -c \"print('x' * 15000)\"")
        if len("x" * 15000) > 10_000:
            assert "truncated" in result or len(result) <= 11_000

    @pytest.mark.asyncio
    async def test_pipe_command(self):
        """Test piped commands."""
        result = await shell("echo 'hello world' | tr 'h' 'H'")
        assert "Hello" in result
