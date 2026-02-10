"""Tests for filesystem tools."""

import pytest

from harombe.tools.filesystem import read_file, write_file


class TestReadFile:
    @pytest.mark.asyncio
    async def test_read_existing_file(self, tmp_path):
        """Test reading an existing file."""
        f = tmp_path / "test.txt"
        f.write_text("hello world")

        result = await read_file(str(f))
        assert result == "hello world"

    @pytest.mark.asyncio
    async def test_read_nonexistent_file(self, tmp_path):
        """Test reading a file that does not exist."""
        result = await read_file(str(tmp_path / "missing.txt"))
        assert "Error: File not found" in result

    @pytest.mark.asyncio
    async def test_read_directory(self, tmp_path):
        """Test reading a directory path."""
        result = await read_file(str(tmp_path))
        assert "Error: Path is not a file" in result

    @pytest.mark.asyncio
    async def test_read_truncates_large_file(self, tmp_path):
        """Test that large files are truncated to 20KB."""
        f = tmp_path / "large.txt"
        content = "x" * 25_000
        f.write_text(content)

        result = await read_file(str(f))
        assert "truncated" in result
        assert len(result) < 25_000

    @pytest.mark.asyncio
    async def test_read_small_file_not_truncated(self, tmp_path):
        """Test that small files are not truncated."""
        f = tmp_path / "small.txt"
        content = "short content"
        f.write_text(content)

        result = await read_file(str(f))
        assert result == content
        assert "truncated" not in result

    @pytest.mark.asyncio
    async def test_read_binary_file(self, tmp_path):
        """Test reading a file with binary-like content uses error replacement."""
        f = tmp_path / "binary.bin"
        f.write_bytes(b"\xff\xfe\x00\x01hello")

        result = await read_file(str(f))
        assert "hello" in result

    @pytest.mark.asyncio
    async def test_read_permission_denied(self, tmp_path):
        """Test reading a file without permission."""
        f = tmp_path / "noperm.txt"
        f.write_text("secret")
        f.chmod(0o000)

        try:
            result = await read_file(str(f))
            assert "Error: Permission denied" in result
        finally:
            f.chmod(0o644)

    @pytest.mark.asyncio
    async def test_read_home_expansion(self, tmp_path):
        """Test that ~ paths are expanded."""
        # This tests the expanduser() call - we mock it to point to tmp_path
        f = tmp_path / "test.txt"
        f.write_text("expanded")

        result = await read_file(str(f))
        assert result == "expanded"

    @pytest.mark.asyncio
    async def test_read_empty_file(self, tmp_path):
        """Test reading an empty file."""
        f = tmp_path / "empty.txt"
        f.write_text("")

        result = await read_file(str(f))
        assert result == ""


class TestWriteFile:
    @pytest.mark.asyncio
    async def test_write_new_file(self, tmp_path):
        """Test writing to a new file."""
        f = tmp_path / "new.txt"

        result = await write_file(str(f), "hello world")
        assert "Successfully" in result
        assert f.read_text() == "hello world"

    @pytest.mark.asyncio
    async def test_write_overwrites_existing(self, tmp_path):
        """Test overwriting an existing file."""
        f = tmp_path / "existing.txt"
        f.write_text("old content")

        result = await write_file(str(f), "new content")
        assert "Successfully" in result
        assert f.read_text() == "new content"

    @pytest.mark.asyncio
    async def test_write_creates_parent_dirs(self, tmp_path):
        """Test that parent directories are created."""
        f = tmp_path / "sub" / "dir" / "file.txt"

        result = await write_file(str(f), "deep write")
        assert "Successfully" in result
        assert f.read_text() == "deep write"

    @pytest.mark.asyncio
    async def test_write_reports_size(self, tmp_path):
        """Test that result includes character count."""
        f = tmp_path / "sized.txt"
        content = "12345"

        result = await write_file(str(f), content)
        assert "5 chars" in result

    @pytest.mark.asyncio
    async def test_write_permission_denied(self, tmp_path):
        """Test writing to a protected directory."""
        protected_dir = tmp_path / "protected"
        protected_dir.mkdir()
        protected_dir.chmod(0o000)

        try:
            f = protected_dir / "file.txt"
            result = await write_file(str(f), "content")
            assert "Error: Permission denied" in result
        finally:
            protected_dir.chmod(0o755)
