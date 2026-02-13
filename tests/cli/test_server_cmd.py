"""Tests for CLI server commands."""

import signal
from pathlib import Path
from unittest.mock import MagicMock, mock_open, patch

from harombe.cli.server_cmd import (
    _read_pid,
    _remove_pid,
    _write_pid,
    start_command,
    status_command,
    stop_command,
)
from harombe.config.schema import HarombeConfig

# ── PID helpers ──────────────────────────────────────────────────────────────


class TestPidHelpers:
    def test_write_and_read_pid(self, tmp_path):
        pid_file = tmp_path / "server.pid"
        with patch("harombe.cli.server_cmd.PID_FILE", pid_file):
            _write_pid(12345)
            assert pid_file.read_text() == "12345"

            with patch("os.kill"):  # process "exists"
                assert _read_pid() == 12345

    def test_read_pid_missing_file(self, tmp_path):
        pid_file = tmp_path / "server.pid"
        with patch("harombe.cli.server_cmd.PID_FILE", pid_file):
            assert _read_pid() is None

    def test_read_pid_stale_process(self, tmp_path):
        pid_file = tmp_path / "server.pid"
        pid_file.write_text("99999")
        with patch("harombe.cli.server_cmd.PID_FILE", pid_file):
            with patch("os.kill", side_effect=ProcessLookupError):
                assert _read_pid() is None
            assert not pid_file.exists()  # cleaned up

    def test_remove_pid(self, tmp_path):
        pid_file = tmp_path / "server.pid"
        pid_file.write_text("1")
        with patch("harombe.cli.server_cmd.PID_FILE", pid_file):
            _remove_pid()
            assert not pid_file.exists()

    def test_remove_pid_already_gone(self, tmp_path):
        pid_file = tmp_path / "nonexistent.pid"
        with patch("harombe.cli.server_cmd.PID_FILE", pid_file):
            _remove_pid()  # should not raise


# ── start_command ────────────────────────────────────────────────────────────


class TestStartCommand:
    def test_foreground_loads_config_and_runs(self, tmp_path):
        pid_file = tmp_path / "server.pid"
        config = HarombeConfig()
        config.server.host = "0.0.0.0"
        config.server.port = 9000

        with (
            patch("harombe.cli.server_cmd.PID_FILE", pid_file),
            patch("harombe.config.loader.load_config", return_value=config),
            patch("harombe.server.app.create_app") as mock_app,
            patch("uvicorn.run") as mock_uvicorn,
        ):
            mock_app.return_value = MagicMock()
            start_command(config_path=None, detach=False)

            mock_uvicorn.assert_called_once_with(
                mock_app.return_value,
                host="0.0.0.0",
                port=9000,
                log_level="info",
            )

    def test_foreground_with_custom_config_path(self, tmp_path):
        pid_file = tmp_path / "server.pid"
        config_path = str(tmp_path / "custom.yaml")
        config = HarombeConfig()

        with (
            patch("harombe.cli.server_cmd.PID_FILE", pid_file),
            patch("harombe.config.loader.load_config", return_value=config) as mock_load,
            patch("harombe.server.app.create_app", return_value=MagicMock()),
            patch("uvicorn.run"),
        ):
            start_command(config_path=config_path)
            mock_load.assert_called_once_with(Path(config_path))

    def test_config_load_failure(self, tmp_path):
        pid_file = tmp_path / "server.pid"
        with (
            patch("harombe.cli.server_cmd.PID_FILE", pid_file),
            patch(
                "harombe.config.loader.load_config",
                side_effect=Exception("config not found"),
            ),
        ):
            start_command(config_path=None)  # should not raise

    def test_refuses_if_already_running(self, tmp_path):
        pid_file = tmp_path / "server.pid"
        pid_file.write_text("12345")

        with (
            patch("harombe.cli.server_cmd.PID_FILE", pid_file),
            patch("os.kill"),  # process exists
            patch("harombe.config.loader.load_config") as mock_load,
        ):
            start_command(config_path=None)
            mock_load.assert_not_called()

    def test_detach_spawns_subprocess(self, tmp_path):
        pid_file = tmp_path / "server.pid"
        config = HarombeConfig()
        config.server.host = "127.0.0.1"
        config.server.port = 8000

        mock_proc = MagicMock()
        mock_proc.pid = 42

        with (
            patch("harombe.cli.server_cmd.PID_FILE", pid_file),
            patch("harombe.config.loader.load_config", return_value=config),
            patch("subprocess.Popen", return_value=mock_proc) as mock_popen,
            patch("builtins.open", mock_open()),
        ):
            start_command(config_path=None, detach=True)

            mock_popen.assert_called_once()
            assert pid_file.read_text() == "42"


# ── stop_command ─────────────────────────────────────────────────────────────


class TestStopCommand:
    def test_stop_running_server(self, tmp_path):
        pid_file = tmp_path / "server.pid"
        pid_file.write_text("12345")

        with (
            patch("harombe.cli.server_cmd.PID_FILE", pid_file),
            patch("os.kill") as mock_kill,
        ):
            stop_command()
            mock_kill.assert_any_call(12345, signal.SIGTERM)
            assert not pid_file.exists()

    def test_stop_no_server(self, tmp_path):
        pid_file = tmp_path / "server.pid"
        with patch("harombe.cli.server_cmd.PID_FILE", pid_file):
            stop_command()  # should not raise

    def test_stop_already_exited(self, tmp_path):
        pid_file = tmp_path / "server.pid"
        pid_file.write_text("99999")

        with (
            patch("harombe.cli.server_cmd.PID_FILE", pid_file),
            patch("os.kill", side_effect=[None, ProcessLookupError]),
        ):
            stop_command()  # should not raise
            assert not pid_file.exists()


# ── status_command ───────────────────────────────────────────────────────────


class TestStatusCommand:
    def test_status_server_running(self, tmp_path):
        pid_file = tmp_path / "server.pid"
        pid_file.write_text("12345")
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "status": "healthy",
            "model": "llama3.2:3b",
            "version": "0.3.1",
        }

        with (
            patch("harombe.cli.server_cmd.PID_FILE", pid_file),
            patch("os.kill"),
            patch("harombe.config.loader.load_config", return_value=HarombeConfig()),
            patch("httpx.get", return_value=mock_resp),
        ):
            status_command()  # should not raise

    def test_status_server_not_running(self, tmp_path):
        pid_file = tmp_path / "server.pid"
        with (
            patch("harombe.cli.server_cmd.PID_FILE", pid_file),
            patch("harombe.config.loader.load_config", return_value=HarombeConfig()),
            patch("httpx.get", side_effect=Exception("connection refused")),
        ):
            status_command()  # should not raise
