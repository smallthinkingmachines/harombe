"""Tests for CLI app entry point."""

from unittest.mock import patch

from typer.testing import CliRunner

from harombe.cli.app import app, main

runner = CliRunner()


def test_version_command():
    """Test 'version' prints harombe version string."""
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "harombe version" in result.output


def test_no_args_shows_help():
    """Test invoking with no arguments shows help (no_args_is_help)."""
    result = runner.invoke(app, [])
    # Typer's no_args_is_help triggers a SystemExit(0) that surfaces
    # as exit_code 0 or 2
    assert result.exit_code in (0, 2)
    assert "Usage" in result.output or "harombe" in result.output


def test_init_command():
    """Test 'init' delegates to init_command."""
    with patch("harombe.cli.init_cmd.init_command") as mock_init:
        result = runner.invoke(app, ["init", "--non-interactive"])
        mock_init.assert_called_once()
        assert result.exit_code == 0


def test_doctor_command():
    """Test 'doctor' delegates to doctor_command."""
    with patch("harombe.cli.doctor.doctor_command") as mock_cmd:
        result = runner.invoke(app, ["doctor"])
        mock_cmd.assert_called_once()
        assert result.exit_code == 0


def test_main_keyboard_interrupt():
    """Test main() handles KeyboardInterrupt with exit code 130."""
    with (
        patch("harombe.cli.app.app", side_effect=KeyboardInterrupt),
        patch("harombe.cli.app.sys") as mock_sys,
    ):
        main()
        mock_sys.exit.assert_called_with(130)


def test_main_exception():
    """Test main() handles unexpected exceptions with exit code 1."""
    with (
        patch("harombe.cli.app.app", side_effect=RuntimeError("test error")),
        patch("harombe.cli.app.sys") as mock_sys,
    ):
        main()
        mock_sys.exit.assert_called_with(1)


# --- Tests for uncovered command callbacks ---


def test_chat_command():
    """Test 'chat' delegates to chat_command."""
    with patch("harombe.cli.chat.chat_command") as mock_cmd:
        result = runner.invoke(app, ["chat"])
        mock_cmd.assert_called_once_with(config_path=None)
        assert result.exit_code == 0


def test_start_command():
    """Test 'start' delegates to start_command."""
    with patch("harombe.cli.server_cmd.start_command") as mock_cmd:
        result = runner.invoke(app, ["start"])
        mock_cmd.assert_called_once_with(config_path=None, detach=False)
        assert result.exit_code == 0


def test_stop_command():
    """Test 'stop' delegates to stop_command."""
    with patch("harombe.cli.server_cmd.stop_command") as mock_cmd:
        result = runner.invoke(app, ["stop"])
        mock_cmd.assert_called_once()
        assert result.exit_code == 0


def test_status_command():
    """Test 'status' delegates to status_command."""
    with patch("harombe.cli.server_cmd.status_command") as mock_cmd:
        result = runner.invoke(app, ["status"])
        mock_cmd.assert_called_once()
        assert result.exit_code == 0


def test_plugin_list_command():
    """Test 'plugin list' delegates to list_plugins."""
    with patch("harombe.cli.plugin_cmd.list_plugins") as mock_cmd:
        result = runner.invoke(app, ["plugin", "list"])
        mock_cmd.assert_called_once()
        assert result.exit_code == 0


def test_plugin_info_command():
    """Test 'plugin info' delegates to info_plugin."""
    with patch("harombe.cli.plugin_cmd.info_plugin") as mock_cmd:
        result = runner.invoke(app, ["plugin", "info", "my-plugin"])
        mock_cmd.assert_called_once_with("my-plugin")
        assert result.exit_code == 0


def test_plugin_enable_command():
    """Test 'plugin enable' delegates to enable_plugin."""
    with patch("harombe.cli.plugin_cmd.enable_plugin") as mock_cmd:
        result = runner.invoke(app, ["plugin", "enable", "my-plugin"])
        mock_cmd.assert_called_once_with("my-plugin")
        assert result.exit_code == 0


def test_plugin_disable_command():
    """Test 'plugin disable' delegates to disable_plugin."""
    with patch("harombe.cli.plugin_cmd.disable_plugin") as mock_cmd:
        result = runner.invoke(app, ["plugin", "disable", "my-plugin"])
        mock_cmd.assert_called_once_with("my-plugin")
        assert result.exit_code == 0


def test_mcp_serve_command():
    """Test 'mcp serve' delegates to serve_command."""
    with patch("harombe.cli.mcp_cmd.serve_command") as mock_cmd:
        result = runner.invoke(app, ["mcp", "serve"])
        mock_cmd.assert_called_once_with(
            transport="stdio",
            host="127.0.0.1",
            port=8200,
            config_path=None,
        )
        assert result.exit_code == 0


def test_cluster_init_command():
    """Test 'cluster init' delegates to cluster_init_command."""
    with patch("harombe.cli.cluster_cmd.cluster_init_command") as mock_cmd:
        result = runner.invoke(app, ["cluster", "init"])
        mock_cmd.assert_called_once()
        assert result.exit_code == 0


def test_cluster_status_command():
    """Test 'cluster status' delegates to cluster_status_command."""
    with patch("harombe.cli.cluster_cmd.cluster_status_command") as mock_cmd:
        result = runner.invoke(app, ["cluster", "status"])
        mock_cmd.assert_called_once_with(config_path=None)
        assert result.exit_code == 0


def test_cluster_test_command():
    """Test 'cluster test' delegates to cluster_test_command."""
    with patch("harombe.cli.cluster_cmd.cluster_test_command") as mock_cmd:
        result = runner.invoke(app, ["cluster", "test"])
        mock_cmd.assert_called_once_with(config_path=None)
        assert result.exit_code == 0


def test_cluster_metrics_command():
    """Test 'cluster metrics' delegates to cluster_metrics_command."""
    with patch("harombe.cli.cluster_cmd.cluster_metrics_command") as mock_cmd:
        result = runner.invoke(app, ["cluster", "metrics"])
        mock_cmd.assert_called_once_with(config_path=None, node=None)
        assert result.exit_code == 0


def test_audit_events_command():
    """Test 'audit events' delegates to query_events."""
    with patch("harombe.cli.audit_cmd.query_events") as mock_cmd:
        result = runner.invoke(app, ["audit", "events"])
        mock_cmd.assert_called_once_with(
            db_path="~/.harombe/audit.db",
            session_id=None,
            correlation_id=None,
            limit=20,
            output_format="table",
        )
        assert result.exit_code == 0


def test_audit_tools_command():
    """Test 'audit tools' delegates to query_tools."""
    with patch("harombe.cli.audit_cmd.query_tools") as mock_cmd:
        result = runner.invoke(app, ["audit", "tools"])
        mock_cmd.assert_called_once_with(
            db_path="~/.harombe/audit.db",
            tool_name=None,
            hours=None,
            limit=20,
            output_format="table",
        )
        assert result.exit_code == 0


def test_audit_security_command():
    """Test 'audit security' delegates to query_security."""
    with patch("harombe.cli.audit_cmd.query_security") as mock_cmd:
        result = runner.invoke(app, ["audit", "security"])
        mock_cmd.assert_called_once_with(
            db_path="~/.harombe/audit.db",
            decision_type=None,
            decision=None,
            limit=20,
            output_format="table",
        )
        assert result.exit_code == 0


def test_audit_stats_command():
    """Test 'audit stats' delegates to stats."""
    with patch("harombe.cli.audit_cmd.stats") as mock_cmd:
        result = runner.invoke(app, ["audit", "stats"])
        mock_cmd.assert_called_once_with(db_path="~/.harombe/audit.db", hours=None)
        assert result.exit_code == 0


def test_audit_export_command():
    """Test 'audit export' delegates to export."""
    with patch("harombe.cli.audit_cmd.export") as mock_cmd:
        result = runner.invoke(app, ["audit", "export", "/tmp/audit.json"])
        mock_cmd.assert_called_once()
        assert result.exit_code == 0


def test_voice_command():
    """Test 'voice' delegates to voice_command via asyncio.run."""
    with (
        patch(
            "harombe.cli.voice.voice_command",
        ) as mock_cmd,
        patch("asyncio.run") as mock_run,
    ):
        result = runner.invoke(app, ["voice"])
        mock_cmd.assert_called_once_with(
            stt_model="medium",
            tts_engine="piper",
            tts_model="en_US-lessac-medium",
        )
        mock_run.assert_called_once()
        assert result.exit_code == 0
