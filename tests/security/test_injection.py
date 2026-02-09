"""Tests for secret injection implementation."""

import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from harombe.security.injection import (
    DotEnvLoader,
    SecretInjector,
    SecretRotationScheduler,
    create_injector,
)
from harombe.security.vault import VaultBackend


class MockVaultBackend(VaultBackend):
    """Mock vault backend for testing."""

    def __init__(self):
        """Initialize mock vault with test secrets."""
        self.secrets = {
            "github/api-token": "ghp_test1234567890abcdefghijklmnop",
            "slack/webhook-url": "https://hooks.slack.com/services/TEST/SECRET",
            "api/key": "sk-test-1234567890abcdefghijklmnopqrstuvwxyz",
            "database/password": 'P@ssw0rd!with"quotes"and\\backslashes',
        }
        self.rotation_count = {}

    async def get_secret(self, key: str) -> str | None:
        """Get secret from mock storage."""
        return self.secrets.get(key)

    async def set_secret(self, key: str, value: str, **metadata) -> None:
        """Store secret in mock storage."""
        self.secrets[key] = value

    async def delete_secret(self, key: str) -> None:
        """Delete secret from mock storage."""
        self.secrets.pop(key, None)

    async def list_secrets(self, prefix: str = "") -> list[str]:
        """List secrets with optional prefix."""
        if prefix:
            return [k for k in self.secrets if k.startswith(prefix)]
        return list(self.secrets.keys())

    async def rotate_secret(self, key: str) -> None:
        """Mock secret rotation."""
        if key in self.secrets:
            self.rotation_count[key] = self.rotation_count.get(key, 0) + 1


@pytest.fixture
def mock_vault():
    """Provide a mock vault backend."""
    return MockVaultBackend()


@pytest.fixture
def temp_dir():
    """Provide a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


@pytest.fixture
def secret_injector(mock_vault, temp_dir):
    """Provide a SecretInjector instance."""
    return SecretInjector(vault_backend=mock_vault, temp_dir=temp_dir)


class TestSecretInjector:
    """Tests for SecretInjector."""

    @pytest.mark.asyncio
    async def test_inject_secrets_creates_env_file(self, secret_injector, temp_dir):
        """Test that inject_secrets creates a .env file."""
        secret_mapping = {
            "GITHUB_TOKEN": "github/api-token",
            "SLACK_WEBHOOK": "slack/webhook-url",
        }

        env_file = await secret_injector.inject_secrets("test-container", secret_mapping)

        assert env_file.exists()
        assert env_file.name == "test-container.env"
        assert env_file.parent == Path(temp_dir)

    @pytest.mark.asyncio
    async def test_inject_secrets_content(self, secret_injector):
        """Test that .env file contains correct content."""
        secret_mapping = {
            "GITHUB_TOKEN": "github/api-token",
            "API_KEY": "api/key",
        }

        env_file = await secret_injector.inject_secrets("test-container", secret_mapping)

        with open(env_file) as f:
            content = f.read()

        assert 'GITHUB_TOKEN="ghp_test1234567890abcdefghijklmnop"' in content
        assert 'API_KEY="sk-test-1234567890abcdefghijklmnopqrstuvwxyz"' in content

    @pytest.mark.asyncio
    async def test_inject_secrets_escapes_special_chars(self, secret_injector):
        """Test that special characters are properly escaped."""
        secret_mapping = {
            "DATABASE_PASSWORD": "database/password",
        }

        env_file = await secret_injector.inject_secrets("test-container", secret_mapping)

        with open(env_file) as f:
            content = f.read()

        # Quotes and backslashes should be escaped
        assert 'DATABASE_PASSWORD="P@ssw0rd!with\\"quotes\\"and\\\\backslashes"' in content

    @pytest.mark.asyncio
    async def test_inject_secrets_secure_permissions(self, secret_injector):
        """Test that .env file has secure permissions (owner read-only)."""
        secret_mapping = {
            "GITHUB_TOKEN": "github/api-token",
        }

        env_file = await secret_injector.inject_secrets("test-container", secret_mapping)

        # Check file permissions (0o400 = owner read-only)
        stat_info = os.stat(env_file)
        mode = stat_info.st_mode & 0o777
        assert mode == 0o400

    @pytest.mark.asyncio
    async def test_inject_secrets_missing_secret_raises_error(self, secret_injector):
        """Test that missing secrets raise ValueError."""
        secret_mapping = {
            "NONEXISTENT": "nonexistent/key",
        }

        with pytest.raises(ValueError, match="Secret 'nonexistent/key' not found in vault"):
            await secret_injector.inject_secrets("test-container", secret_mapping)

    @pytest.mark.asyncio
    async def test_inject_secrets_multiple_containers(self, secret_injector, temp_dir):
        """Test that multiple containers get separate .env files."""
        secret_mapping = {
            "TOKEN": "github/api-token",
        }

        env_file_1 = await secret_injector.inject_secrets("container-1", secret_mapping)
        env_file_2 = await secret_injector.inject_secrets("container-2", secret_mapping)

        assert env_file_1.exists()
        assert env_file_2.exists()
        assert env_file_1 != env_file_2
        assert env_file_1.name == "container-1.env"
        assert env_file_2.name == "container-2.env"

    @pytest.mark.asyncio
    async def test_cleanup_removes_file(self, secret_injector):
        """Test that cleanup removes the secrets file."""
        secret_mapping = {
            "TOKEN": "github/api-token",
        }

        env_file = await secret_injector.inject_secrets("test-container", secret_mapping)
        assert env_file.exists()

        # Change permissions back to allow cleanup (file was set to read-only)
        os.chmod(env_file, 0o600)
        secret_injector.cleanup("test-container")
        assert not env_file.exists()

    @pytest.mark.asyncio
    async def test_cleanup_overwrites_before_delete(self, secret_injector):
        """Test that cleanup overwrites file with random data before deletion."""
        secret_mapping = {
            "TOKEN": "github/api-token",
        }

        env_file = await secret_injector.inject_secrets("test-container", secret_mapping)
        # File exists with content
        assert env_file.stat().st_size > 0

        # Change permissions to allow reading and cleanup
        os.chmod(env_file, 0o600)

        # Track file writes to verify overwrite happened
        original_open = open
        write_called = {"count": 0, "mode": None}

        def tracking_open(*args, **kwargs):
            if len(args) > 1 and "w" in args[1]:
                write_called["count"] += 1
                write_called["mode"] = args[1]
            return original_open(*args, **kwargs)

        with patch("builtins.open", side_effect=tracking_open):
            secret_injector.cleanup("test-container")

        # File should be deleted
        assert not env_file.exists()
        # Should have written to file (overwrite operation)
        assert write_called["count"] >= 1
        assert "b" in write_called["mode"]  # Binary write mode

    @pytest.mark.asyncio
    async def test_cleanup_nonexistent_file(self, secret_injector):
        """Test that cleanup handles nonexistent files gracefully."""
        # Should not raise an error
        secret_injector.cleanup("nonexistent-container")

    @pytest.mark.asyncio
    async def test_cleanup_all_removes_all_files(self, secret_injector):
        """Test that cleanup_all removes all .env files."""
        secret_mapping = {
            "TOKEN": "github/api-token",
        }

        env_file_1 = await secret_injector.inject_secrets("container-1", secret_mapping)
        env_file_2 = await secret_injector.inject_secrets("container-2", secret_mapping)
        env_file_3 = await secret_injector.inject_secrets("container-3", secret_mapping)

        assert env_file_1.exists()
        assert env_file_2.exists()
        assert env_file_3.exists()

        # Change permissions to allow cleanup
        os.chmod(env_file_1, 0o600)
        os.chmod(env_file_2, 0o600)
        os.chmod(env_file_3, 0o600)

        secret_injector.cleanup_all()

        assert not env_file_1.exists()
        assert not env_file_2.exists()
        assert not env_file_3.exists()

    @pytest.mark.asyncio
    async def test_temp_dir_created_with_secure_permissions(self, mock_vault):
        """Test that temp directory is created with secure permissions."""
        with tempfile.TemporaryDirectory() as tmpdir:
            temp_path = Path(tmpdir) / "test-secrets"
            SecretInjector(vault_backend=mock_vault, temp_dir=str(temp_path))

            assert temp_path.exists()
            stat_info = os.stat(temp_path)
            mode = stat_info.st_mode & 0o777
            assert mode == 0o700  # Owner only


class TestDotEnvLoader:
    """Tests for DotEnvLoader."""

    @pytest.fixture
    def env_loader(self):
        """Provide a DotEnvLoader instance."""
        return DotEnvLoader(warn_on_secrets=False)

    def test_load_simple_env_file(self, env_loader, temp_dir):
        """Test loading a simple .env file."""
        env_file = Path(temp_dir) / ".env"
        env_file.write_text("KEY1=value1\nKEY2=value2\n")

        variables = env_loader.load(env_file)

        assert variables == {"KEY1": "value1", "KEY2": "value2"}

    def test_load_env_file_with_quotes(self, env_loader, temp_dir):
        """Test loading .env file with quoted values."""
        env_file = Path(temp_dir) / ".env"
        env_file.write_text("KEY1=\"value with spaces\"\nKEY2='single quotes'\n")

        variables = env_loader.load(env_file)

        assert variables == {"KEY1": "value with spaces", "KEY2": "single quotes"}

    def test_load_env_file_with_comments(self, env_loader, temp_dir):
        """Test that comments are ignored."""
        env_file = Path(temp_dir) / ".env"
        env_file.write_text("# This is a comment\nKEY1=value1\n# Another comment\nKEY2=value2\n")

        variables = env_loader.load(env_file)

        assert variables == {"KEY1": "value1", "KEY2": "value2"}

    def test_load_env_file_with_empty_lines(self, env_loader, temp_dir):
        """Test that empty lines are ignored."""
        env_file = Path(temp_dir) / ".env"
        env_file.write_text("KEY1=value1\n\n\nKEY2=value2\n\n")

        variables = env_loader.load(env_file)

        assert variables == {"KEY1": "value1", "KEY2": "value2"}

    def test_load_env_file_variable_expansion_braces(self, env_loader, temp_dir):
        """Test ${VAR} style variable expansion."""
        env_file = Path(temp_dir) / ".env"
        env_file.write_text("BASE_URL=https://api.example.com\nAPI_URL=${BASE_URL}/v1\n")

        variables = env_loader.load(env_file)

        assert variables["BASE_URL"] == "https://api.example.com"
        assert variables["API_URL"] == "https://api.example.com/v1"

    def test_load_env_file_variable_expansion_simple(self, env_loader, temp_dir):
        """Test $VAR style variable expansion."""
        env_file = Path(temp_dir) / ".env"
        env_file.write_text("USER=john\nHOME=/home/$USER\n")

        variables = env_loader.load(env_file)

        assert variables["USER"] == "john"
        assert variables["HOME"] == "/home/john"

    def test_load_env_file_variable_expansion_from_environment(self, env_loader, temp_dir):
        """Test variable expansion from existing environment variables."""
        os.environ["EXISTING_VAR"] = "existing_value"

        env_file = Path(temp_dir) / ".env"
        env_file.write_text("NEW_VAR=${EXISTING_VAR}/suffix\n")

        try:
            variables = env_loader.load(env_file)
            assert variables["NEW_VAR"] == "existing_value/suffix"
        finally:
            os.environ.pop("EXISTING_VAR", None)

    def test_load_env_file_variable_expansion_missing_var(self, env_loader, temp_dir):
        """Test that missing variables expand to empty string."""
        env_file = Path(temp_dir) / ".env"
        env_file.write_text("VALUE=${NONEXISTENT_VAR}\n")

        variables = env_loader.load(env_file)

        assert variables["VALUE"] == ""

    def test_load_sets_environment_variables(self, env_loader, temp_dir):
        """Test that loaded variables are set in environment."""
        env_file = Path(temp_dir) / ".env"
        env_file.write_text("TEST_VAR=test_value\n")

        # Clean up any existing value
        os.environ.pop("TEST_VAR", None)

        try:
            env_loader.load(env_file)
            assert os.environ["TEST_VAR"] == "test_value"
        finally:
            os.environ.pop("TEST_VAR", None)

    def test_load_respects_override_flag(self, env_loader, temp_dir):
        """Test that override flag controls whether existing vars are overwritten."""
        env_file = Path(temp_dir) / ".env"
        env_file.write_text("TEST_VAR=new_value\n")

        os.environ["TEST_VAR"] = "existing_value"

        try:
            # Without override, existing value should be kept
            env_loader.load(env_file, override=False)
            assert os.environ["TEST_VAR"] == "existing_value"

            # With override, new value should be set
            env_loader.load(env_file, override=True)
            assert os.environ["TEST_VAR"] == "new_value"
        finally:
            os.environ.pop("TEST_VAR", None)

    def test_load_nonexistent_file_raises_error(self, env_loader, temp_dir):
        """Test that loading nonexistent file raises FileNotFoundError."""
        env_file = Path(temp_dir) / "nonexistent.env"

        with pytest.raises(FileNotFoundError, match=r"\.env file not found"):
            env_loader.load(env_file)

    def test_load_invalid_line_format(self, env_loader, temp_dir, capsys):
        """Test that invalid lines generate warnings."""
        env_file = Path(temp_dir) / ".env"
        env_file.write_text("VALID=value\nINVALID_LINE_NO_EQUALS\nVALID2=value2\n")

        variables = env_loader.load(env_file)

        # Invalid line should be skipped
        assert variables == {"VALID": "value", "VALID2": "value2"}

        # Should print warning
        captured = capsys.readouterr()
        assert "Warning: Invalid line" in captured.out

    def test_load_with_whitespace(self, env_loader, temp_dir):
        """Test that whitespace around keys and values is handled correctly."""
        env_file = Path(temp_dir) / ".env"
        env_file.write_text("  KEY1  =  value1  \n KEY2=value2\n")

        variables = env_loader.load(env_file)

        assert variables == {"KEY1": "value1", "KEY2": "value2"}

    def test_load_equals_in_value(self, env_loader, temp_dir):
        """Test that equals sign in value is preserved."""
        env_file = Path(temp_dir) / ".env"
        env_file.write_text("URL=https://example.com?param=value\n")

        variables = env_loader.load(env_file)

        assert variables["URL"] == "https://example.com?param=value"

    @patch("harombe.security.secrets.SecretScanner")
    def test_warn_on_secrets_enabled(self, mock_scanner_class, temp_dir, capsys):
        """Test that secret warnings are shown when enabled."""
        # Create mock scanner instance
        mock_scanner = MagicMock()
        mock_match = MagicMock()
        mock_match.confidence = 0.95
        mock_scanner.scan.return_value = [mock_match]
        mock_scanner_class.return_value = mock_scanner

        loader = DotEnvLoader(warn_on_secrets=True)
        env_file = Path(temp_dir) / ".env"
        env_file.write_text("SECRET_KEY=sk-1234567890abcdefghijklmnop\n")

        loader.load(env_file)

        # Should have called scanner
        mock_scanner.scan.assert_called()

        # Should print warning
        captured = capsys.readouterr()
        assert "SECURITY WARNING" in captured.out

    @patch("harombe.security.secrets.SecretScanner")
    def test_warn_on_secrets_disabled(self, mock_scanner_class, temp_dir):
        """Test that secret warnings are not shown when disabled."""
        mock_scanner = MagicMock()
        mock_scanner_class.return_value = mock_scanner

        loader = DotEnvLoader(warn_on_secrets=False)
        env_file = Path(temp_dir) / ".env"
        env_file.write_text("SECRET_KEY=sk-1234567890abcdefghijklmnop\n")

        loader.load(env_file)

        # Should not have called scanner
        mock_scanner.scan.assert_not_called()

    def test_complex_variable_expansion(self, env_loader, temp_dir):
        """Test complex variable expansion scenarios."""
        env_file = Path(temp_dir) / ".env"
        env_file.write_text(
            "HOST=localhost\n"
            "PORT=8080\n"
            "PROTOCOL=https\n"
            "BASE_URL=$PROTOCOL://$HOST:$PORT\n"
            "API_URL=${BASE_URL}/api/v1\n"
        )

        variables = env_loader.load(env_file)

        assert variables["HOST"] == "localhost"
        assert variables["PORT"] == "8080"
        assert variables["PROTOCOL"] == "https"
        assert variables["BASE_URL"] == "https://localhost:8080"
        assert variables["API_URL"] == "https://localhost:8080/api/v1"


class TestSecretRotationScheduler:
    """Tests for SecretRotationScheduler."""

    @pytest.fixture
    def rotation_scheduler(self, mock_vault, secret_injector):
        """Provide a SecretRotationScheduler instance."""
        return SecretRotationScheduler(vault_backend=mock_vault, injector=secret_injector)

    def test_add_policy(self, rotation_scheduler):
        """Test adding a rotation policy."""
        rotation_scheduler.add_policy("github/api-token", "30d")

        assert "github/api-token" in rotation_scheduler.rotation_policies
        assert rotation_scheduler.rotation_policies["github/api-token"] == "30d"

    def test_add_multiple_policies(self, rotation_scheduler):
        """Test adding multiple rotation policies."""
        rotation_scheduler.add_policy("github/api-token", "30d")
        rotation_scheduler.add_policy("slack/webhook-url", "90d")
        rotation_scheduler.add_policy("api/key", "60d")

        assert len(rotation_scheduler.rotation_policies) == 3
        assert rotation_scheduler.rotation_policies["github/api-token"] == "30d"
        assert rotation_scheduler.rotation_policies["slack/webhook-url"] == "90d"
        assert rotation_scheduler.rotation_policies["api/key"] == "60d"

    def test_add_policy_overwrites_existing(self, rotation_scheduler):
        """Test that adding a policy overwrites existing policy for same key."""
        rotation_scheduler.add_policy("github/api-token", "30d")
        rotation_scheduler.add_policy("github/api-token", "60d")

        assert rotation_scheduler.rotation_policies["github/api-token"] == "60d"

    @pytest.mark.asyncio
    async def test_rotate_secret_with_generator(self, rotation_scheduler, mock_vault):
        """Test rotating a secret with a custom generator."""
        original_value = await mock_vault.get_secret("github/api-token")

        def generator():
            return "ghp_new_token_1234567890abcdefghijklmnop"

        await rotation_scheduler.rotate_secret("github/api-token", generator=generator)

        new_value = await mock_vault.get_secret("github/api-token")
        assert new_value != original_value
        assert new_value == "ghp_new_token_1234567890abcdefghijklmnop"

    @pytest.mark.asyncio
    async def test_rotate_secret_without_generator(self, rotation_scheduler, mock_vault):
        """Test rotating a secret using vault's rotation mechanism."""
        await rotation_scheduler.rotate_secret("github/api-token")

        # Should have called vault's rotate_secret
        assert mock_vault.rotation_count.get("github/api-token", 0) == 1

    @pytest.mark.asyncio
    async def test_rotate_secret_multiple_times(self, rotation_scheduler, mock_vault):
        """Test rotating a secret multiple times."""
        await rotation_scheduler.rotate_secret("github/api-token")
        await rotation_scheduler.rotate_secret("github/api-token")
        await rotation_scheduler.rotate_secret("github/api-token")

        assert mock_vault.rotation_count.get("github/api-token", 0) == 3

    @pytest.mark.asyncio
    async def test_check_and_rotate(self, rotation_scheduler):
        """Test check_and_rotate method (currently no-op)."""
        # Should not raise an error
        await rotation_scheduler.check_and_rotate()


class TestCreateInjector:
    """Tests for create_injector factory function."""

    def test_create_injector_with_env_provider(self):
        """Test creating injector with env provider."""
        injector = create_injector(provider="env")

        assert isinstance(injector, SecretInjector)
        assert injector.vault is not None

    def test_create_injector_with_custom_temp_dir(self):
        """Test creating injector with custom temp directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            temp_path = Path(tmpdir) / "custom-secrets"
            # Create vault backend and injector separately to set custom temp_dir
            from harombe.security.vault import create_vault_backend

            vault = create_vault_backend(provider="env")
            injector = SecretInjector(vault_backend=vault, temp_dir=str(temp_path))

            assert injector.temp_dir == temp_path
            assert temp_path.exists()

    def test_create_injector_with_sops_provider(self):
        """Test creating injector with sops provider."""
        with tempfile.TemporaryDirectory() as tmpdir:
            secrets_file = Path(tmpdir) / "secrets.enc.json"
            injector = create_injector(provider="sops", secrets_file=str(secrets_file))

            assert isinstance(injector, SecretInjector)

    def test_create_injector_invalid_provider(self):
        """Test that invalid provider raises ValueError."""
        with pytest.raises(ValueError, match="Unknown vault provider"):
            create_injector(provider="invalid")


class TestIntegration:
    """Integration tests for secret injection workflow."""

    @pytest.mark.asyncio
    async def test_full_injection_workflow(self, mock_vault, temp_dir):
        """Test complete workflow: inject -> use -> cleanup."""
        # Create injector
        injector = SecretInjector(vault_backend=mock_vault, temp_dir=temp_dir)

        # Inject secrets
        secret_mapping = {
            "GITHUB_TOKEN": "github/api-token",
            "SLACK_WEBHOOK": "slack/webhook-url",
        }
        env_file = await injector.inject_secrets("test-app", secret_mapping)

        # Verify file exists and has correct permissions
        assert env_file.exists()
        stat_info = os.stat(env_file)
        assert (stat_info.st_mode & 0o777) == 0o400

        # Change permissions to allow reading
        os.chmod(env_file, 0o600)

        # Load and verify content
        loader = DotEnvLoader(warn_on_secrets=False)
        variables = loader.load(env_file, override=False)

        assert variables["GITHUB_TOKEN"] == "ghp_test1234567890abcdefghijklmnop"
        assert variables["SLACK_WEBHOOK"] == "https://hooks.slack.com/services/TEST/SECRET"

        # Cleanup
        injector.cleanup("test-app")
        assert not env_file.exists()

    @pytest.mark.asyncio
    async def test_rotation_workflow(self, mock_vault, temp_dir):
        """Test secret rotation workflow."""
        # Create components
        injector = SecretInjector(vault_backend=mock_vault, temp_dir=temp_dir)
        scheduler = SecretRotationScheduler(vault_backend=mock_vault, injector=injector)

        # Add rotation policy
        scheduler.add_policy("github/api-token", "30d")

        # Inject initial secrets
        secret_mapping = {"GITHUB_TOKEN": "github/api-token"}
        env_file_1 = await injector.inject_secrets("app-v1", secret_mapping)

        # Change permissions to allow reading
        os.chmod(env_file_1, 0o600)

        # Load initial value
        loader = DotEnvLoader(warn_on_secrets=False)
        vars_1 = loader.load(env_file_1, override=False)
        initial_value = vars_1["GITHUB_TOKEN"]

        # Rotate secret
        def generator():
            return "ghp_rotated_token_9876543210"

        await scheduler.rotate_secret("github/api-token", generator=generator)

        # Inject rotated secrets
        env_file_2 = await injector.inject_secrets("app-v2", secret_mapping)

        # Change permissions to allow reading
        os.chmod(env_file_2, 0o600)

        # Load rotated value
        vars_2 = loader.load(env_file_2, override=False)
        rotated_value = vars_2["GITHUB_TOKEN"]

        assert rotated_value != initial_value
        assert rotated_value == "ghp_rotated_token_9876543210"

        # Cleanup
        injector.cleanup_all()
