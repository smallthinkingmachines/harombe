"""Tests for vault backend implementations.

This test suite provides comprehensive coverage for the vault backend system,
which supports multiple secret storage backends for secure credential management.

Test Coverage:
--------------

1. EnvVarBackend (Environment Variables - Development Only)
   - Basic CRUD operations (get, set, delete secrets)
   - List secrets with prefix filtering
   - Key name conversion (handles slashes, case insensitivity)
   - Custom prefix configuration
   - No-op rotation behavior

2. SOPSBackend (File Encryption with SOPS)
   - Encrypted file operations (mocked subprocess calls)
   - Secret retrieval from encrypted files
   - Secret storage and deletion
   - Prefix-based listing
   - Caching behavior to avoid redundant decryption
   - Error handling (decrypt failure, encrypt failure, missing binary)
   - Custom age key file support
   - Non-existent file handling

3. HashiCorpVault (Production Vault Server)
   - KV v2 secret operations (mocked HTTP requests)
   - Token authentication and initialization
   - CRUD operations with proper error handling
   - List secrets (including empty results)
   - Secret rotation
   - Token auto-renewal mechanism
   - Background renewal task management
   - Error recovery in renewal loop
   - Custom mount points and namespaces
   - Connection error handling

4. Factory Function (create_vault_backend)
   - Creates correct backend for each provider type
   - Default provider behavior
   - Error handling for unknown providers

5. Integration Tests
   - Full workflow tests for EnvVarBackend
   - Non-existent file handling for SOPSBackend

Coverage: 97% of vault.py (missing only abstract method pass statements)

Mock Strategy:
--------------
- subprocess.run: Mocked for SOPS backend to avoid requiring sops binary
- httpx.AsyncClient: Mocked for HashiCorpVault to avoid requiring Vault server
- os.environ: Carefully managed with fixtures to avoid test pollution

All tests use pytest-asyncio for async test support.
"""

import asyncio
import contextlib
import json
import os
import subprocess
from unittest.mock import AsyncMock, Mock, patch

import httpx
import pytest

from harombe.security.vault import (
    EnvVarBackend,
    HashiCorpVault,
    SOPSBackend,
    create_vault_backend,
)


class TestEnvVarBackend:
    """Tests for EnvVarBackend."""

    @pytest.fixture
    def backend(self):
        """Create EnvVarBackend instance."""
        return EnvVarBackend(prefix="TEST_SECRET_")

    @pytest.fixture
    def clean_env(self):
        """Clean up test environment variables."""
        # Store original env
        original_env = os.environ.copy()

        # Remove test vars before test
        for key in list(os.environ.keys()):
            if key.startswith("TEST_SECRET_"):
                del os.environ[key]

        yield

        # Restore original env after test
        for key in list(os.environ.keys()):
            if key.startswith("TEST_SECRET_"):
                del os.environ[key]

        for key, value in original_env.items():
            if key.startswith("TEST_SECRET_"):
                os.environ[key] = value

    @pytest.mark.asyncio
    async def test_get_secret_existing(self, backend, clean_env):
        """Test getting an existing secret from environment."""
        os.environ["TEST_SECRET_MY_KEY"] = "secret_value"

        value = await backend.get_secret("my_key")

        assert value == "secret_value"

    @pytest.mark.asyncio
    async def test_get_secret_not_found(self, backend, clean_env):
        """Test getting a non-existent secret."""
        value = await backend.get_secret("nonexistent")

        assert value is None

    @pytest.mark.asyncio
    async def test_set_secret(self, backend, clean_env):
        """Test setting a secret in environment."""
        await backend.set_secret("new_key", "new_value")

        assert os.environ["TEST_SECRET_NEW_KEY"] == "new_value"

    @pytest.mark.asyncio
    async def test_delete_secret_existing(self, backend, clean_env):
        """Test deleting an existing secret."""
        os.environ["TEST_SECRET_DELETE_ME"] = "value"

        await backend.delete_secret("delete_me")

        assert "TEST_SECRET_DELETE_ME" not in os.environ

    @pytest.mark.asyncio
    async def test_delete_secret_not_found(self, backend, clean_env):
        """Test deleting a non-existent secret (should not raise)."""
        await backend.delete_secret("nonexistent")
        # Should not raise an exception

    @pytest.mark.asyncio
    async def test_list_secrets_all(self, backend, clean_env):
        """Test listing all secrets."""
        os.environ["TEST_SECRET_KEY1"] = "value1"
        os.environ["TEST_SECRET_KEY2"] = "value2"
        os.environ["OTHER_KEY"] = "value3"

        keys = await backend.list_secrets()

        assert len(keys) == 2
        assert "key1" in keys
        assert "key2" in keys
        assert "other" not in keys

    @pytest.mark.asyncio
    async def test_list_secrets_with_prefix(self, backend, clean_env):
        """Test listing secrets with prefix filter."""
        os.environ["TEST_SECRET_API_KEY"] = "value1"
        os.environ["TEST_SECRET_API_SECRET"] = "value2"
        os.environ["TEST_SECRET_DB_PASSWORD"] = "value3"

        keys = await backend.list_secrets(prefix="api")

        assert len(keys) == 2
        assert "api/key" in keys or "api_key" in keys.lower()
        assert "api/secret" in keys or "api_secret" in keys.lower()

    @pytest.mark.asyncio
    async def test_key_name_conversion_with_slashes(self, backend, clean_env):
        """Test key name conversion with slashes."""
        await backend.set_secret("path/to/secret", "value")

        # Should convert to uppercase and replace / with _
        assert os.environ["TEST_SECRET_PATH_TO_SECRET"] == "value"

        # Should be able to retrieve it
        value = await backend.get_secret("path/to/secret")
        assert value == "value"

    @pytest.mark.asyncio
    async def test_key_name_conversion_case_insensitive(self, backend, clean_env):
        """Test key name conversion is case insensitive."""
        os.environ["TEST_SECRET_MY_KEY"] = "value"

        # Should work with any case
        value1 = await backend.get_secret("my_key")
        value2 = await backend.get_secret("MY_KEY")
        value3 = await backend.get_secret("My_Key")

        assert value1 == "value"
        assert value2 == "value"
        assert value3 == "value"

    @pytest.mark.asyncio
    async def test_rotate_secret_noop(self, backend, clean_env):
        """Test rotate_secret is a no-op."""
        os.environ["TEST_SECRET_ROTATE_ME"] = "value"

        await backend.rotate_secret("rotate_me")

        # Should still exist unchanged
        assert os.environ["TEST_SECRET_ROTATE_ME"] == "value"

    @pytest.mark.asyncio
    async def test_custom_prefix(self, clean_env):
        """Test using a custom prefix."""
        backend = EnvVarBackend(prefix="CUSTOM_")

        await backend.set_secret("key", "value")

        assert os.environ["CUSTOM_KEY"] == "value"


class TestSOPSBackend:
    """Tests for SOPSBackend."""

    @pytest.fixture
    def backend(self, tmp_path):
        """Create SOPSBackend instance with temp file."""
        secrets_file = tmp_path / "secrets.enc.json"
        return SOPSBackend(secrets_file=str(secrets_file))

    @pytest.mark.asyncio
    async def test_get_secret_from_encrypted_file(self, backend, tmp_path):
        """Test getting secret from encrypted file."""
        # Create the file so it tries to decrypt
        backend.secrets_file.touch()

        # Mock sops decrypt
        decrypted_data = {"api_key": "secret123", "db_password": "pass456"}

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(stdout=json.dumps(decrypted_data), returncode=0)

            value = await backend.get_secret("api_key")

            assert value == "secret123"

            # Verify sops was called correctly
            mock_run.assert_called_once()
            args = mock_run.call_args
            assert "sops" in args[0][0]
            assert "--decrypt" in args[0][0]

    @pytest.mark.asyncio
    async def test_get_secret_not_found(self, backend):
        """Test getting non-existent secret."""
        # Create the file so it tries to decrypt
        backend.secrets_file.touch()

        decrypted_data = {"existing_key": "value"}

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(stdout=json.dumps(decrypted_data), returncode=0)

            value = await backend.get_secret("nonexistent")

            assert value is None

    @pytest.mark.asyncio
    async def test_get_secret_file_not_exists(self, backend):
        """Test getting secret when file doesn't exist."""
        # File doesn't exist, should return None
        value = await backend.get_secret("any_key")

        assert value is None

    @pytest.mark.asyncio
    async def test_set_secret(self, backend, tmp_path):
        """Test setting a secret."""
        # File doesn't exist initially, so _load_secrets won't call sops
        # Only _save_secrets will call sops
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=0)  # encrypt succeeds

            await backend.set_secret("new_key", "new_value")

            # Should have called sops encrypt once
            assert mock_run.call_count == 1
            encrypt_call = mock_run.call_args_list[0]
            assert "sops" in encrypt_call[0][0]
            assert "--encrypt" in encrypt_call[0][0]
            assert "--in-place" in encrypt_call[0][0]

    @pytest.mark.asyncio
    async def test_set_secret_updates_cache(self, backend):
        """Test that set_secret updates internal cache."""
        # File doesn't exist, so no decrypt call
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=0)  # encrypt succeeds

            await backend.set_secret("key1", "value1")

            # Cache should be updated
            assert backend._secrets_cache["key1"] == "value1"

    @pytest.mark.asyncio
    async def test_delete_secret(self, backend):
        """Test deleting a secret."""
        # Create file so it loads
        backend.secrets_file.touch()

        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                Mock(stdout=json.dumps({"key1": "value1", "key2": "value2"}), returncode=0),  # load
                Mock(returncode=0),  # encrypt after delete
            ]

            await backend.delete_secret("key1")

            # Should have called sops twice (decrypt + encrypt)
            assert mock_run.call_count == 2

            # Cache should not have deleted key
            assert "key1" not in backend._secrets_cache
            assert "key2" in backend._secrets_cache

    @pytest.mark.asyncio
    async def test_delete_secret_not_found(self, backend):
        """Test deleting non-existent secret."""
        # Create file so it loads
        backend.secrets_file.touch()

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(stdout=json.dumps({"existing": "value"}), returncode=0)

            # Should not raise error (and should not save since key doesn't exist)
            await backend.delete_secret("nonexistent")

            # Should only have called decrypt, not encrypt
            assert mock_run.call_count == 1

    @pytest.mark.asyncio
    async def test_list_secrets_all(self, backend):
        """Test listing all secrets."""
        # Create file so it loads
        backend.secrets_file.touch()

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(
                stdout=json.dumps({"key1": "v1", "key2": "v2", "key3": "v3"}), returncode=0
            )

            keys = await backend.list_secrets()

            assert len(keys) == 3
            assert "key1" in keys
            assert "key2" in keys
            assert "key3" in keys

    @pytest.mark.asyncio
    async def test_list_secrets_with_prefix(self, backend):
        """Test listing secrets with prefix filter."""
        # Create file so it loads
        backend.secrets_file.touch()

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(
                stdout=json.dumps({"api_key": "v1", "api_secret": "v2", "db_password": "v3"}),
                returncode=0,
            )

            keys = await backend.list_secrets(prefix="api")

            assert len(keys) == 2
            assert "api_key" in keys
            assert "api_secret" in keys
            assert "db_password" not in keys

    @pytest.mark.asyncio
    async def test_rotate_secret(self, backend):
        """Test rotating a secret (reloading from file)."""
        # Create file so it loads
        backend.secrets_file.touch()

        with patch("subprocess.run") as mock_run:
            # First load
            mock_run.return_value = Mock(stdout=json.dumps({"key": "old_value"}), returncode=0)

            await backend.get_secret("key")
            assert backend._secrets_cache["key"] == "old_value"

            # Rotate (should reload)
            mock_run.return_value = Mock(stdout=json.dumps({"key": "new_value"}), returncode=0)

            await backend.rotate_secret("key")

            # Should have reloaded
            assert backend._secrets_cache["key"] == "new_value"

    @pytest.mark.asyncio
    async def test_sops_decrypt_failure(self, backend, tmp_path):
        """Test handling sops decrypt failure."""
        # Create the file so it tries to decrypt
        backend.secrets_file.touch()

        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.CalledProcessError(
                1, "sops", stderr="decryption failed"
            )

            with pytest.raises(ValueError, match="Failed to decrypt secrets with SOPS"):
                await backend.get_secret("key")

    @pytest.mark.asyncio
    async def test_sops_binary_not_found(self, backend, tmp_path):
        """Test handling missing sops binary."""
        backend.secrets_file.touch()

        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = FileNotFoundError()

            with pytest.raises(ValueError, match="sops binary not found"):
                await backend.get_secret("key")

    @pytest.mark.asyncio
    async def test_sops_encrypt_failure(self, backend):
        """Test handling sops encrypt failure."""
        # File doesn't exist, so no decrypt call, only encrypt
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.CalledProcessError(
                1, "sops", stderr="encryption failed"
            )

            with pytest.raises(ValueError, match="Failed to encrypt secrets with SOPS"):
                await backend.set_secret("key", "value")

    @pytest.mark.asyncio
    async def test_custom_key_file(self, tmp_path):
        """Test using custom age key file."""
        secrets_file = tmp_path / "secrets.enc.json"
        key_file = tmp_path / "age_key.txt"

        backend = SOPSBackend(secrets_file=str(secrets_file), key_file=str(key_file))

        # Create file so it loads
        backend.secrets_file.touch()

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(stdout=json.dumps({}), returncode=0)

            await backend.get_secret("key")

            # Should pass key file in environment
            env = mock_run.call_args.kwargs["env"]
            assert env["SOPS_AGE_KEY_FILE"] == str(key_file)

    @pytest.mark.asyncio
    async def test_caching_avoids_redundant_decryption(self, backend):
        """Test that caching avoids redundant sops calls."""
        # Create file so it loads
        backend.secrets_file.touch()

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(stdout=json.dumps({"key1": "value1"}), returncode=0)

            # First call loads from file
            value1 = await backend.get_secret("key1")
            assert value1 == "value1"
            assert mock_run.call_count == 1

            # Second call uses cache
            value2 = await backend.get_secret("key1")
            assert value2 == "value1"
            assert mock_run.call_count == 1  # No additional call


class TestHashiCorpVault:
    """Tests for HashiCorpVault backend."""

    @pytest.fixture
    def mock_client(self):
        """Create mock httpx client."""
        client = AsyncMock(spec=httpx.AsyncClient)
        return client

    @pytest.fixture
    def backend(self, mock_client):
        """Create HashiCorpVault instance with mocked client."""
        with patch.dict(os.environ, {"VAULT_TOKEN": "test-token"}):
            vault = HashiCorpVault(
                vault_addr="http://localhost:8200",
                auto_renew=False,  # Disable auto-renew for tests
            )
            vault.client = mock_client
            return vault

    @pytest.mark.asyncio
    async def test_init_without_token(self):
        """Test initialization fails without token."""
        with (
            patch.dict(os.environ, {}, clear=True),
            pytest.raises(ValueError, match="Vault token required"),
        ):
            HashiCorpVault()

    @pytest.mark.asyncio
    async def test_init_with_token_param(self):
        """Test initialization with explicit token."""
        vault = HashiCorpVault(vault_token="explicit-token", auto_renew=False)
        assert vault.vault_token == "explicit-token"

    @pytest.mark.asyncio
    async def test_init_with_env_token(self):
        """Test initialization with environment token."""
        with patch.dict(os.environ, {"VAULT_TOKEN": "env-token"}):
            vault = HashiCorpVault(auto_renew=False)
            assert vault.vault_token == "env-token"

    @pytest.mark.asyncio
    async def test_get_secret_success(self, backend, mock_client):
        """Test getting a secret successfully."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": {"data": {"value": "secret123"}}}
        mock_client.get.return_value = mock_response

        value = await backend.get_secret("my/secret")

        assert value == "secret123"
        mock_client.get.assert_called_once_with("/v1/secret/data/my/secret")

    @pytest.mark.asyncio
    async def test_get_secret_not_found(self, backend, mock_client):
        """Test getting non-existent secret."""
        mock_response = Mock()
        mock_response.status_code = 404
        mock_client.get.return_value = mock_response

        value = await backend.get_secret("nonexistent")

        assert value is None

    @pytest.mark.asyncio
    async def test_get_secret_first_field_fallback(self, backend, mock_client):
        """Test fallback to first field when 'value' not present."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {"data": {"password": "secret123", "username": "user"}}
        }
        mock_client.get.return_value = mock_response

        value = await backend.get_secret("my/secret")

        # Should return first value
        assert value in ["secret123", "user"]

    @pytest.mark.asyncio
    async def test_get_secret_connection_error(self, backend, mock_client):
        """Test handling connection errors."""
        mock_client.get.side_effect = httpx.ConnectError("Connection failed")

        with pytest.raises(ValueError, match="Failed to connect to Vault"):
            await backend.get_secret("my/secret")

    @pytest.mark.asyncio
    async def test_get_secret_vault_error(self, backend, mock_client):
        """Test handling Vault API errors."""
        mock_response = Mock()
        mock_response.status_code = 500
        mock_response.text = "Internal server error"
        mock_client.get.return_value = mock_response

        with pytest.raises(ValueError, match="Vault error: 500"):
            await backend.get_secret("my/secret")

    @pytest.mark.asyncio
    async def test_set_secret(self, backend, mock_client):
        """Test setting a secret."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_client.post.return_value = mock_response

        await backend.set_secret("my/secret", "new_value", metadata="extra")

        # Verify the request
        mock_client.post.assert_called_once()
        call_args = mock_client.post.call_args
        assert call_args[0][0] == "/v1/secret/data/my/secret"

        payload = call_args[1]["json"]
        assert payload["data"]["value"] == "new_value"
        assert payload["data"]["metadata"] == "extra"

    @pytest.mark.asyncio
    async def test_set_secret_failure(self, backend, mock_client):
        """Test handling set secret failure."""
        mock_response = Mock()
        mock_response.status_code = 403
        mock_response.text = "Permission denied"
        mock_client.post.return_value = mock_response

        with pytest.raises(ValueError, match="Failed to store secret"):
            await backend.set_secret("my/secret", "value")

    @pytest.mark.asyncio
    async def test_delete_secret(self, backend, mock_client):
        """Test deleting a secret."""
        mock_response = Mock()
        mock_response.status_code = 204
        mock_client.delete.return_value = mock_response

        await backend.delete_secret("my/secret")

        mock_client.delete.assert_called_once_with("/v1/secret/data/my/secret")

    @pytest.mark.asyncio
    async def test_delete_secret_failure(self, backend, mock_client):
        """Test handling delete secret failure."""
        mock_response = Mock()
        mock_response.status_code = 500
        mock_client.delete.return_value = mock_response

        with pytest.raises(ValueError, match="Failed to delete secret"):
            await backend.delete_secret("my/secret")

    @pytest.mark.asyncio
    async def test_list_secrets(self, backend, mock_client):
        """Test listing secrets."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": {"keys": ["secret1", "secret2", "secret3"]}}
        mock_client.request.return_value = mock_response

        keys = await backend.list_secrets("path/")

        assert keys == ["secret1", "secret2", "secret3"]
        mock_client.request.assert_called_once_with("LIST", "/v1/secret/metadata/path/")

    @pytest.mark.asyncio
    async def test_list_secrets_empty(self, backend, mock_client):
        """Test listing secrets when none exist."""
        mock_response = Mock()
        mock_response.status_code = 404
        mock_client.request.return_value = mock_response

        keys = await backend.list_secrets()

        assert keys == []

    @pytest.mark.asyncio
    async def test_list_secrets_failure(self, backend, mock_client):
        """Test handling list secrets failure."""
        mock_response = Mock()
        mock_response.status_code = 500
        mock_client.request.return_value = mock_response

        with pytest.raises(ValueError, match="Failed to list secrets"):
            await backend.list_secrets()

    @pytest.mark.asyncio
    async def test_rotate_secret(self, backend, mock_client):
        """Test rotating a secret."""
        # Mock get
        get_response = Mock()
        get_response.status_code = 200
        get_response.json.return_value = {"data": {"data": {"value": "current_value"}}}
        mock_client.get.return_value = get_response

        # Mock set
        set_response = Mock()
        set_response.status_code = 200
        mock_client.post.return_value = set_response

        await backend.rotate_secret("my/secret")

        # Should get and then set
        assert mock_client.get.call_count == 1
        assert mock_client.post.call_count == 1

    @pytest.mark.asyncio
    async def test_rotate_secret_not_found(self, backend, mock_client):
        """Test rotating non-existent secret."""
        mock_response = Mock()
        mock_response.status_code = 404
        mock_client.get.return_value = mock_response

        with pytest.raises(ValueError, match="Secret .* not found"):
            await backend.rotate_secret("nonexistent")

    @pytest.mark.asyncio
    async def test_headers_without_namespace(self):
        """Test headers without namespace."""
        with patch.dict(os.environ, {"VAULT_TOKEN": "test-token"}):
            vault = HashiCorpVault(auto_renew=False)
            headers = vault._get_headers()

            assert headers["X-Vault-Token"] == "test-token"
            assert "X-Vault-Namespace" not in headers

    @pytest.mark.asyncio
    async def test_headers_with_namespace(self):
        """Test headers with namespace."""
        with patch.dict(os.environ, {"VAULT_TOKEN": "test-token"}):
            vault = HashiCorpVault(vault_namespace="prod", auto_renew=False)
            headers = vault._get_headers()

            assert headers["X-Vault-Token"] == "test-token"
            assert headers["X-Vault-Namespace"] == "prod"

    @pytest.mark.asyncio
    async def test_custom_mount_point(self, mock_client):
        """Test using custom mount point."""
        with patch.dict(os.environ, {"VAULT_TOKEN": "test-token"}):
            vault = HashiCorpVault(mount_point="custom", auto_renew=False)
            vault.client = mock_client

            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"data": {"data": {"value": "v"}}}
            mock_client.get.return_value = mock_response

            await vault.get_secret("key")

            # Should use custom mount point
            mock_client.get.assert_called_with("/v1/custom/data/key")

    @pytest.mark.asyncio
    async def test_start_with_auto_renew(self, mock_client):
        """Test starting token renewal."""
        with patch.dict(os.environ, {"VAULT_TOKEN": "test-token"}):
            vault = HashiCorpVault(auto_renew=True)
            vault.client = mock_client

            # Mock token lookup
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"data": {"ttl": 1800}}
            mock_client.get.return_value = mock_response

            await vault.start()

            # Should have looked up token
            mock_client.get.assert_called_with("/v1/auth/token/lookup-self")

            # Should have started renewal task
            assert vault._renewal_task is not None
            assert vault._token_ttl == 1800

            # Cleanup
            await vault.stop()

    @pytest.mark.asyncio
    async def test_stop_cancels_renewal(self, mock_client):
        """Test stopping cancels renewal task."""
        with patch.dict(os.environ, {"VAULT_TOKEN": "test-token"}):
            vault = HashiCorpVault(auto_renew=True)
            vault.client = mock_client

            # Create a mock renewal task
            vault._renewal_task = asyncio.create_task(asyncio.sleep(100))

            await vault.stop()

            # Task should be cancelled
            assert vault._renewal_task.cancelled()

            # Client should be closed
            mock_client.aclose.assert_called_once()

    @pytest.mark.asyncio
    async def test_token_renewal(self, mock_client):
        """Test token renewal."""
        with patch.dict(os.environ, {"VAULT_TOKEN": "test-token"}):
            vault = HashiCorpVault(auto_renew=False)
            vault.client = mock_client

            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"auth": {"lease_duration": 3600}}
            mock_client.post.return_value = mock_response

            await vault._renew_token()

            mock_client.post.assert_called_with("/v1/auth/token/renew-self")
            assert vault._token_ttl == 3600

    @pytest.mark.asyncio
    async def test_token_renewal_loop_handles_errors(self, mock_client):
        """Test token renewal loop handles errors gracefully."""
        with patch.dict(os.environ, {"VAULT_TOKEN": "test-token"}):
            vault = HashiCorpVault(auto_renew=False)
            vault.client = mock_client

            # Mock renewal to fail once, then succeed
            call_count = 0

            async def mock_renew():
                nonlocal call_count
                call_count += 1
                if call_count == 1:
                    raise httpx.ConnectError("Connection failed")
                # Second call succeeds (do nothing)

            vault._renew_token = mock_renew

            # Start the renewal loop in background
            task = asyncio.create_task(vault._token_renewal_loop(0.01))

            # Wait a bit for it to run twice
            await asyncio.sleep(0.05)

            # Cancel the task
            task.cancel()

            # Should have handled error and continued
            with contextlib.suppress(asyncio.CancelledError):
                await task

            # Should have been called at least twice (one error, one success)
            assert call_count >= 2


class TestCreateVaultBackend:
    """Tests for create_vault_backend factory function."""

    def test_create_env_backend(self):
        """Test creating EnvVarBackend."""
        backend = create_vault_backend("env", prefix="CUSTOM_")

        assert isinstance(backend, EnvVarBackend)
        assert backend.prefix == "CUSTOM_"

    def test_create_sops_backend(self, tmp_path):
        """Test creating SOPSBackend."""
        secrets_file = tmp_path / "secrets.json"
        backend = create_vault_backend("sops", secrets_file=str(secrets_file))

        assert isinstance(backend, SOPSBackend)
        assert backend.secrets_file == secrets_file

    def test_create_vault_backend_with_token(self):
        """Test creating HashiCorpVault."""
        backend = create_vault_backend(
            "vault", vault_token="test-token", vault_addr="http://localhost:8200", auto_renew=False
        )

        assert isinstance(backend, HashiCorpVault)
        assert backend.vault_token == "test-token"
        assert backend.vault_addr == "http://localhost:8200"

    def test_create_unknown_provider(self):
        """Test creating with unknown provider."""
        with pytest.raises(ValueError, match="Unknown vault provider"):
            create_vault_backend("unknown")

    def test_create_default_provider(self):
        """Test creating with default provider."""
        backend = create_vault_backend()

        assert isinstance(backend, EnvVarBackend)


class TestVaultIntegration:
    """Integration tests for vault backends."""

    @pytest.mark.asyncio
    async def test_env_backend_full_workflow(self):
        """Test complete workflow with EnvVarBackend."""
        backend = EnvVarBackend(prefix="INTEGRATION_TEST_")

        try:
            # Set secrets
            await backend.set_secret("api_key", "key123")
            await backend.set_secret("db_password", "pass456")

            # Get secrets
            assert await backend.get_secret("api_key") == "key123"
            assert await backend.get_secret("db_password") == "pass456"

            # List secrets
            keys = await backend.list_secrets()
            assert "api_key" in [k.replace("/", "_") for k in keys]
            assert "db_password" in [k.replace("/", "_") for k in keys]

            # Delete secret
            await backend.delete_secret("api_key")
            assert await backend.get_secret("api_key") is None

            # Other secret still exists
            assert await backend.get_secret("db_password") == "pass456"

        finally:
            # Cleanup
            await backend.delete_secret("api_key")
            await backend.delete_secret("db_password")

    @pytest.mark.asyncio
    async def test_sops_backend_with_nonexistent_file(self, tmp_path):
        """Test SOPS backend with non-existent file."""
        secrets_file = tmp_path / "nonexistent.json"
        backend = SOPSBackend(secrets_file=str(secrets_file))

        # Should return None for non-existent secrets
        value = await backend.get_secret("any_key")
        assert value is None

        # Should return empty list
        keys = await backend.list_secrets()
        assert keys == []
