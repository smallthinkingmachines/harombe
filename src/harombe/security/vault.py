"""Credential vault integration for secure secret management.

Supports multiple secret backends:
- HashiCorp Vault (production)
- SOPS file encryption (simpler alternative)
- Environment variables (development only)

Features:
- Time-limited tokens with auto-refresh
- Secret injection at container startup
- No secrets in config files or logs
- Audit trail for all secret access
"""

import asyncio
import contextlib
import json
import os
import subprocess
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import Any

import httpx
from pydantic import BaseModel, Field


class SecretMetadata(BaseModel):
    """Metadata for a secret."""

    key: str
    version: int = 1
    created_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: datetime | None = None
    rotation_policy: str | None = None  # e.g., "30d", "90d"


class SecretValue(BaseModel):
    """A secret value with metadata."""

    value: str
    metadata: SecretMetadata


class VaultBackend(ABC):
    """Abstract base class for secret vault backends."""

    @abstractmethod
    async def get_secret(self, key: str) -> str | None:
        """Retrieve a secret by key.

        Args:
            key: Secret key/path

        Returns:
            Secret value or None if not found
        """
        pass

    @abstractmethod
    async def set_secret(self, key: str, value: str, **metadata: Any) -> None:
        """Store a secret.

        Args:
            key: Secret key/path
            value: Secret value
            metadata: Additional metadata
        """
        pass

    @abstractmethod
    async def delete_secret(self, key: str) -> None:
        """Delete a secret.

        Args:
            key: Secret key/path
        """
        pass

    @abstractmethod
    async def list_secrets(self, prefix: str = "") -> list[str]:
        """List all secret keys with optional prefix.

        Args:
            prefix: Optional key prefix filter

        Returns:
            List of secret keys
        """
        pass

    @abstractmethod
    async def rotate_secret(self, key: str) -> None:
        """Rotate a secret (create new version).

        Args:
            key: Secret key/path
        """
        pass


class HashiCorpVault(VaultBackend):
    """HashiCorp Vault integration.

    Supports:
    - KV v2 secrets engine
    - Token authentication (default)
    - AppRole authentication
    - Token auto-renewal
    """

    def __init__(
        self,
        vault_addr: str = "http://127.0.0.1:8200",
        vault_token: str | None = None,
        vault_namespace: str | None = None,
        mount_point: str = "secret",
        auto_renew: bool = True,
    ):
        """Initialize Vault client.

        Args:
            vault_addr: Vault server address
            vault_token: Vault token (or use VAULT_TOKEN env var)
            vault_namespace: Vault namespace (enterprise feature)
            mount_point: KV secrets engine mount point
            auto_renew: Automatically renew token
        """
        self.vault_addr = vault_addr
        self.vault_token = vault_token or os.getenv("VAULT_TOKEN")
        self.vault_namespace = vault_namespace
        self.mount_point = mount_point
        self.auto_renew = auto_renew

        if not self.vault_token:
            raise ValueError("Vault token required (set VAULT_TOKEN or pass vault_token)")

        self.client = httpx.AsyncClient(
            base_url=vault_addr,
            headers=self._get_headers(),
            timeout=30.0,
        )

        self._renewal_task: asyncio.Task | None = None
        self._token_ttl: int | None = None

    def _get_headers(self) -> dict[str, str]:
        """Get HTTP headers for Vault requests."""
        headers = {"X-Vault-Token": self.vault_token}
        if self.vault_namespace:
            headers["X-Vault-Namespace"] = self.vault_namespace
        return headers

    async def start(self) -> None:
        """Start token renewal background task."""
        if self.auto_renew:
            # Get current token TTL
            response = await self.client.get("/v1/auth/token/lookup-self")
            if response.status_code == 200:
                data = response.json()
                self._token_ttl = data["data"].get("ttl", 3600)

                # Start renewal task (renew at 50% of TTL)
                renewal_interval = self._token_ttl / 2
                self._renewal_task = asyncio.create_task(self._token_renewal_loop(renewal_interval))

    async def stop(self) -> None:
        """Stop token renewal and close client."""
        if self._renewal_task:
            self._renewal_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._renewal_task

        await self.client.aclose()

    async def _token_renewal_loop(self, interval: float) -> None:
        """Background task to renew token periodically."""
        while True:
            try:
                await asyncio.sleep(interval)
                await self._renew_token()
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"Token renewal failed: {e}")
                # Continue trying to renew

    async def _renew_token(self) -> None:
        """Renew the Vault token."""
        response = await self.client.post("/v1/auth/token/renew-self")
        if response.status_code == 200:
            data = response.json()
            self._token_ttl = data["auth"].get("lease_duration", 3600)

    async def get_secret(self, key: str) -> str | None:
        """Get secret from Vault KV v2.

        Args:
            key: Secret path (without mount point)

        Returns:
            Secret value or None
        """
        path = f"/v1/{self.mount_point}/data/{key}"

        try:
            response = await self.client.get(path)

            if response.status_code == 404:
                return None

            if response.status_code != 200:
                raise ValueError(f"Vault error: {response.status_code} - {response.text}")

            data = response.json()
            # KV v2 nests data under data.data
            secret_data = data.get("data", {}).get("data", {})

            # Return the "value" field if it exists, otherwise return first value
            if "value" in secret_data:
                return secret_data["value"]
            elif secret_data:
                return next(iter(secret_data.values()))

            return None

        except httpx.RequestError as e:
            raise ValueError(f"Failed to connect to Vault: {e}") from e

    async def set_secret(self, key: str, value: str, **metadata: Any) -> None:
        """Store secret in Vault KV v2.

        Args:
            key: Secret path
            value: Secret value
            metadata: Additional metadata
        """
        path = f"/v1/{self.mount_point}/data/{key}"

        # KV v2 requires data nested under "data"
        payload = {
            "data": {
                "value": value,
                **metadata,
            }
        }

        response = await self.client.post(path, json=payload)

        if response.status_code not in (200, 204):
            raise ValueError(f"Failed to store secret: {response.status_code} - {response.text}")

    async def delete_secret(self, key: str) -> None:
        """Delete secret from Vault.

        Args:
            key: Secret path
        """
        path = f"/v1/{self.mount_point}/data/{key}"
        response = await self.client.delete(path)

        if response.status_code not in (200, 204):
            raise ValueError(f"Failed to delete secret: {response.status_code}")

    async def list_secrets(self, prefix: str = "") -> list[str]:
        """List secret keys.

        Args:
            prefix: Key prefix filter

        Returns:
            List of secret keys
        """
        path = f"/v1/{self.mount_point}/metadata/{prefix}"

        response = await self.client.request("LIST", path)

        if response.status_code == 404:
            return []

        if response.status_code != 200:
            raise ValueError(f"Failed to list secrets: {response.status_code}")

        data = response.json()
        return data.get("data", {}).get("keys", [])

    async def rotate_secret(self, key: str) -> None:
        """Rotate a secret by creating a new version.

        Args:
            key: Secret path
        """
        # Get current secret
        current = await self.get_secret(key)
        if current is None:
            raise ValueError(f"Secret '{key}' not found")

        # For now, just update with same value to create new version
        # In production, you'd generate a new value here
        await self.set_secret(key, current)


class SOPSBackend(VaultBackend):
    """SOPS (Secrets OPerationS) file encryption backend.

    Simpler alternative to Vault for small deployments.
    Uses age or GPG for encryption.
    """

    def __init__(
        self,
        secrets_file: str = "~/.harombe/secrets.enc.json",
        key_file: str | None = None,
    ):
        """Initialize SOPS backend.

        Args:
            secrets_file: Path to encrypted secrets file
            key_file: Path to age key file (default: ~/.config/sops/age/keys.txt)
        """
        self.secrets_file = Path(secrets_file).expanduser()
        self.key_file = key_file
        self._secrets_cache: dict[str, str] = {}
        self._cache_loaded = False

    async def _load_secrets(self) -> None:
        """Load and decrypt secrets file."""
        if not self.secrets_file.exists():
            self._secrets_cache = {}
            self._cache_loaded = True
            return

        try:
            # Use sops to decrypt
            env = os.environ.copy()
            if self.key_file:
                env["SOPS_AGE_KEY_FILE"] = self.key_file

            result = subprocess.run(
                ["sops", "--decrypt", str(self.secrets_file)],
                capture_output=True,
                text=True,
                check=True,
                env=env,
            )

            self._secrets_cache = json.loads(result.stdout)
            self._cache_loaded = True

        except subprocess.CalledProcessError as e:
            raise ValueError(f"Failed to decrypt secrets with SOPS: {e.stderr}") from e
        except FileNotFoundError:
            raise ValueError(
                "sops binary not found. Install sops: https://github.com/getsops/sops"
            ) from None

    async def _save_secrets(self) -> None:
        """Encrypt and save secrets file."""
        # Create directory if needed
        self.secrets_file.parent.mkdir(parents=True, exist_ok=True)

        # Write plaintext temporarily
        temp_file = self.secrets_file.with_suffix(".tmp.json")
        with open(temp_file, "w") as f:
            json.dump(self._secrets_cache, f, indent=2)

        try:
            # Encrypt with sops
            env = os.environ.copy()
            if self.key_file:
                env["SOPS_AGE_KEY_FILE"] = self.key_file

            subprocess.run(
                ["sops", "--encrypt", "--in-place", str(temp_file)],
                check=True,
                env=env,
                capture_output=True,
            )

            # Move to final location
            temp_file.replace(self.secrets_file)

        except subprocess.CalledProcessError as e:
            temp_file.unlink(missing_ok=True)
            raise ValueError(f"Failed to encrypt secrets with SOPS: {e.stderr}") from e

    async def get_secret(self, key: str) -> str | None:
        """Get secret from encrypted file.

        Args:
            key: Secret key

        Returns:
            Secret value or None
        """
        if not self._cache_loaded:
            await self._load_secrets()

        return self._secrets_cache.get(key)

    async def set_secret(self, key: str, value: str, **metadata: Any) -> None:
        """Store secret in encrypted file.

        Args:
            key: Secret key
            value: Secret value
            metadata: Ignored for SOPS
        """
        if not self._cache_loaded:
            await self._load_secrets()

        self._secrets_cache[key] = value
        await self._save_secrets()

    async def delete_secret(self, key: str) -> None:
        """Delete secret.

        Args:
            key: Secret key
        """
        if not self._cache_loaded:
            await self._load_secrets()

        if key in self._secrets_cache:
            del self._secrets_cache[key]
            await self._save_secrets()

    async def list_secrets(self, prefix: str = "") -> list[str]:
        """List secret keys.

        Args:
            prefix: Key prefix filter

        Returns:
            List of matching keys
        """
        if not self._cache_loaded:
            await self._load_secrets()

        if prefix:
            return [k for k in self._secrets_cache if k.startswith(prefix)]
        return list(self._secrets_cache.keys())

    async def rotate_secret(self, key: str) -> None:
        """Rotate secret (no-op for SOPS, just reload).

        Args:
            key: Secret key
        """
        # For SOPS, rotation means external process updates the file
        # We just reload
        self._cache_loaded = False
        await self._load_secrets()


class EnvVarBackend(VaultBackend):
    """Environment variable backend for development.

    NOT SECURE - only use for local development.
    Reads secrets from environment variables prefixed with HAROMBE_SECRET_.
    """

    def __init__(self, prefix: str = "HAROMBE_SECRET_"):
        """Initialize environment variable backend.

        Args:
            prefix: Environment variable prefix
        """
        self.prefix = prefix

    async def get_secret(self, key: str) -> str | None:
        """Get secret from environment.

        Args:
            key: Secret key

        Returns:
            Secret value from env var
        """
        env_key = f"{self.prefix}{key.upper().replace('/', '_')}"
        return os.getenv(env_key)

    async def set_secret(self, key: str, value: str, **metadata: Any) -> None:
        """Set secret in environment (runtime only).

        Args:
            key: Secret key
            value: Secret value
            metadata: Ignored
        """
        env_key = f"{self.prefix}{key.upper().replace('/', '_')}"
        os.environ[env_key] = value

    async def delete_secret(self, key: str) -> None:
        """Delete secret from environment.

        Args:
            key: Secret key
        """
        env_key = f"{self.prefix}{key.upper().replace('/', '_')}"
        os.environ.pop(env_key, None)

    async def list_secrets(self, prefix: str = "") -> list[str]:
        """List secrets from environment.

        Args:
            prefix: Key prefix

        Returns:
            List of secret keys
        """
        keys = []
        env_prefix = f"{self.prefix}{prefix.upper().replace('/', '_')}"

        for env_key in os.environ:
            if env_key.startswith(env_prefix):
                # Convert back to key format
                key = env_key[len(self.prefix) :].lower().replace("_", "/")
                keys.append(key)

        return keys

    async def rotate_secret(self, key: str) -> None:
        """No-op for environment variables.

        Args:
            key: Secret key
        """
        pass


def create_vault_backend(
    provider: str = "env",
    **kwargs: Any,
) -> VaultBackend:
    """Create a vault backend instance.

    Args:
        provider: Backend type (vault, sops, env)
        kwargs: Backend-specific configuration

    Returns:
        VaultBackend instance

    Raises:
        ValueError: If provider is unknown
    """
    if provider == "vault":
        return HashiCorpVault(**kwargs)
    elif provider == "sops":
        return SOPSBackend(**kwargs)
    elif provider == "env":
        return EnvVarBackend(**kwargs)
    else:
        raise ValueError(f"Unknown vault provider: {provider}. Use 'vault', 'sops', or 'env'")
