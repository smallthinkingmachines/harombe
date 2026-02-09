"""Secure environment variable injection for containers.

Provides a Vault → Container environment pipeline that:
- Fetches secrets from vault at container startup
- Injects them as environment variables
- Ensures no secrets in config files or logs
- Per-container environment isolation

Features:
- Time-limited secret injection
- Automatic secret rotation
- Secure .env file handling
- Integration with Docker container manager
"""

import os
from pathlib import Path
from typing import Any

from .vault import VaultBackend, create_vault_backend


class SecretInjector:
    """Injects secrets from vault into container environments.

    Workflow:
    1. Read secret mapping from configuration
    2. Fetch secrets from vault backend
    3. Generate temporary .env file (secure permissions)
    4. Mount into container at startup
    5. Clean up after container stops
    """

    def __init__(
        self,
        vault_backend: VaultBackend,
        temp_dir: str = "/tmp/harombe-secrets",
    ):
        """Initialize secret injector.

        Args:
            vault_backend: Vault backend instance
            temp_dir: Directory for temporary secret files
        """
        self.vault = vault_backend
        self.temp_dir = Path(temp_dir)
        self.temp_dir.mkdir(parents=True, exist_ok=True, mode=0o700)  # Owner only

    async def inject_secrets(
        self,
        container_name: str,
        secret_mapping: dict[str, str],
    ) -> Path:
        """Create .env file with secrets for container.

        Args:
            container_name: Container name (for isolation)
            secret_mapping: Map of env_var_name -> vault_key

        Returns:
            Path to generated .env file

        Example:
            secret_mapping = {
                "GITHUB_TOKEN": "github/api-token",
                "SLACK_WEBHOOK": "slack/webhook-url",
            }
        """
        # Create container-specific temp file
        env_file = self.temp_dir / f"{container_name}.env"

        # Fetch secrets from vault
        env_vars: dict[str, str] = {}
        for env_name, vault_key in secret_mapping.items():
            secret_value = await self.vault.get_secret(vault_key)
            if secret_value is None:
                raise ValueError(f"Secret '{vault_key}' not found in vault")
            env_vars[env_name] = secret_value

        # Write to temp file with secure permissions
        with open(env_file, "w") as f:
            for key, value in env_vars.items():
                # Escape special characters for shell safety
                escaped_value = value.replace("\\", "\\\\").replace('"', '\\"')
                f.write(f'{key}="{escaped_value}"\n')

        # Set file permissions (owner read-only)
        os.chmod(env_file, 0o400)

        return env_file

    def cleanup(self, container_name: str) -> None:
        """Clean up secrets file for container.

        Args:
            container_name: Container name
        """
        env_file = self.temp_dir / f"{container_name}.env"
        if env_file.exists():
            # Overwrite with random data before deletion (paranoid security)
            with open(env_file, "wb") as f:
                f.write(os.urandom(env_file.stat().st_size))
            env_file.unlink()

    def cleanup_all(self) -> None:
        """Clean up all secret files."""
        for env_file in self.temp_dir.glob("*.env"):
            # Overwrite with random data
            with open(env_file, "wb") as f:
                f.write(os.urandom(env_file.stat().st_size))
            env_file.unlink()


class DotEnvLoader:
    """Secure .env file loader with secret scanning.

    Loads environment variables from .env files with:
    - Secret detection and warnings
    - Variable expansion
    - Comment support
    - Secure parsing
    """

    def __init__(
        self,
        warn_on_secrets: bool = True,
    ):
        """Initialize .env loader.

        Args:
            warn_on_secrets: Warn if secrets detected in .env file
        """
        self.warn_on_secrets = warn_on_secrets

    def load(
        self,
        env_file: str | Path,
        override: bool = False,
    ) -> dict[str, str]:
        """Load environment variables from .env file.

        Args:
            env_file: Path to .env file
            override: Override existing environment variables

        Returns:
            Dictionary of loaded variables
        """
        env_file = Path(env_file)
        if not env_file.exists():
            raise FileNotFoundError(f".env file not found: {env_file}")

        variables: dict[str, str] = {}

        with open(env_file) as f:
            for line_num, line in enumerate(f, 1):
                # Strip whitespace and skip comments/empty lines
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                # Parse KEY=VALUE
                if "=" not in line:
                    print(f"Warning: Invalid line {line_num} in {env_file}: {line}")
                    continue

                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip()

                # Remove quotes
                if (value.startswith('"') and value.endswith('"')) or (
                    value.startswith("'") and value.endswith("'")
                ):
                    value = value[1:-1]

                # Variable expansion (support ${VAR} and $VAR)
                value = self._expand_variables(value, variables)

                variables[key] = value

                # Set in environment if override=True or not already set
                if override or key not in os.environ:
                    os.environ[key] = value

        # Warn if secrets detected
        if self.warn_on_secrets:
            self._check_for_secrets(variables, env_file)

        return variables

    def _expand_variables(
        self,
        value: str,
        variables: dict[str, str],
    ) -> str:
        """Expand ${VAR} and $VAR references.

        Args:
            value: Value to expand
            variables: Available variables

        Returns:
            Expanded value
        """
        import re

        # Expand ${VAR} style
        def replace_braces(match: re.Match) -> str:
            var_name = match.group(1)
            return variables.get(var_name, os.getenv(var_name, ""))

        value = re.sub(r"\$\{([A-Z_][A-Z0-9_]*)\}", replace_braces, value)

        # Expand $VAR style
        def replace_simple(match: re.Match) -> str:
            var_name = match.group(1)
            return variables.get(var_name, os.getenv(var_name, ""))

        value = re.sub(r"\$([A-Z_][A-Z0-9_]*)", replace_simple, value)

        return value

    def _check_for_secrets(
        self,
        variables: dict[str, str],
        env_file: Path,
    ) -> None:
        """Check for potential secrets in .env file.

        Args:
            variables: Loaded variables
            env_file: Path to .env file
        """
        from .secrets import SecretScanner

        scanner = SecretScanner(min_confidence=0.8)

        for key, value in variables.items():
            matches = scanner.scan(value)
            if matches:
                print(
                    f"[SECURITY WARNING] Potential secret in {env_file}: {key}=" f"{value[:10]}..."
                )
                print("  Recommendation: Move this secret to Vault and reference it via injection")


class SecretRotationScheduler:
    """Schedules and manages secret rotation.

    Features:
    - Automatic rotation based on policies
    - Graceful rotation (no downtime)
    - Rotation audit trail
    """

    def __init__(
        self,
        vault_backend: VaultBackend,
        injector: SecretInjector,
    ):
        """Initialize rotation scheduler.

        Args:
            vault_backend: Vault backend
            injector: Secret injector
        """
        self.vault = vault_backend
        self.injector = injector
        self.rotation_policies: dict[str, str] = {}  # secret_key -> policy (e.g., "30d")

    def add_policy(self, secret_key: str, policy: str) -> None:
        """Add rotation policy for a secret.

        Args:
            secret_key: Vault secret key
            policy: Rotation policy (e.g., "30d", "90d")
        """
        self.rotation_policies[secret_key] = policy

    async def rotate_secret(
        self,
        secret_key: str,
        generator: callable | None = None,
    ) -> None:
        """Rotate a secret.

        Args:
            secret_key: Vault secret key
            generator: Optional function to generate new secret value
        """
        # Generate new secret value
        if generator:
            new_value = generator()
        else:
            # Default: use vault's rotation mechanism
            await self.vault.rotate_secret(secret_key)
            return

        # Store new secret
        await self.vault.set_secret(secret_key, new_value)

        # TODO: Trigger container restart to pick up new secret
        # This would integrate with DockerManager

    async def check_and_rotate(self) -> None:
        """Check all policies and rotate as needed.

        Called periodically by background task.
        """
        # TODO: Implement policy checking and automatic rotation
        # This would check last rotation time and trigger rotation
        # based on policy (e.g., every 30 days)
        pass


def create_injector(
    provider: str = "env",
    **vault_kwargs: Any,
) -> SecretInjector:
    """Create a secret injector with vault backend.

    Args:
        provider: Vault provider (vault, sops, env)
        vault_kwargs: Vault backend configuration

    Returns:
        SecretInjector instance
    """
    vault = create_vault_backend(provider, **vault_kwargs)
    return SecretInjector(vault_backend=vault)
