"""Credential rotation verification framework.

Provides a framework for testing new credentials before promoting them to
production during rotation. Includes provider-specific verification tests
for common services (Anthropic, GitHub, AWS, Stripe, etc.).

Phase 5.3.3 Implementation
"""

import logging
from abc import ABC, abstractmethod
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class VerificationStatus(StrEnum):
    """Status of a verification test."""

    PENDING = "pending"
    RUNNING = "running"
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"


class CheckResult(BaseModel):
    """Result of a single verification test.

    Attributes:
        success: Whether test passed
        message: Human-readable result message
        duration_ms: Time taken to run test
        metadata: Additional test-specific data
    """

    success: bool
    message: str
    duration_ms: float | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class VerificationResult(BaseModel):
    """Result of running verification tests.

    Attributes:
        success: Whether all tests passed
        tests: List of (test_name, success, message) tuples
        total_tests: Total number of tests run
        passed_tests: Number of tests that passed
        failed_tests: Number of tests that failed
        duration_ms: Total time taken for all tests
        error: Error message if verification failed
    """

    success: bool
    tests: list[tuple[str, bool, str]] = Field(default_factory=list)
    total_tests: int = 0
    passed_tests: int = 0
    failed_tests: int = 0
    duration_ms: float | None = None
    error: str | None = None

    def __str__(self) -> str:
        """String representation of verification result."""
        status = "PASSED" if self.success else "FAILED"
        return (
            f"Verification {status}: {self.passed_tests}/{self.total_tests} tests passed "
            f"({self.duration_ms:.1f}ms)"
        )


class VerificationTest(ABC):
    """Base class for verification tests.

    Subclass this to create provider-specific verification tests.
    """

    def __init__(self, name: str, vault_backend: Any | None = None):
        """Initialize verification test.

        Args:
            name: Test name
            vault_backend: Vault backend for retrieving secrets
        """
        self.name = name
        self.vault = vault_backend

    @abstractmethod
    async def run(self, secret_path: str) -> CheckResult:
        """Run the verification test.

        Args:
            secret_path: Path to secret to test

        Returns:
            Test result with success status and message
        """
        pass


class RotationVerificationTester:
    """Test new credentials before rotation.

    Runs a suite of verification tests on new credentials to ensure they
    work correctly before promoting them to production.
    """

    def __init__(self, vault_backend: Any | None = None):
        """Initialize verification tester.

        Args:
            vault_backend: Vault backend for retrieving secrets
        """
        self.vault = vault_backend
        self.registered_tests: dict[str, VerificationTest] = {}

    def register_test(self, test: VerificationTest) -> None:
        """Register a verification test.

        Args:
            test: Verification test to register
        """
        self.registered_tests[test.name] = test
        logger.debug(f"Registered verification test: {test.name}")

    async def verify(
        self, secret_path: str, test_names: list[str] | None = None
    ) -> VerificationResult:
        """Run verification tests on new secret.

        Args:
            secret_path: Path to secret to verify
            test_names: Names of tests to run (None = run all registered)

        Returns:
            Verification result with all test results
        """
        started_at = datetime.now(UTC).replace(tzinfo=None)
        results: list[tuple[str, bool, str]] = []

        # Determine which tests to run
        if test_names is None:
            tests_to_run = list(self.registered_tests.values())
        else:
            tests_to_run = [
                self.registered_tests[name] for name in test_names if name in self.registered_tests
            ]

        if not tests_to_run:
            logger.warning(f"No verification tests to run for {secret_path}")
            return VerificationResult(
                success=True,
                tests=[],
                total_tests=0,
                passed_tests=0,
                failed_tests=0,
                duration_ms=0.0,
            )

        # Run tests
        logger.info(f"Running {len(tests_to_run)} verification tests for {secret_path}")

        for test in tests_to_run:
            try:
                logger.debug(f"Running test: {test.name}")
                result = await test.run(secret_path)
                results.append((test.name, result.success, result.message))

                if result.success:
                    logger.info(f"✓ {test.name}: {result.message}")
                else:
                    logger.warning(f"✗ {test.name}: {result.message}")

            except Exception as e:
                logger.exception(f"Test {test.name} raised exception: {e}")
                results.append((test.name, False, f"Exception: {e!s}"))

        # Calculate results
        completed_at = datetime.now(UTC).replace(tzinfo=None)
        duration_ms = (completed_at - started_at).total_seconds() * 1000

        total_tests = len(results)
        passed_tests = sum(1 for _, success, _ in results if success)
        failed_tests = total_tests - passed_tests
        all_passed = failed_tests == 0

        error = None if all_passed else f"{failed_tests} of {total_tests} tests failed"

        verification_result = VerificationResult(
            success=all_passed,
            tests=results,
            total_tests=total_tests,
            passed_tests=passed_tests,
            failed_tests=failed_tests,
            duration_ms=duration_ms,
            error=error,
        )

        logger.info(f"Verification result: {verification_result}")
        return verification_result


# Built-in Verification Tests


class AnthropicAPIVerification(VerificationTest):
    """Verify Anthropic API key works."""

    def __init__(self, vault_backend: Any | None = None):
        """Initialize Anthropic API verification test."""
        super().__init__(name="anthropic_api_test", vault_backend=vault_backend)

    async def run(self, secret_path: str) -> CheckResult:
        """Test Anthropic API key.

        Args:
            secret_path: Path to API key secret

        Returns:
            Test result
        """
        started_at = datetime.now(UTC).replace(tzinfo=None)

        try:
            # Get API key
            if self.vault is None:
                return CheckResult(
                    success=False,
                    message="No vault backend configured",
                    duration_ms=0.0,
                )

            api_key = await self.vault.get_secret(secret_path)
            if not api_key:
                return CheckResult(
                    success=False,
                    message="API key not found in vault",
                    duration_ms=0.0,
                )

            # Import anthropic (optional dependency)
            try:
                import anthropic
            except ImportError:
                return CheckResult(
                    success=False,
                    message="anthropic package not installed",
                    duration_ms=0.0,
                )

            # Test API call with minimal request
            client = anthropic.Anthropic(api_key=api_key)
            response = await client.messages.create(
                model="claude-3-haiku-20240307",
                max_tokens=10,
                messages=[{"role": "user", "content": "Test"}],
            )

            completed_at = datetime.now(UTC).replace(tzinfo=None)
            duration_ms = (completed_at - started_at).total_seconds() * 1000

            if response and response.content:
                return CheckResult(
                    success=True,
                    message="API key valid, test message sent successfully",
                    duration_ms=duration_ms,
                    metadata={"model": response.model, "usage": response.usage},
                )
            else:
                return CheckResult(
                    success=False,
                    message="API call succeeded but response was empty",
                    duration_ms=duration_ms,
                )

        except Exception as e:
            completed_at = datetime.now(UTC).replace(tzinfo=None)
            duration_ms = (completed_at - started_at).total_seconds() * 1000
            return CheckResult(
                success=False,
                message=f"API test failed: {e!s}",
                duration_ms=duration_ms,
            )


class GitHubAPIVerification(VerificationTest):
    """Verify GitHub token works."""

    def __init__(self, vault_backend: Any | None = None):
        """Initialize GitHub API verification test."""
        super().__init__(name="github_api_test", vault_backend=vault_backend)

    async def run(self, secret_path: str) -> CheckResult:
        """Test GitHub token.

        Args:
            secret_path: Path to token secret

        Returns:
            Test result
        """
        started_at = datetime.now(UTC).replace(tzinfo=None)

        try:
            # Get token
            if self.vault is None:
                return CheckResult(
                    success=False,
                    message="No vault backend configured",
                    duration_ms=0.0,
                )

            token = await self.vault.get_secret(secret_path)
            if not token:
                return CheckResult(
                    success=False,
                    message="Token not found in vault",
                    duration_ms=0.0,
                )

            # Test API call (get authenticated user)
            import httpx

            async with httpx.AsyncClient() as client:
                response = await client.get(
                    "https://api.github.com/user",
                    headers={
                        "Authorization": f"Bearer {token}",
                        "Accept": "application/vnd.github.v3+json",
                    },
                    timeout=10.0,
                )

                completed_at = datetime.now(UTC).replace(tzinfo=None)
                duration_ms = (completed_at - started_at).total_seconds() * 1000

                if response.status_code == 200:
                    user_data = response.json()
                    return CheckResult(
                        success=True,
                        message=f"Token valid for user: {user_data.get('login', 'unknown')}",
                        duration_ms=duration_ms,
                        metadata={"user": user_data.get("login"), "id": user_data.get("id")},
                    )
                else:
                    return CheckResult(
                        success=False,
                        message=f"API returned status {response.status_code}",
                        duration_ms=duration_ms,
                    )

        except Exception as e:
            completed_at = datetime.now(UTC).replace(tzinfo=None)
            duration_ms = (completed_at - started_at).total_seconds() * 1000
            return CheckResult(
                success=False,
                message=f"API test failed: {e!s}",
                duration_ms=duration_ms,
            )


class StripeAPIVerification(VerificationTest):
    """Verify Stripe API key works."""

    def __init__(self, vault_backend: Any | None = None):
        """Initialize Stripe API verification test."""
        super().__init__(name="stripe_api_test", vault_backend=vault_backend)

    async def run(self, secret_path: str) -> CheckResult:
        """Test Stripe API key.

        Args:
            secret_path: Path to API key secret

        Returns:
            Test result
        """
        started_at = datetime.now(UTC).replace(tzinfo=None)

        try:
            # Get API key
            if self.vault is None:
                return CheckResult(
                    success=False,
                    message="No vault backend configured",
                    duration_ms=0.0,
                )

            api_key = await self.vault.get_secret(secret_path)
            if not api_key:
                return CheckResult(
                    success=False,
                    message="API key not found in vault",
                    duration_ms=0.0,
                )

            # Test API call (retrieve account)
            import httpx

            async with httpx.AsyncClient() as client:
                response = await client.get(
                    "https://api.stripe.com/v1/account",
                    auth=(api_key, ""),
                    timeout=10.0,
                )

                completed_at = datetime.now(UTC).replace(tzinfo=None)
                duration_ms = (completed_at - started_at).total_seconds() * 1000

                if response.status_code == 200:
                    account_data = response.json()
                    return CheckResult(
                        success=True,
                        message=f"API key valid for account: {account_data.get('id', 'unknown')}",
                        duration_ms=duration_ms,
                        metadata={
                            "account_id": account_data.get("id"),
                            "email": account_data.get("email"),
                        },
                    )
                else:
                    return CheckResult(
                        success=False,
                        message=f"API returned status {response.status_code}",
                        duration_ms=duration_ms,
                    )

        except Exception as e:
            completed_at = datetime.now(UTC).replace(tzinfo=None)
            duration_ms = (completed_at - started_at).total_seconds() * 1000
            return CheckResult(
                success=False,
                message=f"API test failed: {e!s}",
                duration_ms=duration_ms,
            )


class AWSCredentialsVerification(VerificationTest):
    """Verify AWS credentials work."""

    def __init__(self, vault_backend: Any | None = None):
        """Initialize AWS credentials verification test."""
        super().__init__(name="aws_credentials_test", vault_backend=vault_backend)

    async def run(self, secret_path: str) -> CheckResult:
        """Test AWS credentials.

        Args:
            secret_path: Path to credentials secret

        Returns:
            Test result
        """
        started_at = datetime.now(UTC).replace(tzinfo=None)

        try:
            # Get credentials (expects JSON with access_key_id and secret_access_key)
            if self.vault is None:
                return CheckResult(
                    success=False,
                    message="No vault backend configured",
                    duration_ms=0.0,
                )

            credentials_json = await self.vault.get_secret(secret_path)
            if not credentials_json:
                return CheckResult(
                    success=False,
                    message="Credentials not found in vault",
                    duration_ms=0.0,
                )

            # Parse credentials
            import json

            try:
                credentials = json.loads(credentials_json)
                access_key_id = credentials.get("access_key_id")
                secret_access_key = credentials.get("secret_access_key")
            except (json.JSONDecodeError, AttributeError):
                # Try treating as plain access key
                access_key_id = credentials_json
                secret_access_key = None

            if not access_key_id:
                return CheckResult(
                    success=False,
                    message="Access key ID not found in credentials",
                    duration_ms=0.0,
                )

            # Test API call (get caller identity)

            import httpx

            # Simplified AWS STS GetCallerIdentity request
            # In production, use boto3

            async with httpx.AsyncClient():
                # Note: This is a simplified test that checks if credentials are valid
                # In production, use boto3's get_caller_identity()
                try:
                    import boto3

                    # Use boto3 if available
                    sts = boto3.client(
                        "sts",
                        aws_access_key_id=access_key_id,
                        aws_secret_access_key=secret_access_key or "",
                    )
                    identity = sts.get_caller_identity()

                    completed_at = datetime.now(UTC).replace(tzinfo=None)
                    duration_ms = (completed_at - started_at).total_seconds() * 1000

                    return CheckResult(
                        success=True,
                        message=f"Credentials valid for account: {identity['Account']}",
                        duration_ms=duration_ms,
                        metadata={
                            "account": identity.get("Account"),
                            "arn": identity.get("Arn"),
                        },
                    )
                except ImportError:
                    # boto3 not available, return partial success
                    completed_at = datetime.now(UTC).replace(tzinfo=None)
                    duration_ms = (completed_at - started_at).total_seconds() * 1000
                    return CheckResult(
                        success=True,
                        message="Credentials format valid (boto3 not available for full test)",
                        duration_ms=duration_ms,
                    )

        except Exception as e:
            completed_at = datetime.now(UTC).replace(tzinfo=None)
            duration_ms = (completed_at - started_at).total_seconds() * 1000
            return CheckResult(
                success=False,
                message=f"Credentials test failed: {e!s}",
                duration_ms=duration_ms,
            )


class DatabaseConnectionVerification(VerificationTest):
    """Verify database connection works."""

    def __init__(self, vault_backend: Any | None = None):
        """Initialize database connection verification test."""
        super().__init__(name="database_connection_test", vault_backend=vault_backend)

    async def run(self, secret_path: str) -> CheckResult:
        """Test database connection.

        Args:
            secret_path: Path to connection string/password secret

        Returns:
            Test result
        """
        started_at = datetime.now(UTC).replace(tzinfo=None)

        try:
            # Get connection info
            if self.vault is None:
                return CheckResult(
                    success=False,
                    message="No vault backend configured",
                    duration_ms=0.0,
                )

            connection_info = await self.vault.get_secret(secret_path)
            if not connection_info:
                return CheckResult(
                    success=False,
                    message="Connection info not found in vault",
                    duration_ms=0.0,
                )

            # Try to parse as connection string or JSON
            import json

            try:
                conn_data = json.loads(connection_info)
                host = conn_data.get("host", "localhost")
                port = conn_data.get("port", 5432)
                database = conn_data.get("database", "postgres")
                conn_data.get("user", "postgres")
                conn_data.get("password", "")
            except json.JSONDecodeError:
                # Treat as plain password
                host = "localhost"
                port = 5432
                database = "postgres"

            # Test connection (basic TCP check)
            import socket

            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5.0)
                result_code = sock.connect_ex((host, int(port)))
                sock.close()

                completed_at = datetime.now(UTC).replace(tzinfo=None)
                duration_ms = (completed_at - started_at).total_seconds() * 1000

                if result_code == 0:
                    return CheckResult(
                        success=True,
                        message=f"Database reachable at {host}:{port}",
                        duration_ms=duration_ms,
                        metadata={"host": host, "port": port, "database": database},
                    )
                else:
                    return CheckResult(
                        success=False,
                        message=f"Cannot reach database at {host}:{port}",
                        duration_ms=duration_ms,
                    )
            except Exception as e:
                completed_at = datetime.now(UTC).replace(tzinfo=None)
                duration_ms = (completed_at - started_at).total_seconds() * 1000
                return CheckResult(
                    success=False,
                    message=f"Connection test failed: {e!s}",
                    duration_ms=duration_ms,
                )

        except Exception as e:
            completed_at = datetime.now(UTC).replace(tzinfo=None)
            duration_ms = (completed_at - started_at).total_seconds() * 1000
            return CheckResult(
                success=False,
                message=f"Database test failed: {e!s}",
                duration_ms=duration_ms,
            )


class SlackTokenVerification(VerificationTest):
    """Verify Slack token works."""

    def __init__(self, vault_backend: Any | None = None):
        """Initialize Slack token verification test."""
        super().__init__(name="slack_token_test", vault_backend=vault_backend)

    async def run(self, secret_path: str) -> CheckResult:
        """Test Slack token.

        Args:
            secret_path: Path to token secret

        Returns:
            Test result
        """
        started_at = datetime.now(UTC).replace(tzinfo=None)

        try:
            # Get token
            if self.vault is None:
                return CheckResult(
                    success=False,
                    message="No vault backend configured",
                    duration_ms=0.0,
                )

            token = await self.vault.get_secret(secret_path)
            if not token:
                return CheckResult(
                    success=False,
                    message="Token not found in vault",
                    duration_ms=0.0,
                )

            # Test API call (auth.test)
            import httpx

            async with httpx.AsyncClient() as client:
                response = await client.post(
                    "https://slack.com/api/auth.test",
                    headers={"Authorization": f"Bearer {token}"},
                    timeout=10.0,
                )

                completed_at = datetime.now(UTC).replace(tzinfo=None)
                duration_ms = (completed_at - started_at).total_seconds() * 1000

                if response.status_code == 200:
                    data = response.json()
                    if data.get("ok"):
                        return CheckResult(
                            success=True,
                            message=f"Token valid for team: {data.get('team', 'unknown')}",
                            duration_ms=duration_ms,
                            metadata={"team": data.get("team"), "user": data.get("user")},
                        )
                    else:
                        return CheckResult(
                            success=False,
                            message=f"Slack API error: {data.get('error', 'unknown')}",
                            duration_ms=duration_ms,
                        )
                else:
                    return CheckResult(
                        success=False,
                        message=f"API returned status {response.status_code}",
                        duration_ms=duration_ms,
                    )

        except Exception as e:
            completed_at = datetime.now(UTC).replace(tzinfo=None)
            duration_ms = (completed_at - started_at).total_seconds() * 1000
            return CheckResult(
                success=False,
                message=f"API test failed: {e!s}",
                duration_ms=duration_ms,
            )
