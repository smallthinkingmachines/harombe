"""Tests for credential rotation verification framework."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from harombe.security.verification import (
    AnthropicAPIVerification,
    AWSCredentialsVerification,
    DatabaseConnectionVerification,
    GitHubAPIVerification,
    RotationVerificationTester,
    SlackTokenVerification,
    StripeAPIVerification,
    TestResult,
    VerificationResult,
    VerificationStatus,
    VerificationTest,
)


class MockVaultBackend:
    """Mock vault backend for testing."""

    def __init__(self):
        self.secrets = {}

    async def get_secret(self, key: str) -> str | None:
        return self.secrets.get(key)

    async def set_secret(self, key: str, value: str, **metadata) -> None:
        self.secrets[key] = value


@pytest.fixture
def mock_vault():
    """Create mock vault backend."""
    return MockVaultBackend()


@pytest.fixture
def verification_tester(mock_vault):
    """Create verification tester instance."""
    return RotationVerificationTester(vault_backend=mock_vault)


class TestVerificationStatus:
    """Test VerificationStatus enum."""

    def test_status_values(self):
        """Test verification status values."""
        assert VerificationStatus.PENDING == "pending"
        assert VerificationStatus.RUNNING == "running"
        assert VerificationStatus.PASSED == "passed"
        assert VerificationStatus.FAILED == "failed"
        assert VerificationStatus.SKIPPED == "skipped"


class TestTestResult:
    """Test TestResult model."""

    def test_result_creation(self):
        """Test creating test result."""
        result = TestResult(
            success=True,
            message="Test passed successfully",
            duration_ms=150.5,
            metadata={"key": "value"},
        )

        assert result.success
        assert result.message == "Test passed successfully"
        assert result.duration_ms == 150.5
        assert result.metadata["key"] == "value"

    def test_result_defaults(self):
        """Test result default values."""
        result = TestResult(success=False, message="Failed")

        assert not result.success
        assert result.duration_ms is None
        assert result.metadata == {}


class TestVerificationResult:
    """Test VerificationResult model."""

    def test_verification_result_creation(self):
        """Test creating verification result."""
        result = VerificationResult(
            success=True,
            tests=[("test1", True, "Passed"), ("test2", True, "Passed")],
            total_tests=2,
            passed_tests=2,
            failed_tests=0,
            duration_ms=300.0,
        )

        assert result.success
        assert result.total_tests == 2
        assert result.passed_tests == 2
        assert result.failed_tests == 0
        assert result.error is None

    def test_verification_result_failure(self):
        """Test failed verification result."""
        result = VerificationResult(
            success=False,
            tests=[("test1", True, "Passed"), ("test2", False, "Failed")],
            total_tests=2,
            passed_tests=1,
            failed_tests=1,
            duration_ms=300.0,
            error="1 of 2 tests failed",
        )

        assert not result.success
        assert result.failed_tests == 1
        assert result.error == "1 of 2 tests failed"

    def test_verification_result_str(self):
        """Test string representation."""
        result = VerificationResult(
            success=True,
            total_tests=3,
            passed_tests=3,
            failed_tests=0,
            duration_ms=500.0,
        )

        str_repr = str(result)
        assert "PASSED" in str_repr
        assert "3/3" in str_repr
        assert "500.0ms" in str_repr


class MockVerificationTest(VerificationTest):
    """Mock verification test for testing."""

    def __init__(self, name: str, should_pass: bool = True, vault_backend=None):
        super().__init__(name=name, vault_backend=vault_backend)
        self.should_pass = should_pass

    async def run(self, secret_path: str) -> TestResult:
        """Run mock test."""
        if self.should_pass:
            return TestResult(success=True, message=f"{self.name} passed", duration_ms=100.0)
        else:
            return TestResult(success=False, message=f"{self.name} failed", duration_ms=100.0)


class TestRotationVerificationTester:
    """Test RotationVerificationTester class."""

    def test_initialization(self, verification_tester, mock_vault):
        """Test tester initialization."""
        assert verification_tester.vault == mock_vault
        assert verification_tester.registered_tests == {}

    def test_register_test(self, verification_tester):
        """Test registering verification test."""
        test = MockVerificationTest(name="test1")
        verification_tester.register_test(test)

        assert "test1" in verification_tester.registered_tests
        assert verification_tester.registered_tests["test1"] == test

    @pytest.mark.asyncio
    async def test_verify_no_tests(self, verification_tester, mock_vault):
        """Test verification with no tests registered."""
        await mock_vault.set_secret("/secrets/test", "value")

        result = await verification_tester.verify("/secrets/test", None)

        assert result.success
        assert result.total_tests == 0
        assert result.passed_tests == 0

    @pytest.mark.asyncio
    async def test_verify_all_passing(self, verification_tester, mock_vault):
        """Test verification with all tests passing."""
        await mock_vault.set_secret("/secrets/test", "value")

        # Register passing tests
        test1 = MockVerificationTest(name="test1", should_pass=True)
        test2 = MockVerificationTest(name="test2", should_pass=True)
        verification_tester.register_test(test1)
        verification_tester.register_test(test2)

        # Run all tests
        result = await verification_tester.verify("/secrets/test", None)

        assert result.success
        assert result.total_tests == 2
        assert result.passed_tests == 2
        assert result.failed_tests == 0
        assert result.error is None

    @pytest.mark.asyncio
    async def test_verify_some_failing(self, verification_tester, mock_vault):
        """Test verification with some tests failing."""
        await mock_vault.set_secret("/secrets/test", "value")

        # Register mixed tests
        test1 = MockVerificationTest(name="test1", should_pass=True)
        test2 = MockVerificationTest(name="test2", should_pass=False)
        verification_tester.register_test(test1)
        verification_tester.register_test(test2)

        # Run all tests
        result = await verification_tester.verify("/secrets/test", None)

        assert not result.success
        assert result.total_tests == 2
        assert result.passed_tests == 1
        assert result.failed_tests == 1
        assert "1 of 2 tests failed" in result.error

    @pytest.mark.asyncio
    async def test_verify_specific_tests(self, verification_tester, mock_vault):
        """Test running specific tests only."""
        await mock_vault.set_secret("/secrets/test", "value")

        # Register tests
        test1 = MockVerificationTest(name="test1", should_pass=True)
        test2 = MockVerificationTest(name="test2", should_pass=True)
        test3 = MockVerificationTest(name="test3", should_pass=True)
        verification_tester.register_test(test1)
        verification_tester.register_test(test2)
        verification_tester.register_test(test3)

        # Run only test1 and test2
        result = await verification_tester.verify("/secrets/test", ["test1", "test2"])

        assert result.success
        assert result.total_tests == 2
        assert len(result.tests) == 2

    @pytest.mark.asyncio
    async def test_verify_test_exception(self, verification_tester, mock_vault):
        """Test handling test exceptions."""
        await mock_vault.set_secret("/secrets/test", "value")

        # Create test that raises exception
        class FailingTest(VerificationTest):
            async def run(self, secret_path: str) -> TestResult:
                raise ValueError("Test error")

        test = FailingTest(name="failing_test")
        verification_tester.register_test(test)

        # Run test
        result = await verification_tester.verify("/secrets/test", None)

        assert not result.success
        assert result.failed_tests == 1
        assert "Exception: Test error" in result.tests[0][2]


class TestAnthropicAPIVerification:
    """Test AnthropicAPIVerification."""

    @pytest.mark.asyncio
    async def test_no_vault(self):
        """Test with no vault configured."""
        test = AnthropicAPIVerification(vault_backend=None)
        result = await test.run("/secrets/anthropic")

        assert not result.success
        assert "No vault backend configured" in result.message

    @pytest.mark.asyncio
    async def test_secret_not_found(self, mock_vault):
        """Test with secret not found."""
        test = AnthropicAPIVerification(vault_backend=mock_vault)
        result = await test.run("/secrets/anthropic")

        assert not result.success
        assert "not found in vault" in result.message

    @pytest.mark.asyncio
    async def test_anthropic_not_installed(self, mock_vault):
        """Test with anthropic package not installed."""
        await mock_vault.set_secret("/secrets/anthropic", "test_key")

        test = AnthropicAPIVerification(vault_backend=mock_vault)

        # Mock import error
        with patch("builtins.__import__", side_effect=ImportError("No module")):
            result = await test.run("/secrets/anthropic")

        assert not result.success
        assert "anthropic package not installed" in result.message


class TestGitHubAPIVerification:
    """Test GitHubAPIVerification."""

    @pytest.mark.asyncio
    async def test_no_vault(self):
        """Test with no vault configured."""
        test = GitHubAPIVerification(vault_backend=None)
        result = await test.run("/secrets/github")

        assert not result.success
        assert "No vault backend configured" in result.message

    @pytest.mark.asyncio
    async def test_secret_not_found(self, mock_vault):
        """Test with secret not found."""
        test = GitHubAPIVerification(vault_backend=mock_vault)
        result = await test.run("/secrets/github")

        assert not result.success
        assert "not found in vault" in result.message

    @pytest.mark.asyncio
    async def test_api_success(self, mock_vault):
        """Test successful GitHub API call."""
        await mock_vault.set_secret("/secrets/github", "ghp_test_token_12345")

        test = GitHubAPIVerification(vault_backend=mock_vault)

        # Mock httpx response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"login": "testuser", "id": 12345}

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                return_value=mock_response
            )
            result = await test.run("/secrets/github")

        assert result.success
        assert "testuser" in result.message

    @pytest.mark.asyncio
    async def test_api_failure(self, mock_vault):
        """Test failed GitHub API call."""
        await mock_vault.set_secret("/secrets/github", "invalid_token")

        test = GitHubAPIVerification(vault_backend=mock_vault)

        # Mock httpx response
        mock_response = MagicMock()
        mock_response.status_code = 401

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                return_value=mock_response
            )
            result = await test.run("/secrets/github")

        assert not result.success
        assert "401" in result.message


class TestStripeAPIVerification:
    """Test StripeAPIVerification."""

    @pytest.mark.asyncio
    async def test_api_success(self, mock_vault):
        """Test successful Stripe API call."""
        await mock_vault.set_secret("/secrets/stripe", "sk_test_123")

        test = StripeAPIVerification(vault_backend=mock_vault)

        # Mock httpx response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"id": "acct_123", "email": "test@example.com"}

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                return_value=mock_response
            )
            result = await test.run("/secrets/stripe")

        assert result.success
        assert "acct_123" in result.message


class TestAWSCredentialsVerification:
    """Test AWSCredentialsVerification."""

    @pytest.mark.asyncio
    async def test_credentials_json(self, mock_vault):
        """Test AWS credentials in JSON format."""
        import json

        creds = json.dumps({"access_key_id": "AKIAIOSFODNN7EXAMPLE", "secret_access_key": "secret"})
        await mock_vault.set_secret("/secrets/aws", creds)

        test = AWSCredentialsVerification(vault_backend=mock_vault)

        # Try with real boto3 if available, otherwise mock it
        try:
            import boto3

            # Mock boto3 client
            with patch.object(boto3, "client") as mock_boto:
                mock_sts = MagicMock()
                mock_sts.get_caller_identity.return_value = {
                    "Account": "123456789012",
                    "Arn": "arn:aws:iam::123456789012:user/test",
                }
                mock_boto.return_value = mock_sts

                result = await test.run("/secrets/aws")

            assert result.success
            assert "123456789012" in result.message
        except ImportError:
            # boto3 not installed, just test format validation
            result = await test.run("/secrets/aws")
            assert result.success
            assert "boto3 not available" in result.message

    @pytest.mark.asyncio
    async def test_boto3_not_installed(self, mock_vault):
        """Test with boto3 not installed."""
        await mock_vault.set_secret("/secrets/aws", "AKIAIOSFODNN7EXAMPLE")

        test = AWSCredentialsVerification(vault_backend=mock_vault)

        # This will naturally fail to import boto3 in the test if not installed
        result = await test.run("/secrets/aws")

        # Should still succeed with format check
        assert result.success  # Partial success
        assert "boto3 not available" in result.message or "format valid" in result.message


class TestDatabaseConnectionVerification:
    """Test DatabaseConnectionVerification."""

    @pytest.mark.asyncio
    async def test_connection_success(self, mock_vault):
        """Test successful database connection."""
        import json

        conn = json.dumps({"host": "localhost", "port": 5432, "database": "testdb"})
        await mock_vault.set_secret("/secrets/db", conn)

        test = DatabaseConnectionVerification(vault_backend=mock_vault)

        # Mock socket connection
        with patch("socket.socket") as mock_socket:
            mock_sock = MagicMock()
            mock_sock.connect_ex.return_value = 0  # Success
            mock_socket.return_value = mock_sock

            result = await test.run("/secrets/db")

        assert result.success
        assert "reachable" in result.message

    @pytest.mark.asyncio
    async def test_connection_failure(self, mock_vault):
        """Test failed database connection."""
        await mock_vault.set_secret("/secrets/db", "password123")

        test = DatabaseConnectionVerification(vault_backend=mock_vault)

        # Mock socket connection failure
        with patch("socket.socket") as mock_socket:
            mock_sock = MagicMock()
            mock_sock.connect_ex.return_value = 1  # Failure
            mock_socket.return_value = mock_sock

            result = await test.run("/secrets/db")

        assert not result.success
        assert "Cannot reach" in result.message


class TestSlackTokenVerification:
    """Test SlackTokenVerification."""

    @pytest.mark.asyncio
    async def test_api_success(self, mock_vault):
        """Test successful Slack API call."""
        await mock_vault.set_secret("/secrets/slack", "xoxb-test-token")

        test = SlackTokenVerification(vault_backend=mock_vault)

        # Mock httpx response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"ok": True, "team": "TestTeam", "user": "bot"}

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=mock_response
            )
            result = await test.run("/secrets/slack")

        assert result.success
        assert "TestTeam" in result.message

    @pytest.mark.asyncio
    async def test_api_error(self, mock_vault):
        """Test Slack API error."""
        await mock_vault.set_secret("/secrets/slack", "invalid_token")

        test = SlackTokenVerification(vault_backend=mock_vault)

        # Mock httpx response with error
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"ok": False, "error": "invalid_auth"}

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=mock_response
            )
            result = await test.run("/secrets/slack")

        assert not result.success
        assert "invalid_auth" in result.message


@pytest.mark.integration
class TestVerificationIntegration:
    """Integration tests for verification framework."""

    @pytest.mark.asyncio
    async def test_end_to_end_verification(self, mock_vault):
        """Test complete verification workflow."""
        # Setup secrets
        await mock_vault.set_secret("/secrets/test1", "value1")
        await mock_vault.set_secret("/secrets/test2", "value2")

        # Create tester
        tester = RotationVerificationTester(vault_backend=mock_vault)

        # Register tests
        test1 = MockVerificationTest(name="test1", should_pass=True, vault_backend=mock_vault)
        test2 = MockVerificationTest(name="test2", should_pass=True, vault_backend=mock_vault)
        tester.register_test(test1)
        tester.register_test(test2)

        # Run verification
        result = await tester.verify("/secrets/test1", ["test1", "test2"])

        assert result.success
        assert result.total_tests == 2
        assert result.passed_tests == 2
        assert result.duration_ms > 0

    @pytest.mark.asyncio
    async def test_multiple_providers(self, mock_vault):
        """Test verification with multiple providers."""
        # Setup secrets
        await mock_vault.set_secret("/secrets/github", "ghp_token")
        await mock_vault.set_secret("/secrets/slack", "xoxb-token")

        # Create tester
        tester = RotationVerificationTester(vault_backend=mock_vault)

        # Register provider tests
        github_test = GitHubAPIVerification(vault_backend=mock_vault)
        slack_test = SlackTokenVerification(vault_backend=mock_vault)
        tester.register_test(github_test)
        tester.register_test(slack_test)

        # Mock API responses
        mock_github_response = MagicMock()
        mock_github_response.status_code = 200
        mock_github_response.json.return_value = {"login": "user", "id": 123}

        mock_slack_response = MagicMock()
        mock_slack_response.status_code = 200
        mock_slack_response.json.return_value = {"ok": True, "team": "Team"}

        with patch("httpx.AsyncClient") as mock_client:
            mock_context = mock_client.return_value.__aenter__.return_value
            mock_context.get = AsyncMock(return_value=mock_github_response)
            mock_context.post = AsyncMock(return_value=mock_slack_response)

            # Run GitHub verification
            result_github = await tester.verify("/secrets/github", ["github_api_test"])
            assert result_github.success

            # Run Slack verification
            result_slack = await tester.verify("/secrets/slack", ["slack_token_test"])
            assert result_slack.success
