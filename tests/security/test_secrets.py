"""Tests for secret scanning and detection."""

from harombe.security.secrets import SecretScanner, SecretType


class TestSecretScanner:
    """Tests for SecretScanner."""

    def test_detect_aws_key(self):
        """Test detecting AWS access keys."""
        scanner = SecretScanner()
        text = "My AWS key is AKIAIOSFODNN7EXAMPLE"

        matches = scanner.scan(text)

        assert len(matches) > 0
        assert any(m.type == SecretType.AWS_KEY for m in matches)

    def test_detect_github_token(self):
        """Test detecting GitHub personal access tokens."""
        scanner = SecretScanner()
        text = "export GITHUB_TOKEN=ghp_1234567890abcdefghijklmnopqrstuv"

        matches = scanner.scan(text)

        assert len(matches) > 0
        assert any(m.type == SecretType.GITHUB_TOKEN for m in matches)

    def test_detect_slack_token(self):
        """Test detecting Slack tokens."""
        scanner = SecretScanner()
        text = "SLACK_TOKEN=xoxb-EXAMPLE-FAKE-TOKEN-FOR-TESTING"

        matches = scanner.scan(text)

        assert len(matches) > 0
        assert any(m.type == SecretType.SLACK_TOKEN for m in matches)

    def test_detect_jwt_token(self):
        """Test detecting JWT tokens."""
        scanner = SecretScanner()
        text = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"

        matches = scanner.scan(text)

        assert len(matches) > 0
        assert any(m.type == SecretType.JWT_TOKEN for m in matches)

    def test_detect_private_key(self):
        """Test detecting private keys."""
        scanner = SecretScanner()
        text = """
        -----BEGIN RSA PRIVATE KEY-----
        MIIEpAIBAAKCAQEA1234567890
        -----END RSA PRIVATE KEY-----
        """

        matches = scanner.scan(text)

        assert len(matches) > 0
        assert any(m.type == SecretType.PRIVATE_KEY for m in matches)

    def test_detect_database_url(self):
        """Test detecting database URLs with credentials."""
        scanner = SecretScanner()
        text = "DATABASE_URL=postgresql://user:password@localhost:5432/dbname"

        matches = scanner.scan(text)

        assert len(matches) > 0
        assert any(m.type == SecretType.DATABASE_URL for m in matches)

    def test_detect_api_key(self):
        """Test detecting generic API keys."""
        scanner = SecretScanner()
        text = "API_KEY=sk-1234567890abcdefghijklmnop"

        matches = scanner.scan(text)

        assert len(matches) > 0

    def test_detect_openai_key(self):
        """Test detecting OpenAI API keys."""
        scanner = SecretScanner()
        text = "OPENAI_API_KEY=sk-proj-1234567890abcdefghijklmnopqrstuvwxyz"

        matches = scanner.scan(text)

        assert len(matches) > 0

    def test_entropy_detection(self):
        """Test entropy-based secret detection."""
        scanner = SecretScanner(enable_entropy_detection=True)

        # High-entropy string (likely a secret)
        text = "token=aB3dF9gH2jK4lM6nP8qR0sT1uV3wX5yZ7"

        matches = scanner.scan(text)

        # Should detect as potential secret
        assert len(matches) > 0

    def test_no_false_positives(self):
        """Test that normal text doesn't trigger false positives."""
        scanner = SecretScanner()

        text = "This is a normal sentence with regular words and numbers like 123."

        matches = scanner.scan(text)

        # Should have no matches
        assert len(matches) == 0

    def test_confidence_scores(self):
        """Test confidence scoring."""
        scanner = SecretScanner()

        text = "GITHUB_TOKEN=ghp_1234567890abcdefghijklmnopqrstuv"

        matches = scanner.scan(text)

        assert len(matches) > 0
        # Pattern matches should have high confidence
        assert all(m.confidence >= 0.8 for m in matches)

    def test_context_extraction(self):
        """Test context extraction for matches."""
        scanner = SecretScanner()

        text = "Here is my secret: API_KEY=sk-1234567890abcdefgh and more text"

        matches = scanner.scan(text)

        assert len(matches) > 0
        assert matches[0].context is not None
        assert "secret" in matches[0].context.lower()

    def test_redact_secrets(self):
        """Test redacting secrets from text."""
        scanner = SecretScanner()

        text = "My GitHub token is ghp_1234567890abcdefghijklmnopqrstuv"

        redacted = scanner.redact(text)

        assert "ghp_1234567890abcdefghijklmnopqrstuv" not in redacted
        assert "[REDACTED]" in redacted

    def test_redact_multiple_secrets(self):
        """Test redacting multiple secrets."""
        scanner = SecretScanner()

        text = """
        GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz123456
        AWS_KEY=AKIAIOSFODNN7EXAMPLE
        """

        redacted = scanner.redact(text)

        assert "ghp_" not in redacted
        assert "AKIAIOSFODNN7EXAMPLE" not in redacted
        assert redacted.count("[REDACTED]") >= 2

    def test_alert_on_leakage(self):
        """Test alerting on credential leakage."""
        scanner = SecretScanner()

        text = "Here's my secret key: sk-1234567890abcdefghijklmnop"

        alerts = scanner.alert_if_leaked(text, source="test")

        assert len(alerts) > 0

    def test_custom_confidence_threshold(self):
        """Test custom confidence threshold."""
        # High threshold - only very confident matches
        scanner = SecretScanner(min_confidence=0.95)

        # Medium confidence secret (entropy-based)
        text = "token=abc123def456ghi789"

        matches = scanner.scan(text)

        # Should filter out medium confidence matches
        assert len(matches) == 0

    def test_deduplication(self):
        """Test deduplication of overlapping matches."""
        scanner = SecretScanner()

        # Text with overlapping secret patterns
        text = "API_KEY=sk-1234567890abcdefghijklmnop"

        matches = scanner.scan(text)

        # Should deduplicate overlapping matches
        match_ranges = [(m.start, m.end) for m in matches]
        for i, (start1, end1) in enumerate(match_ranges):
            for start2, end2 in match_ranges[i + 1 :]:
                # No overlaps
                assert end1 <= start2 or end2 <= start1

    def test_stripe_key_detection(self):
        """Test detecting Stripe API keys."""
        scanner = SecretScanner()

        text = "STRIPE_KEY=sk_test_FAKE_KEY_FOR_TESTING_ONLY"

        matches = scanner.scan(text)

        assert len(matches) > 0
        assert any(m.type == SecretType.STRIPE_KEY for m in matches)

    def test_password_detection(self):
        """Test detecting passwords in key-value format."""
        scanner = SecretScanner()

        text = "password=MySecretP@ssw0rd!"

        matches = scanner.scan(text)

        assert len(matches) > 0
        assert any(m.type == SecretType.PASSWORD for m in matches)

    def test_azure_key_detection(self):
        """Test detecting Azure keys."""
        scanner = SecretScanner()

        text = 'AZURE_CLIENT_SECRET="abcdef1234567890ghijklmnopqrstuv"'

        matches = scanner.scan(text)

        assert len(matches) > 0

    def test_min_length_filtering(self):
        """Test minimum length filtering."""
        scanner = SecretScanner(min_length=32)

        # Short string (won't be detected)
        text = "token=short123"

        matches = scanner.scan(text)

        # Should be filtered out
        assert len(matches) == 0
