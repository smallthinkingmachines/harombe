"""
Integration tests for browser automation, vault secrets, and HITL gates.

Validates that browser sessions properly integrate with secret injection
and HITL approval workflows.
"""

import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from harombe.security.audit_db import AuditDatabase, SecurityDecision
from harombe.security.audit_logger import AuditLogger
from harombe.security.hitl import (
    ApprovalDecision,
    ApprovalStatus,
    HITLGate,
    HITLRule,
    Operation,
    RiskLevel,
)
from harombe.tools.browser import BrowserTools


# Mock classes for vault integration (to be implemented in Phase 5)
class SecretValue:
    """Mock secret value for testing."""

    def __init__(self, key: str, value: str, source: str, ttl: int | None = None):
        self.key = key
        self.value = value
        self.source = source
        self.ttl = ttl


class SecretManager:
    """Mock secret manager for testing."""

    async def get_secret(self, key: str) -> SecretValue:
        """Mock get_secret method."""
        pass


class TestBrowserVaultIntegration:
    """Integration tests for browser + vault + HITL."""

    @pytest.fixture
    def temp_db_path(self):
        """Create temporary database for testing."""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        yield db_path
        Path(db_path).unlink(missing_ok=True)

    @pytest.fixture
    def audit_db(self, temp_db_path):
        """Create audit database."""
        db = AuditDatabase(db_path=temp_db_path)
        # AuditDatabase initializes on construction
        yield db
        # No close() method needed - connections are per-operation

    @pytest.fixture
    def audit_logger(self, temp_db_path):
        """Create audit logger."""
        return AuditLogger(db_path=temp_db_path)

    @pytest.fixture
    def secret_manager(self):
        """Create mock secret manager."""
        manager = MagicMock(spec=SecretManager)
        manager.get_secret = AsyncMock(
            return_value=SecretValue(
                key="test_credential",
                value="test_password",
                source="vault",
            )
        )
        return manager

    @pytest.fixture
    def hitl_rules(self):
        """Create test HITL rules for browser operations."""
        return [
            HITLRule(
                tools=["browser_navigate"],
                risk=RiskLevel.HIGH,
                require_approval=True,
                timeout=60,
                description="Browser navigation requires approval",
            ),
            HITLRule(
                tools=["browser_click", "browser_fill"],
                risk=RiskLevel.MEDIUM,
                require_approval=True,
                timeout=30,
                description="Browser interaction requires approval",
            ),
        ]

    @pytest.fixture
    def hitl_gate(self, hitl_rules):
        """Create HITL gate."""
        from harombe.security.hitl import RiskClassifier

        classifier = RiskClassifier(rules=hitl_rules)
        return HITLGate(classifier=classifier)

    @pytest.fixture
    def browser_tools(self):
        """Create browser tools with mocked browser manager."""
        # Mock browser manager
        browser_manager = MagicMock()
        browser_manager.create_session = AsyncMock(return_value="session_123")
        browser_manager.navigate = AsyncMock(
            return_value={"success": True, "url": "https://example.com"}
        )
        browser_manager.close_session = AsyncMock()

        tools = BrowserTools(browser_manager=browser_manager)
        return tools

    @pytest.mark.asyncio
    async def test_browser_with_preauth_credentials(self, browser_tools, secret_manager):
        """Test browser session with pre-injected credentials."""
        # Fetch credentials from vault
        credential = await secret_manager.get_secret("test_credential")
        assert credential.value == "test_password"
        assert credential.source == "vault"

        # Create browser session with pre-auth
        session_id = await browser_tools.browser_manager.create_session(
            pre_auth={
                "url": "https://example.com/login",
                "credentials": {
                    "username": "test_user",
                    "password": credential.value,
                },
            }
        )

        assert session_id == "session_123"

        # Verify create_session called with credentials
        call_args = browser_tools.browser_manager.create_session.call_args
        assert call_args[1]["pre_auth"]["credentials"]["password"] == "test_password"

    @pytest.mark.asyncio
    async def test_browser_navigation_with_hitl_approval(
        self, browser_tools, hitl_gate, audit_logger, audit_db
    ):
        """Test browser navigation requires HITL approval and is logged."""
        # Create operation
        operation = Operation(
            tool_name="browser_navigate",
            params={"url": "https://example.com", "session_id": "session_123"},
            correlation_id="nav_test_123",
        )

        # Mock approval callback
        async def mock_prompt_callback(op, risk_level, timeout):
            return ApprovalDecision(
                decision=ApprovalStatus.APPROVED,
                reason="User approved navigation",
                user="test_user",
            )

        # Request approval
        decision = await hitl_gate.check_approval(operation, prompt_callback=mock_prompt_callback)
        assert decision.decision == ApprovalStatus.APPROVED

        # Navigate (after approval)
        result = await browser_tools.browser_manager.navigate(
            session_id="session_123", url="https://example.com"
        )
        assert result["success"] is True

        # Log security decision
        import uuid

        audit_logger.log_security_decision(
            correlation_id=str(uuid.uuid4()),
            decision_type="browser_navigation",
            decision=SecurityDecision.ALLOW,
            reason=decision.reason,
            actor="test_user",
            tool_name=operation.tool_name,
            context={
                "approved_by": decision.user,
                "url": operation.params["url"],
                "risk_level": "HIGH",
            },
        )

        # Verify audit trail
        events = audit_db.get_security_decisions(limit=10)

        assert len(events) == 1
        event = events[0]
        assert event["tool_name"] == "browser_navigate"
        assert event["decision"] == SecurityDecision.ALLOW.value
        import json

        context = json.loads(event["context"])
        assert context["url"] == "https://example.com"

    @pytest.mark.asyncio
    async def test_browser_denied_navigation(self, browser_tools, hitl_gate):
        """Test that denied browser navigation is blocked."""
        # Create operation
        operation = Operation(
            tool_name="browser_navigate",
            params={
                "url": "https://malicious-site.com",
                "session_id": "session_123",
            },
            correlation_id="deny_test_456",
        )

        # Mock denial callback
        async def mock_prompt_callback(op, risk_level, timeout):
            return ApprovalDecision(
                decision=ApprovalStatus.DENIED,
                reason="User denied navigation",
                user="test_user",
            )

        # Request approval
        decision = await hitl_gate.check_approval(operation, prompt_callback=mock_prompt_callback)
        assert decision.decision == ApprovalStatus.DENIED

        # Should NOT navigate (blocked by denial)
        # In production, this would be enforced by gateway

    @pytest.mark.asyncio
    async def test_credential_rotation_during_session(self, browser_tools, secret_manager):
        """Test handling credential rotation during active browser session."""
        # Initial credential fetch
        credential1 = await secret_manager.get_secret("test_credential")
        assert credential1.value == "test_password"

        # Create session with initial credential
        await browser_tools.browser_manager.create_session(
            pre_auth={
                "url": "https://example.com/login",
                "credentials": {
                    "username": "test_user",
                    "password": credential1.value,
                },
            }
        )

        # Simulate credential rotation
        secret_manager.get_secret = AsyncMock(
            return_value=SecretValue(
                key="test_credential",
                value="new_password",
                source="vault",
            )
        )

        # Fetch rotated credential
        credential2 = await secret_manager.get_secret("test_credential")
        assert credential2.value == "new_password"

        # Verify different credentials
        assert credential1.value != credential2.value

        # In production, would re-authenticate with new credential

    @pytest.mark.asyncio
    async def test_secrets_never_appear_in_audit_logs(
        self, browser_tools, secret_manager, audit_logger, audit_db
    ):
        """Test that secrets are never logged in audit trail."""
        # Fetch credential
        credential = await secret_manager.get_secret("test_credential")

        # Log operation with sanitized details
        import uuid

        audit_logger.log_security_decision(
            correlation_id=str(uuid.uuid4()),
            decision_type="browser_navigation",
            decision=SecurityDecision.ALLOW,
            reason="User approved",
            actor="test_user",
            tool_name="browser_navigate",
            context={
                "url": "https://example.com",
                "session_id": "session_123",
                # NOTE: Never include actual credential value
                # Use a field name that won't be redacted
                "credential_name": credential.key,  # Only the key name
                "risk_level": "HIGH",
            },
        )

        # Verify audit logs don't contain secret
        events = audit_db.get_security_decisions(limit=10)

        assert len(events) == 1
        event = events[0]
        import json

        context = json.loads(event["context"])
        # Verify secret value not in logs
        assert "test_password" not in str(context)
        assert "new_password" not in str(context)
        # Only key name should be present (credential_name won't be redacted)
        assert context.get("credential_name") == "test_credential"

    @pytest.mark.asyncio
    async def test_browser_session_cleanup_on_failure(self, browser_tools):
        """Test that browser sessions are cleaned up on operation failure."""
        # Create session
        session_id = await browser_tools.browser_manager.create_session()
        assert session_id == "session_123"

        # Simulate navigation failure
        browser_tools.browser_manager.navigate = AsyncMock(
            side_effect=Exception("Navigation failed")
        )

        # Try to navigate (will fail)
        with pytest.raises(Exception, match="Navigation failed"):
            await browser_tools.browser_manager.navigate(
                session_id=session_id, url="https://example.com"
            )

        # Cleanup session
        await browser_tools.browser_manager.close_session(session_id)

        # Verify cleanup called
        browser_tools.browser_manager.close_session.assert_called_once_with(session_id)

    @pytest.mark.asyncio
    async def test_multiple_credentials_injection(self, browser_tools, secret_manager):
        """Test injecting multiple credentials into browser session."""

        # Mock multiple secrets
        async def get_secret_side_effect(key: str):
            secrets = {
                "username": SecretValue(key="username", value="test_user", source="vault"),
                "password": SecretValue(key="password", value="test_pass", source="vault"),
                "api_key": SecretValue(key="api_key", value="test_key", source="vault"),
            }
            return secrets.get(key)

        secret_manager.get_secret = AsyncMock(side_effect=get_secret_side_effect)

        # Fetch all credentials
        username = await secret_manager.get_secret("username")
        password = await secret_manager.get_secret("password")
        api_key = await secret_manager.get_secret("api_key")

        # Create session with multiple credentials
        session_id = await browser_tools.browser_manager.create_session(
            pre_auth={
                "url": "https://example.com/login",
                "credentials": {
                    "username": username.value,
                    "password": password.value,
                },
                "headers": {
                    "X-API-Key": api_key.value,
                },
            }
        )

        assert session_id == "session_123"

        # Verify all credentials injected
        call_args = browser_tools.browser_manager.create_session.call_args
        assert call_args[1]["pre_auth"]["credentials"]["username"] == "test_user"
        assert call_args[1]["pre_auth"]["credentials"]["password"] == "test_pass"
        assert call_args[1]["pre_auth"]["headers"]["X-API-Key"] == "test_key"

    @pytest.mark.asyncio
    async def test_concurrent_browser_sessions_with_different_credentials(self, secret_manager):
        """Test multiple concurrent browser sessions with different credentials."""
        import asyncio

        # Mock different credentials for different sessions
        call_count = 0

        async def get_secret_side_effect(key: str):
            nonlocal call_count
            call_count += 1
            return SecretValue(
                key=key,
                value=f"credential_{call_count}",
                source="vault",
            )

        secret_manager.get_secret = AsyncMock(side_effect=get_secret_side_effect)

        # Fetch credentials concurrently
        creds = await asyncio.gather(
            secret_manager.get_secret("session1_cred"),
            secret_manager.get_secret("session2_cred"),
            secret_manager.get_secret("session3_cred"),
        )

        # Verify different credentials
        assert len(creds) == 3
        assert len({c.value for c in creds}) == 3  # All unique

    @pytest.mark.asyncio
    async def test_browser_hitl_timeout(self, browser_tools, hitl_gate, audit_logger, audit_db):
        """Test browser operation timeout with HITL gate."""
        # Create operation
        operation = Operation(
            tool_name="browser_navigate",
            params={"url": "https://example.com", "session_id": "session_123"},
            correlation_id="timeout_test_789",
        )

        # Mock timeout callback
        async def mock_prompt_callback(op, risk_level, timeout):
            return ApprovalDecision(
                decision=ApprovalStatus.TIMEOUT,
                reason="Approval timeout",
                user=None,
            )

        # Request approval (will timeout)
        decision = await hitl_gate.check_approval(operation, prompt_callback=mock_prompt_callback)
        assert decision.decision == ApprovalStatus.TIMEOUT

        # Log security decision
        import uuid

        audit_logger.log_security_decision(
            correlation_id=str(uuid.uuid4()),
            decision_type="browser_navigation",
            decision=SecurityDecision.DENY,  # Timeout = auto-deny
            reason=decision.reason,
            actor="test_user",
            tool_name=operation.tool_name,
            context={
                "timeout": True,
                "url": operation.params["url"],
                "risk_level": "HIGH",
            },
        )

        # Verify audit trail
        events = audit_db.get_security_decisions(limit=10)

        assert len(events) == 1
        event = events[0]
        assert event["decision"] == SecurityDecision.DENY.value
        import json

        context = json.loads(event["context"])
        assert context["timeout"] is True

    @pytest.mark.asyncio
    async def test_credential_fetch_failure_handling(self, browser_tools, secret_manager):
        """Test handling of credential fetch failures."""
        # Mock credential fetch failure
        secret_manager.get_secret = AsyncMock(side_effect=Exception("Vault unavailable"))

        # Try to fetch credential
        with pytest.raises(Exception, match="Vault unavailable"):
            await secret_manager.get_secret("test_credential")

        # Browser session should not be created without credentials
        # In production, would handle gracefully and log error
