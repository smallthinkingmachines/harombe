"""
Tests for BrowserContainerManager.

Tests browser session management, pre-authentication, and accessibility snapshots.
"""

import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from harombe.security.browser_manager import (
    BrowserContainerManager,
    BrowserCredentials,
    BrowserSession,
)


class TestBrowserSession:
    """Tests for BrowserSession dataclass."""

    def test_browser_session_creation(self):
        """Test that browser session is created correctly."""
        session = BrowserSession(
            session_id="sess-123",
            domain="github.com",
        )

        assert session.session_id == "sess-123"
        assert session.domain == "github.com"
        assert session.context is None
        assert session.page is None
        assert session.action_count == 0
        assert session.created_at > 0
        assert session.last_activity > 0


class TestBrowserCredentials:
    """Tests for BrowserCredentials dataclass."""

    def test_browser_credentials_creation(self):
        """Test that browser credentials are created correctly."""
        creds = BrowserCredentials(
            domain="github.com",
            cookies=[{"name": "user_session", "value": "abc123"}],
            local_storage={"theme": "dark"},
        )

        assert creds.domain == "github.com"
        assert len(creds.cookies) == 1
        assert creds.local_storage["theme"] == "dark"
        assert len(creds.session_storage) == 0
        assert len(creds.headers) == 0


class TestBrowserContainerManager:
    """Tests for BrowserContainerManager."""

    def test_manager_initialization(self):
        """Test that manager is initialized correctly."""
        manager = BrowserContainerManager(
            session_timeout=300,
            max_actions_per_session=100,
            max_concurrent_sessions=5,
        )

        assert manager.session_timeout == 300
        assert manager.max_actions_per_session == 100
        assert manager.max_concurrent_sessions == 5
        assert len(manager.sessions) == 0
        assert manager._browser is None

    @pytest.mark.asyncio
    async def test_start_stop(self):
        """Test starting and stopping the browser manager."""
        manager = BrowserContainerManager(headless=True)

        # Mock playwright
        with patch("harombe.security.browser_manager.async_playwright") as mock_pw:
            mock_playwright = AsyncMock()
            mock_browser = AsyncMock()
            mock_pw.return_value.start = AsyncMock(return_value=mock_playwright)
            mock_playwright.chromium.launch = AsyncMock(return_value=mock_browser)

            # Start
            await manager.start()
            assert manager._browser is not None
            assert manager._playwright is not None

            # Stop
            await manager.stop()
            mock_browser.close.assert_called_once()
            mock_playwright.stop.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_session_requires_started_browser(self):
        """Test that creating session requires started browser."""
        manager = BrowserContainerManager()

        with pytest.raises(RuntimeError, match="Browser not started"):
            await manager.create_session(domain="github.com")

    @pytest.mark.asyncio
    async def test_create_session(self):
        """Test creating a browser session."""
        manager = BrowserContainerManager()

        # Mock browser
        mock_browser = AsyncMock()
        mock_context = AsyncMock()
        mock_page = AsyncMock()
        mock_browser.new_context = AsyncMock(return_value=mock_context)
        mock_context.new_page = AsyncMock(return_value=mock_page)
        manager._browser = mock_browser

        # Create session
        session_id = await manager.create_session(
            domain="github.com",
            auto_inject_credentials=False,
        )

        assert session_id.startswith("sess-")
        assert session_id in manager.sessions
        assert manager.sessions[session_id].domain == "github.com"

        # Verify context created
        mock_browser.new_context.assert_called_once()
        mock_context.new_page.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_session_with_custom_id(self):
        """Test creating session with custom ID."""
        manager = BrowserContainerManager()

        # Mock browser
        mock_browser = AsyncMock()
        mock_context = AsyncMock()
        mock_page = AsyncMock()
        mock_browser.new_context = AsyncMock(return_value=mock_context)
        mock_context.new_page = AsyncMock(return_value=mock_page)
        manager._browser = mock_browser

        # Create session with custom ID
        session_id = await manager.create_session(
            domain="github.com",
            session_id="custom-123",
            auto_inject_credentials=False,
        )

        assert session_id == "custom-123"
        assert "custom-123" in manager.sessions

    @pytest.mark.asyncio
    async def test_max_concurrent_sessions(self):
        """Test that max concurrent sessions limit is enforced."""
        manager = BrowserContainerManager(max_concurrent_sessions=2)

        # Mock browser
        mock_browser = AsyncMock()
        mock_context = AsyncMock()
        mock_page = AsyncMock()
        mock_browser.new_context = AsyncMock(return_value=mock_context)
        mock_context.new_page = AsyncMock(return_value=mock_page)
        manager._browser = mock_browser

        # Create 2 sessions
        await manager.create_session(domain="github.com", auto_inject_credentials=False)
        await manager.create_session(domain="gitlab.com", auto_inject_credentials=False)

        # Third should fail
        with pytest.raises(RuntimeError, match="Maximum concurrent sessions"):
            await manager.create_session(domain="bitbucket.com", auto_inject_credentials=False)

    @pytest.mark.asyncio
    async def test_close_session(self):
        """Test closing a browser session."""
        manager = BrowserContainerManager()

        # Mock browser
        mock_browser = AsyncMock()
        mock_context = AsyncMock()
        mock_page = AsyncMock()
        mock_browser.new_context = AsyncMock(return_value=mock_context)
        mock_context.new_page = AsyncMock(return_value=mock_page)
        manager._browser = mock_browser

        # Create session
        session_id = await manager.create_session(
            domain="github.com",
            auto_inject_credentials=False,
        )

        # Close session
        await manager.close_session(session_id)

        # Verify cleanup
        assert session_id not in manager.sessions
        mock_page.close.assert_called_once()
        mock_context.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_close_nonexistent_session(self):
        """Test closing nonexistent session raises error."""
        manager = BrowserContainerManager()

        with pytest.raises(ValueError, match=r"Session .* not found"):
            await manager.close_session("nonexistent")

    @pytest.mark.asyncio
    async def test_inject_credentials_no_vault(self):
        """Test that inject_credentials returns False when no vault."""
        manager = BrowserContainerManager(vault_backend=None)

        # Mock session
        session = BrowserSession(session_id="sess-123", domain="github.com")
        session.context = AsyncMock()
        session.page = AsyncMock()
        manager.sessions["sess-123"] = session

        # Should return False (no vault)
        result = await manager.inject_credentials("sess-123", "github.com")
        assert result is False

    @pytest.mark.asyncio
    async def test_inject_credentials_cookies(self):
        """Test injecting cookies into browser session."""
        # Mock vault
        mock_vault = MagicMock()
        mock_vault.get_secret = MagicMock(
            return_value={
                "cookies": [{"name": "user_session", "value": "abc123", "domain": ".github.com"}]
            }
        )

        manager = BrowserContainerManager(vault_backend=mock_vault)

        # Mock session
        session = BrowserSession(session_id="sess-123", domain="github.com")
        session.context = AsyncMock()
        session.page = AsyncMock()
        manager.sessions["sess-123"] = session

        # Inject credentials
        result = await manager.inject_credentials("sess-123", "github.com")

        assert result is True
        session.context.add_cookies.assert_called_once()
        cookies = session.context.add_cookies.call_args[0][0]
        assert len(cookies) == 1
        assert cookies[0]["name"] == "user_session"

    @pytest.mark.asyncio
    async def test_inject_credentials_local_storage(self):
        """Test injecting localStorage into browser session."""
        # Mock vault
        mock_vault = MagicMock()
        mock_vault.get_secret = MagicMock(
            return_value={"localStorage": {"theme": "dark", "lang": "en"}}
        )

        manager = BrowserContainerManager(vault_backend=mock_vault)

        # Mock session
        session = BrowserSession(session_id="sess-123", domain="github.com")
        session.context = AsyncMock()
        session.page = AsyncMock()
        session.page.goto = AsyncMock()
        session.page.evaluate = AsyncMock()
        manager.sessions["sess-123"] = session

        # Inject credentials
        result = await manager.inject_credentials("sess-123", "github.com")

        assert result is True
        # Should navigate to domain first
        session.page.goto.assert_called_once_with("https://github.com")
        # Should set localStorage items
        assert session.page.evaluate.call_count == 2  # theme + lang

    @pytest.mark.asyncio
    async def test_inject_credentials_no_credentials_found(self):
        """Test inject_credentials when no credentials in vault."""
        # Mock vault returning None
        mock_vault = MagicMock()
        mock_vault.get_secret = MagicMock(return_value=None)

        manager = BrowserContainerManager(vault_backend=mock_vault)

        # Mock session
        session = BrowserSession(session_id="sess-123", domain="github.com")
        session.context = AsyncMock()
        session.page = AsyncMock()
        manager.sessions["sess-123"] = session

        # Should return False (no credentials)
        result = await manager.inject_credentials("sess-123", "github.com")
        assert result is False

    def test_is_session_expired_timeout(self):
        """Test session expiration based on timeout."""
        manager = BrowserContainerManager(session_timeout=60)

        session = BrowserSession(session_id="sess-123", domain="github.com")
        session.last_activity = time.time() - 61  # 61 seconds ago

        assert manager._is_session_expired(session) is True

    def test_is_session_expired_action_count(self):
        """Test session expiration based on action count."""
        manager = BrowserContainerManager(max_actions_per_session=100)

        session = BrowserSession(session_id="sess-123", domain="github.com")
        session.action_count = 101

        assert manager._is_session_expired(session) is True

    def test_is_session_not_expired(self):
        """Test that active session is not expired."""
        manager = BrowserContainerManager(session_timeout=60, max_actions_per_session=100)

        session = BrowserSession(session_id="sess-123", domain="github.com")
        session.last_activity = time.time()
        session.action_count = 50

        assert manager._is_session_expired(session) is False

    @pytest.mark.asyncio
    async def test_navigate(self):
        """Test navigating to a URL."""
        manager = BrowserContainerManager()

        # Mock session
        session = BrowserSession(session_id="sess-123", domain="github.com")
        session.context = AsyncMock()
        session.page = AsyncMock()
        session.page.goto = AsyncMock()
        session.page.url = "https://github.com/settings"
        session.page.title = AsyncMock(return_value="Settings - GitHub")
        session.page.accessibility.snapshot = AsyncMock(
            return_value={"role": "RootWebArea", "name": "Settings"}
        )
        manager.sessions["sess-123"] = session

        # Navigate
        result = await manager.navigate("sess-123", "https://github.com/settings")

        assert result["success"] is True
        assert result["url"] == "https://github.com/settings"
        assert result["title"] == "Settings - GitHub"
        assert "snapshot" in result

        # Verify activity updated
        assert session.action_count == 1
        assert session.last_activity > time.time() - 1

    @pytest.mark.asyncio
    async def test_navigate_nonexistent_session(self):
        """Test navigating with nonexistent session raises error."""
        manager = BrowserContainerManager()

        with pytest.raises(ValueError, match=r"Session .* not found"):
            await manager.navigate("nonexistent", "https://github.com")

    def test_filter_sensitive_elements_password(self):
        """Test filtering password fields from accessibility tree."""
        manager = BrowserContainerManager()

        tree = {
            "role": "form",
            "children": [
                {"role": "textbox", "name": "Email"},
                {"role": "textbox", "name": "Password"},  # Should be filtered
                {"role": "button", "name": "Login"},
            ],
        }

        filtered = manager._filter_sensitive_elements(tree)

        # Password field should be removed
        assert len(filtered["children"]) == 2
        assert filtered["children"][0]["name"] == "Email"
        assert filtered["children"][1]["name"] == "Login"

    def test_filter_sensitive_elements_recursive(self):
        """Test recursive filtering of nested elements."""
        manager = BrowserContainerManager()

        tree = {
            "role": "main",
            "children": [
                {
                    "role": "form",
                    "children": [
                        {"role": "textbox", "name": "Username"},
                        {"role": "textbox", "name": "API Token"},  # Should be filtered
                    ],
                }
            ],
        }

        filtered = manager._filter_sensitive_elements(tree)

        # Check nested filtering
        form = filtered["children"][0]
        assert len(form["children"]) == 1
        assert form["children"][0]["name"] == "Username"

    @pytest.mark.asyncio
    async def test_get_session_info(self):
        """Test getting session information."""
        manager = BrowserContainerManager()

        # Mock session
        session = BrowserSession(session_id="sess-123", domain="github.com")
        session.context = AsyncMock()
        session.page = AsyncMock()
        session.page.url = "https://github.com/settings"
        session.page.title = AsyncMock(return_value="Settings")
        session.action_count = 5
        manager.sessions["sess-123"] = session

        info = await manager.get_session_info("sess-123")

        assert info["session_id"] == "sess-123"
        assert info["domain"] == "github.com"
        assert info["action_count"] == 5
        assert info["url"] == "https://github.com/settings"
        assert info["title"] == "Settings"

    @pytest.mark.asyncio
    async def test_list_sessions(self):
        """Test listing all active sessions."""
        manager = BrowserContainerManager()

        # Mock sessions
        for i in range(3):
            session = BrowserSession(session_id=f"sess-{i}", domain=f"domain{i}.com")
            session.context = AsyncMock()
            session.page = AsyncMock()
            session.page.url = f"https://domain{i}.com"
            session.page.title = AsyncMock(return_value=f"Domain {i}")
            manager.sessions[f"sess-{i}"] = session

        sessions = await manager.list_sessions()

        assert len(sessions) == 3
        assert sessions[0]["session_id"] == "sess-0"
        assert sessions[1]["session_id"] == "sess-1"
        assert sessions[2]["session_id"] == "sess-2"
