"""
Tests for browser automation tools.

Tests browser tools with BrowserContainerManager integration.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from harombe.security.browser_manager import BrowserContainerManager, BrowserSession
from harombe.tools.browser import BrowserTools


class TestBrowserTools:
    """Tests for BrowserTools."""

    @pytest.mark.asyncio
    async def test_browser_navigate_creates_new_session(self):
        """Test that browser_navigate creates new session if not provided."""
        # Mock browser manager
        manager = MagicMock(spec=BrowserContainerManager)
        manager.create_session = AsyncMock(return_value="sess-123")
        manager.navigate = AsyncMock(
            return_value={
                "success": True,
                "url": "https://github.com",
                "title": "GitHub",
                "snapshot": {"role": "RootWebArea"},
            }
        )

        tools = BrowserTools(browser_manager=manager)

        # Navigate without session_id
        result = await tools.browser_navigate(url="https://github.com")

        # Should create new session
        manager.create_session.assert_called_once()
        assert "session_id" in result
        assert result["session_id"] == "sess-123"
        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_browser_navigate_uses_existing_session(self):
        """Test that browser_navigate uses existing session."""
        # Mock browser manager
        manager = MagicMock(spec=BrowserContainerManager)
        manager._get_session = MagicMock()
        manager.navigate = AsyncMock(
            return_value={
                "success": True,
                "url": "https://github.com/settings",
                "title": "Settings",
                "snapshot": {},
            }
        )

        tools = BrowserTools(browser_manager=manager)

        # Navigate with existing session_id
        result = await tools.browser_navigate(
            url="https://github.com/settings", session_id="sess-existing"
        )

        # Should verify session exists
        manager._get_session.assert_called_once_with("sess-existing")
        assert result["session_id"] == "sess-existing"

    @pytest.mark.asyncio
    async def test_browser_navigate_auto_detects_domain(self):
        """Test that browser_navigate auto-detects domain from URL."""
        manager = MagicMock(spec=BrowserContainerManager)
        manager.create_session = AsyncMock(return_value="sess-123")
        manager.navigate = AsyncMock(return_value={"success": True})

        tools = BrowserTools(browser_manager=manager)

        await tools.browser_navigate(url="https://github.com/settings")

        # Should extract domain from URL
        call_args = manager.create_session.call_args
        assert call_args[1]["domain"] == "github.com"

    @pytest.mark.asyncio
    async def test_browser_navigate_error_handling(self):
        """Test error handling in browser_navigate."""
        manager = MagicMock(spec=BrowserContainerManager)
        manager.create_session = AsyncMock(side_effect=RuntimeError("Browser not started"))

        tools = BrowserTools(browser_manager=manager)

        result = await tools.browser_navigate(url="https://github.com")

        assert result["success"] is False
        assert "Browser not started" in result["error"]

    @pytest.mark.asyncio
    async def test_browser_click(self):
        """Test clicking an element."""
        # Mock session
        session = BrowserSession(session_id="sess-123", domain="github.com")
        session.page = AsyncMock()

        # Mock locator
        mock_locator = AsyncMock()
        mock_locator.count = AsyncMock(return_value=1)
        mock_locator.nth = MagicMock(return_value=AsyncMock())
        session.page.get_by_role = MagicMock(return_value=mock_locator)
        session.page.url = "https://github.com"

        # Mock manager
        manager = MagicMock(spec=BrowserContainerManager)
        manager._get_session = MagicMock(return_value=session)
        manager._get_accessibility_snapshot = AsyncMock(return_value={"role": "RootWebArea"})

        tools = BrowserTools(browser_manager=manager)

        # Click button
        result = await tools.browser_click(session_id="sess-123", role="button", name="Save")

        assert result["success"] is True
        assert result["role"] == "button"
        assert result["name"] == "Save"
        assert "snapshot" in result

    @pytest.mark.asyncio
    async def test_browser_click_element_not_found(self):
        """Test clicking when element not found."""
        session = BrowserSession(session_id="sess-123", domain="github.com")
        session.page = AsyncMock()

        # Mock locator with no elements
        mock_locator = AsyncMock()
        mock_locator.count = AsyncMock(return_value=0)
        session.page.get_by_role = MagicMock(return_value=mock_locator)

        manager = MagicMock(spec=BrowserContainerManager)
        manager._get_session = MagicMock(return_value=session)

        tools = BrowserTools(browser_manager=manager)

        result = await tools.browser_click(session_id="sess-123", role="button", name="Nonexistent")

        assert result["success"] is False
        assert "No elements found" in result["error"]

    @pytest.mark.asyncio
    async def test_browser_click_index_out_of_range(self):
        """Test clicking with invalid index."""
        session = BrowserSession(session_id="sess-123", domain="github.com")
        session.page = AsyncMock()

        # Mock locator with 2 elements
        mock_locator = AsyncMock()
        mock_locator.count = AsyncMock(return_value=2)
        session.page.get_by_role = MagicMock(return_value=mock_locator)

        manager = MagicMock(spec=BrowserContainerManager)
        manager._get_session = MagicMock(return_value=session)

        tools = BrowserTools(browser_manager=manager)

        result = await tools.browser_click(
            session_id="sess-123", role="button", name="Save", index=5
        )

        assert result["success"] is False
        assert "out of range" in result["error"]

    @pytest.mark.asyncio
    async def test_browser_type(self):
        """Test typing text into input field."""
        session = BrowserSession(session_id="sess-123", domain="github.com")
        session.page = AsyncMock()

        # Mock locator
        mock_element = AsyncMock()
        mock_locator = AsyncMock()
        mock_locator.count = AsyncMock(return_value=1)
        mock_locator.nth = MagicMock(return_value=mock_element)
        session.page.get_by_role = MagicMock(return_value=mock_locator)
        session.page.url = "https://github.com"

        manager = MagicMock(spec=BrowserContainerManager)
        manager._get_session = MagicMock(return_value=session)
        manager._get_accessibility_snapshot = AsyncMock(return_value={})

        tools = BrowserTools(browser_manager=manager)

        result = await tools.browser_type(
            session_id="sess-123", role="textbox", name="Search", text="hello world"
        )

        assert result["success"] is True
        assert result["text_length"] == 11
        mock_element.type.assert_called_once_with("hello world")

    @pytest.mark.asyncio
    async def test_browser_type_password_field_denied(self):
        """Test that typing into password fields is denied."""
        session = BrowserSession(session_id="sess-123", domain="github.com")
        session.page = AsyncMock()

        manager = MagicMock(spec=BrowserContainerManager)
        manager._get_session = MagicMock(return_value=session)

        tools = BrowserTools(browser_manager=manager)

        # Try to type into password field
        result = await tools.browser_type(
            session_id="sess-123",
            role="textbox",
            name="Password",
            text="secret123",
        )

        assert result["success"] is False
        assert "Cannot type into password fields" in result["error"]
        assert result["error_type"] == "SecurityError"

    @pytest.mark.asyncio
    async def test_browser_type_with_clear(self):
        """Test typing with clear_first option."""
        session = BrowserSession(session_id="sess-123", domain="github.com")
        session.page = AsyncMock()

        mock_element = AsyncMock()
        mock_locator = AsyncMock()
        mock_locator.count = AsyncMock(return_value=1)
        mock_locator.nth = MagicMock(return_value=mock_element)
        session.page.get_by_role = MagicMock(return_value=mock_locator)
        session.page.url = "https://github.com"

        manager = MagicMock(spec=BrowserContainerManager)
        manager._get_session = MagicMock(return_value=session)
        manager._get_accessibility_snapshot = AsyncMock(return_value={})

        tools = BrowserTools(browser_manager=manager)

        result = await tools.browser_type(
            session_id="sess-123",
            role="textbox",
            name="Search",
            text="new text",
            clear_first=True,
        )

        assert result["success"] is True
        mock_element.clear.assert_called_once()
        mock_element.type.assert_called_once_with("new text")

    @pytest.mark.asyncio
    async def test_browser_read(self):
        """Test reading page content."""
        session = BrowserSession(session_id="sess-123", domain="github.com")
        session.page = AsyncMock()
        session.page.url = "https://github.com"
        session.page.title = AsyncMock(return_value="GitHub")
        session.page.inner_text = AsyncMock(return_value="Page content here")

        manager = MagicMock(spec=BrowserContainerManager)
        manager._get_session = MagicMock(return_value=session)
        manager._get_accessibility_snapshot = AsyncMock(
            return_value={
                "role": "main",
                "children": [
                    {"role": "button", "name": "Sign in"},
                    {"role": "link", "name": "Learn more"},
                ],
            }
        )

        tools = BrowserTools(browser_manager=manager)

        result = await tools.browser_read(session_id="sess-123")

        assert result["success"] is True
        assert result["url"] == "https://github.com"
        assert result["title"] == "GitHub"
        assert "snapshot" in result
        assert "interactive_elements" in result
        assert len(result["interactive_elements"]) == 2

    @pytest.mark.asyncio
    async def test_browser_read_markdown_format(self):
        """Test reading page content in markdown format."""
        session = BrowserSession(session_id="sess-123", domain="github.com")
        session.page = AsyncMock()
        session.page.url = "https://github.com"
        session.page.title = AsyncMock(return_value="GitHub")
        session.page.inner_text = AsyncMock(return_value="# Welcome\n\nContent here")

        manager = MagicMock(spec=BrowserContainerManager)
        manager._get_session = MagicMock(return_value=session)
        manager._get_accessibility_snapshot = AsyncMock(return_value={})

        tools = BrowserTools(browser_manager=manager)

        result = await tools.browser_read(session_id="sess-123", format="markdown")

        assert result["success"] is True
        assert "text_content" in result
        assert "# Welcome" in result["text_content"]

    def test_extract_interactive_elements(self):
        """Test extracting interactive elements from tree."""
        manager = MagicMock(spec=BrowserContainerManager)
        tools = BrowserTools(browser_manager=manager)

        tree = {
            "role": "main",
            "children": [
                {"role": "heading", "name": "Title"},
                {"role": "button", "name": "Submit", "value": ""},
                {"role": "link", "name": "Learn more", "value": ""},
                {
                    "role": "form",
                    "children": [{"role": "textbox", "name": "Email", "value": "user@example.com"}],
                },
            ],
        }

        elements = tools._extract_interactive_elements(tree)

        assert len(elements) == 3
        assert elements[0]["role"] == "button"
        assert elements[1]["role"] == "link"
        assert elements[2]["role"] == "textbox"
        assert elements[2]["value"] == "user@example.com"

    @pytest.mark.asyncio
    async def test_browser_screenshot(self):
        """Test capturing screenshot."""
        session = BrowserSession(session_id="sess-123", domain="github.com")
        session.page = AsyncMock()
        session.page.url = "https://github.com"
        session.page.screenshot = AsyncMock(return_value=b"fake_image_data")

        manager = MagicMock(spec=BrowserContainerManager)
        manager._get_session = MagicMock(return_value=session)

        tools = BrowserTools(browser_manager=manager)

        result = await tools.browser_screenshot(session_id="sess-123")

        assert result["success"] is True
        assert "screenshot" in result
        assert result["format"] == "png"
        assert result["full_page"] is False

    @pytest.mark.asyncio
    async def test_browser_screenshot_full_page(self):
        """Test capturing full page screenshot."""
        session = BrowserSession(session_id="sess-123", domain="github.com")
        session.page = AsyncMock()
        session.page.url = "https://github.com"
        session.page.screenshot = AsyncMock(return_value=b"fake_image_data")

        manager = MagicMock(spec=BrowserContainerManager)
        manager._get_session = MagicMock(return_value=session)

        tools = BrowserTools(browser_manager=manager)

        result = await tools.browser_screenshot(session_id="sess-123", full_page=True)

        assert result["success"] is True
        assert result["full_page"] is True
        session.page.screenshot.assert_called_once_with(full_page=True)

    @pytest.mark.asyncio
    async def test_browser_close_session(self):
        """Test closing browser session."""
        manager = MagicMock(spec=BrowserContainerManager)
        manager.close_session = AsyncMock()

        tools = BrowserTools(browser_manager=manager)

        result = await tools.browser_close_session(session_id="sess-123")

        assert result["success"] is True
        assert result["session_id"] == "sess-123"
        manager.close_session.assert_called_once_with("sess-123")

    @pytest.mark.asyncio
    async def test_browser_close_session_error(self):
        """Test error handling when closing session."""
        manager = MagicMock(spec=BrowserContainerManager)
        manager.close_session = AsyncMock(side_effect=ValueError("Session not found"))

        tools = BrowserTools(browser_manager=manager)

        result = await tools.browser_close_session(session_id="sess-invalid")

        assert result["success"] is False
        assert "Session not found" in result["error"]
