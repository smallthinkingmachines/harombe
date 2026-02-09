"""
Browser automation tools for Phase 4.6.

Provides MCP-compatible browser tools with pre-authentication and
accessibility-based interaction.
"""

import logging
from typing import Any

from playwright.async_api import TimeoutError as PlaywrightTimeoutError

from harombe.security.browser_manager import BrowserContainerManager

logger = logging.getLogger(__name__)


class BrowserTools:
    """Browser automation tools with pre-authentication."""

    def __init__(self, browser_manager: BrowserContainerManager):
        """Initialize browser tools.

        Args:
            browser_manager: Browser container manager instance
        """
        self.browser_manager = browser_manager

    async def browser_navigate(
        self,
        url: str,
        session_id: str | None = None,
        domain_hint: str | None = None,
        wait_for: str = "load",
    ) -> dict[str, Any]:
        """Navigate to a URL with pre-authentication.

        Args:
            url: URL to navigate to
            session_id: Existing session ID (creates new if not provided)
            domain_hint: Domain for credential lookup (auto-detected from URL)
            wait_for: Wait condition ("load", "networkidle", "domcontentloaded")

        Returns:
            Navigation result with accessibility snapshot
        """
        try:
            # Extract domain from URL if not provided
            if domain_hint is None:
                from urllib.parse import urlparse

                parsed = urlparse(url)
                domain_hint = parsed.netloc

            # Create new session if needed
            if session_id is None:
                session_id = await self.browser_manager.create_session(
                    domain=domain_hint,
                    auto_inject_credentials=True,
                )
                logger.info(f"Created new browser session {session_id} for {domain_hint}")
            else:
                # Verify session exists
                self.browser_manager._get_session(session_id)

            # Navigate
            result = await self.browser_manager.navigate(
                session_id=session_id,
                url=url,
                wait_for=wait_for,
            )

            # Add session_id to result
            result["session_id"] = session_id

            return result

        except Exception as e:
            logger.error(f"browser_navigate failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "error_type": type(e).__name__,
            }

    async def browser_click(
        self,
        session_id: str,
        role: str,
        name: str | None = None,
        index: int = 0,
    ) -> dict[str, Any]:
        """Click an element using accessibility selector.

        Args:
            session_id: Browser session ID
            role: ARIA role (button, link, etc.)
            name: Accessible name/label (optional)
            index: Index if multiple matches (default: 0)

        Returns:
            Click result
        """
        try:
            session = self.browser_manager._get_session(session_id)

            # Build locator
            locator = session.page.get_by_role(role, name=name)

            # Get count
            count = await locator.count()
            if count == 0:
                return {
                    "success": False,
                    "error": f"No elements found with role='{role}' and name='{name}'",
                }

            if index >= count:
                return {
                    "success": False,
                    "error": f"Index {index} out of range (found {count} elements)",
                }

            # Click element
            await locator.nth(index).click()

            # Update session activity
            session.last_activity = __import__("time").time()
            session.action_count += 1

            logger.info(f"Clicked element role='{role}' name='{name}' in session {session_id}")

            # Get updated snapshot
            snapshot = await self.browser_manager._get_accessibility_snapshot(session.page)

            return {
                "success": True,
                "role": role,
                "name": name,
                "index": index,
                "snapshot": snapshot,
                "url": session.page.url,
            }

        except PlaywrightTimeoutError as e:
            logger.error(f"browser_click timeout: {e}")
            return {
                "success": False,
                "error": "Element click timeout",
                "error_type": "TimeoutError",
            }
        except Exception as e:
            logger.error(f"browser_click failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "error_type": type(e).__name__,
            }

    async def browser_type(
        self,
        session_id: str,
        role: str,
        text: str,
        name: str | None = None,
        index: int = 0,
        clear_first: bool = False,
    ) -> dict[str, Any]:
        """Type text into an input field.

        Args:
            session_id: Browser session ID
            role: ARIA role (usually "textbox")
            text: Text to type
            name: Accessible name/label (optional)
            index: Index if multiple matches (default: 0)
            clear_first: Clear existing text (default: False)

        Returns:
            Type result
        """
        try:
            session = self.browser_manager._get_session(session_id)

            # Security check: Deny password field typing
            if name and any(
                keyword in name.lower() for keyword in ["password", "secret", "token", "key"]
            ):
                logger.warning(f"SECURITY: Denied typing into password field '{name}'")
                return {
                    "success": False,
                    "error": "Cannot type into password fields for security reasons",
                    "error_type": "SecurityError",
                }

            # Build locator
            locator = session.page.get_by_role(role, name=name)

            # Get count
            count = await locator.count()
            if count == 0:
                return {
                    "success": False,
                    "error": f"No elements found with role='{role}' and name='{name}'",
                }

            if index >= count:
                return {
                    "success": False,
                    "error": f"Index {index} out of range (found {count} elements)",
                }

            element = locator.nth(index)

            # Clear if requested
            if clear_first:
                await element.clear()

            # Type text
            await element.type(text)

            # Update session activity
            session.last_activity = __import__("time").time()
            session.action_count += 1

            logger.info(f"Typed text into role='{role}' name='{name}' in session {session_id}")

            # Get updated snapshot
            snapshot = await self.browser_manager._get_accessibility_snapshot(session.page)

            return {
                "success": True,
                "role": role,
                "name": name,
                "index": index,
                "text_length": len(text),
                "snapshot": snapshot,
                "url": session.page.url,
            }

        except PlaywrightTimeoutError as e:
            logger.error(f"browser_type timeout: {e}")
            return {
                "success": False,
                "error": "Element type timeout",
                "error_type": "TimeoutError",
            }
        except Exception as e:
            logger.error(f"browser_type failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "error_type": type(e).__name__,
            }

    async def browser_read(
        self,
        session_id: str,
        format: str = "tree",
    ) -> dict[str, Any]:
        """Extract page content as accessibility snapshot.

        Args:
            session_id: Browser session ID
            format: Output format ("tree" or "markdown")

        Returns:
            Page content
        """
        try:
            session = self.browser_manager._get_session(session_id)

            # Get accessibility snapshot
            snapshot = await self.browser_manager._get_accessibility_snapshot(session.page)

            # Get text content
            text_content = await session.page.inner_text("body")

            # Get interactive elements
            interactive_elements = []
            if snapshot:
                interactive_elements = self._extract_interactive_elements(snapshot)

            result = {
                "success": True,
                "url": session.page.url,
                "title": await session.page.title(),
                "snapshot": snapshot,
                "interactive_elements": interactive_elements,
            }

            if format == "markdown":
                # Simple markdown conversion
                result["text_content"] = text_content

            return result

        except Exception as e:
            logger.error(f"browser_read failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "error_type": type(e).__name__,
            }

    def _extract_interactive_elements(
        self, node: dict[str, Any], elements: list[dict[str, Any]] | None = None
    ) -> list[dict[str, Any]]:
        """Extract interactive elements from accessibility tree.

        Args:
            node: Accessibility tree node
            elements: Accumulated elements list

        Returns:
            List of interactive elements
        """
        if elements is None:
            elements = []

        role = node.get("role", "")

        # Check if interactive
        interactive_roles = [
            "button",
            "link",
            "textbox",
            "checkbox",
            "radio",
            "combobox",
            "listbox",
            "menuitem",
            "tab",
        ]

        if role in interactive_roles:
            elements.append(
                {
                    "role": role,
                    "name": node.get("name", ""),
                    "value": node.get("value", ""),
                }
            )

        # Recursively process children
        for child in node.get("children", []):
            self._extract_interactive_elements(child, elements)

        return elements

    async def browser_screenshot(
        self,
        session_id: str,
        full_page: bool = False,
    ) -> dict[str, Any]:
        """Capture visual screenshot.

        Args:
            session_id: Browser session ID
            full_page: Capture full scrollable page (default: False)

        Returns:
            Screenshot result with base64 encoded image
        """
        try:
            session = self.browser_manager._get_session(session_id)

            # Take screenshot
            screenshot_bytes = await session.page.screenshot(full_page=full_page)

            # Encode as base64
            import base64

            screenshot_base64 = base64.b64encode(screenshot_bytes).decode("utf-8")

            return {
                "success": True,
                "url": session.page.url,
                "screenshot": screenshot_base64,
                "format": "png",
                "full_page": full_page,
            }

        except Exception as e:
            logger.error(f"browser_screenshot failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "error_type": type(e).__name__,
            }

    async def browser_close_session(
        self,
        session_id: str,
    ) -> dict[str, Any]:
        """Close browser session and cleanup resources.

        Args:
            session_id: Browser session ID

        Returns:
            Close result
        """
        try:
            await self.browser_manager.close_session(session_id)

            return {
                "success": True,
                "session_id": session_id,
                "message": "Session closed successfully",
            }

        except Exception as e:
            logger.error(f"browser_close_session failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "error_type": type(e).__name__,
            }
