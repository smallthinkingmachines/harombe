"""
Browser Container Manager for Phase 4.6.

Manages browser automation containers with pre-authentication and
accessibility-based snapshots for safe AI agent interaction.
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from playwright.async_api import Browser, BrowserContext, Page, async_playwright

from .vault import VaultBackend

logger = logging.getLogger(__name__)


@dataclass
class BrowserSession:
    """Represents an active browser session."""

    session_id: str
    domain: str
    context: BrowserContext | None = None
    page: Page | None = None
    created_at: float = field(default_factory=time.time)
    action_count: int = 0
    last_activity: float = field(default_factory=time.time)


@dataclass
class BrowserCredentials:
    """Credentials for browser pre-authentication."""

    domain: str
    cookies: list[dict[str, Any]] = field(default_factory=list)
    local_storage: dict[str, str] = field(default_factory=dict)
    session_storage: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)


class BrowserContainerManager:
    """Manages browser automation with pre-authentication and session isolation."""

    def __init__(
        self,
        vault_backend: VaultBackend | None = None,
        session_timeout: int = 300,
        max_actions_per_session: int = 100,
        max_concurrent_sessions: int = 5,
        headless: bool = True,
    ):
        """Initialize browser container manager.

        Args:
            vault_backend: Credential vault for pre-authentication
            session_timeout: Session timeout in seconds (default: 5 min)
            max_actions_per_session: Max actions before session refresh
            max_concurrent_sessions: Max concurrent browser sessions
            headless: Run browser in headless mode
        """
        self.vault_backend = vault_backend
        self.session_timeout = session_timeout
        self.max_actions_per_session = max_actions_per_session
        self.max_concurrent_sessions = max_concurrent_sessions
        self.headless = headless

        # Active sessions
        self.sessions: dict[str, BrowserSession] = {}

        # Playwright browser instance
        self._playwright = None
        self._browser: Browser | None = None
        self._lock = asyncio.Lock()

    async def start(self) -> None:
        """Start the browser manager and launch browser."""
        if self._browser:
            logger.warning("Browser already started")
            return

        logger.info("Starting browser manager")
        self._playwright = await async_playwright().start()
        self._browser = await self._playwright.chromium.launch(
            headless=self.headless,
            args=[
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--disable-dev-shm-usage",
                "--disable-blink-features=AutomationControlled",
            ],
        )
        logger.info("Browser started successfully")

    async def stop(self) -> None:
        """Stop the browser manager and cleanup all sessions."""
        logger.info("Stopping browser manager")

        # Close all active sessions
        session_ids = list(self.sessions.keys())
        for session_id in session_ids:
            await self.close_session(session_id)

        # Close browser
        if self._browser:
            await self._browser.close()
            self._browser = None

        # Stop playwright
        if self._playwright:
            await self._playwright.stop()
            self._playwright = None

        logger.info("Browser manager stopped")

    async def create_session(
        self,
        domain: str,
        session_id: str | None = None,
        auto_inject_credentials: bool = True,
    ) -> str:
        """Create a new browser session with optional pre-authentication.

        Args:
            domain: Domain for credential lookup (e.g., "github.com")
            session_id: Optional session ID (auto-generated if not provided)
            auto_inject_credentials: Automatically inject credentials from vault

        Returns:
            Session ID

        Raises:
            RuntimeError: If browser not started or session limit reached
        """
        if not self._browser:
            raise RuntimeError("Browser not started. Call start() first.")

        async with self._lock:
            # Check session limit
            if len(self.sessions) >= self.max_concurrent_sessions:
                # Cleanup expired sessions
                await self._cleanup_expired_sessions()

                # Still over limit?
                if len(self.sessions) >= self.max_concurrent_sessions:
                    raise RuntimeError(
                        f"Maximum concurrent sessions ({self.max_concurrent_sessions}) reached"
                    )

            # Generate session ID
            if session_id is None:
                session_id = f"sess-{uuid4()}"

            # Create browser context (isolated session)
            context = await self._browser.new_context(
                viewport={"width": 1280, "height": 720},
                user_agent="Mozilla/5.0 (compatible; Harombe/1.0; +https://github.com/smallthinkingmachines/harombe)",
                locale="en-US",
                timezone_id="America/Los_Angeles",
            )

            # Create new page
            page = await context.new_page()

            # Create session
            session = BrowserSession(
                session_id=session_id,
                domain=domain,
                context=context,
                page=page,
            )

            self.sessions[session_id] = session

            logger.info(f"Created browser session {session_id} for domain {domain}")

            # Pre-authenticate if enabled
            if auto_inject_credentials and self.vault_backend:
                await self.inject_credentials(session_id, domain)

            return session_id

    async def inject_credentials(self, session_id: str, domain: str) -> bool:
        """Inject credentials into browser session.

        This is the KEY SECURITY STEP - credentials are injected BEFORE
        the agent gains access to the browser.

        Args:
            session_id: Session ID
            domain: Domain for credential lookup

        Returns:
            True if credentials were injected, False if no credentials found

        Raises:
            ValueError: If session not found
        """
        session = self._get_session(session_id)

        if not self.vault_backend:
            logger.warning("No vault backend configured, skipping credential injection")
            return False

        try:
            # Fetch credentials from vault
            # Vault path: secrets/browser/{domain}
            vault_path = f"browser/{domain}"
            creds_data = await asyncio.to_thread(self.vault_backend.get_secret, vault_path)

            if not creds_data:
                logger.info(f"No credentials found for domain {domain}")
                return False

            # Parse credentials
            credentials = BrowserCredentials(
                domain=domain,
                cookies=creds_data.get("cookies", []),
                local_storage=creds_data.get("localStorage", {}),
                session_storage=creds_data.get("sessionStorage", {}),
                headers=creds_data.get("headers", {}),
            )

            logger.info(f"Injecting credentials for {domain} into session {session_id}")

            # Inject cookies
            if credentials.cookies:
                await session.context.add_cookies(credentials.cookies)
                logger.debug(f"Injected {len(credentials.cookies)} cookies")

            # Inject localStorage and sessionStorage
            # Must navigate to domain first
            if credentials.local_storage or credentials.session_storage:
                # Navigate to domain root to set storage
                await session.page.goto(f"https://{domain}")

                # Inject localStorage
                for key, value in credentials.local_storage.items():
                    await session.page.evaluate(f"localStorage.setItem('{key}', '{value}')")

                # Inject sessionStorage
                for key, value in credentials.session_storage.items():
                    await session.page.evaluate(f"sessionStorage.setItem('{key}', '{value}')")

                logger.debug(
                    f"Injected {len(credentials.local_storage)} localStorage items, "
                    f"{len(credentials.session_storage)} sessionStorage items"
                )

            # Set custom headers (via CDP)
            if credentials.headers:
                # Note: Setting headers requires CDP (Chrome DevTools Protocol)
                # For now, we'll skip this - can be added later if needed
                logger.debug(f"Custom headers: {list(credentials.headers.keys())}")

            logger.info(f"Successfully injected credentials for {domain}")
            return True

        except Exception as e:
            logger.error(f"Failed to inject credentials for {domain}: {e}")
            raise

    async def close_session(self, session_id: str) -> None:
        """Close browser session and cleanup resources.

        Args:
            session_id: Session ID

        Raises:
            ValueError: If session not found
        """
        if session_id not in self.sessions:
            raise ValueError(f"Session {session_id} not found")

        session = self.sessions[session_id]

        try:
            # Close page
            if session.page:
                await session.page.close()

            # Close context (destroys all credentials in memory)
            if session.context:
                await session.context.close()

            logger.info(f"Closed browser session {session_id}")

        except Exception as e:
            logger.error(f"Error closing session {session_id}: {e}")

        finally:
            # Remove from sessions dict
            del self.sessions[session_id]

    def _get_session(self, session_id: str) -> BrowserSession:
        """Get session by ID.

        Args:
            session_id: Session ID

        Returns:
            Browser session

        Raises:
            ValueError: If session not found or expired
        """
        if session_id not in self.sessions:
            raise ValueError(f"Session {session_id} not found")

        session = self.sessions[session_id]

        # Check if expired
        if self._is_session_expired(session):
            raise ValueError(f"Session {session_id} has expired")

        return session

    def _is_session_expired(self, session: BrowserSession) -> bool:
        """Check if session has expired.

        Args:
            session: Browser session

        Returns:
            True if expired, False otherwise
        """
        # Check timeout
        if time.time() - session.last_activity > self.session_timeout:
            return True

        # Check action count
        return session.action_count >= self.max_actions_per_session

    async def _cleanup_expired_sessions(self) -> None:
        """Cleanup expired sessions."""
        expired = [
            sid for sid, session in self.sessions.items() if self._is_session_expired(session)
        ]

        for session_id in expired:
            logger.info(f"Cleaning up expired session {session_id}")
            try:
                await self.close_session(session_id)
            except Exception as e:
                logger.error(f"Error cleaning up session {session_id}: {e}")

    async def navigate(
        self,
        session_id: str,
        url: str,
        wait_for: str = "load",
    ) -> dict[str, Any]:
        """Navigate to URL.

        Args:
            session_id: Session ID
            url: URL to navigate to
            wait_for: Wait condition ("load", "networkidle", "domcontentloaded")

        Returns:
            Navigation result with accessibility snapshot

        Raises:
            ValueError: If session not found or navigation fails
        """
        session = self._get_session(session_id)

        try:
            # Navigate
            await session.page.goto(url, wait_until=wait_for)

            # Update session activity
            session.last_activity = time.time()
            session.action_count += 1

            # Get accessibility snapshot
            snapshot = await self._get_accessibility_snapshot(session.page)

            logger.info(f"Navigated to {url} in session {session_id}")

            return {
                "success": True,
                "url": session.page.url,
                "title": await session.page.title(),
                "snapshot": snapshot,
            }

        except Exception as e:
            logger.error(f"Navigation failed for {url}: {e}")
            raise ValueError(f"Navigation failed: {e!s}") from e

    async def _get_accessibility_snapshot(self, page: Page) -> dict[str, Any]:
        """Generate accessibility snapshot from page.

        Returns semantic accessibility tree instead of raw HTML for security.

        Args:
            page: Playwright page

        Returns:
            Accessibility tree snapshot
        """
        try:
            # Get accessibility snapshot
            snapshot = await page.accessibility.snapshot()

            # Filter sensitive elements (password inputs)
            if snapshot:
                snapshot = self._filter_sensitive_elements(snapshot)

            return snapshot or {}

        except Exception as e:
            logger.error(f"Failed to get accessibility snapshot: {e}")
            return {}

    def _filter_sensitive_elements(self, node: dict[str, Any]) -> dict[str, Any] | None:
        """Filter sensitive elements from accessibility tree.

        Recursively removes password inputs and other sensitive fields.

        Args:
            node: Accessibility tree node

        Returns:
            Filtered node, or None if node should be excluded
        """
        # Exclude password fields
        role = node.get("role", "")
        name = node.get("name", "")

        if role == "textbox" and any(
            keyword in name.lower() for keyword in ["password", "secret", "token", "key"]
        ):
            logger.debug(f"Filtering sensitive field: {name}")
            return None

        # Recursively filter children
        if "children" in node:
            filtered_children = []
            for child in node["children"]:
                filtered_child = self._filter_sensitive_elements(child)
                if filtered_child:
                    filtered_children.append(filtered_child)

            node["children"] = filtered_children

        return node

    async def get_session_info(self, session_id: str) -> dict[str, Any]:
        """Get session information.

        Args:
            session_id: Session ID

        Returns:
            Session information dict
        """
        session = self._get_session(session_id)

        return {
            "session_id": session.session_id,
            "domain": session.domain,
            "created_at": datetime.fromtimestamp(session.created_at, UTC).isoformat(),
            "last_activity": datetime.fromtimestamp(session.last_activity, UTC).isoformat(),
            "action_count": session.action_count,
            "url": session.page.url if session.page else None,
            "title": await session.page.title() if session.page else None,
        }

    async def list_sessions(self) -> list[dict[str, Any]]:
        """List all active sessions.

        Returns:
            List of session info dicts
        """
        return [await self.get_session_info(session_id) for session_id in self.sessions]
