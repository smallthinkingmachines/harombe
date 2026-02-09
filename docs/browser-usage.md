# Browser Container Usage Guide

**Phase 4.6 - Browser Automation with Pre-Authentication**

This guide shows how to use Harombe's browser automation tools with pre-authentication and accessibility-based interaction.

## Overview

Harombe's browser container provides:

- **Pre-authenticated browsing** - Credentials injected before agent access
- **Accessibility-first** - Agent sees semantic tree, not raw HTML/JS
- **HITL protection** - Destructive actions require human approval
- **Session isolation** - Each session in separate container

## Quick Start

### 1. Install Dependencies

```bash
# Playwright is required for browser automation
pip install "playwright>=1.40"

# Install browser binaries
python -m playwright install chromium
```

### 2. Store Credentials in Vault

Store browser credentials in your vault backend:

```bash
# Using HashiCorp Vault
vault kv put secrets/browser/github.com \
  cookies='[{"name":"user_session","value":"abc123...","domain":".github.com"}]' \
  localStorage='{"theme":"dark"}'

# Using SOPS (encrypted file)
# Edit secrets.yaml:
browser:
  github.com:
    cookies:
      - name: user_session
        value: abc123...
        domain: .github.com
        secure: true
        httpOnly: true
    localStorage:
      theme: dark
```

### 3. Basic Browser Automation

```python
import asyncio
from harombe.security.browser_manager import BrowserContainerManager
from harombe.security.vault import create_vault_backend
from harombe.tools.browser import BrowserTools

async def main():
    # Create vault backend
    vault = create_vault_backend("vault")  # or "sops", "env"

    # Create browser manager
    manager = BrowserContainerManager(
        vault_backend=vault,
        session_timeout=300,  # 5 minutes
        headless=True,
    )

    # Start browser
    await manager.start()

    # Create browser tools
    tools = BrowserTools(browser_manager=manager)

    try:
        # Navigate (automatically creates session and injects credentials)
        result = await tools.browser_navigate(
            url="https://github.com/settings"
        )

        print(f"Navigated to: {result['url']}")
        print(f"Session ID: {result['session_id']}")

        # The agent sees accessibility tree, not raw HTML
        print(f"Page structure: {result['snapshot']}")

        # Click a button
        click_result = await tools.browser_click(
            session_id=result['session_id'],
            role="button",
            name="Update profile"
        )

        # Read page content
        read_result = await tools.browser_read(
            session_id=result['session_id']
        )

        print(f"Interactive elements: {read_result['interactive_elements']}")

    finally:
        # Cleanup
        await manager.stop()

if __name__ == "__main__":
    asyncio.run(main())
```

## Browser Tools

### browser_navigate

Navigate to a URL with pre-authentication.

**Parameters:**

- `url` (str, required): URL to navigate to
- `session_id` (str, optional): Existing session ID (creates new if not provided)
- `domain_hint` (str, optional): Domain for credential lookup (auto-detected)
- `wait_for` (str, optional): Wait condition ("load", "networkidle", "domcontentloaded")

**Returns:**

```python
{
    "success": True,
    "url": "https://github.com/settings",
    "title": "Settings - GitHub",
    "session_id": "sess-abc123",
    "snapshot": {
        "role": "RootWebArea",
        "children": [...]
    }
}
```

**Example:**

```python
result = await tools.browser_navigate(
    url="https://github.com/settings",
    wait_for="networkidle"  # Wait for all network requests
)
```

### browser_click

Click an element using accessibility selector.

**Parameters:**

- `session_id` (str, required): Browser session ID
- `role` (str, required): ARIA role (button, link, checkbox, etc.)
- `name` (str, optional): Accessible name/label
- `index` (int, optional): Index if multiple matches (default: 0)

**Returns:**

```python
{
    "success": True,
    "role": "button",
    "name": "Save changes",
    "index": 0,
    "snapshot": {...},
    "url": "https://github.com/settings"
}
```

**Example:**

```python
# Click the first "Save" button
await tools.browser_click(
    session_id=session_id,
    role="button",
    name="Save changes"
)

# Click the second "Delete" link (if multiple)
await tools.browser_click(
    session_id=session_id,
    role="link",
    name="Delete",
    index=1
)
```

**Common ARIA Roles:**

- `button` - Buttons and button-like elements
- `link` - Hyperlinks
- `textbox` - Input fields
- `checkbox` - Checkboxes
- `radio` - Radio buttons
- `combobox` - Dropdowns/select elements
- `tab` - Tab controls
- `menuitem` - Menu items

### browser_type

Type text into an input field.

**Parameters:**

- `session_id` (str, required): Browser session ID
- `role` (str, required): ARIA role (usually "textbox")
- `text` (str, required): Text to type
- `name` (str, optional): Accessible name/label
- `index` (int, optional): Index if multiple matches (default: 0)
- `clear_first` (bool, optional): Clear existing text (default: False)

**Returns:**

```python
{
    "success": True,
    "role": "textbox",
    "name": "Search",
    "text_length": 11,
    "snapshot": {...}
}
```

**Security Note:** Typing into password fields is automatically denied. Use pre-authentication instead.

**Example:**

```python
# Type into search box
await tools.browser_type(
    session_id=session_id,
    role="textbox",
    name="Search repositories",
    text="harombe"
)

# Replace existing text
await tools.browser_type(
    session_id=session_id,
    role="textbox",
    name="Name",
    text="New Name",
    clear_first=True
)
```

### browser_read

Extract page content as accessibility snapshot.

**Parameters:**

- `session_id` (str, required): Browser session ID
- `format` (str, optional): Output format ("tree" or "markdown")

**Returns:**

```python
{
    "success": True,
    "url": "https://github.com/settings",
    "title": "Settings - GitHub",
    "snapshot": {...},
    "interactive_elements": [
        {"role": "button", "name": "Save changes", "value": ""},
        {"role": "link", "name": "Delete account", "value": ""}
    ],
    "text_content": "..."  # Only if format="markdown"
}
```

**Example:**

```python
# Get accessibility tree
result = await tools.browser_read(session_id=session_id)

# Get as markdown
result = await tools.browser_read(
    session_id=session_id,
    format="markdown"
)
print(result['text_content'])
```

### browser_screenshot

Capture visual screenshot for debugging.

**Parameters:**

- `session_id` (str, required): Browser session ID
- `full_page` (bool, optional): Capture full scrollable page (default: False)

**Returns:**

```python
{
    "success": True,
    "url": "https://github.com/settings",
    "screenshot": "iVBORw0KGgo...",  # Base64 encoded PNG
    "format": "png",
    "full_page": False
}
```

**Example:**

```python
import base64

result = await tools.browser_screenshot(session_id=session_id)

# Save to file
screenshot_data = base64.b64decode(result['screenshot'])
with open('screenshot.png', 'wb') as f:
    f.write(screenshot_data)
```

### browser_close_session

Close browser session and cleanup resources.

**Parameters:**

- `session_id` (str, required): Browser session ID

**Example:**

```python
await tools.browser_close_session(session_id=session_id)
```

## Credential Management

### Credential Schema

Credentials are stored in the vault with this structure:

```yaml
# Vault path: secrets/browser/{domain}
domain: github.com
cookies:
  - name: user_session
    value: abc123...
    domain: .github.com
    path: /
    expires: 1735689600 # Unix timestamp
    httpOnly: true
    secure: true
    sameSite: Lax

localStorage:
  theme: dark
  lang: en

sessionStorage:
  temp_key: temp_value

headers:
  Authorization: Bearer token123
```

### Extracting Credentials from Browser

Use browser DevTools to extract credentials:

```javascript
// In browser console (while logged in)

// Get cookies
document.cookie.split("; ").map((c) => {
  const [name, value] = c.split("=");
  return { name, value, domain: window.location.hostname };
});

// Get localStorage
JSON.stringify(localStorage);

// Get sessionStorage
JSON.stringify(sessionStorage);
```

### Vault Backend Setup

**HashiCorp Vault:**

```bash
# Store credentials
vault kv put secrets/browser/github.com \
  cookies='[...]' \
  localStorage='{...}'

# Retrieve credentials (for testing)
vault kv get secrets/browser/github.com
```

**SOPS (Encrypted File):**

```yaml
# secrets.yaml (encrypted with SOPS)
browser:
  github.com:
    cookies: [...]
    localStorage: { ... }
```

**Environment Variables:**

```bash
# .env file
BROWSER_GITHUB_COM_COOKIES='[...]'
BROWSER_GITHUB_COM_LOCALSTORAGE='{...}'
```

## HITL Integration

Browser operations are protected by HITL gates based on risk level.

### Risk Levels

**CRITICAL** (30s timeout):

- Financial/payment sites
- Account deletion buttons

**HIGH** (60s timeout):

- Email/admin/settings navigation
- Destructive actions (delete, remove, revoke)
- Send/submit/publish buttons

**MEDIUM** (120s timeout):

- New domain navigation
- Save/update/create actions
- Personal information fields

**LOW** (auto-approved):

- Same-domain navigation
- Read-only operations
- Search inputs

### Configuring Trusted Domains

Configure domains that don't require approval:

```yaml
# harombe.yaml
security:
  browser:
    hitl:
      enabled: true

      # Auto-approve navigation to these domains
      trusted_domains:
        - github.com
        - stackoverflow.com
        - docs.python.org

      # Always require approval for these domains
      sensitive_domains:
        - mail.google.com
        - paypal.com
        - admin.*
```

### Custom HITL Rules

```python
from harombe.security.hitl import HITLRule, RiskLevel
from harombe.security.browser_risk import get_browser_hitl_rules

# Get default rules
rules = get_browser_hitl_rules()

# Add custom rule
custom_rule = HITLRule(
    tools=["browser_navigate"],
    risk=RiskLevel.HIGH,
    conditions=[
        {"param": "url", "matches": r"internal\.company\.com"}
    ],
    timeout=60,
    description="Internal company site navigation"
)

rules.append(custom_rule)

# Apply to HITL gate
from harombe.security.hitl import RiskClassifier, HITLGate

classifier = RiskClassifier(rules=rules)
hitl_gate = HITLGate(classifier=classifier)
```

## Complete Example: Automated GitHub Workflow

```python
import asyncio
from harombe.security.browser_manager import BrowserContainerManager
from harombe.security.vault import create_vault_backend
from harombe.tools.browser import BrowserTools

async def update_github_profile():
    """Automated GitHub profile update with HITL protection."""

    # Setup
    vault = create_vault_backend("vault")
    manager = BrowserContainerManager(vault_backend=vault)
    await manager.start()

    tools = BrowserTools(browser_manager=manager)

    try:
        # Navigate to settings (credentials auto-injected)
        result = await tools.browser_navigate(
            url="https://github.com/settings/profile"
        )
        session_id = result['session_id']

        print(f"✓ Navigated to GitHub settings")

        # Read current profile
        content = await tools.browser_read(session_id=session_id)
        print(f"✓ Found {len(content['interactive_elements'])} interactive elements")

        # Update bio field
        await tools.browser_type(
            session_id=session_id,
            role="textbox",
            name="Bio",
            text="AI Safety Researcher | Building Harombe",
            clear_first=True
        )
        print(f"✓ Updated bio field")

        # Save changes (requires HITL approval - HIGH risk)
        await tools.browser_click(
            session_id=session_id,
            role="button",
            name="Update profile"
        )
        print(f"✓ Clicked Update profile button")

        # Take screenshot for verification
        screenshot = await tools.browser_screenshot(
            session_id=session_id
        )
        print(f"✓ Captured screenshot ({len(screenshot['screenshot'])} bytes)")

        # Cleanup
        await tools.browser_close_session(session_id=session_id)
        print(f"✓ Session closed")

    finally:
        await manager.stop()

if __name__ == "__main__":
    asyncio.run(update_github_profile())
```

## Security Best Practices

1. **Never store plaintext credentials in code**
   - Always use vault backend (Vault, SOPS, or env vars)
   - Never commit credentials to git

2. **Use pre-authentication for sensitive sites**
   - Don't type passwords via `browser_type`
   - Pre-inject credentials via vault

3. **Review HITL prompts carefully**
   - Destructive actions require human approval
   - Verify the operation before approving

4. **Limit session lifetime**
   - Set appropriate `session_timeout` (default: 5 minutes)
   - Close sessions when done

5. **Use accessibility selectors, not XPath/CSS**
   - More robust to UI changes
   - Semantic and easier to understand

6. **Monitor audit logs**
   - All browser actions are logged
   - Review for suspicious activity

## Troubleshooting

### "Browser not started"

```python
# Always call start() before using
await manager.start()
```

### "Session not found"

```python
# Session may have expired (timeout or action limit)
# Create new session:
result = await tools.browser_navigate(url="...")
session_id = result['session_id']
```

### "Element not found"

```python
# Check role and name are correct
# Use browser_read to see available elements:
content = await tools.browser_read(session_id=session_id)
print(content['interactive_elements'])
```

### "Cannot type into password fields"

```python
# This is intentional security protection
# Use pre-authentication instead:
# 1. Store credentials in vault
# 2. Credentials auto-injected on navigation
```

### Playwright installation issues

```bash
# Install playwright browsers
python -m playwright install chromium

# If issues persist, install system dependencies:
# macOS (via Homebrew)
brew install --cask chromedriver

# Linux
python -m playwright install-deps
```

## Configuration Reference

```yaml
# harombe.yaml
security:
  browser:
    enabled: true

    # Session limits
    session_timeout: 300 # 5 minutes
    max_actions_per_session: 100
    max_concurrent_sessions: 5

    # Container resources
    container:
      memory_limit: "512m"
      cpu_shares: 0.5

    # Pre-authentication
    credentials:
      vault_backend: "vault" # or "sops", "env"
      vault_path: "secrets/browser/"
      auto_inject: true

    # Accessibility snapshot
    snapshot:
      exclude_password_fields: true
      exclude_hidden_elements: true
      max_depth: 10

    # HITL integration
    hitl:
      enabled: true
      trusted_domains:
        - github.com
        - stackoverflow.com
      sensitive_domains:
        - gmail.com
        - paypal.com
```

## Next Steps

- **Phase 4.7**: Code execution sandbox with gVisor
- **Phase 4.8**: End-to-end security integration
- **Phase 5**: Privacy router with PII detection

## References

- [Browser Container Design](./browser-container-design.md) - Architecture details
- [HITL Gates](./hitl-design.md) - Approval flow
- [Secret Management](./security-credentials.md) - Vault integration
- [Playwright Documentation](https://playwright.dev/python/) - Browser automation API
