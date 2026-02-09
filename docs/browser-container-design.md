# Browser Container Design - Phase 4.6

**Status:** Design Complete
**Implementation:** Phase 4.6
**Dependencies:** Phase 4.1-4.5 (MCP Gateway, HITL Gates, Secret Management)

## Overview

The Browser Container provides safe, pre-authenticated browser automation for AI agents. It prevents credential exposure by injecting authentication tokens before the agent gains access, using accessibility snapshots instead of raw DOM/HTML to reduce attack surface.

## Goals

1. **Credential Safety** - Never expose passwords or auth tokens to the agent or LLM
2. **Pre-Authentication** - Inject credentials before agent access using vault-stored tokens
3. **Accessibility-First** - Use accessibility tree instead of DOM to reduce XSS/injection risks
4. **Session Isolation** - Each browser session in isolated container with cleanup
5. **HITL Integration** - Require approval for sensitive browser operations
6. **Audit Trail** - Log all browser actions for security review

## Architecture

### Component Overview

```
┌─────────────────────────────────────────────────────────────┐
│ Agent                                                        │
│ - Receives accessibility snapshot (not raw HTML)            │
│ - Makes decisions based on semantic tree                    │
│ - No access to credentials or auth tokens                   │
└────────────────┬────────────────────────────────────────────┘
                 │ browser_navigate, browser_click, etc.
                 │ JSON-RPC 2.0 via MCP Gateway
                 ▼
┌─────────────────────────────────────────────────────────────┐
│ MCP Gateway                                                  │
│ ┌─────────────────────────────────────────────────────────┐│
│ │ HITL Gate: Check if browser action requires approval   ││
│ │ - Medium risk: browser_navigate to new domain          ││
│ │ - High risk: browser_click on "Delete" or "Send"       ││
│ │ - Critical risk: browser_type into password fields     ││
│ └─────────────────────────────────────────────────────────┘│
│                         │                                    │
│                         ▼                                    │
│ ┌─────────────────────────────────────────────────────────┐│
│ │ Route to Browser Container                              ││
│ └─────────────────────────────────────────────────────────┘│
└────────────────┬────────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────────┐
│ Browser MCP Server (in Docker container)                    │
│                                                              │
│ ┌────────────────────────────────────────────────────────┐ │
│ │ BrowserContainerManager                                │ │
│ │ - Session lifecycle (create, cleanup)                  │ │
│ │ - Container resource limits                            │ │
│ │ - Health monitoring                                    │ │
│ └────────────────────────────────────────────────────────┘ │
│                         │                                    │
│                         ▼                                    │
│ ┌────────────────────────────────────────────────────────┐ │
│ │ Pre-Authentication Module                              │ │
│ │ - Fetch credentials from vault (read-only access)      │ │
│ │ - Inject cookies/localStorage before agent access      │ │
│ │ - Credential vault isolation (vault → browser only)    │ │
│ └────────────────────────────────────────────────────────┘ │
│                         │                                    │
│                         ▼                                    │
│ ┌────────────────────────────────────────────────────────┐ │
│ │ Playwright Browser Automation                          │ │
│ │ - Chromium in headless mode                            │ │
│ │ - Isolated browser context per session                 │ │
│ │ - Screenshot capture                                   │ │
│ └────────────────────────────────────────────────────────┘ │
│                         │                                    │
│                         ▼                                    │
│ ┌────────────────────────────────────────────────────────┐ │
│ │ Accessibility Snapshot Generator                       │ │
│ │ - Extract semantic accessibility tree                  │ │
│ │ - Filter sensitive elements (password inputs)          │ │
│ │ - Return structured tree (not raw HTML)                │ │
│ └────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

## Pre-Authentication Flow

The key security innovation is pre-authentication: credentials are injected **before** the agent can access the browser.

```
1. Agent Request
   │
   │ browser_navigate(url="https://github.com/settings")
   │
   ▼
2. Gateway HITL Check
   │
   │ RiskClassifier: "github.com/settings" → MEDIUM risk
   │ → Auto-approve (user configured github.com as trusted)
   │
   ▼
3. Browser Container Creation
   │
   │ BrowserContainerManager.create_session(
   │   domain="github.com",
   │   session_id="sess-abc123"
   │ )
   │
   ▼
4. **PRE-AUTH: Credential Injection** ⭐ KEY SECURITY STEP
   │
   │ credentials = vault.get_credentials("github.com")
   │ # credentials = {"cookies": [...], "localStorage": {...}}
   │
   │ browser.context.add_cookies(credentials["cookies"])
   │ browser.evaluate("localStorage.setItem(...)")
   │
   │ ❌ Agent NEVER sees credentials
   │ ❌ LLM NEVER processes auth tokens
   │
   ▼
5. Navigate to URL
   │
   │ browser.goto("https://github.com/settings")
   │ # Browser is now authenticated via injected credentials
   │
   ▼
6. Generate Accessibility Snapshot
   │
   │ snapshot = browser.accessibility.snapshot()
   │ # Returns semantic tree, NOT raw HTML
   │ # Example:
   │ # {
   │ #   "role": "main",
   │ #   "children": [
   │ #     {"role": "heading", "level": 1, "name": "Settings"},
   │ #     {"role": "button", "name": "Delete account"}
   │ #   ]
   │ # }
   │
   ▼
7. Return to Agent
   │
   │ response = {
   │   "success": true,
   │   "snapshot": <accessibility_tree>,
   │   "screenshot_id": "img-xyz789"  # Optional visual reference
   │ }
   │
   ▼
8. Agent Decision
   │
   │ Agent analyzes accessibility tree (not HTML)
   │ Decides next action based on semantic structure
   │ Makes next tool call (e.g., browser_click)
```

## Browser Tools

### browser_navigate

Navigate to a URL with pre-authentication.

**Parameters:**

- `url` (string, required): URL to navigate to
- `domain_hint` (string, optional): Domain for credential lookup (auto-detected from URL)
- `wait_for` (string, optional): Wait condition ("load", "networkidle", "domcontentloaded")

**HITL Risk Classification:**

- LOW: Same domain as current page
- MEDIUM: New domain (requires approval if domain not in allowlist)
- HIGH: Known sensitive domains (banking, email, admin panels)

**Example:**

```json
{
  "method": "tools/call",
  "params": {
    "name": "browser_navigate",
    "arguments": {
      "url": "https://github.com/settings",
      "wait_for": "networkidle"
    }
  }
}
```

**Response:**

```json
{
  "result": {
    "success": true,
    "url": "https://github.com/settings",
    "title": "Settings - GitHub",
    "snapshot": {
      "role": "RootWebArea",
      "name": "Settings - GitHub",
      "children": [...]
    },
    "screenshot_id": "img-abc123"
  }
}
```

### browser_click

Click an element using accessibility selector.

**Parameters:**

- `role` (string, required): ARIA role (button, link, etc.)
- `name` (string, optional): Accessible name/label
- `index` (int, optional): Index if multiple matches (default: 0)

**HITL Risk Classification:**

- LOW: Navigation buttons, read-only actions
- MEDIUM: Form submissions, "Save" buttons
- HIGH: Destructive actions ("Delete", "Remove", "Send")
- CRITICAL: Payment/transfer buttons, account deletion

**Example:**

```json
{
  "method": "tools/call",
  "params": {
    "name": "browser_click",
    "arguments": {
      "role": "button",
      "name": "Delete account"
    }
  }
}
```

### browser_type

Type text into an input field.

**Parameters:**

- `role` (string, required): Usually "textbox"
- `name` (string, optional): Label text
- `text` (string, required): Text to type
- `clear_first` (bool, optional): Clear existing text (default: false)

**HITL Risk Classification:**

- LOW: Search boxes, comment fields
- MEDIUM: Form inputs (name, email, etc.)
- HIGH: Configuration fields, code editors
- CRITICAL: Password fields (**automatically denied** - agent should never type passwords)

**Security:** Password fields are automatically detected and denied. Credentials must be pre-injected.

### browser_read

Extract page content as accessibility snapshot.

**Parameters:**

- `format` (string, optional): "tree" (default) or "markdown"

**HITL Risk:** LOW (read-only)

**Response:**

```json
{
  "result": {
    "snapshot": {
      "role": "RootWebArea",
      "children": [...]
    },
    "text_content": "Markdown representation of page...",
    "interactive_elements": [
      {"role": "button", "name": "Save changes"},
      {"role": "link", "name": "Help"}
    ]
  }
}
```

### browser_screenshot

Capture visual screenshot (for debugging/verification).

**Parameters:**

- `full_page` (bool, optional): Capture full scrollable page (default: false)

**HITL Risk:** LOW (read-only)

## Credential Management

### Vault Integration

Credentials are stored in the vault backend (HashiCorp Vault, SOPS, or env vars) and retrieved only by the Browser Container.

**Credential Schema:**

```yaml
# In vault: secrets/browser/github.com
{
  "domain": "github.com",
  "cookies":
    [
      {
        "name": "user_session",
        "value": "abc123...",
        "domain": ".github.com",
        "path": "/",
        "expires": 1735689600,
        "httpOnly": true,
        "secure": true,
        "sameSite": "Lax",
      },
    ],
  "localStorage": { "theme": "dark", "timezone": "America/Los_Angeles" },
  "sessionStorage": {},
  "headers": { "Authorization": "Bearer ghp_..." },
}
```

### Credential Lifecycle

1. **Storage:** Admin stores credentials via vault backend
2. **Retrieval:** Browser Container retrieves credentials (agent NEVER has access)
3. **Injection:** Credentials injected before navigation
4. **Isolation:** Credentials remain in browser memory only
5. **Cleanup:** Browser context destroyed after session, credentials purged

### Security Boundaries

```
┌────────────────────────┐
│ Vault Backend          │
│ - Stores credentials   │
└───────┬────────────────┘
        │ Read-only access
        ▼
┌────────────────────────┐
│ Browser Container      │
│ - Injects credentials  │
│ - Never logs/exposes   │
└────────────────────────┘
        ▲
        │ Accessibility snapshots only
        │ (NO credentials)
        │
┌────────────────────────┐
│ Agent / LLM            │
│ - Sees page structure  │
│ - NEVER sees tokens    │
└────────────────────────┘
```

## Session Management

### Session Lifecycle

```python
# 1. Create session
session_id = browser_manager.create_session(
    domain="github.com",
    timeout=300  # 5 minutes
)

# 2. Pre-authenticate
browser_manager.inject_credentials(
    session_id=session_id,
    domain="github.com"
)

# 3. Agent performs actions
# ... browser_navigate, browser_click, etc.

# 4. Auto-cleanup
# - After timeout (300s)
# - After max_actions (100)
# - On explicit close
browser_manager.close_session(session_id)
```

### Resource Limits

Per-session limits to prevent abuse:

- **Timeout:** 5 minutes (configurable)
- **Max Actions:** 100 actions per session
- **Memory:** 512MB container limit
- **CPU:** 0.5 CPU shares
- **Network:** Egress filtering via Phase 4.4

## Accessibility Snapshot Format

Instead of raw HTML (which can contain XSS, credential leaks, etc.), we use the accessibility tree.

**Benefits:**

1. **Security:** No raw HTML/JS/CSS exposure to LLM
2. **Semantic:** Structured by ARIA roles, easier for agent to understand
3. **Compact:** Much smaller than full DOM
4. **Filtered:** Password inputs automatically excluded

**Example Snapshot:**

```json
{
  "role": "RootWebArea",
  "name": "GitHub Settings",
  "children": [
    {
      "role": "banner",
      "children": [
        { "role": "link", "name": "Homepage" },
        { "role": "button", "name": "Profile" }
      ]
    },
    {
      "role": "main",
      "children": [
        { "role": "heading", "level": 1, "name": "Public profile" },
        {
          "role": "form",
          "children": [
            {
              "role": "textbox",
              "name": "Name",
              "value": "John Doe"
            },
            {
              "role": "textbox",
              "name": "Bio",
              "value": "Developer",
              "multiline": true
            },
            {
              "role": "button",
              "name": "Update profile"
            }
          ]
        }
      ]
    }
  ]
}
```

## HITL Integration

Browser operations integrate with Phase 4.5 HITL gates.

### Risk Classification Rules

```python
# In BrowserRiskClassifier
HITLRule(
    tools=["browser_navigate"],
    risk=RiskLevel.MEDIUM,
    conditions=[
        {"param": "url", "matches": r"^https://(mail|admin|settings)\."}
    ],
    description="Sensitive domain navigation"
)

HITLRule(
    tools=["browser_click"],
    risk=RiskLevel.HIGH,
    conditions=[
        {"param": "name", "matches": r"(?i)(delete|remove|revoke)"}
    ],
    description="Destructive button clicks"
)

HITLRule(
    tools=["browser_type"],
    risk=RiskLevel.CRITICAL,
    conditions=[
        {"param": "role", "equals": "textbox"},
        # Detect password fields via accessibility tree
        {"param": "name", "matches": r"(?i)(password|secret)"}
    ],
    description="Password field typing (auto-deny)"
)
```

### Approval Flow

```
Agent → browser_click("Delete account")
  │
  ▼
HITL Gate detects "Delete" → CRITICAL risk
  │
  ▼
Prompt user:
┌──────────────────────────────────────┐
│ CRITICAL RISK - APPROVAL REQUIRED    │
├──────────────────────────────────────┤
│ Tool: browser_click                  │
│ Action: Click "Delete account" btn   │
│ Domain: github.com                   │
│                                      │
│ This operation is IRREVERSIBLE       │
│                                      │
│ [Approve] [Deny]                     │
│ Auto-deny in 30 seconds...           │
└──────────────────────────────────────┘
  │
  ▼
User approves → Execute click
User denies → Return error to agent
Timeout → Auto-deny, log to audit trail
```

## Security Considerations

### Credential Isolation

1. **Vault Access:** Only BrowserContainerManager can read credentials
2. **No Logging:** Credentials never logged (redacted in audit trail)
3. **Memory Only:** Credentials only in browser memory, never disk
4. **Container Isolation:** Browser runs in isolated Docker container
5. **Cleanup:** Browser context destroyed after session

### Attack Surface Reduction

1. **No Raw HTML:** Agent sees accessibility tree, not HTML/JS
2. **Filtered Elements:** Password inputs excluded from snapshots
3. **HITL Gates:** Destructive actions require human approval
4. **Network Isolation:** Browser container has egress filtering
5. **Resource Limits:** CPU/memory limits prevent DoS

### Audit Trail

All browser actions logged:

```json
{
  "event_type": "browser_action",
  "correlation_id": "req-123",
  "timestamp": "2026-02-09T15:30:45Z",
  "action": "browser_navigate",
  "domain": "github.com",
  "url": "https://github.com/settings",
  "user_agent": "harombe-browser/1.0",
  "session_id": "sess-abc123",
  "hitl_decision": "auto_approved",
  "duration_ms": 1234
}
```

## Configuration

### Browser Container Config

```yaml
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
      network: "isolated" # Use Phase 4.4 network isolation

    # Pre-authentication
    credentials:
      vault_backend: "vault" # or "sops", "env"
      vault_path: "secrets/browser/"
      auto_inject: true

    # Accessibility
    snapshot:
      exclude_password_fields: true
      exclude_hidden_elements: true
      max_depth: 10

    # HITL integration
    hitl:
      enabled: true
      trusted_domains:
        - "github.com"
        - "stackoverflow.com"
      sensitive_domains:
        - "gmail.com"
        - "mail.google.com"
        - "admin.*"
```

## Implementation Phases

### Phase 1: Core Browser Manager (Days 1-2)

- [x] Design document (this file)
- [ ] BrowserContainerManager class
- [ ] Docker container lifecycle
- [ ] Playwright integration
- [ ] Session management

### Phase 2: Pre-Authentication (Day 3)

- [ ] Vault credential retrieval
- [ ] Cookie injection
- [ ] localStorage/sessionStorage injection
- [ ] Credential isolation testing

### Phase 3: Browser Tools (Day 4)

- [ ] browser_navigate tool
- [ ] browser_click tool
- [ ] browser_type tool
- [ ] browser_read tool
- [ ] browser_screenshot tool
- [ ] Accessibility snapshot generator

### Phase 4: HITL & Security (Day 5)

- [ ] Browser risk classifier
- [ ] HITL rule integration
- [ ] Audit logging
- [ ] Security testing

### Phase 5: Testing & Docs (Day 6)

- [ ] Unit tests (container manager, tools)
- [ ] Integration tests (real browser automation)
- [ ] Security tests (credential isolation)
- [ ] Usage documentation
- [ ] Update architecture docs

## References

- [MCP Gateway Design](./mcp-gateway-design.md) - Gateway architecture
- [HITL Design](./hitl-design.md) - Human-in-the-loop gates
- [Secret Management](./security-credentials.md) - Vault integration
- [Playwright API](https://playwright.dev/python/) - Browser automation
- [ARIA Specification](https://www.w3.org/TR/wai-aria/) - Accessibility roles
