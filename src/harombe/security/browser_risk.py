"""
Risk classification rules for browser automation tools.

Integrates with HITL gates to require approval for sensitive browser operations.
"""

from .hitl import HITLRule, RiskLevel


def get_browser_hitl_rules() -> list[HITLRule]:
    """Get HITL rules for browser automation tools.

    Returns:
        List of HITL rules for browser tools
    """
    return [
        # Navigation rules
        HITLRule(
            tools=["browser_navigate"],
            risk=RiskLevel.CRITICAL,
            conditions=[
                {
                    "param": "url",
                    "matches": r"(?i)(bank|payment|paypal|stripe|checkout|purchase)",
                }
            ],
            timeout=30,
            description="Navigation to financial/payment sites",
        ),
        HITLRule(
            tools=["browser_navigate"],
            risk=RiskLevel.HIGH,
            conditions=[
                {
                    "param": "url",
                    "matches": r"(?i)(mail|email|admin|settings|account|profile)",
                }
            ],
            timeout=60,
            description="Navigation to sensitive domains (email, admin, settings)",
        ),
        HITLRule(
            tools=["browser_navigate"],
            risk=RiskLevel.MEDIUM,
            conditions=[
                # New domain (different from current page)
                # Note: This requires runtime check in gateway
            ],
            timeout=120,
            description="Navigation to new domain",
        ),
        HITLRule(
            tools=["browser_navigate"],
            risk=RiskLevel.LOW,
            require_approval=False,
            description="Navigation within same domain (safe)",
        ),
        # Click rules
        HITLRule(
            tools=["browser_click"],
            risk=RiskLevel.CRITICAL,
            conditions=[
                {
                    "param": "name",
                    "matches": r"(?i)(delete account|close account|terminate|deactivate account|remove account)",
                }
            ],
            timeout=30,
            description="Account deletion/termination buttons",
        ),
        HITLRule(
            tools=["browser_click"],
            risk=RiskLevel.HIGH,
            conditions=[
                {
                    "param": "name",
                    "matches": r"(?i)(delete|remove|revoke|cancel|unsubscribe|disconnect|sign out)",
                }
            ],
            timeout=60,
            description="Destructive actions (delete, remove, revoke)",
        ),
        HITLRule(
            tools=["browser_click"],
            risk=RiskLevel.HIGH,
            conditions=[
                {
                    "param": "name",
                    "matches": r"(?i)(send|submit|post|publish|share|transfer|pay|purchase|buy)",
                }
            ],
            timeout=60,
            description="Communication/transaction actions (send, submit, pay)",
        ),
        HITLRule(
            tools=["browser_click"],
            risk=RiskLevel.MEDIUM,
            conditions=[
                {
                    "param": "name",
                    "matches": r"(?i)(save|update|edit|modify|change|add|create)",
                }
            ],
            timeout=120,
            description="Modification actions (save, update, create)",
        ),
        HITLRule(
            tools=["browser_click"],
            risk=RiskLevel.LOW,
            require_approval=False,
            description="Navigation clicks (safe)",
        ),
        # Type rules
        HITLRule(
            tools=["browser_type"],
            risk=RiskLevel.CRITICAL,
            conditions=[
                {
                    "param": "name",
                    "matches": r"(?i)(password|secret|token|key|api.?key)",
                }
            ],
            require_approval=False,  # Auto-deny (handled in tool)
            description="Password field typing (auto-denied)",
        ),
        HITLRule(
            tools=["browser_type"],
            risk=RiskLevel.HIGH,
            conditions=[
                {
                    "param": "name",
                    "matches": r"(?i)(credit.?card|card.?number|cvv|ssn|social.?security)",
                }
            ],
            timeout=60,
            description="Sensitive data fields (credit card, SSN)",
        ),
        HITLRule(
            tools=["browser_type"],
            risk=RiskLevel.MEDIUM,
            conditions=[
                {
                    "param": "name",
                    "matches": r"(?i)(email|address|phone|name|message|comment|note)",
                }
            ],
            timeout=120,
            description="Personal information fields",
        ),
        HITLRule(
            tools=["browser_type"],
            risk=RiskLevel.LOW,
            require_approval=False,
            description="Search and filter inputs (safe)",
        ),
        # Read rules (always low risk)
        HITLRule(
            tools=["browser_read", "browser_screenshot"],
            risk=RiskLevel.LOW,
            require_approval=False,
            description="Read-only operations",
        ),
        # Session management
        HITLRule(
            tools=["browser_close_session"],
            risk=RiskLevel.LOW,
            require_approval=False,
            description="Session cleanup",
        ),
    ]


def get_trusted_domains() -> list[str]:
    """Get list of trusted domains that don't require approval for navigation.

    Users can configure this list in their harombe.yaml:
    ```yaml
    security:
      browser:
        trusted_domains:
          - github.com
          - stackoverflow.com
          - docs.python.org
    ```

    Returns:
        List of trusted domains
    """
    # Default trusted domains (can be overridden in config)
    return [
        # Development resources
        "github.com",
        "gitlab.com",
        "stackoverflow.com",
        "stackexchange.com",
        # Documentation
        "docs.python.org",
        "developer.mozilla.org",
        "w3.org",
        # Search engines (read-only)
        "google.com",
        "duckduckgo.com",
        "bing.com",
    ]


def get_sensitive_domains() -> list[str]:
    """Get list of sensitive domains that always require approval.

    Returns:
        List of sensitive domains
    """
    return [
        # Email
        "mail.google.com",
        "gmail.com",
        "outlook.com",
        "outlook.office.com",
        # Financial
        "paypal.com",
        "stripe.com",
        "square.com",
        # Banking (wildcards)
        "*.bank",
        "*.banking",
        # Admin/settings
        "admin.*",
        "*/admin",
        "*/settings",
        "*/account",
    ]
