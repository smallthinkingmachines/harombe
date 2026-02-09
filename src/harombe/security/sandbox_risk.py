"""
Risk classification rules for code execution sandbox tools.

Integrates with HITL gates to require approval for code execution operations.
"""

from .hitl import HITLRule, RiskLevel


def get_sandbox_hitl_rules() -> list[HITLRule]:
    """Get HITL rules for code execution sandbox tools.

    Returns:
        List of HITL rules for sandbox tools
    """
    return [
        # Code execution with network - CRITICAL
        HITLRule(
            tools=["code_execute"],
            risk=RiskLevel.CRITICAL,
            conditions=[{"param": "network_enabled", "equals": True}],
            timeout=30,
            description="Code execution with network access",
        ),
        # Dangerous code patterns - CRITICAL
        HITLRule(
            tools=["code_execute"],
            risk=RiskLevel.CRITICAL,
            conditions=[
                {
                    "param": "code",
                    "matches": r"(?i)(rm\s+-rf|curl.*\|\s*sh|wget.*\|\s*sh|eval\(|exec\(|__import__|subprocess|os\.system)",
                }
            ],
            timeout=30,
            description="Dangerous code patterns detected (rm -rf, eval, exec, subprocess)",
        ),
        # Any code execution - HIGH
        HITLRule(
            tools=["code_execute"],
            risk=RiskLevel.HIGH,
            require_approval=True,
            timeout=60,
            description="Code execution in sandbox",
        ),
        # Package installation from standard registries - HIGH
        HITLRule(
            tools=["code_install_package"],
            risk=RiskLevel.HIGH,
            conditions=[
                {"param": "registry", "matches": r"^(pypi|npm)$"},
            ],
            timeout=60,
            description="Package installation from standard registry",
        ),
        # Package installation from non-standard registry - CRITICAL
        HITLRule(
            tools=["code_install_package"],
            risk=RiskLevel.CRITICAL,
            conditions=[
                {"param": "registry", "matches": r"^(?!pypi$|npm$)"},
            ],
            timeout=30,
            description="Package installation from non-standard registry",
        ),
        # Writing executable files - HIGH
        HITLRule(
            tools=["code_write_file"],
            risk=RiskLevel.HIGH,
            conditions=[
                {"param": "file_path", "matches": r"\.(sh|py|js|exe|bin)$"},
            ],
            timeout=60,
            description="Writing executable file",
        ),
        # Writing files - MEDIUM
        HITLRule(
            tools=["code_write_file"],
            risk=RiskLevel.MEDIUM,
            timeout=120,
            description="Writing file to sandbox workspace",
        ),
        # Reading files - MEDIUM
        HITLRule(
            tools=["code_read_file"],
            risk=RiskLevel.MEDIUM,
            timeout=120,
            description="Reading file from sandbox workspace",
        ),
        # Listing files - MEDIUM
        HITLRule(
            tools=["code_list_files"],
            risk=RiskLevel.MEDIUM,
            timeout=120,
            description="Listing files in sandbox workspace",
        ),
        # Destroying sandbox - LOW (cleanup)
        HITLRule(
            tools=["code_destroy_sandbox"],
            risk=RiskLevel.LOW,
            require_approval=False,
            description="Sandbox cleanup",
        ),
    ]


def get_allowed_registries() -> dict[str, list[str]]:
    """Get allowed package registries by language.

    Returns:
        Dictionary mapping language to allowed registries
    """
    return {
        "python": ["pypi"],
        "javascript": ["npm"],
        "shell": [],  # No package installation for shell
    }
