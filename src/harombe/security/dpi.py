"""Deep packet inspection for detecting malicious patterns and data exfiltration.

This module provides deep packet inspection (DPI) capabilities for analyzing
network traffic contents to detect secrets, malicious patterns, and potential
data exfiltration attempts.

Features:
- Secret detection in packet payloads
- Malicious pattern matching
- Data exfiltration heuristics
- Processing latency <10ms per packet
- Configurable pattern database

Example:
    >>> from harombe.security.dpi import DeepPacketInspector, NetworkPacket
    >>>
    >>> # Create inspector
    >>> inspector = DeepPacketInspector()
    >>>
    >>> # Inspect packet
    >>> packet = NetworkPacket(
    ...     source_ip="192.168.1.100",
    ...     dest_ip="203.0.113.1",
    ...     payload=b"GET /api?key=ghp_abc123... HTTP/1.1",
    ... )
    >>>
    >>> result = await inspector.inspect(packet)
    >>>
    >>> if not result.allowed:
    ...     print(f"Blocked: {result.issues}")
"""

import logging
import re
from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from harombe.security.secrets import SecretScanner

logger = logging.getLogger(__name__)


class IssueSeverity(StrEnum):
    """Severity level for security issues found in packets.

    Attributes:
        LOW: Minor issue, log but allow
        MEDIUM: Moderate issue, may require investigation
        HIGH: Serious issue, should block
        CRITICAL: Severe issue, block and alert
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IssueType(StrEnum):
    """Type of security issue detected in packet.

    Attributes:
        SECRET_LEAK: Sensitive credential detected
        MALICIOUS_PATTERN: Known malicious pattern detected
        DATA_EXFILTRATION: Potential data exfiltration attempt
        SUSPICIOUS_PAYLOAD: Unusual or suspicious payload
        ENCODING_EVASION: Encoding used to evade detection
        COMMAND_INJECTION: Command injection attempt
        SQL_INJECTION: SQL injection attempt
        XSS_ATTEMPT: Cross-site scripting attempt
    """

    SECRET_LEAK = "secret_leak"
    MALICIOUS_PATTERN = "malicious_pattern"
    DATA_EXFILTRATION = "data_exfiltration"
    SUSPICIOUS_PAYLOAD = "suspicious_payload"
    ENCODING_EVASION = "encoding_evasion"
    COMMAND_INJECTION = "command_injection"
    SQL_INJECTION = "sql_injection"
    XSS_ATTEMPT = "xss_attempt"


class SecurityIssue(BaseModel):
    """Security issue found in packet.

    Attributes:
        severity: Severity level of the issue
        type: Type of security issue
        details: Human-readable description
        evidence: Evidence from packet (truncated)
        remediation: Suggested remediation action
    """

    severity: IssueSeverity
    type: IssueType
    details: str
    evidence: str | None = None
    remediation: str | None = None


class NetworkPacket(BaseModel):
    """Network packet for inspection.

    Attributes:
        source_ip: Source IP address
        dest_ip: Destination IP address
        dest_port: Destination port
        protocol: Protocol (TCP, UDP, etc.)
        payload: Packet payload bytes
        size: Total packet size
        timestamp: When packet was captured
        metadata: Additional packet metadata
    """

    source_ip: str
    dest_ip: str
    dest_port: int | None = None
    protocol: str = "TCP"
    payload: bytes
    size: int | None = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    metadata: dict[str, Any] = Field(default_factory=dict)

    def __init__(self, **data):
        """Initialize packet and calculate size if not provided."""
        if "size" not in data and "payload" in data:
            data["size"] = len(data["payload"])
        super().__init__(**data)


class InspectionResult(BaseModel):
    """Result of deep packet inspection.

    Attributes:
        allowed: Whether packet should be allowed
        issues: List of security issues found
        duration_ms: Time taken for inspection
        secret_count: Number of secrets detected
        pattern_matches: Number of pattern matches
        exfiltration_score: Data exfiltration risk score (0-1)
    """

    allowed: bool
    issues: list[SecurityIssue] = Field(default_factory=list)
    duration_ms: float | None = None
    secret_count: int = 0
    pattern_matches: int = 0
    exfiltration_score: float = Field(default=0.0, ge=0.0, le=1.0)


class MaliciousPattern(BaseModel):
    """Malicious pattern definition.

    Attributes:
        name: Pattern name
        pattern: Regex pattern to match
        severity: Severity if matched
        issue_type: Type of issue this pattern detects
        description: Human-readable description
        enabled: Whether pattern is enabled
    """

    name: str
    pattern: re.Pattern
    severity: IssueSeverity
    issue_type: IssueType
    description: str
    enabled: bool = True

    class Config:
        arbitrary_types_allowed = True


class DeepPacketInspector:
    """Deep packet inspector for detecting security threats in network traffic.

    The inspector analyzes packet payloads for:
    - Secrets and credentials
    - Malicious patterns (SQL injection, XSS, command injection)
    - Data exfiltration indicators
    - Encoding evasion attempts

    Designed for <10ms latency per packet inspection.

    Example:
        >>> inspector = DeepPacketInspector()
        >>> packet = NetworkPacket(
        ...     source_ip="192.168.1.100",
        ...     dest_ip="203.0.113.1",
        ...     payload=b"sensitive data",
        ... )
        >>> result = await inspector.inspect(packet)
        >>> if not result.allowed:
        ...     print(f"Blocked: {result.issues[0].details}")
    """

    def __init__(
        self,
        enable_secret_scanning: bool = True,
        enable_pattern_matching: bool = True,
        enable_exfiltration_detection: bool = True,
        max_payload_size: int = 1024 * 1024,  # 1MB
    ):
        """Initialize deep packet inspector.

        Args:
            enable_secret_scanning: Whether to scan for secrets
            enable_pattern_matching: Whether to match malicious patterns
            enable_exfiltration_detection: Whether to detect exfiltration
            max_payload_size: Maximum payload size to inspect (bytes)
        """
        self.enable_secret_scanning = enable_secret_scanning
        self.enable_pattern_matching = enable_pattern_matching
        self.enable_exfiltration_detection = enable_exfiltration_detection
        self.max_payload_size = max_payload_size

        # Initialize secret scanner
        self.secret_scanner = SecretScanner() if enable_secret_scanning else None

        # Load malicious patterns
        self.patterns = self._load_malicious_patterns() if enable_pattern_matching else []

        # Statistics
        self.stats = {
            "total_inspections": 0,
            "packets_blocked": 0,
            "packets_allowed": 0,
            "secrets_detected": 0,
            "patterns_matched": 0,
            "exfiltration_detected": 0,
        }

    def _load_malicious_patterns(self) -> list[MaliciousPattern]:
        """Load malicious pattern database.

        Returns:
            List of malicious patterns to check
        """
        return [
            # SQL Injection patterns
            MaliciousPattern(
                name="sql_injection_union",
                pattern=re.compile(r"(?i)\bUNION\s+(ALL\s+)?SELECT\b"),
                severity=IssueSeverity.HIGH,
                issue_type=IssueType.SQL_INJECTION,
                description="SQL injection attempt (UNION SELECT)",
            ),
            MaliciousPattern(
                name="sql_injection_comment",
                pattern=re.compile(r"(?i)(--|#|/\*|\*/)\s*(DROP|DELETE|UPDATE|INSERT)"),
                severity=IssueSeverity.HIGH,
                issue_type=IssueType.SQL_INJECTION,
                description="SQL injection with comment evasion",
            ),
            MaliciousPattern(
                name="sql_injection_auth_bypass",
                pattern=re.compile(r"(?i)('\s*(OR|AND)\s*'?\d*\s*'?\s*=\s*'?\d*)"),
                severity=IssueSeverity.HIGH,
                issue_type=IssueType.SQL_INJECTION,
                description="SQL injection authentication bypass",
            ),
            # Command Injection patterns
            MaliciousPattern(
                name="command_injection_shell",
                pattern=re.compile(r"[;&|`$]\s*(bash|sh|curl|wget|nc|netcat)\b"),
                severity=IssueSeverity.CRITICAL,
                issue_type=IssueType.COMMAND_INJECTION,
                description="Shell command injection attempt",
            ),
            MaliciousPattern(
                name="command_injection_separator",
                pattern=re.compile(r";\s*(cat|head|tail|grep|awk|sed|ls|pwd|id|whoami)\b"),
                severity=IssueSeverity.CRITICAL,
                issue_type=IssueType.COMMAND_INJECTION,
                description="Command injection via separator",
            ),
            MaliciousPattern(
                name="command_injection_pipe",
                pattern=re.compile(r"\|\s*(cat|head|tail|grep|awk|sed)\b"),
                severity=IssueSeverity.HIGH,
                issue_type=IssueType.COMMAND_INJECTION,
                description="Command injection via pipe",
            ),
            # XSS patterns
            MaliciousPattern(
                name="xss_script_tag",
                pattern=re.compile(r"(?i)<script[^>]*>.*?</script>"),
                severity=IssueSeverity.MEDIUM,
                issue_type=IssueType.XSS_ATTEMPT,
                description="XSS attempt with script tag",
            ),
            MaliciousPattern(
                name="xss_event_handler",
                pattern=re.compile(r"(?i)on(load|error|click|mouse\w+)\s*="),
                severity=IssueSeverity.MEDIUM,
                issue_type=IssueType.XSS_ATTEMPT,
                description="XSS attempt via event handler",
            ),
            # Encoding evasion patterns
            MaliciousPattern(
                name="base64_large_blob",
                pattern=re.compile(r"(?:[A-Za-z0-9+/]{100,}={0,2})"),
                severity=IssueSeverity.LOW,
                issue_type=IssueType.ENCODING_EVASION,
                description="Large base64-encoded blob (potential evasion)",
            ),
            MaliciousPattern(
                name="hex_encoded_commands",
                pattern=re.compile(r"(?:\\x[0-9a-fA-F]{2}){10,}"),
                severity=IssueSeverity.MEDIUM,
                issue_type=IssueType.ENCODING_EVASION,
                description="Hex-encoded payload (potential evasion)",
            ),
            # Data exfiltration patterns
            MaliciousPattern(
                name="base64_exfiltration",
                pattern=re.compile(r"(?i)(data|output|result)\s*=\s*[A-Za-z0-9+/]{50,}"),
                severity=IssueSeverity.MEDIUM,
                issue_type=IssueType.DATA_EXFILTRATION,
                description="Potential data exfiltration via base64",
            ),
            MaliciousPattern(
                name="dns_tunneling",
                pattern=re.compile(r"[a-z0-9]{32,}\.[a-z0-9-]+\.[a-z]{2,}"),
                severity=IssueSeverity.HIGH,
                issue_type=IssueType.DATA_EXFILTRATION,
                description="Potential DNS tunneling",
            ),
        ]

    async def inspect(self, packet: NetworkPacket) -> InspectionResult:
        """Inspect packet for security threats.

        Args:
            packet: Network packet to inspect

        Returns:
            InspectionResult with issues found and allow/block decision
        """
        start_time = datetime.utcnow()
        self.stats["total_inspections"] += 1

        issues: list[SecurityIssue] = []

        # Check payload size
        if len(packet.payload) > self.max_payload_size:
            logger.warning(
                f"Payload too large for inspection: {len(packet.payload)} bytes "
                f"(max: {self.max_payload_size})"
            )
            # Allow but don't inspect (performance)
            self.stats["packets_allowed"] += 1
            return InspectionResult(
                allowed=True,
                issues=[],
                duration_ms=(datetime.utcnow() - start_time).total_seconds() * 1000,
            )

        # Decode payload for text-based inspection
        payload_text = self._decode_payload(packet.payload)

        # 1. Secret scanning
        secret_count = 0
        if self.enable_secret_scanning and self.secret_scanner:
            secret_issues = self._scan_for_secrets(payload_text, packet.payload)
            issues.extend(secret_issues)
            secret_count = len(secret_issues)
            self.stats["secrets_detected"] += secret_count

        # 2. Malicious pattern matching
        pattern_matches = 0
        if self.enable_pattern_matching:
            pattern_issues = self._check_malicious_patterns(payload_text)
            issues.extend(pattern_issues)
            pattern_matches = len(pattern_issues)
            self.stats["patterns_matched"] += pattern_matches

        # 3. Data exfiltration detection
        exfiltration_score = 0.0
        if self.enable_exfiltration_detection:
            exfil_issue, score = self._check_exfiltration(packet, payload_text)
            if exfil_issue:
                issues.append(exfil_issue)
                self.stats["exfiltration_detected"] += 1
            exfiltration_score = score

        # Decide allow/block based on issues
        allowed = self._should_allow(issues)

        if allowed:
            self.stats["packets_allowed"] += 1
        else:
            self.stats["packets_blocked"] += 1
            logger.warning(
                f"Blocked packet from {packet.source_ip} to {packet.dest_ip}:{packet.dest_port} "
                f"({len(issues)} issues)"
            )

        # Calculate duration
        duration_ms = (datetime.utcnow() - start_time).total_seconds() * 1000

        return InspectionResult(
            allowed=allowed,
            issues=issues,
            duration_ms=duration_ms,
            secret_count=secret_count,
            pattern_matches=pattern_matches,
            exfiltration_score=exfiltration_score,
        )

    def _decode_payload(self, payload: bytes) -> str:
        """Decode payload bytes to text for inspection.

        Args:
            payload: Raw payload bytes

        Returns:
            Decoded text (UTF-8, with errors replaced)
        """
        try:
            return payload.decode("utf-8", errors="replace")
        except Exception:
            # If decoding fails, return empty string (binary data)
            return ""

    def _scan_for_secrets(self, payload_text: str, payload_bytes: bytes) -> list[SecurityIssue]:
        """Scan payload for secrets and credentials.

        Args:
            payload_text: Decoded payload text
            payload_bytes: Raw payload bytes

        Returns:
            List of security issues for detected secrets
        """
        issues = []

        if not payload_text:
            return issues

        # Scan for secrets
        secrets = self.secret_scanner.scan(payload_text)

        for secret in secrets:
            # Truncate secret value for evidence
            evidence = secret.value[:20] + "..." if len(secret.value) > 20 else secret.value

            issues.append(
                SecurityIssue(
                    severity=IssueSeverity.CRITICAL,
                    type=IssueType.SECRET_LEAK,
                    details=f"Detected {secret.type.value} in packet payload",
                    evidence=evidence,
                    remediation="Block packet and alert security team",
                )
            )

        return issues

    def _check_malicious_patterns(self, payload_text: str) -> list[SecurityIssue]:
        """Check payload for malicious patterns.

        Args:
            payload_text: Decoded payload text

        Returns:
            List of security issues for matched patterns
        """
        issues = []

        if not payload_text:
            return issues

        for pattern_def in self.patterns:
            if not pattern_def.enabled:
                continue

            matches = pattern_def.pattern.finditer(payload_text)
            for match in matches:
                # Truncate match for evidence
                evidence = match.group(0)[:50]

                issues.append(
                    SecurityIssue(
                        severity=pattern_def.severity,
                        type=pattern_def.issue_type,
                        details=pattern_def.description,
                        evidence=evidence,
                        remediation=(
                            "Block packet and investigate source"
                            if pattern_def.severity in [IssueSeverity.HIGH, IssueSeverity.CRITICAL]
                            else "Log and monitor"
                        ),
                    )
                )

        return issues

    def _check_exfiltration(
        self, packet: NetworkPacket, payload_text: str
    ) -> tuple[SecurityIssue | None, float]:
        """Check for data exfiltration indicators.

        Args:
            packet: Network packet
            payload_text: Decoded payload text

        Returns:
            Tuple of (security issue if detected, exfiltration score 0-1)
        """
        score = 0.0
        factors = []

        # Factor 1: Large payload size (>100KB is suspicious for exfiltration)
        if packet.size and packet.size > 100 * 1024:
            score += 0.3
            factors.append(f"large payload ({packet.size} bytes)")

        # Factor 2: High data density (low entropy suggests compressed/encrypted data)
        if payload_text:
            entropy = self._calculate_entropy(payload_text)
            if entropy > 7.5:  # High entropy
                score += 0.3
                factors.append(f"high entropy ({entropy:.2f})")

        # Factor 3: Unusual destination port
        if packet.dest_port and packet.dest_port not in [80, 443, 8080, 8443]:
            score += 0.2
            factors.append(f"unusual port ({packet.dest_port})")

        # Factor 4: Multiple encoded sections
        base64_count = len(re.findall(r"[A-Za-z0-9+/]{40,}={0,2}", payload_text))
        if base64_count > 3:
            score += 0.2
            factors.append(f"multiple base64 blobs ({base64_count})")

        # Cap score at 1.0
        score = min(score, 1.0)

        # Create issue if score is high enough
        if score >= 0.7:
            return (
                SecurityIssue(
                    severity=IssueSeverity.HIGH,
                    type=IssueType.DATA_EXFILTRATION,
                    details=f"Potential data exfiltration detected (score: {score:.2f})",
                    evidence=f"Factors: {', '.join(factors)}",
                    remediation="Block packet and investigate destination",
                ),
                score,
            )

        return None, score

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text.

        Higher entropy indicates more random/compressed/encrypted data.

        Args:
            text: Text to analyze

        Returns:
            Shannon entropy (0-8 for byte data)
        """
        import math

        if not text:
            return 0.0

        # Count character frequencies
        freq = {}
        for char in text:
            freq[char] = freq.get(char, 0) + 1

        # Calculate Shannon entropy
        entropy = 0.0
        text_len = len(text)
        for count in freq.values():
            probability = count / text_len
            if probability > 0:
                entropy -= probability * math.log2(probability)

        return entropy

    def _should_allow(self, issues: list[SecurityIssue]) -> bool:
        """Decide whether to allow packet based on issues found.

        Args:
            issues: List of security issues

        Returns:
            True if packet should be allowed, False to block
        """
        if not issues:
            return True

        # Block if any critical issues
        for issue in issues:
            if issue.severity == IssueSeverity.CRITICAL:
                return False

        # Block if HIGH severity injection attacks (very dangerous)
        for issue in issues:
            if issue.severity == IssueSeverity.HIGH and issue.type in [
                IssueType.SQL_INJECTION,
                IssueType.COMMAND_INJECTION,
                IssueType.DATA_EXFILTRATION,
            ]:
                return False

        # Block if multiple high severity issues
        high_severity_count = sum(1 for issue in issues if issue.severity == IssueSeverity.HIGH)

        # Allow otherwise (log issues but don't block)
        return high_severity_count < 2

    def get_stats(self) -> dict[str, int]:
        """Get inspection statistics.

        Returns:
            Dictionary with operation counts
        """
        return self.stats.copy()

    def add_pattern(self, pattern: MaliciousPattern) -> None:
        """Add custom malicious pattern.

        Args:
            pattern: Malicious pattern to add
        """
        self.patterns.append(pattern)
        logger.info(f"Added malicious pattern: {pattern.name}")

    def remove_pattern(self, name: str) -> bool:
        """Remove malicious pattern by name.

        Args:
            name: Pattern name to remove

        Returns:
            True if pattern was removed, False if not found
        """
        initial_count = len(self.patterns)
        self.patterns = [p for p in self.patterns if p.name != name]
        removed = len(self.patterns) < initial_count

        if removed:
            logger.info(f"Removed malicious pattern: {name}")

        return removed

    def get_patterns(self) -> list[MaliciousPattern]:
        """Get all malicious patterns.

        Returns:
            List of malicious patterns
        """
        return self.patterns.copy()
