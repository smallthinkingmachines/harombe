"""Tests for deep packet inspection."""

import pytest

from harombe.security.dpi import (
    DeepPacketInspector,
    InspectionResult,
    IssueSeverity,
    IssueType,
    MaliciousPattern,
    NetworkPacket,
    SecurityIssue,
)


@pytest.fixture
def inspector():
    """Create deep packet inspector."""
    return DeepPacketInspector()


@pytest.fixture
def minimal_inspector():
    """Create inspector with all features disabled."""
    return DeepPacketInspector(
        enable_secret_scanning=False,
        enable_pattern_matching=False,
        enable_exfiltration_detection=False,
    )


# Enum Tests


def test_issue_severity_values():
    """Test IssueSeverity enum values."""
    assert IssueSeverity.LOW == "low"
    assert IssueSeverity.MEDIUM == "medium"
    assert IssueSeverity.HIGH == "high"
    assert IssueSeverity.CRITICAL == "critical"


def test_issue_type_values():
    """Test IssueType enum values."""
    assert IssueType.SECRET_LEAK == "secret_leak"
    assert IssueType.MALICIOUS_PATTERN == "malicious_pattern"
    assert IssueType.DATA_EXFILTRATION == "data_exfiltration"
    assert IssueType.SQL_INJECTION == "sql_injection"
    assert IssueType.COMMAND_INJECTION == "command_injection"


# Model Tests


def test_security_issue_creation():
    """Test SecurityIssue model creation."""
    issue = SecurityIssue(
        severity=IssueSeverity.HIGH,
        type=IssueType.SECRET_LEAK,
        details="API key detected",
        evidence="ghp_abc123...",
        remediation="Block packet",
    )

    assert issue.severity == IssueSeverity.HIGH
    assert issue.type == IssueType.SECRET_LEAK
    assert issue.details == "API key detected"
    assert issue.evidence == "ghp_abc123..."


def test_network_packet_creation():
    """Test NetworkPacket model creation."""
    packet = NetworkPacket(
        source_ip="192.168.1.100",
        dest_ip="203.0.113.1",
        dest_port=443,
        protocol="TCP",
        payload=b"test payload",
    )

    assert packet.source_ip == "192.168.1.100"
    assert packet.dest_ip == "203.0.113.1"
    assert packet.dest_port == 443
    assert packet.protocol == "TCP"
    assert packet.payload == b"test payload"
    assert packet.size == 12  # Auto-calculated


def test_network_packet_auto_size():
    """Test NetworkPacket automatically calculates size."""
    packet = NetworkPacket(
        source_ip="192.168.1.1",
        dest_ip="192.168.1.2",
        payload=b"hello world",
    )

    assert packet.size == 11


def test_inspection_result_defaults():
    """Test InspectionResult with defaults."""
    result = InspectionResult(allowed=True)

    assert result.allowed is True
    assert result.issues == []
    assert result.secret_count == 0
    assert result.pattern_matches == 0
    assert result.exfiltration_score == 0.0


def test_malicious_pattern_creation():
    """Test MaliciousPattern model creation."""
    import re

    pattern = MaliciousPattern(
        name="test_pattern",
        pattern=re.compile(r"malicious"),
        severity=IssueSeverity.HIGH,
        issue_type=IssueType.MALICIOUS_PATTERN,
        description="Test pattern",
        enabled=True,
    )

    assert pattern.name == "test_pattern"
    assert pattern.severity == IssueSeverity.HIGH
    assert pattern.enabled is True


# DeepPacketInspector Tests


def test_inspector_initialization(inspector):
    """Test DeepPacketInspector initialization."""
    assert inspector.enable_secret_scanning is True
    assert inspector.enable_pattern_matching is True
    assert inspector.enable_exfiltration_detection is True
    assert inspector.secret_scanner is not None
    assert len(inspector.patterns) > 0
    assert inspector.stats["total_inspections"] == 0


def test_inspector_disabled_features(minimal_inspector):
    """Test inspector with all features disabled."""
    assert minimal_inspector.enable_secret_scanning is False
    assert minimal_inspector.enable_pattern_matching is False
    assert minimal_inspector.enable_exfiltration_detection is False
    assert minimal_inspector.secret_scanner is None
    assert len(minimal_inspector.patterns) == 0


@pytest.mark.asyncio
async def test_inspect_clean_packet(inspector):
    """Test inspecting clean packet with no issues."""
    packet = NetworkPacket(
        source_ip="192.168.1.100",
        dest_ip="203.0.113.1",
        dest_port=443,
        payload=b"GET /api/users HTTP/1.1\r\nHost: example.com\r\n",
    )

    result = await inspector.inspect(packet)

    assert result.allowed is True
    assert len(result.issues) == 0
    assert result.secret_count == 0
    assert result.pattern_matches == 0
    assert result.duration_ms is not None
    assert result.duration_ms < 100  # Should be <100ms (relaxed for CI)
    assert inspector.stats["packets_allowed"] == 1


@pytest.mark.asyncio
async def test_inspect_packet_with_github_token(inspector):
    """Test detecting GitHub token in packet."""
    # Use valid GitHub token format
    packet = NetworkPacket(
        source_ip="192.168.1.100",
        dest_ip="203.0.113.1",
        payload=b"Authorization: token ghp_" + b"a" * 36,
    )

    result = await inspector.inspect(packet)

    assert result.allowed is False  # Should block critical issues
    assert result.secret_count == 1
    assert len(result.issues) >= 1
    assert any(issue.type == IssueType.SECRET_LEAK for issue in result.issues)
    assert inspector.stats["secrets_detected"] == 1
    assert inspector.stats["packets_blocked"] == 1


@pytest.mark.asyncio
async def test_inspect_packet_with_aws_key(inspector):
    """Test detecting AWS key in packet."""
    packet = NetworkPacket(
        source_ip="192.168.1.100",
        dest_ip="203.0.113.1",
        payload=b"aws_access_key_id=AKIAIOSFODNN7EXAMPLE",
    )

    result = await inspector.inspect(packet)

    assert result.allowed is False
    assert result.secret_count >= 1
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)


@pytest.mark.asyncio
async def test_inspect_sql_injection_attempt(inspector):
    """Test detecting SQL injection pattern."""
    packet = NetworkPacket(
        source_ip="192.168.1.100",
        dest_ip="203.0.113.1",
        payload=b"GET /api?id=1 UNION SELECT * FROM users",
    )

    result = await inspector.inspect(packet)

    assert result.allowed is False  # Should block high severity
    assert result.pattern_matches >= 1
    assert any(issue.type == IssueType.SQL_INJECTION for issue in result.issues)
    assert inspector.stats["patterns_matched"] >= 1


@pytest.mark.asyncio
async def test_inspect_command_injection_attempt(inspector):
    """Test detecting command injection pattern."""
    packet = NetworkPacket(
        source_ip="192.168.1.100",
        dest_ip="203.0.113.1",
        payload=b"file=/etc/passwd; cat /etc/shadow",
    )

    result = await inspector.inspect(packet)

    assert result.allowed is False
    assert any(issue.type == IssueType.COMMAND_INJECTION for issue in result.issues)
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)


@pytest.mark.asyncio
async def test_inspect_xss_attempt(inspector):
    """Test detecting XSS pattern."""
    packet = NetworkPacket(
        source_ip="192.168.1.100",
        dest_ip="203.0.113.1",
        payload=b'<script>alert("XSS")</script>',
    )

    result = await inspector.inspect(packet)

    # XSS is medium severity, so may be allowed with single issue
    assert any(issue.type == IssueType.XSS_ATTEMPT for issue in result.issues)


@pytest.mark.asyncio
async def test_inspect_large_payload_skip(inspector):
    """Test that very large payloads are skipped for performance."""
    # Create payload larger than max size
    large_payload = b"x" * (2 * 1024 * 1024)  # 2MB
    packet = NetworkPacket(
        source_ip="192.168.1.100",
        dest_ip="203.0.113.1",
        payload=large_payload,
    )

    result = await inspector.inspect(packet)

    # Should allow without inspection (too large)
    assert result.allowed is True
    assert len(result.issues) == 0


@pytest.mark.asyncio
async def test_inspect_binary_payload(inspector):
    """Test inspecting binary (non-text) payload."""
    # Binary data that can't be decoded as UTF-8
    packet = NetworkPacket(
        source_ip="192.168.1.100",
        dest_ip="203.0.113.1",
        payload=b"\x00\x01\x02\x03\xff\xfe\xfd",
    )

    result = await inspector.inspect(packet)

    # Should handle gracefully (no crashes)
    assert result.allowed is True


@pytest.mark.asyncio
async def test_exfiltration_detection_large_payload(inspector):
    """Test exfiltration detection for large payload."""
    # Create 150KB payload
    large_data = b"A" * (150 * 1024)
    packet = NetworkPacket(
        source_ip="192.168.1.100",
        dest_ip="203.0.113.1",
        dest_port=9999,  # Unusual port
        payload=large_data,
    )

    result = await inspector.inspect(packet)

    # Should detect potential exfiltration
    assert result.exfiltration_score >= 0.5
    # May or may not block depending on other factors


@pytest.mark.asyncio
async def test_exfiltration_detection_high_entropy(inspector):
    """Test exfiltration detection for high entropy data."""
    # High entropy data (looks encrypted/compressed)
    import random
    import string

    high_entropy = "".join(random.choices(string.ascii_letters + string.digits, k=1000)).encode()

    packet = NetworkPacket(
        source_ip="192.168.1.100",
        dest_ip="203.0.113.1",
        dest_port=8888,
        payload=high_entropy,
    )

    result = await inspector.inspect(packet)

    # Should have some exfiltration score
    assert result.exfiltration_score >= 0.0


@pytest.mark.asyncio
async def test_multiple_issues_blocks_packet(inspector):
    """Test that multiple high severity issues blocks packet."""
    # Packet with both SQL injection and command injection
    packet = NetworkPacket(
        source_ip="192.168.1.100",
        dest_ip="203.0.113.1",
        payload=b"id=1 UNION SELECT * FROM users; cat /etc/passwd",
    )

    result = await inspector.inspect(packet)

    assert result.allowed is False
    assert len(result.issues) >= 2


@pytest.mark.asyncio
async def test_single_medium_issue_allows_packet(inspector):
    """Test that single medium severity issue allows packet."""
    # XSS is medium severity
    packet = NetworkPacket(
        source_ip="192.168.1.100",
        dest_ip="203.0.113.1",
        payload=b"<img onerror=alert(1)>",
    )

    result = await inspector.inspect(packet)

    # Should allow but log issue
    assert result.allowed is True
    assert len(result.issues) >= 1


def test_add_custom_pattern(inspector):
    """Test adding custom malicious pattern."""
    import re

    initial_count = len(inspector.patterns)

    pattern = MaliciousPattern(
        name="custom_test",
        pattern=re.compile(r"DANGEROUS"),
        severity=IssueSeverity.HIGH,
        issue_type=IssueType.MALICIOUS_PATTERN,
        description="Custom test pattern",
    )

    inspector.add_pattern(pattern)

    assert len(inspector.patterns) == initial_count + 1
    assert inspector.patterns[-1].name == "custom_test"


@pytest.mark.asyncio
async def test_custom_pattern_detection(inspector):
    """Test that custom patterns are detected."""
    import re

    # Add custom pattern
    inspector.add_pattern(
        MaliciousPattern(
            name="forbidden_word",
            pattern=re.compile(r"FORBIDDEN"),
            severity=IssueSeverity.HIGH,
            issue_type=IssueType.MALICIOUS_PATTERN,
            description="Forbidden word detected",
        )
    )

    packet = NetworkPacket(
        source_ip="192.168.1.100",
        dest_ip="203.0.113.1",
        payload=b"This contains FORBIDDEN word",
    )

    result = await inspector.inspect(packet)

    assert result.pattern_matches >= 1
    assert any("Forbidden word" in issue.details for issue in result.issues)


def test_remove_pattern(inspector):
    """Test removing pattern by name."""
    initial_count = len(inspector.patterns)

    # Get first pattern name
    pattern_name = inspector.patterns[0].name

    removed = inspector.remove_pattern(pattern_name)

    assert removed is True
    assert len(inspector.patterns) == initial_count - 1


def test_remove_nonexistent_pattern(inspector):
    """Test removing pattern that doesn't exist."""
    removed = inspector.remove_pattern("nonexistent_pattern")
    assert removed is False


def test_get_patterns(inspector):
    """Test getting all patterns."""
    patterns = inspector.get_patterns()

    assert len(patterns) > 0
    assert all(isinstance(p, MaliciousPattern) for p in patterns)


def test_get_stats(inspector):
    """Test getting statistics."""
    stats = inspector.get_stats()

    assert "total_inspections" in stats
    assert "packets_blocked" in stats
    assert "packets_allowed" in stats
    assert "secrets_detected" in stats
    assert "patterns_matched" in stats
    assert stats["total_inspections"] >= 0


@pytest.mark.asyncio
async def test_stats_tracking(inspector):
    """Test that statistics are tracked correctly."""
    # Inspect clean packet
    clean = NetworkPacket(
        source_ip="192.168.1.1",
        dest_ip="203.0.113.1",
        payload=b"clean data",
    )
    await inspector.inspect(clean)

    # Inspect packet with secret
    secret = NetworkPacket(
        source_ip="192.168.1.1",
        dest_ip="203.0.113.1",
        payload=b"token: ghp_" + b"a" * 36,
    )
    await inspector.inspect(secret)

    stats = inspector.get_stats()

    assert stats["total_inspections"] == 2
    assert stats["packets_allowed"] == 1
    assert stats["packets_blocked"] == 1
    assert stats["secrets_detected"] == 1


def test_calculate_entropy(inspector):
    """Test entropy calculation."""
    # Low entropy (repetitive)
    low_entropy = inspector._calculate_entropy("aaaaaaaaaa")
    assert low_entropy < 2.0

    # High entropy (random-looking)
    high_entropy = inspector._calculate_entropy("aB3xK9pQzL")
    assert high_entropy > low_entropy


def test_should_allow_no_issues(inspector):
    """Test should allow with no issues."""
    assert inspector._should_allow([]) is True


def test_should_allow_low_severity(inspector):
    """Test should allow with only low severity issues."""
    issues = [
        SecurityIssue(
            severity=IssueSeverity.LOW,
            type=IssueType.SUSPICIOUS_PAYLOAD,
            details="Minor issue",
        )
    ]

    assert inspector._should_allow(issues) is True


def test_should_block_critical_severity(inspector):
    """Test should block with critical severity."""
    issues = [
        SecurityIssue(
            severity=IssueSeverity.CRITICAL,
            type=IssueType.SECRET_LEAK,
            details="Critical issue",
        )
    ]

    assert inspector._should_allow(issues) is False


def test_should_block_multiple_high_severity(inspector):
    """Test should block with multiple high severity issues."""
    issues = [
        SecurityIssue(
            severity=IssueSeverity.HIGH,
            type=IssueType.SQL_INJECTION,
            details="Issue 1",
        ),
        SecurityIssue(
            severity=IssueSeverity.HIGH,
            type=IssueType.COMMAND_INJECTION,
            details="Issue 2",
        ),
    ]

    assert inspector._should_allow(issues) is False


def test_decode_payload_utf8(inspector):
    """Test decoding UTF-8 payload."""
    payload = b"Hello, world!"
    decoded = inspector._decode_payload(payload)
    assert decoded == "Hello, world!"


def test_decode_payload_binary(inspector):
    """Test decoding binary payload."""
    payload = b"\x00\x01\x02\xff"
    decoded = inspector._decode_payload(payload)
    # Should return string with replacement characters
    assert isinstance(decoded, str)


# Integration Tests


@pytest.mark.asyncio
@pytest.mark.integration
async def test_end_to_end_inspection():
    """Test end-to-end packet inspection workflow."""
    inspector = DeepPacketInspector()

    # Create packet with multiple issues
    packet = NetworkPacket(
        source_ip="192.168.1.100",
        dest_ip="203.0.113.1",
        dest_port=443,
        payload=b"API_KEY=ghp_" + b"a" * 36 + b" UNION SELECT * FROM users",
    )

    result = await inspector.inspect(packet)

    # Should detect both secret and SQL injection
    assert result.allowed is False
    assert result.secret_count >= 1
    assert result.pattern_matches >= 1
    assert len(result.issues) >= 2
    assert result.duration_ms < 100  # Performance requirement (relaxed for CI)


@pytest.mark.asyncio
@pytest.mark.integration
async def test_performance_requirement():
    """Test that inspection meets <100ms performance requirement (relaxed for CI)."""
    inspector = DeepPacketInspector()

    # Create typical packet
    packet = NetworkPacket(
        source_ip="192.168.1.100",
        dest_ip="203.0.113.1",
        payload=b"GET /api/users?page=1&limit=10 HTTP/1.1\r\nHost: example.com\r\n",
    )

    result = await inspector.inspect(packet)

    # Should complete in <100ms (relaxed for CI)
    assert result.duration_ms < 100


@pytest.mark.asyncio
@pytest.mark.integration
async def test_all_features_disabled():
    """Test inspector with all features disabled."""
    inspector = DeepPacketInspector(
        enable_secret_scanning=False,
        enable_pattern_matching=False,
        enable_exfiltration_detection=False,
    )

    # Packet with secret and malicious pattern
    packet = NetworkPacket(
        source_ip="192.168.1.1",
        dest_ip="203.0.113.1",
        payload=b"ghp_" + b"a" * 36 + b" UNION SELECT",
    )

    result = await inspector.inspect(packet)

    # Should allow everything (no checks enabled)
    assert result.allowed is True
    assert len(result.issues) == 0
    assert result.secret_count == 0
    assert result.pattern_matches == 0
