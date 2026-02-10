"""Protocol-aware network filtering for detecting protocol violations and abuse.

This module provides protocol-level filtering to ensure only allowed protocols
and well-formed traffic passes through the network security layer.

Features:
- Protocol detection from packet payload
- Allowed protocol enforcement (HTTP/HTTPS only by default)
- HTTP method validation
- HTTP header validation
- Suspicious request pattern detection
- WebSocket upgrade detection
- Processing latency <1ms per packet

Example:
    >>> from harombe.security.protocol_filter import ProtocolFilter, ProtocolPolicy
    >>>
    >>> # Create filter with default policy (HTTP/HTTPS only)
    >>> pf = ProtocolFilter()
    >>>
    >>> # Filter a packet
    >>> from harombe.security.dpi import NetworkPacket
    >>> packet = NetworkPacket(
    ...     source_ip="192.168.1.100",
    ...     dest_ip="203.0.113.1",
    ...     dest_port=443,
    ...     payload=b"GET /api/v1/data HTTP/1.1\\r\\nHost: api.example.com\\r\\n\\r\\n",
    ... )
    >>>
    >>> result = pf.filter(packet)
    >>> if not result.allowed:
    ...     print(f"Blocked: {result.reason}")
"""

import logging
import re
import time
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from harombe.security.dpi import NetworkPacket

logger = logging.getLogger(__name__)


class Protocol(StrEnum):
    """Network protocol identifiers.

    Attributes:
        HTTP: Hypertext Transfer Protocol
        HTTPS: HTTP over TLS
        DNS: Domain Name System
        WEBSOCKET: WebSocket protocol
        FTP: File Transfer Protocol
        SSH: Secure Shell
        SMTP: Simple Mail Transfer Protocol
        UNKNOWN: Unrecognized protocol
    """

    HTTP = "http"
    HTTPS = "https"
    DNS = "dns"
    WEBSOCKET = "websocket"
    FTP = "ftp"
    SSH = "ssh"
    SMTP = "smtp"
    UNKNOWN = "unknown"


# Port-to-protocol mapping for common services
_PORT_PROTOCOL_MAP: dict[int, Protocol] = {
    80: Protocol.HTTP,
    443: Protocol.HTTPS,
    8080: Protocol.HTTP,
    8443: Protocol.HTTPS,
    53: Protocol.DNS,
    21: Protocol.FTP,
    22: Protocol.SSH,
    25: Protocol.SMTP,
    587: Protocol.SMTP,
    465: Protocol.SMTP,
}

# Valid HTTP methods per RFC 7231 / RFC 5789
_VALID_HTTP_METHODS = frozenset(
    {
        "GET",
        "HEAD",
        "POST",
        "PUT",
        "DELETE",
        "PATCH",
        "OPTIONS",
        "TRACE",
        "CONNECT",
    }
)

# HTTP methods allowed by default (TRACE and CONNECT are risky)
_DEFAULT_ALLOWED_METHODS = frozenset(
    {
        "GET",
        "HEAD",
        "POST",
        "PUT",
        "DELETE",
        "PATCH",
        "OPTIONS",
    }
)

# Required HTTP headers
_REQUIRED_HEADERS = frozenset({"host"})

# Headers that should never appear in outbound requests
_FORBIDDEN_HEADERS = frozenset(
    {
        "x-forwarded-for",
        "x-real-ip",
        "x-originating-ip",
    }
)

# Regex for HTTP request line
_HTTP_REQUEST_LINE = re.compile(
    r"^(GET|HEAD|POST|PUT|DELETE|PATCH|OPTIONS|TRACE|CONNECT)\s+\S+\s+HTTP/\d\.\d\r?\n",
    re.IGNORECASE,
)

# Regex for HTTP response status line
_HTTP_RESPONSE_LINE = re.compile(
    r"^HTTP/\d\.\d\s+\d{3}\s+",
    re.IGNORECASE,
)

# SSH banner pattern
_SSH_BANNER = re.compile(r"^SSH-\d+\.\d+-")

# FTP greeting pattern
_FTP_GREETING = re.compile(r"^220[ -]")

# SMTP greeting pattern
_SMTP_GREETING = re.compile(r"^(220|EHLO|HELO)\s", re.IGNORECASE)

# Suspicious HTTP patterns
_SUSPICIOUS_HTTP_PATTERNS = [
    (re.compile(r"\.\.(/|\\)"), "Path traversal attempt"),
    (re.compile(r"%2e%2e[/\\%]", re.IGNORECASE), "Encoded path traversal"),
    (re.compile(r"CONNECT\s+\S+:\d+\s+HTTP", re.IGNORECASE), "HTTP CONNECT tunnel"),
    (
        re.compile(r"Proxy-Authorization:", re.IGNORECASE),
        "Proxy auth header (potential proxy abuse)",
    ),
    (
        re.compile(r"Transfer-Encoding:\s*chunked.*Transfer-Encoding:", re.IGNORECASE | re.DOTALL),
        "HTTP request smuggling (duplicate TE)",
    ),
    (
        re.compile(r"Content-Length:.*Content-Length:", re.IGNORECASE | re.DOTALL),
        "HTTP request smuggling (duplicate CL)",
    ),
]


class ProtocolPolicy(BaseModel):
    """Protocol filtering policy.

    Attributes:
        allowed_protocols: Protocols that are permitted
        allowed_http_methods: HTTP methods that are permitted
        require_host_header: Whether HTTP Host header is required
        block_forbidden_headers: Whether to block requests with forbidden headers
        detect_smuggling: Whether to detect HTTP request smuggling
        max_header_size: Maximum total header size in bytes
        max_url_length: Maximum URL length in characters
    """

    allowed_protocols: list[Protocol] = Field(
        default_factory=lambda: [Protocol.HTTP, Protocol.HTTPS, Protocol.DNS],
        description="Protocols that are permitted through the filter",
    )
    allowed_http_methods: list[str] = Field(
        default_factory=lambda: list(_DEFAULT_ALLOWED_METHODS),
        description="HTTP methods that are permitted",
    )
    require_host_header: bool = Field(
        default=True,
        description="Require Host header in HTTP requests",
    )
    block_forbidden_headers: bool = Field(
        default=True,
        description="Block requests containing forbidden headers",
    )
    detect_smuggling: bool = Field(
        default=True,
        description="Detect HTTP request smuggling attempts",
    )
    max_header_size: int = Field(
        default=8192,
        description="Maximum total header size in bytes",
    )
    max_url_length: int = Field(
        default=2048,
        description="Maximum URL length in characters",
    )


class FilterResult(BaseModel):
    """Result of protocol filtering.

    Attributes:
        allowed: Whether the packet is allowed
        reason: Human-readable reason for the decision
        protocol: Detected protocol
        details: Additional details about the filtering decision
        duration_ms: Time taken for filtering
    """

    allowed: bool
    reason: str
    protocol: Protocol = Protocol.UNKNOWN
    details: dict[str, Any] = Field(default_factory=dict)
    duration_ms: float | None = None


class HTTPRequest(BaseModel):
    """Parsed HTTP request for validation.

    Attributes:
        method: HTTP method (GET, POST, etc.)
        url: Request URL/path
        version: HTTP version string
        headers: Request headers (lowercase keys)
        header_size: Total size of headers in bytes
        is_websocket_upgrade: Whether this is a WebSocket upgrade request
    """

    method: str
    url: str
    version: str
    headers: dict[str, str] = Field(default_factory=dict)
    header_size: int = 0
    is_websocket_upgrade: bool = False


class HTTPValidator:
    """Validate HTTP/HTTPS request structure and content.

    Checks:
    - HTTP method is allowed
    - Required headers are present
    - No forbidden headers
    - No request smuggling indicators
    - No suspicious URL patterns
    - Header size limits
    """

    def __init__(self, policy: ProtocolPolicy):
        """Initialize HTTP validator.

        Args:
            policy: Protocol policy to enforce
        """
        self.policy = policy
        self._allowed_methods = frozenset(m.upper() for m in policy.allowed_http_methods)

    def parse_request(self, payload_text: str) -> HTTPRequest | None:
        """Parse HTTP request from payload text.

        Args:
            payload_text: Decoded payload text

        Returns:
            Parsed HTTPRequest or None if not a valid HTTP request
        """
        lines = payload_text.split("\n")
        if not lines:
            return None

        # Parse request line
        request_line = lines[0].rstrip("\r")
        parts = request_line.split(" ", 2)
        if len(parts) < 3:
            return None

        method, url, version = parts

        if method.upper() not in _VALID_HTTP_METHODS:
            return None

        if not version.upper().startswith("HTTP/"):
            return None

        # Parse headers
        headers: dict[str, str] = {}
        header_size = 0
        for line in lines[1:]:
            line = line.rstrip("\r")
            if not line:
                break
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.strip().lower()] = value.strip()
                header_size += len(line)

        # Check for WebSocket upgrade
        is_ws = (
            headers.get("upgrade", "").lower() == "websocket"
            and headers.get("connection", "").lower() == "upgrade"
        )

        return HTTPRequest(
            method=method.upper(),
            url=url,
            version=version,
            headers=headers,
            header_size=header_size,
            is_websocket_upgrade=is_ws,
        )

    def validate(self, request: HTTPRequest) -> FilterResult:
        """Validate HTTP request against policy.

        Args:
            request: Parsed HTTP request

        Returns:
            FilterResult with validation outcome
        """
        # Check HTTP method
        if request.method not in self._allowed_methods:
            return FilterResult(
                allowed=False,
                reason=f"HTTP method {request.method} not allowed",
                protocol=Protocol.HTTP,
                details={"method": request.method, "allowed": list(self._allowed_methods)},
            )

        # Check URL length
        if len(request.url) > self.policy.max_url_length:
            return FilterResult(
                allowed=False,
                reason=f"URL too long ({len(request.url)} > {self.policy.max_url_length})",
                protocol=Protocol.HTTP,
                details={"url_length": len(request.url)},
            )

        # Check required headers
        if self.policy.require_host_header:
            for header in _REQUIRED_HEADERS:
                if header not in request.headers:
                    return FilterResult(
                        allowed=False,
                        reason=f"Missing required header: {header}",
                        protocol=Protocol.HTTP,
                        details={"missing_header": header},
                    )

        # Check forbidden headers
        if self.policy.block_forbidden_headers:
            for header in _FORBIDDEN_HEADERS:
                if header in request.headers:
                    return FilterResult(
                        allowed=False,
                        reason=f"Forbidden header present: {header}",
                        protocol=Protocol.HTTP,
                        details={"forbidden_header": header},
                    )

        # Check header size
        if request.header_size > self.policy.max_header_size:
            return FilterResult(
                allowed=False,
                reason=f"Header size exceeds limit ({request.header_size} > {self.policy.max_header_size})",
                protocol=Protocol.HTTP,
                details={"header_size": request.header_size},
            )

        # Check for suspicious patterns in URL
        for pattern, description in _SUSPICIOUS_HTTP_PATTERNS:
            combined = f"{request.method} {request.url} {request.version}\r\n"
            for key, value in request.headers.items():
                combined += f"{key}: {value}\r\n"
            if pattern.search(combined):
                return FilterResult(
                    allowed=False,
                    reason=f"Suspicious HTTP pattern: {description}",
                    protocol=Protocol.HTTP,
                    details={"pattern": description},
                )

        return FilterResult(
            allowed=True,
            reason="HTTP request valid",
            protocol=Protocol.HTTP,
            details={
                "method": request.method,
                "url": request.url[:100],
                "is_websocket": request.is_websocket_upgrade,
            },
        )


class ProtocolFilter:
    """Protocol-aware network traffic filter.

    Detects the protocol in use and enforces protocol-level policies.
    Only permits allowed protocols with well-formed traffic.

    Example:
        >>> pf = ProtocolFilter()
        >>> packet = NetworkPacket(
        ...     source_ip="10.0.0.1",
        ...     dest_ip="203.0.113.1",
        ...     dest_port=443,
        ...     payload=b"GET / HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n",
        ... )
        >>> result = pf.filter(packet)
        >>> print(result.allowed)
        True
    """

    def __init__(self, policy: ProtocolPolicy | None = None):
        """Initialize protocol filter.

        Args:
            policy: Protocol policy to enforce (uses defaults if None)
        """
        self.policy = policy or ProtocolPolicy()
        self.http_validator = HTTPValidator(self.policy)
        self.stats: dict[str, int] = {
            "total_filtered": 0,
            "allowed": 0,
            "blocked": 0,
            "http_requests": 0,
            "protocol_violations": 0,
            "smuggling_attempts": 0,
        }

    def detect_protocol(self, packet: NetworkPacket) -> Protocol:
        """Detect the protocol from a network packet.

        Uses a combination of port mapping and payload inspection.

        Args:
            packet: Network packet to inspect

        Returns:
            Detected protocol
        """
        # Try payload-based detection first (more reliable)
        if packet.payload:
            payload_text = self._decode_payload(packet.payload)

            if payload_text:
                # Check for HTTP request
                if _HTTP_REQUEST_LINE.match(payload_text):
                    if packet.dest_port in (443, 8443):
                        return Protocol.HTTPS
                    return Protocol.HTTP

                # Check for HTTP response
                if _HTTP_RESPONSE_LINE.match(payload_text):
                    if packet.dest_port in (443, 8443):
                        return Protocol.HTTPS
                    return Protocol.HTTP

                # Check for SSH
                if _SSH_BANNER.match(payload_text):
                    return Protocol.SSH

                # Check for SMTP (before FTP since both use 220 greeting)
                # Use port hint to disambiguate when possible
                if _SMTP_GREETING.match(payload_text):
                    if packet.dest_port in (25, 587, 465):
                        return Protocol.SMTP
                    if _FTP_GREETING.match(payload_text) and packet.dest_port == 21:
                        return Protocol.FTP
                    return Protocol.SMTP

                # Check for FTP
                if _FTP_GREETING.match(payload_text):
                    return Protocol.FTP

        # Fall back to port-based detection
        if packet.dest_port is not None:
            protocol = _PORT_PROTOCOL_MAP.get(packet.dest_port)
            if protocol is not None:
                return protocol

        return Protocol.UNKNOWN

    def filter(self, packet: NetworkPacket) -> FilterResult:
        """Filter packet based on protocol policy.

        Args:
            packet: Network packet to filter

        Returns:
            FilterResult with allow/block decision
        """
        start = time.perf_counter()
        self.stats["total_filtered"] += 1

        # Detect protocol
        protocol = self.detect_protocol(packet)

        # Check if protocol is allowed
        if protocol == Protocol.UNKNOWN:
            # Unknown protocols are blocked unless the packet has no payload
            # (could be a SYN or other control packet)
            if packet.payload:
                self.stats["blocked"] += 1
                self.stats["protocol_violations"] += 1
                duration_ms = (time.perf_counter() - start) * 1000
                logger.warning(
                    f"Blocked unknown protocol: {packet.source_ip} -> "
                    f"{packet.dest_ip}:{packet.dest_port}"
                )
                return FilterResult(
                    allowed=False,
                    reason="Unknown protocol not allowed",
                    protocol=Protocol.UNKNOWN,
                    duration_ms=duration_ms,
                )
            # Allow empty-payload packets (connection setup)
            self.stats["allowed"] += 1
            duration_ms = (time.perf_counter() - start) * 1000
            return FilterResult(
                allowed=True,
                reason="Empty payload (connection setup)",
                protocol=Protocol.UNKNOWN,
                duration_ms=duration_ms,
            )

        if protocol not in self.policy.allowed_protocols:
            self.stats["blocked"] += 1
            self.stats["protocol_violations"] += 1
            duration_ms = (time.perf_counter() - start) * 1000
            logger.warning(
                f"Blocked disallowed protocol {protocol.value}: "
                f"{packet.source_ip} -> {packet.dest_ip}:{packet.dest_port}"
            )
            return FilterResult(
                allowed=False,
                reason=f"Protocol {protocol.value} not allowed",
                protocol=protocol,
                duration_ms=duration_ms,
            )

        # Protocol-specific validation
        if protocol in (Protocol.HTTP, Protocol.HTTPS):
            result = self._validate_http(packet, protocol)
            if result is not None:
                result.duration_ms = (time.perf_counter() - start) * 1000
                if result.allowed:
                    self.stats["allowed"] += 1
                else:
                    self.stats["blocked"] += 1
                return result

        # Allowed protocol with no further validation needed
        self.stats["allowed"] += 1
        duration_ms = (time.perf_counter() - start) * 1000
        return FilterResult(
            allowed=True,
            reason=f"Protocol {protocol.value} allowed",
            protocol=protocol,
            duration_ms=duration_ms,
        )

    def _validate_http(self, packet: NetworkPacket, protocol: Protocol) -> FilterResult | None:
        """Validate HTTP/HTTPS packet content.

        Args:
            packet: Network packet with HTTP payload
            protocol: Detected protocol (HTTP or HTTPS)

        Returns:
            FilterResult if validation produces a decision, None to fall through
        """
        self.stats["http_requests"] += 1

        payload_text = self._decode_payload(packet.payload)
        if not payload_text:
            return None

        # Parse HTTP request
        request = self.http_validator.parse_request(payload_text)
        if request is None:
            # Could not parse as HTTP - might be a TLS handshake or binary data
            return None

        # Check for request smuggling
        if self.policy.detect_smuggling:
            smuggling = self._check_smuggling(payload_text)
            if smuggling is not None:
                self.stats["smuggling_attempts"] += 1
                smuggling.protocol = protocol
                return smuggling

        # Validate the parsed request
        result = self.http_validator.validate(request)
        result.protocol = protocol
        return result

    def _check_smuggling(self, payload_text: str) -> FilterResult | None:
        """Check for HTTP request smuggling indicators.

        Args:
            payload_text: Decoded payload text

        Returns:
            FilterResult if smuggling detected, None otherwise
        """
        # Check for conflicting Content-Length and Transfer-Encoding
        has_cl = "content-length:" in payload_text.lower()
        has_te = "transfer-encoding:" in payload_text.lower()

        if has_cl and has_te:
            return FilterResult(
                allowed=False,
                reason="HTTP request smuggling: conflicting Content-Length and Transfer-Encoding",
                details={"smuggling_type": "CL-TE conflict"},
            )

        # Check for duplicate Content-Length headers
        cl_count = payload_text.lower().count("content-length:")
        if cl_count > 1:
            return FilterResult(
                allowed=False,
                reason="HTTP request smuggling: duplicate Content-Length headers",
                details={"smuggling_type": "duplicate CL"},
            )

        # Check for duplicate Transfer-Encoding headers
        te_count = payload_text.lower().count("transfer-encoding:")
        if te_count > 1:
            return FilterResult(
                allowed=False,
                reason="HTTP request smuggling: duplicate Transfer-Encoding headers",
                details={"smuggling_type": "duplicate TE"},
            )

        return None

    @staticmethod
    def _decode_payload(payload: bytes) -> str:
        """Decode payload bytes to text.

        Args:
            payload: Raw payload bytes

        Returns:
            Decoded text (UTF-8 with errors replaced)
        """
        try:
            return payload.decode("utf-8", errors="replace")
        except Exception:
            return ""

    def get_stats(self) -> dict[str, int]:
        """Get filtering statistics.

        Returns:
            Dictionary with operation counts
        """
        return self.stats.copy()

    def update_policy(self, policy: ProtocolPolicy) -> None:
        """Update the filtering policy.

        Args:
            policy: New protocol policy
        """
        self.policy = policy
        self.http_validator = HTTPValidator(policy)
        logger.info("Protocol filter policy updated")
