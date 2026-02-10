"""Network isolation and egress control for Docker containers.

This module provides comprehensive network isolation for MCP capability containers,
including custom Docker networks, egress filtering, DNS allowlisting, and network
monitoring.

Features:
- Custom Docker network per container
- Egress filtering via iptables
- DNS allowlisting with domain resolution
- Wildcard domain support (*.github.com)
- CIDR block support (192.168.0.0/16)
- Network telemetry (connections, bandwidth)
- Dynamic policy updates (no container restart)
- Blocked connection logging
- Suspicious pattern detection
- Integration with audit logging

Architecture:
    NetworkPolicy: Define egress rules (domains, IPs, CIDRs)
    EgressFilter: Determine if connection should be allowed
    NetworkIsolationManager: Manage Docker networks and iptables
    NetworkMonitor: Track and alert on network activity
"""

import ipaddress
import logging
import re
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from .audit_db import SecurityDecision
from .audit_logger import AuditLogger

logger = logging.getLogger(__name__)


class NetworkPolicy(BaseModel):
    """Network egress policy for a container.

    Defines what outbound network connections are allowed. Supports:
    - Domain allowlist with wildcards (*.github.com)
    - IP addresses (1.1.1.1)
    - CIDR blocks (192.168.0.0/16, 2001:db8::/32)
    - DNS resolution caching for performance
    - Policy validation
    """

    allowed_domains: list[str] = Field(
        default_factory=list,
        description="Allowed domains with wildcard support (e.g., '*.github.com', 'api.openai.com')",
    )
    allowed_ips: list[str] = Field(
        default_factory=list,
        description="Allowed IP addresses (e.g., '1.1.1.1', '8.8.8.8')",
    )
    allowed_cidrs: list[str] = Field(
        default_factory=list,
        description="Allowed CIDR blocks (e.g., '192.168.0.0/16', '10.0.0.0/8')",
    )
    block_by_default: bool = Field(
        default=True,
        description="Block all connections not explicitly allowed",
    )
    allow_dns: bool = Field(
        default=True,
        description="Allow DNS queries (port 53)",
    )
    allow_localhost: bool = Field(
        default=True,
        description="Allow connections to localhost/127.0.0.1",
    )

    def validate_policy(self) -> list[str]:
        """Validate policy configuration.

        Returns:
            List of validation errors (empty if valid)
        """
        errors = []

        # Validate domain patterns
        for domain in self.allowed_domains:
            if not self._is_valid_domain_pattern(domain):
                errors.append(f"Invalid domain pattern: {domain}")

        # Validate IP addresses
        for ip in self.allowed_ips:
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                errors.append(f"Invalid IP address: {ip}")

        # Validate CIDR blocks
        for cidr in self.allowed_cidrs:
            try:
                ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                errors.append(f"Invalid CIDR block: {cidr}")

        return errors

    @staticmethod
    def _is_valid_domain_pattern(pattern: str) -> bool:
        """Check if domain pattern is valid.

        Supports:
        - Regular domains: example.com
        - Wildcards: *.example.com
        - Subdomains: api.example.com

        Args:
            pattern: Domain pattern to validate

        Returns:
            True if valid, False otherwise
        """
        # Remove leading wildcard for validation
        domain = pattern.lstrip("*.")

        # Simple validation: must have at least one dot and valid characters
        if "." not in domain:
            return False

        # Check for invalid characters
        valid_pattern = re.compile(r"^[a-zA-Z0-9\-\.]+$")
        return bool(valid_pattern.match(domain))

    def matches_domain(self, domain: str) -> bool:
        """Check if domain matches any allowed pattern.

        Args:
            domain: Domain to check

        Returns:
            True if allowed, False otherwise
        """
        domain = domain.lower().strip()

        for pattern in self.allowed_domains:
            pattern = pattern.lower().strip()

            # Exact match
            if pattern == domain:
                return True

            # Wildcard match (*.example.com matches api.example.com)
            if pattern.startswith("*."):
                suffix = pattern[2:]  # Remove "*."
                if domain.endswith(suffix) or domain == suffix:
                    return True

        return False

    def matches_ip(self, ip: str) -> bool:
        """Check if IP address is allowed.

        Args:
            ip: IP address to check

        Returns:
            True if allowed, False otherwise
        """
        try:
            ip_addr = ipaddress.ip_address(ip)

            # Check exact IP matches
            for allowed_ip in self.allowed_ips:
                if ip_addr == ipaddress.ip_address(allowed_ip):
                    return True

            # Check CIDR blocks
            for cidr in self.allowed_cidrs:
                network = ipaddress.ip_network(cidr, strict=False)
                if ip_addr in network:
                    return True

        except ValueError:
            logger.warning(f"Invalid IP address format: {ip}")
            return False

        return False


@dataclass
class DNSCacheEntry:
    """DNS resolution cache entry."""

    domain: str
    ips: list[str]
    timestamp: float
    ttl: int = 300  # 5 minutes default


class DNSResolver:
    """DNS resolver with caching for performance.

    Caches domain → IP resolutions to avoid repeated lookups.
    Supports both A (IPv4) and AAAA (IPv6) records.
    """

    def __init__(self, cache_ttl: int = 300):
        """Initialize DNS resolver.

        Args:
            cache_ttl: Cache TTL in seconds (default: 5 minutes)
        """
        self._cache: dict[str, DNSCacheEntry] = {}
        self._cache_ttl = cache_ttl

    def resolve(self, domain: str) -> list[str]:
        """Resolve domain to IP addresses.

        Args:
            domain: Domain name to resolve

        Returns:
            List of IP addresses (empty if resolution fails)
        """
        # Check cache
        if domain in self._cache:
            entry = self._cache[domain]
            if time.time() - entry.timestamp < entry.ttl:
                logger.debug(f"DNS cache hit for {domain}: {entry.ips}")
                return entry.ips

        # Resolve using system DNS
        ips = self._system_resolve(domain)

        # Update cache
        if ips:
            self._cache[domain] = DNSCacheEntry(
                domain=domain,
                ips=ips,
                timestamp=time.time(),
                ttl=self._cache_ttl,
            )

        return ips

    def _system_resolve(self, domain: str) -> list[str]:
        """Resolve domain using system DNS.

        Args:
            domain: Domain to resolve

        Returns:
            List of IP addresses
        """
        try:
            import dns.resolver

            ips = []

            # Try A records (IPv4)
            try:
                answers = dns.resolver.resolve(domain, "A")
                for rdata in answers:
                    ips.append(str(rdata))
            except dns.resolver.NXDOMAIN:
                pass
            except dns.resolver.NoAnswer:
                pass

            # Try AAAA records (IPv6)
            try:
                answers = dns.resolver.resolve(domain, "AAAA")
                for rdata in answers:
                    ips.append(str(rdata))
            except dns.resolver.NXDOMAIN:
                pass
            except dns.resolver.NoAnswer:
                pass

            logger.debug(f"Resolved {domain} to {ips}")
            return ips

        except ImportError:
            logger.warning("dnspython not installed, using basic resolution")
            return self._basic_resolve(domain)
        except Exception as e:
            logger.error(f"DNS resolution failed for {domain}: {e}")
            return []

    def _basic_resolve(self, domain: str) -> list[str]:
        """Fallback DNS resolution using socket library.

        Args:
            domain: Domain to resolve

        Returns:
            List of IP addresses
        """
        try:
            import socket

            result = socket.getaddrinfo(domain, None)
            ips = list({str(addr[4][0]) for addr in result})
            return ips
        except Exception as e:
            logger.error(f"Basic DNS resolution failed for {domain}: {e}")
            return []

    def clear_cache(self) -> None:
        """Clear DNS resolution cache."""
        self._cache.clear()
        logger.info("DNS cache cleared")


class EgressFilter:
    """Determine if an egress connection should be allowed.

    Performs:
    - Domain allowlist checking with wildcard support
    - IP allowlist checking
    - CIDR block matching
    - DNS resolution and caching
    - Performance optimized (<1ms overhead)
    """

    def __init__(self, policy: NetworkPolicy, dns_resolver: DNSResolver | None = None):
        """Initialize egress filter.

        Args:
            policy: Network policy to enforce
            dns_resolver: DNS resolver (creates new one if None)
        """
        self.policy = policy
        self.dns_resolver = dns_resolver or DNSResolver()

        # Validate policy on initialization
        errors = policy.validate_policy()
        if errors:
            logger.warning(f"Policy validation errors: {errors}")

    def is_allowed(self, destination: str, port: int | None = None) -> tuple[bool, str]:
        """Check if connection to destination is allowed.

        Args:
            destination: Domain name or IP address
            port: Destination port (optional)

        Returns:
            Tuple of (allowed: bool, reason: str)
        """
        start_time = time.time()

        # Allow DNS queries
        if port == 53 and self.policy.allow_dns:
            reason = "DNS query allowed by policy"
            logger.debug(f"{reason}: {destination}:{port}")
            return True, reason

        # Allow localhost
        if self.policy.allow_localhost and self._is_localhost(destination):
            reason = "Localhost connection allowed by policy"
            logger.debug(f"{reason}: {destination}")
            return True, reason

        # Check if destination is IP address
        if self._is_ip_address(destination):
            allowed = self.policy.matches_ip(destination)
            reason = "IP in allowlist" if allowed else "IP not in allowlist"
            elapsed = (time.time() - start_time) * 1000
            logger.debug(f"IP check for {destination}: {allowed} ({elapsed:.2f}ms)")
            return allowed, reason

        # Check domain against allowlist
        if self.policy.matches_domain(destination):
            reason = "Domain in allowlist"
            elapsed = (time.time() - start_time) * 1000
            logger.debug(f"Domain check for {destination}: allowed ({elapsed:.2f}ms)")
            return True, reason

        # Resolve domain to IPs and check if any match
        ips = self.dns_resolver.resolve(destination)
        for ip in ips:
            if self.policy.matches_ip(ip):
                reason = f"Domain resolves to allowed IP: {ip}"
                elapsed = (time.time() - start_time) * 1000
                logger.debug(f"DNS-based check for {destination}: allowed ({elapsed:.2f}ms)")
                return True, reason

        # Block by default
        reason = f"Destination {destination} not in allowlist"
        elapsed = (time.time() - start_time) * 1000
        logger.debug(f"Connection blocked: {destination} ({elapsed:.2f}ms)")
        return False, reason

    @staticmethod
    def _is_ip_address(destination: str) -> bool:
        """Check if destination is an IP address.

        Args:
            destination: String to check

        Returns:
            True if IP address, False otherwise
        """
        try:
            ipaddress.ip_address(destination)
            return True
        except ValueError:
            return False

    @staticmethod
    def _is_localhost(destination: str) -> bool:
        """Check if destination is localhost.

        Args:
            destination: Destination to check

        Returns:
            True if localhost, False otherwise
        """
        localhost_patterns = [
            "localhost",
            "127.0.0.1",
            "::1",
            "0.0.0.0",
        ]

        destination = destination.lower()
        return any(pattern in destination for pattern in localhost_patterns)


@dataclass
class NetworkMetrics:
    """Network usage metrics for a container."""

    container_name: str
    start_time: float = field(default_factory=time.time)
    total_connections: int = 0
    allowed_connections: int = 0
    blocked_connections: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    last_updated: float = field(default_factory=time.time)


@dataclass
class ConnectionAttempt:
    """Record of a connection attempt."""

    timestamp: float
    container_name: str
    destination: str
    port: int | None
    allowed: bool
    reason: str


class NetworkMonitor:
    """Monitor network activity and detect suspicious patterns.

    Features:
    - Track connection attempts
    - Detect suspicious patterns (port scanning, rapid failures)
    - Integration with audit logger
    - Metrics collection
    - Alerting
    """

    # Thresholds for suspicious activity
    MAX_BLOCKED_PER_MINUTE = 10
    MAX_UNIQUE_DESTINATIONS_PER_MINUTE = 20
    PORT_SCAN_THRESHOLD = 5  # Different ports to same IP

    def __init__(self, audit_logger: AuditLogger | None = None):
        """Initialize network monitor.

        Args:
            audit_logger: Audit logger for security decisions
        """
        self.audit_logger = audit_logger
        self._metrics: dict[str, NetworkMetrics] = {}
        self._connection_history: list[ConnectionAttempt] = []
        self._max_history_size = 1000

    def record_connection(
        self,
        container_name: str,
        destination: str,
        port: int | None,
        allowed: bool,
        reason: str,
    ) -> None:
        """Record a connection attempt.

        Args:
            container_name: Name of container
            destination: Destination domain/IP
            port: Destination port
            allowed: Whether connection was allowed
            reason: Reason for allow/deny decision
        """
        # Update metrics
        if container_name not in self._metrics:
            self._metrics[container_name] = NetworkMetrics(container_name=container_name)

        metrics = self._metrics[container_name]
        metrics.total_connections += 1
        metrics.last_updated = time.time()

        if allowed:
            metrics.allowed_connections += 1
        else:
            metrics.blocked_connections += 1

        # Record connection attempt
        attempt = ConnectionAttempt(
            timestamp=time.time(),
            container_name=container_name,
            destination=destination,
            port=port,
            allowed=allowed,
            reason=reason,
        )

        self._connection_history.append(attempt)

        # Trim history if too large
        if len(self._connection_history) > self._max_history_size:
            self._connection_history = self._connection_history[-self._max_history_size :]

        # Log blocked connections
        if not allowed:
            logger.warning(
                f"Blocked connection: {container_name} -> {destination}:{port} "
                f"(reason: {reason})"
            )

            # Log to audit if available
            if self.audit_logger:
                self.audit_logger.log_security_decision(
                    correlation_id=f"network-{int(time.time() * 1000)}",
                    decision_type="egress",
                    decision=SecurityDecision.DENY,
                    reason=reason,
                    actor=container_name,
                    context={
                        "destination": destination,
                        "port": port,
                        "timestamp": datetime.utcnow().isoformat(),
                    },
                )

        # Check for suspicious patterns
        self._check_suspicious_activity(container_name)

    def _check_suspicious_activity(self, container_name: str) -> None:
        """Check for suspicious network activity patterns.

        Args:
            container_name: Container to check
        """
        now = time.time()
        one_minute_ago = now - 60

        # Get recent attempts for this container
        recent_attempts = [
            attempt
            for attempt in self._connection_history
            if attempt.container_name == container_name and attempt.timestamp > one_minute_ago
        ]

        if not recent_attempts:
            return

        # Check for excessive blocked connections
        blocked_count = sum(1 for attempt in recent_attempts if not attempt.allowed)
        if blocked_count > self.MAX_BLOCKED_PER_MINUTE:
            self._alert_suspicious(
                container_name,
                "excessive_blocks",
                f"{blocked_count} blocked connections in last minute",
            )

        # Check for too many unique destinations
        unique_destinations = len({attempt.destination for attempt in recent_attempts})
        if unique_destinations > self.MAX_UNIQUE_DESTINATIONS_PER_MINUTE:
            self._alert_suspicious(
                container_name,
                "destination_scanning",
                f"{unique_destinations} unique destinations in last minute",
            )

        # Check for port scanning (many ports to same IP)
        destination_ports: dict[str, set[int]] = {}
        for attempt in recent_attempts:
            if attempt.port:
                if attempt.destination not in destination_ports:
                    destination_ports[attempt.destination] = set()
                destination_ports[attempt.destination].add(attempt.port)

        for destination, ports in destination_ports.items():
            if len(ports) >= self.PORT_SCAN_THRESHOLD:
                self._alert_suspicious(
                    container_name,
                    "port_scanning",
                    f"{len(ports)} different ports to {destination}",
                )

    def _alert_suspicious(self, container_name: str, pattern: str, details: str) -> None:
        """Alert on suspicious network activity.

        Args:
            container_name: Container exhibiting suspicious behavior
            pattern: Type of suspicious pattern
            details: Details about the suspicious activity
        """
        logger.error(f"SUSPICIOUS ACTIVITY: {container_name} - {pattern}: {details}")

        if self.audit_logger:
            self.audit_logger.log_security_decision(
                correlation_id=f"alert-{int(time.time() * 1000)}",
                decision_type="alert",
                decision=SecurityDecision.DENY,
                reason=f"Suspicious network activity: {pattern}",
                actor=container_name,
                context={
                    "pattern": pattern,
                    "details": details,
                    "timestamp": datetime.utcnow().isoformat(),
                },
            )

    def get_metrics(self, container_name: str) -> NetworkMetrics | None:
        """Get network metrics for a container.

        Args:
            container_name: Container name

        Returns:
            Network metrics or None if not found
        """
        return self._metrics.get(container_name)

    def get_all_metrics(self) -> dict[str, NetworkMetrics]:
        """Get metrics for all containers.

        Returns:
            Dictionary of container_name -> NetworkMetrics
        """
        return self._metrics.copy()

    def get_recent_attempts(
        self, container_name: str | None = None, minutes: int = 5
    ) -> list[ConnectionAttempt]:
        """Get recent connection attempts.

        Args:
            container_name: Filter by container (None for all)
            minutes: How many minutes of history to return

        Returns:
            List of connection attempts
        """
        cutoff = time.time() - (minutes * 60)

        attempts = [attempt for attempt in self._connection_history if attempt.timestamp > cutoff]

        if container_name:
            attempts = [attempt for attempt in attempts if attempt.container_name == container_name]

        return attempts


class NetworkIsolationManager:
    """Manage Docker networks and iptables rules for container isolation.

    Provides:
    - Custom Docker network per container
    - iptables-based egress filtering
    - DNS allowlisting
    - Network telemetry
    - Dynamic policy updates
    """

    def __init__(
        self,
        audit_logger: AuditLogger | None = None,
        enable_iptables: bool = True,
    ):
        """Initialize network isolation manager.

        Args:
            audit_logger: Audit logger for security decisions
            enable_iptables: Enable iptables rules (requires root)
        """
        self.audit_logger = audit_logger
        self.enable_iptables = enable_iptables
        self.dns_resolver = DNSResolver()
        self.network_monitor = NetworkMonitor(audit_logger=audit_logger)

        # Container -> Policy mapping
        self._policies: dict[str, NetworkPolicy] = {}

        # Container -> EgressFilter mapping
        self._filters: dict[str, EgressFilter] = {}

        # Container -> Docker network name mapping
        self._networks: dict[str, str] = {}

        self._docker: Any = None

    def _get_docker_client(self) -> Any:
        """Get Docker client.

        Returns:
            Docker client

        Raises:
            ImportError: If docker package not installed
        """
        if self._docker is None:
            try:
                import docker

                self._docker = docker.from_env()  # type: ignore[attr-defined]
                logger.info("Connected to Docker daemon for network management")
            except ImportError as e:
                msg = "Docker SDK not installed. Install with: pip install 'harombe[docker]'"
                raise ImportError(msg) from e

        return self._docker

    async def create_isolated_network(
        self,
        container_name: str,
        policy: NetworkPolicy,
    ) -> str:
        """Create isolated Docker network for container.

        Args:
            container_name: Name of container
            policy: Network policy to enforce

        Returns:
            Network name

        Raises:
            Exception: If network creation fails
        """
        network_name = f"harombe-{container_name}-net"

        try:
            client = self._get_docker_client()

            # Check if network already exists
            try:
                client.networks.get(network_name)
                logger.info(f"Network {network_name} already exists")
                self._networks[container_name] = network_name
                return network_name
            except Exception:
                pass

            # Create network with isolation
            client.networks.create(
                name=network_name,
                driver="bridge",
                internal=False,  # Allow external connections (filtered by iptables)
                enable_ipv6=False,  # IPv6 support optional
                options={
                    "com.docker.network.bridge.name": network_name[:15],  # Max 15 chars
                },
            )

            logger.info(f"Created isolated network: {network_name}")

            # Store policy and create filter
            self._policies[container_name] = policy
            self._filters[container_name] = EgressFilter(policy, self.dns_resolver)
            self._networks[container_name] = network_name

            # Apply iptables rules if enabled
            if self.enable_iptables:
                await self._apply_iptables_rules(container_name, network_name, policy)

            return network_name

        except Exception as e:
            logger.error(f"Failed to create isolated network for {container_name}: {e}")
            raise

    async def _apply_iptables_rules(
        self,
        container_name: str,
        network_name: str,
        policy: NetworkPolicy,
    ) -> None:
        """Apply iptables rules for egress filtering.

        Args:
            container_name: Container name
            network_name: Docker network name
            policy: Network policy

        Note:
            Requires root/sudo privileges. Will warn if unable to apply rules.
        """
        try:
            # Get network interface name
            client = self._get_docker_client()
            network = client.networks.get(network_name)
            network_info = network.attrs

            # Extract bridge interface (typically br-<network_id>)
            bridge_name = network_info.get("Options", {}).get(
                "com.docker.network.bridge.name", f"br-{network_info['Id'][:12]}"
            )

            logger.info(f"Applying iptables rules for {network_name} on {bridge_name}")

            # Create custom chain for this container
            chain_name = f"HAROMBE_{container_name[:20].upper()}"  # Max chain name length

            # Create chain if not exists
            subprocess.run(
                ["iptables", "-N", chain_name],
                check=False,  # May already exist
                capture_output=True,
            )

            # Flush existing rules in chain
            subprocess.run(
                ["iptables", "-F", chain_name],
                check=True,
                capture_output=True,
            )

            # Allow localhost if enabled
            if policy.allow_localhost:
                subprocess.run(
                    [
                        "iptables",
                        "-A",
                        chain_name,
                        "-d",
                        "127.0.0.0/8",
                        "-j",
                        "ACCEPT",
                    ],
                    check=True,
                    capture_output=True,
                )

            # Allow DNS if enabled
            if policy.allow_dns:
                subprocess.run(
                    [
                        "iptables",
                        "-A",
                        chain_name,
                        "-p",
                        "udp",
                        "--dport",
                        "53",
                        "-j",
                        "ACCEPT",
                    ],
                    check=True,
                    capture_output=True,
                )
                subprocess.run(
                    [
                        "iptables",
                        "-A",
                        chain_name,
                        "-p",
                        "tcp",
                        "--dport",
                        "53",
                        "-j",
                        "ACCEPT",
                    ],
                    check=True,
                    capture_output=True,
                )

            # Allow specific IPs
            for ip in policy.allowed_ips:
                subprocess.run(
                    [
                        "iptables",
                        "-A",
                        chain_name,
                        "-d",
                        ip,
                        "-j",
                        "ACCEPT",
                    ],
                    check=True,
                    capture_output=True,
                )

            # Allow CIDR blocks
            for cidr in policy.allowed_cidrs:
                subprocess.run(
                    [
                        "iptables",
                        "-A",
                        chain_name,
                        "-d",
                        cidr,
                        "-j",
                        "ACCEPT",
                    ],
                    check=True,
                    capture_output=True,
                )

            # Block everything else if block_by_default
            if policy.block_by_default:
                subprocess.run(
                    [
                        "iptables",
                        "-A",
                        chain_name,
                        "-j",
                        "DROP",
                    ],
                    check=True,
                    capture_output=True,
                )

            # Link chain to FORWARD chain for this network
            subprocess.run(
                [
                    "iptables",
                    "-I",
                    "FORWARD",
                    "-i",
                    bridge_name,
                    "-j",
                    chain_name,
                ],
                check=True,
                capture_output=True,
            )

            logger.info(f"Applied iptables rules for {container_name}")

        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to apply iptables rules: {e.stderr.decode()}")
            logger.warning("Network isolation may be incomplete - consider running with sudo")
        except Exception as e:
            logger.error(f"Error applying iptables rules: {e}")

    async def update_policy(
        self,
        container_name: str,
        policy: NetworkPolicy,
    ) -> None:
        """Update network policy for a container dynamically.

        Updates the policy without requiring container restart.

        Args:
            container_name: Container name
            policy: New network policy

        Raises:
            ValueError: If container not found
        """
        if container_name not in self._policies:
            raise ValueError(f"Container {container_name} not found in network manager")

        # Validate new policy
        errors = policy.validate_policy()
        if errors:
            raise ValueError(f"Invalid policy: {errors}")

        # Update policy and filter
        self._policies[container_name] = policy
        self._filters[container_name] = EgressFilter(policy, self.dns_resolver)

        logger.info(f"Updated network policy for {container_name}")

        # Re-apply iptables rules if enabled
        if self.enable_iptables and container_name in self._networks:
            network_name = self._networks[container_name]
            await self._apply_iptables_rules(container_name, network_name, policy)

    def check_connection(
        self,
        container_name: str,
        destination: str,
        port: int | None = None,
    ) -> tuple[bool, str]:
        """Check if a connection is allowed by policy.

        Args:
            container_name: Container attempting connection
            destination: Destination domain/IP
            port: Destination port

        Returns:
            Tuple of (allowed: bool, reason: str)
        """
        # Get filter for container
        if container_name not in self._filters:
            logger.warning(f"No policy found for {container_name}, denying by default")
            return False, "No network policy configured"

        egress_filter = self._filters[container_name]

        # Check if allowed
        allowed, reason = egress_filter.is_allowed(destination, port)

        # Record for monitoring
        self.network_monitor.record_connection(
            container_name=container_name,
            destination=destination,
            port=port,
            allowed=allowed,
            reason=reason,
        )

        return allowed, reason

    def get_metrics(self, container_name: str) -> NetworkMetrics | None:
        """Get network metrics for a container.

        Args:
            container_name: Container name

        Returns:
            Network metrics or None
        """
        return self.network_monitor.get_metrics(container_name)

    def get_all_metrics(self) -> dict[str, NetworkMetrics]:
        """Get metrics for all containers.

        Returns:
            Dictionary of container_name -> NetworkMetrics
        """
        return self.network_monitor.get_all_metrics()

    def get_recent_blocks(
        self, container_name: str | None = None, minutes: int = 5
    ) -> list[ConnectionAttempt]:
        """Get recent blocked connection attempts.

        Args:
            container_name: Filter by container (None for all)
            minutes: How many minutes of history

        Returns:
            List of blocked connection attempts
        """
        attempts = self.network_monitor.get_recent_attempts(container_name, minutes)
        return [attempt for attempt in attempts if not attempt.allowed]

    async def cleanup_network(self, container_name: str) -> None:
        """Clean up network resources for a container.

        Args:
            container_name: Container name
        """
        if container_name not in self._networks:
            logger.warning(f"No network found for {container_name}")
            return

        network_name = self._networks[container_name]

        try:
            # Remove iptables rules
            if self.enable_iptables:
                chain_name = f"HAROMBE_{container_name[:20].upper()}"
                subprocess.run(
                    ["iptables", "-D", "FORWARD", "-j", chain_name],
                    check=False,
                    capture_output=True,
                )
                subprocess.run(
                    ["iptables", "-F", chain_name],
                    check=False,
                    capture_output=True,
                )
                subprocess.run(
                    ["iptables", "-X", chain_name],
                    check=False,
                    capture_output=True,
                )

            # Remove Docker network
            client = self._get_docker_client()
            network = client.networks.get(network_name)
            network.remove()

            logger.info(f"Cleaned up network {network_name}")

        except Exception as e:
            logger.error(f"Error cleaning up network for {container_name}: {e}")

        # Clean up internal state
        self._policies.pop(container_name, None)
        self._filters.pop(container_name, None)
        self._networks.pop(container_name, None)

    async def cleanup_all(self) -> None:
        """Clean up all managed networks."""
        container_names = list(self._networks.keys())

        for container_name in container_names:
            try:
                await self.cleanup_network(container_name)
            except Exception as e:
                logger.error(f"Failed to cleanup network for {container_name}: {e}")

        logger.info("Cleaned up all networks")
