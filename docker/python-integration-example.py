#!/usr/bin/env python3
"""
Harombe Network Isolation Manager - Python Integration Example

This module demonstrates how to integrate the firewall-rules.sh script
with Python code for dynamic network isolation management.

This would typically be part of src/harombe/security/network_isolation.py
"""

import logging
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class FirewallRule:
    """Represents a firewall rule."""

    container_name: str
    destination_ip: str
    port: int | None = None
    protocol: str = "tcp"  # tcp, udp, or both


class NetworkIsolationManager:
    """Manager for Docker container network isolation using iptables.

    This class provides a Python interface to the firewall-rules.sh script,
    enabling dynamic network policy enforcement for containerized MCP capabilities.

    Example:
        >>> manager = NetworkIsolationManager()
        >>> manager.initialize_firewall()
        >>> manager.add_allow_rule("harombe-browser", "93.184.216.34", 443)
        >>> manager.enable_logging()
    """

    def __init__(
        self,
        script_path: Path | str = "docker/firewall-rules.sh",
        use_sudo: bool = True,
    ):
        """Initialize the network isolation manager.

        Args:
            script_path: Path to the firewall-rules.sh script
            use_sudo: Whether to use sudo for script execution (required on Linux)
        """
        self.script_path = Path(script_path).resolve()
        self.use_sudo = use_sudo
        self._active_rules: list[FirewallRule] = []

        if not self.script_path.exists():
            msg = f"Firewall script not found: {self.script_path}"
            raise FileNotFoundError(msg)

        if not self.script_path.is_file() or not self._is_executable():
            msg = f"Firewall script is not executable: {self.script_path}"
            raise PermissionError(msg)

    def _is_executable(self) -> bool:
        """Check if the script is executable."""
        import os

        return os.access(self.script_path, os.X_OK)

    def _run_command(
        self, *args: str, check: bool = True, capture_output: bool = True
    ) -> subprocess.CompletedProcess:
        """Run firewall script command.

        Args:
            *args: Arguments to pass to the script
            check: Whether to raise exception on non-zero exit
            capture_output: Whether to capture stdout/stderr

        Returns:
            CompletedProcess instance

        Raises:
            subprocess.CalledProcessError: If command fails and check=True
        """
        cmd = []

        if self.use_sudo:
            cmd.append("sudo")

        cmd.append(str(self.script_path))
        cmd.extend(args)

        logger.debug(f"Running command: {' '.join(cmd)}")

        try:
            result = subprocess.run(
                cmd,
                check=check,
                capture_output=capture_output,
                text=True,
            )

            if result.stdout:
                logger.debug(f"Command output: {result.stdout}")

            return result

        except subprocess.CalledProcessError as e:
            logger.error(f"Command failed: {e}")
            if e.stderr:
                logger.error(f"Error output: {e.stderr}")
            raise

    def initialize_firewall(self) -> None:
        """Initialize iptables firewall rules.

        Creates custom chains, sets up default policies, and enables
        stateful connection tracking.

        Raises:
            subprocess.CalledProcessError: If initialization fails
        """
        logger.info("Initializing firewall rules...")
        self._run_command("init")
        logger.info("Firewall initialized successfully")

    def cleanup_firewall(self) -> None:
        """Clean up all firewall rules and chains.

        Removes all custom chains and rules. Containers will use
        default Docker networking after cleanup.

        Raises:
            subprocess.CalledProcessError: If cleanup fails
        """
        logger.info("Cleaning up firewall rules...")
        self._run_command("cleanup")
        self._active_rules.clear()
        logger.info("Firewall cleaned up successfully")

    def add_allow_rule(
        self,
        container_name: str,
        destination_ip: str,
        port: int | None = None,
    ) -> None:
        """Add an allow rule for container egress traffic.

        Args:
            container_name: Name of the container (e.g., "harombe-browser")
            destination_ip: Destination IP address or CIDR block
            port: Optional destination port number

        Example:
            >>> manager.add_allow_rule("harombe-browser", "93.184.216.34", 443)
            >>> manager.add_allow_rule("harombe-web-search", "10.0.0.0/8")

        Raises:
            subprocess.CalledProcessError: If rule addition fails
        """
        logger.info(
            f"Adding allow rule: {container_name} -> {destination_ip}"
            f"{f':{port}' if port else ''}"
        )

        args = ["add", container_name, destination_ip]
        if port:
            args.append(str(port))

        self._run_command(*args)

        # Track active rule
        rule = FirewallRule(container_name, destination_ip, port)
        self._active_rules.append(rule)

        logger.info("Allow rule added successfully")

    def remove_allow_rule(
        self,
        container_name: str,
        destination_ip: str,
        port: int | None = None,
    ) -> None:
        """Remove an allow rule.

        Args:
            container_name: Name of the container
            destination_ip: Destination IP address or CIDR block
            port: Optional destination port number

        Raises:
            subprocess.CalledProcessError: If rule removal fails
        """
        logger.info(
            f"Removing allow rule: {container_name} -> {destination_ip}"
            f"{f':{port}' if port else ''}"
        )

        args = ["remove", container_name, destination_ip]
        if port:
            args.append(str(port))

        self._run_command(*args)

        # Remove from tracked rules
        self._active_rules = [
            r
            for r in self._active_rules
            if not (
                r.container_name == container_name
                and r.destination_ip == destination_ip
                and r.port == port
            )
        ]

        logger.info("Allow rule removed successfully")

    def block_all_egress(self, container_name: str) -> None:
        """Block all egress traffic from a container.

        This removes all existing allow rules for the container and
        installs an explicit DROP rule.

        Args:
            container_name: Name of the container

        Example:
            >>> manager.block_all_egress("harombe-code-exec")

        Raises:
            subprocess.CalledProcessError: If blocking fails
        """
        logger.info(f"Blocking all egress traffic from: {container_name}")
        self._run_command("block-all", container_name)

        # Remove tracked rules for this container
        self._active_rules = [r for r in self._active_rules if r.container_name != container_name]

        logger.info(f"All egress blocked for {container_name}")

    def enable_logging(self) -> None:
        """Enable logging of blocked connection attempts.

        Logs are written to both syslog and /var/log/harombe-firewall.log.
        Logging is rate-limited to prevent flooding.

        Raises:
            subprocess.CalledProcessError: If logging setup fails
        """
        logger.info("Enabling firewall logging...")
        self._run_command("enable-logging")
        logger.info("Firewall logging enabled")

    def disable_logging(self) -> None:
        """Disable firewall logging.

        Raises:
            subprocess.CalledProcessError: If logging disable fails
        """
        logger.info("Disabling firewall logging...")
        self._run_command("disable-logging")
        logger.info("Firewall logging disabled")

    def get_status(self) -> str:
        """Get current firewall status.

        Returns:
            Status output showing active rules and chains

        Raises:
            subprocess.CalledProcessError: If status check fails
        """
        result = self._run_command("status", capture_output=True)
        return result.stdout

    def get_active_rules(self) -> list[FirewallRule]:
        """Get list of active firewall rules.

        Returns:
            List of FirewallRule objects
        """
        return self._active_rules.copy()

    def apply_allowlist(self, container_name: str, allowlist: list[dict[str, Any]]) -> None:
        """Apply a complete allowlist for a container.

        This is a convenience method that adds multiple rules at once.

        Args:
            container_name: Name of the container
            allowlist: List of allowed destinations, each with 'ip' and optional 'port'

        Example:
            >>> allowlist = [
            ...     {"ip": "93.184.216.34", "port": 443},
            ...     {"ip": "10.0.0.0/8"},
            ...     {"ip": "52.1.2.3", "port": 8080},
            ... ]
            >>> manager.apply_allowlist("harombe-browser", allowlist)
        """
        logger.info(f"Applying allowlist for {container_name}: {len(allowlist)} rules")

        for item in allowlist:
            ip = item.get("ip")
            port = item.get("port")

            if not ip:
                logger.warning(f"Skipping allowlist item without IP: {item}")
                continue

            try:
                self.add_allow_rule(container_name, ip, port)
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to add rule for {ip}:{port}: {e}")
                # Continue with other rules

        logger.info(f"Allowlist applied for {container_name}")


def main():
    """Example usage of NetworkIsolationManager."""
    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    # Initialize manager
    manager = NetworkIsolationManager(
        script_path="firewall-rules.sh",
        use_sudo=True,
    )

    try:
        # Initialize firewall
        manager.initialize_firewall()
        manager.enable_logging()

        # Configure browser container with allowlist
        browser_allowlist = [
            {"ip": "93.184.216.34", "port": 443},  # example.com
            {"ip": "8.8.8.8", "port": 53},  # Google DNS
            {"ip": "172.217.0.0/16", "port": 443},  # Google IPs
        ]
        manager.apply_allowlist("harombe-browser", browser_allowlist)

        # Configure web search container
        web_search_allowlist = [
            {"ip": "52.1.2.3", "port": 8080},  # API endpoint
            {"ip": "10.0.0.0/8"},  # Internal subnet
        ]
        manager.apply_allowlist("harombe-web-search", web_search_allowlist)

        # Block code execution container completely
        manager.block_all_egress("harombe-code-exec")

        # Show status
        print("\n" + "=" * 60)
        print("FIREWALL STATUS")
        print("=" * 60)
        print(manager.get_status())

        # Show active rules
        print("\n" + "=" * 60)
        print("ACTIVE RULES")
        print("=" * 60)
        for rule in manager.get_active_rules():
            port_str = f":{rule.port}" if rule.port else ""
            print(f"  {rule.container_name} -> {rule.destination_ip}{port_str}")

    except Exception as e:
        logger.error(f"Error: {e}")
        raise

    finally:
        # Cleanup (optional - comment out to keep rules)
        # manager.cleanup_firewall()
        pass


if __name__ == "__main__":
    main()
