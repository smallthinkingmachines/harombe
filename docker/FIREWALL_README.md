# Harombe Firewall Rules - iptables-based Network Isolation

## Overview

The `firewall-rules.sh` script provides iptables-based network isolation for Docker containers in the Harombe MCP Gateway system. It implements a default-deny egress policy with allowlist-based access control, ensuring that containers can only communicate with explicitly permitted destinations.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Docker Host (iptables)                    │
│                                                               │
│  ┌──────────────┐         ┌────────────────────┐            │
│  │   Gateway    │         │ Custom iptables    │            │
│  │  Container   │◄───────►│    Chains          │            │
│  └──────────────┘         │                    │            │
│         │                 │ - HAROMBE_FORWARD  │            │
│         │                 │ - HAROMBE_INPUT    │            │
│         ▼                 │ - HAROMBE_OUTPUT   │            │
│  ┌──────────────┐         │ - HAROMBE_LOG      │            │
│  │   Browser    │         └────────────────────┘            │
│  │  Container   │──────────► Allowlist Rules                │
│  └──────────────┘         (IP/Port specific)                │
│         │                                                    │
│         │                 Default: DROP                      │
│         ▼                                                    │
│    Internet                                                  │
│   (Blocked by default)                                       │
└─────────────────────────────────────────────────────────────┘
```

## Features

### 1. Default Deny Egress

- All outbound traffic is blocked by default
- Containers must be explicitly granted access to destinations
- Prevents data exfiltration and unauthorized network access

### 2. Allowlist-based Access Control

- Add rules for specific IP addresses or CIDR blocks
- Port-specific filtering (e.g., only allow HTTPS on port 443)
- Both TCP and UDP protocol support

### 3. Dynamic Rule Updates

- Add/remove rules without restarting containers
- Real-time policy enforcement
- Integrates with Python NetworkIsolationManager

### 4. Comprehensive Logging

- Logs all blocked connection attempts
- Rate-limited to prevent log flooding
- Outputs to syslog and custom log file
- Includes source/destination IP, port, and protocol

### 5. Docker Integration

- Works with Docker bridge networks
- Per-container isolation
- Supports Docker Compose deployments

## Installation

### Prerequisites

```bash
# Install iptables (usually pre-installed on Linux)
sudo apt-get install iptables  # Debian/Ubuntu
sudo yum install iptables       # RHEL/CentOS

# Install Docker
curl -fsSL https://get.docker.com | sh

# Create Docker network
docker network create --driver bridge --subnet 172.20.0.0/16 harombe-network
```

### Setup

```bash
# Make script executable
chmod +x docker/firewall-rules.sh

# Initialize firewall (requires root)
sudo ./docker/firewall-rules.sh init

# Enable logging
sudo ./docker/firewall-rules.sh enable-logging
```

## Usage

### Command Reference

```bash
# Initialize firewall rules
sudo ./firewall-rules.sh init

# Add allow rule (IP only)
sudo ./firewall-rules.sh add <container_name> <destination_ip>

# Add allow rule (IP + port)
sudo ./firewall-rules.sh add <container_name> <destination_ip> <port>

# Remove allow rule
sudo ./firewall-rules.sh remove <container_name> <destination_ip> [port]

# Block all egress from container
sudo ./firewall-rules.sh block-all <container_name>

# Enable/disable logging
sudo ./firewall-rules.sh enable-logging
sudo ./firewall-rules.sh disable-logging

# Check firewall status
sudo ./firewall-rules.sh status

# Clean up all rules
sudo ./firewall-rules.sh cleanup
```

### Examples

#### Example 1: Allow Browser Container to Access Specific Website

```bash
# Allow browser to access example.com (93.184.216.34) on HTTPS
sudo ./firewall-rules.sh add harombe-browser 93.184.216.34 443

# Verify rule was added
sudo ./firewall-rules.sh status
```

#### Example 2: Allow Web Search Container to Access API Subnet

```bash
# Allow web-search container to access entire API subnet
sudo ./firewall-rules.sh add harombe-web-search 10.0.0.0/8

# Allow specific API endpoint
sudo ./firewall-rules.sh add harombe-web-search 52.1.2.3 8080
```

#### Example 3: Complete Egress Lockdown for Code Execution

```bash
# Block all external access from code execution container
sudo ./firewall-rules.sh block-all harombe-code-exec

# Container can still communicate with other containers in the network
```

#### Example 4: Temporary Access Grant

```bash
# Add temporary rule
sudo ./firewall-rules.sh add harombe-browser 203.0.113.50 443

# ... perform operation ...

# Remove rule when done
sudo ./firewall-rules.sh remove harombe-browser 203.0.113.50 443
```

## Integration with Python

The script is designed to be called from the `NetworkIsolationManager` Python class:

```python
import subprocess
from pathlib import Path

class NetworkIsolationManager:
    """Manager for network isolation using iptables firewall."""

    def __init__(self, script_path: Path = Path("docker/firewall-rules.sh")):
        self.script_path = script_path

    def initialize_firewall(self) -> None:
        """Initialize firewall rules."""
        subprocess.run(
            ["sudo", str(self.script_path), "init"],
            check=True,
            capture_output=True
        )

    def add_allow_rule(
        self,
        container_name: str,
        destination_ip: str,
        port: int | None = None
    ) -> None:
        """Add allow rule for container -> destination."""
        cmd = ["sudo", str(self.script_path), "add", container_name, destination_ip]
        if port:
            cmd.append(str(port))

        subprocess.run(cmd, check=True, capture_output=True)

    def remove_allow_rule(
        self,
        container_name: str,
        destination_ip: str,
        port: int | None = None
    ) -> None:
        """Remove allow rule."""
        cmd = ["sudo", str(self.script_path), "remove", container_name, destination_ip]
        if port:
            cmd.append(str(port))

        subprocess.run(cmd, check=True, capture_output=True)

    def block_all_egress(self, container_name: str) -> None:
        """Block all egress traffic from container."""
        subprocess.run(
            ["sudo", str(self.script_path), "block-all", container_name],
            check=True,
            capture_output=True
        )

    def enable_logging(self) -> None:
        """Enable firewall logging."""
        subprocess.run(
            ["sudo", str(self.script_path), "enable-logging"],
            check=True,
            capture_output=True
        )

# Usage example
manager = NetworkIsolationManager()
manager.initialize_firewall()
manager.enable_logging()

# Allow browser to access specific website
manager.add_allow_rule("harombe-browser", "93.184.216.34", 443)

# Block code execution container
manager.block_all_egress("harombe-code-exec")
```

## Network Architecture

### Docker Network Layout

```
Network: harombe-network (172.20.0.0/16)
├── harombe-gateway      (172.20.0.2)   - Full internet access
├── harombe-browser      (172.20.0.3)   - Allowlist-based access
├── harombe-filesystem   (172.20.0.4)   - No network access
├── harombe-code-exec    (172.20.0.5)   - No network access
└── harombe-web-search   (172.20.0.6)   - Allowlist-based access
```

### iptables Chain Structure

```
FORWARD
  └── HAROMBE_FORWARD
      ├── ACCEPT (RELATED,ESTABLISHED)     # Stateful connections
      ├── ACCEPT (br-harombe -> br-harombe) # Inter-container
      ├── ACCEPT (DNS queries)              # UDP/TCP port 53
      ├── ACCEPT (Allowlist rules)          # Per-container rules
      └── DROP (Default)                    # Block everything else

LOG
  └── HAROMBE_LOG
      ├── LOG (rate limited)                # Log blocked packets
      └── NFLOG (if available)              # Userspace logging
```

## Security Considerations

### 1. Principle of Least Privilege

- Only grant minimum necessary network access
- Use port-specific rules instead of allowing all ports
- Regularly audit and remove unused rules

### 2. Defense in Depth

- Firewall rules are one layer of defense
- Combine with:
  - Docker security options (seccomp, AppArmor)
  - Read-only filesystem mounts
  - Resource limits
  - Capability dropping

### 3. DNS Resolution

- DNS queries (port 53) are allowed by default
- This is necessary for domain name resolution
- Use IP addresses directly for maximum security

### 4. Logging and Monitoring

- Enable logging to detect unauthorized access attempts
- Monitor logs regularly for suspicious activity
- Set up alerts for repeated blocked attempts

### 5. Stateful Connection Tracking

- Established connections are automatically allowed
- Return traffic doesn't need explicit rules
- Based on Linux connection tracking (conntrack)

## Troubleshooting

### Issue: Rules not working

```bash
# Check if chains exist
sudo iptables -L HAROMBE_FORWARD -n

# Check if jump rule exists
sudo iptables -L FORWARD -n | grep HAROMBE

# Reinitialize firewall
sudo ./firewall-rules.sh cleanup
sudo ./firewall-rules.sh init
```

### Issue: Container can't access allowed destination

```bash
# Verify container IP
docker inspect <container_name> | grep IPAddress

# Check rule exists
sudo iptables -L HAROMBE_FORWARD -n -v

# Check DNS resolution
docker exec <container_name> nslookup example.com

# Enable logging and check what's being blocked
sudo ./firewall-rules.sh enable-logging
sudo tail -f /var/log/harombe-firewall.log
```

### Issue: DNS not working

```bash
# Check DNS rules
sudo iptables -L HAROMBE_FORWARD -n | grep 53

# Test DNS from container
docker exec <container_name> dig example.com

# Check Docker DNS server
docker exec <container_name> cat /etc/resolv.conf
```

### Issue: Inter-container communication broken

```bash
# Verify bridge interface
ip link show | grep br-

# Check subnet
docker network inspect harombe-network

# Verify inter-container rule
sudo iptables -L HAROMBE_FORWARD -n | grep 172.20.0.0
```

## Performance Considerations

### 1. Rule Ordering

- Most frequently used rules should be near the top
- Use `iptables -I` (insert) vs `iptables -A` (append)
- Current script uses append for simplicity

### 2. Connection Tracking

- Stateful connections are faster (matched early)
- Reduces rule evaluation overhead
- Automatically enabled in script

### 3. Logging Rate Limiting

- Prevents log flooding attacks
- Limits to 10 packets/minute with burst of 20
- Adjustable in script configuration

### 4. IPv6

- Current script focuses on IPv4
- Extend with ip6tables for IPv6 support
- Use same chain structure for consistency

## Advanced Usage

### Custom Log File Location

```bash
# Set custom log file
export LOG_FILE=/var/log/custom-firewall.log
sudo ./firewall-rules.sh init
```

### Cleanup on Exit

```bash
# Automatically cleanup rules on script exit
export CLEANUP_ON_EXIT=true
sudo ./firewall-rules.sh init
```

### Integration with systemd

Create `/etc/systemd/system/harombe-firewall.service`:

```ini
[Unit]
Description=Harombe Firewall Rules
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/path/to/docker/firewall-rules.sh init
ExecStop=/path/to/docker/firewall-rules.sh cleanup

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable harombe-firewall
sudo systemctl start harombe-firewall
```

## Testing

### Unit Tests

```bash
# Test initialization
sudo ./firewall-rules.sh init
sudo ./firewall-rules.sh status

# Test adding rules
sudo ./firewall-rules.sh add harombe-browser 93.184.216.34 443
sudo iptables -L HAROMBE_FORWARD -n | grep 93.184.216.34

# Test removing rules
sudo ./firewall-rules.sh remove harombe-browser 93.184.216.34 443
sudo iptables -L HAROMBE_FORWARD -n | grep 93.184.216.34

# Test cleanup
sudo ./firewall-rules.sh cleanup
sudo iptables -L HAROMBE_FORWARD -n 2>&1 | grep "No chain"
```

### Integration Tests

```bash
# Start containers
docker-compose up -d

# Initialize firewall
sudo ./firewall-rules.sh init

# Test blocked access
docker exec harombe-browser curl -m 5 https://example.com
# Should timeout

# Add allow rule
sudo ./firewall-rules.sh add harombe-browser 93.184.216.34 443

# Test allowed access
docker exec harombe-browser curl -m 5 https://example.com
# Should succeed

# Check logs
sudo tail /var/log/harombe-firewall.log
```

## FAQ

**Q: Do I need to restart containers after adding rules?**
A: No, rules take effect immediately for new connections.

**Q: Can I use domain names instead of IP addresses?**
A: No, iptables works with IPs. Resolve domains to IPs first or use DNS-based filtering.

**Q: What happens if Docker restarts?**
A: Rules persist but may need reinitialization if network changes. Use systemd service.

**Q: Does this work with Kubernetes?**
A: This is designed for Docker. Kubernetes uses NetworkPolicies instead.

**Q: Can I rate-limit specific containers?**
A: Yes, extend the script with iptables rate limiting modules (`-m limit`).

**Q: How do I allow ICMP (ping)?**
A: Add custom rule: `iptables -A HAROMBE_FORWARD -p icmp -j ACCEPT`

## Contributing

Contributions are welcome! Please:

1. Test changes thoroughly
2. Update documentation
3. Follow existing code style
4. Add comments for complex logic

## License

This script is part of the Harombe project. See LICENSE file for details.

## Support

- GitHub Issues: https://github.com/yourusername/harombe/issues
- Documentation: https://harombe.readthedocs.io
- Email: support@harombe.dev
