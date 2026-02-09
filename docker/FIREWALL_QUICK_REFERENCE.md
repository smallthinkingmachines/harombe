# Harombe Firewall - Quick Reference Card

## Quick Start

```bash
# 1. Initialize firewall
sudo ./firewall-rules.sh init

# 2. Enable logging
sudo ./firewall-rules.sh enable-logging

# 3. Add rules for your containers
sudo ./firewall-rules.sh add harombe-browser 93.184.216.34 443

# 4. Check status
sudo ./firewall-rules.sh status
```

## Common Commands

| Command                          | Description                    | Example                                                             |
| -------------------------------- | ------------------------------ | ------------------------------------------------------------------- |
| `init`                           | Initialize firewall            | `sudo ./firewall-rules.sh init`                                     |
| `add <container> <ip> [port]`    | Allow container -> destination | `sudo ./firewall-rules.sh add harombe-browser 93.184.216.34 443`    |
| `remove <container> <ip> [port]` | Remove allow rule              | `sudo ./firewall-rules.sh remove harombe-browser 93.184.216.34 443` |
| `block-all <container>`          | Block all egress               | `sudo ./firewall-rules.sh block-all harombe-code-exec`              |
| `enable-logging`                 | Enable logging                 | `sudo ./firewall-rules.sh enable-logging`                           |
| `disable-logging`                | Disable logging                | `sudo ./firewall-rules.sh disable-logging`                          |
| `status`                         | Show current rules             | `sudo ./firewall-rules.sh status`                                   |
| `cleanup`                        | Remove all rules               | `sudo ./firewall-rules.sh cleanup`                                  |
| `help`                           | Show help                      | `./firewall-rules.sh help`                                          |

## Common Use Cases

### 1. Allow Browser to Access Website

```bash
# Resolve domain to IP
IP=$(dig +short example.com | head -1)

# Add HTTPS rule
sudo ./firewall-rules.sh add harombe-browser $IP 443

# Add HTTP rule (if needed)
sudo ./firewall-rules.sh add harombe-browser $IP 80
```

### 2. Allow Access to Subnet

```bash
# Allow access to entire private network
sudo ./firewall-rules.sh add harombe-web-search 10.0.0.0/8

# Allow access to specific subnet
sudo ./firewall-rules.sh add harombe-web-search 192.168.1.0/24
```

### 3. Lockdown Code Execution Container

```bash
# Block all external network access
sudo ./firewall-rules.sh block-all harombe-code-exec

# Container can still communicate with other containers in the network
```

### 4. Allow API Access with Multiple Endpoints

```bash
# Add rules for each API endpoint
sudo ./firewall-rules.sh add harombe-web-search 52.1.2.3 8080
sudo ./firewall-rules.sh add harombe-web-search 52.1.2.4 8080
sudo ./firewall-rules.sh add harombe-web-search 52.1.2.5 8080
```

### 5. Temporary Access

```bash
# Add temporary rule
sudo ./firewall-rules.sh add harombe-browser 203.0.113.50 443

# Do your work...

# Remove rule when done
sudo ./firewall-rules.sh remove harombe-browser 203.0.113.50 443
```

## Container Network Map

```
Container               | IP Address    | Default Policy
------------------------|---------------|----------------
harombe-gateway         | 172.20.0.2    | Allow all
harombe-browser         | 172.20.0.3    | Deny all (allowlist)
harombe-filesystem      | 172.20.0.4    | No network
harombe-code-exec       | 172.20.0.5    | No network
harombe-web-search      | 172.20.0.6    | Deny all (allowlist)
```

## Logging

### View Real-time Logs

```bash
# Tail firewall log file
sudo tail -f /var/log/harombe-firewall.log

# View syslog
sudo journalctl -f -t harombe-firewall

# View kernel logs for iptables
sudo dmesg -w | grep "HAROMBE"
```

### Log Format

```
[HAROMBE-FW] BLOCKED: IN=br-harombe OUT=eth0 SRC=172.20.0.3 DST=93.184.216.34 PROTO=TCP DPT=443
```

Fields:

- `IN`: Incoming interface
- `OUT`: Outgoing interface
- `SRC`: Source IP (container)
- `DST`: Destination IP
- `PROTO`: Protocol (TCP/UDP)
- `DPT`: Destination port

## Troubleshooting

### Container Can't Connect

1. **Check container IP:**

   ```bash
   docker inspect harombe-browser | grep IPAddress
   ```

2. **Verify rule exists:**

   ```bash
   sudo iptables -L HAROMBE_FORWARD -n -v | grep <destination_ip>
   ```

3. **Enable logging and watch:**

   ```bash
   sudo ./firewall-rules.sh enable-logging
   sudo tail -f /var/log/harombe-firewall.log
   ```

4. **Test connection from container:**
   ```bash
   docker exec harombe-browser curl -v -m 5 https://example.com
   ```

### DNS Issues

```bash
# Check DNS rules
sudo iptables -L HAROMBE_FORWARD -n | grep 53

# Test DNS from container
docker exec harombe-browser nslookup example.com

# Add explicit DNS rule if needed
sudo ./firewall-rules.sh add harombe-browser 8.8.8.8 53
```

### Rules Not Working

```bash
# Check if chains exist
sudo iptables -L HAROMBE_FORWARD -n

# Reinitialize
sudo ./firewall-rules.sh cleanup
sudo ./firewall-rules.sh init

# Verify jump rule
sudo iptables -L FORWARD -n | grep HAROMBE
```

### Performance Issues

```bash
# Check number of rules
sudo iptables -L HAROMBE_FORWARD -n | wc -l

# Too many rules? Consider using CIDR blocks instead of individual IPs

# Check connection tracking
sudo conntrack -L | wc -l
```

## iptables Commands

### Manual Rule Inspection

```bash
# List all rules with line numbers
sudo iptables -L HAROMBE_FORWARD -n -v --line-numbers

# Show rules for specific container IP
sudo iptables -L HAROMBE_FORWARD -n | grep 172.20.0.3

# Count rules
sudo iptables -L HAROMBE_FORWARD -n | grep -c ACCEPT
```

### Save/Restore Rules

```bash
# Save current rules
sudo iptables-save > /tmp/firewall-backup.rules

# Restore rules
sudo iptables-restore < /tmp/firewall-backup.rules
```

## Python Integration

### Basic Usage

```python
from network_isolation import NetworkIsolationManager

manager = NetworkIsolationManager()
manager.initialize_firewall()
manager.enable_logging()

# Add rule
manager.add_allow_rule("harombe-browser", "93.184.216.34", 443)

# Block all
manager.block_all_egress("harombe-code-exec")

# Get status
print(manager.get_status())
```

### Batch Operations

```python
# Apply multiple rules at once
allowlist = [
    {"ip": "93.184.216.34", "port": 443},
    {"ip": "8.8.8.8", "port": 53},
    {"ip": "10.0.0.0/8"},
]
manager.apply_allowlist("harombe-browser", allowlist)
```

## Configuration Files

### Environment Variables

```bash
# Set custom log file
export LOG_FILE=/var/log/custom-firewall.log

# Enable cleanup on exit
export CLEANUP_ON_EXIT=true
```

### systemd Service

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

Enable:

```bash
sudo systemctl daemon-reload
sudo systemctl enable harombe-firewall
sudo systemctl start harombe-firewall
```

## Security Best Practices

1. **Principle of Least Privilege**
   - Only allow required destinations
   - Use port-specific rules when possible
   - Regularly audit and remove unused rules

2. **Use CIDR Blocks**
   - Group IPs into subnets when possible
   - Reduces rule count and improves performance

3. **Enable Logging**
   - Monitor for unauthorized access attempts
   - Set up alerts for repeated blocks

4. **Regular Audits**
   - Review rules monthly
   - Remove rules for decommissioned services
   - Update IP addresses for migrated services

5. **Test in Non-Production**
   - Test rules before production deployment
   - Verify no legitimate traffic is blocked
   - Have rollback plan ready

## Performance Optimization

### Rule Ordering

```bash
# Most frequently used rules first
# (manual insertion at specific position)
sudo iptables -I HAROMBE_FORWARD 1 -s 172.20.0.3 -d 93.184.216.34 -j ACCEPT
```

### CIDR Consolidation

```bash
# Instead of multiple single IPs
# 10.0.0.1, 10.0.0.2, 10.0.0.3...

# Use CIDR block
sudo ./firewall-rules.sh add harombe-browser 10.0.0.0/24
```

### Connection Tracking

```bash
# Check conntrack table size
sudo sysctl net.netfilter.nf_conntrack_max

# Increase if needed
sudo sysctl -w net.netfilter.nf_conntrack_max=262144
```

## Common IP Addresses

| Service        | IP Address       | Ports   |
| -------------- | ---------------- | ------- |
| Google DNS     | 8.8.8.8, 8.8.4.4 | 53      |
| Cloudflare DNS | 1.1.1.1, 1.0.0.1 | 53      |
| Example.com    | 93.184.216.34    | 80, 443 |
| GitHub         | 140.82.113.0/24  | 443     |
| Docker Hub     | 104.18.121.25    | 443     |

## Additional Resources

- Full Documentation: `FIREWALL_README.md`
- Test Script: `test-firewall.sh`
- Python Integration: `python-integration-example.py`
- Project Repository: https://github.com/yourusername/harombe
- iptables Tutorial: https://www.netfilter.org/documentation/

## Support

**Issues?** Run diagnostics:

```bash
sudo ./firewall-rules.sh status
sudo ./test-firewall.sh
```

**Still stuck?** Check logs:

```bash
sudo tail -50 /var/log/harombe-firewall.log
sudo journalctl -u harombe-firewall -n 50
```

**Need help?** Open an issue on GitHub with:

- Output of `sudo ./firewall-rules.sh status`
- Relevant log entries
- Container configuration
- Steps to reproduce
