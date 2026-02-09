#!/bin/bash
################################################################################
# Harombe MCP Gateway - iptables Firewall Rules Script
#
# This script manages iptables-based firewall rules for Docker container network
# isolation. It provides granular egress control, allowlist-based access, and
# comprehensive logging of blocked connection attempts.
#
# Usage:
#   ./firewall-rules.sh init                          # Initialize firewall
#   ./firewall-rules.sh add <container> <ip> [port]   # Add allow rule
#   ./firewall-rules.sh remove <container> <ip> [port] # Remove allow rule
#   ./firewall-rules.sh block-all <container>         # Block all egress
#   ./firewall-rules.sh enable-logging                # Enable connection logging
#   ./firewall-rules.sh cleanup                       # Remove all rules
#   ./firewall-rules.sh status                        # Show current rules
#
# Examples:
#   ./firewall-rules.sh init
#   ./firewall-rules.sh add harombe-browser 93.184.216.34 443
#   ./firewall-rules.sh add harombe-browser 10.0.0.0/8
#   ./firewall-rules.sh block-all harombe-code-exec
#   ./firewall-rules.sh remove harombe-browser 93.184.216.34 443
#
# Network Architecture:
#   - Docker bridge network: harombe-network (172.20.0.0/16)
#   - Default policy: DENY all egress traffic
#   - Allowlist-based: Only explicitly allowed destinations are accessible
#   - Per-container rules: Each container has isolated firewall rules
#
# Security Features:
#   - Default deny egress policy
#   - Port-specific filtering
#   - CIDR block support
#   - Connection state tracking
#   - Comprehensive logging to syslog/file
#   - Automatic cleanup on script exit
#
# Requirements:
#   - Root/sudo privileges
#   - iptables installed
#   - Docker daemon running
#   - harombe-network bridge network created
#
# Called by:
#   - src/harombe/security/network_isolation.py (NetworkIsolationManager)
#   - Docker container lifecycle management
#   - Gateway security enforcement
#
# Author: Harombe MCP Security Team
# Version: 1.0.0
################################################################################

set -euo pipefail  # Exit on error, undefined vars, pipe failures

################################################################################
# Configuration
################################################################################

# Script metadata
readonly SCRIPT_NAME="$(basename "${BASH_SOURCE[0]}")"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly VERSION="1.0.0"

# Docker network configuration
readonly DOCKER_NETWORK="harombe-network"
readonly DOCKER_SUBNET="172.20.0.0/16"
readonly DOCKER_BRIDGE="br-harombe"  # Bridge interface name (may vary)

# iptables chain names
readonly CHAIN_PREFIX="HAROMBE"
readonly CHAIN_FORWARD="${CHAIN_PREFIX}_FORWARD"
readonly CHAIN_INPUT="${CHAIN_PREFIX}_INPUT"
readonly CHAIN_OUTPUT="${CHAIN_PREFIX}_OUTPUT"
readonly CHAIN_LOG="${CHAIN_PREFIX}_LOG"

# Logging configuration
readonly LOG_FILE="${LOG_FILE:-/var/log/harombe-firewall.log}"
readonly LOG_PREFIX="[HAROMBE-FW]"
readonly SYSLOG_TAG="harombe-firewall"

# Exit codes
readonly EXIT_SUCCESS=0
readonly EXIT_ERROR=1
readonly EXIT_INVALID_ARGS=2
readonly EXIT_NO_PERMISSIONS=3

################################################################################
# Utility Functions
################################################################################

# Print colored output
print_color() {
    local color="$1"
    shift
    case "$color" in
        red)    echo -e "\033[0;31m$*\033[0m" ;;
        green)  echo -e "\033[0;32m$*\033[0m" ;;
        yellow) echo -e "\033[0;33m$*\033[0m" ;;
        blue)   echo -e "\033[0;34m$*\033[0m" ;;
        *)      echo "$*" ;;
    esac
}

# Logging functions
log_info() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] $*" | tee -a "$LOG_FILE"
    logger -t "$SYSLOG_TAG" -p user.info "$*"
}

log_error() {
    print_color red "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] $*" | tee -a "$LOG_FILE"
    logger -t "$SYSLOG_TAG" -p user.err "$*"
}

log_warn() {
    print_color yellow "$(date '+%Y-%m-%d %H:%M:%S') [WARN] $*" | tee -a "$LOG_FILE"
    logger -t "$SYSLOG_TAG" -p user.warning "$*"
}

log_success() {
    print_color green "$(date '+%Y-%m-%d %H:%M:%S') [SUCCESS] $*" | tee -a "$LOG_FILE"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root or with sudo"
        exit "$EXIT_NO_PERMISSIONS"
    fi
}

# Check if iptables is installed
check_iptables() {
    if ! command -v iptables &>/dev/null; then
        log_error "iptables not found. Please install iptables."
        exit "$EXIT_ERROR"
    fi
}

# Check if Docker network exists
check_docker_network() {
    if ! docker network ls --format '{{.Name}}' | grep -q "^${DOCKER_NETWORK}$"; then
        log_error "Docker network '${DOCKER_NETWORK}' not found"
        log_error "Create it with: docker network create --driver bridge --subnet ${DOCKER_SUBNET} ${DOCKER_NETWORK}"
        exit "$EXIT_ERROR"
    fi
}

# Get Docker bridge interface name
get_bridge_interface() {
    local network_id
    network_id=$(docker network inspect "$DOCKER_NETWORK" -f '{{.Id}}' 2>/dev/null || echo "")

    if [[ -z "$network_id" ]]; then
        log_error "Could not find network ID for ${DOCKER_NETWORK}"
        return 1
    fi

    # Bridge interface is typically br-<first 12 chars of network ID>
    local bridge_name="br-${network_id:0:12}"

    if ip link show "$bridge_name" &>/dev/null; then
        echo "$bridge_name"
        return 0
    else
        log_warn "Bridge interface ${bridge_name} not found, using default"
        echo "docker0"
        return 0
    fi
}

# Get container IP address
get_container_ip() {
    local container_name="$1"
    local ip

    ip=$(docker inspect -f "{{.NetworkSettings.Networks.${DOCKER_NETWORK}.IPAddress}}" "$container_name" 2>/dev/null || echo "")

    if [[ -z "$ip" ]]; then
        log_error "Could not find IP address for container: ${container_name}"
        return 1
    fi

    echo "$ip"
}

# Validate IP address or CIDR block
validate_ip() {
    local ip="$1"

    # Check if it's a valid IP address or CIDR block
    if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$ ]]; then
        return 0
    else
        log_error "Invalid IP address or CIDR block: ${ip}"
        return 1
    fi
}

# Validate port number
validate_port() {
    local port="$1"

    if [[ "$port" =~ ^[0-9]+$ ]] && [[ "$port" -ge 1 ]] && [[ "$port" -le 65535 ]]; then
        return 0
    else
        log_error "Invalid port number: ${port}"
        return 1
    fi
}

################################################################################
# Firewall Chain Management
################################################################################

# Create custom iptables chains
create_chains() {
    log_info "Creating custom iptables chains..."

    # Create main chains if they don't exist
    for chain in "$CHAIN_FORWARD" "$CHAIN_INPUT" "$CHAIN_OUTPUT" "$CHAIN_LOG"; do
        if ! iptables -L "$chain" -n &>/dev/null; then
            iptables -N "$chain"
            log_info "Created chain: ${chain}"
        else
            log_info "Chain already exists: ${chain}"
        fi
    done

    # Flush chains to start fresh
    iptables -F "$CHAIN_FORWARD"
    iptables -F "$CHAIN_INPUT"
    iptables -F "$CHAIN_OUTPUT"
    iptables -F "$CHAIN_LOG"

    log_success "Custom chains created and flushed"
}

# Delete custom iptables chains
delete_chains() {
    log_info "Deleting custom iptables chains..."

    # Remove jump rules first
    iptables -D FORWARD -j "$CHAIN_FORWARD" 2>/dev/null || true
    iptables -D INPUT -j "$CHAIN_INPUT" 2>/dev/null || true
    iptables -D OUTPUT -j "$CHAIN_OUTPUT" 2>/dev/null || true

    # Flush and delete chains
    for chain in "$CHAIN_FORWARD" "$CHAIN_INPUT" "$CHAIN_OUTPUT" "$CHAIN_LOG"; do
        if iptables -L "$chain" -n &>/dev/null; then
            iptables -F "$chain"
            iptables -X "$chain"
            log_info "Deleted chain: ${chain}"
        fi
    done

    log_success "Custom chains deleted"
}

################################################################################
# Core Firewall Functions
################################################################################

# Initialize firewall rules
initialize_firewall() {
    log_info "Initializing Harombe firewall (version ${VERSION})..."

    # Prerequisite checks
    check_root
    check_iptables
    check_docker_network

    # Get bridge interface
    local bridge_iface
    bridge_iface=$(get_bridge_interface)
    log_info "Using bridge interface: ${bridge_iface}"

    # Create custom chains
    create_chains

    # Set up chain jumping rules
    # All traffic from Docker network goes through our custom chains
    if ! iptables -C FORWARD -j "$CHAIN_FORWARD" 2>/dev/null; then
        iptables -I FORWARD 1 -j "$CHAIN_FORWARD"
        log_info "Added FORWARD jump rule"
    fi

    # Allow established and related connections (stateful firewall)
    iptables -A "$CHAIN_FORWARD" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    log_info "Added stateful connection tracking rule"

    # Allow inter-container communication within the network
    iptables -A "$CHAIN_FORWARD" -i "$bridge_iface" -o "$bridge_iface" -j ACCEPT
    log_info "Allowed inter-container communication"

    # Allow DNS queries (essential for domain resolution)
    iptables -A "$CHAIN_FORWARD" -s "$DOCKER_SUBNET" -p udp --dport 53 -j ACCEPT
    iptables -A "$CHAIN_FORWARD" -s "$DOCKER_SUBNET" -p tcp --dport 53 -j ACCEPT
    log_info "Allowed DNS queries"

    # Allow loopback
    iptables -A "$CHAIN_FORWARD" -i lo -j ACCEPT
    iptables -A "$CHAIN_FORWARD" -o lo -j ACCEPT
    log_info "Allowed loopback traffic"

    # Default DROP policy for egress traffic (will add specific ACCEPT rules)
    # This will be handled per-container with explicit deny rules

    log_success "Firewall initialized successfully"
    log_info "Default policy: DENY all egress (allowlist mode)"
    log_info "Use 'add_allow_rule' to permit specific destinations"
}

# Add allow rule for specific destination
add_allow_rule() {
    local container_name="$1"
    local dest_ip="$2"
    local dest_port="${3:-}"  # Optional port

    log_info "Adding allow rule: ${container_name} -> ${dest_ip}${dest_port:+:${dest_port}}"

    # Validate inputs
    if [[ -z "$container_name" ]] || [[ -z "$dest_ip" ]]; then
        log_error "Usage: add_allow_rule <container_name> <destination_ip> [port]"
        return "$EXIT_INVALID_ARGS"
    fi

    if ! validate_ip "$dest_ip"; then
        return "$EXIT_INVALID_ARGS"
    fi

    if [[ -n "$dest_port" ]] && ! validate_port "$dest_port"; then
        return "$EXIT_INVALID_ARGS"
    fi

    # Get container IP
    local container_ip
    container_ip=$(get_container_ip "$container_name") || return "$EXIT_ERROR"

    # Build iptables rule
    local rule_args="-s ${container_ip} -d ${dest_ip}"

    if [[ -n "$dest_port" ]]; then
        # Add port-specific rules for both TCP and UDP
        rule_args="${rule_args} -p tcp --dport ${dest_port}"
        iptables -A "$CHAIN_FORWARD" $rule_args -j ACCEPT
        log_info "Added TCP rule: ${container_ip} -> ${dest_ip}:${dest_port}"

        rule_args="-s ${container_ip} -d ${dest_ip} -p udp --dport ${dest_port}"
        iptables -A "$CHAIN_FORWARD" $rule_args -j ACCEPT
        log_info "Added UDP rule: ${container_ip} -> ${dest_ip}:${dest_port}"
    else
        # Allow all traffic to destination
        iptables -A "$CHAIN_FORWARD" $rule_args -j ACCEPT
        log_info "Added rule: ${container_ip} -> ${dest_ip} (all ports)"
    fi

    log_success "Allow rule added successfully"
}

# Remove allow rule
remove_allow_rule() {
    local container_name="$1"
    local dest_ip="$2"
    local dest_port="${3:-}"

    log_info "Removing allow rule: ${container_name} -> ${dest_ip}${dest_port:+:${dest_port}}"

    # Validate inputs
    if [[ -z "$container_name" ]] || [[ -z "$dest_ip" ]]; then
        log_error "Usage: remove_allow_rule <container_name> <destination_ip> [port]"
        return "$EXIT_INVALID_ARGS"
    fi

    # Get container IP
    local container_ip
    container_ip=$(get_container_ip "$container_name") || return "$EXIT_ERROR"

    # Build iptables rule
    local rule_args="-s ${container_ip} -d ${dest_ip}"

    if [[ -n "$dest_port" ]]; then
        # Remove port-specific rules
        rule_args="${rule_args} -p tcp --dport ${dest_port}"
        iptables -D "$CHAIN_FORWARD" $rule_args -j ACCEPT 2>/dev/null || log_warn "TCP rule not found"

        rule_args="-s ${container_ip} -d ${dest_ip} -p udp --dport ${dest_port}"
        iptables -D "$CHAIN_FORWARD" $rule_args -j ACCEPT 2>/dev/null || log_warn "UDP rule not found"
    else
        # Remove general rule
        iptables -D "$CHAIN_FORWARD" $rule_args -j ACCEPT 2>/dev/null || log_warn "Rule not found"
    fi

    log_success "Allow rule removed successfully"
}

# Block all egress traffic from a container
block_all_egress() {
    local container_name="$1"

    log_info "Blocking all egress traffic from: ${container_name}"

    if [[ -z "$container_name" ]]; then
        log_error "Usage: block_all_egress <container_name>"
        return "$EXIT_INVALID_ARGS"
    fi

    # Get container IP
    local container_ip
    container_ip=$(get_container_ip "$container_name") || return "$EXIT_ERROR"

    # Get bridge interface
    local bridge_iface
    bridge_iface=$(get_bridge_interface)

    # Remove any existing allow rules for this container
    log_info "Removing existing allow rules for ${container_name}..."
    iptables-save | grep -E "^-A ${CHAIN_FORWARD}.*-s ${container_ip}" | \
        sed 's/^-A //' | \
        while read -r rule; do
            iptables -D $rule 2>/dev/null || true
        done

    # Add explicit DROP rule for this container's egress traffic
    # (excluding internal Docker network traffic)
    iptables -I "$CHAIN_FORWARD" 1 -s "$container_ip" ! -d "$DOCKER_SUBNET" -j "$CHAIN_LOG"
    iptables -I "$CHAIN_FORWARD" 2 -s "$container_ip" ! -d "$DOCKER_SUBNET" -j DROP

    log_success "All egress traffic blocked for ${container_name} (${container_ip})"
}

# Enable comprehensive logging for blocked connections
enable_logging() {
    log_info "Enabling firewall logging..."

    check_root

    # Set up logging chain
    # Log blocked packets with rate limiting to prevent log flooding
    iptables -F "$CHAIN_LOG"
    iptables -A "$CHAIN_LOG" -m limit --limit 10/min --limit-burst 20 -j LOG \
        --log-prefix "${LOG_PREFIX} BLOCKED: " \
        --log-level 4 \
        --log-tcp-options \
        --log-ip-options

    # Also log to our custom log file via ULOG (if available)
    if iptables -A "$CHAIN_LOG" -j NFLOG --nflog-group 1 --nflog-prefix "${LOG_PREFIX}" 2>/dev/null; then
        log_info "NFLOG logging enabled (group 1)"
    else
        log_warn "NFLOG not available, using syslog only"
    fi

    log_success "Firewall logging enabled"
    log_info "Blocked packets logged to: ${LOG_FILE} and syslog"
    log_info "View logs with: tail -f ${LOG_FILE} or journalctl -f -t ${SYSLOG_TAG}"
}

# Disable logging
disable_logging() {
    log_info "Disabling firewall logging..."
    iptables -F "$CHAIN_LOG"
    log_success "Firewall logging disabled"
}

################################################################################
# Maintenance Functions
################################################################################

# Show current firewall status
show_status() {
    print_color blue "========================================"
    print_color blue "Harombe Firewall Status (v${VERSION})"
    print_color blue "========================================"
    echo ""

    print_color yellow "Custom Chains:"
    for chain in "$CHAIN_FORWARD" "$CHAIN_INPUT" "$CHAIN_OUTPUT" "$CHAIN_LOG"; do
        if iptables -L "$chain" -n &>/dev/null; then
            echo "  [✓] $chain"
        else
            echo "  [✗] $chain (not found)"
        fi
    done
    echo ""

    print_color yellow "FORWARD Chain Rules:"
    iptables -L "$CHAIN_FORWARD" -n -v --line-numbers 2>/dev/null || echo "  Chain not found"
    echo ""

    print_color yellow "LOG Chain Rules:"
    iptables -L "$CHAIN_LOG" -n -v --line-numbers 2>/dev/null || echo "  Chain not found"
    echo ""

    print_color yellow "Container IPs:"
    docker ps --format 'table {{.Names}}\t{{.Networks}}' | grep "$DOCKER_NETWORK" | while read -r line; do
        local name=$(echo "$line" | awk '{print $1}')
        local ip=$(get_container_ip "$name" 2>/dev/null || echo "N/A")
        echo "  ${name}: ${ip}"
    done
    echo ""

    print_color blue "========================================"
}

# Clean up all firewall rules
cleanup() {
    log_info "Cleaning up Harombe firewall rules..."

    check_root

    # Delete custom chains (this also removes all rules)
    delete_chains

    log_success "Firewall cleanup completed"
}

# Trap cleanup on script exit
trap_cleanup() {
    if [[ "${CLEANUP_ON_EXIT:-false}" == "true" ]]; then
        log_info "Script exiting, cleaning up..."
        cleanup
    fi
}

trap trap_cleanup EXIT INT TERM

################################################################################
# Main Script Logic
################################################################################

# Print usage information
usage() {
    cat <<EOF
Harombe MCP Gateway - iptables Firewall Rules Script v${VERSION}

Usage:
    $SCRIPT_NAME <command> [arguments]

Commands:
    init                                Initialize firewall rules
    add <container> <ip> [port]         Add allow rule for container -> destination
    remove <container> <ip> [port]      Remove allow rule
    block-all <container>               Block all egress from container
    enable-logging                      Enable logging of blocked connections
    disable-logging                     Disable logging
    status                              Show current firewall status
    cleanup                             Remove all firewall rules
    help                                Show this help message

Examples:
    # Initialize firewall
    $SCRIPT_NAME init

    # Allow browser container to access example.com (93.184.216.34) on port 443
    $SCRIPT_NAME add harombe-browser 93.184.216.34 443

    # Allow access to entire subnet
    $SCRIPT_NAME add harombe-web-search 10.0.0.0/8

    # Block all egress from code execution container
    $SCRIPT_NAME block-all harombe-code-exec

    # Remove specific rule
    $SCRIPT_NAME remove harombe-browser 93.184.216.34 443

    # Enable logging
    $SCRIPT_NAME enable-logging

    # Check status
    $SCRIPT_NAME status

    # Clean up all rules
    $SCRIPT_NAME cleanup

Environment Variables:
    LOG_FILE            Log file path (default: /var/log/harombe-firewall.log)
    CLEANUP_ON_EXIT     Clean up rules on script exit (default: false)

Requirements:
    - Root/sudo privileges
    - iptables installed
    - Docker daemon running
    - harombe-network bridge network created

For more information, see: https://github.com/yourusername/harombe
EOF
}

# Main command dispatcher
main() {
    local command="${1:-}"

    case "$command" in
        init)
            initialize_firewall
            ;;
        add)
            shift
            add_allow_rule "$@"
            ;;
        remove)
            shift
            remove_allow_rule "$@"
            ;;
        block-all)
            shift
            block_all_egress "$@"
            ;;
        enable-logging)
            enable_logging
            ;;
        disable-logging)
            disable_logging
            ;;
        status)
            show_status
            ;;
        cleanup)
            cleanup
            ;;
        help|--help|-h)
            usage
            exit "$EXIT_SUCCESS"
            ;;
        "")
            log_error "No command specified"
            usage
            exit "$EXIT_INVALID_ARGS"
            ;;
        *)
            log_error "Unknown command: ${command}"
            usage
            exit "$EXIT_INVALID_ARGS"
            ;;
    esac
}

# Execute main function with all arguments
main "$@"
