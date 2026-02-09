#!/bin/bash
################################################################################
# Harombe Firewall Rules - Test Script
#
# This script demonstrates the usage of firewall-rules.sh and performs
# basic functionality tests.
#
# Usage: sudo ./test-firewall.sh
################################################################################

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIREWALL_SCRIPT="${SCRIPT_DIR}/firewall-rules.sh"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_test() {
    echo -e "${BLUE}[TEST]${NC} $*"
}

print_pass() {
    echo -e "${GREEN}[PASS]${NC} $*"
}

print_fail() {
    echo -e "${RED}[FAIL]${NC} $*"
}

print_info() {
    echo -e "${YELLOW}[INFO]${NC} $*"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}This script must be run as root${NC}"
    exit 1
fi

echo -e "\n${BLUE}========================================${NC}"
echo -e "${BLUE}Harombe Firewall Rules - Test Suite${NC}"
echo -e "${BLUE}========================================${NC}\n"

# Test 1: Script exists and is executable
print_test "Checking if firewall script exists and is executable"
if [[ -x "$FIREWALL_SCRIPT" ]]; then
    print_pass "Script found: ${FIREWALL_SCRIPT}"
else
    print_fail "Script not found or not executable"
    exit 1
fi

# Test 2: Show help
print_test "Testing help command"
if "$FIREWALL_SCRIPT" help &>/dev/null; then
    print_pass "Help command works"
else
    print_fail "Help command failed"
fi

# Test 3: Check prerequisites
print_test "Checking prerequisites"

# Check iptables
if command -v iptables &>/dev/null; then
    print_pass "iptables installed"
else
    print_fail "iptables not found"
    exit 1
fi

# Check Docker
if command -v docker &>/dev/null; then
    print_pass "Docker installed"
else
    print_fail "Docker not found"
    print_info "Docker is required for full testing"
fi

# Test 4: Check Docker network
print_test "Checking Docker network"
if docker network inspect harombe-network &>/dev/null; then
    print_pass "harombe-network exists"
else
    print_fail "harombe-network not found"
    print_info "Creating harombe-network..."
    docker network create --driver bridge --subnet 172.20.0.0/16 harombe-network || {
        print_fail "Failed to create network"
        exit 1
    }
    print_pass "harombe-network created"
fi

# Test 5: Initialize firewall
print_test "Initializing firewall"
if "$FIREWALL_SCRIPT" init; then
    print_pass "Firewall initialized"
else
    print_fail "Firewall initialization failed"
    exit 1
fi

# Test 6: Check if chains were created
print_test "Verifying custom chains"
chains=("HAROMBE_FORWARD" "HAROMBE_INPUT" "HAROMBE_OUTPUT" "HAROMBE_LOG")
for chain in "${chains[@]}"; do
    if iptables -L "$chain" -n &>/dev/null; then
        print_pass "Chain exists: ${chain}"
    else
        print_fail "Chain not found: ${chain}"
    fi
done

# Test 7: Enable logging
print_test "Enabling logging"
if "$FIREWALL_SCRIPT" enable-logging; then
    print_pass "Logging enabled"
else
    print_fail "Failed to enable logging"
fi

# Test 8: Show status
print_test "Checking firewall status"
echo ""
if "$FIREWALL_SCRIPT" status; then
    echo ""
    print_pass "Status command works"
else
    print_fail "Status command failed"
fi

# Test 9: Test with actual containers (if available)
print_test "Testing with Docker containers"
if docker ps --format '{{.Names}}' | grep -q "harombe-"; then
    CONTAINER_NAME=$(docker ps --format '{{.Names}}' | grep "harombe-" | head -1)
    print_info "Found container: ${CONTAINER_NAME}"

    # Test add rule
    print_test "Adding allow rule"
    if "$FIREWALL_SCRIPT" add "$CONTAINER_NAME" 93.184.216.34 443; then
        print_pass "Rule added successfully"

        # Verify rule exists
        if iptables -L HAROMBE_FORWARD -n | grep -q 93.184.216.34; then
            print_pass "Rule verified in iptables"
        else
            print_fail "Rule not found in iptables"
        fi

        # Test remove rule
        print_test "Removing allow rule"
        if "$FIREWALL_SCRIPT" remove "$CONTAINER_NAME" 93.184.216.34 443; then
            print_pass "Rule removed successfully"
        else
            print_fail "Failed to remove rule"
        fi
    else
        print_fail "Failed to add rule"
    fi
else
    print_info "No Harombe containers running, skipping container tests"
    print_info "Start containers with: docker-compose up -d"
fi

# Test 10: Cleanup
print_test "Testing cleanup"
if "$FIREWALL_SCRIPT" cleanup; then
    print_pass "Cleanup successful"

    # Verify chains are gone
    if ! iptables -L HAROMBE_FORWARD -n &>/dev/null; then
        print_pass "Chains removed successfully"
    else
        print_fail "Chains still exist after cleanup"
    fi
else
    print_fail "Cleanup failed"
fi

# Summary
echo -e "\n${BLUE}========================================${NC}"
echo -e "${GREEN}Test suite completed!${NC}"
echo -e "${BLUE}========================================${NC}\n"

print_info "Next steps:"
echo "  1. Start containers: cd ${SCRIPT_DIR} && docker-compose up -d"
echo "  2. Initialize firewall: sudo ${FIREWALL_SCRIPT} init"
echo "  3. Add rules: sudo ${FIREWALL_SCRIPT} add <container> <ip> [port]"
echo "  4. Monitor logs: sudo tail -f /var/log/harombe-firewall.log"
echo ""
