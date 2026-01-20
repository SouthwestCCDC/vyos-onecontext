#!/bin/bash
# DNS diagnostic script for QEMU SLIRP networking
# Run this inside the nested VM to understand DNS behavior
#
# KEY INSIGHT: deployment builds use 10.0.2.3 (SLIRP proxy) and are more reliable.
# vyos-onecontext uses 8.8.8.8 (direct). This script compares both approaches.

set -x  # Echo all commands

echo "=== DNS DIAGNOSTIC START ==="
echo "Timestamp: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
echo

echo "=== Network interfaces ==="
ip addr show
echo

echo "=== Routing table ==="
ip route show
echo

echo "=== ARP table ==="
ip neigh show
echo

echo "=== resolv.conf (current) ==="
cat /etc/resolv.conf
echo

echo "=== gai.conf (address selection) ==="
cat /etc/gai.conf 2>/dev/null || echo "(no gai.conf)"
echo

# Note: ICMP doesn't work in SLIRP, so these will fail - that's expected
echo "=== Testing ICMP (expected to fail in SLIRP) ==="
ping -c 1 -W 2 10.0.2.2 2>&1 || echo "ICMP to gateway failed (expected in SLIRP)"
ping -c 1 -W 2 8.8.8.8 2>&1 || echo "ICMP to 8.8.8.8 failed (expected in SLIRP)"
echo

echo "=== DETAILED NETWORK STATE ==="
echo "--- Default route ---"
ip route show default
echo
echo "--- All routes ---"
ip route show
echo
echo "--- ARP/neighbor cache ---"
ip neigh show
echo

echo "=== GATEWAY CONNECTIVITY TEST ==="
echo "SLIRP gateway should be 10.0.2.2"
echo "--- Attempting to reach gateway via TCP (port 80, won't connect but tests routing) ---"
timeout 2 bash -c 'echo > /dev/tcp/10.0.2.2/80' 2>&1 && echo "TCP to gateway succeeded" || echo "TCP to gateway: $?"
echo

echo "=== EXTERNAL CONNECTIVITY TESTS ==="
echo "--- TCP to 8.8.8.8:53 ---"
timeout 5 bash -c 'echo > /dev/tcp/8.8.8.8/53' 2>&1 && echo "TCP to 8.8.8.8:53 is OPEN" || echo "TCP to 8.8.8.8:53 FAILED: exit $?"
echo "--- TCP to 8.8.8.8:443 ---"
timeout 5 bash -c 'echo > /dev/tcp/8.8.8.8/443' 2>&1 && echo "TCP to 8.8.8.8:443 is OPEN" || echo "TCP to 8.8.8.8:443 FAILED: exit $?"
echo "--- TCP to 1.1.1.1:53 ---"
timeout 5 bash -c 'echo > /dev/tcp/1.1.1.1/53' 2>&1 && echo "TCP to 1.1.1.1:53 is OPEN" || echo "TCP to 1.1.1.1:53 FAILED: exit $?"
echo

echo "=== DNS CONSISTENCY TEST (same host, multiple attempts) ==="
echo "Testing if DNS is consistent within this VM..."
echo "nameserver 10.0.2.3" | sudo tee /etc/resolv.conf > /dev/null
for i in 1 2 3 4 5; do
    echo "--- Attempt $i: getent ahostsv4 google.com ---"
    getent ahostsv4 google.com 2>&1 | head -1 || echo "FAILED"
done
echo

# =============================================================================
# COMPARE DNS APPROACHES: SLIRP proxy (10.0.2.3) vs Direct (8.8.8.8)
# =============================================================================

TEST_HOSTS="astral.sh github.com release-assets.githubusercontent.com google.com"

echo "========================================"
echo "=== COMPARING DNS APPROACHES ==="
echo "========================================"
echo

# Test 1: Using SLIRP DNS proxy (10.0.2.3)
echo "=== TEST 1: SLIRP DNS Proxy (10.0.2.3) ==="
echo "This is what deployment/vrouter-infra uses"
echo "SLIRP proxy forwards to host's DNS (10.63.4.101), which can resolve internal hosts"
echo "nameserver 10.0.2.3" | sudo tee /etc/resolv.conf > /dev/null
cat /etc/resolv.conf
echo
for host in $TEST_HOSTS; do
    echo "--- Resolving $host via 10.0.2.3 ---"
    time getent ahostsv4 "$host" 2>&1 || echo "FAILED to resolve $host via SLIRP proxy"
    echo
done
# Also test internal hostname via SLIRP proxy
echo "--- Resolving artifacts.swccdc.com via SLIRP proxy (internal host) ---"
time getent ahostsv4 artifacts.swccdc.com 2>&1 || echo "FAILED to resolve artifacts.swccdc.com via SLIRP proxy"
echo

# Test 2: Using Google DNS directly (8.8.8.8)
echo "=== TEST 2: Google DNS Direct (8.8.8.8) ==="
echo "This is what vyos-onecontext currently uses"
echo "nameserver 8.8.8.8" | sudo tee /etc/resolv.conf > /dev/null
echo "nameserver 8.8.4.4" | sudo tee -a /etc/resolv.conf > /dev/null
cat /etc/resolv.conf
echo
for host in $TEST_HOSTS; do
    echo "--- Resolving $host via 8.8.8.8 ---"
    time getent ahostsv4 "$host" 2>&1 || echo "FAILED to resolve $host via Google DNS"
    echo
done

# Test 3: Using Cloudflare DNS directly (1.1.1.1)
echo "=== TEST 3: Cloudflare DNS Direct (1.1.1.1) ==="
echo "Alternative external DNS"
echo "nameserver 1.1.1.1" | sudo tee /etc/resolv.conf > /dev/null
echo "nameserver 1.0.0.1" | sudo tee -a /etc/resolv.conf > /dev/null
cat /etc/resolv.conf
echo
for host in $TEST_HOSTS; do
    echo "--- Resolving $host via 1.1.1.1 ---"
    time getent ahostsv4 "$host" 2>&1 || echo "FAILED to resolve $host via Cloudflare DNS"
    echo
done

# Test 4: Using internal DNS directly (10.63.4.101)
# This is the DNS server configured for the game_tools network where runners live.
# SLIRP proxy (10.0.2.3) should forward to this via the host's resolv.conf.
echo "=== TEST 4: Internal DNS Direct (10.63.4.101) ==="
echo "This is the upstream DNS that SLIRP should forward to"
echo "nameserver 10.63.4.101" | sudo tee /etc/resolv.conf > /dev/null
cat /etc/resolv.conf
echo
# First test: can we even reach it?
echo "--- Testing TCP connectivity to 10.63.4.101:53 ---"
if timeout 5 bash -c 'echo > /dev/tcp/10.63.4.101/53' 2>/dev/null; then
    echo "TCP to 10.63.4.101:53 is OPEN"
else
    echo "TCP to 10.63.4.101:53 FAILED or timed out (may not be routable from SLIRP)"
fi
echo
# Now test resolution
for host in $TEST_HOSTS; do
    echo "--- Resolving $host via 10.63.4.101 ---"
    time getent ahostsv4 "$host" 2>&1 || echo "FAILED to resolve $host via internal DNS"
    echo
done
# Also test an internal hostname if we know one
echo "--- Resolving artifacts.swccdc.com via 10.63.4.101 ---"
time getent ahostsv4 artifacts.swccdc.com 2>&1 || echo "FAILED to resolve artifacts.swccdc.com via internal DNS"
echo

echo "========================================"
echo "=== END DNS COMPARISON ==="
echo "========================================"
echo

# Additional tests if dig is available
if command -v dig &>/dev/null; then
    echo "=== Additional dig tests (UDP vs TCP) ==="
    echo "--- UDP to 8.8.8.8 ---"
    dig +short +time=5 +tries=1 @8.8.8.8 astral.sh A 2>&1 || echo "dig UDP failed"
    echo "--- TCP to 8.8.8.8 ---"
    dig +short +time=5 +tries=1 +tcp @8.8.8.8 astral.sh A 2>&1 || echo "dig TCP failed"
    echo "--- UDP to SLIRP proxy ---"
    dig +short +time=5 +tries=1 @10.0.2.3 astral.sh A 2>&1 || echo "dig SLIRP failed"
    echo
fi

echo "=== CURL CONNECTIVITY TEST (verbose, shows exact errors) ==="
echo "--- curl to 8.8.8.8 (IP direct, no DNS) ---"
curl -4 -v --connect-timeout 10 --max-time 15 -o /dev/null https://8.8.8.8/ 2>&1 | grep -E "Trying|Connected|Could not|error:|Failed"
echo
echo "--- curl to google.com (requires DNS) ---"
curl -4 -v --connect-timeout 10 --max-time 15 -o /dev/null https://google.com/ 2>&1 | grep -E "Trying|Connected|Could not|error:|Failed|Resolving"
echo

echo "=== FINAL NETWORK STATE (check if anything changed) ==="
echo "--- Routes at end ---"
ip route show
echo "--- Neighbor cache at end ---"
ip neigh show
echo

echo "=== DNS DIAGNOSTIC END ==="
