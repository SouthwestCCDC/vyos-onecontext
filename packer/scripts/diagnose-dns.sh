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

echo "=== Testing TCP connectivity ==="
echo "--- TCP to 8.8.8.8:53 ---"
if timeout 5 bash -c 'echo > /dev/tcp/8.8.8.8/53' 2>/dev/null; then
    echo "TCP to 8.8.8.8:53 is OPEN"
else
    echo "TCP to 8.8.8.8:53 FAILED or timed out"
fi
echo "--- TCP to 8.8.8.8:443 ---"
if timeout 5 bash -c 'echo > /dev/tcp/8.8.8.8/443' 2>/dev/null; then
    echo "TCP to 8.8.8.8:443 is OPEN"
else
    echo "TCP to 8.8.8.8:443 FAILED or timed out"
fi
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
echo "nameserver 10.0.2.3" | sudo tee /etc/resolv.conf > /dev/null
cat /etc/resolv.conf
echo
for host in $TEST_HOSTS; do
    echo "--- Resolving $host via 10.0.2.3 ---"
    time getent ahostsv4 "$host" 2>&1 || echo "FAILED to resolve $host via SLIRP proxy"
    echo
done

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

echo "========================================"
echo "=== END DNS COMPARISON ==="
echo "========================================"
echo

# Additional tests if dig is available
if command -v dig &>/dev/null; then
    echo "=== Additional dig tests (UDP vs TCP) ==="
    echo "--- UDP to 8.8.8.8 ---"
    dig +short +time=5 +tries=1 @8.8.8.8 astral.sh A || echo "dig UDP failed"
    echo "--- TCP to 8.8.8.8 ---"
    dig +short +time=5 +tries=1 +tcp @8.8.8.8 astral.sh A || echo "dig TCP failed"
    echo "--- UDP to SLIRP proxy ---"
    dig +short +time=5 +tries=1 @10.0.2.3 astral.sh A || echo "dig SLIRP failed"
    echo
fi

echo "=== Testing HTTPS connectivity (bypasses DNS) ==="
echo "--- curl to IP directly (no DNS needed) ---"
curl -4 -s --connect-timeout 10 --max-time 15 -o /dev/null -w "HTTP %{http_code} to 8.8.8.8:443\n" https://8.8.8.8/ 2>&1 || echo "curl to 8.8.8.8 failed"
echo

echo "=== DNS DIAGNOSTIC END ==="
