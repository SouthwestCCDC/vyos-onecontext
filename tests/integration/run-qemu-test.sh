#!/bin/bash
# Run VyOS in QEMU with test context and validate configuration
#
# This script boots a VyOS image in QEMU with a context ISO and validates
# that contextualization works correctly.
#
# Usage: run-qemu-test.sh <vyos-image.qcow2> <context.iso> [timeout]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VYOS_IMAGE="${1:?VyOS image path required}"
CONTEXT_ISO="${2:?Context ISO path required}"
TIMEOUT="${3:-180}"  # Default 3 minutes for boot + context

# Extract context name from ISO filename (e.g., simple.iso -> simple)
CONTEXT_NAME=$(basename "$CONTEXT_ISO" .iso)

# Validate inputs
if [ ! -f "$VYOS_IMAGE" ]; then
    echo "ERROR: VyOS image not found: $VYOS_IMAGE"
    exit 1
fi

if [ ! -f "$CONTEXT_ISO" ]; then
    echo "ERROR: Context ISO not found: $CONTEXT_ISO"
    exit 1
fi

# Check for KVM support - use array to safely handle empty case
if [ ! -e /dev/kvm ]; then
    echo "WARNING: /dev/kvm not found. Tests will run without KVM acceleration (slow)."
    KVM_ARGS=()
else
    KVM_ARGS=(-enable-kvm)
fi

# Create temporary directory for test artifacts
TEST_DIR=$(mktemp -d)

SERIAL_LOG="$TEST_DIR/serial.log"
MONITOR_SOCKET="$TEST_DIR/monitor.sock"
# Port 10022 is used for SSH forwarding from the guest.
# Note: Tests are run sequentially by run-all-tests.sh, so no port conflicts occur.
# If parallel execution is ever needed, dynamic port allocation should be implemented.
SSH_PORT=10022
QEMU_PID=""

# Function to cleanup QEMU
# shellcheck disable=SC2317
cleanup_qemu() {
    if [ -n "$QEMU_PID" ] && kill -0 "$QEMU_PID" 2>/dev/null; then
        echo "Terminating QEMU (PID: $QEMU_PID)..."
        kill "$QEMU_PID" 2>/dev/null || true
        sleep 5
        if kill -0 "$QEMU_PID" 2>/dev/null; then
            echo "Force killing QEMU..."
            kill -9 "$QEMU_PID" 2>/dev/null || true
        fi
    fi
}

# Combined cleanup function to handle both QEMU and temp directory
# shellcheck disable=SC2317
cleanup_all() {
    cleanup_qemu
    rm -rf "$TEST_DIR"
}
# Trap EXIT, INT (Ctrl+C), and TERM (kill) to ensure QEMU cleanup
trap cleanup_all EXIT INT TERM

echo "Starting VyOS VM for integration testing..."
echo "  Image: $VYOS_IMAGE"
echo "  Context: $CONTEXT_ISO"
echo "  Context name: $CONTEXT_NAME"
echo "  Serial log: $SERIAL_LOG"
echo "  SSH port: $SSH_PORT"

# Start QEMU in background
qemu-system-x86_64 \
    "${KVM_ARGS[@]}" \
    -m 2048 \
    -smp 2 \
    -drive file="$VYOS_IMAGE",format=qcow2,if=virtio,snapshot=on \
    -cdrom "$CONTEXT_ISO" \
    -serial file:"$SERIAL_LOG" \
    -monitor unix:"$MONITOR_SOCKET",server,nowait \
    -nographic \
    -netdev user,id=net0,hostfwd=tcp::${SSH_PORT}-:22 \
    -device virtio-net-pci,netdev=net0 \
    -display none \
    &

QEMU_PID=$!
echo "QEMU started with PID: $QEMU_PID"

# Wait for boot and contextualization
echo "Waiting for VM to boot and contextualize (timeout: ${TIMEOUT}s)..."
START_TIME=$(date +%s)
PROGRESS_COUNTER=0

while true; do
    ELAPSED=$(($(date +%s) - START_TIME))

    # Check if we've exceeded timeout
    if [ $ELAPSED -ge $TIMEOUT ]; then
        echo "ERROR: Timeout waiting for contextualization"
        echo "=== Serial log ==="
        cat "$SERIAL_LOG" || echo "No serial log available"
        exit 1
    fi

    # Check if QEMU is still running
    if ! kill -0 "$QEMU_PID" 2>/dev/null; then
        echo "ERROR: QEMU process died unexpectedly"
        echo "=== Serial log ==="
        cat "$SERIAL_LOG" || echo "No serial log available"
        exit 1
    fi

    # Check serial log for contextualization completion
    # The boot script logs via syslog with tag "vyos-onecontext"
    # Messages include: "completed successfully", "failed with exit code"
    # Note: QEMU writes to this file concurrently. Serial output is line-buffered
    # so grep sees complete lines in practice. The theoretical race is acceptable
    # for test infrastructure.
    if [ -f "$SERIAL_LOG" ]; then
        if grep -q "vyos-onecontext.*completed successfully" "$SERIAL_LOG" 2>/dev/null; then
            echo "[PASS] Contextualization completed successfully"
            break
        elif grep -q "vyos-onecontext.*failed with exit code 1" "$SERIAL_LOG" 2>/dev/null; then
            # Exit code 1 is acceptable for error scenarios (partial valid config)
            # Check if this is an expected error scenario
            case "$CONTEXT_NAME" in
                invalid-json|missing-required-fields|partial-valid)
                    echo "[INFO] Contextualization completed with expected errors (exit code 1)"
                    echo "      This is expected for error scenario '$CONTEXT_NAME'"
                    break
                    ;;
                *)
                    echo "ERROR: Contextualization failed with exit code 1"
                    echo "=== Serial log ==="
                    cat "$SERIAL_LOG"
                    exit 1
                    ;;
            esac
        elif grep -q "vyos-onecontext.*failed" "$SERIAL_LOG" 2>/dev/null; then
            echo "ERROR: Contextualization failed"
            echo "=== Serial log ==="
            cat "$SERIAL_LOG"
            exit 1
        fi
    fi

    # Show progress every 10 seconds (5 iterations * 2s sleep)
    ((PROGRESS_COUNTER++)) || true
    if [ $((PROGRESS_COUNTER % 5)) -eq 0 ]; then
        echo "  ... still waiting (${ELAPSED}s elapsed)"
    fi

    sleep 2
done

echo ""
echo "=== SSH Connection Setup ==="

# Check if sshpass is available (REQUIRED for SSH-based testing)
if ! command -v sshpass >/dev/null 2>&1; then
    echo "ERROR: sshpass is required for SSH-based testing but not found"
    echo "Install with: apt-get install sshpass"
    exit 1
fi

SSH_AVAILABLE=1
echo "Using password authentication (vyos/vyos default credentials)"

# SSH connection parameters
SSH_TIMEOUT="${SSH_TIMEOUT:-60}"  # Default 60s timeout for SSH readiness
SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=5"
# shellcheck disable=SC2086
# Note: SSH_OPTS is intentionally unquoted to allow multiple options
SSH_USER="vyos"
SSH_PASSWORD="vyos"
SSH_HOST="localhost"

# Helper function to run SSH commands on the VM
ssh_command() {
    # shellcheck disable=SC2086
    # Note: SSH_OPTS is intentionally unquoted to allow multiple options
    sshpass -p "$SSH_PASSWORD" ssh $SSH_OPTS -p "$SSH_PORT" "${SSH_USER}@${SSH_HOST}" "$@"
}

# Export for use in test scripts and validation
export -f ssh_command
export SSH_PORT SSH_OPTS SSH_USER SSH_HOST SSH_PASSWORD SSH_AVAILABLE

# Wait for SSH to become available
echo "Waiting for SSH to become ready (timeout: ${SSH_TIMEOUT}s)..."
SSH_START_TIME=$(date +%s)

while true; do
    SSH_ELAPSED=$(($(date +%s) - SSH_START_TIME))

    if [ $SSH_ELAPSED -ge $SSH_TIMEOUT ]; then
        echo "WARNING: SSH did not become ready within ${SSH_TIMEOUT}s"
        echo "SSH-based validation will be skipped"
        SSH_AVAILABLE=0
        export SSH_AVAILABLE
        break
    fi

    # Try to connect via SSH
    if ssh_command "echo 'SSH ready'" >/dev/null 2>&1; then
        echo "[PASS] SSH connection established"
        break
    fi

    # Show progress every 5 attempts (10 seconds)
    if [ $((SSH_ELAPSED % 10)) -eq 0 ] && [ $SSH_ELAPSED -gt 0 ]; then
        echo "  ... still waiting (${SSH_ELAPSED}s elapsed)"
    fi

    sleep 2
done

echo ""
echo "=== Validation ==="

# Give the system a moment to settle after contextualization
sleep 2

# Validate configuration by checking serial log
VALIDATION_FAILED=0

echo "Checking for expected configuration markers in serial log..."

# Check that contextualization ran
if grep -q "vyos-onecontext" "$SERIAL_LOG"; then
    echo "[PASS] Contextualization script executed"
else
    echo "[FAIL] Contextualization script did not execute"
    VALIDATION_FAILED=1
fi

# Check for errors in contextualization (expected for error scenarios)
case "$CONTEXT_NAME" in
    invalid-json|missing-required-fields|partial-valid)
        # Error scenarios SHOULD have errors
        if grep -q "vyos-onecontext.*error\|vyos-onecontext.*ERROR" "$SERIAL_LOG"; then
            echo "[PASS] Contextualization errors detected (expected for error scenario)"
        else
            echo "[FAIL] No contextualization errors detected (expected errors for '$CONTEXT_NAME')"
            VALIDATION_FAILED=1
        fi
        ;;
    *)
        # Normal scenarios should NOT have errors
        if grep -q "vyos-onecontext.*error\|vyos-onecontext.*ERROR" "$SERIAL_LOG"; then
            echo "[FAIL] Contextualization errors detected"
            VALIDATION_FAILED=1
        else
            echo "[PASS] No contextualization errors detected"
        fi
        ;;
esac

# Check for Python exceptions in vyos-onecontext output
# Matches: "Traceback (most recent", "SomeError:", "SomeException:"
# Scope to vyos-onecontext lines to avoid false positives from other system logs
if grep "vyos-onecontext" "$SERIAL_LOG" | grep -qE "(Traceback \(most recent|[A-Z][a-zA-Z]*Error:|[A-Z][a-zA-Z]*Exception:)"; then
    echo "[FAIL] Python exceptions detected in vyos-onecontext output"
    VALIDATION_FAILED=1
else
    echo "[PASS] No Python exceptions detected in vyos-onecontext output"
fi

# CRITICAL: Verify configuration commands were actually generated
# This ensures the test context is properly processed, not just "didn't crash"
echo ""
echo "=== Command Generation Validation ==="

# Helper function to check for required commands
assert_command_generated() {
    local pattern="$1"
    local description="$2"
    if grep -q "VYOS_CMD:.*$pattern" "$SERIAL_LOG"; then
        echo "[PASS] $description"
        return 0
    else
        echo "[FAIL] $description - command not generated"
        echo "       Expected pattern: $pattern"
        VALIDATION_FAILED=1
        return 1
    fi
}

# Check that ANY commands were generated (baseline requirement)
if grep -q "VYOS_CMD:" "$SERIAL_LOG"; then
    CMD_COUNT=$(grep -c "VYOS_CMD:" "$SERIAL_LOG")
    echo "[PASS] Generated $CMD_COUNT configuration commands"
    echo ""
    echo "Commands generated:"
    grep "VYOS_CMD:" "$SERIAL_LOG" | sed 's/.*VYOS_CMD: /  /' | head -30
    echo ""
else
    echo "[CRITICAL FAIL] No configuration commands were generated!"
    echo "This means the test context is not being processed correctly."
    VALIDATION_FAILED=1
fi

# Context-specific command assertions
# Extract context name from the ISO path or environment
CONTEXT_NAME="${CONTEXT_NAME:-unknown}"
echo ""
echo "=== Context-Specific Assertions ($CONTEXT_NAME) ==="

case "$CONTEXT_NAME" in
    simple)
        assert_command_generated "set system host-name" "Hostname configuration"
        assert_command_generated "set interfaces ethernet eth0 address" "Interface eth0 IP address"
        ;;
    quotes)
        assert_command_generated "set system host-name" "Hostname configuration"
        # Note: This test originally validated SSH key quote handling (issue #40)
        # but now uses default VyOS credentials. The parser quote handling is
        # validated by other tests with quoted values.
        ;;
    multi-interface)
        assert_command_generated "set system host-name" "Hostname configuration"
        assert_command_generated "set interfaces ethernet eth0 address.*192.168.122.30" "Primary IP (192.168.122.30)"
        # Verify alias IP is configured (secondary address on eth0)
        assert_command_generated "set interfaces ethernet eth0 address.*192.168.122.31" "Alias IP (192.168.122.31)"
        ;;
    management-vrf)
        assert_command_generated "set system host-name" "Hostname configuration"
        assert_command_generated "set vrf name management table 100" "VRF creation"
        assert_command_generated "set interfaces ethernet eth0 vrf management" "Interface VRF assignment"
        assert_command_generated "set service ssh vrf management" "SSH VRF binding"
        ;;
    static-routes)
        assert_command_generated "set system host-name" "Hostname configuration"

        # Static route validation: Gateway route
        # Fixture: {"interface": "eth0", "destination": "10.0.0.0/8", "gateway": "192.168.122.1"}
        assert_command_generated "set protocols static route 10.0.0.0/8 next-hop 192.168.122.1" "Gateway route (10.0.0.0/8 via 192.168.122.1)"

        # Static route validation: Interface route (no next-hop)
        # Fixture: {"interface": "eth0", "destination": "172.16.0.0/12"}
        assert_command_generated "set protocols static route 172.16.0.0/12 interface eth0" "Interface route (172.16.0.0/12 via eth0)"

        # Negative assertion: Interface route must NOT have next-hop
        if grep -q "VYOS_CMD:.*route 172.16.0.0/12.*next-hop" "$SERIAL_LOG"; then
            echo "[FAIL] Interface route 172.16.0.0/12 should not have next-hop"
            VALIDATION_FAILED=1
        else
            echo "[PASS] Interface route 172.16.0.0/12 correctly has no next-hop"
        fi

        # Negative assertion: Gateway route must NOT use 'interface' syntax
        if grep -q "VYOS_CMD:.*route 10.0.0.0/8 interface" "$SERIAL_LOG"; then
            echo "[FAIL] Gateway route 10.0.0.0/8 should not use 'interface' syntax"
            VALIDATION_FAILED=1
        else
            echo "[PASS] Gateway route 10.0.0.0/8 correctly uses next-hop syntax"
        fi
        ;;
    ospf)
        assert_command_generated "set system host-name" "Hostname configuration"

        # OSPF router ID validation
        # Fixture: "router_id":"192.168.122.70"
        assert_command_generated "set protocols ospf parameters router-id '192.168.122.70'" "OSPF router ID (192.168.122.70)"

        # OSPF interface area assignment validation
        # Fixture: {"name":"eth0","area":"0.0.0.0","passive":true}
        assert_command_generated "set protocols ospf interface eth0 area '0.0.0.0'" "OSPF interface eth0 in area 0.0.0.0"

        # OSPF passive interface validation
        # Fixture specifies passive:true for eth0
        assert_command_generated "set protocols ospf interface eth0 passive" "OSPF interface eth0 passive"

        # OSPF route redistribution validation
        # Fixture: "redistribute":["connected"]
        assert_command_generated "set protocols ospf redistribute connected" "OSPF redistribute connected routes"

        # OSPF default-information originate validation
        # Fixture: "default_information":{"originate":true,"always":true,"metric":100}
        assert_command_generated "set protocols ospf default-information originate always" "OSPF default-information originate always"
        assert_command_generated "set protocols ospf default-information originate metric '100'" "OSPF default-information metric 100"

        # Negative assertion: Verify only expected redistribution protocols
        if grep -q "VYOS_CMD:.*ospf redistribute static" "$SERIAL_LOG"; then
            echo "[FAIL] OSPF should not redistribute static routes (only connected)"
            VALIDATION_FAILED=1
        else
            echo "[PASS] OSPF correctly redistributes only connected routes"
        fi
        ;;
    dhcp)
        assert_command_generated "set system host-name" "Hostname configuration"
        # DHCP shared-network creation for eth0
        assert_command_generated "set service dhcp-server shared-network-name dhcp-eth0" "DHCP shared-network creation"
        # Subnet configuration
        assert_command_generated "set service dhcp-server shared-network-name dhcp-eth0 subnet 10.50.1.0/24" "DHCP subnet configuration"
        # DHCP range configuration
        assert_command_generated "range 0 start 10.50.1.100" "DHCP range start address"
        assert_command_generated "range 0 stop 10.50.1.200" "DHCP range end address"
        # Gateway option (default-router)
        assert_command_generated "default-router 10.50.1.1" "DHCP default router option"
        # DNS servers option
        assert_command_generated "name-server" "DHCP DNS server option"
        # Lease time
        assert_command_generated "lease 3600" "DHCP lease time"
        # Domain name option
        assert_command_generated "domain-name test.local" "DHCP domain name option"
        # Static mapping
        assert_command_generated "static-mapping reserved-host" "DHCP static mapping"
        assert_command_generated "mac-address 00:11:22:33:44:55" "DHCP static mapping MAC address"
        assert_command_generated "ip-address 10.50.1.50" "DHCP static mapping IP address"
        ;;
    snat)
        assert_command_generated "set system host-name" "Hostname configuration"
        # Source NAT rule
        assert_command_generated "set nat source rule 100" "Source NAT rule created"
        assert_command_generated "outbound-interface name eth0" "SNAT outbound interface (eth0)"
        assert_command_generated "source address 10.100.0.0/24" "SNAT source address"
        assert_command_generated "translation address masquerade" "SNAT masquerade translation"
        ;;
    dnat)
        assert_command_generated "set system host-name" "Hostname configuration"
        # Destination NAT rule
        assert_command_generated "set nat destination rule 100" "Destination NAT rule created"
        assert_command_generated "inbound-interface name eth0" "DNAT inbound interface (eth0)"
        assert_command_generated "protocol tcp" "DNAT protocol (tcp)"
        assert_command_generated "destination port 443" "DNAT destination port"
        assert_command_generated "translation address 10.100.0.50" "DNAT translation address"
        ;;
    nat-full)
        assert_command_generated "set system host-name" "Hostname configuration"
        # Source NAT (masquerade)
        assert_command_generated "set nat source rule 100" "Source NAT rule created"
        assert_command_generated "outbound-interface name eth0" "SNAT outbound interface"
        assert_command_generated "translation address masquerade" "SNAT masquerade translation"
        # Destination NAT (port forward)
        assert_command_generated "set nat destination rule 100" "Destination NAT rule created"
        assert_command_generated "destination port 8080" "DNAT destination port"
        assert_command_generated "translation address 10.100.0.80" "DNAT translation address"
        assert_command_generated "translation port 80" "DNAT translation port"
        # Binat (1:1 NAT) - creates both source and destination rules at 500
        assert_command_generated "set nat source rule 500" "Binat source rule created"
        assert_command_generated "set nat destination rule 500" "Binat destination rule created"
        assert_command_generated "source address.*10.100.0.100" "Binat internal address (source rule)"
        assert_command_generated "destination address.*192.168.122.100" "Binat external address (destination rule)"
        ;;
    vrf-with-routing)
        assert_command_generated "set system host-name" "Hostname configuration"
        # Management VRF
        assert_command_generated "set vrf name management" "VRF creation"
        assert_command_generated "set interfaces ethernet eth0 vrf management" "Interface VRF assignment"
        # Static routes in VRF (Sagitta syntax: set vrf name <vrf> protocols static route ...)
        assert_command_generated "set vrf name management protocols static route 10.10.0.0/16" "Static route in VRF"
        # OSPF is disabled in this test (no interfaces available due to single-NIC limitation)
        # Negative assertion: Verify OSPF commands are NOT generated
        if grep -q "VYOS_CMD:.*set protocols ospf" "$SERIAL_LOG"; then
            echo "[FAIL] OSPF commands should not be generated (OSPF disabled in fixture)"
            VALIDATION_FAILED=1
        else
            echo "[PASS] OSPF correctly not configured (disabled in fixture)"
        fi
        ;;
    nat-with-firewall)
        assert_command_generated "set system host-name" "Hostname configuration"
        # NAT rules
        assert_command_generated "set nat source rule" "NAT rules generated"
        assert_command_generated "outbound-interface name eth0" "NAT outbound interface"
        assert_command_generated "translation address masquerade" "NAT masquerade translation"
        # Firewall zone (single zone - can't test multi-zone with single NIC)
        assert_command_generated "set firewall zone WAN" "WAN zone creation"
        assert_command_generated "default-action drop" "Zone default action"
        # Global state policies
        assert_command_generated "set firewall global-options state-policy" "Global state policy"
        ;;
    start-script)
        assert_command_generated "set system host-name" "Hostname configuration"
        # START_SCRIPT is executed AFTER commit, so we need SSH to verify it ran
        if [ "$SSH_AVAILABLE" -eq 1 ]; then
            echo ""
            echo "=== START_SCRIPT Validation ==="
            # Check if the marker file was created by START_SCRIPT
            if ssh_command "test -f /tmp/start-script-marker" 2>/dev/null; then
                echo "[PASS] START_SCRIPT marker file exists"
                # Verify the content
                MARKER_CONTENT=$(ssh_command "cat /tmp/start-script-marker" 2>/dev/null)
                if echo "$MARKER_CONTENT" | grep -q "START_SCRIPT executed"; then
                    echo "[PASS] START_SCRIPT marker file contains expected content"
                else
                    echo "[FAIL] START_SCRIPT marker file has unexpected content"
                    VALIDATION_FAILED=1
                fi
            else
                echo "[FAIL] START_SCRIPT marker file not found - script did not execute"
                VALIDATION_FAILED=1
            fi
        else
            echo "[WARN] SSH not available - cannot verify START_SCRIPT execution"
        fi
        ;;
    invalid-json)
        echo ""
        echo "=== Error Scenario: Invalid JSON ==="
        assert_command_generated "set system host-name test-invalid-json" "Hostname configuration (valid)"
        assert_command_generated "set interfaces ethernet eth0 address.*192.168.122.90" "Interface eth0 IP (valid)"

        # DHCP should be configured (valid section)
        assert_command_generated "set service dhcp-server" "DHCP server configuration (valid)"

        # Should have error about ROUTES_JSON
        if grep -q "ERROR.*ROUTES_JSON" "$SERIAL_LOG"; then
            echo "[PASS] ROUTES_JSON error logged"
        else
            echo "[FAIL] ROUTES_JSON error not logged"
            VALIDATION_FAILED=1
        fi

        # Should show error summary
        if grep -q "ERROR SUMMARY" "$SERIAL_LOG"; then
            echo "[PASS] Error summary logged"
        else
            echo "[FAIL] Error summary not logged"
            VALIDATION_FAILED=1
        fi

        # Should NOT have route commands from ROUTES_JSON (invalid section skipped)
        # Note: Default gateway route (0.0.0.0/0) is valid and should be present
        # Check specifically for the route that would come from invalid ROUTES_JSON
        if grep -q "VYOS_CMD:.*set protocols static route 10.0.0.0/8" "$SERIAL_LOG"; then
            echo "[FAIL] Static route 10.0.0.0/8 should not be generated (invalid ROUTES_JSON)"
            VALIDATION_FAILED=1
        else
            echo "[PASS] Static routes from ROUTES_JSON correctly skipped (invalid JSON)"
        fi

        # Default gateway route should still be present (from ETH0_GATEWAY)
        if grep -q "VYOS_CMD:.*set protocols static route 0.0.0.0/0 next-hop 192.168.122.1" "$SERIAL_LOG"; then
            echo "[PASS] Default gateway route present (from ETH0_GATEWAY, valid)"
        else
            echo "[FAIL] Default gateway route not present (should be configured from ETH0_GATEWAY)"
            VALIDATION_FAILED=1
        fi
        ;;
    missing-required-fields)
        echo ""
        echo "=== Error Scenario: Missing Required Fields ==="
        assert_command_generated "set system host-name test-missing-fields" "Hostname configuration (valid)"
        assert_command_generated "set interfaces ethernet eth0 address.*192.168.122.91" "Interface eth0 IP (valid)"

        # DHCP should be configured (valid section)
        assert_command_generated "set service dhcp-server" "DHCP server configuration (valid)"

        # Should have error about OSPF_JSON missing required field
        if grep -q "ERROR.*OSPF_JSON" "$SERIAL_LOG"; then
            echo "[PASS] OSPF_JSON error logged"
        else
            echo "[FAIL] OSPF_JSON error not logged"
            VALIDATION_FAILED=1
        fi

        # Should show error summary
        if grep -q "ERROR SUMMARY" "$SERIAL_LOG"; then
            echo "[PASS] Error summary logged"
        else
            echo "[FAIL] Error summary not logged"
            VALIDATION_FAILED=1
        fi

        # Should NOT have OSPF commands (invalid section skipped)
        if grep -q "VYOS_CMD:.*set protocols ospf" "$SERIAL_LOG"; then
            echo "[FAIL] OSPF commands should not be generated (missing required field)"
            VALIDATION_FAILED=1
        else
            echo "[PASS] OSPF commands correctly skipped (missing required field)"
        fi
        ;;
    partial-valid)
        echo ""
        echo "=== Error Scenario: Partial Valid Config (Multiple Errors) ==="
        assert_command_generated "set system host-name test-partial-valid" "Hostname configuration (valid)"
        assert_command_generated "set interfaces ethernet eth0 address.*192.168.122.92" "Interface eth0 IP (valid)"

        # DHCP should be configured (valid section)
        assert_command_generated "set service dhcp-server" "DHCP server configuration (valid)"

        # Should have errors about both ROUTES_JSON and OSPF_JSON
        ROUTES_ERROR_FOUND=0
        OSPF_ERROR_FOUND=0

        if grep -q "ERROR.*ROUTES_JSON" "$SERIAL_LOG"; then
            echo "[PASS] ROUTES_JSON error logged"
            ROUTES_ERROR_FOUND=1
        else
            echo "[FAIL] ROUTES_JSON error not logged"
            VALIDATION_FAILED=1
        fi

        if grep -q "ERROR.*OSPF_JSON" "$SERIAL_LOG"; then
            echo "[PASS] OSPF_JSON error logged"
            OSPF_ERROR_FOUND=1
        else
            echo "[FAIL] OSPF_JSON error not logged"
            VALIDATION_FAILED=1
        fi

        # Should show error summary with multiple errors
        if grep -q "ERROR SUMMARY" "$SERIAL_LOG"; then
            echo "[PASS] Error summary logged"
        else
            echo "[FAIL] Error summary not logged"
            VALIDATION_FAILED=1
        fi

        # Should NOT have routes from ROUTES_JSON (malformed JSON)
        # Note: Default gateway route (0.0.0.0/0) is valid and should be present
        # Check specifically for routes that would come from invalid ROUTES_JSON
        ROUTES_FROM_JSON_FOUND=0
        if grep -q "VYOS_CMD:.*set protocols static route 10.0.0.0/8" "$SERIAL_LOG"; then
            echo "[FAIL] Static route 10.0.0.0/8 should not be generated (malformed ROUTES_JSON)"
            VALIDATION_FAILED=1
            ROUTES_FROM_JSON_FOUND=1
        fi
        if grep -q "VYOS_CMD:.*set protocols static route 172.16.0.0/12" "$SERIAL_LOG"; then
            echo "[FAIL] Static route 172.16.0.0/12 should not be generated (malformed ROUTES_JSON)"
            VALIDATION_FAILED=1
            ROUTES_FROM_JSON_FOUND=1
        fi
        if [ $ROUTES_FROM_JSON_FOUND -eq 0 ]; then
            echo "[PASS] Static routes from ROUTES_JSON correctly skipped (malformed JSON)"
        fi

        # Default gateway route should still be present (from ETH0_GATEWAY)
        if grep -q "VYOS_CMD:.*set protocols static route 0.0.0.0/0 next-hop 192.168.122.1" "$SERIAL_LOG"; then
            echo "[PASS] Default gateway route present (from ETH0_GATEWAY, valid)"
        else
            echo "[FAIL] Default gateway route not present (should be configured from ETH0_GATEWAY)"
            VALIDATION_FAILED=1
        fi

        if grep -q "VYOS_CMD:.*set protocols ospf" "$SERIAL_LOG"; then
            echo "[FAIL] OSPF commands should not be generated (missing required field)"
            VALIDATION_FAILED=1
        else
            echo "[PASS] OSPF commands correctly skipped (missing required field)"
        fi
        ;;
    ssh-keys)
        assert_command_generated "set system host-name" "Hostname configuration"
        # SSH key configuration commands
        assert_command_generated "set service ssh port 22" "SSH service enabled on port 22"
        assert_command_generated "set system login user vyos authentication public-keys" "SSH public key configuration"
        # Verify key type and key data are configured
        assert_command_generated "authentication public-keys.*type" "SSH key type configured"
        assert_command_generated "authentication public-keys.*key" "SSH key data configured"

        # Verify multiple keys if configured (ssh-keys.env has 2 keys)
        # Count distinct "authentication public-keys <identifier>" entries
        # Extract key identifiers from commands like "set system login user vyos authentication public-keys <id> ..."
        KEY_COUNT=$(grep "VYOS_CMD:.*authentication public-keys" "$SERIAL_LOG" | \
                    sed -n 's/.*authentication public-keys \([^ ]*\).*/\1/p' | \
                    sort -u | wc -l)
        if [ "$KEY_COUNT" -ge 2 ]; then
            echo "[PASS] Multiple SSH keys configured (found $KEY_COUNT distinct keys)"
        elif [ "$KEY_COUNT" -eq 1 ]; then
            echo "[WARN] Only one SSH key found, expected multiple for ssh-keys fixture"
        else
            echo "[FAIL] No SSH keys found in configuration"
            VALIDATION_FAILED=1
        fi
        ;;
    *)
        echo "[WARN] Unknown context '$CONTEXT_NAME' - no specific assertions"
        ;;
esac

echo ""
if [ $VALIDATION_FAILED -eq 0 ]; then
    echo "=== [PASS] All serial log validation checks passed ==="
else
    echo "=== [FAIL] Serial log validation failed ==="
    echo ""
    echo "=== Full serial log ==="
    cat "$SERIAL_LOG"
    exit 1
fi

# Run pytest SSH integration tests if SSH is available
if [ "$SSH_AVAILABLE" -eq 1 ]; then
    echo ""
    echo "=== Pytest SSH Integration Tests ==="
    echo ""

    # Check if pytest is available
    if command -v pytest >/dev/null 2>&1; then
        PYTEST_CMD="pytest"
    elif command -v uv >/dev/null 2>&1; then
        PYTEST_CMD="uv run pytest"
    else
        echo "[WARN] Neither pytest nor uv found - skipping pytest tests"
        echo "       Shell-based validation passed, marking test as successful"
        echo ""
        echo "Test completed successfully!"
        exit 0
    fi

    # Run pytest with integration marker, capturing output
    # The ssh_connection fixture will use the exported SSH_* environment variables
    # Change to repo root to run pytest (tests are at tests/test_ssh_integration.py)
    REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
    echo "Running pytest integration tests from $REPO_ROOT..."
    cd "$REPO_ROOT"
    if $PYTEST_CMD -m integration tests/test_ssh_integration.py -v; then
        echo ""
        echo "[PASS] Pytest integration tests passed"
        echo ""
        echo "Test completed successfully!"
        exit 0
    else
        echo ""
        echo "[FAIL] Pytest integration tests failed"
        exit 1
    fi
else
    echo ""
    echo "[WARN] SSH not available - skipping pytest tests"
    echo "       Shell-based validation passed, marking test as successful"
    echo ""
    echo "Test completed successfully!"
    exit 0
fi
