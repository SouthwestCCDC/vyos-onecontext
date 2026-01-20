#!/bin/bash
# Run VyOS in QEMU with test context and validate configuration
#
# This script boots a VyOS image in QEMU with a context ISO and validates
# that contextualization works correctly.
#
# Usage: run-qemu-test.sh <vyos-image.qcow2> <context.iso> [timeout]

set -euo pipefail

VYOS_IMAGE="${1:?VyOS image path required}"
CONTEXT_ISO="${2:?Context ISO path required}"
TIMEOUT="${3:-180}"  # Default 3 minutes for boot + context

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
cleanup_all() {
    cleanup_qemu
    rm -rf "$TEST_DIR"
}
# Trap EXIT, INT (Ctrl+C), and TERM (kill) to ensure QEMU cleanup
trap cleanup_all EXIT INT TERM

echo "Starting VyOS VM for integration testing..."
echo "  Image: $VYOS_IMAGE"
echo "  Context: $CONTEXT_ISO"
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
echo "=== Validation ==="

# Give the system a moment to settle after contextualization
sleep 5

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

# Check for errors in contextualization
if grep -q "vyos-onecontext.*error\|vyos-onecontext.*ERROR" "$SERIAL_LOG"; then
    echo "[FAIL] Contextualization errors detected"
    VALIDATION_FAILED=1
else
    echo "[PASS] No contextualization errors detected"
fi

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
        assert_command_generated "set system login user vyos authentication public-keys" "SSH public key"
        ;;
    quotes)
        assert_command_generated "set system host-name" "Hostname configuration"
        assert_command_generated "set system login user vyos authentication public-keys" "SSH public key"
        # Verify the quoted comment field is preserved (issue #40 regression test)
        # The SSH key comment "test@quotes" is sanitized to "test_at_quotes" (@ -> _at_)
        # The double quotes around the comment are preserved in the key identifier
        if grep -q 'VYOS_CMD:.*public-keys.*test_at_quotes' "$SERIAL_LOG"; then
            echo "[PASS] SSH key comment with quotes preserved and sanitized correctly"
        else
            echo "[FAIL] SSH key comment not found - quote handling may be broken"
            VALIDATION_FAILED=1
        fi
        ;;
    multi-interface)
        assert_command_generated "set system host-name" "Hostname configuration"
        assert_command_generated "set interfaces ethernet eth0 address.*192.168.122.30" "Primary IP (192.168.122.30)"
        # Verify alias IPs are configured (secondary addresses on eth0)
        assert_command_generated "set interfaces ethernet eth0 address.*10.0.0.1" "Alias IP 1 (10.0.0.1)"
        assert_command_generated "set interfaces ethernet eth0 address.*172.16.0.1" "Alias IP 2 (172.16.0.1)"
        ;;
    management-vrf)
        assert_command_generated "set system host-name" "Hostname configuration"
        assert_command_generated "set vrf name management table 100" "VRF creation"
        assert_command_generated "set interfaces ethernet eth0 vrf management" "Interface VRF assignment"
        assert_command_generated "set service ssh vrf management" "SSH VRF binding"
        ;;
    static-routes)
        assert_command_generated "set system host-name" "Hostname configuration"
        # Gateway route: 10.0.0.0/8 via 192.168.122.254
        assert_command_generated "set protocols static route 10.0.0.0/8 next-hop 192.168.122.254" "Gateway route (10.0.0.0/8)"
        # Interface route: 172.16.0.0/12 via eth0 (no gateway)
        assert_command_generated "set protocols static route 172.16.0.0/12 interface eth0" "Interface route (172.16.0.0/12)"
        ;;
    *)
        echo "[WARN] Unknown context '$CONTEXT_NAME' - no specific assertions"
        ;;
esac

echo ""
if [ $VALIDATION_FAILED -eq 0 ]; then
    echo "=== [PASS] All validation checks passed ==="
    echo ""
    echo "Test completed successfully!"
    exit 0
else
    echo "=== [FAIL] Validation failed ==="
    echo ""
    echo "=== Full serial log ==="
    cat "$SERIAL_LOG"
    exit 1
fi
