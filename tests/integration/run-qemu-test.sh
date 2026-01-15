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

# Check for KVM support
if [ ! -e /dev/kvm ]; then
    echo "WARNING: /dev/kvm not found. Tests will run without KVM acceleration (slow)."
    KVM_FLAG=""
else
    KVM_FLAG="-enable-kvm"
fi

# Create temporary directory for test artifacts
TEST_DIR=$(mktemp -d)

SERIAL_LOG="$TEST_DIR/serial.log"
MONITOR_SOCKET="$TEST_DIR/monitor.sock"
SSH_PORT=10022
QEMU_PID=""

# Function to cleanup QEMU
cleanup_qemu() {
    if [ -n "$QEMU_PID" ] && kill -0 "$QEMU_PID" 2>/dev/null; then
        echo "Terminating QEMU (PID: $QEMU_PID)..."
        kill "$QEMU_PID" 2>/dev/null || true
        sleep 2
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
trap cleanup_all EXIT

echo "Starting VyOS VM for integration testing..."
echo "  Image: $VYOS_IMAGE"
echo "  Context: $CONTEXT_ISO"
echo "  Serial log: $SERIAL_LOG"
echo "  SSH port: $SSH_PORT"

# Start QEMU in background
qemu-system-x86_64 \
    $KVM_FLAG \
    -m 2048 \
    -smp 2 \
    -drive file="$VYOS_IMAGE",format=qcow2,if=virtio,snapshot=on \
    -cdrom "$CONTEXT_ISO" \
    -serial file:"$SERIAL_LOG" \
    -monitor unix:"$MONITOR_SOCKET",server,nowait \
    -nographic \
    -net nic,model=virtio \
    -net user,hostfwd=tcp::${SSH_PORT}-:22 \
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

# Check for Python exceptions (specific patterns to avoid false positives)
# Matches: "Traceback (most recent", "SomeError:", "SomeException:"
if grep -qE "(Traceback \(most recent|^[A-Za-z]+Error:|^[A-Za-z]+Exception:)" "$SERIAL_LOG"; then
    echo "[FAIL] Python exceptions detected in log"
    VALIDATION_FAILED=1
else
    echo "[PASS] No Python exceptions detected"
fi

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
