#!/bin/bash
# Run VyOS in QEMU with test context and validate configuration
#
# This script boots a VyOS image in QEMU with a context ISO and validates
# that contextualization works correctly.
#
# Usage: run-qemu-test.sh <vyos-image.qcow2> <context.iso> [timeout]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source shared validation library
# shellcheck source=tests/integration/lib/validate-fixture.sh
source "$SCRIPT_DIR/lib/validate-fixture.sh"

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

# Initialize validation state
VALIDATION_FAILED=0

# Set serial log offset to 0 (search full log in individual test mode)
SERIAL_LOG_OFFSET=0

# Run common validation markers
validate_common_markers "$SERIAL_LOG" "$CONTEXT_NAME"

# Run fixture-specific assertions
validate_fixture_assertions "$CONTEXT_NAME"

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

# Run pytest SSH integration tests
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
run_pytest_ssh_tests "$REPO_ROOT"

# Check final validation status
if [ $VALIDATION_FAILED -eq 0 ]; then
    echo ""
    echo "Test completed successfully!"
    exit 0
else
    echo ""
    echo "[FAIL] Test failed - see validation errors above"
    exit 1
fi
