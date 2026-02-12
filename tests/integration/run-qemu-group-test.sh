#!/bin/bash
# Run multiple VyOS test fixtures in a single QEMU VM boot cycle
#
# This script boots a VM once and applies multiple test configurations
# sequentially, resetting configuration state between tests to maintain
# isolation.
#
# Usage: run-qemu-group-test.sh <vyos-image.qcow2> <group-name> <fixture1> [fixture2] [fixture3] ...
#
# Example: run-qemu-group-test.sh vyos.qcow2 basic simple quotes multi-interface

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source shared validation library
# shellcheck source=tests/integration/lib/validate-fixture.sh
source "$SCRIPT_DIR/lib/validate-fixture.sh"

VYOS_IMAGE="${1:?VyOS image path required}"
GROUP_NAME="${2:?Group name required}"
shift 2  # Remove first two arguments
FIXTURES=("$@")

if [ ${#FIXTURES[@]} -eq 0 ]; then
    echo "ERROR: At least one fixture name required"
    exit 1
fi

# Validate VyOS image exists
if [ ! -f "$VYOS_IMAGE" ]; then
    echo "ERROR: VyOS image not found: $VYOS_IMAGE"
    exit 1
fi

# Validate context files exist
for fixture in "${FIXTURES[@]}"; do
    CONTEXT_FILE="$SCRIPT_DIR/contexts/${fixture}.env"
    if [ ! -f "$CONTEXT_FILE" ]; then
        echo "ERROR: Context file not found: $CONTEXT_FILE"
        exit 1
    fi
done

# Check for KVM support
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
SSH_PORT=10022
QEMU_PID=""

# Cleanup function
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

cleanup_all() {
    cleanup_qemu
    rm -rf "$TEST_DIR"
}

trap cleanup_all EXIT INT TERM

echo "========================================"
echo "  VyOS Group Integration Test"
echo "========================================"
echo "Image: $VYOS_IMAGE"
echo "Group: $GROUP_NAME"
echo "Fixtures: ${FIXTURES[*]}"
echo "Serial log: $SERIAL_LOG"
echo ""

# For the initial boot, we need a minimal context to get SSH working
# Create a bootstrap context that just sets up basic connectivity
BOOTSTRAP_ISO="$TEST_DIR/bootstrap.iso"
cat > "$TEST_DIR/context.sh" <<'BOOTSTRAP_CTX'
# Bootstrap context for group testing
HOSTNAME="test-group-runner"
ONECONTEXT_MODE="stateless"
ETH0_IP="192.168.122.99"
ETH0_MASK="255.255.255.0"
ETH0_GATEWAY="192.168.122.1"
ETH0_DNS="8.8.8.8"
BOOTSTRAP_CTX

echo "Creating bootstrap context ISO..."
if ! "$SCRIPT_DIR/create-test-iso.sh" "$BOOTSTRAP_ISO" "$TEST_DIR/context.sh"; then
    echo "ERROR: Failed to create bootstrap ISO"
    exit 1
fi

# Start QEMU with bootstrap context
echo "Starting VyOS VM with bootstrap context..."
qemu-system-x86_64 \
    "${KVM_ARGS[@]}" \
    -m 2048 \
    -smp 2 \
    -drive file="$VYOS_IMAGE",format=qcow2,if=virtio,snapshot=on \
    -cdrom "$BOOTSTRAP_ISO" \
    -serial file:"$SERIAL_LOG" \
    -monitor unix:"$MONITOR_SOCKET",server,nowait \
    -nographic \
    -netdev user,id=net0,hostfwd=tcp::${SSH_PORT}-:22 \
    -device virtio-net-pci,netdev=net0 \
    -display none \
    &

QEMU_PID=$!
echo "QEMU started with PID: $QEMU_PID"

# Wait for initial boot and contextualization
echo "Waiting for VM to boot and initialize (timeout: 180s)..."
START_TIME=$(date +%s)
TIMEOUT=180

while true; do
    ELAPSED=$(($(date +%s) - START_TIME))

    if [ $ELAPSED -ge $TIMEOUT ]; then
        echo "ERROR: Timeout waiting for initial boot"
        echo "=== Serial log ==="
        cat "$SERIAL_LOG" || echo "No serial log available"
        exit 1
    fi

    if ! kill -0 "$QEMU_PID" 2>/dev/null; then
        echo "ERROR: QEMU process died unexpectedly"
        echo "=== Serial log ==="
        cat "$SERIAL_LOG" || echo "No serial log available"
        exit 1
    fi

    # Check for bootstrap contextualization completion or failure
    if [ -f "$SERIAL_LOG" ]; then
        if grep -q "vyos-onecontext.*completed successfully" "$SERIAL_LOG" 2>/dev/null; then
            echo "[PASS] Bootstrap contextualization completed"
            break
        elif grep -q "vyos-onecontext.*failed" "$SERIAL_LOG" 2>/dev/null; then
            echo "ERROR: Bootstrap contextualization failed"
            echo "=== Serial log ==="
            cat "$SERIAL_LOG"
            exit 1
        fi
    fi

    sleep 2
done

# Set up SSH connection
echo ""
echo "=== SSH Connection Setup ==="

if ! command -v sshpass >/dev/null 2>&1; then
    echo "ERROR: sshpass is required but not found"
    exit 1
fi

SSH_TIMEOUT=60
SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=5"
SSH_USER="vyos"
SSH_PASSWORD="vyos"
SSH_HOST="localhost"

# Helper function to run SSH commands
ssh_command() {
    # shellcheck disable=SC2086
    sshpass -p "$SSH_PASSWORD" ssh $SSH_OPTS -p "$SSH_PORT" "${SSH_USER}@${SSH_HOST}" "$@"
}

# Export SSH config for helper scripts and validation library
export SSH_PORT SSH_OPTS SSH_USER SSH_HOST SSH_PASSWORD
export -f ssh_command
SSH_AVAILABLE=1
export SSH_AVAILABLE

# Wait for SSH to become available
echo "Waiting for SSH to become ready (timeout: ${SSH_TIMEOUT}s)..."
SSH_START_TIME=$(date +%s)

while true; do
    SSH_ELAPSED=$(($(date +%s) - SSH_START_TIME))
    
    if [ $SSH_ELAPSED -ge $SSH_TIMEOUT ]; then
        echo "ERROR: SSH did not become ready within ${SSH_TIMEOUT}s"
        exit 1
    fi
    
    if ssh_command "echo 'SSH ready'" >/dev/null 2>&1; then
        echo "[PASS] SSH connection established"
        break
    fi
    
    sleep 2
done

# Give system a moment to settle
sleep 2

# Function to reset VyOS configuration between test fixtures
reset_vyos_config() {
    local fixture_num="${1:-unknown}"
    echo "Resetting VyOS configuration to clean state..."

    # Use per-run log file under test temp directory
    local RESET_LOG="$TEST_DIR/reset-output-${fixture_num}.log"

    # Build reset commands as a multi-line script
    RESET_SCRIPT=$(cat <<'RESET_EOF'
#!/bin/vbash
source /opt/vyatta/etc/functions/script-template

# Enter configuration mode
configure

# Delete user-configured sections (preserve system basics)
# Note: We keep system login, ssh, and eth0 connectivity
# First delete all eth0 addresses (prevents IP state leakage from previous tests)
delete interfaces ethernet eth0 address
delete interfaces ethernet eth0 vrf

# Re-apply the management IP address for SSH connectivity
set interfaces ethernet eth0 address '192.168.122.99/24'

# Delete other user configurations
delete protocols
delete nat
delete service dhcp-server
delete service ntp
delete firewall
delete vrf
delete policy

# Commit the clean state
commit

# Exit configuration mode
exit

echo "RESET_COMPLETE"
RESET_EOF
)

    # Execute reset script via SSH - send script over stdin to avoid quoting issues
    if ssh_command "sudo /bin/vbash -s" <<< "$RESET_SCRIPT" 2>&1 | tee "$RESET_LOG"; then
        if grep -q "RESET_COMPLETE" "$RESET_LOG"; then
            echo "[PASS] Configuration reset completed"

            # Clean up start-script artifacts that may have been created
            ssh_command "rm -f /tmp/start-script-marker" 2>/dev/null || true

            return 0
        else
            echo "[FAIL] Configuration reset did not complete properly"
            return 1
        fi
    else
        echo "[FAIL] Configuration reset failed"
        cat "$RESET_LOG"
        return 1
    fi
}

echo ""
echo "========================================"
echo "  Running Test Fixtures"
echo "========================================"

TOTAL_TESTS=${#FIXTURES[@]}
PASSED=0
FAILED=0
FAILED_FIXTURES=()

# Run each fixture in the group
for i in "${!FIXTURES[@]}"; do
    fixture="${FIXTURES[$i]}"
    fixture_num=$((i + 1))
    CONTEXT_NAME="$fixture"  # Set context name for validation functions

    echo ""
    echo "========================================"
    echo "Test $fixture_num/$TOTAL_TESTS: $fixture"
    echo "========================================"

    CONTEXT_FILE="$SCRIPT_DIR/contexts/${fixture}.env"

    # Record serial log offset before applying context
    # This allows validation to search only the new log entries
    # Use 1-indexed offset so `tail -c +N` starts after the current end of file
    SERIAL_LOG_OFFSET=$(( $(wc -c < "$SERIAL_LOG") + 1 ))
    export SERIAL_LOG_OFFSET

    # Apply the context configuration via SSH
    echo "Applying configuration via SSH..."
    if ! "$SCRIPT_DIR/apply-context-via-ssh.sh" "$CONTEXT_FILE"; then
        # For error scenarios, exit code 1 is expected
        case "$fixture" in
            invalid-json|missing-required-fields|partial-valid)
                echo "[INFO] Configuration application completed with expected errors"
                echo "      This is expected for error scenario '$fixture'"
                ;;
            *)
                echo "[FAIL] Configuration application failed unexpectedly"
                FAILED_FIXTURES+=("$fixture")
                ((FAILED++)) || true

                # Skip validation for failed application
                # Reset configuration for next test (skip reset after last test)
                if [ $fixture_num -lt $TOTAL_TESTS ]; then
                    echo ""
                    echo "Resetting configuration for next test..."
                    reset_vyos_config "$fixture_num" || echo "[WARN] Reset failed"
                fi
                continue
                ;;
        esac
    fi

    # Wait for contextualization to complete
    # Check serial log (from offset) for completion markers
    echo "Waiting for contextualization to complete..."
    APPLY_START_TIME=$(date +%s)
    APPLY_TIMEOUT=60
    APPLY_COMPLETED=0

    while true; do
        APPLY_ELAPSED=$(($(date +%s) - APPLY_START_TIME))

        if [ $APPLY_ELAPSED -ge $APPLY_TIMEOUT ]; then
            echo "[FAIL] Timeout waiting for contextualization to complete"
            FAILED_FIXTURES+=("$fixture")
            ((FAILED++)) || true
            break
        fi

        # Check serial log from offset for completion
        if tail -c +${SERIAL_LOG_OFFSET} "$SERIAL_LOG" | grep -q "vyos-onecontext.*completed successfully" 2>/dev/null; then
            echo "[PASS] Contextualization completed successfully"
            APPLY_COMPLETED=1
            break
        elif tail -c +${SERIAL_LOG_OFFSET} "$SERIAL_LOG" | grep -q "vyos-onecontext.*failed with exit code 1" 2>/dev/null; then
            # Exit code 1 is acceptable for error scenarios
            case "$fixture" in
                invalid-json|missing-required-fields|partial-valid)
                    echo "[INFO] Contextualization completed with expected errors (exit code 1)"
                    echo "      This is expected for error scenario '$fixture'"
                    APPLY_COMPLETED=1
                    break
                    ;;
                *)
                    echo "[FAIL] Contextualization failed with exit code 1"
                    FAILED_FIXTURES+=("$fixture")
                    ((FAILED++)) || true
                    break
                    ;;
            esac
        elif tail -c +${SERIAL_LOG_OFFSET} "$SERIAL_LOG" | grep -q "vyos-onecontext.*failed" 2>/dev/null; then
            echo "[FAIL] Contextualization failed"
            FAILED_FIXTURES+=("$fixture")
            ((FAILED++)) || true
            break
        fi

        sleep 2
    done

    # Run validation if contextualization completed
    if [ $APPLY_COMPLETED -eq 1 ]; then
        echo ""
        echo "=== Validation ==="

        # Initialize validation state for this fixture
        VALIDATION_FAILED=0

        # Run common validation markers (with offset)
        validate_common_markers "$SERIAL_LOG" "$CONTEXT_NAME"

        # Run fixture-specific assertions (with offset)
        validate_fixture_assertions "$CONTEXT_NAME"

        # Run pytest SSH integration tests
        REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
        run_pytest_ssh_tests "$REPO_ROOT"

        # Check validation results
        if [ $VALIDATION_FAILED -eq 0 ]; then
            echo ""
            echo "[PASS] All validation checks passed for $fixture"
            ((PASSED++)) || true
        else
            echo ""
            echo "[FAIL] Validation failed for $fixture"
            echo ""
            echo "=== Serial log (from offset $SERIAL_LOG_OFFSET) ==="
            tail -c +${SERIAL_LOG_OFFSET} "$SERIAL_LOG"
            FAILED_FIXTURES+=("$fixture")
            ((FAILED++)) || true
        fi
    fi

    # Reset configuration for next test (skip reset after last test)
    if [ $fixture_num -lt $TOTAL_TESTS ]; then
        echo ""
        echo "Resetting configuration for next test..."
        if reset_vyos_config "$fixture_num"; then
            echo "[PASS] Configuration reset"
        else
            echo "[WARN] Configuration reset failed - next test may be affected"
        fi
    fi

    echo ""
done

echo "========================================"
echo "  Group Test Results: $GROUP_NAME"
echo "========================================"
echo "Total:  $TOTAL_TESTS"
echo "Passed: $PASSED"
echo "Failed: $FAILED"

if [ $FAILED -gt 0 ]; then
    echo ""
    echo "Failed fixtures:"
    for fixture in "${FAILED_FIXTURES[@]}"; do
        echo "  - $fixture"
    done
fi

echo ""

# Emit machine-readable summary for dispatcher
echo "GROUP_SUMMARY:PASSED=$PASSED:FAILED=$FAILED"

if [ $FAILED -eq 0 ]; then
    echo "[PASS] All tests in group passed!"
    exit 0
else
    echo "[FAIL] Some tests in group failed"
    exit 1
fi
